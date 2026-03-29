use crate::adapters::inspect_repo;
use crate::capabilities::detect_capabilities;
use crate::collectors::{CollectReport, collect_once};
use crate::config::FixerConfig;
use crate::models::{
    ComplaintCollectionReport, ComplaintOutcome, ParticipationMode, SharedOpportunity,
};
use crate::network::{self, ParticipationSnapshot, SyncOutcome, WorkerRunOutcome};
use crate::proposal;
use crate::storage::Store;
use crate::util::{command_exists, hash_text, now_rfc3339};
use crate::workspace::ensure_workspace_for_opportunity;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

pub struct App {
    pub config: FixerConfig,
    pub store: Store,
}

impl App {
    pub fn load(config_path: Option<&Path>) -> Result<Self> {
        let config = FixerConfig::load(config_path)?;
        Self::from_config(config)
    }

    fn from_config(config: FixerConfig) -> Result<Self> {
        config.ensure_parent_dirs()?;
        let store = Store::open(&config.service.database_path)?;
        if let Err(error) = store.sync_capabilities(&detect_capabilities()) {
            if !is_permission_or_readonly_error(&error) {
                return Err(error);
            }
        }
        Ok(Self { config, store })
    }

    pub fn collect_once(&self) -> Result<CollectReport> {
        collect_once(&self.config, &self.store)
    }

    pub fn complain(&self, description: &str, collect_now: bool) -> Result<ComplaintOutcome> {
        let description = description.trim();
        if description.is_empty() {
            return Err(anyhow!("complaint text must not be empty"));
        }

        match self.complain_impl(description, collect_now, false) {
            Ok(outcome) => Ok(outcome),
            Err(error) if should_retry_complaint_in_overlay(&error) => {
                let overlay = self.open_complaint_overlay(description)?;
                overlay.complain_impl(description, collect_now, true)
            }
            Err(error) => Err(error),
        }
    }

    fn complain_impl(
        &self,
        description: &str,
        collect_now: bool,
        used_overlay: bool,
    ) -> Result<ComplaintOutcome> {
        let collection_report = if collect_now {
            Some(self.collect_once()?)
        } else {
            None
        };
        let complaint_finding = crate::models::FindingInput {
            kind: "complaint".to_string(),
            title: format!("User complaint: {}", summarize_complaint(description)),
            severity: "medium".to_string(),
            fingerprint: hash_text(format!(
                "complaint:{}:{}",
                now_rfc3339(),
                description.to_ascii_lowercase()
            )),
            summary: description.to_string(),
            details: json!({
                "subsystem": "user-complaint",
                "complaint_text": description,
                "collect_now": collect_now,
                "collection_report": collection_report.as_ref().map(complaint_collection_report),
            }),
            artifact: None,
            repo_root: None,
            ecosystem: None,
        };
        let finding_id = self.store.record_finding(&complaint_finding)?;
        let opportunity = self.store.get_opportunity_by_finding(finding_id)?;
        self.store
            .set_opportunity_state(opportunity.id, "local-only")?;
        let opportunity = self.store.get_opportunity(opportunity.id)?;

        let related = self.related_candidates_for_complaint(description, opportunity.id)?;
        let collection_report = collection_report.as_ref().map(complaint_collection_report);
        let proposal = proposal::create_complaint_plan_proposal(
            &self.store,
            &self.config,
            &opportunity,
            description,
            collection_report.as_ref(),
            &related,
        )?;

        Ok(ComplaintOutcome {
            opportunity,
            proposal,
            collection_report,
            related_opportunity_ids: related.iter().map(|item| item.opportunity.id).collect(),
            workspace_root: self.config.service.state_dir.clone(),
            used_overlay,
        })
    }

    pub fn run_loop(&self) -> Result<()> {
        loop {
            let report = self.collect_once()?;
            tracing::info!(
                capabilities = report.capabilities_seen,
                artifacts = report.artifacts_seen,
                findings = report.findings_seen,
                "completed collection cycle"
            );
            let participation = self.participation()?;
            if participation.state.mode.can_submit()
                && self.should_run_network_task(
                    "last_sync_at",
                    self.config.network.sync_interval_seconds,
                )
            {
                match self.sync() {
                    Ok(outcome) => {
                        if let Some(message) = network::server_upgrade_message(&outcome.hello) {
                            tracing::warn!(message = %message, "server recommends upgrading fixer");
                        }
                        tracing::info!(
                            items_uploaded = outcome.items_uploaded,
                            promoted_clusters = outcome.receipt.promoted_clusters,
                            "completed sync cycle"
                        );
                    }
                    Err(error) => tracing::warn!(error = %error, "sync cycle failed"),
                }
            }
            if participation.state.mode.can_work()
                && self.should_run_network_task(
                    "last_worker_run_at",
                    self.config.service.poll_interval_seconds,
                )
            {
                match self.worker_once() {
                    Ok(outcome) => {
                        if let Some(message) = network::server_upgrade_message(&outcome.hello) {
                            tracing::warn!(message = %message, "server recommends upgrading fixer");
                        }
                        tracing::info!(message = %outcome.offer.message, "completed worker poll");
                    }
                    Err(error) => tracing::warn!(error = %error, "worker poll failed"),
                }
            }
            thread::sleep(Duration::from_secs(
                self.config.service.poll_interval_seconds,
            ));
        }
    }

    pub fn validate(&self, opportunity_id: i64) -> Result<Vec<(String, String)>> {
        let opportunity = self.store.get_opportunity(opportunity_id)?;
        let workspace = ensure_workspace_for_opportunity(&self.config, &opportunity)?;
        let repo_root = workspace.repo_root;
        let insight = inspect_repo(&repo_root)
            .ok_or_else(|| anyhow!("no adapter matched {}", repo_root.display()))?;
        let mut results = Vec::new();
        for command in insight.validation {
            if !command_exists(&command.program) {
                let status = format!("missing `{}`", command.program);
                self.store.record_validation(
                    opportunity_id,
                    &command.render(),
                    "skipped",
                    &status,
                )?;
                results.push((command.render(), status));
                continue;
            }
            let output = Command::new(&command.program)
                .args(&command.args)
                .current_dir(&repo_root)
                .output()?;
            let status = if output.status.success() {
                "passed"
            } else {
                "failed"
            };
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            self.store
                .record_validation(opportunity_id, &command.render(), status, &combined)?;
            results.push((command.render(), status.to_string()));
        }
        Ok(results)
    }

    pub fn propose_fix(
        &self,
        opportunity_id: i64,
        engine: &str,
    ) -> Result<crate::models::ProposalRecord> {
        let opportunity = self.store.get_opportunity(opportunity_id)?;
        if engine == "deterministic" && proposal::supports_local_remediation(&opportunity) {
            return proposal::create_local_remediation_proposal(
                &self.store,
                &self.config,
                &opportunity,
            );
        }
        if engine == "deterministic"
            && proposal::supports_process_investigation_report(&opportunity)
        {
            return proposal::create_process_investigation_report_proposal(
                &self.store,
                &self.config,
                &opportunity,
                None,
            );
        }
        match ensure_workspace_for_opportunity(&self.config, &opportunity) {
            Ok(workspace) => proposal::create_proposal(
                &self.store,
                &self.config,
                &opportunity,
                &workspace,
                engine,
            ),
            Err(error) if engine == "deterministic" => {
                if proposal::supports_process_investigation_report(&opportunity) {
                    proposal::create_process_investigation_report_proposal(
                        &self.store,
                        &self.config,
                        &opportunity,
                        Some(&error.to_string()),
                    )
                } else {
                    proposal::create_external_report_proposal(
                        &self.store,
                        &self.config,
                        &opportunity,
                        &error.to_string(),
                    )
                }
            }
            Err(error) => Err(anyhow!(
                "{error}. Use `propose-fix {opportunity_id} --engine deterministic` to generate an external bug report instead."
            )),
        }
    }

    pub fn prepare_submit(&self, proposal_id: i64) -> Result<std::path::PathBuf> {
        proposal::prepare_submission(&self.store, proposal_id)
    }

    pub fn participation(&self) -> Result<ParticipationSnapshot> {
        network::participation_snapshot(&self.store, &self.config)
    }

    pub fn opt_in(
        &self,
        mode: ParticipationMode,
        richer_evidence_allowed: bool,
    ) -> Result<ParticipationSnapshot> {
        network::opt_in(&self.store, &self.config, mode, richer_evidence_allowed)
    }

    pub fn opt_out(&self) -> Result<ParticipationSnapshot> {
        network::opt_out(&self.store, &self.config)
    }

    pub fn sync(&self) -> Result<SyncOutcome> {
        network::sync_once(&self.store, &self.config)
    }

    pub fn worker_once(&self) -> Result<WorkerRunOutcome> {
        let outcome = network::worker_once(&self.store, &self.config)?;
        self.store
            .set_local_state("last_worker_run_at", &Utc::now().to_rfc3339())?;
        Ok(outcome)
    }

    fn should_run_network_task(&self, key: &str, interval_seconds: u64) -> bool {
        let last_run = self
            .store
            .get_local_state::<String>(key)
            .ok()
            .flatten()
            .and_then(|raw| DateTime::parse_from_rfc3339(&raw).ok())
            .map(|value| value.with_timezone(&Utc));
        last_run
            .map(|value| {
                Utc::now().signed_duration_since(value).num_seconds() >= interval_seconds as i64
            })
            .unwrap_or(true)
    }

    fn related_candidates_for_complaint(
        &self,
        description: &str,
        complaint_opportunity_id: i64,
    ) -> Result<Vec<SharedOpportunity>> {
        let keywords = tokenize_complaint_text(description);
        let mut candidates = self.store.list_submission_candidates(40)?;
        candidates.retain(|item| item.opportunity.id != complaint_opportunity_id);
        if keywords.is_empty() {
            candidates.truncate(5);
            return Ok(candidates);
        }

        let mut ranked = candidates
            .into_iter()
            .filter_map(|candidate| {
                let score = complaint_match_score(&keywords, &candidate);
                (score > 0).then_some((score, candidate))
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| right.1.opportunity.score.cmp(&left.1.opportunity.score))
        });
        let mut related = ranked
            .into_iter()
            .map(|(_, candidate)| candidate)
            .take(8)
            .collect::<Vec<_>>();
        if related.is_empty() {
            related = self
                .store
                .list_submission_candidates(5)?
                .into_iter()
                .filter(|item| item.opportunity.id != complaint_opportunity_id)
                .take(5)
                .collect();
        }
        Ok(related)
    }

    fn open_complaint_overlay(&self, description: &str) -> Result<Self> {
        let mut overlay_config = self.config.clone();
        let workspace_root = complaint_workspace_root(description);
        let database_path = workspace_root.join("fixer.sqlite3");
        let state_dir = workspace_root.join("state");

        fs::create_dir_all(&state_dir)?;
        if self.config.service.database_path.is_file() && !database_path.exists() {
            let _ = fs::copy(&self.config.service.database_path, &database_path);
        }

        overlay_config.service.database_path = database_path;
        overlay_config.service.state_dir = state_dir;
        Self::from_config(overlay_config)
    }
}

fn complaint_collection_report(report: &CollectReport) -> ComplaintCollectionReport {
    ComplaintCollectionReport {
        capabilities_seen: report.capabilities_seen,
        artifacts_seen: report.artifacts_seen,
        findings_seen: report.findings_seen,
    }
}

fn tokenize_complaint_text(input: &str) -> BTreeSet<String> {
    const STOP_WORDS: &[&str] = &[
        "the", "and", "that", "this", "with", "have", "from", "into", "when", "then", "after",
        "before", "just", "like", "does", "dont", "doesnt", "cant", "wont", "issue", "problem",
        "broken", "wrong", "please", "need", "make", "sure",
    ];
    input
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| token.len() >= 3)
        .filter(|token| !STOP_WORDS.contains(&token.as_str()))
        .collect()
}

fn complaint_match_score(keywords: &BTreeSet<String>, candidate: &SharedOpportunity) -> usize {
    let mut haystacks = vec![
        candidate.opportunity.title.to_ascii_lowercase(),
        candidate.opportunity.summary.to_ascii_lowercase(),
        candidate.finding.title.to_ascii_lowercase(),
        candidate.finding.summary.to_ascii_lowercase(),
        candidate.finding.details.to_string().to_ascii_lowercase(),
    ];
    if let Some(package_name) = candidate.finding.package_name.as_deref() {
        haystacks.push(package_name.to_ascii_lowercase());
    }
    if let Some(package_name) = candidate
        .opportunity
        .evidence
        .get("package_name")
        .and_then(serde_json::Value::as_str)
    {
        haystacks.push(package_name.to_ascii_lowercase());
    }

    let mut score = 0usize;
    for keyword in keywords {
        if haystacks.iter().any(|haystack| haystack.contains(keyword)) {
            score += 1;
        }
    }
    if keywords
        .iter()
        .any(|keyword| candidate.opportunity.kind.eq_ignore_ascii_case(keyword))
    {
        score += 1;
    }
    score
}

fn summarize_complaint(description: &str) -> String {
    let words = description.split_whitespace().collect::<Vec<_>>();
    if words.len() <= 8 {
        return description.to_string();
    }
    format!("{}...", words[..8].join(" "))
}

fn should_retry_complaint_in_overlay(error: &anyhow::Error) -> bool {
    is_permission_or_readonly_error(error)
}

fn is_permission_or_readonly_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let text = cause.to_string().to_ascii_lowercase();
        text.contains("readonly database")
            || text.contains("read-only database")
            || text.contains("permission denied")
    })
}

fn complaint_workspace_root(description: &str) -> PathBuf {
    let base = env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .unwrap_or_else(|| std::env::temp_dir().join("fixer-state"));
    let digest = hash_text(description.to_ascii_lowercase());
    let digest_prefix = &digest[..12];
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    base.join("fixer")
        .join("complaints")
        .join(format!("{timestamp}-{digest_prefix}"))
}

#[cfg(test)]
mod tests {
    use super::{
        complaint_match_score, complaint_workspace_root, is_permission_or_readonly_error,
        should_retry_complaint_in_overlay, tokenize_complaint_text,
    };
    use crate::models::{FindingRecord, OpportunityRecord, SharedOpportunity};
    use anyhow::anyhow;
    use serde_json::json;

    #[test]
    fn tokenizes_complaint_text_without_common_noise() {
        let tokens = tokenize_complaint_text("Chrome crashes when sharing screen after update");
        assert!(tokens.contains("chrome"));
        assert!(tokens.contains("crashes"));
        assert!(tokens.contains("sharing"));
        assert!(!tokens.contains("when"));
        assert!(!tokens.contains("after"));
    }

    #[test]
    fn complaint_matching_prefers_relevant_package_text() {
        let keywords = tokenize_complaint_text("chrome sharing screen crash");
        let candidate = SharedOpportunity {
            local_opportunity_id: 7,
            opportunity: OpportunityRecord {
                id: 7,
                finding_id: 11,
                kind: "crash".to_string(),
                title: "Crash with stack trace in chrome".to_string(),
                score: 90,
                state: "open".to_string(),
                summary: "Top frame: gpu process".to_string(),
                evidence: json!({"package_name": "google-chrome-stable"}),
                repo_root: None,
                ecosystem: None,
                created_at: "now".to_string(),
                updated_at: "now".to_string(),
            },
            finding: FindingRecord {
                id: 11,
                kind: "crash".to_string(),
                title: "Crash with stack trace in chrome".to_string(),
                severity: "high".to_string(),
                fingerprint: "abc".to_string(),
                summary: "gpu process died while sharing screen".to_string(),
                details: json!({"line": "sharing screen"}),
                artifact_name: Some("chrome".to_string()),
                artifact_path: None,
                package_name: Some("google-chrome-stable".to_string()),
                repo_root: None,
                ecosystem: None,
                first_seen: "now".to_string(),
                last_seen: "now".to_string(),
            },
        };
        assert!(complaint_match_score(&keywords, &candidate) >= 3);
    }

    #[test]
    fn readonly_errors_trigger_overlay_retry() {
        let error = anyhow!("attempt to write a readonly database");
        assert!(should_retry_complaint_in_overlay(&error));
        assert!(is_permission_or_readonly_error(&error));
    }

    #[test]
    fn complaint_workspace_root_is_stable_and_local() {
        let path = complaint_workspace_root("chrome is slow when opening tabs");
        let rendered = path.display().to_string();
        assert!(rendered.contains("fixer/complaints"));
        assert!(path.file_name().is_some());
    }
}
