use crate::adapters::inspect_repo;
use crate::capabilities::detect_capabilities;
use crate::collectors::{CollectReport, collect_once};
use crate::config::FixerConfig;
use crate::models::ParticipationMode;
use crate::network::{self, ParticipationSnapshot, SyncOutcome, WorkerRunOutcome};
use crate::proposal;
use crate::storage::Store;
use crate::util::command_exists;
use crate::workspace::ensure_workspace_for_opportunity;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use std::path::Path;
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
        config.ensure_parent_dirs()?;
        let store = Store::open(&config.service.database_path)?;
        store.sync_capabilities(&detect_capabilities())?;
        Ok(Self { config, store })
    }

    pub fn collect_once(&self) -> Result<CollectReport> {
        collect_once(&self.config, &self.store)
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
                    Ok(outcome) => tracing::info!(
                        items_uploaded = outcome.items_uploaded,
                        promoted_clusters = outcome.receipt.promoted_clusters,
                        "completed sync cycle"
                    ),
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
        match ensure_workspace_for_opportunity(&self.config, &opportunity) {
            Ok(workspace) => proposal::create_proposal(
                &self.store,
                &self.config,
                &opportunity,
                &workspace,
                engine,
            ),
            Err(error) if engine == "deterministic" => proposal::create_external_report_proposal(
                &self.store,
                &self.config,
                &opportunity,
                &error.to_string(),
            ),
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
}
