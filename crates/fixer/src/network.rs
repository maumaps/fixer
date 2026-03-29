use crate::config::FixerConfig;
use crate::models::{
    ClientHello, FindingBundle, FindingInput, ImpossibleReason, InstallIdentity, ObservedArtifact,
    OpportunityRecord, ParticipationMode, ParticipationState, PatchAttempt, ServerHello,
    SharedOpportunity, SubmissionEnvelope, SubmissionReceipt, WorkOffer, WorkPullRequest,
    WorkerResultEnvelope,
};
use crate::pow::{mine_pow, verify_pow};
use crate::privacy::{consent_policy_digest, consent_policy_text, redact_string, redact_value};
use crate::proposal;
use crate::protocol::{current_binary_version, default_protocol_version};
use crate::storage::Store;
use crate::util::{command_exists, hash_text, now_rfc3339, read_text};
use crate::workspace::ensure_workspace_for_opportunity;
use anyhow::{Context, Result, anyhow};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipationSnapshot {
    pub identity: InstallIdentity,
    pub state: ParticipationState,
    pub server_url: String,
    pub policy_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncOutcome {
    pub hello: ServerHello,
    pub receipt: SubmissionReceipt,
    pub items_uploaded: usize,
    pub redactions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRunOutcome {
    pub hello: ServerHello,
    pub offer: WorkOffer,
    pub result: Option<WorkerResultEnvelope>,
}

pub fn opt_in(
    store: &Store,
    config: &FixerConfig,
    mode: ParticipationMode,
    richer_evidence_allowed: bool,
) -> Result<ParticipationSnapshot> {
    let identity = store.ensure_install_identity()?;
    let state = ParticipationState {
        mode,
        consented_at: Some(now_rfc3339()),
        consent_policy_version: Some(config.privacy.policy_version.clone()),
        consent_policy_digest: Some(consent_policy_digest(&config.privacy.policy_version)),
        opt_out_at: None,
        richer_evidence_allowed,
    };
    store.save_participation_state(&state)?;
    Ok(ParticipationSnapshot {
        identity,
        state,
        server_url: config.network.server_url.clone(),
        policy_text: consent_policy_text(&config.privacy.policy_version),
    })
}

pub fn opt_out(store: &Store, config: &FixerConfig) -> Result<ParticipationSnapshot> {
    let identity = store.ensure_install_identity()?;
    let mut state = store
        .load_participation_state()?
        .unwrap_or_else(|| default_participation_state(config));
    state.mode = ParticipationMode::LocalOnly;
    state.opt_out_at = Some(now_rfc3339());
    store.save_participation_state(&state)?;
    Ok(ParticipationSnapshot {
        identity,
        state,
        server_url: config.network.server_url.clone(),
        policy_text: consent_policy_text(&config.privacy.policy_version),
    })
}

pub fn participation_snapshot(
    store: &Store,
    config: &FixerConfig,
) -> Result<ParticipationSnapshot> {
    Ok(ParticipationSnapshot {
        identity: store.ensure_install_identity()?,
        state: store
            .load_participation_state()?
            .unwrap_or_else(|| default_participation_state(config)),
        server_url: config.network.server_url.clone(),
        policy_text: consent_policy_text(&config.privacy.policy_version),
    })
}

pub fn sync_once(store: &Store, config: &FixerConfig) -> Result<SyncOutcome> {
    let participation = participation_snapshot(store, config)?;
    if config.privacy.require_opt_in_for_upload && !participation.state.mode.can_submit() {
        return Err(anyhow!(
            "network participation is disabled; run `fixer opt-in --mode submitter` or `submitter+worker` first"
        ));
    }
    let hello_request =
        build_client_hello(store, config, &participation.identity, &participation.state)?;

    let hello = post_json::<_, ServerHello>(config, "v1/install/hello", &hello_request)?;
    ensure_server_hello_compatible(&hello)?;
    let bundle = build_submission_bundle(store, config, &participation)?;
    if bundle.items.is_empty() {
        return Err(anyhow!("no opportunities available for submission"));
    }
    let content_hash = hash_text(serde_json::to_vec(&bundle)?);
    let proof = mine_pow(
        &participation.identity.install_id,
        &content_hash,
        hello
            .submission_pow_difficulty
            .max(config.network.submission_pow_difficulty),
    );
    let envelope = SubmissionEnvelope {
        client: hello_request,
        content_hash,
        proof_of_work: proof,
        bundle,
    };
    let receipt = post_json::<_, SubmissionReceipt>(config, "v1/submissions", &envelope)?;
    store.set_local_state("last_sync_at", &now_rfc3339())?;
    store.set_local_state("last_sync_receipt", &receipt)?;
    Ok(SyncOutcome {
        hello,
        receipt,
        items_uploaded: envelope.bundle.items.len(),
        redactions: envelope.bundle.redactions,
    })
}

pub fn worker_once(store: &Store, config: &FixerConfig) -> Result<WorkerRunOutcome> {
    let participation = participation_snapshot(store, config)?;
    if !participation.state.mode.can_work() {
        return Err(anyhow!(
            "worker participation is disabled; run `fixer opt-in --mode submitter+worker` first"
        ));
    }
    if !store.capability_available("codex")? || !command_exists(&config.patch.codex_command) {
        return Err(anyhow!(
            "Codex is not available on this host, so it cannot accept worker leases"
        ));
    }

    let hello_request =
        build_client_hello(store, config, &participation.identity, &participation.state)?;
    let hello = post_json::<_, ServerHello>(config, "v1/install/hello", &hello_request)?;
    ensure_server_hello_compatible(&hello)?;
    if !hello.worker_allowed {
        return Ok(WorkerRunOutcome {
            hello,
            offer: WorkOffer {
                message: "server says this install is not yet trusted for worker leases"
                    .to_string(),
                lease: None,
            },
            result: None,
        });
    }

    let work_payload_hash = hash_text(serde_json::to_vec(&hello_request)?);
    let work_request = WorkPullRequest {
        client: hello_request,
        proof_of_work: mine_pow(
            &participation.identity.install_id,
            &work_payload_hash,
            hello
                .worker_pow_difficulty
                .max(config.network.worker_pow_difficulty),
        ),
    };
    let offer = post_json::<_, WorkOffer>(config, "v1/work/pull", &work_request)?;
    let Some(lease) = offer.lease.clone() else {
        return Ok(WorkerRunOutcome {
            hello,
            offer,
            result: None,
        });
    };

    let opportunity = materialize_shared_opportunity(store, &lease.issue.representative)?;
    let supports_process_report = proposal::supports_process_investigation_report(&opportunity);
    if supports_process_report && process_investigation_prefers_report_only(&opportunity) {
        let report = proposal::create_process_investigation_report_proposal(
            store,
            config,
            &opportunity,
            Some(
                "the collected evidence points below user space, so Fixer skipped an automatic package patch attempt",
            ),
        )?;
        let submission_bundle = proposal::prepare_submission(store, report.id).ok();
        let result = WorkerResultEnvelope {
            lease_id: lease.lease_id.clone(),
            attempt: PatchAttempt {
                cluster_id: lease.issue.id,
                install_id: participation.identity.install_id.clone(),
                outcome: "report".to_string(),
                state: report.state.clone(),
                summary: format!(
                    "{} Fixer produced a diagnosis report and intentionally skipped a package patch attempt because the wait appears to be below user space.",
                    process_investigation_worker_summary(&opportunity)
                ),
                bundle_path: Some(report.bundle_path.display().to_string()),
                output_path: report
                    .output_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
                validation_status: Some(report.state.clone()),
                details: json!({
                    "local_proposal_id": report.id,
                    "local_submission_bundle": submission_bundle.map(|path| path.display().to_string()),
                    "local_opportunity_id": opportunity.id,
                    "diagnosis": process_investigation_worker_diagnosis(&opportunity),
                    "report_only_reason": "likely-external-root-cause",
                }),
                created_at: now_rfc3339(),
            },
            impossible_reason: None,
            evidence_request: None,
        };
        let endpoint = format!("v1/work/{}/result", lease.lease_id);
        let submitted = post_json::<_, WorkerResultEnvelope>(config, &endpoint, &result)?;
        store.set_local_state("last_worker_result", &submitted)?;
        return Ok(WorkerRunOutcome {
            hello,
            offer,
            result: Some(submitted),
        });
    }
    let result = match ensure_workspace_for_opportunity(config, &opportunity) {
        Ok(workspace) => {
            let investigation_report = if supports_process_report {
                proposal::create_process_investigation_report_proposal(
                    store,
                    config,
                    &opportunity,
                    None,
                )
                .ok()
            } else {
                None
            };
            match proposal::create_proposal(store, config, &opportunity, &workspace, "codex") {
                Ok(local_proposal) => {
                    let submission_bundle =
                        proposal::prepare_submission(store, local_proposal.id).ok();
                    let diagnosis_bundle = investigation_report
                        .as_ref()
                        .and_then(|report| proposal::prepare_submission(store, report.id).ok());
                    WorkerResultEnvelope {
                        lease_id: lease.lease_id.clone(),
                        attempt: PatchAttempt {
                            cluster_id: lease.issue.id,
                            install_id: participation.identity.install_id.clone(),
                            outcome: "patch".to_string(),
                            state: local_proposal.state.clone(),
                            summary: if local_proposal.state == "ready" {
                                if supports_process_report {
                                    format!(
                                        "{} A diagnosis report and patch proposal were created locally.",
                                        process_investigation_worker_summary(&opportunity)
                                    )
                                } else {
                                    "Patch proposal created locally. Review it and submit it upstream if it looks correct."
                                        .to_string()
                                }
                            } else {
                                if supports_process_report {
                                    format!(
                                        "{} The diagnosis was captured, but the patch proposal did not complete cleanly.",
                                        process_investigation_worker_summary(&opportunity)
                                    )
                                } else {
                                    "Worker attempted a patch but the local proposal did not complete cleanly."
                                        .to_string()
                                }
                            },
                            bundle_path: Some(local_proposal.bundle_path.display().to_string()),
                            output_path: local_proposal
                                .output_path
                                .as_ref()
                                .map(|path| path.display().to_string()),
                            validation_status: Some(local_proposal.state.clone()),
                            details: json!({
                                "local_proposal_id": local_proposal.id,
                                "local_submission_bundle": submission_bundle.map(|path| path.display().to_string()),
                                "diagnosis_proposal_id": investigation_report.as_ref().map(|report| report.id),
                                "diagnosis_submission_bundle": diagnosis_bundle.map(|path| path.display().to_string()),
                                "diagnosis_bundle_path": investigation_report.as_ref().map(|report| report.bundle_path.display().to_string()),
                                "local_opportunity_id": opportunity.id,
                                "diagnosis": process_investigation_worker_diagnosis(&opportunity),
                                "workspace": workspace,
                            }),
                            created_at: now_rfc3339(),
                        },
                        impossible_reason: None,
                        evidence_request: None,
                    }
                }
                Err(error) => {
                    if let Some(report) = investigation_report {
                        let submission_bundle = proposal::prepare_submission(store, report.id).ok();
                        WorkerResultEnvelope {
                            lease_id: lease.lease_id.clone(),
                            attempt: PatchAttempt {
                                cluster_id: lease.issue.id,
                                install_id: participation.identity.install_id.clone(),
                                outcome: "report".to_string(),
                                state: report.state.clone(),
                                summary: format!(
                                    "{} A diagnosis report was created, but the patch attempt failed to run cleanly: {}",
                                    process_investigation_worker_summary(&opportunity),
                                    error
                                ),
                                bundle_path: Some(report.bundle_path.display().to_string()),
                                output_path: report
                                    .output_path
                                    .as_ref()
                                    .map(|path| path.display().to_string()),
                                validation_status: Some(report.state.clone()),
                                details: json!({
                                    "local_proposal_id": report.id,
                                    "local_submission_bundle": submission_bundle.map(|path| path.display().to_string()),
                                    "local_opportunity_id": opportunity.id,
                                    "diagnosis": process_investigation_worker_diagnosis(&opportunity),
                                    "patch_error": error.to_string(),
                                    "workspace": workspace,
                                }),
                                created_at: now_rfc3339(),
                            },
                            impossible_reason: None,
                            evidence_request: None,
                        }
                    } else {
                        build_impossible_result(
                            &participation.identity.install_id,
                            lease.issue.id,
                            &lease.lease_id,
                            "codex-execution",
                            &error.to_string(),
                            json!({"local_opportunity_id": opportunity.id}),
                        )
                    }
                }
            }
        }
        Err(error) => {
            if supports_process_report {
                match proposal::create_process_investigation_report_proposal(
                    store,
                    config,
                    &opportunity,
                    Some(&error.to_string()),
                ) {
                    Ok(report) => {
                        let submission_bundle = proposal::prepare_submission(store, report.id).ok();
                        WorkerResultEnvelope {
                            lease_id: lease.lease_id.clone(),
                            attempt: PatchAttempt {
                                cluster_id: lease.issue.id,
                                install_id: participation.identity.install_id.clone(),
                                outcome: "report".to_string(),
                                state: report.state.clone(),
                                summary: format!(
                                    "{} A diagnosis report was created even though no patchable workspace was available.",
                                    process_investigation_worker_summary(&opportunity)
                                ),
                                bundle_path: Some(report.bundle_path.display().to_string()),
                                output_path: report
                                    .output_path
                                    .as_ref()
                                    .map(|path| path.display().to_string()),
                                validation_status: Some(report.state.clone()),
                                details: json!({
                                    "local_proposal_id": report.id,
                                    "local_submission_bundle": submission_bundle.map(|path| path.display().to_string()),
                                    "local_opportunity_id": opportunity.id,
                                    "diagnosis": process_investigation_worker_diagnosis(&opportunity),
                                    "workspace_error": error.to_string(),
                                }),
                                created_at: now_rfc3339(),
                            },
                            impossible_reason: None,
                            evidence_request: None,
                        }
                    }
                    Err(report_error) => build_impossible_result(
                        &participation.identity.install_id,
                        lease.issue.id,
                        &lease.lease_id,
                        "workspace-acquisition",
                        &format!("{error}; failed to create diagnostic report: {report_error}"),
                        json!({
                            "local_opportunity_id": opportunity.id,
                            "package_name": opportunity.evidence.get("package_name"),
                            "repo_root": opportunity.repo_root.as_ref().map(|path| path.display().to_string()),
                            "diagnosis": process_investigation_worker_diagnosis(&opportunity),
                        }),
                    ),
                }
            } else {
                build_impossible_result(
                    &participation.identity.install_id,
                    lease.issue.id,
                    &lease.lease_id,
                    "workspace-acquisition",
                    &error.to_string(),
                    json!({
                        "local_opportunity_id": opportunity.id,
                        "package_name": opportunity.evidence.get("package_name"),
                        "repo_root": opportunity.repo_root.as_ref().map(|path| path.display().to_string()),
                    }),
                )
            }
        }
    };

    let endpoint = format!("v1/work/{}/result", lease.lease_id);
    let submitted = post_json::<_, WorkerResultEnvelope>(config, &endpoint, &result)?;
    store.set_local_state("last_worker_result", &submitted)?;
    Ok(WorkerRunOutcome {
        hello,
        offer,
        result: Some(submitted),
    })
}

fn build_submission_bundle(
    store: &Store,
    config: &FixerConfig,
    participation: &ParticipationSnapshot,
) -> Result<FindingBundle> {
    let status = store.status()?;
    let capabilities = store.list_capabilities()?;
    let mut redactions = Vec::new();
    let items = store
        .list_submission_candidates(config.network.max_submission_items)?
        .into_iter()
        .map(|item| redact_shared_opportunity(item, &mut redactions))
        .collect::<Vec<_>>();
    redactions.sort();
    redactions.dedup();
    Ok(FindingBundle {
        captured_at: now_rfc3339(),
        policy_version: participation
            .state
            .consent_policy_version
            .clone()
            .unwrap_or_else(|| config.privacy.policy_version.clone()),
        richer_evidence_allowed: participation.state.richer_evidence_allowed,
        status,
        capabilities,
        items,
        redactions,
    })
}

fn redact_shared_opportunity(
    item: SharedOpportunity,
    redactions: &mut Vec<String>,
) -> SharedOpportunity {
    let (finding_title, finding_title_notes) = redact_string(&item.finding.title);
    let (finding_summary, finding_summary_notes) = redact_string(&item.finding.summary);
    let (details, detail_notes) = redact_value(&item.finding.details);
    let (op_title, op_title_notes) = redact_string(&item.opportunity.title);
    let (op_summary, op_summary_notes) = redact_string(&item.opportunity.summary);
    let (evidence, evidence_notes) = redact_value(&item.opportunity.evidence);
    let (artifact_name, artifact_name_notes) = item
        .finding
        .artifact_name
        .as_deref()
        .map(redact_string)
        .map(|(value, notes)| (Some(value), notes))
        .unwrap_or((None, Vec::new()));
    redactions.extend(finding_title_notes);
    redactions.extend(finding_summary_notes);
    redactions.extend(detail_notes);
    redactions.extend(op_title_notes);
    redactions.extend(op_summary_notes);
    redactions.extend(evidence_notes);
    redactions.extend(artifact_name_notes);

    SharedOpportunity {
        local_opportunity_id: item.local_opportunity_id,
        opportunity: crate::models::OpportunityRecord {
            title: op_title,
            summary: op_summary,
            evidence,
            ..item.opportunity
        },
        finding: crate::models::FindingRecord {
            title: finding_title,
            summary: finding_summary,
            details,
            artifact_name,
            ..item.finding
        },
    }
}

fn materialize_shared_opportunity(
    store: &Store,
    item: &SharedOpportunity,
) -> Result<OpportunityRecord> {
    let artifact = if item.finding.artifact_name.is_some()
        || item.finding.artifact_path.is_some()
        || item.finding.package_name.is_some()
        || item.finding.repo_root.is_some()
        || item.finding.ecosystem.is_some()
    {
        Some(ObservedArtifact {
            kind: "shared-artifact".to_string(),
            name: item
                .finding
                .artifact_name
                .clone()
                .unwrap_or_else(|| item.finding.title.clone()),
            path: item.finding.artifact_path.clone(),
            package_name: item.finding.package_name.clone(),
            repo_root: item
                .finding
                .repo_root
                .clone()
                .or_else(|| item.opportunity.repo_root.clone()),
            ecosystem: item
                .finding
                .ecosystem
                .clone()
                .or_else(|| item.opportunity.ecosystem.clone()),
            metadata: json!({
                "source": "shared-opportunity",
                "remote_local_opportunity_id": item.local_opportunity_id,
                "remote_opportunity_id": item.opportunity.id,
                "remote_finding_id": item.finding.id,
            }),
        })
    } else {
        None
    };

    let finding_id = store.record_finding(&FindingInput {
        kind: item.finding.kind.clone(),
        title: item.finding.title.clone(),
        severity: item.finding.severity.clone(),
        fingerprint: item.finding.fingerprint.clone(),
        summary: item.finding.summary.clone(),
        details: item.finding.details.clone(),
        artifact,
        repo_root: item
            .finding
            .repo_root
            .clone()
            .or_else(|| item.opportunity.repo_root.clone()),
        ecosystem: item
            .finding
            .ecosystem
            .clone()
            .or_else(|| item.opportunity.ecosystem.clone()),
    })?;
    store.get_opportunity_by_finding(finding_id)
}

fn build_client_hello(
    store: &Store,
    _config: &FixerConfig,
    identity: &InstallIdentity,
    state: &ParticipationState,
) -> Result<ClientHello> {
    let capabilities = store
        .list_capabilities()?
        .into_iter()
        .filter(|capability| capability.available)
        .map(|capability| capability.name)
        .collect::<Vec<_>>();
    Ok(ClientHello {
        install_id: identity.install_id.clone(),
        version: current_binary_version().to_string(),
        protocol_version: default_protocol_version(),
        mode: state.mode.clone(),
        hostname: current_hostname(),
        has_codex: capabilities.iter().any(|capability| capability == "codex"),
        capabilities,
        richer_evidence_allowed: state.richer_evidence_allowed,
    })
}

fn current_hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| read_text(Path::new("/etc/hostname")).map(|value| value.trim().to_string()))
}

fn default_participation_state(config: &FixerConfig) -> ParticipationState {
    ParticipationState {
        mode: config.participation.mode.clone(),
        richer_evidence_allowed: config.participation.richer_evidence_allowed,
        ..ParticipationState::default()
    }
}

fn http_client(config: &FixerConfig) -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(config.network.connect_timeout_seconds))
        .build()
        .context("failed to build HTTP client")
}

fn endpoint_url(config: &FixerConfig, path: &str) -> Result<Url> {
    let base = Url::parse(&config.network.server_url)
        .with_context(|| format!("invalid server URL {}", config.network.server_url))?;
    base.join(path)
        .with_context(|| format!("invalid endpoint path {path}"))
}

fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
    config: &FixerConfig,
    path: &str,
    payload: &T,
) -> Result<R> {
    let url = endpoint_url(config, path)?;
    let response = http_client(config)?
        .post(url)
        .json(payload)
        .send()
        .with_context(|| format!("failed to POST {path}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        return Err(anyhow!("server returned {status}: {body}"));
    }
    response
        .json()
        .with_context(|| format!("failed to parse {path} response"))
}

fn ensure_server_hello_compatible(hello: &ServerHello) -> Result<()> {
    if hello.upgrade_required {
        let message = server_upgrade_message(hello)
            .unwrap_or("the server requires this client to upgrade before continuing");
        return Err(anyhow!(message.to_string()));
    }
    Ok(())
}

pub fn server_upgrade_message(hello: &ServerHello) -> Option<&str> {
    if !hello.upgrade_available && !hello.upgrade_required {
        return None;
    }
    let message = hello.upgrade_message.trim();
    (!message.is_empty()).then_some(message)
}

fn process_investigation_worker_summary(opportunity: &crate::models::OpportunityRecord) -> String {
    let details = process_investigation_worker_diagnosis(opportunity);
    let target = details
        .get("profile_target")
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("the process");
    let classification = details
        .get("loop_classification")
        .and_then(Value::as_str)
        .unwrap_or("unknown-investigation")
        .replace('-', " ");
    if details.get("subsystem").and_then(Value::as_str) == Some("stuck-process") {
        format!("{target} likely remains stuck in a {classification} wait.")
    } else {
        format!("{target} likely remains stuck in a {classification} loop.")
    }
}

fn process_investigation_worker_diagnosis(opportunity: &crate::models::OpportunityRecord) -> Value {
    opportunity
        .evidence
        .get("details")
        .cloned()
        .unwrap_or_else(|| json!({}))
}

fn process_investigation_prefers_report_only(
    opportunity: &crate::models::OpportunityRecord,
) -> bool {
    let details = process_investigation_worker_diagnosis(opportunity);
    details
        .get("likely_external_root_cause")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn build_impossible_result(
    install_id: &str,
    cluster_id: String,
    lease_id: &str,
    category: &str,
    summary: &str,
    details: Value,
) -> WorkerResultEnvelope {
    WorkerResultEnvelope {
        lease_id: lease_id.to_string(),
        attempt: PatchAttempt {
            cluster_id,
            install_id: install_id.to_string(),
            outcome: "impossible".to_string(),
            state: "explained".to_string(),
            summary: format!("Worker could not make a safe patch: {summary}"),
            bundle_path: None,
            output_path: None,
            validation_status: None,
            details: details.clone(),
            created_at: now_rfc3339(),
        },
        impossible_reason: Some(ImpossibleReason {
            category: category.to_string(),
            summary: summary.to_string(),
            details,
        }),
        evidence_request: None,
    }
}

pub fn verify_worker_pull_pow(
    install_id: &str,
    request: &WorkPullRequest,
    required_difficulty: u32,
) -> bool {
    let payload_hash = hash_text(serde_json::to_vec(&request.client).unwrap_or_default());
    verify_pow(
        install_id,
        &request.proof_of_work,
        &payload_hash,
        required_difficulty,
        30,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{FindingRecord, OpportunityRecord};
    use crate::storage::Store;
    use serde_json::json;
    use tempfile::tempdir;

    fn sample_server_hello() -> ServerHello {
        ServerHello {
            policy_version: "2026-03-29".to_string(),
            submission_pow_difficulty: 1,
            worker_pow_difficulty: 1,
            server_protocol_version: 1,
            min_supported_protocol_version: 1,
            latest_client_version: crate::protocol::current_binary_version().to_string(),
            upgrade_available: false,
            upgrade_required: false,
            upgrade_message: String::new(),
            install_trust_score: 1,
            quarantined: false,
            worker_allowed: true,
            message: "ok".to_string(),
            server_time: "2026-03-29T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn compatible_server_hello_allows_work_to_continue() {
        assert!(ensure_server_hello_compatible(&sample_server_hello()).is_ok());
    }

    #[test]
    fn incompatible_server_hello_stops_the_client() {
        let mut hello = sample_server_hello();
        hello.upgrade_required = true;
        hello.upgrade_message = "Upgrade fixer before syncing.".to_string();

        let error = ensure_server_hello_compatible(&hello).unwrap_err();
        assert!(error.to_string().contains("Upgrade fixer"));
    }

    #[test]
    fn server_upgrade_message_only_surfaces_upgrade_notices() {
        let mut hello = sample_server_hello();
        assert!(server_upgrade_message(&hello).is_none());

        hello.upgrade_available = true;
        hello.upgrade_message = format!(
            "Fixer {} is available.",
            crate::protocol::current_binary_version()
        );
        assert_eq!(
            server_upgrade_message(&hello),
            Some(hello.upgrade_message.as_str())
        );
    }

    #[test]
    fn materializing_shared_opportunities_uses_local_ids() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("fixer.sqlite")).unwrap();
        let finding_id = store
            .record_finding(&FindingInput {
                kind: "investigation".to_string(),
                title: "Runaway CPU investigation for packagekitd".to_string(),
                severity: "high".to_string(),
                fingerprint: "shared-fingerprint".to_string(),
                summary: "packagekitd is spinning".to_string(),
                details: json!({"subsystem": "runaway-process"}),
                artifact: Some(ObservedArtifact {
                    kind: "binary".to_string(),
                    name: "packagekitd".to_string(),
                    path: Some("/usr/libexec/packagekitd".into()),
                    package_name: Some("packagekit".to_string()),
                    repo_root: None,
                    ecosystem: None,
                    metadata: json!({}),
                }),
                repo_root: None,
                ecosystem: None,
            })
            .unwrap();
        let local = store.get_opportunity_by_finding(finding_id).unwrap();

        let shared = SharedOpportunity {
            local_opportunity_id: 594,
            opportunity: OpportunityRecord {
                id: 594,
                finding_id: 594,
                kind: "investigation".to_string(),
                title: local.title.clone(),
                score: 106,
                state: "open".to_string(),
                summary: local.summary.clone(),
                evidence: local.evidence.clone(),
                repo_root: None,
                ecosystem: None,
                created_at: "2026-03-29T00:00:00Z".to_string(),
                updated_at: "2026-03-29T00:00:00Z".to_string(),
            },
            finding: FindingRecord {
                id: 594,
                kind: "investigation".to_string(),
                title: local.title.clone(),
                severity: "high".to_string(),
                fingerprint: "shared-fingerprint".to_string(),
                summary: "packagekitd is spinning".to_string(),
                details: json!({"subsystem": "runaway-process"}),
                artifact_name: Some("packagekitd".to_string()),
                artifact_path: Some("/usr/libexec/packagekitd".into()),
                package_name: Some("packagekit".to_string()),
                repo_root: None,
                ecosystem: None,
                first_seen: "2026-03-29T00:00:00Z".to_string(),
                last_seen: "2026-03-29T00:00:00Z".to_string(),
            },
        };

        let materialized = materialize_shared_opportunity(&store, &shared).unwrap();
        assert_eq!(materialized.id, local.id);
        assert_ne!(materialized.id, shared.opportunity.id);
    }
}
