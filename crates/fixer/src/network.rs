use crate::config::FixerConfig;
use crate::models::{
    ClientHello, FindingBundle, ImpossibleReason, InstallIdentity, ParticipationMode,
    ParticipationState, PatchAttempt, ServerHello, SharedOpportunity, SubmissionEnvelope,
    SubmissionReceipt, WorkOffer, WorkPullRequest, WorkerResultEnvelope,
};
use crate::pow::{mine_pow, verify_pow};
use crate::privacy::{consent_policy_digest, consent_policy_text, redact_string, redact_value};
use crate::proposal;
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

    let hello = post_json::<_, ServerHello>(
        config,
        "v1/install/hello",
        &build_client_hello(store, config, &participation.identity, &participation.state)?,
    )?;
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
        client: build_client_hello(store, config, &participation.identity, &participation.state)?,
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

    let opportunity = lease.issue.representative.opportunity.clone();
    let result = match ensure_workspace_for_opportunity(config, &opportunity) {
        Ok(workspace) => {
            match proposal::create_proposal(store, config, &opportunity, &workspace, "codex") {
                Ok(local_proposal) => {
                    let submission_bundle =
                        proposal::prepare_submission(store, local_proposal.id).ok();
                    WorkerResultEnvelope {
                        lease_id: lease.lease_id.clone(),
                        attempt: PatchAttempt {
                            cluster_id: lease.issue.id,
                            install_id: participation.identity.install_id.clone(),
                            outcome: "patch".to_string(),
                            state: local_proposal.state.clone(),
                            summary: if local_proposal.state == "ready" {
                                "Patch proposal created locally. Review it and submit it upstream if it looks correct."
                                    .to_string()
                            } else {
                                "Worker attempted a patch but the local proposal did not complete cleanly."
                                    .to_string()
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
                                "local_opportunity_id": opportunity.id,
                                "workspace": workspace,
                            }),
                            created_at: now_rfc3339(),
                        },
                        impossible_reason: None,
                        evidence_request: None,
                    }
                }
                Err(error) => build_impossible_result(
                    &participation.identity.install_id,
                    lease.issue.id,
                    &lease.lease_id,
                    "codex-execution",
                    &error.to_string(),
                    json!({"local_opportunity_id": opportunity.id}),
                ),
            }
        }
        Err(error) => build_impossible_result(
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
        ),
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
        version: env!("CARGO_PKG_VERSION").to_string(),
        mode: state.mode.clone(),
        hostname: current_hostname(),
        has_codex: capabilities.iter().any(|capability| capability == "codex"),
        capabilities,
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

fn build_impossible_result(
    install_id: &str,
    cluster_id: i64,
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
