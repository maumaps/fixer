use crate::config::FixerConfig;
use crate::models::{
    ClientHello, CodexAuthLease, CodexAuthLeaseStatus, CodexAuthMode, CodexJobSpec, CodexJobStatus,
    CodexLeaseBudget, FindingBundle, FindingInput, ImpossibleReason, InstallIdentity,
    LeaseBudgetPreset, ObservedArtifact, OpportunityRecord, ParticipationMode, ParticipationState,
    PatchAttempt, ServerHello, SharedOpportunity, SubmissionEnvelope, SubmissionReceipt, WorkOffer,
    WorkPullRequest, WorkerResultEnvelope,
};
use crate::pow::{mine_pow, verify_pow};
use crate::privacy::{consent_policy_digest, consent_policy_text, redact_string, redact_value};
use crate::proposal;
use crate::protocol::{current_binary_version, default_protocol_version};
use crate::storage::Store;
use crate::util::{command_exists, hash_text, now_rfc3339, read_text};
use crate::workspace::ensure_workspace_for_opportunity;
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone)]
struct LocalUserAccount {
    user: String,
    uid: u32,
    home: PathBuf,
    shell: String,
}

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

pub fn bootstrap_codex_auth_user(
    store: &Store,
    config: &FixerConfig,
    user: &str,
    enable_linger: bool,
) -> Result<CodexAuthLeaseStatus> {
    require_local_admin_tools()?;
    if enable_linger {
        let status = Command::new("loginctl")
            .args(["enable-linger", user])
            .status()
            .with_context(|| format!("failed to enable linger for {user}"))?;
        if !status.success() {
            return Err(anyhow!("failed to enable linger for {user}"));
        }
    }
    let uid = lookup_uid(user)?;
    probe_user_codex_environment(user, uid)?;
    codex_auth_lease_status(store, config)
}

pub fn grant_codex_auth_lease(
    store: &Store,
    _config: &FixerConfig,
    user: &str,
    ttl_seconds: u64,
    budget_preset: LeaseBudgetPreset,
    allow_kernel: bool,
) -> Result<CodexAuthLease> {
    require_local_admin_tools()?;
    let uid = lookup_uid(user)?;
    probe_user_codex_environment(user, uid)?;
    let now = Utc::now();
    let lease = CodexAuthLease {
        user: user.to_string(),
        uid,
        granted_at: now.to_rfc3339(),
        expires_at: (now + ChronoDuration::seconds(ttl_seconds as i64)).to_rfc3339(),
        budget_preset: budget_preset.clone(),
        budget: lease_budget_for_preset(&budget_preset),
        allow_kernel,
        paused_reason: None,
        revoked_at: None,
        active_jobs: 0,
        jobs_started_day: now.format("%Y-%m-%d").to_string(),
        jobs_started_today: 0,
        recent_failures: Vec::new(),
    };
    store.save_codex_auth_lease(&lease)?;
    Ok(lease)
}

pub fn codex_auth_lease_status(
    store: &Store,
    config: &FixerConfig,
) -> Result<CodexAuthLeaseStatus> {
    let lease = store.load_codex_auth_lease()?;
    let mut notes = Vec::new();
    if config.patch.auth_mode != crate::models::CodexAuthMode::UserLease {
        notes.push("patch.auth_mode is not `user-lease`".to_string());
    }
    if let Some(lease) = &lease {
        if is_lease_revoked(lease) {
            notes.push("lease has been revoked".to_string());
        }
        if is_lease_expired(lease) {
            notes.push("lease has expired".to_string());
        }
        if let Some(reason) = lease.paused_reason.as_deref() {
            notes.push(format!("lease is paused: {reason}"));
        }
        if lease.budget_preset == LeaseBudgetPreset::Off {
            notes.push("lease budget preset is `off`".to_string());
        }
        match probe_user_codex_environment(&lease.user, lease.uid) {
            Ok(()) => {}
            Err(error) => notes.push(error.to_string()),
        }
    } else {
        notes.push("no active Codex auth lease is configured".to_string());
    }
    Ok(CodexAuthLeaseStatus {
        ready: notes.is_empty(),
        lease,
        notes,
    })
}

pub fn revoke_codex_auth_lease(store: &Store) -> Result<Option<CodexAuthLease>> {
    let Some(mut lease) = store.load_codex_auth_lease()? else {
        return Ok(None);
    };
    lease.revoked_at = Some(now_rfc3339());
    lease.paused_reason = Some("revoked by operator".to_string());
    lease.active_jobs = 0;
    store.save_codex_auth_lease(&lease)?;
    Ok(Some(lease))
}

fn require_local_admin_tools() -> Result<()> {
    for tool in ["runuser", "systemd-run", "getent", "chown"] {
        if !command_exists(tool) {
            return Err(anyhow!(
                "required local helper `{tool}` is not available for user-leased Codex jobs"
            ));
        }
    }
    Ok(())
}

fn lookup_user_account(user: &str) -> Result<LocalUserAccount> {
    let output = Command::new("getent")
        .args(["passwd", user])
        .output()
        .with_context(|| format!("failed to look up user `{user}`"))?;
    if !output.status.success() {
        return Err(anyhow!("could not find local user `{user}`"));
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    let line = raw
        .lines()
        .next()
        .ok_or_else(|| anyhow!("`getent passwd {user}` returned no rows"))?;
    let mut fields = line.split(':');
    let account_name = fields.next().unwrap_or_default().to_string();
    let _password = fields.next();
    let uid = fields
        .next()
        .ok_or_else(|| anyhow!("passwd entry for `{user}` is missing a uid"))?
        .parse::<u32>()
        .with_context(|| format!("passwd entry for `{user}` has an invalid uid"))?;
    let _gid = fields.next();
    let _gecos = fields.next();
    let home = fields
        .next()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("passwd entry for `{user}` is missing a home directory"))?;
    let shell = fields
        .next()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("/bin/sh")
        .to_string();
    Ok(LocalUserAccount {
        user: account_name,
        uid,
        home,
        shell,
    })
}

fn lookup_uid(user: &str) -> Result<u32> {
    Ok(lookup_user_account(user)?.uid)
}

fn user_runtime_dir(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{uid}"))
}

fn default_user_path(home: &Path) -> String {
    format!("{}/.local/bin:/usr/local/bin:/usr/bin:/bin", home.display())
}

fn resolve_user_login_path(account: &LocalUserAccount) -> Result<String> {
    let output = Command::new("runuser")
        .args([
            "-u",
            &account.user,
            "--",
            &account.shell,
            "-lc",
            "printf '%s' \"$PATH\"",
        ])
        .output()
        .with_context(|| format!("failed to resolve login PATH for {}", account.user))?;
    if !output.status.success() {
        return Ok(default_user_path(&account.home));
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        Ok(default_user_path(&account.home))
    } else {
        Ok(path)
    }
}

fn probe_user_codex_environment(user: &str, uid: u32) -> Result<()> {
    let account = lookup_user_account(user)?;
    if account.uid != uid {
        return Err(anyhow!(
            "lease for `{user}` expected uid {uid}, but the local account is {}",
            account.uid
        ));
    }
    let auth_path = account.home.join(".codex").join("auth.json");
    if !auth_path.exists() {
        return Err(anyhow!(
            "Codex auth was not found at {}; log in as `{}` before granting a lease",
            auth_path.display(),
            user
        ));
    }
    let runtime_dir = user_runtime_dir(uid);
    let bus_path = runtime_dir.join("bus");
    if !bus_path.exists() {
        return Err(anyhow!(
            "the user systemd manager for `{user}` is not available; log in as that user or enable linger"
        ));
    }
    let status = Command::new("runuser")
        .args(["-u", user, "--", "env"])
        .arg(format!("XDG_RUNTIME_DIR={}", runtime_dir.display()))
        .arg(format!(
            "DBUS_SESSION_BUS_ADDRESS=unix:path={}",
            bus_path.display()
        ))
        .arg("systemd-run")
        .args([
            "--user",
            "--wait",
            "--collect",
            "--pipe",
            "--quiet",
            "/usr/bin/true",
        ])
        .status()
        .with_context(|| format!("failed to probe the user systemd manager for `{user}`"))?;
    if !status.success() {
        return Err(anyhow!(
            "the user systemd manager for `{user}` is not ready to launch transient jobs"
        ));
    }
    Ok(())
}

fn lease_budget_for_preset(preset: &LeaseBudgetPreset) -> CodexLeaseBudget {
    match preset {
        LeaseBudgetPreset::Off => CodexLeaseBudget {
            max_active_jobs: 0,
            max_jobs_per_day: 0,
            job_timeout_seconds: 0,
        },
        LeaseBudgetPreset::Conservative => CodexLeaseBudget {
            max_active_jobs: 1,
            max_jobs_per_day: 6,
            job_timeout_seconds: 30 * 60,
        },
        LeaseBudgetPreset::Balanced => CodexLeaseBudget {
            max_active_jobs: 2,
            max_jobs_per_day: 18,
            job_timeout_seconds: 45 * 60,
        },
        LeaseBudgetPreset::Aggressive => CodexLeaseBudget {
            max_active_jobs: 4,
            max_jobs_per_day: 48,
            job_timeout_seconds: 60 * 60,
        },
    }
}

fn is_lease_revoked(lease: &CodexAuthLease) -> bool {
    lease.revoked_at.is_some()
}

fn is_lease_expired(lease: &CodexAuthLease) -> bool {
    DateTime::parse_from_rfc3339(&lease.expires_at)
        .map(|expires| expires.with_timezone(&Utc) <= Utc::now())
        .unwrap_or(true)
}

fn current_lease_day() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

fn reset_daily_budget_if_needed(lease: &mut CodexAuthLease) {
    let today = current_lease_day();
    if lease.jobs_started_day != today {
        lease.jobs_started_day = today;
        lease.jobs_started_today = 0;
    }
}

fn prune_recent_failures(lease: &mut CodexAuthLease, window_seconds: u64) {
    let cutoff = Utc::now() - ChronoDuration::seconds(window_seconds as i64);
    lease.recent_failures.retain(|failure| {
        DateTime::parse_from_rfc3339(&failure.occurred_at)
            .map(|time| time.with_timezone(&Utc) >= cutoff)
            .unwrap_or(false)
    });
}

fn begin_codex_auth_job(store: &Store) -> Result<CodexAuthLease> {
    let mut lease = store
        .load_codex_auth_lease()?
        .ok_or_else(|| anyhow!("no active Codex auth lease is configured"))?;
    if is_lease_revoked(&lease) {
        return Err(anyhow!("the current Codex auth lease has been revoked"));
    }
    if is_lease_expired(&lease) {
        return Err(anyhow!("the current Codex auth lease has expired"));
    }
    if let Some(reason) = lease.paused_reason.as_deref() {
        return Err(anyhow!("the current Codex auth lease is paused: {reason}"));
    }
    reset_daily_budget_if_needed(&mut lease);
    if lease.budget.max_active_jobs == 0 || lease.budget.max_jobs_per_day == 0 {
        return Err(anyhow!(
            "the current Codex auth lease budget is disabled (`{}`)",
            lease.budget_preset.as_str()
        ));
    }
    if lease.active_jobs >= lease.budget.max_active_jobs {
        return Err(anyhow!(
            "the current Codex auth lease is already using {} active jobs",
            lease.active_jobs
        ));
    }
    if lease.jobs_started_today >= lease.budget.max_jobs_per_day {
        return Err(anyhow!(
            "the current Codex auth lease has exhausted its daily budget ({})",
            lease.budget.max_jobs_per_day
        ));
    }
    lease.active_jobs += 1;
    lease.jobs_started_today += 1;
    store.save_codex_auth_lease(&lease)?;
    Ok(lease)
}

fn complete_codex_auth_job(
    store: &Store,
    config: &FixerConfig,
    status: Option<&CodexJobStatus>,
    command_failure: Option<&str>,
) -> Result<()> {
    let Some(mut lease) = store.load_codex_auth_lease()? else {
        return Ok(());
    };
    lease.active_jobs = lease.active_jobs.saturating_sub(1);
    prune_recent_failures(&mut lease, config.patch.lease_failure_pause_window_seconds);
    if let Some(status) = status {
        if let Some(kind) = status.failure_kind.as_deref() {
            lease
                .recent_failures
                .push(crate::models::CodexLeaseFailure {
                    occurred_at: now_rfc3339(),
                    kind: kind.to_string(),
                    message: status
                        .error
                        .clone()
                        .unwrap_or_else(|| "Codex job failed".to_string()),
                });
        } else {
            lease.recent_failures.clear();
        }
    } else if let Some(message) = command_failure {
        lease
            .recent_failures
            .push(crate::models::CodexLeaseFailure {
                occurred_at: now_rfc3339(),
                kind: "dispatch".to_string(),
                message: message.to_string(),
            });
    }
    prune_recent_failures(&mut lease, config.patch.lease_failure_pause_window_seconds);
    if lease.recent_failures.len() >= config.patch.lease_failure_pause_threshold as usize {
        lease.paused_reason = Some(format!(
            "auto-paused after {} recent Codex failures",
            lease.recent_failures.len()
        ));
    }
    store.save_codex_auth_lease(&lease)?;
    Ok(())
}

fn chown_path_recursive(user: &str, path: &Path) -> Result<()> {
    let ownership = format!("{user}:{user}");
    let status = Command::new("chown")
        .args(["-R", &ownership])
        .arg(path)
        .status()
        .with_context(|| format!("failed to hand {} to {}", path.display(), user))?;
    if !status.success() {
        return Err(anyhow!("failed to hand {} to {}", path.display(), user));
    }
    Ok(())
}

fn sanitize_unit_name(raw: &str) -> String {
    raw.chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => ch,
            _ => '-',
        })
        .collect()
}

fn read_codex_job_status(bundle_dir: &Path) -> Result<CodexJobStatus> {
    let path = bundle_dir.join("status.json");
    let raw = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

fn render_command_failure(output: &std::process::Output) -> String {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let trimmed = combined.trim();
    if trimmed.is_empty() {
        format!("exit status {}", output.status)
    } else {
        trimmed.to_string()
    }
}

fn run_codex_job_as_user(
    store: &Store,
    config: &FixerConfig,
    job: &CodexJobSpec,
) -> Result<CodexJobStatus> {
    require_local_admin_tools()?;
    let lease = begin_codex_auth_job(store)?;
    let result = (|| -> Result<CodexJobStatus> {
        let account = lookup_user_account(&lease.user)?;
        if account.uid != lease.uid {
            return Err(anyhow!(
                "lease for `{}` points at uid {}, but the local account resolved to {}",
                lease.user,
                lease.uid,
                account.uid
            ));
        }
        probe_user_codex_environment(&account.user, account.uid)?;
        chown_path_recursive(&account.user, &job.bundle_dir)?;
        let login_path = resolve_user_login_path(&account)?;
        let runtime_dir = user_runtime_dir(account.uid);
        let bus_path = runtime_dir.join("bus");
        let executable =
            std::env::current_exe().context("failed to resolve the fixer binary path")?;
        let auth_paths = [
            account.home.join(".codex"),
            account.home.join(".cache").join("codex"),
            account.home.join(".local").join("share").join("codex"),
        ];

        let mut command = Command::new("runuser");
        command.args(["-u", &account.user, "--", "env"]);
        command.arg(format!("XDG_RUNTIME_DIR={}", runtime_dir.display()));
        command.arg(format!(
            "DBUS_SESSION_BUS_ADDRESS=unix:path={}",
            bus_path.display()
        ));
        command.arg("systemd-run");
        command.args(["--user", "--wait", "--collect", "--pipe", "--quiet"]);
        command.arg(format!(
            "--unit=fixer-codex-{}",
            sanitize_unit_name(&job.job_id)
        ));
        command.arg(format!("--setenv=HOME={}", account.home.display()));
        command.arg(format!("--setenv=PATH={login_path}"));
        command.arg(format!(
            "--setenv=XDG_RUNTIME_DIR={}",
            runtime_dir.display()
        ));
        command.arg("-p").arg("NoNewPrivileges=yes");
        command.arg("-p").arg("PrivateTmp=yes");
        command.arg("-p").arg("ProtectSystem=strict");
        command.arg("-p").arg("ProtectHome=read-only");
        command.arg("-p").arg("RestrictSUIDSGID=yes");
        command.arg("-p").arg("ProtectControlGroups=yes");
        command.arg("-p").arg("ProtectKernelTunables=yes");
        command.arg("-p").arg("LockPersonality=yes");
        command.arg("-p").arg("UMask=0077");
        command.arg("-p").arg(format!(
            "WorkingDirectory={}",
            job.workspace.repo_root.display()
        ));
        command.arg("-p").arg(format!(
            "RuntimeMaxSec={}",
            lease.budget.job_timeout_seconds
        ));
        command
            .arg("-p")
            .arg(format!("ReadWritePaths={}", job.bundle_dir.display()));
        for path in auth_paths {
            command
                .arg("-p")
                .arg(format!("ReadWritePaths={}", path.display()));
        }
        command.arg(executable);
        command.arg("auth");
        command.arg("exec-job");
        command.arg("--job");
        command.arg(&job.bundle_dir);
        let output = command
            .output()
            .context("failed to launch the transient user-scoped Codex job")?;
        if !output.status.success() {
            return Err(anyhow!(
                "the transient user-scoped Codex job failed: {}",
                render_command_failure(&output)
            ));
        }
        read_codex_job_status(&job.bundle_dir)
    })();

    match result {
        Ok(status) => {
            complete_codex_auth_job(store, config, Some(&status), None)?;
            Ok(status)
        }
        Err(error) => {
            complete_codex_auth_job(store, config, None, Some(&error.to_string()))?;
            Err(error)
        }
    }
}

fn create_worker_codex_proposal(
    store: &Store,
    config: &FixerConfig,
    issue: &crate::models::IssueCluster,
    opportunity: &OpportunityRecord,
    workspace: &crate::models::PreparedWorkspace,
) -> Result<crate::models::ProposalRecord> {
    match config.patch.auth_mode {
        CodexAuthMode::RootDirect => proposal::create_proposal_with_prior_patch(
            store,
            config,
            opportunity,
            workspace,
            issue.best_patch.as_ref(),
            "codex",
        ),
        CodexAuthMode::UserLease => {
            let lease = store
                .load_codex_auth_lease()?
                .ok_or_else(|| anyhow!("no active Codex auth lease is configured"))?;
            let job = proposal::prepare_codex_job_with_prior_patch(
                config,
                opportunity,
                workspace,
                issue.best_patch.as_ref(),
                &lease.user,
                lease.allow_kernel,
            )?;
            let status = run_codex_job_as_user(store, config, &job)?;
            store.create_proposal(
                opportunity.id,
                "codex",
                &status.state,
                &job.bundle_dir,
                status.output_path.as_deref(),
            )
        }
    }
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
    if config.patch.auth_mode == CodexAuthMode::RootDirect
        && (!store.capability_available("codex")? || !command_exists(&config.patch.codex_command))
    {
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
            match create_worker_codex_proposal(
                store,
                config,
                &lease.issue,
                &opportunity,
                &workspace,
            ) {
                Ok(local_proposal) => {
                    let submission_bundle =
                        proposal::prepare_submission(store, local_proposal.id).ok();
                    let diagnosis_bundle = investigation_report
                        .as_ref()
                        .and_then(|report| proposal::prepare_submission(store, report.id).ok());
                    let mut details = serde_json::Map::from_iter([
                        ("local_proposal_id".to_string(), json!(local_proposal.id)),
                        (
                            "local_submission_bundle".to_string(),
                            json!(submission_bundle.map(|path| path.display().to_string())),
                        ),
                        (
                            "diagnosis_proposal_id".to_string(),
                            json!(investigation_report.as_ref().map(|report| report.id)),
                        ),
                        (
                            "diagnosis_submission_bundle".to_string(),
                            json!(diagnosis_bundle.map(|path| path.display().to_string())),
                        ),
                        (
                            "diagnosis_bundle_path".to_string(),
                            json!(
                                investigation_report
                                    .as_ref()
                                    .map(|report| report.bundle_path.display().to_string())
                            ),
                        ),
                        ("local_opportunity_id".to_string(), json!(opportunity.id)),
                        (
                            "diagnosis".to_string(),
                            process_investigation_worker_diagnosis(&opportunity),
                        ),
                        ("workspace".to_string(), json!(workspace)),
                        (
                            "worker_fixer_version".to_string(),
                            json!(current_binary_version()),
                        ),
                    ]);
                    if let Some(best_patch) = lease.issue.best_patch.as_ref() {
                        details.insert(
                            "supersedes_patch_created_at".to_string(),
                            json!(best_patch.created_at),
                        );
                        if let Some(version) = best_patch
                            .details
                            .get("worker_fixer_version")
                            .and_then(Value::as_str)
                            .or_else(|| {
                                best_patch
                                    .details
                                    .get("fixer_version")
                                    .and_then(Value::as_str)
                            })
                        {
                            details.insert(
                                "supersedes_patch_fixer_version".to_string(),
                                json!(version),
                            );
                        }
                    }
                    if let Ok(public_session) =
                        proposal::load_published_codex_session(&local_proposal.bundle_path)
                    {
                        details.insert("published_session".to_string(), public_session);
                    }
                    let published_session = details.get("published_session").cloned();
                    let published_session_ref = published_session.as_ref();
                    let is_triage_ready = local_proposal.state == "ready"
                        && !published_session_has_diff(published_session_ref)
                        && published_session_marks_successful_triage(published_session_ref);
                    if is_triage_ready {
                        details.insert(
                            "report_only_reason".to_string(),
                            json!(worker_triage_reason(published_session_ref)),
                        );
                        details.insert(
                            "handoff".to_string(),
                            worker_triage_handoff(&opportunity, published_session_ref),
                        );
                    }
                    WorkerResultEnvelope {
                        lease_id: lease.lease_id.clone(),
                        attempt: PatchAttempt {
                            cluster_id: lease.issue.id,
                            install_id: participation.identity.install_id.clone(),
                            outcome: if is_triage_ready {
                                "triage".to_string()
                            } else {
                                "patch".to_string()
                            },
                            state: local_proposal.state.clone(),
                            summary: if local_proposal.state == "ready" {
                                if is_triage_ready {
                                    if supports_process_report {
                                        format!(
                                            "{} A diagnosis report and external handoff were created locally.",
                                            process_investigation_worker_summary(&opportunity)
                                        )
                                    } else {
                                        "A diagnosis and external handoff were created locally. Review it and report it to the likely owner."
                                            .to_string()
                                    }
                                } else if supports_process_report {
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
                            details: Value::Object(details),
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

fn published_session_has_diff(session: Option<&Value>) -> bool {
    session
        .and_then(|value| value.get("diff"))
        .and_then(Value::as_str)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

fn published_session_response(session: Option<&Value>) -> Option<&str> {
    session
        .and_then(|value| value.get("response"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn published_session_marks_successful_triage(session: Option<&Value>) -> bool {
    let Some(response) = published_session_response(session) else {
        return false;
    };
    [
        "No source change landed.",
        "outside this repository",
        "outside this source tree",
        "speculative and unsafe",
        "no safe code change was made",
    ]
    .iter()
    .any(|marker| response.contains(marker))
}

fn worker_triage_reason(session: Option<&Value>) -> &'static str {
    let response = published_session_response(session).unwrap_or_default();
    if response.contains("outside this repository") || response.contains("outside this source tree")
    {
        "likely-external-root-cause"
    } else {
        "no-safe-local-change"
    }
}

fn worker_triage_handoff(
    opportunity: &crate::models::OpportunityRecord,
    session: Option<&Value>,
) -> Value {
    let diagnosis = process_investigation_worker_diagnosis(opportunity);
    let target = diagnosis
        .get("profile_target")
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            published_session_response(session).and_then(|response| {
                let shared_object_re =
                    regex::Regex::new(r"\b([A-Za-z0-9_.+-]+\.so)\b").expect("valid so regex");
                shared_object_re
                    .captures(response)
                    .and_then(|captures| captures.get(1))
                    .map(|value| format!("module `{}` or the workload driving it", value.as_str()))
            })
        })
        .unwrap_or_else(|| {
            "external dependency or workload outside the current source tree".to_string()
        });
    let report_url = diagnosis
        .get("package_metadata")
        .and_then(|value| value.get("report_url"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            diagnosis
                .get("package_metadata")
                .and_then(|value| value.get("homepage"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        });
    json!({
        "target": target,
        "report_url": report_url,
        "next_steps": [
            format!("Confirm the hotspot still points at {target} with a fresh perf sample before filing the bug."),
            "Capture the actual hot backend or child process rather than the parent service wrapper if the issue recurs.",
            format!("Map {target} to its owning package or project and file an upstream or distro bug with the summarized evidence."),
            "If the owner is still unclear, collect another short strace plus `/proc/<pid>/maps` at the moment of the spike.",
        ],
    })
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

    fn sample_lease(expires_at: &str) -> CodexAuthLease {
        CodexAuthLease {
            user: "kom".to_string(),
            uid: 1000,
            granted_at: "2026-03-29T12:00:00Z".to_string(),
            expires_at: expires_at.to_string(),
            budget_preset: LeaseBudgetPreset::Conservative,
            budget: lease_budget_for_preset(&LeaseBudgetPreset::Conservative),
            allow_kernel: false,
            paused_reason: None,
            revoked_at: None,
            active_jobs: 0,
            jobs_started_day: "2026-03-29".to_string(),
            jobs_started_today: 0,
            recent_failures: Vec::new(),
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
    fn lease_expiration_detects_past_due_leases() {
        let expired = sample_lease("2000-01-01T00:00:00Z");
        let active = sample_lease("2999-01-01T00:00:00Z");

        assert!(is_lease_expired(&expired));
        assert!(!is_lease_expired(&active));
    }

    #[test]
    fn conservative_budget_is_bounded() {
        let budget = lease_budget_for_preset(&LeaseBudgetPreset::Conservative);
        assert_eq!(budget.max_active_jobs, 1);
        assert!(budget.max_jobs_per_day > 0);
        assert!(budget.job_timeout_seconds >= 30 * 60);
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
