use crate::config::FixerConfig;
use crate::models::{
    ClientHello, CodexAuthLease, CodexAuthLeaseStatus, CodexAuthMode, CodexJobSpec, CodexJobStatus,
    CodexLeaseBudget, FindingBundle, FindingInput, ImpossibleReason, InstallIdentity,
    LeaseBudgetPreset, ObservedArtifact, OpportunityRecord, ParticipationMode, ParticipationState,
    PatchAttempt, PatchDriver, ProposalRecord, ServerHello, SharedOpportunity, SubmissionEnvelope,
    SubmissionReceipt, SubmittedProposal, WorkOffer, WorkPullRequest, WorkerResultEnvelope,
};
use crate::pow::{mine_pow, verify_pow};
use crate::privacy::{consent_policy_digest, consent_policy_text, redact_string, redact_value};
use crate::proposal;
use crate::protocol::{current_binary_version, default_protocol_version};
use crate::storage::Store;
use crate::util::{command_exists, hash_text, now_rfc3339, read_text};
use crate::workspace::{ensure_workspace_for_opportunity, origin_is_debian_source_friendly};
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;
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

const LOCAL_WORKER_BLOCKER_HISTORY_KEY: &str = "worker_local_blocker_history";
const MAX_LOCAL_WORKER_BLOCKERS: usize = 64;
const MAX_CLIENT_SUBMISSION_BUNDLE_BYTES: usize = 384 * 1024;
const SUBMITTED_WORKER_RESULT_MARKER: &str = "submitted-worker-result.json";
const UNRECOVERABLE_WORKER_RESULT_MARKER: &str = "unrecoverable-worker-result.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalWorkerBlocker {
    cluster_id: String,
    blocker_kind: String,
    blocker_reason: String,
    error: String,
    created_at: String,
    cooldown_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct LocalWorkerBlockerHistory {
    entries: Vec<LocalWorkerBlocker>,
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

#[derive(Debug, Clone)]
struct CodexWorkerAvailability {
    ready: bool,
    reason: Option<String>,
}

fn codex_worker_availability(
    store: &Store,
    config: &FixerConfig,
) -> Result<CodexWorkerAvailability> {
    match config.patch.driver {
        PatchDriver::Claude => {
            let ready = command_exists(&config.patch.claude_command);
            return Ok(CodexWorkerAvailability {
                ready,
                reason: (!ready).then(|| "Claude CLI is not installed on this host".to_string()),
            });
        }
        PatchDriver::Gemini => {
            let ready = command_exists(&config.patch.gemini_command);
            return Ok(CodexWorkerAvailability {
                ready,
                reason: (!ready).then(|| "Gemini CLI is not installed on this host".to_string()),
            });
        }
        PatchDriver::Aider => {
            let ready = command_exists(&config.patch.aider_command);
            return Ok(CodexWorkerAvailability {
                ready,
                reason: (!ready).then(|| "aider is not installed on this host".to_string()),
            });
        }
        PatchDriver::Codex => {}
    }
    let has_codex_binary =
        store.capability_available("codex")? || command_exists(&config.patch.codex_command);
    if !has_codex_binary {
        return Ok(CodexWorkerAvailability {
            ready: false,
            reason: Some("Codex is not installed on this host".to_string()),
        });
    }

    match config.patch.auth_mode {
        CodexAuthMode::RootDirect => Ok(CodexWorkerAvailability {
            ready: true,
            reason: None,
        }),
        CodexAuthMode::UserLease => {
            let status = codex_auth_lease_status(store, config)?;
            Ok(CodexWorkerAvailability {
                ready: status.ready,
                reason: (!status.ready).then(|| {
                    format!(
                        "Codex auth lease is not ready on this host: {}",
                        status.notes.join("; ")
                    )
                }),
            })
        }
    }
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

fn codex_state_dir_paths(home: &Path) -> [PathBuf; 2] {
    [
        home.join(".cache").join("codex"),
        home.join(".local").join("share").join("codex"),
    ]
}

fn running_as_root() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|raw| {
            raw.lines().find_map(|line| {
                let suffix = line.strip_prefix("Uid:")?;
                suffix.split_whitespace().next()?.parse::<u32>().ok()
            })
        })
        == Some(0)
}

fn ensure_user_owned_dir_chain(user: &str, root: &Path, target: &Path) -> Result<()> {
    let relative = target.strip_prefix(root).with_context(|| {
        format!(
            "failed to prepare Codex state path {} outside {}",
            target.display(),
            root.display()
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        if current.exists() {
            if current.is_dir() {
                continue;
            }
            return Err(anyhow!(
                "Codex state path {} exists but is not a directory",
                current.display()
            ));
        }
        fs::create_dir(&current)
            .with_context(|| format!("failed to create {}", current.display()))?;
        if running_as_root() {
            chown_path_recursive(user, &current)?;
        }
    }
    Ok(())
}

fn ensure_codex_state_dirs(account: &LocalUserAccount) -> Result<()> {
    for path in codex_state_dir_paths(&account.home) {
        ensure_user_owned_dir_chain(&account.user, &account.home, &path)?;
    }
    Ok(())
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
    ensure_codex_state_dirs(&account)?;
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

fn observed_active_codex_jobs(lease: &CodexAuthLease) -> Result<Option<u32>> {
    let machine = format!("{}@.host", lease.user);
    let output = Command::new("systemctl")
        .args([
            "--machine",
            &machine,
            "--user",
            "list-units",
            "fixer-codex-*",
            "--type=service",
            "--state=running,activating",
            "--plain",
            "--no-legend",
            "--no-pager",
        ])
        .output();
    let output = match output {
        Ok(output) => output,
        Err(_) => return Ok(None),
    };
    if !output.status.success() {
        return Ok(None);
    }
    let count = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    Ok(Some(count as u32))
}

fn reconcile_codex_auth_job_count(store: &Store, lease: &mut CodexAuthLease) -> Result<()> {
    let Some(observed_jobs) = observed_active_codex_jobs(lease)? else {
        return Ok(());
    };
    if observed_jobs != lease.active_jobs {
        lease.active_jobs = observed_jobs;
        store.save_codex_auth_lease(lease)?;
    }
    Ok(())
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
    reconcile_codex_auth_job_count(store, &mut lease)?;
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

pub(crate) fn run_codex_job_as_user(
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
        let cache_home = account.home.join(".cache");
        let data_home = account.home.join(".local").join("share");
        let [cache_dir, data_dir] = codex_state_dir_paths(&account.home);
        let executable =
            std::env::current_exe().context("failed to resolve the fixer binary path")?;
        let auth_paths = [account.home.join(".codex"), cache_dir, data_dir];

        let mut command = Command::new("runuser");
        command.args(["-u", &account.user, "--", "env"]);
        command.arg(format!("XDG_RUNTIME_DIR={}", runtime_dir.display()));
        command.arg(format!("XDG_CACHE_HOME={}", cache_home.display()));
        command.arg(format!("XDG_DATA_HOME={}", data_home.display()));
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
        command.arg(format!("--setenv=XDG_CACHE_HOME={}", cache_home.display()));
        command.arg(format!("--setenv=XDG_DATA_HOME={}", data_home.display()));
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
        proposal::load_codex_job_status(&job.bundle_dir)
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
    lease_id: &str,
    install_id: &str,
    issue: &crate::models::IssueCluster,
    opportunity: &OpportunityRecord,
    workspace: &crate::models::PreparedWorkspace,
) -> Result<crate::models::ProposalRecord> {
    let tool_name = match config.patch.driver {
        PatchDriver::Codex => "codex",
        PatchDriver::Claude => "claude",
        PatchDriver::Gemini => "gemini",
        PatchDriver::Aider => "aider",
    };
    match config.patch.driver {
        PatchDriver::Claude | PatchDriver::Gemini | PatchDriver::Aider => {
            proposal::create_proposal_with_prior_patch(
                store,
                config,
                opportunity,
                workspace,
                issue.best_patch.as_ref(),
                tool_name,
            )
        }
        PatchDriver::Codex => match config.patch.auth_mode {
            CodexAuthMode::RootDirect => proposal::create_proposal_with_prior_patch(
                store,
                config,
                opportunity,
                workspace,
                issue.best_patch.as_ref(),
                tool_name,
            ),
            CodexAuthMode::UserLease => {
                let lease = store
                    .load_codex_auth_lease()?
                    .ok_or_else(|| anyhow!("no active Codex auth lease is configured"))?;
                let mut job = proposal::prepare_codex_job_with_prior_patch(
                    config,
                    opportunity,
                    workspace,
                    issue.best_patch.as_ref(),
                    &lease.user,
                    lease.allow_kernel,
                )?;
                job.worker_lease_id = Some(lease_id.to_string());
                job.worker_issue_id = Some(issue.id.clone());
                job.worker_install_id = Some(install_id.to_string());
                fs::write(
                    job.bundle_dir.join("job.json"),
                    serde_json::to_vec_pretty(&job)?,
                )?;
                let status = run_codex_job_as_user(store, config, &job)?;
                store.create_proposal(
                    opportunity.id,
                    tool_name,
                    &status.state,
                    &job.bundle_dir,
                    status.output_path.as_deref(),
                )
            }
        },
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
    let bundle = fit_submission_bundle_to_payload_budget(build_submission_bundle(
        store,
        config,
        &participation,
    )?)?;
    if bundle.items.is_empty() && bundle.proposals.is_empty() {
        return Err(anyhow!(
            "no opportunities or ready proposals available for submission"
        ));
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
    remember_synced_issue_links(store, &envelope.bundle, &receipt)?;
    remember_published_proposals(store, &envelope.bundle)?;
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
    let codex_worker = codex_worker_availability(store, config)?;
    if !codex_worker.ready {
        return Err(anyhow!(
            "{}",
            codex_worker.reason.unwrap_or_else(|| {
                "Codex worker is not ready on this host, so it cannot accept worker leases"
                    .to_string()
            })
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
    if let Some(recovered) = recover_unpublished_worker_result(config, &participation)? {
        let endpoint = format!("v1/work/{}/result", recovered.lease_id);
        match post_json::<_, WorkerResultEnvelope>(config, &endpoint, &recovered.result) {
            Ok(submitted) => {
                mark_worker_result_submitted(&recovered.bundle_dir, &submitted)?;
                store.set_local_state("last_worker_result", &submitted)?;
                return Ok(WorkerRunOutcome {
                    hello,
                    offer: WorkOffer {
                        message: format!(
                            "published completed local worker bundle {} before requesting fresh work",
                            recovered.bundle_dir.display()
                        ),
                        lease: None,
                    },
                    result: Some(submitted),
                });
            }
            Err(error) if is_expired_worker_result_error(&error) => {
                mark_worker_result_unrecoverable(&recovered.bundle_dir, &recovered.result, &error)?;
                store.clear_local_state("last_worker_result")?;
            }
            Err(error) => return Err(error),
        }
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
    let mut offer = post_json::<_, WorkOffer>(config, "v1/work/pull", &work_request)?;
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
                &lease.lease_id,
                &participation.identity.install_id,
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
                    if let Ok(job_status) =
                        proposal::load_codex_job_status(&local_proposal.bundle_path)
                    {
                        append_job_status_details(&mut details, &job_status);
                    }
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
                    let invalidates_prior_patch = prior_patch_review_rejected_for_refresh(
                        &local_proposal,
                        lease.issue.best_patch.as_ref(),
                    );
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
                    if let Some(status) = invalidates_prior_patch.as_ref() {
                        details.insert("invalidates_best_patch".to_string(), json!(true));
                        details.insert("report_only_reason".to_string(), json!("stale-best-patch"));
                        if let Some(best_patch) = lease.issue.best_patch.as_ref() {
                            details.insert(
                                "invalidates_patch_created_at".to_string(),
                                json!(best_patch.created_at.clone()),
                            );
                        }
                        if let Some(kind) = status.failure_kind.as_deref() {
                            details.insert("patch_refresh_failure_kind".to_string(), json!(kind));
                        }
                        if let Some(error) = status.error.as_deref() {
                            details.insert("patch_refresh_error".to_string(), json!(error));
                        }
                    }
                    WorkerResultEnvelope {
                        lease_id: lease.lease_id.clone(),
                        attempt: PatchAttempt {
                            cluster_id: lease.issue.id,
                            install_id: participation.identity.install_id.clone(),
                            outcome: if is_triage_ready {
                                "triage".to_string()
                            } else if invalidates_prior_patch.is_some() {
                                "report".to_string()
                            } else {
                                "patch".to_string()
                            },
                            state: if invalidates_prior_patch.is_some() {
                                "ready".to_string()
                            } else {
                                local_proposal.state.clone()
                            },
                            summary: if invalidates_prior_patch.is_some() {
                                if supports_process_report {
                                    format!(
                                        "{} Fixer re-reviewed the previous patch, found it stale or incorrect, and reopened the issue for another pass. No replacement patch survived review yet.",
                                        process_investigation_worker_summary(&opportunity)
                                    )
                                } else {
                                    "Fixer re-reviewed the previous patch, found it stale or incorrect, and reopened the issue for another pass. No replacement patch survived review yet."
                                        .to_string()
                                }
                            } else if local_proposal.state == "ready" {
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
                            validation_status: Some(if invalidates_prior_patch.is_some() {
                                "review-rejected".to_string()
                            } else {
                                local_proposal.state.clone()
                            }),
                            details: Value::Object(details),
                            created_at: now_rfc3339(),
                        },
                        impossible_reason: None,
                        evidence_request: None,
                    }
                }
                Err(error) => {
                    if let Some(report) = investigation_report {
                        let patch_error = error.to_string();
                        if supports_process_report
                            && !should_publish_process_investigation_blocker(&patch_error)
                        {
                            let blocker =
                                record_local_worker_blocker(store, &lease.issue.id, &patch_error)?;
                            offer.message = format!(
                                "worker lease {} hit a local blocker on this host ({}); Fixer recorded it and reported the diagnosis once so the shared queue can cool down",
                                lease.lease_id, blocker.blocker_reason
                            );
                        }
                        let _ = proposal::annotate_process_investigation_report_blocker(
                            &report.bundle_path,
                            &patch_error,
                        );
                        let submission_bundle = proposal::prepare_submission(store, report.id).ok();
                        WorkerResultEnvelope {
                            lease_id: lease.lease_id.clone(),
                            attempt: PatchAttempt {
                                cluster_id: lease.issue.id,
                                install_id: participation.identity.install_id.clone(),
                                outcome: "report".to_string(),
                                state: report.state.clone(),
                                summary: process_investigation_blocked_patch_summary(
                                    &opportunity,
                                    &patch_error,
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
                                    "patch_error": patch_error,
                                    "automatic_patch_blocker_kind": proposal::process_investigation_blocker_kind(&patch_error),
                                    "report_only_reason": process_investigation_report_only_reason_for_error(&patch_error),
                                    "workspace": workspace,
                                    "local_blocker_cooldown_seconds": process_investigation_blocker_cooldown_seconds(&patch_error),
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
                        let workspace_error = error.to_string();
                        let workspace_classification =
                            workspace_blocker_classification(&opportunity, &workspace_error);
                        let handoff = workspace_classification
                            .as_ref()
                            .map(|_| workspace_blocked_handoff(&opportunity, &workspace_error));
                        WorkerResultEnvelope {
                            lease_id: lease.lease_id.clone(),
                            attempt: PatchAttempt {
                                cluster_id: lease.issue.id,
                                install_id: participation.identity.install_id.clone(),
                                outcome: "report".to_string(),
                                state: report.state.clone(),
                                summary: process_investigation_blocked_patch_summary(
                                    &opportunity,
                                    &workspace_error,
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
                                    "workspace_error": workspace_error,
                                    "automatic_patch_blocker_kind": proposal::process_investigation_blocker_kind(&workspace_error),
                                    "report_only_reason": process_investigation_report_only_reason_for_error(&workspace_error),
                                    "workspace_classification": workspace_classification,
                                    "workspace_acquisition_note": format!("Fixer could not prepare a patchable workspace: {}", error),
                                    "handoff": handoff,
                                }),
                                created_at: now_rfc3339(),
                            },
                            impossible_reason: None,
                            evidence_request: None,
                        }
                    }
                    Err(report_error) => build_internal_only_impossible_result(
                        &participation.identity.install_id,
                        lease.issue.id,
                        &lease.lease_id,
                        "workspace-acquisition",
                        "Fixer hit an internal error while recording the diagnosis for this workspace failure",
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
    let submitted = match post_json::<_, WorkerResultEnvelope>(config, &endpoint, &result) {
        Ok(submitted) => submitted,
        Err(error) if is_expired_worker_result_error(&error) => {
            if let Some(bundle_path) = result.attempt.bundle_path.as_deref() {
                let _ = mark_worker_result_unrecoverable(Path::new(bundle_path), &result, &error);
            }
            store.clear_local_state("last_worker_result")?;
            return Err(error.context(
                "worker lease expired after the local patch attempt completed; \
                 the result was marked unrecoverable so the next worker run can request fresh work",
            ));
        }
        Err(error) => return Err(error),
    };
    if let Some(bundle_path) = result.attempt.bundle_path.as_deref() {
        let _ = mark_worker_result_submitted(Path::new(bundle_path), &submitted);
    }
    store.set_local_state("last_worker_result", &submitted)?;
    Ok(WorkerRunOutcome {
        hello,
        offer,
        result: Some(submitted),
    })
}

#[derive(Debug)]
struct RecoverableWorkerResult {
    lease_id: String,
    bundle_dir: PathBuf,
    result: WorkerResultEnvelope,
}

fn recover_unpublished_worker_result(
    config: &FixerConfig,
    participation: &ParticipationSnapshot,
) -> Result<Option<RecoverableWorkerResult>> {
    let proposals_root = config.service.state_dir.join("proposals");
    if !proposals_root.exists() {
        return Ok(None);
    }
    let mut bundle_dirs = fs::read_dir(&proposals_root)?
        .filter_map(|entry| entry.ok().map(|item| item.path()))
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    bundle_dirs.sort();
    bundle_dirs.reverse();
    for bundle_dir in bundle_dirs.into_iter().take(32) {
        if bundle_dir.join(SUBMITTED_WORKER_RESULT_MARKER).exists()
            || bundle_dir.join(UNRECOVERABLE_WORKER_RESULT_MARKER).exists()
        {
            continue;
        }
        let job = match proposal::load_codex_job(&bundle_dir) {
            Ok(job) => job,
            Err(_) => continue,
        };
        let Some(lease_id) = job.worker_lease_id.clone() else {
            continue;
        };
        let Some(issue_id) = job.worker_issue_id.clone() else {
            continue;
        };
        let status = match proposal::load_codex_job_status(&bundle_dir) {
            Ok(status) => status,
            Err(_) => continue,
        };
        if status.state != "ready" && status.state != "failed" {
            continue;
        }
        let evidence_raw = match fs::read(bundle_dir.join("evidence.json")) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        let evidence: Value = match serde_json::from_slice(&evidence_raw) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let opportunity: OpportunityRecord = match evidence
            .get("opportunity")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
        {
            Some(opportunity) => opportunity,
            None => continue,
        };
        let supports_process_report = proposal::supports_process_investigation_report(&opportunity);
        let mut details = serde_json::Map::from_iter([
            ("local_opportunity_id".to_string(), json!(opportunity.id)),
            (
                "worker_fixer_version".to_string(),
                json!(current_binary_version()),
            ),
            (
                "recovered_unpublished_bundle".to_string(),
                json!(bundle_dir.display().to_string()),
            ),
        ]);
        if let Some(workspace) = evidence
            .get("source_workspace")
            .cloned()
            .or_else(|| evidence.get("workspace").cloned())
        {
            details.insert("workspace".to_string(), workspace);
        }
        if supports_process_report {
            details.insert(
                "diagnosis".to_string(),
                process_investigation_worker_diagnosis(&opportunity),
            );
        }
        append_job_status_details(&mut details, &status);
        if let Ok(public_session) = proposal::load_published_codex_session(&bundle_dir) {
            details.insert("published_session".to_string(), public_session);
        }
        let published_session = details.get("published_session").cloned();
        let is_triage_ready = status.state == "ready"
            && !published_session_has_diff(published_session.as_ref())
            && published_session_marks_successful_triage(published_session.as_ref());
        if is_triage_ready {
            details.insert(
                "report_only_reason".to_string(),
                json!(worker_triage_reason(published_session.as_ref())),
            );
            details.insert(
                "handoff".to_string(),
                worker_triage_handoff(&opportunity, published_session.as_ref()),
            );
        }
        let summary = if status.state == "ready" {
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
        } else if supports_process_report {
            format!(
                "{} The diagnosis was captured, but the patch proposal did not complete cleanly.",
                process_investigation_worker_summary(&opportunity)
            )
        } else {
            "Worker attempted a patch but the local proposal did not complete cleanly.".to_string()
        };
        return Ok(Some(RecoverableWorkerResult {
            lease_id: lease_id.clone(),
            bundle_dir: bundle_dir.clone(),
            result: WorkerResultEnvelope {
                lease_id,
                attempt: PatchAttempt {
                    cluster_id: issue_id,
                    install_id: job
                        .worker_install_id
                        .clone()
                        .unwrap_or_else(|| participation.identity.install_id.clone()),
                    outcome: if is_triage_ready {
                        "triage".to_string()
                    } else {
                        "patch".to_string()
                    },
                    state: status.state.clone(),
                    summary,
                    bundle_path: Some(bundle_dir.display().to_string()),
                    output_path: status
                        .output_path
                        .as_ref()
                        .map(|path| path.display().to_string()),
                    validation_status: Some(status.state.clone()),
                    details: Value::Object(details),
                    created_at: status.finished_at.clone(),
                },
                impossible_reason: None,
                evidence_request: None,
            },
        }));
    }
    Ok(None)
}

fn mark_worker_result_submitted(bundle_dir: &Path, submitted: &WorkerResultEnvelope) -> Result<()> {
    fs::write(
        bundle_dir.join(SUBMITTED_WORKER_RESULT_MARKER),
        serde_json::to_vec_pretty(submitted)?,
    )?;
    Ok(())
}

fn mark_worker_result_unrecoverable(
    bundle_dir: &Path,
    result: &WorkerResultEnvelope,
    error: &anyhow::Error,
) -> Result<()> {
    fs::write(
        bundle_dir.join(UNRECOVERABLE_WORKER_RESULT_MARKER),
        serde_json::to_vec_pretty(&json!({
            "marked_at": now_rfc3339(),
            "reason": error.to_string(),
            "result": result,
        }))?,
    )?;
    Ok(())
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
        .map(canonicalize_shared_opportunity)
        .map(|item| redact_shared_opportunity(item, &mut redactions))
        .collect::<Vec<_>>();
    let proposals = build_submission_proposals(store, config, participation, &items)?;
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
        proposals,
        redactions,
    })
}

fn fit_submission_bundle_to_payload_budget(mut bundle: FindingBundle) -> Result<FindingBundle> {
    while serde_json::to_vec(&bundle)?.len() > MAX_CLIENT_SUBMISSION_BUNDLE_BYTES {
        if bundle.proposals.pop().is_some() {
            continue;
        }
        if bundle.items.pop().is_some() {
            continue;
        }
        break;
    }
    Ok(bundle)
}

fn build_submission_proposals(
    store: &Store,
    config: &FixerConfig,
    participation: &ParticipationSnapshot,
    items: &[SharedOpportunity],
) -> Result<Vec<SubmittedProposal>> {
    let mut proposals = Vec::new();
    let mut used_bytes = 0_usize;
    let item_ids = items
        .iter()
        .map(|item| item.local_opportunity_id)
        .collect::<std::collections::HashSet<_>>();

    for item in items {
        if proposals.len() >= config.network.max_submission_proposals {
            break;
        }
        let Some(local_proposal) =
            store.latest_ready_codex_proposal_for_opportunity(item.local_opportunity_id)?
        else {
            continue;
        };
        let remote_issue_id = store.synced_issue_link(item.local_opportunity_id)?;
        let Some(result) = submission_result_for_local_proposal(
            participation,
            &item.opportunity,
            &local_proposal,
            remote_issue_id.as_deref(),
        )?
        else {
            continue;
        };
        let candidate = SubmittedProposal {
            local_opportunity_id: item.local_opportunity_id,
            local_proposal_id: local_proposal.id,
            remote_issue_id,
            result,
        };
        if !proposal_needs_publication(store, &candidate)? {
            continue;
        }
        if !push_submission_proposal(&mut proposals, &mut used_bytes, config, candidate)? {
            break;
        }
    }

    for (local_proposal, remote_issue_id) in store
        .list_latest_ready_codex_proposals_with_issue_links(
            config.network.max_submission_proposals,
        )?
    {
        if proposals.len() >= config.network.max_submission_proposals {
            break;
        }
        if item_ids.contains(&local_proposal.opportunity_id) {
            continue;
        }
        let opportunity = match store.get_opportunity(local_proposal.opportunity_id) {
            Ok(opportunity) => opportunity,
            Err(_) => continue,
        };
        let Some(result) = submission_result_for_local_proposal(
            participation,
            &opportunity,
            &local_proposal,
            Some(&remote_issue_id),
        )?
        else {
            continue;
        };
        let candidate = SubmittedProposal {
            local_opportunity_id: local_proposal.opportunity_id,
            local_proposal_id: local_proposal.id,
            remote_issue_id: Some(remote_issue_id),
            result,
        };
        if !proposal_needs_publication(store, &candidate)? {
            continue;
        }
        if !push_submission_proposal(&mut proposals, &mut used_bytes, config, candidate)? {
            break;
        }
    }

    Ok(proposals)
}

fn push_submission_proposal(
    proposals: &mut Vec<SubmittedProposal>,
    used_bytes: &mut usize,
    config: &FixerConfig,
    candidate: SubmittedProposal,
) -> Result<bool> {
    let candidate_bytes = serde_json::to_vec(&candidate)?.len();
    if candidate_bytes > config.network.max_submission_proposal_bytes {
        return Ok(false);
    }
    if !proposals.is_empty()
        && used_bytes.saturating_add(candidate_bytes) > config.network.max_submission_proposal_bytes
    {
        return Ok(false);
    }
    *used_bytes = used_bytes.saturating_add(candidate_bytes);
    proposals.push(candidate);
    Ok(true)
}

fn submission_result_for_local_proposal(
    participation: &ParticipationSnapshot,
    opportunity: &OpportunityRecord,
    local_proposal: &ProposalRecord,
    remote_issue_id: Option<&str>,
) -> Result<Option<WorkerResultEnvelope>> {
    let status = match proposal::load_codex_job_status(&local_proposal.bundle_path) {
        Ok(status) => status,
        Err(_) => return Ok(None),
    };
    if status.state != "ready" {
        return Ok(None);
    }

    let supports_process_report = proposal::supports_process_investigation_report(opportunity);
    let mut details = serde_json::Map::from_iter([
        ("local_opportunity_id".to_string(), json!(opportunity.id)),
        (
            "worker_fixer_version".to_string(),
            json!(current_binary_version()),
        ),
        ("submitted_via_sync".to_string(), json!(true)),
    ]);
    append_job_status_details(&mut details, &status);
    if supports_process_report {
        details.insert(
            "diagnosis".to_string(),
            process_investigation_worker_diagnosis(opportunity),
        );
    }
    if let Ok(public_session) = proposal::load_published_codex_session(&local_proposal.bundle_path)
    {
        details.insert("published_session".to_string(), public_session);
    }
    let published_session = details.get("published_session").cloned();
    if let Some(remote_issue_id) = remote_issue_id {
        details.insert("remote_issue_id".to_string(), json!(remote_issue_id));
    }
    append_public_patch_quality_details(
        &mut details,
        &status,
        published_session.as_ref(),
        &local_proposal.bundle_path,
        remote_issue_id,
    );
    if published_session.is_none() {
        return Ok(None);
    }
    let is_triage_ready = !published_session_has_diff(published_session.as_ref())
        && published_session_marks_successful_triage(published_session.as_ref());
    if is_triage_ready {
        details.insert(
            "report_only_reason".to_string(),
            json!(worker_triage_reason(published_session.as_ref())),
        );
        details.insert(
            "handoff".to_string(),
            worker_triage_handoff(opportunity, published_session.as_ref()),
        );
    }
    let summary = if is_triage_ready {
        if supports_process_report {
            format!(
                "{} A diagnosis report and external handoff were created locally.",
                process_investigation_worker_summary(opportunity)
            )
        } else {
            "A diagnosis and external handoff were created locally. Review it and report it to the likely owner."
                .to_string()
        }
    } else if supports_process_report {
        format!(
            "{} A diagnosis report and patch proposal were created locally.",
            process_investigation_worker_summary(opportunity)
        )
    } else {
        "Patch proposal created locally. Review it and submit it upstream if it looks correct."
            .to_string()
    };

    Ok(Some(WorkerResultEnvelope {
        lease_id: String::new(),
        attempt: PatchAttempt {
            cluster_id: String::new(),
            install_id: participation.identity.install_id.clone(),
            outcome: if is_triage_ready {
                "triage".to_string()
            } else {
                "patch".to_string()
            },
            state: status.state.clone(),
            summary,
            bundle_path: Some(local_proposal.bundle_path.display().to_string()),
            output_path: status
                .output_path
                .as_ref()
                .map(|path| path.display().to_string()),
            validation_status: Some(status.state.clone()),
            details: Value::Object(details),
            created_at: status.finished_at.clone(),
        },
        impossible_reason: None,
        evidence_request: None,
    }))
}

fn remember_synced_issue_links(
    store: &Store,
    bundle: &FindingBundle,
    receipt: &SubmissionReceipt,
) -> Result<()> {
    for (item, issue_id) in bundle.items.iter().zip(receipt.issue_ids.iter()) {
        store.save_synced_issue_link(item.local_opportunity_id, issue_id)?;
    }
    Ok(())
}

fn remember_published_proposals(store: &Store, bundle: &FindingBundle) -> Result<()> {
    for proposal in &bundle.proposals {
        let Some(remote_issue_id) = proposal.remote_issue_id.as_deref() else {
            continue;
        };
        let Some(session) = proposal.result.attempt.details.get("published_session") else {
            continue;
        };
        store.mark_proposal_published(
            proposal.local_proposal_id,
            remote_issue_id,
            &hash_text(serde_json::to_vec(session)?),
        )?;
    }
    Ok(())
}

fn proposal_needs_publication(store: &Store, candidate: &SubmittedProposal) -> Result<bool> {
    let Some(remote_issue_id) = candidate.remote_issue_id.as_deref() else {
        return Ok(true);
    };
    let Some(session) = candidate.result.attempt.details.get("published_session") else {
        return Ok(true);
    };
    let session_hash = hash_text(serde_json::to_vec(session)?);
    let prior = store.proposal_publication_marker(candidate.local_proposal_id)?;
    Ok(!matches!(
        prior,
        Some((ref published_issue_id, ref published_hash))
            if published_issue_id == remote_issue_id && published_hash == &session_hash
    ))
}

fn append_public_patch_quality_details(
    details: &mut serde_json::Map<String, Value>,
    status: &CodexJobStatus,
    published_session: Option<&Value>,
    bundle_dir: &Path,
    remote_issue_id: Option<&str>,
) {
    let published_diff_present = published_session_has_diff(published_session);
    let response = published_session_response(published_session).unwrap_or_default();
    let validation_quality = if !published_diff_present {
        "not-run"
    } else if response.contains("Ran `cmake --build")
        && response.contains("successfully")
        && !response.contains("could not")
        && !response.contains("failed")
    {
        "passed"
    } else if response.contains("Could not complete")
        || response.contains("failed during configure")
        || response.contains("I could not")
    {
        "blocked"
    } else if status.state == "ready" {
        "partial"
    } else {
        "blocked"
    };
    details.insert(
        "published_diff_present".to_string(),
        json!(published_diff_present),
    );
    details.insert("validation_quality".to_string(), json!(validation_quality));
    details.insert(
        "review_rounds_completed".to_string(),
        json!(count_review_rounds(bundle_dir)),
    );
    details.insert(
        "review_findings_resolved".to_string(),
        json!(count_resolved_review_findings(bundle_dir)),
    );
    if published_diff_present && remote_issue_id.is_some() {
        details.insert("supersedes_best_patch".to_string(), json!(true));
        details.insert(
            "supersedence_reason".to_string(),
            json!("newer-ready-proposal-for-existing-public-issue"),
        );
        if let Some(created_at) = prior_best_patch_created_at_from_bundle(bundle_dir) {
            details.insert("supersedes_patch_created_at".to_string(), json!(created_at));
        }
    }
}

fn count_review_rounds(bundle_dir: &Path) -> usize {
    fs::read_dir(bundle_dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("review-") && name.ends_with("-output.txt"))
        })
        .count()
}

fn count_resolved_review_findings(bundle_dir: &Path) -> usize {
    let has_fix_needed = fs::read_dir(bundle_dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .any(|entry| {
            let is_review_output = entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("review-") && name.ends_with("-output.txt"));
            is_review_output
                && read_text(&entry.path())
                    .map(|text| text.contains("RESULT: fix-needed"))
                    .unwrap_or(false)
        });
    let final_review_ok = read_text(&bundle_dir.join("codex-output.txt"))
        .map(|text| text.contains("RESULT: ok"))
        .unwrap_or(false);
    usize::from(has_fix_needed && final_review_ok)
}

fn prior_best_patch_created_at_from_bundle(bundle_dir: &Path) -> Option<String> {
    let evidence = read_text(&bundle_dir.join("evidence.json"))?;
    let value = serde_json::from_str::<Value>(&evidence).ok()?;
    value
        .get("prior_best_patch")
        .and_then(|value| value.get("created_at"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
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

    let mut finding_details = item.finding.details.clone();
    match &mut finding_details {
        Value::Object(details) => {
            details.insert("shared_opportunity".to_string(), json!(true));
            details.insert(
                "remote_opportunity_id".to_string(),
                json!(item.opportunity.id),
            );
            details.insert("remote_finding_id".to_string(), json!(item.finding.id));
        }
        other => {
            finding_details = json!({
                "shared_opportunity": true,
                "remote_opportunity_id": item.opportunity.id,
                "remote_finding_id": item.finding.id,
                "original_details": other,
            });
        }
    }

    let finding_id = store.record_finding(&FindingInput {
        kind: item.finding.kind.clone(),
        title: item.finding.title.clone(),
        severity: item.finding.severity.clone(),
        fingerprint: item.finding.fingerprint.clone(),
        summary: item.finding.summary.clone(),
        details: finding_details,
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
    config: &FixerConfig,
    identity: &InstallIdentity,
    state: &ParticipationState,
) -> Result<ClientHello> {
    let capabilities = store
        .list_capabilities()?
        .into_iter()
        .filter(|capability| capability.available)
        .map(|capability| capability.name)
        .collect::<Vec<_>>();
    let codex_worker = codex_worker_availability(store, config)?;
    let driver_name = match config.patch.driver {
        PatchDriver::Codex => "codex",
        PatchDriver::Claude => "claude",
        PatchDriver::Gemini => "gemini",
        PatchDriver::Aider => "aider",
    };
    Ok(ClientHello {
        install_id: identity.install_id.clone(),
        version: current_binary_version().to_string(),
        protocol_version: default_protocol_version(),
        mode: state.mode.clone(),
        hostname: current_hostname(),
        has_codex: codex_worker.ready,
        capabilities,
        richer_evidence_allowed: state.richer_evidence_allowed,
        patch_driver: Some(driver_name.to_string()),
        patch_model: config.patch.model.clone(),
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
        return Err(HttpStatusError {
            path: path.to_string(),
            status,
            body,
        }
        .into());
    }
    response
        .json()
        .with_context(|| format!("failed to parse {path} response"))
}

#[derive(Debug)]
struct HttpStatusError {
    path: String,
    status: StatusCode,
    body: String,
}

impl fmt::Display for HttpStatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "server returned {}: {}", self.status, self.body)
    }
}

impl std::error::Error for HttpStatusError {}

fn is_expired_worker_result_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<HttpStatusError>()
        .map(|status_error| {
            status_error.status == StatusCode::GONE
                && status_error.path.starts_with("v1/work/")
                && status_error.path.ends_with("/result")
        })
        .unwrap_or(false)
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
        .map(normalize_worker_summary_target)
        .unwrap_or_else(|| "the process".to_string());
    let classification = details
        .get("loop_classification")
        .and_then(Value::as_str)
        .unwrap_or("unknown-investigation");
    match details.get("subsystem").and_then(Value::as_str) {
        Some("stuck-process") => {
            let phrase = investigation_classification_phrase(classification, "wait");
            format!("{target} likely remains stuck in {phrase}.")
        }
        Some("desktop-resume") => {
            let crashed = details
                .get("crashed_processes")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .take(3)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "the desktop session".to_string());
            let display_manager = details
                .get("display_manager")
                .and_then(Value::as_str)
                .unwrap_or("the display manager");
            format!(
                "{target} disappeared after resume when {crashed} crashed and {display_manager} restarted the display stack."
            )
        }
        Some("oom-kill") => format!("{target} was killed by the kernel OOM killer."),
        _ => {
            let phrase = investigation_classification_phrase(classification, "loop");
            format!("{target} likely remains stuck in {phrase}.")
        }
    }
}

fn normalize_worker_summary_target(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches(" (deleted)").trim();
    if !trimmed.starts_with("kworker/") {
        return trimmed.to_string();
    }
    trimmed
        .split_once('+')
        .map(|(_, suffix)| format!("kworker+{suffix}"))
        .unwrap_or_else(|| "kworker".to_string())
}

fn investigation_classification_phrase(classification: &str, fallback_kind: &str) -> String {
    match (classification, fallback_kind) {
        ("unknown-userspace-loop", _) => "an unclassified userspace loop".to_string(),
        ("unknown-uninterruptible-wait", _) => "an unclassified uninterruptible wait".to_string(),
        ("file-not-found-retry", _) => "a file-not-found retry loop".to_string(),
        ("busy-poll", _) => "a busy-poll loop".to_string(),
        ("dbus-spin", _) => "a DBus message-loop spin".to_string(),
        ("fuse-wait", _) => "a FUSE wait".to_string(),
        ("kernel-oom-kill", _) => "a kernel OOM kill".to_string(),
        (value, "wait") if value.ends_with("-wait") => {
            format!("a {}", value.replace('-', " "))
        }
        (value, "loop") if value.ends_with("-loop") => {
            format!("a {}", value.replace('-', " "))
        }
        (value, "loop") if value.ends_with("-spin") => {
            format!("a {}", value.replace('-', " "))
        }
        (value, kind) => format!("a {} {kind}", value.replace('-', " ")),
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

fn process_investigation_report_only_reason_for_error(error: &str) -> &'static str {
    match proposal::process_investigation_blocker_kind(error) {
        "codex-auth" => "codex-auth-unavailable",
        "workspace" => "workspace-acquisition",
        _ => "automatic-patch-blocked",
    }
}

fn should_publish_process_investigation_blocker(error: &str) -> bool {
    proposal::process_investigation_blocker_kind(error) != "codex-auth"
}

fn process_investigation_blocker_cooldown_seconds(error: &str) -> u64 {
    match proposal::process_investigation_blocker_kind(error) {
        "codex-auth" => 60 * 60,
        "workspace" => 30 * 60,
        _ => 15 * 60,
    }
}

fn record_local_worker_blocker(
    store: &Store,
    cluster_id: &str,
    error: &str,
) -> Result<LocalWorkerBlocker> {
    let blocker = LocalWorkerBlocker {
        cluster_id: cluster_id.to_string(),
        blocker_kind: proposal::process_investigation_blocker_kind(error).to_string(),
        blocker_reason: process_investigation_report_only_reason_for_error(error).to_string(),
        error: error.to_string(),
        created_at: now_rfc3339(),
        cooldown_seconds: process_investigation_blocker_cooldown_seconds(error),
    };
    let mut history = prune_local_worker_blocker_history(
        store
            .get_local_state::<LocalWorkerBlockerHistory>(LOCAL_WORKER_BLOCKER_HISTORY_KEY)?
            .unwrap_or_default(),
    );
    history.entries.retain(|entry| {
        !(entry.cluster_id == blocker.cluster_id && entry.blocker_reason == blocker.blocker_reason)
    });
    history.entries.push(blocker.clone());
    if history.entries.len() > MAX_LOCAL_WORKER_BLOCKERS {
        let drain = history.entries.len() - MAX_LOCAL_WORKER_BLOCKERS;
        history.entries.drain(0..drain);
    }
    store.set_local_state(LOCAL_WORKER_BLOCKER_HISTORY_KEY, &history)?;
    store.set_local_state("last_worker_local_blocker", &blocker)?;
    Ok(blocker)
}

fn prune_local_worker_blocker_history(
    mut history: LocalWorkerBlockerHistory,
) -> LocalWorkerBlockerHistory {
    let now = Utc::now();
    history.entries.retain(|entry| {
        let Ok(created_at) = DateTime::parse_from_rfc3339(&entry.created_at) else {
            return false;
        };
        created_at.with_timezone(&Utc) + ChronoDuration::seconds(entry.cooldown_seconds as i64)
            > now
    });
    history
        .entries
        .sort_by(|left, right| left.created_at.cmp(&right.created_at));
    history
}

fn canonicalize_submission_source_package(
    package_name: Option<&str>,
    source_package: Option<&str>,
) -> Option<String> {
    let source_package = source_package
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match (package_name.map(str::trim), source_package) {
        (Some(package_name), Some(source_package))
            if (package_name.starts_with("linux-image-")
                || package_name.starts_with("linux-headers-")
                || package_name.starts_with("linux-modules-"))
                && (source_package.starts_with("linux-signed")
                    || source_package.starts_with("linux-image")
                    || source_package.starts_with("linux-headers")
                    || source_package.starts_with("linux-modules")
                    || source_package == "linux") =>
        {
            Some("linux".to_string())
        }
        (_, Some(source_package)) => Some(source_package.to_string()),
        (Some("linux"), None) => Some("linux".to_string()),
        _ => None,
    }
}

fn diagnosis_target_name(diagnosis: &Value) -> Option<&str> {
    diagnosis
        .get("profile_target")
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .or_else(|| diagnosis.get("process_name").and_then(Value::as_str))
        .or_else(|| diagnosis.get("target_name").and_then(Value::as_str))
}

fn diagnosis_points_to_kernel_target(diagnosis: &Value) -> bool {
    diagnosis_target_name(diagnosis).is_some_and(|target| {
        let normalized = target.trim().to_ascii_lowercase();
        normalized.starts_with("kworker")
            || normalized.starts_with("jbd2/")
            || normalized.starts_with("kswapd")
            || normalized.starts_with("kcompactd")
            || normalized.starts_with("ksoftirqd")
    })
}

fn source_package_from_shared_evidence(item: &SharedOpportunity) -> Option<String> {
    let details = item.opportunity.evidence.get("details");
    canonicalize_submission_source_package(
        item.finding.package_name.as_deref().or_else(|| {
            item.opportunity
                .evidence
                .get("package_name")
                .and_then(Value::as_str)
        }),
        item.opportunity
            .evidence
            .get("source_package")
            .and_then(Value::as_str)
            .or_else(|| {
                details
                    .and_then(|value| value.get("source_package"))
                    .and_then(Value::as_str)
            })
            .or_else(|| {
                details
                    .and_then(|value| value.get("package_metadata"))
                    .and_then(|value| value.get("source_package"))
                    .and_then(Value::as_str)
            }),
    )
}

fn canonicalize_shared_opportunity(mut item: SharedOpportunity) -> SharedOpportunity {
    if let Some(source_package) = source_package_from_shared_evidence(&item) {
        if let Some(object) = item.opportunity.evidence.as_object_mut() {
            object
                .entry("source_package".to_string())
                .or_insert_with(|| json!(source_package));
        }
    }
    item
}

fn workspace_blocker_classification(
    opportunity: &crate::models::OpportunityRecord,
    error: &str,
) -> Option<String> {
    if proposal::process_investigation_blocker_kind(error) != "workspace" {
        return None;
    }
    let diagnosis = process_investigation_worker_diagnosis(opportunity);
    let package_name = opportunity
        .evidence
        .get("package_name")
        .and_then(Value::as_str)
        .or_else(|| diagnosis.get("package_name").and_then(Value::as_str))
        .unwrap_or_default();
    let source_package = opportunity
        .evidence
        .get("source_package")
        .and_then(Value::as_str)
        .or_else(|| diagnosis.get("source_package").and_then(Value::as_str))
        .or_else(|| {
            diagnosis
                .get("package_metadata")
                .and_then(|value| value.get("source_package"))
                .and_then(Value::as_str)
        })
        .unwrap_or_default();
    if package_name.starts_with("linux-")
        || source_package == "linux"
        || diagnosis_points_to_kernel_target(&diagnosis)
    {
        return Some("kernel-source-unavailable".to_string());
    }
    let chrome_can_use_chromium_sources = matches!(
        package_name,
        "google-chrome-stable" | "google-chrome-beta" | "google-chrome-unstable"
    );
    if error.contains("external package")
        || diagnosis
            .get("package_metadata")
            .and_then(|value| value.get("apt_origins"))
            .and_then(Value::as_array)
            .is_some_and(|origins| {
                origins
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|origin| !origin_is_debian_source_friendly(origin))
            })
    {
        if !chrome_can_use_chromium_sources {
            return Some("external-package".to_string());
        }
    }
    let cloneable_homepage = diagnosis
        .get("package_metadata")
        .and_then(|value| value.get("cloneable_homepage"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let has_external_report_target = diagnosis
        .get("package_metadata")
        .and_then(|value| value.get("report_url"))
        .and_then(Value::as_str)
        .is_some()
        || diagnosis
            .get("package_metadata")
            .and_then(|value| value.get("homepage"))
            .and_then(Value::as_str)
            .is_some();
    if has_external_report_target && !cloneable_homepage {
        return Some("external-package".to_string());
    }
    Some("workspace-unavailable".to_string())
}

fn workspace_blocked_handoff(opportunity: &crate::models::OpportunityRecord, error: &str) -> Value {
    let diagnosis = process_investigation_worker_diagnosis(opportunity);
    let classification = workspace_blocker_classification(opportunity, error)
        .unwrap_or_else(|| "workspace-unavailable".to_string());
    let target = opportunity
        .evidence
        .get("source_package")
        .and_then(Value::as_str)
        .or_else(|| {
            opportunity
                .evidence
                .get("package_name")
                .and_then(Value::as_str)
        })
        .or_else(|| {
            diagnosis
                .get("package_metadata")
                .and_then(|value| value.get("source_package"))
                .and_then(Value::as_str)
        })
        .unwrap_or("the upstream maintainer")
        .to_string();
    let report_url = diagnosis
        .get("package_metadata")
        .and_then(|value| value.get("report_url"))
        .and_then(Value::as_str)
        .or_else(|| {
            diagnosis
                .get("package_metadata")
                .and_then(|value| value.get("homepage"))
                .and_then(Value::as_str)
        });
    let next_steps = match classification.as_str() {
        "kernel-source-unavailable" => vec![
            "Treat this as a kernel or lower-level subsystem handoff, not a package patch.".to_string(),
            "File or update the relevant kernel/driver report with the diagnosis bundle and wait-site evidence.".to_string(),
        ],
        "external-package" => vec![
            "File an upstream or vendor issue with the diagnosis bundle and package metadata.".to_string(),
            "Include the workspace acquisition note so maintainers know why no local source patch was attempted.".to_string(),
        ],
        _ => vec![
            "Review the package metadata and attach a source tree or upstream clone if one exists.".to_string(),
            "If no patchable tree is available, file an external bug using the diagnosis bundle.".to_string(),
        ],
    };
    json!({
        "target": target,
        "report_url": report_url,
        "next_steps": next_steps,
    })
}

fn append_job_status_details(
    details: &mut serde_json::Map<String, Value>,
    status: &CodexJobStatus,
) {
    details.insert("worker_model".to_string(), json!(status.selected_model));
    details.insert("worker_models_used".to_string(), json!(status.models_used));
    details.insert(
        "worker_rate_limit_fallback_used".to_string(),
        json!(status.rate_limit_fallback_used),
    );
    if let Some(stage) = status.failure_stage.as_deref() {
        details.insert("patch_failure_stage".to_string(), json!(stage));
    }
    if let Some(kind) = status.failure_kind.as_deref() {
        details.insert("patch_failure_kind".to_string(), json!(kind));
    }
    if let Some(error) = status.error.as_deref() {
        details.insert("patch_error".to_string(), json!(error));
    }
    if let Some(exit_status) = status.exit_status {
        details.insert("patch_exit_status".to_string(), json!(exit_status));
    }
    if let Some(stderr_excerpt) = status.last_stderr_excerpt.as_deref() {
        details.insert(
            "patch_last_stderr_excerpt".to_string(),
            json!(stderr_excerpt),
        );
    }
    if let Some(category) = status.review_failure_category.as_deref() {
        details.insert("patch_review_failure_category".to_string(), json!(category));
    }
}

fn process_investigation_blocked_patch_summary(
    opportunity: &crate::models::OpportunityRecord,
    error: &str,
) -> String {
    match proposal::process_investigation_blocker_kind(error) {
        "codex-auth" => format!(
            "{} A diagnosis report was created, but Fixer could not start the automated patch attempt because Codex auth on this host is unavailable: {}",
            process_investigation_worker_summary(opportunity),
            error
        ),
        "workspace" => format!(
            "{} A diagnosis report was created even though no patchable workspace was available: {}",
            process_investigation_worker_summary(opportunity),
            error
        ),
        _ => format!(
            "{} A diagnosis report was created, but the automated patch attempt stopped before completion: {}",
            process_investigation_worker_summary(opportunity),
            error
        ),
    }
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

fn prior_patch_review_rejected_for_refresh(
    local_proposal: &ProposalRecord,
    prior_best_patch: Option<&PatchAttempt>,
) -> Option<CodexJobStatus> {
    if prior_best_patch.is_none() || local_proposal.state == "ready" {
        return None;
    }
    let status = proposal::load_codex_job_status(&local_proposal.bundle_path).ok()?;
    (status.failure_kind.as_deref() == Some("review")).then_some(status)
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

fn build_internal_only_impossible_result(
    install_id: &str,
    cluster_id: String,
    lease_id: &str,
    category: &str,
    public_summary: &str,
    internal_error: &str,
    mut details: Value,
) -> WorkerResultEnvelope {
    if let Some(object) = details.as_object_mut() {
        object.insert("internal_only".to_string(), json!(true));
        object.insert(
            "internal_error_category".to_string(),
            json!(category.to_string()),
        );
        object.insert("internal_error".to_string(), json!(internal_error));
    }
    build_impossible_result(
        install_id,
        cluster_id,
        lease_id,
        category,
        public_summary,
        details,
    )
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
    use crate::models::{
        Capability, CodexJobStatus, FindingInput, FindingRecord, OpportunityRecord,
        ParticipationMode, ParticipationState,
    };
    use crate::storage::Store;
    use serde_json::json;
    use std::fs;
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

    fn sample_codex_capability() -> Capability {
        Capability {
            name: "codex".to_string(),
            binary: "codex".to_string(),
            available: true,
            path: Some("/usr/bin/codex".into()),
            notes: Some("AI patch proposal engine".to_string()),
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
    fn workspace_blocker_classification_detects_external_binary_packages() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "investigation".to_string(),
            title: "Crash with stack trace in chrome".to_string(),
            score: 10,
            state: "open".to_string(),
            repo_root: None,
            summary: "chrome crashed".to_string(),
            evidence: json!({
                "package_name": "google-chrome-stable",
                "details": {
                    "subsystem": "crash",
                    "package_metadata": {
                        "package_name": "google-chrome-stable",
                        "source_package": "google-chrome-stable",
                        "cloneable_homepage": false,
                        "apt_origins": [
                            "http://dl.google.com/linux/chrome/deb stable/main amd64 Packages"
                        ]
                    }
                }
            }),
            ecosystem: None,
            created_at: "2026-03-29T00:00:00Z".to_string(),
            updated_at: "2026-03-29T00:00:00Z".to_string(),
        };

        assert_eq!(
            workspace_blocker_classification(
                &opportunity,
                "could not acquire a workspace for external package google-chrome-stable; no Debian source package, Debian VCS metadata, or cloneable upstream repository is available"
            )
            .as_deref(),
            Some("workspace-unavailable")
        );
    }

    #[test]
    fn workspace_blocker_classification_keeps_other_vendor_packages_external() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "investigation".to_string(),
            title: "Zoom spins CPU".to_string(),
            score: 10,
            state: "open".to_string(),
            repo_root: None,
            summary: "zoom spins".to_string(),
            evidence: json!({
                "package_name": "zoom",
                "details": {
                    "subsystem": "cpu",
                    "package_metadata": {
                        "package_name": "zoom",
                        "source_package": "zoom",
                        "cloneable_homepage": false,
                        "apt_origins": [
                            "https://zoom.us/linux/download stable/main amd64 Packages"
                        ]
                    }
                }
            }),
            ecosystem: None,
            created_at: "2026-03-29T00:00:00Z".to_string(),
            updated_at: "2026-03-29T00:00:00Z".to_string(),
        };

        assert_eq!(
            workspace_blocker_classification(
                &opportunity,
                "could not acquire a workspace for external package zoom; no Debian source package, Debian VCS metadata, or cloneable upstream repository is available"
            )
            .as_deref(),
            Some("external-package")
        );
    }

    #[test]
    fn workspace_blocker_classification_accepts_debian_mirror_origins() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "investigation".to_string(),
            title: "htop burns CPU".to_string(),
            score: 10,
            state: "open".to_string(),
            repo_root: None,
            summary: "htop loops".to_string(),
            evidence: json!({
                "package_name": "htop",
                "source_package": "htop",
                "details": {
                    "subsystem": "cpu",
                    "package_metadata": {
                        "package_name": "htop",
                        "source_package": "htop",
                        "cloneable_homepage": false,
                        "apt_origins": [
                            "http://debian.grena.ge/debian stable/main amd64 Packages"
                        ]
                    }
                }
            }),
            ecosystem: None,
            created_at: "2026-04-01T00:00:00Z".to_string(),
            updated_at: "2026-04-01T00:00:00Z".to_string(),
        };

        assert_eq!(
            workspace_blocker_classification(
                &opportunity,
                "could not acquire a workspace for htop; enable deb-src, ensure apt-cache showsrc lists downloadable source files, or provide Debian VCS/cloneable upstream metadata"
            )
            .as_deref(),
            Some("workspace-unavailable")
        );
    }

    #[test]
    fn process_investigation_worker_summary_does_not_duplicate_loop_or_wait_words() {
        let mut opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "investigation".to_string(),
            title: "Runaway CPU investigation for htop".to_string(),
            score: 10,
            state: "open".to_string(),
            repo_root: None,
            summary: "htop loops".to_string(),
            evidence: json!({
                "details": {
                    "subsystem": "runaway-process",
                    "profile_target": { "name": "htop" },
                    "loop_classification": "unknown-userspace-loop"
                }
            }),
            ecosystem: None,
            created_at: "2026-04-01T00:00:00Z".to_string(),
            updated_at: "2026-04-01T00:00:00Z".to_string(),
        };

        assert_eq!(
            process_investigation_worker_summary(&opportunity),
            "htop likely remains stuck in an unclassified userspace loop."
        );

        opportunity.evidence = json!({
            "details": {
                "subsystem": "stuck-process",
                "profile_target": { "name": "kworker/u33:3+i915_flip" },
                "loop_classification": "unknown-uninterruptible-wait"
            }
        });

        assert_eq!(
            process_investigation_worker_summary(&opportunity),
            "kworker+i915_flip likely remains stuck in an unclassified uninterruptible wait."
        );

        opportunity.evidence = json!({
            "details": {
                "subsystem": "stuck-process",
                "profile_target": { "name": "codex (deleted)" },
                "loop_classification": "unknown-uninterruptible-wait"
            }
        });

        assert_eq!(
            process_investigation_worker_summary(&opportunity),
            "codex likely remains stuck in an unclassified uninterruptible wait."
        );

        opportunity.evidence = json!({
            "details": {
                "subsystem": "runaway-process",
                "profile_target": { "name": "packagekitd" },
                "loop_classification": "dbus-spin"
            }
        });

        assert_eq!(
            process_investigation_worker_summary(&opportunity),
            "packagekitd likely remains stuck in a DBus message-loop spin."
        );
    }

    #[test]
    fn process_investigation_blocked_patch_reason_detects_codex_auth_failures() {
        assert_eq!(
            process_investigation_report_only_reason_for_error(
                "the current Codex auth lease is paused: auto-paused after 3 recent Codex failures"
            ),
            "codex-auth-unavailable"
        );
        assert_eq!(
            process_investigation_report_only_reason_for_error(
                "opportunity 655 has no repo root or package name"
            ),
            "workspace-acquisition"
        );
    }

    #[test]
    fn conservative_budget_is_bounded() {
        let budget = lease_budget_for_preset(&LeaseBudgetPreset::Conservative);
        assert_eq!(budget.max_active_jobs, 1);
        assert!(budget.max_jobs_per_day > 0);
        assert!(budget.job_timeout_seconds >= 30 * 60);
    }

    #[test]
    fn codex_state_dir_paths_use_standard_xdg_locations() {
        let home = Path::new("/home/alice");
        let paths = codex_state_dir_paths(home);
        assert_eq!(paths[0], Path::new("/home/alice/.cache/codex"));
        assert_eq!(paths[1], Path::new("/home/alice/.local/share/codex"));
    }

    #[test]
    fn build_client_hello_hides_codex_when_user_lease_is_not_ready() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("fixer.sqlite")).unwrap();
        store
            .sync_capabilities(&[sample_codex_capability()])
            .unwrap();

        let config = FixerConfig::default();
        let identity = store.ensure_install_identity().unwrap();
        let state = ParticipationState {
            mode: ParticipationMode::SubmitterWorker,
            ..ParticipationState::default()
        };

        let hello = build_client_hello(&store, &config, &identity, &state).unwrap();
        assert!(!hello.has_codex);
        assert!(
            hello
                .capabilities
                .iter()
                .any(|capability| capability == "codex")
        );
    }

    #[test]
    fn build_client_hello_advertises_codex_for_root_direct_hosts() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("fixer.sqlite")).unwrap();
        store
            .sync_capabilities(&[sample_codex_capability()])
            .unwrap();

        let mut config = FixerConfig::default();
        config.patch.auth_mode = CodexAuthMode::RootDirect;
        config.patch.codex_command = "sh".to_string();
        let identity = store.ensure_install_identity().unwrap();
        let state = ParticipationState {
            mode: ParticipationMode::SubmitterWorker,
            ..ParticipationState::default()
        };

        let hello = build_client_hello(&store, &config, &identity, &state).unwrap();
        assert!(hello.has_codex);
    }

    #[test]
    fn worker_once_stops_before_polling_when_user_lease_is_not_ready() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("fixer.sqlite")).unwrap();
        store
            .sync_capabilities(&[sample_codex_capability()])
            .unwrap();
        store
            .save_participation_state(&ParticipationState {
                mode: ParticipationMode::SubmitterWorker,
                ..ParticipationState::default()
            })
            .unwrap();

        let error = worker_once(&store, &FixerConfig::default()).unwrap_err();
        assert!(error.to_string().contains("Codex auth lease is not ready"));
    }

    #[test]
    fn ensure_user_owned_dir_chain_creates_missing_parents() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir(&home).unwrap();
        let target = home.join(".local").join("share").join("codex");

        ensure_user_owned_dir_chain("root", &home, &target).unwrap();

        assert!(home.join(".local").is_dir());
        assert!(home.join(".local/share").is_dir());
        assert!(target.is_dir());
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

    #[test]
    fn build_submission_bundle_includes_ready_codex_proposals() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("fixer.sqlite3")).unwrap();
        let finding_id = store
            .record_finding(&FindingInput {
                kind: "investigation".to_string(),
                title: "Keyboard layout config investigation".to_string(),
                severity: "high".to_string(),
                fingerprint: "desktop-input-config-1".to_string(),
                summary: "Wayland keyboard layout switching is inconsistent".to_string(),
                details: json!({
                    "subsystem": "desktop-input-config",
                    "profile_target": { "name": "plasma-desktop" },
                }),
                artifact: None,
                repo_root: None,
                ecosystem: None,
            })
            .unwrap();
        let opportunity = store.get_opportunity_by_finding(finding_id).unwrap();

        let source_root = dir.path().join("source");
        let workspace_root = dir.path().join("workspace");
        fs::create_dir_all(&source_root).unwrap();
        fs::create_dir_all(&workspace_root).unwrap();
        fs::write(source_root.join("keyboard_daemon.cpp"), "before\n").unwrap();
        fs::write(workspace_root.join("keyboard_daemon.cpp"), "after\n").unwrap();

        let bundle_dir = dir.path().join("proposal-bundle");
        fs::create_dir_all(&bundle_dir).unwrap();
        let output_path = bundle_dir.join("codex-output.txt");
        fs::write(
            bundle_dir.join("evidence.json"),
            serde_json::to_vec_pretty(&json!({
                "opportunity": opportunity,
                "workspace": { "repo_root": workspace_root.display().to_string() },
                "source_workspace": { "repo_root": source_root.display().to_string() },
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(bundle_dir.join("prompt.md"), "Patch the keyboard daemon.\n").unwrap();
        fs::write(&output_path, "Updated the layout switch guard.\n").unwrap();
        fs::write(
            bundle_dir.join("status.json"),
            serde_json::to_vec_pretty(&CodexJobStatus {
                job_id: "job-1".to_string(),
                state: "ready".to_string(),
                started_at: "2026-04-04T12:00:00Z".to_string(),
                finished_at: "2026-04-04T12:05:00Z".to_string(),
                output_path: Some(output_path.clone()),
                selected_model: Some("codex-default".to_string()),
                models_used: vec!["codex-default".to_string()],
                rate_limit_fallback_used: false,
                failure_stage: None,
                error: None,
                failure_kind: None,
                exit_status: Some(0),
                last_stderr_excerpt: None,
                review_failure_category: None,
            })
            .unwrap(),
        )
        .unwrap();
        store
            .create_proposal(
                opportunity.id,
                "codex",
                "ready",
                &bundle_dir,
                Some(&output_path),
            )
            .unwrap();

        let config = FixerConfig::default();
        let identity = store.ensure_install_identity().unwrap();
        let participation = ParticipationSnapshot {
            identity,
            state: ParticipationState {
                mode: ParticipationMode::SubmitterWorker,
                ..ParticipationState::default()
            },
            server_url: config.network.server_url.clone(),
            policy_text: "test policy".to_string(),
        };

        let bundle = build_submission_bundle(&store, &config, &participation).unwrap();
        assert_eq!(bundle.items.len(), 1);
        assert_eq!(bundle.proposals.len(), 1);
        assert_eq!(bundle.proposals[0].local_opportunity_id, opportunity.id);
        assert_eq!(bundle.proposals[0].local_proposal_id, 1);
        let diff = bundle.proposals[0]
            .result
            .attempt
            .details
            .get("published_session")
            .and_then(|value| value.get("diff"))
            .and_then(Value::as_str)
            .unwrap();
        assert!(diff.contains("keyboard_daemon.cpp"));
        assert!(diff.contains("+after"));
    }

    #[test]
    fn build_submission_bundle_includes_ready_proposals_for_known_issue_without_items() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("fixer.sqlite3")).unwrap();
        let finding_id = store
            .record_finding(&FindingInput {
                kind: "investigation".to_string(),
                title: "Keyboard layout config investigation".to_string(),
                severity: "high".to_string(),
                fingerprint: "desktop-input-config-2".to_string(),
                summary: "Wayland keyboard layout switching is inconsistent".to_string(),
                details: json!({
                    "subsystem": "desktop-input-config",
                    "profile_target": { "name": "plasma-desktop" },
                }),
                artifact: None,
                repo_root: None,
                ecosystem: None,
            })
            .unwrap();
        let opportunity = store.get_opportunity_by_finding(finding_id).unwrap();
        store
            .save_synced_issue_link(opportunity.id, "issue-public-1")
            .unwrap();

        let source_root = dir.path().join("source");
        let workspace_root = dir.path().join("workspace");
        fs::create_dir_all(&source_root).unwrap();
        fs::create_dir_all(&workspace_root).unwrap();
        fs::write(source_root.join("keyboard_daemon.cpp"), "before\n").unwrap();
        fs::write(workspace_root.join("keyboard_daemon.cpp"), "after\n").unwrap();

        let bundle_dir = dir.path().join("proposal-bundle");
        fs::create_dir_all(&bundle_dir).unwrap();
        let output_path = bundle_dir.join("codex-output.txt");
        fs::write(
            bundle_dir.join("evidence.json"),
            serde_json::to_vec_pretty(&json!({
                "opportunity": opportunity,
                "workspace": { "repo_root": workspace_root.display().to_string() },
                "source_workspace": { "repo_root": source_root.display().to_string() },
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(bundle_dir.join("prompt.md"), "Patch the keyboard daemon.\n").unwrap();
        fs::write(
            &output_path,
            "Ran `cmake --build build-fix --target kded_keyboard -j2` successfully.\n",
        )
        .unwrap();
        let proposal = store
            .create_proposal(
                opportunity.id,
                "codex",
                "ready",
                &bundle_dir,
                Some(&output_path),
            )
            .unwrap();
        fs::write(
            bundle_dir.join("status.json"),
            serde_json::to_vec_pretty(&CodexJobStatus {
                job_id: "job-2".to_string(),
                state: "ready".to_string(),
                started_at: "2026-04-04T12:00:00Z".to_string(),
                finished_at: "2026-04-04T12:05:00Z".to_string(),
                output_path: Some(output_path.clone()),
                selected_model: Some("codex-default".to_string()),
                models_used: vec!["codex-default".to_string()],
                rate_limit_fallback_used: false,
                failure_stage: None,
                error: None,
                failure_kind: None,
                exit_status: Some(0),
                last_stderr_excerpt: None,
                review_failure_category: None,
            })
            .unwrap(),
        )
        .unwrap();

        let mut config = FixerConfig::default();
        config.network.max_submission_items = 0;
        let identity = store.ensure_install_identity().unwrap();
        let participation = ParticipationSnapshot {
            identity,
            state: ParticipationState {
                mode: ParticipationMode::SubmitterWorker,
                ..ParticipationState::default()
            },
            server_url: config.network.server_url.clone(),
            policy_text: "test policy".to_string(),
        };

        let bundle = build_submission_bundle(&store, &config, &participation).unwrap();
        assert!(bundle.items.is_empty());
        assert_eq!(bundle.proposals.len(), 1);
        assert_eq!(bundle.proposals[0].local_proposal_id, proposal.id);
        assert_eq!(
            bundle.proposals[0].remote_issue_id.as_deref(),
            Some("issue-public-1")
        );
        assert_eq!(
            bundle.proposals[0]
                .result
                .attempt
                .details
                .get("validation_quality")
                .and_then(Value::as_str),
            Some("passed")
        );
        assert_eq!(
            bundle.proposals[0]
                .result
                .attempt
                .details
                .get("supersedes_best_patch")
                .and_then(Value::as_bool),
            Some(true)
        );
    }
}
