use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixerConfig {
    #[serde(default)]
    pub service: ServiceConfig,
    #[serde(default)]
    pub patch: PatchConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub participation: ParticipationConfig,
    #[serde(default)]
    pub privacy: PrivacyConfig,
    #[serde(default)]
    pub server: ServerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    #[serde(default = "default_database_path")]
    pub database_path: PathBuf,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_seconds: u64,
    #[serde(default = "default_true")]
    pub collect_processes: bool,
    #[serde(default = "default_true")]
    pub collect_crashes: bool,
    #[serde(default = "default_true")]
    pub collect_warnings: bool,
    #[serde(default)]
    pub collect_perf: bool,
    #[serde(default)]
    pub collect_bpftrace: bool,
    #[serde(default = "default_perf_duration")]
    pub perf_duration_seconds: u64,
    #[serde(default = "default_coredump_limit")]
    pub coredump_limit: usize,
    #[serde(default = "default_journal_lines")]
    pub journal_lines: usize,
    #[serde(default)]
    pub watched_repos: Vec<PathBuf>,
    #[serde(default)]
    pub warning_logs: Vec<PathBuf>,
    #[serde(default)]
    pub bpftrace_script: Option<String>,
    #[serde(default = "default_bpftrace_timeout")]
    pub bpftrace_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchConfig {
    #[serde(default = "default_codex_command")]
    pub codex_command: String,
    #[serde(default)]
    pub codex_args: Vec<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub sandbox: Option<String>,
    #[serde(default)]
    pub approval_policy: Option<String>,
    #[serde(default)]
    pub extra_instructions: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_server_url")]
    pub server_url: String,
    #[serde(default = "default_sync_interval")]
    pub sync_interval_seconds: u64,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_submission_pow_difficulty")]
    pub submission_pow_difficulty: u32,
    #[serde(default = "default_worker_pow_difficulty")]
    pub worker_pow_difficulty: u32,
    #[serde(default = "default_max_submission_items")]
    pub max_submission_items: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipationConfig {
    #[serde(default)]
    pub mode: crate::models::ParticipationMode,
    #[serde(default)]
    pub richer_evidence_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    #[serde(default = "default_policy_version")]
    pub policy_version: String,
    #[serde(default = "default_true")]
    pub redact_known_secrets: bool,
    #[serde(default = "default_true")]
    pub require_opt_in_for_upload: bool,
    #[serde(default = "default_true")]
    pub require_secondary_opt_in_for_richer_evidence: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen_addr")]
    pub listen: String,
    #[serde(default = "default_postgres_url")]
    pub postgres_url: String,
    #[serde(default = "default_submission_pow_difficulty")]
    pub submission_pow_difficulty: u32,
    #[serde(default = "default_worker_pow_difficulty")]
    pub worker_pow_difficulty: u32,
    #[serde(default = "default_max_payload_bytes")]
    pub max_payload_bytes: usize,
    #[serde(default = "default_max_submission_items")]
    pub max_bundle_items: usize,
    #[serde(default = "default_quarantine_threshold")]
    pub quarantine_corroboration_threshold: i64,
    #[serde(default = "default_lease_seconds")]
    pub lease_seconds: u64,
    #[serde(default = "default_worker_trust_minimum")]
    pub worker_trust_minimum: i64,
    #[serde(default = "default_rate_limit_per_hour")]
    pub max_submissions_per_hour: i64,
    #[serde(default = "default_rate_limit_per_hour")]
    pub max_work_pulls_per_hour: i64,
    #[serde(default = "default_abuse_threshold")]
    pub max_abuse_events_before_ban: i64,
}

impl Default for FixerConfig {
    fn default() -> Self {
        Self {
            service: ServiceConfig::default(),
            patch: PatchConfig::default(),
            network: NetworkConfig::default(),
            participation: ParticipationConfig::default(),
            privacy: PrivacyConfig::default(),
            server: ServerConfig::default(),
        }
    }
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            database_path: default_database_path(),
            state_dir: default_state_dir(),
            poll_interval_seconds: default_poll_interval(),
            collect_processes: true,
            collect_crashes: true,
            collect_warnings: true,
            collect_perf: false,
            collect_bpftrace: false,
            perf_duration_seconds: default_perf_duration(),
            coredump_limit: default_coredump_limit(),
            journal_lines: default_journal_lines(),
            watched_repos: Vec::new(),
            warning_logs: Vec::new(),
            bpftrace_script: None,
            bpftrace_timeout_seconds: default_bpftrace_timeout(),
        }
    }
}

impl Default for PatchConfig {
    fn default() -> Self {
        Self {
            codex_command: default_codex_command(),
            codex_args: Vec::new(),
            model: None,
            sandbox: Some("workspace-write".to_string()),
            approval_policy: Some("never".to_string()),
            extra_instructions: None,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            server_url: default_server_url(),
            sync_interval_seconds: default_sync_interval(),
            connect_timeout_seconds: default_connect_timeout(),
            submission_pow_difficulty: default_submission_pow_difficulty(),
            worker_pow_difficulty: default_worker_pow_difficulty(),
            max_submission_items: default_max_submission_items(),
        }
    }
}

impl Default for ParticipationConfig {
    fn default() -> Self {
        Self {
            mode: crate::models::ParticipationMode::LocalOnly,
            richer_evidence_allowed: false,
        }
    }
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            policy_version: default_policy_version(),
            redact_known_secrets: true,
            require_opt_in_for_upload: true,
            require_secondary_opt_in_for_richer_evidence: true,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen_addr(),
            postgres_url: default_postgres_url(),
            submission_pow_difficulty: default_submission_pow_difficulty(),
            worker_pow_difficulty: default_worker_pow_difficulty(),
            max_payload_bytes: default_max_payload_bytes(),
            max_bundle_items: default_max_submission_items(),
            quarantine_corroboration_threshold: default_quarantine_threshold(),
            lease_seconds: default_lease_seconds(),
            worker_trust_minimum: default_worker_trust_minimum(),
            max_submissions_per_hour: default_rate_limit_per_hour(),
            max_work_pulls_per_hour: default_rate_limit_per_hour(),
            max_abuse_events_before_ban: default_abuse_threshold(),
        }
    }
}

impl FixerConfig {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = path.unwrap_or_else(|| Path::new("/etc/fixer/fixer.toml"));
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config at {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
    }

    pub fn ensure_parent_dirs(&self) -> Result<()> {
        if let Some(parent) = self.service.database_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::create_dir_all(&self.service.state_dir)
            .with_context(|| format!("failed to create {}", self.service.state_dir.display()))?;
        Ok(())
    }
}

fn default_database_path() -> PathBuf {
    PathBuf::from("/var/lib/fixer/fixer.sqlite3")
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/fixer")
}

fn default_poll_interval() -> u64 {
    300
}

fn default_perf_duration() -> u64 {
    3
}

fn default_coredump_limit() -> usize {
    10
}

fn default_journal_lines() -> usize {
    50
}

fn default_bpftrace_timeout() -> u64 {
    10
}

fn default_codex_command() -> String {
    "codex".to_string()
}

fn default_server_url() -> String {
    "https://fixer.maumap.com".to_string()
}

fn default_sync_interval() -> u64 {
    900
}

fn default_connect_timeout() -> u64 {
    20
}

fn default_submission_pow_difficulty() -> u32 {
    4
}

fn default_worker_pow_difficulty() -> u32 {
    5
}

fn default_max_submission_items() -> usize {
    50
}

fn default_policy_version() -> String {
    "2026-03-28".to_string()
}

fn default_listen_addr() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_postgres_url() -> String {
    "postgres://fixer@127.0.0.1/fixer".to_string()
}

fn default_max_payload_bytes() -> usize {
    512 * 1024
}

fn default_quarantine_threshold() -> i64 {
    2
}

fn default_lease_seconds() -> u64 {
    900
}

fn default_worker_trust_minimum() -> i64 {
    2
}

fn default_rate_limit_per_hour() -> i64 {
    60
}

fn default_abuse_threshold() -> i64 {
    8
}

fn default_true() -> bool {
    true
}
