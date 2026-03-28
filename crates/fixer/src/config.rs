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

impl Default for FixerConfig {
    fn default() -> Self {
        Self {
            service: ServiceConfig::default(),
            patch: PatchConfig::default(),
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

fn default_true() -> bool {
    true
}
