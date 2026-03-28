use crate::adapters::inspect_repo;
use crate::capabilities::detect_capabilities;
use crate::collectors::{CollectReport, collect_once};
use crate::config::FixerConfig;
use crate::proposal;
use crate::storage::Store;
use crate::util::command_exists;
use crate::workspace::ensure_workspace_for_opportunity;
use anyhow::{Result, anyhow};
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
            thread::sleep(Duration::from_secs(self.config.service.poll_interval_seconds));
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
                self.store
                    .record_validation(opportunity_id, &command.render(), "skipped", &status)?;
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

    pub fn propose_fix(&self, opportunity_id: i64, engine: &str) -> Result<crate::models::ProposalRecord> {
        let opportunity = self.store.get_opportunity(opportunity_id)?;
        match ensure_workspace_for_opportunity(&self.config, &opportunity) {
            Ok(workspace) => {
                proposal::create_proposal(&self.store, &self.config, &opportunity, &workspace, engine)
            }
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
}
