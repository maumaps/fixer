use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub name: String,
    pub binary: String,
    pub available: bool,
    pub path: Option<PathBuf>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedArtifact {
    pub kind: String,
    pub name: String,
    pub path: Option<PathBuf>,
    pub package_name: Option<String>,
    pub repo_root: Option<PathBuf>,
    pub ecosystem: Option<String>,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingInput {
    pub kind: String,
    pub title: String,
    pub severity: String,
    pub fingerprint: String,
    pub summary: String,
    pub details: Value,
    pub artifact: Option<ObservedArtifact>,
    pub repo_root: Option<PathBuf>,
    pub ecosystem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRecord {
    pub id: i64,
    pub kind: String,
    pub title: String,
    pub severity: String,
    pub fingerprint: String,
    pub summary: String,
    pub details: Value,
    pub artifact_name: Option<String>,
    pub artifact_path: Option<PathBuf>,
    pub package_name: Option<String>,
    pub repo_root: Option<PathBuf>,
    pub ecosystem: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpportunityRecord {
    pub id: i64,
    pub finding_id: i64,
    pub kind: String,
    pub title: String,
    pub score: i64,
    pub state: String,
    pub summary: String,
    pub evidence: Value,
    pub repo_root: Option<PathBuf>,
    pub ecosystem: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalRecord {
    pub id: i64,
    pub opportunity_id: i64,
    pub engine: String,
    pub state: String,
    pub bundle_path: PathBuf,
    pub output_path: Option<PathBuf>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRecord {
    pub id: i64,
    pub opportunity_id: i64,
    pub command: String,
    pub status: String,
    pub output: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusSnapshot {
    pub capabilities: i64,
    pub artifacts: i64,
    pub findings: i64,
    pub opportunities: i64,
    pub proposals: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopEntry {
    pub group: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl ValidationCommand {
    pub fn render(&self) -> String {
        let mut parts = Vec::with_capacity(self.args.len() + 1);
        parts.push(self.program.clone());
        parts.extend(self.args.iter().cloned());
        parts.join(" ")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoInsight {
    pub ecosystem: String,
    pub display_name: String,
    pub upstream_url: Option<String>,
    pub bug_tracker_url: Option<String>,
    pub owners: Vec<String>,
    pub summary: String,
    pub validation: Vec<ValidationCommand>,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedWorkspace {
    pub repo_root: PathBuf,
    pub ecosystem: Option<String>,
    pub source_kind: String,
    pub package_name: Option<String>,
    pub source_package: Option<String>,
    pub homepage: Option<String>,
    pub acquisition_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPackageMetadata {
    pub package_name: String,
    pub source_package: String,
    pub installed_version: Option<String>,
    pub candidate_version: Option<String>,
    pub architecture: Option<String>,
    pub maintainer: Option<String>,
    pub vendor: Option<String>,
    pub homepage: Option<String>,
    pub report_url: Option<String>,
    pub report_url_source: Option<String>,
    pub status: Option<String>,
    pub apt_policy_raw: Option<String>,
    pub apt_origins: Vec<String>,
    pub upgrade_available: bool,
    pub update_command: Option<String>,
    pub cloneable_homepage: bool,
}
