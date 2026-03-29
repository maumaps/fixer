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
pub struct PopularBinaryProfile {
    pub name: String,
    pub path: PathBuf,
    pub package_name: Option<String>,
    pub process_count: i64,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ParticipationMode {
    #[default]
    LocalOnly,
    Submitter,
    SubmitterWorker,
}

impl ParticipationMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LocalOnly => "local-only",
            Self::Submitter => "submitter",
            Self::SubmitterWorker => "submitter-worker",
        }
    }

    pub fn can_submit(&self) -> bool {
        !matches!(self, Self::LocalOnly)
    }

    pub fn can_work(&self) -> bool {
        matches!(self, Self::SubmitterWorker)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipationState {
    pub mode: ParticipationMode,
    pub consented_at: Option<String>,
    pub consent_policy_version: Option<String>,
    pub consent_policy_digest: Option<String>,
    pub opt_out_at: Option<String>,
    pub richer_evidence_allowed: bool,
}

impl Default for ParticipationState {
    fn default() -> Self {
        Self {
            mode: ParticipationMode::LocalOnly,
            consented_at: None,
            consent_policy_version: None,
            consent_policy_digest: None,
            opt_out_at: None,
            richer_evidence_allowed: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallIdentity {
    pub install_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedOpportunity {
    pub local_opportunity_id: i64,
    pub opportunity: OpportunityRecord,
    pub finding: FindingRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub install_id: String,
    pub version: String,
    pub mode: ParticipationMode,
    pub hostname: Option<String>,
    pub capabilities: Vec<String>,
    pub has_codex: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfWork {
    pub algorithm: String,
    pub difficulty: u32,
    pub issued_at: String,
    pub nonce: u64,
    pub payload_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingBundle {
    pub captured_at: String,
    pub policy_version: String,
    pub status: StatusSnapshot,
    pub capabilities: Vec<Capability>,
    pub items: Vec<SharedOpportunity>,
    pub redactions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionEnvelope {
    pub client: ClientHello,
    pub content_hash: String,
    pub proof_of_work: ProofOfWork,
    pub bundle: FindingBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub policy_version: String,
    pub submission_pow_difficulty: u32,
    pub worker_pow_difficulty: u32,
    pub install_trust_score: i64,
    pub quarantined: bool,
    pub worker_allowed: bool,
    pub message: String,
    pub server_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionReceipt {
    pub submission_id: i64,
    pub accepted: bool,
    pub duplicate: bool,
    pub quarantined: bool,
    pub promoted_clusters: usize,
    pub issue_ids: Vec<i64>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueCluster {
    pub id: i64,
    pub cluster_key: String,
    pub kind: String,
    pub title: String,
    pub summary: String,
    pub package_name: Option<String>,
    pub source_package: Option<String>,
    pub ecosystem: Option<String>,
    pub severity: Option<String>,
    pub score: i64,
    pub corroboration_count: i64,
    pub quarantined: bool,
    pub promoted: bool,
    pub representative: SharedOpportunity,
    pub best_patch: Option<PatchAttempt>,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkPullRequest {
    pub client: ClientHello,
    pub proof_of_work: ProofOfWork,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkOffer {
    pub message: String,
    pub lease: Option<WorkLease>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkLease {
    pub lease_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub issue: IssueCluster,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchAttempt {
    pub cluster_id: i64,
    pub install_id: String,
    pub outcome: String,
    pub state: String,
    pub summary: String,
    pub bundle_path: Option<String>,
    pub output_path: Option<String>,
    pub validation_status: Option<String>,
    pub details: Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpossibleReason {
    pub category: String,
    pub summary: String,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceUpgradeRequest {
    pub issue_id: i64,
    pub requested_by_install_id: Option<String>,
    pub reason: String,
    pub requested_fields: Vec<String>,
    pub requested_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResultEnvelope {
    pub lease_id: String,
    pub attempt: PatchAttempt,
    pub impossible_reason: Option<ImpossibleReason>,
    pub evidence_request: Option<EvidenceUpgradeRequest>,
}
