use crate::protocol::{
    default_latest_client_version, default_min_supported_protocol_version,
    default_protocol_version, default_server_protocol_version,
};
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CodexAuthMode {
    RootDirect,
    #[default]
    UserLease,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PatchDriver {
    #[default]
    Codex,
    Claude,
    Gemini,
    Aider,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum LeaseBudgetPreset {
    Off,
    #[default]
    Conservative,
    Balanced,
    Aggressive,
}

impl LeaseBudgetPreset {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Conservative => "conservative",
            Self::Balanced => "balanced",
            Self::Aggressive => "aggressive",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexLeaseBudget {
    pub max_active_jobs: u32,
    pub max_jobs_per_day: u32,
    pub job_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexLeaseFailure {
    pub occurred_at: String,
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexAuthLease {
    pub user: String,
    pub uid: u32,
    pub granted_at: String,
    pub expires_at: String,
    pub budget_preset: LeaseBudgetPreset,
    pub budget: CodexLeaseBudget,
    pub allow_kernel: bool,
    pub paused_reason: Option<String>,
    pub revoked_at: Option<String>,
    pub active_jobs: u32,
    pub jobs_started_day: String,
    pub jobs_started_today: u32,
    #[serde(default)]
    pub recent_failures: Vec<CodexLeaseFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexAuthLeaseStatus {
    pub lease: Option<CodexAuthLease>,
    pub ready: bool,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexJobSpec {
    pub job_id: String,
    pub opportunity_id: i64,
    #[serde(default)]
    pub subsystem: Option<String>,
    pub run_as_user: String,
    #[serde(default)]
    pub worker_lease_id: Option<String>,
    #[serde(default)]
    pub worker_issue_id: Option<String>,
    #[serde(default)]
    pub worker_install_id: Option<String>,
    pub workspace: PreparedWorkspace,
    pub bundle_dir: PathBuf,
    pub prompt_path: PathBuf,
    pub output_path: PathBuf,
    pub failure_pause_threshold: u32,
    pub failure_pause_window_seconds: u64,
    pub allow_kernel: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexJobStatus {
    pub job_id: String,
    pub state: String,
    pub started_at: String,
    pub finished_at: String,
    pub output_path: Option<PathBuf>,
    #[serde(default)]
    pub selected_model: Option<String>,
    #[serde(default)]
    pub models_used: Vec<String>,
    #[serde(default)]
    pub rate_limit_fallback_used: bool,
    #[serde(default)]
    pub failure_stage: Option<String>,
    pub error: Option<String>,
    pub failure_kind: Option<String>,
    #[serde(default)]
    pub exit_status: Option<i32>,
    #[serde(default)]
    pub last_stderr_excerpt: Option<String>,
    #[serde(default)]
    pub review_failure_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplaintCollectionReport {
    pub capabilities_seen: usize,
    pub artifacts_seen: usize,
    pub findings_seen: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplaintOutcome {
    pub opportunity: OpportunityRecord,
    pub proposal: ProposalRecord,
    pub collection_report: Option<ComplaintCollectionReport>,
    pub related_opportunity_ids: Vec<i64>,
    pub workspace_root: PathBuf,
    pub used_overlay: bool,
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
    pub total_cpu_percent: f64,
    pub max_cpu_percent: f64,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
pub struct SubmittedProposal {
    pub local_opportunity_id: i64,
    pub local_proposal_id: i64,
    #[serde(default)]
    pub remote_issue_id: Option<String>,
    pub result: WorkerResultEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub install_id: String,
    pub version: String,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u32,
    pub mode: ParticipationMode,
    pub hostname: Option<String>,
    pub capabilities: Vec<String>,
    pub has_codex: bool,
    #[serde(default)]
    pub richer_evidence_allowed: bool,
    #[serde(default)]
    pub patch_driver: Option<String>,
    #[serde(default)]
    pub patch_model: Option<String>,
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
    #[serde(default)]
    pub richer_evidence_allowed: bool,
    pub status: StatusSnapshot,
    pub capabilities: Vec<Capability>,
    pub items: Vec<SharedOpportunity>,
    #[serde(default)]
    pub proposals: Vec<SubmittedProposal>,
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
    #[serde(default = "default_server_protocol_version")]
    pub server_protocol_version: u32,
    #[serde(default = "default_min_supported_protocol_version")]
    pub min_supported_protocol_version: u32,
    #[serde(default = "default_latest_client_version")]
    pub latest_client_version: String,
    #[serde(default)]
    pub upgrade_available: bool,
    #[serde(default)]
    pub upgrade_required: bool,
    #[serde(default)]
    pub upgrade_message: String,
    pub install_trust_score: i64,
    pub quarantined: bool,
    pub worker_allowed: bool,
    pub message: String,
    pub server_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionReceipt {
    pub submission_id: String,
    pub accepted: bool,
    pub duplicate: bool,
    pub quarantined: bool,
    pub promoted_clusters: usize,
    pub issue_ids: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueCluster {
    pub id: String,
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
    pub cluster_id: String,
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
    pub issue_id: String,
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
