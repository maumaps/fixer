use crate::config::FixerConfig;
use crate::models::{
    ClientHello, IssueCluster, PatchAttempt, ServerHello, SharedOpportunity, SubmissionEnvelope,
    SubmissionReceipt, WorkLease, WorkOffer, WorkPullRequest, WorkerResultEnvelope,
};
use crate::network::verify_worker_pull_pow;
use crate::pow::verify_pow;
use crate::privacy::PRIVACY_WARNING;
use crate::protocol::{
    CURRENT_PROTOCOL_VERSION, MIN_SUPPORTED_PROTOCOL_VERSION, current_binary_version,
    evaluate_client_compatibility, is_binary_upgrade_available,
};
use crate::util::{hash_text, now_rfc3339};
use anyhow::{Context, Result, anyhow};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path as AxumPath, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio_postgres::{Client, NoTls, Row};
use uuid::Uuid;

const APP_CSS: &str = r#"
:root {
    color-scheme: light;
    --bg: #f5efe4;
    --bg-strong: #fffaf2;
    --panel: rgba(255, 251, 244, 0.82);
    --line: rgba(94, 70, 34, 0.18);
    --text: #2a2012;
    --muted: #6e5a3c;
    --accent: #0b7a75;
    --accent-strong: #095955;
    --warm: #b14c22;
    --good: #245c2d;
    --shadow: 0 18px 40px rgba(66, 45, 15, 0.12);
    --radius: 22px;
    --mono: "Iosevka Term", "JetBrains Mono", "SFMono-Regular", monospace;
    --sans: "IBM Plex Sans", "Segoe UI", sans-serif;
}

* {
    box-sizing: border-box;
}

html, body {
    margin: 0;
    padding: 0;
    font-family: var(--sans);
    background:
        radial-gradient(circle at top left, rgba(11, 122, 117, 0.18), transparent 32%),
        radial-gradient(circle at top right, rgba(177, 76, 34, 0.14), transparent 24%),
        linear-gradient(180deg, #f8f3ea 0%, var(--bg) 100%);
    color: var(--text);
}

body {
    min-height: 100vh;
}

a {
    color: var(--accent-strong);
}

code, pre {
    font-family: var(--mono);
}

.shell {
    width: min(1180px, calc(100% - 2rem));
    margin: 0 auto;
    padding: 1rem 0 4rem;
}

.nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    padding: 1rem 0 1.5rem;
}

.nav a {
    text-decoration: none;
    color: inherit;
}

.brand {
    font-size: 1.15rem;
    font-weight: 700;
    letter-spacing: 0.04em;
}

.nav-links {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
}

.nav-links a,
.nav-status {
    padding: 0.55rem 0.9rem;
    border-radius: 999px;
    border: 1px solid transparent;
}

.nav-links a.active,
.nav-links a:hover {
    border-color: var(--line);
    background: rgba(255, 255, 255, 0.5);
}

.nav-status {
    cursor: default;
    border-color: var(--line);
    background: rgba(255, 255, 255, 0.4);
}

.hero,
.panel {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
}

.hero {
    padding: clamp(1.5rem, 4vw, 3rem);
    overflow: hidden;
    position: relative;
}

.hero::after {
    content: "";
    position: absolute;
    inset: auto -6rem -6rem auto;
    width: 18rem;
    height: 18rem;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(11, 122, 117, 0.18), transparent 68%);
}

.hero h1 {
    font-size: clamp(2rem, 4vw, 4rem);
    line-height: 1;
    margin: 0 0 1rem;
    max-width: 12ch;
}

.hero p {
    margin: 0;
    max-width: 60ch;
    color: var(--muted);
    font-size: 1.05rem;
}

.hero-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.9rem;
    margin-top: 1.5rem;
}

.hero-grid {
    display: grid;
    grid-template-columns: minmax(0, 1.45fr) minmax(300px, 0.9fr);
    gap: 1.2rem;
    align-items: stretch;
}

.home-hero {
    background:
        radial-gradient(circle at top right, rgba(255, 255, 255, 0.62), transparent 36%),
        linear-gradient(135deg, rgba(255, 250, 242, 0.92), rgba(241, 250, 248, 0.92));
}

.home-hero::before {
    content: "";
    position: absolute;
    inset: 1rem auto auto 52%;
    width: 12rem;
    height: 12rem;
    border-radius: 2.4rem;
    border: 1px solid rgba(11, 122, 117, 0.1);
    background: linear-gradient(180deg, rgba(11, 122, 117, 0.06), rgba(11, 122, 117, 0));
    transform: rotate(18deg);
}

.hero-copy,
.live-board {
    position: relative;
    z-index: 1;
}

.hero-copy h1 {
    max-width: 9.5ch;
}

.hero-copy .lede {
    font-size: 1.12rem;
    max-width: 62ch;
}

.mini-badges {
    display: flex;
    flex-wrap: wrap;
    gap: 0.7rem;
    margin-top: 1.15rem;
}

.mini-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.45rem;
    padding: 0.55rem 0.8rem;
    border-radius: 999px;
    border: 1px solid rgba(94, 70, 34, 0.14);
    background: rgba(255, 255, 255, 0.66);
    color: var(--muted);
    font-size: 0.94rem;
}

.mini-badge strong {
    color: var(--text);
}

.live-board {
    padding: 1.15rem;
    border-radius: 20px;
    border: 1px solid rgba(94, 70, 34, 0.12);
    background:
        linear-gradient(180deg, rgba(255, 255, 255, 0.88), rgba(245, 250, 249, 0.84));
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.65);
}

.eyebrow {
    margin: 0 0 0.45rem;
    color: var(--accent-strong);
    font-size: 0.9rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}

.live-board h2 {
    margin: 0;
    font-size: 1.25rem;
}

.live-board p {
    margin-top: 0.45rem;
}

.snapshot-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.8rem;
    margin-top: 1rem;
}

.snapshot-stat {
    padding: 0.95rem;
    border-radius: 16px;
    border: 1px solid rgba(94, 70, 34, 0.12);
    background: rgba(255, 255, 255, 0.78);
}

.snapshot-stat strong {
    display: block;
    margin-bottom: 0.2rem;
    font-size: 1.55rem;
    line-height: 1;
}

.snapshot-stat span {
    color: var(--muted);
    font-size: 0.94rem;
}

.snapshot-foot {
    margin-top: 1rem;
    padding-top: 0.95rem;
    border-top: 1px solid rgba(94, 70, 34, 0.12);
}

.snapshot-foot p {
    margin: 0.2rem 0;
}

.button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 0.8rem 1.15rem;
    border-radius: 999px;
    border: 1px solid var(--line);
    text-decoration: none;
    font-weight: 600;
    background: rgba(255, 255, 255, 0.66);
}

.button.primary {
    background: var(--accent);
    color: white;
    border-color: transparent;
}

.button.primary:hover {
    background: var(--accent-strong);
}

.button.soft {
    background: rgba(11, 122, 117, 0.08);
    border-color: rgba(11, 122, 117, 0.15);
}

.grid {
    display: grid;
    gap: 1rem;
}

.stats {
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    margin-top: 1.25rem;
}

.stat {
    padding: 1rem 1.1rem;
}

.stat-value {
    font-size: clamp(1.6rem, 3vw, 2.4rem);
    font-weight: 700;
    margin-bottom: 0.3rem;
}

.stat-label {
    color: var(--muted);
}

.section {
    margin-top: 1.4rem;
}

.section h2 {
    margin: 0 0 0.6rem;
    font-size: 1.35rem;
}

.section p,
.section li {
    color: var(--muted);
}

.panel {
    padding: 1.25rem;
}

.columns {
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
}

.feature-grid {
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
}

.feature-card {
    padding: 1.15rem;
    border-radius: 18px;
    border: 1px solid var(--line);
    background: rgba(255, 255, 255, 0.62);
}

.feature-card h3 {
    margin: 0 0 0.45rem;
    font-size: 1.02rem;
}

.feature-card p {
    margin: 0;
}

.journey-list {
    display: grid;
    gap: 0.8rem;
    margin-top: 1rem;
}

.journey-step {
    padding: 0.95rem 1rem;
    border-radius: 18px;
    border: 1px solid rgba(94, 70, 34, 0.12);
    background: rgba(255, 255, 255, 0.6);
}

.journey-step strong {
    display: block;
    margin-bottom: 0.3rem;
    font-size: 1rem;
}

.section-intro {
    margin: 0 0 1rem;
    color: var(--muted);
    max-width: 62ch;
}

.callout {
    margin-top: 1rem;
    padding: 0.9rem 1rem;
    border-radius: 18px;
    border: 1px solid rgba(11, 122, 117, 0.14);
    background: rgba(11, 122, 117, 0.06);
}

.callout p {
    margin: 0;
}

.issue-list {
    display: grid;
    gap: 0.9rem;
}

.issue-card {
    padding: 1rem 1.05rem;
    border-radius: 18px;
    border: 1px solid var(--line);
    background: rgba(255, 255, 255, 0.58);
}

.patch-card {
    border-color: rgba(36, 92, 45, 0.2);
    background: linear-gradient(
        180deg,
        rgba(255, 255, 255, 0.82),
        rgba(238, 247, 239, 0.82)
    );
}

.issue-topline {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: flex-start;
}

.issue-card h3 {
    margin: 0;
    font-size: 1.05rem;
}

.issue-summary {
    margin: 0.55rem 0 0.8rem;
}

.impact-summary {
    margin: 0 0 0.85rem;
    padding: 0.8rem 0.9rem;
    border-radius: 14px;
    border: 1px solid rgba(11, 122, 117, 0.12);
    background: rgba(11, 122, 117, 0.06);
    color: var(--text);
}

.impact-summary strong {
    color: var(--accent-strong);
}

.patch-summary,
.patch-preview {
    margin-top: 0.9rem;
}

.patch-copy > :first-child {
    margin-top: 0;
}

.patch-panel {
    border-color: rgba(36, 92, 45, 0.2);
    background: linear-gradient(
        180deg,
        rgba(255, 255, 255, 0.86),
        rgba(238, 247, 239, 0.84)
    );
}

.patch-summary {
    padding: 0.9rem 1rem;
    border-radius: 16px;
    border: 1px solid rgba(36, 92, 45, 0.18);
    background: rgba(36, 92, 45, 0.06);
}

.patch-summary h4,
.patch-preview h4 {
    margin: 0 0 0.55rem;
}

.meta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.55rem;
}

.tag {
    display: inline-flex;
    align-items: center;
    border-radius: 999px;
    background: rgba(11, 122, 117, 0.08);
    border: 1px solid rgba(11, 122, 117, 0.16);
    color: var(--accent-strong);
    padding: 0.35rem 0.7rem;
    font-size: 0.92rem;
}

.tag.patch {
    background: rgba(36, 92, 45, 0.1);
    border-color: rgba(36, 92, 45, 0.16);
    color: var(--good);
}

.tag.impact-high {
    background: rgba(177, 76, 34, 0.12);
    border-color: rgba(177, 76, 34, 0.22);
    color: var(--warm);
}

.tag.impact-medium {
    background: rgba(163, 118, 25, 0.12);
    border-color: rgba(163, 118, 25, 0.22);
    color: #8b5f00;
}

.tag.impact-low {
    background: rgba(11, 122, 117, 0.08);
    border-color: rgba(11, 122, 117, 0.16);
    color: var(--accent-strong);
}

.tag.triage {
    background: rgba(163, 118, 25, 0.12);
    border-color: rgba(163, 118, 25, 0.22);
    color: #8b5f00;
}

.tag.severity-high {
    background: rgba(177, 76, 34, 0.12);
    border-color: rgba(177, 76, 34, 0.22);
    color: var(--warm);
}

.tag.severity-medium {
    background: rgba(163, 118, 25, 0.12);
    border-color: rgba(163, 118, 25, 0.22);
    color: #8b5f00;
}

.tag.severity-low {
    background: rgba(11, 122, 117, 0.08);
}

.lede {
    font-size: 1.05rem;
    max-width: 70ch;
}

.code-block {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    padding: 1rem;
    border-radius: 16px;
    border: 1px solid var(--line);
    background: #211a12;
    color: #fef3db;
}

.attempt-session {
    margin-top: 0.95rem;
}

.attempt-session summary {
    cursor: pointer;
    font-weight: 600;
    color: var(--accent-strong);
}

.fine-print {
    font-size: 0.95rem;
}

.footer {
    margin-top: 2rem;
    color: var(--muted);
}

@media (max-width: 720px) {
    .nav {
        flex-direction: column;
        align-items: flex-start;
    }

    .issue-topline {
        flex-direction: column;
    }

    .hero-grid {
        grid-template-columns: 1fr;
    }

    .snapshot-grid {
        grid-template-columns: 1fr 1fr;
    }
}
"#;

const HEALTH_INDICATOR_SCRIPT: &str = r#"
<script>
(() => {
    const indicator = document.getElementById("health-indicator");
    if (!indicator) {
        return;
    }

    const render = (emoji, title) => {
        indicator.textContent = `${emoji} Health`;
        indicator.setAttribute("aria-label", title);
        indicator.title = title;
    };

    const update = async () => {
        try {
            const response = await fetch("/healthz", {
                headers: { accept: "application/json" },
                cache: "no-store",
            });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const payload = await response.json();
            const healthy = payload.status === "ok" && payload.database === "ok";
            if (healthy) {
                render("🟢", "Health: server and database are ok");
                return;
            }
            render(
                "🔴",
                `Health: server=${payload.status ?? "unknown"}, database=${payload.database ?? "unknown"}`
            );
        } catch (_error) {
            render("🔴", "Health: request failed");
        }
    };

    update();
})();
</script>
"#;

#[derive(Clone)]
struct ServerState {
    config: FixerConfig,
    db: ServerDb,
}

#[derive(Clone)]
enum ServerDb {
    Postgres(Arc<Client>),
    Sqlite(PathBuf),
}

#[derive(Debug, Clone, Serialize)]
struct PublicIssue {
    id: String,
    kind: String,
    title: String,
    summary: String,
    package_name: Option<String>,
    source_package: Option<String>,
    ecosystem: Option<String>,
    severity: Option<String>,
    score: i64,
    corroboration_count: i64,
    best_patch_available: bool,
    best_triage_available: bool,
    last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublishedAttemptSession {
    prompt: String,
    response: Option<String>,
    diff: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    models_used: Vec<String>,
    #[serde(default)]
    rate_limit_fallback_used: bool,
}

#[derive(Debug, Clone)]
struct PublicPatchCover {
    subject: String,
    commit_message: String,
    problem: String,
    issue_connection: String,
    changed_files: Vec<String>,
    validation_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PublicAttempt {
    outcome: String,
    state: String,
    summary: String,
    validation_status: Option<String>,
    created_at: String,
    published_session: Option<PublishedAttemptSession>,
    handoff: Option<PublicTriageHandoff>,
    blocker_reason: Option<String>,
    failure_diagnostics: Option<PublicFailureDiagnostics>,
    failure_context: Option<PublicFailureContext>,
}

#[derive(Debug, Clone, Serialize)]
struct PublicFailureDiagnostics {
    failure_kind: Option<String>,
    review_failure_category: Option<String>,
    exit_status: Option<i32>,
    error: Option<String>,
    last_stderr_excerpt: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PublicFailureContext {
    note: Option<String>,
    subsystem: Option<String>,
    loop_classification: Option<String>,
    hot_path_symbol: Option<String>,
    command_line: Option<String>,
    loop_explanation: Option<String>,
    thread_backtrace_summary: Option<String>,
    raw_backtrace_excerpt: Option<String>,
    representative_backtraces: Vec<String>,
    common_frame_clusters: Vec<String>,
    lock_contention_signals: Vec<String>,
    implicated_packages: Vec<String>,
    source_package: Option<String>,
    source_kind: Option<String>,
    acquisition_note: Option<String>,
    homepage: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PublicAttemptEntry {
    issue_id: String,
    issue_title: String,
    issue_summary: String,
    kind: String,
    package_name: Option<String>,
    source_package: Option<String>,
    ecosystem: Option<String>,
    severity: Option<String>,
    score: i64,
    corroboration_count: i64,
    best_patch_available: bool,
    best_triage_available: bool,
    attempt: PublicAttempt,
}

#[derive(Debug, Clone, Serialize, Default)]
struct PublicAttemptSummary {
    total_attempt_count: usize,
    ready_patch_count: usize,
    ready_triage_count: usize,
    ready_report_count: usize,
    failed_patch_count: usize,
    explained_impossible_count: usize,
    other_attempt_count: usize,
    top_blockers: Vec<PublicAttemptBlocker>,
}

#[derive(Debug, Clone, Serialize)]
struct PublicAttemptBlocker {
    label: String,
    count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublicTriageHandoff {
    reason: String,
    target: String,
    report_url: Option<String>,
    next_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PublicIssueDetail {
    id: String,
    kind: String,
    title: String,
    summary: String,
    package_name: Option<String>,
    source_package: Option<String>,
    ecosystem: Option<String>,
    severity: Option<String>,
    score: i64,
    corroboration_count: i64,
    best_patch_available: bool,
    best_triage_available: bool,
    best_patch_diff_url: Option<String>,
    best_patch: Option<PublicAttempt>,
    best_triage: Option<PublicAttempt>,
    best_triage_handoff: Option<PublicTriageHandoff>,
    last_seen: String,
    technical_snapshot: Option<PublicTechnicalSnapshot>,
    possible_duplicates: Vec<PublicPossibleDuplicate>,
    attempt_summary: PublicAttemptSummary,
    attempts_omitted_count: usize,
    attempts: Vec<PublicAttempt>,
    showing_all_attempts: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptBoardFilter {
    All,
    Reports,
    Failures,
    Impossible,
}

#[derive(Debug, Deserialize, Default)]
struct AttemptBoardQuery {
    kind: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct IssueDetailQuery {
    all_attempts: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PublicTechnicalSnapshot {
    title: String,
    summary: String,
    frames: Vec<String>,
    highlights: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PublicPossibleDuplicate {
    id: String,
    kind: String,
    title: String,
    summary: String,
    package_name: Option<String>,
    source_package: Option<String>,
    ecosystem: Option<String>,
    severity: Option<String>,
    score: i64,
    corroboration_count: i64,
    best_patch_available: bool,
    best_triage_available: bool,
    last_seen: String,
    similarity_score: f64,
    match_reasons: Vec<String>,
}

#[derive(Debug, Clone)]
struct DuplicateCandidateIssue {
    issue: PublicIssue,
    representative: SharedOpportunity,
}

#[derive(Debug, Clone)]
struct PublicIssueCandidate {
    issue: PublicIssue,
    signals: IssuePrioritySignals,
}

#[derive(Debug, Clone, Default)]
struct IssuePrioritySignals {
    subsystem: Option<String>,
    target_name: Option<String>,
    likely_external_root_cause: bool,
}

#[derive(Debug, Clone)]
struct IssueHumanContext {
    kind_label: String,
    impact_label: String,
    impact_class: String,
    impact_summary: String,
}

#[derive(Debug, Clone)]
struct DuplicateMatchFeatures {
    kind: String,
    normalized_title: String,
    normalized_summary: String,
    package_name: Option<String>,
    source_package: Option<String>,
    ecosystem: Option<String>,
    subsystem: Option<String>,
    classification: Option<String>,
    wchan: Option<String>,
    target_name: Option<String>,
    primary_signature: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PublicPatchEntry {
    id: String,
    kind: String,
    title: String,
    summary: String,
    package_name: Option<String>,
    source_package: Option<String>,
    ecosystem: Option<String>,
    severity: Option<String>,
    score: i64,
    corroboration_count: i64,
    last_seen: String,
    best_patch_diff_url: Option<String>,
    best_patch: PublicAttempt,
}

#[derive(Debug, Clone, Serialize)]
struct PublicTriageEntry {
    id: String,
    kind: String,
    title: String,
    summary: String,
    package_name: Option<String>,
    source_package: Option<String>,
    ecosystem: Option<String>,
    severity: Option<String>,
    score: i64,
    corroboration_count: i64,
    last_seen: String,
    best_triage: PublicAttempt,
    handoff: PublicTriageHandoff,
}

#[derive(Debug, Clone, Serialize)]
struct Healthz {
    status: &'static str,
    database: &'static str,
    server_time: String,
}

#[derive(Debug, Clone)]
struct DashboardSnapshot {
    install_count: i64,
    submission_count: i64,
    promoted_issue_count: i64,
    quarantined_issue_count: i64,
    ready_patch_count: i64,
    ready_triage_count: i64,
    ready_report_count: i64,
    failed_patch_attempt_count: i64,
    explained_impossible_count: i64,
    corroborated_public_issue_count: i64,
    largest_public_cluster_size: i64,
    last_submission_at: Option<String>,
    top_issues: Vec<PublicIssueCandidate>,
}

fn sqlite_path_from_url(url: &str) -> Option<PathBuf> {
    let rest = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))?;
    let path = if rest.starts_with('/') {
        PathBuf::from(rest)
    } else {
        PathBuf::from(format!("./{rest}"))
    };
    Some(path)
}

fn sqlite_connection(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let connection =
        Connection::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    connection
        .busy_timeout(StdDuration::from_secs(5))
        .context("failed to configure sqlite busy timeout")?;
    Ok(connection)
}

async fn open_server_db(config: &FixerConfig) -> Result<ServerDb> {
    if let Some(path) = sqlite_path_from_url(&config.server.postgres_url) {
        return Ok(ServerDb::Sqlite(path));
    }
    let (client, connection) = tokio_postgres::connect(&config.server.postgres_url, NoTls)
        .await
        .with_context(|| format!("failed to connect to {}", config.server.postgres_url))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::error!(?error, "postgres connection failed");
        }
    });
    Ok(ServerDb::Postgres(Arc::new(client)))
}

async fn db_ping(db: &ServerDb) -> Result<()> {
    match db {
        ServerDb::Postgres(client) => {
            let _: i32 = client.query_one("SELECT 1", &[]).await?.get(0);
            Ok(())
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let _: i64 = connection.query_row("SELECT 1", [], |row| row.get(0))?;
            Ok(())
        }
    }
}

pub async fn serve(config: FixerConfig) -> Result<()> {
    let db = open_server_db(&config).await?;
    let state = Arc::new(ServerState {
        config: config.clone(),
        db,
    });
    let maintenance_db = state.db.clone();
    let maintenance_config = config.clone();
    let maintenance_threshold = config.server.quarantine_corroboration_threshold;

    let app = Router::new()
        .route("/", get(landing_page))
        .route("/robots.txt", get(robots_txt))
        .route("/issues", get(public_issues_page))
        .route("/attempts", get(public_attempts_page))
        .route("/triage", get(public_triage_page))
        .route("/patches", get(public_patches_page))
        .route("/issues/{id}/best.patch", get(public_issue_best_patch))
        .route("/issues/{id}/best.diff", get(public_issue_best_diff))
        .route("/issues/{id}", get(public_issue_detail_page))
        .route("/healthz", get(healthz))
        .route("/assets/app.css", get(stylesheet))
        .route("/v1/install/hello", post(install_hello))
        .route("/v1/submissions", post(submit_bundle))
        .route("/v1/work/pull", post(pull_work))
        .route("/v1/work/{lease_id}/result", post(submit_work_result))
        .route("/v1/issues", get(list_issues))
        .route("/v1/attempts", get(list_attempts))
        .route("/v1/triage", get(list_triage))
        .route("/v1/patches", get(list_patches))
        .route("/v1/issues/{id}", get(get_issue))
        .route(
            "/v1/evidence-requests/{id}/respond",
            post(respond_evidence_request),
        )
        .layer(DefaultBodyLimit::max(config.server.max_payload_bytes))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.server.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.server.listen))?;
    tokio::spawn(async move {
        let result = async {
            init_db(&maintenance_db, &maintenance_config).await?;
            run_startup_maintenance(&maintenance_db, maintenance_threshold).await
        }
        .await;
        if let Err(error) = result {
            tracing::error!(?error, "fixer-server startup maintenance failed");
        }
    });
    tracing::info!("fixer-server listening on {}", config.server.listen);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server failed")?;
    Ok(())
}

async fn landing_page(State(state): State<Arc<ServerState>>) -> Result<Html<String>, ApiError> {
    let snapshot = load_dashboard_snapshot(&state.db).await?;
    Ok(Html(render_landing_page(&state.config, &snapshot)))
}

async fn public_issues_page(
    State(state): State<Arc<ServerState>>,
) -> Result<Html<String>, ApiError> {
    let issues = load_public_issue_candidates(&state.db, 100).await?;
    Ok(Html(render_issues_page(&issues)))
}

async fn public_attempts_page(
    State(state): State<Arc<ServerState>>,
    Query(query): Query<AttemptBoardQuery>,
) -> Result<Html<String>, ApiError> {
    let filter = attempt_board_filter_from_query(query.kind.as_deref())?;
    let attempts = load_public_attempt_entries(&state.db, filter, 250).await?;
    Ok(Html(render_attempts_page(filter, &attempts)))
}

async fn public_patches_page(
    State(state): State<Arc<ServerState>>,
) -> Result<Html<String>, ApiError> {
    let patches = load_public_patches(&state.db, 100).await?;
    Ok(Html(render_patches_page(&patches)))
}

async fn public_triage_page(
    State(state): State<Arc<ServerState>>,
) -> Result<Html<String>, ApiError> {
    let triage = load_public_triage(&state.db, 100).await?;
    Ok(Html(render_triage_page(&triage)))
}

async fn public_issue_detail_page(
    State(state): State<Arc<ServerState>>,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<IssueDetailQuery>,
) -> Result<Html<String>, ApiError> {
    validate_uuid_param(&id, "issue id")?;
    let show_all_attempts = query
        .all_attempts
        .as_deref()
        .map(|value| matches!(value, "1" | "true" | "yes" | "all"))
        .unwrap_or(false);
    let issue = load_public_issue_detail(&state.db, id, show_all_attempts).await?;
    Ok(Html(render_issue_detail_page(&issue)))
}

async fn robots_txt() -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        concat!(
            "User-agent: *\n",
            "Allow: /\n",
            "Allow: /issues\n",
            "Allow: /issues/\n",
            "Allow: /attempts\n",
            "Allow: /patches\n",
            "Allow: /triage\n",
            "Disallow: /v1/\n",
            "Disallow: /healthz\n",
            "Disallow: /issues/*/best.patch\n",
            "Disallow: /issues/*/best.diff\n",
            "Disallow: /apt/\n"
        ),
    )
        .into_response()
}

async fn public_issue_best_patch(
    State(state): State<Arc<ServerState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, ApiError> {
    validate_uuid_param(&id, "issue id")?;
    let issue = load_public_issue_detail(&state.db, id, true).await?;
    let best_patch = issue
        .best_patch
        .as_ref()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "public patch not found"))?;
    let patch = render_public_patch_email(&issue, best_patch)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "public patch diff not found"))?;
    Ok((
        [(header::CONTENT_TYPE, "text/x-patch; charset=utf-8")],
        patch,
    )
        .into_response())
}

async fn public_issue_best_diff(
    State(state): State<Arc<ServerState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, ApiError> {
    validate_uuid_param(&id, "issue id")?;
    let best_patch = load_public_issue_best_patch(&state.db, &id).await?;
    let diff = best_patch
        .as_ref()
        .and_then(public_attempt_diff)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "public patch diff not found"))?;
    Ok((
        [(header::CONTENT_TYPE, "text/x-diff; charset=utf-8")],
        diff.to_string(),
    )
        .into_response())
}

async fn healthz(State(state): State<Arc<ServerState>>) -> Result<Json<Healthz>, ApiError> {
    db_ping(&state.db).await.map_err(ApiError::internal)?;
    Ok(Json(Healthz {
        status: "ok",
        database: "ok",
        server_time: now_rfc3339(),
    }))
}

async fn stylesheet() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS)
}

async fn install_hello(
    State(state): State<Arc<ServerState>>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Json(request): Json<ClientHello>,
) -> Result<Json<ServerHello>, ApiError> {
    let remote_ip = remote_addr.ip().to_string();
    let install_id = request.install_id.clone();
    let config = state.config.clone();
    ensure_install(&state.db, &request, remote_ip, &config)
        .await
        .map_err(ApiError::internal)?;
    let (submission_trust, worker_trust, banned_until) = install_trust(&state.db, &install_id)
        .await
        .map_err(ApiError::internal)?;
    if banned_until.map(|ts| ts > Utc::now()).unwrap_or(false) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "install is temporarily banned due to repeated abusive requests",
        ));
    }
    let compatibility = evaluate_client_compatibility(request.protocol_version, &request.version);
    let worker_allowed = request.mode.can_work()
        && request.has_codex
        && !compatibility.upgrade_required
        && (worker_trust >= state.config.server.worker_trust_minimum
            || submission_trust >= state.config.server.worker_trust_minimum);
    Ok(Json(ServerHello {
        policy_version: state.config.privacy.policy_version.clone(),
        submission_pow_difficulty: state.config.server.submission_pow_difficulty,
        worker_pow_difficulty: state.config.server.worker_pow_difficulty,
        server_protocol_version: CURRENT_PROTOCOL_VERSION,
        min_supported_protocol_version: MIN_SUPPORTED_PROTOCOL_VERSION,
        latest_client_version: current_binary_version().to_string(),
        upgrade_available: compatibility.upgrade_available,
        upgrade_required: compatibility.upgrade_required,
        upgrade_message: compatibility.upgrade_message,
        install_trust_score: submission_trust.max(worker_trust),
        quarantined: submission_trust < state.config.server.quarantine_corroboration_threshold,
        worker_allowed,
        message: PRIVACY_WARNING.to_string(),
        server_time: now_rfc3339(),
    }))
}

async fn submit_bundle(
    State(state): State<Arc<ServerState>>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Json(envelope): Json<SubmissionEnvelope>,
) -> Result<Json<SubmissionReceipt>, ApiError> {
    let payload_size = serde_json::to_vec(&envelope)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX);
    if payload_size > state.config.server.max_payload_bytes {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "submission exceeded the configured payload size limit",
        ));
    }
    if envelope.bundle.items.len() > state.config.server.max_bundle_items {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "submission contains too many items",
        ));
    }
    if !envelope.client.mode.can_submit() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "this install is not opted in for submissions",
        ));
    }

    let remote_ip = remote_addr.ip().to_string();
    let install_id = envelope.client.install_id.clone();
    let config = state.config.clone();

    if !verify_pow(
        &install_id,
        &envelope.proof_of_work,
        &envelope.content_hash,
        state.config.server.submission_pow_difficulty,
        30,
    ) {
        record_abuse(&state.db, &install_id, "invalid-submission-pow", &config)
            .await
            .map_err(ApiError::internal)?;
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "invalid or stale proof-of-work",
        ));
    }

    ensure_install(&state.db, &envelope.client, remote_ip.clone(), &config)
        .await
        .map_err(ApiError::internal)?;
    reject_incompatible_client(&envelope.client)?;

    let rate_limited_submission = rate_limited(
        &state.db,
        "submission",
        &install_id,
        &remote_ip,
        state.config.server.max_submissions_per_hour,
    )
    .await
    .map_err(ApiError::internal)?;
    if rate_limited_submission {
        record_abuse(&state.db, &install_id, "submission-rate-limit", &config)
            .await
            .map_err(ApiError::internal)?;
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "submission rate limit exceeded",
        ));
    }

    let bundle_json = serde_json::to_value(&envelope.bundle).map_err(ApiError::internal)?;
    let payload_hash = envelope.proof_of_work.payload_hash.clone();
    let content_hash = envelope.content_hash.clone();
    if let Some(existing_id) = find_submission_by_content_hash(&state.db, &content_hash)
        .await
        .map_err(ApiError::internal)?
    {
        return Ok(Json(SubmissionReceipt {
            submission_id: existing_id,
            accepted: true,
            duplicate: true,
            quarantined: true,
            promoted_clusters: 0,
            issue_ids: Vec::new(),
            message: "duplicate submission ignored".to_string(),
        }));
    }

    let received_at = Utc::now();
    let submission_id = insert_submission(
        &state.db,
        &install_id,
        &content_hash,
        &payload_hash,
        received_at,
        &remote_ip,
        &bundle_json,
    )
    .await
    .map_err(ApiError::internal)?;
    mark_submission_received(&state.db, &install_id, received_at)
        .await
        .map_err(ApiError::internal)?;
    note_rate_event(&state.db, "submission", &install_id, &remote_ip)
        .await
        .map_err(ApiError::internal)?;

    let submission_trust = install_trust(&state.db, &install_id)
        .await
        .map_err(ApiError::internal)?
        .0;
    let mut issue_ids = Vec::new();
    let mut issue_by_local_opportunity_id = HashMap::new();
    let mut promoted_clusters = 0_usize;
    for item in &envelope.bundle.items {
        let cluster_key = cluster_key_for(item);
        let issue_id = upsert_issue_cluster(
            &state.db,
            item,
            &cluster_key,
            &submission_id,
            &install_id,
            submission_trust,
            &state.config,
        )
        .await
        .map_err(ApiError::internal)?;
        let promoted = is_issue_promoted(&state.db, &issue_id)
            .await
            .map_err(ApiError::internal)?;
        if promoted {
            promoted_clusters += 1;
        }
        issue_by_local_opportunity_id.insert(item.local_opportunity_id, issue_id.clone());
        issue_ids.push(issue_id);
    }
    for proposal in &envelope.bundle.proposals {
        let issue_id = issue_by_local_opportunity_id
            .get(&proposal.local_opportunity_id)
            .cloned()
            .or_else(|| proposal.remote_issue_id.clone());
        let Some(issue_id) = issue_id else {
            continue;
        };
        store_submitted_proposal_result(&state.db, &issue_id, &proposal.result)
            .await
            .map_err(ApiError::internal)?;
    }
    if promoted_clusters > 0 {
        bump_submission_trust(&state.db, &install_id)
            .await
            .map_err(ApiError::internal)?;
    }

    let receipt = SubmissionReceipt {
        submission_id,
        accepted: true,
        duplicate: false,
        quarantined: promoted_clusters == 0,
        promoted_clusters,
        issue_ids,
        message: if promoted_clusters > 0 {
            "submission accepted and at least one issue cluster is promoted".to_string()
        } else {
            "submission accepted into quarantine pending corroboration".to_string()
        },
    };

    Ok(Json(receipt))
}

async fn pull_work(
    State(state): State<Arc<ServerState>>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Json(request): Json<WorkPullRequest>,
) -> Result<Json<WorkOffer>, ApiError> {
    if !request.client.mode.can_work() || !request.client.has_codex {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "this install is not opted in as a worker",
        ));
    }
    let remote_ip = remote_addr.ip().to_string();
    let install_id = request.client.install_id.clone();
    let config = state.config.clone();

    if !verify_worker_pull_pow(
        &install_id,
        &request,
        state.config.server.worker_pow_difficulty,
    ) {
        record_abuse(&state.db, &install_id, "invalid-worker-pow", &config)
            .await
            .map_err(ApiError::internal)?;
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "invalid or stale worker proof-of-work",
        ));
    }

    ensure_install(&state.db, &request.client, remote_ip.clone(), &config)
        .await
        .map_err(ApiError::internal)?;
    reject_incompatible_client(&request.client)?;

    let rate_limited_pull = rate_limited(
        &state.db,
        "work-pull",
        &install_id,
        &remote_ip,
        state.config.server.max_work_pulls_per_hour,
    )
    .await
    .map_err(ApiError::internal)?;
    if rate_limited_pull {
        record_abuse(&state.db, &install_id, "worker-rate-limit", &config)
            .await
            .map_err(ApiError::internal)?;
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "worker pull rate limit exceeded",
        ));
    }

    note_rate_event(&state.db, "work-pull", &install_id, &remote_ip)
        .await
        .map_err(ApiError::internal)?;
    let (submission_trust, worker_trust, banned_until) = install_trust(&state.db, &install_id)
        .await
        .map_err(ApiError::internal)?;
    if banned_until
        .map(|value| value > Utc::now())
        .unwrap_or(false)
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "install is temporarily banned due to repeated abusive requests",
        ));
    }
    if worker_trust < state.config.server.worker_trust_minimum
        && submission_trust < state.config.server.worker_trust_minimum
    {
        return Ok(Json(WorkOffer {
            message:
                "worker is still quarantined; gain trust through corroborated submissions first"
                    .to_string(),
            lease: None,
        }));
    }

    let worker_model = request.client.patch_model.clone();
    let Some(mut issue) = next_issue_for_worker(
        &state.db,
        &install_id,
        state.config.server.worker_attempt_cooldown_seconds,
        worker_model,
    )
    .await
    .map_err(ApiError::internal)?
    else {
        return Ok(Json(WorkOffer {
            message: "no promoted work is currently available".to_string(),
            lease: None,
        }));
    };
    if issue.best_patch.is_none() {
        issue.best_patch = load_latest_patch_context_for_worker(&state.db, &issue.id)
            .await
            .map_err(ApiError::internal)?;
    }
    let lease_id = new_server_id();
    let leased_at = Utc::now();
    let expires_at = leased_at + Duration::seconds(state.config.server.lease_seconds as i64);
    let lease = WorkLease {
        lease_id: lease_id.clone(),
        issued_at: leased_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        issue: issue.clone(),
    };
    insert_worker_lease(
        &state.db,
        &lease,
        &install_id,
        &issue.id,
        leased_at,
        expires_at,
    )
    .await
    .map_err(ApiError::internal)?;

    let result = WorkOffer {
        message: "lease granted".to_string(),
        lease: Some(lease),
    };

    Ok(Json(result))
}

async fn submit_work_result(
    State(state): State<Arc<ServerState>>,
    AxumPath(lease_id): AxumPath<String>,
    Json(result): Json<WorkerResultEnvelope>,
) -> Result<Json<WorkerResultEnvelope>, ApiError> {
    if result.lease_id != lease_id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "lease id in path and payload do not match",
        ));
    }
    let lease_row = active_worker_lease(&state.db, &lease_id)
        .await
        .map_err(ApiError::internal)?;
    let Some(lease_row) = lease_row else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "lease was not found or is no longer active",
        ));
    };
    let (cluster_id, install_id, expires_at) = lease_row;
    if install_id != result.attempt.install_id {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "worker result does not belong to the lease holder",
        ));
    }
    if expires_at < Utc::now() {
        return Err(ApiError::new(
            StatusCode::GONE,
            "lease expired before the worker submitted a result",
        ));
    }
    let result = canonicalize_worker_result_envelope(result);
    let result_clone = result.clone();

    store_worker_result(&state.db, &cluster_id, &result)
        .await
        .map_err(ApiError::internal)?;
    if let Some(request) = &result.evidence_request {
        store_evidence_request(&state.db, request)
            .await
            .map_err(ApiError::internal)?;
    }
    Ok(Json(result_clone))
}

async fn list_issues(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<Vec<PublicIssue>>, ApiError> {
    let issues = load_public_issues(&state.db, 100).await?;
    Ok(Json(issues))
}

async fn list_patches(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<Vec<PublicPatchEntry>>, ApiError> {
    let patches = load_public_patches(&state.db, 100).await?;
    Ok(Json(patches))
}

async fn list_triage(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<Vec<PublicTriageEntry>>, ApiError> {
    let triage = load_public_triage(&state.db, 100).await?;
    Ok(Json(triage))
}

async fn list_attempts(
    State(state): State<Arc<ServerState>>,
    Query(query): Query<AttemptBoardQuery>,
) -> Result<Json<Vec<PublicAttemptEntry>>, ApiError> {
    let filter = attempt_board_filter_from_query(query.kind.as_deref())?;
    let attempts = load_public_attempt_entries(&state.db, filter, 250).await?;
    Ok(Json(attempts))
}

async fn get_issue(
    State(state): State<Arc<ServerState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<PublicIssueDetail>, ApiError> {
    validate_uuid_param(&id, "issue id")?;
    let issue = load_public_issue_detail(&state.db, id, true).await?;
    Ok(Json(issue))
}

async fn respond_evidence_request(
    State(state): State<Arc<ServerState>>,
    AxumPath(id): AxumPath<String>,
    Json(response): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    validate_uuid_param(&id, "evidence request id")?;
    let updated = respond_evidence_request_storage(&state.db, &id, &response)
        .await
        .map_err(ApiError::internal)?;
    if !updated {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "evidence request not found",
        ));
    }
    Ok(Json(json!({"id": id, "stored": true})))
}

async fn init_db(db: &ServerDb, config: &FixerConfig) -> Result<()> {
    if needs_schema_migration(db).await? {
        migrate_legacy_schema(db, config).await?;
    }
    ensure_current_schema(db).await
}

async fn run_startup_maintenance(
    db: &ServerDb,
    quarantine_corroboration_threshold: i64,
) -> Result<()> {
    backfill_result_classification(db).await?;
    recluster_current_issue_state(db, quarantine_corroboration_threshold).await
}

async fn ensure_current_schema(db: &ServerDb) -> Result<()> {
    match db {
        ServerDb::Postgres(client) => {
            client
                .batch_execute(
                    "
        CREATE TABLE IF NOT EXISTS installs (
            install_id TEXT PRIMARY KEY,
            first_seen TIMESTAMPTZ NOT NULL,
            last_seen TIMESTAMPTZ NOT NULL,
            mode TEXT NOT NULL,
            hostname TEXT,
            version TEXT NOT NULL,
            has_codex BOOLEAN NOT NULL DEFAULT FALSE,
            capabilities_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            last_ip TEXT,
            submission_trust_score BIGINT NOT NULL DEFAULT 0,
            worker_trust_score BIGINT NOT NULL DEFAULT 0,
            submission_count BIGINT NOT NULL DEFAULT 0,
            worker_result_count BIGINT NOT NULL DEFAULT 0,
            abuse_events BIGINT NOT NULL DEFAULT 0,
            banned_until TIMESTAMPTZ,
            patch_driver TEXT,
            patch_model TEXT
        );

        CREATE TABLE IF NOT EXISTS submissions (
            id TEXT PRIMARY KEY,
            install_id TEXT NOT NULL REFERENCES installs(install_id),
            content_hash TEXT NOT NULL UNIQUE,
            payload_hash TEXT NOT NULL,
            received_at TIMESTAMPTZ NOT NULL,
            remote_addr TEXT,
            quarantined BOOLEAN NOT NULL DEFAULT TRUE,
            bundle_json JSONB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS issue_clusters (
            id TEXT PRIMARY KEY,
            cluster_key TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            public_title TEXT NOT NULL,
            public_summary TEXT NOT NULL,
            public_visible BOOLEAN NOT NULL DEFAULT FALSE,
            package_name TEXT,
            source_package TEXT,
            ecosystem TEXT,
            severity TEXT,
            score BIGINT NOT NULL DEFAULT 0,
            corroboration_count BIGINT NOT NULL DEFAULT 0,
            quarantined BOOLEAN NOT NULL DEFAULT TRUE,
            promoted BOOLEAN NOT NULL DEFAULT FALSE,
            representative_json JSONB NOT NULL,
            best_patch_json JSONB,
            best_triage_json JSONB,
            last_seen TIMESTAMPTZ NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cluster_reports (
            cluster_id TEXT NOT NULL REFERENCES issue_clusters(id) ON DELETE CASCADE,
            install_id TEXT NOT NULL REFERENCES installs(install_id),
            submission_id TEXT NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (cluster_id, install_id)
        );

        CREATE TABLE IF NOT EXISTS worker_leases (
            id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL REFERENCES issue_clusters(id) ON DELETE CASCADE,
            install_id TEXT NOT NULL REFERENCES installs(install_id),
            state TEXT NOT NULL,
            leased_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            work_json JSONB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS patch_attempts (
            id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL REFERENCES issue_clusters(id) ON DELETE CASCADE,
            lease_id TEXT REFERENCES worker_leases(id),
            install_id TEXT NOT NULL REFERENCES installs(install_id),
            outcome TEXT NOT NULL,
            state TEXT NOT NULL,
            summary TEXT NOT NULL,
            bundle_json JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL
        );

        CREATE TABLE IF NOT EXISTS evidence_requests (
            id TEXT PRIMARY KEY,
            issue_id TEXT NOT NULL REFERENCES issue_clusters(id) ON DELETE CASCADE,
            requested_by_install_id TEXT,
            reason TEXT NOT NULL,
            requested_fields_json JSONB NOT NULL,
            requested_at TIMESTAMPTZ NOT NULL,
            response_json JSONB
        );

        CREATE TABLE IF NOT EXISTS rate_events (
            id TEXT PRIMARY KEY,
            scope_kind TEXT NOT NULL,
            scope_value TEXT NOT NULL,
            event_kind TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL
        );
        ",
                )
                .await?;
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            connection.execute_batch(
                "
        CREATE TABLE IF NOT EXISTS installs (
            install_id TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            mode TEXT NOT NULL,
            hostname TEXT,
            version TEXT NOT NULL,
            has_codex INTEGER NOT NULL DEFAULT 0,
            capabilities_json TEXT NOT NULL DEFAULT '[]',
            last_ip TEXT,
            submission_trust_score INTEGER NOT NULL DEFAULT 0,
            worker_trust_score INTEGER NOT NULL DEFAULT 0,
            submission_count INTEGER NOT NULL DEFAULT 0,
            worker_result_count INTEGER NOT NULL DEFAULT 0,
            abuse_events INTEGER NOT NULL DEFAULT 0,
            banned_until TEXT,
            patch_driver TEXT,
            patch_model TEXT
        );

        CREATE TABLE IF NOT EXISTS submissions (
            id TEXT PRIMARY KEY,
            install_id TEXT NOT NULL REFERENCES installs(install_id),
            content_hash TEXT NOT NULL UNIQUE,
            payload_hash TEXT NOT NULL,
            received_at TEXT NOT NULL,
            remote_addr TEXT,
            quarantined INTEGER NOT NULL DEFAULT 1,
            bundle_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS issue_clusters (
            id TEXT PRIMARY KEY,
            cluster_key TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            public_title TEXT NOT NULL,
            public_summary TEXT NOT NULL,
            public_visible INTEGER NOT NULL DEFAULT 0,
            package_name TEXT,
            source_package TEXT,
            ecosystem TEXT,
            severity TEXT,
            score INTEGER NOT NULL DEFAULT 0,
            corroboration_count INTEGER NOT NULL DEFAULT 0,
            quarantined INTEGER NOT NULL DEFAULT 1,
            promoted INTEGER NOT NULL DEFAULT 0,
            representative_json TEXT NOT NULL,
            best_patch_json TEXT,
            best_triage_json TEXT,
            last_seen TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cluster_reports (
            cluster_id TEXT NOT NULL REFERENCES issue_clusters(id) ON DELETE CASCADE,
            install_id TEXT NOT NULL REFERENCES installs(install_id),
            submission_id TEXT NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            PRIMARY KEY (cluster_id, install_id)
        );

        CREATE TABLE IF NOT EXISTS worker_leases (
            id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL REFERENCES issue_clusters(id) ON DELETE CASCADE,
            install_id TEXT NOT NULL REFERENCES installs(install_id),
            state TEXT NOT NULL,
            leased_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            work_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS patch_attempts (
            id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL REFERENCES issue_clusters(id) ON DELETE CASCADE,
            lease_id TEXT REFERENCES worker_leases(id),
            install_id TEXT NOT NULL REFERENCES installs(install_id),
            outcome TEXT NOT NULL,
            state TEXT NOT NULL,
            summary TEXT NOT NULL,
            bundle_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS evidence_requests (
            id TEXT PRIMARY KEY,
            issue_id TEXT NOT NULL REFERENCES issue_clusters(id) ON DELETE CASCADE,
            requested_by_install_id TEXT,
            reason TEXT NOT NULL,
            requested_fields_json TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            response_json TEXT
        );

        CREATE TABLE IF NOT EXISTS rate_events (
            id TEXT PRIMARY KEY,
            scope_kind TEXT NOT NULL,
            scope_value TEXT NOT NULL,
            event_kind TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        ",
            )?;
        }
    }
    ensure_forward_issue_cluster_schema(db).await?;
    ensure_forward_installs_schema(db).await?;
    Ok(())
}

async fn ensure_forward_installs_schema(db: &ServerDb) -> Result<()> {
    match db {
        ServerDb::Postgres(db) => {
            db.batch_execute(
                "
            ALTER TABLE installs ADD COLUMN IF NOT EXISTS patch_driver TEXT;
            ALTER TABLE installs ADD COLUMN IF NOT EXISTS patch_model TEXT
            ",
            )
            .await?;
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let mut stmt = connection.prepare("PRAGMA table_info(installs)")?;
            let columns = stmt
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if !columns.iter().any(|name| name == "patch_driver") {
                connection.execute("ALTER TABLE installs ADD COLUMN patch_driver TEXT", [])?;
            }
            if !columns.iter().any(|name| name == "patch_model") {
                connection.execute("ALTER TABLE installs ADD COLUMN patch_model TEXT", [])?;
            }
        }
    }
    Ok(())
}

async fn ensure_forward_issue_cluster_schema(db: &ServerDb) -> Result<()> {
    match db {
        ServerDb::Postgres(db) => {
            db.batch_execute(
                "
            ALTER TABLE issue_clusters
            ADD COLUMN IF NOT EXISTS best_triage_json JSONB
            ",
            )
            .await?;
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let mut stmt = connection.prepare("PRAGMA table_info(issue_clusters)")?;
            let columns = stmt
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if !columns.iter().any(|name| name == "best_triage_json") {
                connection.execute(
                    "ALTER TABLE issue_clusters ADD COLUMN best_triage_json TEXT",
                    [],
                )?;
            }
        }
    }
    Ok(())
}

async fn backfill_result_classification(db: &ServerDb) -> Result<()> {
    match db {
        ServerDb::Postgres(client) => {
            let attempt_rows = client
                .query(
                    "
                SELECT id, cluster_id, bundle_json
                FROM patch_attempts
                ",
                    &[],
                )
                .await?;
            let mut attempts_by_cluster = HashMap::<String, Vec<PatchAttempt>>::new();
            for row in attempt_rows {
                let attempt_id: String = row.get(0);
                let cluster_id: String = row.get(1);
                let bundle_json: Value = row.get(2);
                let envelope = serde_json::from_value::<WorkerResultEnvelope>(bundle_json.clone())?;
                let canonical = canonicalize_worker_result_envelope(envelope);
                attempts_by_cluster
                    .entry(cluster_id)
                    .or_default()
                    .push(canonical.attempt.clone());
                let canonical_json = serde_json::to_value(&canonical)?;
                if canonical_json != bundle_json {
                    client
                        .execute(
                            "
                        UPDATE patch_attempts
                        SET outcome = $2,
                            state = $3,
                            summary = $4,
                            bundle_json = $5
                        WHERE id = $1
                        ",
                            &[
                                &attempt_id,
                                &canonical.attempt.outcome,
                                &canonical.attempt.state,
                                &canonical.attempt.summary,
                                &canonical_json,
                            ],
                        )
                        .await?;
                }
            }
            let cluster_rows = client
                .query(
                    "
                SELECT id, best_patch_json, best_triage_json
                FROM issue_clusters
                ",
                    &[],
                )
                .await?;
            for row in cluster_rows {
                let cluster_id: String = row.get(0);
                let mut candidates = attempts_by_cluster.remove(&cluster_id).unwrap_or_default();
                if let Some(value) = row.get::<_, Option<Value>>(1) {
                    if let Ok(attempt) = serde_json::from_value::<PatchAttempt>(value) {
                        candidates.push(canonicalize_patch_attempt(attempt));
                    }
                }
                if let Some(value) = row.get::<_, Option<Value>>(2) {
                    if let Ok(attempt) = serde_json::from_value::<PatchAttempt>(value) {
                        candidates.push(canonicalize_patch_attempt(attempt));
                    }
                }
                let (best_patch, best_triage) = best_attempts_from_candidates(candidates);
                client
                    .execute(
                        "
                    UPDATE issue_clusters
                    SET best_patch_json = $2,
                        best_triage_json = $3
                    WHERE id = $1
                    ",
                        &[
                            &cluster_id,
                            &best_patch.as_ref().map(serde_json::to_value).transpose()?,
                            &best_triage.as_ref().map(serde_json::to_value).transpose()?,
                        ],
                    )
                    .await?;
            }
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let mut attempt_stmt = connection.prepare(
                "
                SELECT id, cluster_id, bundle_json
                FROM patch_attempts
                ",
            )?;
            let attempt_rows = attempt_stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            let mut attempts_by_cluster = HashMap::<String, Vec<PatchAttempt>>::new();
            for row in attempt_rows {
                let (attempt_id, cluster_id, bundle_json) = row?;
                let envelope = serde_json::from_str::<WorkerResultEnvelope>(&bundle_json)?;
                let canonical = canonicalize_worker_result_envelope(envelope);
                attempts_by_cluster
                    .entry(cluster_id)
                    .or_default()
                    .push(canonical.attempt.clone());
                let canonical_json = serde_json::to_string(&canonical)?;
                if canonical_json != bundle_json {
                    connection.execute(
                        "
                        UPDATE patch_attempts
                        SET outcome = ?2,
                            state = ?3,
                            summary = ?4,
                            bundle_json = ?5
                        WHERE id = ?1
                        ",
                        params![
                            attempt_id,
                            canonical.attempt.outcome,
                            canonical.attempt.state,
                            canonical.attempt.summary,
                            canonical_json,
                        ],
                    )?;
                }
            }
            let mut cluster_stmt = connection.prepare(
                "
                SELECT id, best_patch_json, best_triage_json
                FROM issue_clusters
                ",
            )?;
            let cluster_rows = cluster_stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?;
            for row in cluster_rows {
                let (cluster_id, best_patch_raw, best_triage_raw) = row?;
                let mut candidates = attempts_by_cluster.remove(&cluster_id).unwrap_or_default();
                if let Some(raw) = best_patch_raw {
                    if let Ok(attempt) = serde_json::from_str::<PatchAttempt>(&raw) {
                        candidates.push(canonicalize_patch_attempt(attempt));
                    }
                }
                if let Some(raw) = best_triage_raw {
                    if let Ok(attempt) = serde_json::from_str::<PatchAttempt>(&raw) {
                        candidates.push(canonicalize_patch_attempt(attempt));
                    }
                }
                let (best_patch, best_triage) = best_attempts_from_candidates(candidates);
                connection.execute(
                    "
                    UPDATE issue_clusters
                    SET best_patch_json = ?2,
                        best_triage_json = ?3
                    WHERE id = ?1
                    ",
                    params![
                        cluster_id,
                        best_patch.as_ref().map(serde_json::to_string).transpose()?,
                        best_triage
                            .as_ref()
                            .map(serde_json::to_string)
                            .transpose()?,
                    ],
                )?;
            }
        }
    }
    Ok(())
}

async fn recluster_current_issue_state(
    db: &ServerDb,
    quarantine_corroboration_threshold: i64,
) -> Result<()> {
    let state = load_current_issue_state(db).await?;
    let reclustered = tokio::task::spawn_blocking(move || {
        recluster_issue_state(state, quarantine_corroboration_threshold)
    })
    .await
    .context("recluster worker panicked")??;
    let Some(reclustered) = reclustered else {
        return Ok(());
    };
    write_reclustered_issue_state(db, &reclustered).await
}

async fn load_current_issue_state(db: &ServerDb) -> Result<CurrentIssueState> {
    match db {
        ServerDb::Postgres(client) => {
            let issue_clusters = client
                .query(
                    "
                SELECT id, cluster_key, kind, title, summary, public_title, public_summary,
                       public_visible, package_name, source_package, ecosystem, severity, score,
                       corroboration_count, quarantined, promoted, representative_json,
                       best_patch_json, best_triage_json, last_seen
                FROM issue_clusters
                ",
                    &[],
                )
                .await?
                .into_iter()
                .map(|row| CurrentIssueCluster {
                    id: row.get(0),
                    cluster_key: row.get(1),
                    kind: row.get(2),
                    title: row.get(3),
                    summary: row.get(4),
                    public_title: row.get(5),
                    public_summary: row.get(6),
                    public_visible: row.get(7),
                    package_name: row.get(8),
                    source_package: row.get(9),
                    ecosystem: row.get(10),
                    severity: row.get(11),
                    score: row.get(12),
                    corroboration_count: row.get(13),
                    quarantined: row.get(14),
                    promoted: row.get(15),
                    representative_json: row.get(16),
                    best_patch_json: row.get(17),
                    best_triage_json: row.get(18),
                    last_seen: row.get::<_, DateTime<Utc>>(19).to_rfc3339(),
                })
                .collect::<Vec<_>>();
            let cluster_reports = client
                .query(
                    "
                SELECT cluster_id, install_id, submission_id, created_at
                FROM cluster_reports
                ",
                    &[],
                )
                .await?
                .into_iter()
                .map(|row| CurrentClusterReport {
                    cluster_id: row.get(0),
                    install_id: row.get(1),
                    submission_id: row.get(2),
                    created_at: row.get::<_, DateTime<Utc>>(3).to_rfc3339(),
                })
                .collect::<Vec<_>>();
            let worker_leases = client
                .query(
                    "
                SELECT id, cluster_id, install_id, state, leased_at, expires_at, work_json
                FROM worker_leases
                ",
                    &[],
                )
                .await?
                .into_iter()
                .map(|row| CurrentWorkerLease {
                    id: row.get(0),
                    cluster_id: row.get(1),
                    install_id: row.get(2),
                    state: row.get(3),
                    leased_at: row.get::<_, DateTime<Utc>>(4).to_rfc3339(),
                    expires_at: row.get::<_, DateTime<Utc>>(5).to_rfc3339(),
                    work_json: row.get(6),
                })
                .collect::<Vec<_>>();
            let patch_attempts = client
                .query(
                    "
                SELECT id, cluster_id, lease_id, install_id, outcome, state, summary, bundle_json, created_at
                FROM patch_attempts
                ",
                    &[],
                )
                .await?
                .into_iter()
                .map(|row| CurrentPatchAttempt {
                    id: row.get(0),
                    cluster_id: row.get(1),
                    lease_id: row.get(2),
                    install_id: row.get(3),
                    outcome: row.get(4),
                    state: row.get(5),
                    summary: row.get(6),
                    bundle_json: row.get(7),
                    created_at: row.get::<_, DateTime<Utc>>(8).to_rfc3339(),
                })
                .collect::<Vec<_>>();
            let evidence_requests = client
                .query(
                    "
                SELECT id, issue_id, requested_by_install_id, reason, requested_fields_json, requested_at, response_json
                FROM evidence_requests
                ",
                    &[],
                )
                .await?
                .into_iter()
                .map(|row| CurrentEvidenceRequest {
                    id: row.get(0),
                    issue_id: row.get(1),
                    requested_by_install_id: row.get(2),
                    reason: row.get(3),
                    requested_fields_json: row.get(4),
                    requested_at: row.get::<_, DateTime<Utc>>(5).to_rfc3339(),
                    response_json: row.get(6),
                })
                .collect::<Vec<_>>();
            Ok(CurrentIssueState {
                issue_clusters,
                cluster_reports,
                worker_leases,
                patch_attempts,
                evidence_requests,
            })
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let mut issue_stmt = connection.prepare(
                "
                SELECT id, cluster_key, kind, title, summary, public_title, public_summary,
                       public_visible, package_name, source_package, ecosystem, severity, score,
                       corroboration_count, quarantined, promoted, representative_json,
                       best_patch_json, best_triage_json, last_seen
                FROM issue_clusters
                ",
            )?;
            let issue_clusters = issue_stmt
                .query_map([], |row| {
                    Ok(CurrentIssueCluster {
                        id: row.get(0)?,
                        cluster_key: row.get(1)?,
                        kind: row.get(2)?,
                        title: row.get(3)?,
                        summary: row.get(4)?,
                        public_title: row.get(5)?,
                        public_summary: row.get(6)?,
                        public_visible: row.get::<_, i64>(7)? != 0,
                        package_name: row.get(8)?,
                        source_package: row.get(9)?,
                        ecosystem: row.get(10)?,
                        severity: row.get(11)?,
                        score: row.get(12)?,
                        corroboration_count: row.get(13)?,
                        quarantined: row.get::<_, i64>(14)? != 0,
                        promoted: row.get::<_, i64>(15)? != 0,
                        representative_json: serde_json::from_str(&row.get::<_, String>(16)?)
                            .map_err(|error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    16,
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            })?,
                        best_patch_json: row
                            .get::<_, Option<String>>(17)?
                            .map(|raw| serde_json::from_str::<Value>(&raw))
                            .transpose()
                            .map_err(|error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    17,
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            })?,
                        best_triage_json: row
                            .get::<_, Option<String>>(18)?
                            .map(|raw| serde_json::from_str::<Value>(&raw))
                            .transpose()
                            .map_err(|error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    18,
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            })?,
                        last_seen: row.get(19)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut report_stmt = connection.prepare(
                "
                SELECT cluster_id, install_id, submission_id, created_at
                FROM cluster_reports
                ",
            )?;
            let cluster_reports = report_stmt
                .query_map([], |row| {
                    Ok(CurrentClusterReport {
                        cluster_id: row.get(0)?,
                        install_id: row.get(1)?,
                        submission_id: row.get(2)?,
                        created_at: row.get(3)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut lease_stmt = connection.prepare(
                "
                SELECT id, cluster_id, install_id, state, leased_at, expires_at, work_json
                FROM worker_leases
                ",
            )?;
            let worker_leases = lease_stmt
                .query_map([], |row| {
                    Ok(CurrentWorkerLease {
                        id: row.get(0)?,
                        cluster_id: row.get(1)?,
                        install_id: row.get(2)?,
                        state: row.get(3)?,
                        leased_at: row.get(4)?,
                        expires_at: row.get(5)?,
                        work_json: serde_json::from_str(&row.get::<_, String>(6)?).map_err(
                            |error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    6,
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            },
                        )?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut attempt_stmt = connection.prepare(
                "
                SELECT id, cluster_id, lease_id, install_id, outcome, state, summary, bundle_json, created_at
                FROM patch_attempts
                ",
            )?;
            let patch_attempts = attempt_stmt
                .query_map([], |row| {
                    Ok(CurrentPatchAttempt {
                        id: row.get(0)?,
                        cluster_id: row.get(1)?,
                        lease_id: row.get(2)?,
                        install_id: row.get(3)?,
                        outcome: row.get(4)?,
                        state: row.get(5)?,
                        summary: row.get(6)?,
                        bundle_json: serde_json::from_str(&row.get::<_, String>(7)?).map_err(
                            |error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    7,
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            },
                        )?,
                        created_at: row.get(8)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut evidence_stmt = connection.prepare(
                "
                SELECT id, issue_id, requested_by_install_id, reason, requested_fields_json, requested_at, response_json
                FROM evidence_requests
                ",
            )?;
            let evidence_requests = evidence_stmt
                .query_map([], |row| {
                    Ok(CurrentEvidenceRequest {
                        id: row.get(0)?,
                        issue_id: row.get(1)?,
                        requested_by_install_id: row.get(2)?,
                        reason: row.get(3)?,
                        requested_fields_json: serde_json::from_str(&row.get::<_, String>(4)?)
                            .map_err(|error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    4,
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            })?,
                        requested_at: row.get(5)?,
                        response_json: row
                            .get::<_, Option<String>>(6)?
                            .map(|raw| serde_json::from_str::<Value>(&raw))
                            .transpose()
                            .map_err(|error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    6,
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            })?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(CurrentIssueState {
                issue_clusters,
                cluster_reports,
                worker_leases,
                patch_attempts,
                evidence_requests,
            })
        }
    }
}

fn recluster_issue_state(
    state: CurrentIssueState,
    quarantine_corroboration_threshold: i64,
) -> Result<Option<CurrentIssueState>> {
    let mut grouped_clusters = BTreeMap::<String, CurrentClusterAccumulator>::new();
    let mut needs_recluster = false;
    for row in &state.issue_clusters {
        let representative: SharedOpportunity =
            serde_json::from_value(row.representative_json.clone())?;
        let cluster_key = cluster_key_for(&representative);
        let public_fields = build_public_issue_fields(&representative);
        let source_package = inferred_public_source_package(&representative);
        if cluster_key != row.cluster_key
            || public_fields.title != row.public_title
            || public_fields.summary != row.public_summary
            || public_fields.visible != row.public_visible
            || (optional_string_is_empty(&row.source_package) && source_package.is_some())
        {
            needs_recluster = true;
        }
        match grouped_clusters.entry(cluster_key.clone()) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                needs_recluster = true;
                entry.get_mut().absorb(row, &public_fields, source_package);
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(CurrentClusterAccumulator::new(
                    row,
                    cluster_key,
                    &public_fields,
                    source_package,
                ));
            }
        }
    }
    if !needs_recluster {
        return Ok(None);
    }

    let mut cluster_id_map = HashMap::<String, String>::new();
    let mut issue_clusters = grouped_clusters
        .into_values()
        .map(|group| {
            for existing_id in &group.existing_ids {
                cluster_id_map.insert(existing_id.clone(), group.canonical_id.clone());
            }
            CurrentIssueCluster {
                id: group.canonical_id,
                cluster_key: group.cluster_key,
                kind: group.kind,
                title: group.title,
                summary: group.summary,
                public_title: group.public_title,
                public_summary: group.public_summary,
                public_visible: group.public_visible,
                package_name: group.package_name,
                source_package: group.source_package,
                ecosystem: group.ecosystem,
                severity: group.severity,
                score: group.score,
                corroboration_count: 0,
                quarantined: true,
                promoted: group.any_promoted,
                representative_json: group.representative_json,
                best_patch_json: group.fallback_best_patch_json,
                best_triage_json: group.fallback_best_triage_json,
                last_seen: group.last_seen,
            }
        })
        .collect::<Vec<_>>();

    let mut cluster_report_map = HashMap::<(String, String), CurrentClusterReport>::new();
    for report in state.cluster_reports {
        let Some(cluster_id) = cluster_id_map.get(&report.cluster_id).cloned() else {
            continue;
        };
        let key = (cluster_id.clone(), report.install_id.clone());
        match cluster_report_map.get_mut(&key) {
            Some(existing) if report.created_at > existing.created_at => {
                existing.submission_id = report.submission_id.clone();
                existing.created_at = report.created_at.clone();
            }
            Some(_) => {}
            None => {
                cluster_report_map.insert(
                    key,
                    CurrentClusterReport {
                        cluster_id,
                        install_id: report.install_id,
                        submission_id: report.submission_id,
                        created_at: report.created_at,
                    },
                );
            }
        }
    }
    let cluster_reports = cluster_report_map.into_values().collect::<Vec<_>>();

    let worker_leases = state
        .worker_leases
        .into_iter()
        .filter_map(|lease| {
            cluster_id_map
                .get(&lease.cluster_id)
                .map(|cluster_id| CurrentWorkerLease {
                    id: lease.id.clone(),
                    cluster_id: cluster_id.clone(),
                    install_id: lease.install_id,
                    state: lease.state,
                    leased_at: lease.leased_at,
                    expires_at: lease.expires_at,
                    work_json: rewrite_work_lease_json(lease.work_json, cluster_id, &lease.id),
                })
        })
        .collect::<Vec<_>>();

    let patch_attempts = state
        .patch_attempts
        .into_iter()
        .filter_map(|attempt| {
            cluster_id_map
                .get(&attempt.cluster_id)
                .map(|cluster_id| CurrentPatchAttempt {
                    id: attempt.id,
                    cluster_id: cluster_id.clone(),
                    lease_id: attempt.lease_id.clone(),
                    install_id: attempt.install_id,
                    outcome: attempt.outcome,
                    state: attempt.state,
                    summary: attempt.summary,
                    bundle_json: rewrite_worker_result_json(
                        attempt.bundle_json,
                        cluster_id,
                        attempt.lease_id.as_deref(),
                    ),
                    created_at: attempt.created_at,
                })
        })
        .collect::<Vec<_>>();

    let evidence_requests = state
        .evidence_requests
        .into_iter()
        .filter_map(|request| {
            cluster_id_map
                .get(&request.issue_id)
                .map(|issue_id| CurrentEvidenceRequest {
                    id: request.id,
                    issue_id: issue_id.clone(),
                    requested_by_install_id: request.requested_by_install_id,
                    reason: request.reason,
                    requested_fields_json: request.requested_fields_json,
                    requested_at: request.requested_at,
                    response_json: request.response_json,
                })
        })
        .collect::<Vec<_>>();

    let mut issue_counts = HashMap::<String, i64>::new();
    for report in &cluster_reports {
        *issue_counts.entry(report.cluster_id.clone()).or_default() += 1;
    }

    let mut patch_attempt_best = HashMap::<String, (&str, Value)>::new();
    let mut triage_attempt_best = HashMap::<String, (&str, Value)>::new();
    for attempt in &patch_attempts {
        if attempt.state != "ready" {
            continue;
        }
        let payload = attempt
            .bundle_json
            .get("attempt")
            .cloned()
            .unwrap_or_else(|| {
                json!({
                    "cluster_id": attempt.cluster_id,
                    "install_id": attempt.install_id,
                    "outcome": attempt.outcome,
                    "state": attempt.state,
                    "summary": attempt.summary,
                    "bundle_path": Value::Null,
                    "output_path": Value::Null,
                    "validation_status": Value::Null,
                    "details": {},
                    "created_at": attempt.created_at,
                })
            });
        if attempt.outcome == "patch" {
            patch_attempt_best
                .entry(attempt.cluster_id.clone())
                .and_modify(|existing| {
                    if attempt.created_at.as_str() > existing.0 {
                        *existing = (attempt.created_at.as_str(), payload.clone());
                    }
                })
                .or_insert((attempt.created_at.as_str(), payload.clone()));
        }
        if attempt.outcome == "triage" {
            triage_attempt_best
                .entry(attempt.cluster_id.clone())
                .and_modify(|existing| {
                    if attempt.created_at.as_str() > existing.0 {
                        *existing = (attempt.created_at.as_str(), payload.clone());
                    }
                })
                .or_insert((attempt.created_at.as_str(), payload));
        }
    }

    for issue in &mut issue_clusters {
        issue.corroboration_count = *issue_counts.get(&issue.id).unwrap_or(&0);
        issue.promoted =
            issue.promoted || issue.corroboration_count >= quarantine_corroboration_threshold;
        issue.quarantined = !issue.promoted;
        if let Some((_, best_patch)) = patch_attempt_best.get(&issue.id) {
            issue.best_patch_json = Some(best_patch.clone());
        } else if let Some(best_patch) = issue.best_patch_json.clone() {
            let best_patch = rewrite_patch_attempt_json(best_patch, &issue.id);
            if let Ok(attempt) = serde_json::from_value::<PatchAttempt>(best_patch) {
                let attempt = canonicalize_patch_attempt(attempt);
                if attempt.state == "ready" && attempt.outcome == "patch" {
                    issue.best_patch_json = Some(serde_json::to_value(attempt)?);
                } else {
                    issue.best_patch_json = None;
                }
            } else {
                issue.best_patch_json = None;
            }
        }
        if let Some((_, best_triage)) = triage_attempt_best.get(&issue.id) {
            issue.best_triage_json = Some(best_triage.clone());
        } else if let Some(best_triage) = issue.best_triage_json.clone() {
            let best_triage = rewrite_patch_attempt_json(best_triage, &issue.id);
            if let Ok(attempt) = serde_json::from_value::<PatchAttempt>(best_triage) {
                let attempt = canonicalize_patch_attempt(attempt);
                if attempt.state == "ready" && attempt.outcome == "triage" {
                    issue.best_triage_json = Some(serde_json::to_value(attempt)?);
                } else {
                    issue.best_triage_json = None;
                }
            } else {
                issue.best_triage_json = None;
            }
        }
    }

    Ok(Some(CurrentIssueState {
        issue_clusters,
        cluster_reports,
        worker_leases,
        patch_attempts,
        evidence_requests,
    }))
}

async fn write_reclustered_issue_state(db: &ServerDb, state: &CurrentIssueState) -> Result<()> {
    match db {
        ServerDb::Postgres(client) => {
            client.batch_execute("BEGIN").await?;
            let result = async {
                client.execute("DELETE FROM patch_attempts", &[]).await?;
                client.execute("DELETE FROM evidence_requests", &[]).await?;
                client.execute("DELETE FROM worker_leases", &[]).await?;
                client.execute("DELETE FROM cluster_reports", &[]).await?;
                client.execute("DELETE FROM issue_clusters", &[]).await?;

                for issue in &state.issue_clusters {
                    client
                        .execute(
                            "
                        INSERT INTO issue_clusters
                            (id, cluster_key, kind, title, summary, public_title, public_summary, public_visible,
                             package_name, source_package, ecosystem, severity, score, corroboration_count,
                             quarantined, promoted, representative_json, best_patch_json, best_triage_json, last_seen)
                        VALUES
                            ($1, $2, $3, $4, $5, $6, $7, $8,
                             $9, $10, $11, $12, $13, $14,
                             $15, $16, $17, $18, $19, $20)
                        ",
                            &[
                                &issue.id,
                                &issue.cluster_key,
                                &issue.kind,
                                &issue.title,
                                &issue.summary,
                                &issue.public_title,
                                &issue.public_summary,
                                &issue.public_visible,
                                &issue.package_name,
                                &issue.source_package,
                                &issue.ecosystem,
                                &issue.severity,
                                &issue.score,
                                &issue.corroboration_count,
                                &issue.quarantined,
                                &issue.promoted,
                                &issue.representative_json,
                                &issue.best_patch_json,
                                &issue.best_triage_json,
                                &parse_timestamp(&issue.last_seen)
                                    .ok_or_else(|| anyhow!("invalid timestamp {}", issue.last_seen))?,
                            ],
                        )
                        .await?;
                }
                for report in &state.cluster_reports {
                    client
                        .execute(
                            "
                        INSERT INTO cluster_reports (cluster_id, install_id, submission_id, created_at)
                        VALUES ($1, $2, $3, $4)
                        ",
                            &[
                                &report.cluster_id,
                                &report.install_id,
                                &report.submission_id,
                                &parse_timestamp(&report.created_at)
                                    .ok_or_else(|| anyhow!("invalid timestamp {}", report.created_at))?,
                            ],
                        )
                        .await?;
                }
                for lease in &state.worker_leases {
                    client
                        .execute(
                            "
                        INSERT INTO worker_leases (id, cluster_id, install_id, state, leased_at, expires_at, work_json)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        ",
                            &[
                                &lease.id,
                                &lease.cluster_id,
                                &lease.install_id,
                                &lease.state,
                                &parse_timestamp(&lease.leased_at)
                                    .ok_or_else(|| anyhow!("invalid timestamp {}", lease.leased_at))?,
                                &parse_timestamp(&lease.expires_at)
                                    .ok_or_else(|| anyhow!("invalid timestamp {}", lease.expires_at))?,
                                &lease.work_json,
                            ],
                        )
                        .await?;
                }
                for attempt in &state.patch_attempts {
                    client
                        .execute(
                            "
                        INSERT INTO patch_attempts (id, cluster_id, lease_id, install_id, outcome, state, summary, bundle_json, created_at)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                        ",
                            &[
                                &attempt.id,
                                &attempt.cluster_id,
                                &attempt.lease_id,
                                &attempt.install_id,
                                &attempt.outcome,
                                &attempt.state,
                                &attempt.summary,
                                &attempt.bundle_json,
                                &parse_timestamp(&attempt.created_at)
                                    .ok_or_else(|| anyhow!("invalid timestamp {}", attempt.created_at))?,
                            ],
                        )
                        .await?;
                }
                for request in &state.evidence_requests {
                    client
                        .execute(
                            "
                        INSERT INTO evidence_requests
                            (id, issue_id, requested_by_install_id, reason, requested_fields_json, requested_at, response_json)
                        VALUES
                            ($1, $2, $3, $4, $5, $6, $7)
                        ",
                            &[
                                &request.id,
                                &request.issue_id,
                                &request.requested_by_install_id,
                                &request.reason,
                                &request.requested_fields_json,
                                &parse_timestamp(&request.requested_at)
                                    .ok_or_else(|| anyhow!("invalid timestamp {}", request.requested_at))?,
                                &request.response_json,
                            ],
                        )
                        .await?;
                }
                Ok::<(), anyhow::Error>(())
            }
            .await;
            match result {
                Ok(()) => {
                    client.batch_execute("COMMIT").await?;
                    Ok(())
                }
                Err(error) => {
                    let _ = client.batch_execute("ROLLBACK").await;
                    Err(error)
                }
            }
        }
        ServerDb::Sqlite(path) => {
            let mut connection = sqlite_connection(path)?;
            let tx = connection.transaction()?;
            tx.execute("DELETE FROM patch_attempts", [])?;
            tx.execute("DELETE FROM evidence_requests", [])?;
            tx.execute("DELETE FROM worker_leases", [])?;
            tx.execute("DELETE FROM cluster_reports", [])?;
            tx.execute("DELETE FROM issue_clusters", [])?;

            for issue in &state.issue_clusters {
                tx.execute(
                    "
                    INSERT INTO issue_clusters
                        (id, cluster_key, kind, title, summary, public_title, public_summary, public_visible,
                         package_name, source_package, ecosystem, severity, score, corroboration_count,
                         quarantined, promoted, representative_json, best_patch_json, best_triage_json, last_seen)
                    VALUES
                        (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                         ?9, ?10, ?11, ?12, ?13, ?14,
                         ?15, ?16, ?17, ?18, ?19, ?20)
                    ",
                    params![
                        issue.id,
                        issue.cluster_key,
                        issue.kind,
                        issue.title,
                        issue.summary,
                        issue.public_title,
                        issue.public_summary,
                        issue.public_visible,
                        issue.package_name,
                        issue.source_package,
                        issue.ecosystem,
                        issue.severity,
                        issue.score,
                        issue.corroboration_count,
                        issue.quarantined,
                        issue.promoted,
                        serde_json::to_string(&issue.representative_json)?,
                        issue.best_patch_json
                            .as_ref()
                            .map(serde_json::to_string)
                            .transpose()?,
                        issue.best_triage_json
                            .as_ref()
                            .map(serde_json::to_string)
                            .transpose()?,
                        issue.last_seen,
                    ],
                )?;
            }
            for report in &state.cluster_reports {
                tx.execute(
                    "
                    INSERT INTO cluster_reports (cluster_id, install_id, submission_id, created_at)
                    VALUES (?1, ?2, ?3, ?4)
                    ",
                    params![
                        report.cluster_id,
                        report.install_id,
                        report.submission_id,
                        report.created_at
                    ],
                )?;
            }
            for lease in &state.worker_leases {
                tx.execute(
                    "
                    INSERT INTO worker_leases (id, cluster_id, install_id, state, leased_at, expires_at, work_json)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                    ",
                    params![
                        lease.id,
                        lease.cluster_id,
                        lease.install_id,
                        lease.state,
                        lease.leased_at,
                        lease.expires_at,
                        serde_json::to_string(&lease.work_json)?,
                    ],
                )?;
            }
            for attempt in &state.patch_attempts {
                tx.execute(
                    "
                    INSERT INTO patch_attempts (id, cluster_id, lease_id, install_id, outcome, state, summary, bundle_json, created_at)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                    ",
                    params![
                        attempt.id,
                        attempt.cluster_id,
                        attempt.lease_id,
                        attempt.install_id,
                        attempt.outcome,
                        attempt.state,
                        attempt.summary,
                        serde_json::to_string(&attempt.bundle_json)?,
                        attempt.created_at,
                    ],
                )?;
            }
            for request in &state.evidence_requests {
                tx.execute(
                    "
                    INSERT INTO evidence_requests
                        (id, issue_id, requested_by_install_id, reason, requested_fields_json, requested_at, response_json)
                    VALUES
                        (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                    ",
                    params![
                        request.id,
                        request.issue_id,
                        request.requested_by_install_id,
                        request.reason,
                        serde_json::to_string(&request.requested_fields_json)?,
                        request.requested_at,
                        request
                            .response_json
                            .as_ref()
                            .map(serde_json::to_string)
                            .transpose()?,
                    ],
                )?;
            }
            tx.commit()?;
            Ok(())
        }
    }
}

#[derive(Debug, Clone)]
struct LegacyServerState {
    submissions: Vec<LegacySubmission>,
    issue_clusters: Vec<LegacyIssueCluster>,
    cluster_reports: Vec<LegacyClusterReport>,
    worker_leases: Vec<LegacyWorkerLease>,
    patch_attempts: Vec<LegacyPatchAttempt>,
    evidence_requests: Vec<LegacyEvidenceRequest>,
    rate_events: Vec<LegacyRateEvent>,
}

#[derive(Debug, Clone)]
struct LegacySubmission {
    id: i64,
    install_id: String,
    content_hash: String,
    payload_hash: String,
    received_at: String,
    remote_addr: Option<String>,
    quarantined: bool,
    bundle_json: Value,
}

#[derive(Debug, Clone)]
struct LegacyIssueCluster {
    id: i64,
    kind: String,
    title: String,
    summary: String,
    package_name: Option<String>,
    source_package: Option<String>,
    ecosystem: Option<String>,
    severity: Option<String>,
    score: i64,
    promoted: bool,
    representative_json: Value,
    best_patch_json: Option<Value>,
    last_seen: String,
}

#[derive(Debug, Clone)]
struct LegacyClusterReport {
    cluster_id: i64,
    install_id: String,
    submission_id: i64,
    created_at: String,
}

#[derive(Debug, Clone)]
struct LegacyWorkerLease {
    id: String,
    cluster_id: i64,
    install_id: String,
    state: String,
    leased_at: String,
    expires_at: String,
    work_json: Value,
}

#[derive(Debug, Clone)]
struct LegacyPatchAttempt {
    cluster_id: i64,
    lease_id: Option<String>,
    install_id: String,
    outcome: String,
    state: String,
    summary: String,
    bundle_json: Value,
    created_at: String,
}

#[derive(Debug, Clone)]
struct LegacyEvidenceRequest {
    issue_id: i64,
    requested_by_install_id: Option<String>,
    reason: String,
    requested_fields_json: Value,
    requested_at: String,
    response_json: Option<Value>,
}

#[derive(Debug, Clone)]
struct LegacyRateEvent {
    scope_kind: String,
    scope_value: String,
    event_kind: String,
    created_at: String,
}

#[derive(Debug, Clone)]
struct MigratedServerState {
    submissions: Vec<MigratedSubmission>,
    issue_clusters: Vec<MigratedIssueCluster>,
    cluster_reports: Vec<MigratedClusterReport>,
    worker_leases: Vec<MigratedWorkerLease>,
    patch_attempts: Vec<MigratedPatchAttempt>,
    evidence_requests: Vec<MigratedEvidenceRequest>,
    rate_events: Vec<MigratedRateEvent>,
}

#[derive(Debug, Clone)]
struct MigratedSubmission {
    id: String,
    install_id: String,
    content_hash: String,
    payload_hash: String,
    received_at: String,
    remote_addr: Option<String>,
    quarantined: bool,
    bundle_json: Value,
}

#[derive(Debug, Clone)]
struct MigratedIssueCluster {
    id: String,
    cluster_key: String,
    kind: String,
    title: String,
    summary: String,
    public_title: String,
    public_summary: String,
    public_visible: bool,
    package_name: Option<String>,
    source_package: Option<String>,
    ecosystem: Option<String>,
    severity: Option<String>,
    score: i64,
    corroboration_count: i64,
    quarantined: bool,
    promoted: bool,
    representative_json: Value,
    best_patch_json: Option<Value>,
    best_triage_json: Option<Value>,
    last_seen: String,
}

#[derive(Debug, Clone)]
struct MigratedClusterReport {
    cluster_id: String,
    install_id: String,
    submission_id: String,
    created_at: String,
}

#[derive(Debug, Clone)]
struct MigratedWorkerLease {
    id: String,
    cluster_id: String,
    install_id: String,
    state: String,
    leased_at: String,
    expires_at: String,
    work_json: Value,
}

#[derive(Debug, Clone)]
struct MigratedPatchAttempt {
    id: String,
    cluster_id: String,
    lease_id: Option<String>,
    install_id: String,
    outcome: String,
    state: String,
    summary: String,
    bundle_json: Value,
    created_at: String,
}

#[derive(Debug, Clone)]
struct MigratedEvidenceRequest {
    id: String,
    issue_id: String,
    requested_by_install_id: Option<String>,
    reason: String,
    requested_fields_json: Value,
    requested_at: String,
    response_json: Option<Value>,
}

#[derive(Debug, Clone)]
struct MigratedRateEvent {
    id: String,
    scope_kind: String,
    scope_value: String,
    event_kind: String,
    created_at: String,
}

#[derive(Debug, Clone)]
struct CurrentIssueState {
    issue_clusters: Vec<CurrentIssueCluster>,
    cluster_reports: Vec<CurrentClusterReport>,
    worker_leases: Vec<CurrentWorkerLease>,
    patch_attempts: Vec<CurrentPatchAttempt>,
    evidence_requests: Vec<CurrentEvidenceRequest>,
}

fn optional_string_is_empty(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(|value| value.trim().is_empty())
}

fn nonempty_optional_string(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

#[derive(Debug, Clone)]
struct CurrentIssueCluster {
    id: String,
    cluster_key: String,
    kind: String,
    title: String,
    summary: String,
    public_title: String,
    public_summary: String,
    public_visible: bool,
    package_name: Option<String>,
    source_package: Option<String>,
    ecosystem: Option<String>,
    severity: Option<String>,
    score: i64,
    corroboration_count: i64,
    quarantined: bool,
    promoted: bool,
    representative_json: Value,
    best_patch_json: Option<Value>,
    best_triage_json: Option<Value>,
    last_seen: String,
}

#[derive(Debug, Clone)]
struct CurrentClusterReport {
    cluster_id: String,
    install_id: String,
    submission_id: String,
    created_at: String,
}

#[derive(Debug, Clone)]
struct CurrentWorkerLease {
    id: String,
    cluster_id: String,
    install_id: String,
    state: String,
    leased_at: String,
    expires_at: String,
    work_json: Value,
}

#[derive(Debug, Clone)]
struct CurrentPatchAttempt {
    id: String,
    cluster_id: String,
    lease_id: Option<String>,
    install_id: String,
    outcome: String,
    state: String,
    summary: String,
    bundle_json: Value,
    created_at: String,
}

#[derive(Debug, Clone)]
struct CurrentEvidenceRequest {
    id: String,
    issue_id: String,
    requested_by_install_id: Option<String>,
    reason: String,
    requested_fields_json: Value,
    requested_at: String,
    response_json: Option<Value>,
}

#[derive(Debug, Clone)]
struct CurrentClusterAccumulator {
    existing_ids: Vec<String>,
    canonical_id: String,
    canonical_corroboration_count: i64,
    canonical_promoted: bool,
    canonical_score: i64,
    canonical_last_seen: String,
    cluster_key: String,
    kind: String,
    title: String,
    summary: String,
    public_title: String,
    public_summary: String,
    public_visible: bool,
    package_name: Option<String>,
    source_package: Option<String>,
    ecosystem: Option<String>,
    severity: Option<String>,
    score: i64,
    representative_json: Value,
    last_seen: String,
    any_promoted: bool,
    fallback_best_patch_json: Option<Value>,
    fallback_best_patch_seen_at: Option<String>,
    fallback_best_triage_json: Option<Value>,
    fallback_best_triage_seen_at: Option<String>,
}

#[derive(Debug, Clone)]
struct ClusterAccumulator {
    legacy_ids: Vec<i64>,
    kind: String,
    title: String,
    summary: String,
    public_title: String,
    public_summary: String,
    public_visible: bool,
    package_name: Option<String>,
    source_package: Option<String>,
    ecosystem: Option<String>,
    severity: Option<String>,
    score: i64,
    representative_json: Value,
    last_seen: String,
    any_promoted: bool,
    fallback_best_patch_json: Option<Value>,
    fallback_best_patch_seen_at: Option<String>,
    fallback_best_triage_json: Option<Value>,
}

impl ClusterAccumulator {
    fn new(row: &LegacyIssueCluster, public_fields: &PublicIssueFields) -> Self {
        Self {
            legacy_ids: vec![row.id],
            kind: row.kind.clone(),
            title: row.title.clone(),
            summary: row.summary.clone(),
            public_title: public_fields.title.clone(),
            public_summary: public_fields.summary.clone(),
            public_visible: public_fields.visible,
            package_name: row.package_name.clone(),
            source_package: row.source_package.clone(),
            ecosystem: row.ecosystem.clone(),
            severity: row.severity.clone(),
            score: row.score,
            representative_json: row.representative_json.clone(),
            last_seen: row.last_seen.clone(),
            any_promoted: row.promoted,
            fallback_best_patch_json: row.best_patch_json.clone(),
            fallback_best_patch_seen_at: row
                .best_patch_json
                .as_ref()
                .map(|_| row.last_seen.clone()),
            fallback_best_triage_json: None,
        }
    }

    fn absorb(&mut self, row: &LegacyIssueCluster, public_fields: &PublicIssueFields) {
        self.legacy_ids.push(row.id);
        self.public_visible |= public_fields.visible;
        let replace_representative =
            row.score > self.score || (row.score == self.score && row.last_seen > self.last_seen);
        self.score = self.score.max(row.score);
        if self.package_name.is_none() {
            self.package_name = row.package_name.clone();
        }
        if self.source_package.is_none() {
            self.source_package = row.source_package.clone();
        }
        if self.ecosystem.is_none() {
            self.ecosystem = row.ecosystem.clone();
        }
        if self.severity.is_none() {
            self.severity = row.severity.clone();
        }
        self.any_promoted |= row.promoted;
        if row.best_patch_json.is_some()
            && self
                .fallback_best_patch_seen_at
                .as_deref()
                .map(|current| row.last_seen.as_str() >= current)
                .unwrap_or(true)
        {
            self.fallback_best_patch_json = row.best_patch_json.clone();
            self.fallback_best_patch_seen_at = Some(row.last_seen.clone());
        }
        if replace_representative {
            self.kind = row.kind.clone();
            self.title = row.title.clone();
            self.summary = row.summary.clone();
            self.public_title = public_fields.title.clone();
            self.public_summary = public_fields.summary.clone();
            self.representative_json = row.representative_json.clone();
            self.last_seen = row.last_seen.clone();
        } else {
            self.last_seen = self.last_seen.clone().max(row.last_seen.clone());
        }
    }
}

impl CurrentClusterAccumulator {
    fn new(
        row: &CurrentIssueCluster,
        cluster_key: String,
        public_fields: &PublicIssueFields,
        source_package: Option<String>,
    ) -> Self {
        Self {
            existing_ids: vec![row.id.clone()],
            canonical_id: row.id.clone(),
            canonical_corroboration_count: row.corroboration_count,
            canonical_promoted: row.promoted,
            canonical_score: row.score,
            canonical_last_seen: row.last_seen.clone(),
            cluster_key,
            kind: row.kind.clone(),
            title: row.title.clone(),
            summary: row.summary.clone(),
            public_title: public_fields.title.clone(),
            public_summary: public_fields.summary.clone(),
            public_visible: public_fields.visible,
            package_name: row.package_name.clone(),
            source_package: source_package
                .or_else(|| nonempty_optional_string(&row.source_package)),
            ecosystem: row.ecosystem.clone(),
            severity: row.severity.clone(),
            score: row.score,
            representative_json: row.representative_json.clone(),
            last_seen: row.last_seen.clone(),
            any_promoted: row.promoted,
            fallback_best_patch_json: row.best_patch_json.clone(),
            fallback_best_patch_seen_at: row
                .best_patch_json
                .as_ref()
                .map(|_| row.last_seen.clone()),
            fallback_best_triage_json: row.best_triage_json.clone(),
            fallback_best_triage_seen_at: row
                .best_triage_json
                .as_ref()
                .map(|_| row.last_seen.clone()),
        }
    }

    fn absorb(
        &mut self,
        row: &CurrentIssueCluster,
        public_fields: &PublicIssueFields,
        source_package: Option<String>,
    ) {
        self.existing_ids.push(row.id.clone());
        self.public_visible |= public_fields.visible;
        let replace_representative =
            row.score > self.score || (row.score == self.score && row.last_seen > self.last_seen);
        let replace_canonical = row.corroboration_count > self.canonical_corroboration_count
            || (row.corroboration_count == self.canonical_corroboration_count
                && row.promoted
                && !self.canonical_promoted)
            || (row.corroboration_count == self.canonical_corroboration_count
                && row.promoted == self.canonical_promoted
                && row.score > self.canonical_score)
            || (row.corroboration_count == self.canonical_corroboration_count
                && row.promoted == self.canonical_promoted
                && row.score == self.canonical_score
                && row.last_seen > self.canonical_last_seen);
        if replace_canonical {
            self.canonical_id = row.id.clone();
            self.canonical_corroboration_count = row.corroboration_count;
            self.canonical_promoted = row.promoted;
            self.canonical_score = row.score;
            self.canonical_last_seen = row.last_seen.clone();
        }
        self.score = self.score.max(row.score);
        if self.package_name.is_none() {
            self.package_name = row.package_name.clone();
        }
        if optional_string_is_empty(&self.source_package) {
            self.source_package =
                source_package.or_else(|| nonempty_optional_string(&row.source_package));
        }
        if self.ecosystem.is_none() {
            self.ecosystem = row.ecosystem.clone();
        }
        if self.severity.is_none() {
            self.severity = row.severity.clone();
        }
        self.any_promoted |= row.promoted;
        if row.best_patch_json.is_some()
            && self
                .fallback_best_patch_seen_at
                .as_deref()
                .map(|current| row.last_seen.as_str() >= current)
                .unwrap_or(true)
        {
            self.fallback_best_patch_json = row.best_patch_json.clone();
            self.fallback_best_patch_seen_at = Some(row.last_seen.clone());
        }
        if row.best_triage_json.is_some()
            && self
                .fallback_best_triage_seen_at
                .as_deref()
                .map(|current| row.last_seen.as_str() >= current)
                .unwrap_or(true)
        {
            self.fallback_best_triage_json = row.best_triage_json.clone();
            self.fallback_best_triage_seen_at = Some(row.last_seen.clone());
        }
        if replace_representative {
            self.kind = row.kind.clone();
            self.title = row.title.clone();
            self.summary = row.summary.clone();
            self.public_title = public_fields.title.clone();
            self.public_summary = public_fields.summary.clone();
            self.representative_json = row.representative_json.clone();
            self.last_seen = row.last_seen.clone();
        } else {
            self.last_seen = self.last_seen.clone().max(row.last_seen.clone());
        }
    }
}

async fn needs_schema_migration(db: &ServerDb) -> Result<bool> {
    match db {
        ServerDb::Postgres(db) => Ok(db
            .query_opt(
                "
            SELECT 1
            FROM information_schema.columns
            WHERE table_name = 'issue_clusters' AND column_name = 'public_visible'
            ",
                &[],
            )
            .await?
            .is_none()
            && db
                .query_opt(
                    "
                SELECT 1
                FROM information_schema.tables
                WHERE table_name = 'issue_clusters'
                ",
                    &[],
                )
                .await?
                .is_some()),
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let table_exists: Option<i64> = connection
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'issue_clusters'",
                    [],
                    |row| row.get(0),
                )
                .optional()?;
            if table_exists.is_none() {
                return Ok(false);
            }
            let mut stmt = connection.prepare("PRAGMA table_info(issue_clusters)")?;
            let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
            Ok(!columns
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .any(|name| name == "public_visible"))
        }
    }
}

async fn migrate_legacy_schema(db: &ServerDb, config: &FixerConfig) -> Result<()> {
    let legacy = load_legacy_state(db).await?;
    let migrated = migrate_legacy_state(legacy, config.server.quarantine_corroboration_threshold)?;
    drop_legacy_server_tables(db).await?;
    ensure_current_schema(db).await?;
    write_migrated_state(db, &migrated).await
}

async fn load_legacy_state(db: &ServerDb) -> Result<LegacyServerState> {
    match db {
        ServerDb::Postgres(db) => load_legacy_state_postgres(db).await,
        ServerDb::Sqlite(path) => load_legacy_state_sqlite(path),
    }
}

async fn load_legacy_state_postgres(db: &Client) -> Result<LegacyServerState> {
    let submissions = db
        .query(
            "
        SELECT id, install_id, content_hash, payload_hash, received_at, remote_addr, quarantined, bundle_json
        FROM submissions
        ",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| {
            let received_at: DateTime<Utc> = row.get(4);
            Ok(LegacySubmission {
                id: row.get(0),
                install_id: row.get(1),
                content_hash: row.get(2),
                payload_hash: row.get(3),
                received_at: received_at.to_rfc3339(),
                remote_addr: row.get(5),
                quarantined: row.get(6),
                bundle_json: row.get(7),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let issue_clusters = db
        .query(
            "
        SELECT id, kind, title, summary, package_name, source_package, ecosystem, severity,
               score, promoted, representative_json, best_patch_json, last_seen
        FROM issue_clusters
        ",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| {
            let last_seen: DateTime<Utc> = row.get(12);
            Ok(LegacyIssueCluster {
                id: row.get(0),
                kind: row.get(1),
                title: row.get(2),
                summary: row.get(3),
                package_name: row.get(4),
                source_package: row.get(5),
                ecosystem: row.get(6),
                severity: row.get(7),
                score: row.get(8),
                promoted: row.get(9),
                representative_json: row.get(10),
                best_patch_json: row.get(11),
                last_seen: last_seen.to_rfc3339(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let cluster_reports = db
        .query(
            "
        SELECT cluster_id, install_id, submission_id, created_at
        FROM cluster_reports
        ",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| {
            let created_at: DateTime<Utc> = row.get(3);
            LegacyClusterReport {
                cluster_id: row.get(0),
                install_id: row.get(1),
                submission_id: row.get(2),
                created_at: created_at.to_rfc3339(),
            }
        })
        .collect();
    let worker_leases = db
        .query(
            "
        SELECT id, cluster_id, install_id, state, leased_at, expires_at, work_json
        FROM worker_leases
        ",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| {
            let leased_at: DateTime<Utc> = row.get(4);
            let expires_at: DateTime<Utc> = row.get(5);
            LegacyWorkerLease {
                id: row.get(0),
                cluster_id: row.get(1),
                install_id: row.get(2),
                state: row.get(3),
                leased_at: leased_at.to_rfc3339(),
                expires_at: expires_at.to_rfc3339(),
                work_json: row.get(6),
            }
        })
        .collect();
    let patch_attempts = db
        .query(
            "
        SELECT cluster_id, lease_id, install_id, outcome, state, summary, bundle_json, created_at
        FROM patch_attempts
        ",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| {
            let created_at: DateTime<Utc> = row.get(7);
            LegacyPatchAttempt {
                cluster_id: row.get(0),
                lease_id: row.get(1),
                install_id: row.get(2),
                outcome: row.get(3),
                state: row.get(4),
                summary: row.get(5),
                bundle_json: row.get(6),
                created_at: created_at.to_rfc3339(),
            }
        })
        .collect();
    let evidence_requests = db
        .query(
            "
        SELECT issue_id, requested_by_install_id, reason, requested_fields_json, requested_at, response_json
        FROM evidence_requests
        ",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| {
            let requested_at: DateTime<Utc> = row.get(4);
            LegacyEvidenceRequest {
                issue_id: row.get(0),
                requested_by_install_id: row.get(1),
                reason: row.get(2),
                requested_fields_json: row.get(3),
                requested_at: requested_at.to_rfc3339(),
                response_json: row.get(5),
            }
        })
        .collect();
    let rate_events = db
        .query(
            "
        SELECT scope_kind, scope_value, event_kind, created_at
        FROM rate_events
        ",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| {
            let created_at: DateTime<Utc> = row.get(3);
            LegacyRateEvent {
                scope_kind: row.get(0),
                scope_value: row.get(1),
                event_kind: row.get(2),
                created_at: created_at.to_rfc3339(),
            }
        })
        .collect();

    Ok(LegacyServerState {
        submissions,
        issue_clusters,
        cluster_reports,
        worker_leases,
        patch_attempts,
        evidence_requests,
        rate_events,
    })
}

fn load_legacy_state_sqlite(path: &Path) -> Result<LegacyServerState> {
    let connection = sqlite_connection(path)?;
    let submissions = connection
        .prepare(
            "
        SELECT id, install_id, content_hash, payload_hash, received_at, remote_addr, quarantined, bundle_json
        FROM submissions
        ",
        )?
        .query_map([], |row| {
            Ok(LegacySubmission {
                id: row.get(0)?,
                install_id: row.get(1)?,
                content_hash: row.get(2)?,
                payload_hash: row.get(3)?,
                received_at: row.get(4)?,
                remote_addr: row.get(5)?,
                quarantined: row.get::<_, i64>(6)? != 0,
                bundle_json: sqlite_json_value(row.get::<_, String>(7)?)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let issue_clusters = connection
        .prepare(
            "
        SELECT id, kind, title, summary, package_name, source_package, ecosystem, severity,
               score, promoted, representative_json, best_patch_json, last_seen
        FROM issue_clusters
        ",
        )?
        .query_map([], |row| {
            Ok(LegacyIssueCluster {
                id: row.get(0)?,
                kind: row.get(1)?,
                title: row.get(2)?,
                summary: row.get(3)?,
                package_name: row.get(4)?,
                source_package: row.get(5)?,
                ecosystem: row.get(6)?,
                severity: row.get(7)?,
                score: row.get(8)?,
                promoted: row.get::<_, i64>(9)? != 0,
                representative_json: sqlite_json_value(row.get::<_, String>(10)?)?,
                best_patch_json: row
                    .get::<_, Option<String>>(11)?
                    .map(sqlite_json_value)
                    .transpose()?,
                last_seen: row.get(12)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let cluster_reports = connection
        .prepare(
            "
        SELECT cluster_id, install_id, submission_id, created_at
        FROM cluster_reports
        ",
        )?
        .query_map([], |row| {
            Ok(LegacyClusterReport {
                cluster_id: row.get(0)?,
                install_id: row.get(1)?,
                submission_id: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let worker_leases = connection
        .prepare(
            "
        SELECT id, cluster_id, install_id, state, leased_at, expires_at, work_json
        FROM worker_leases
        ",
        )?
        .query_map([], |row| {
            Ok(LegacyWorkerLease {
                id: row.get(0)?,
                cluster_id: row.get(1)?,
                install_id: row.get(2)?,
                state: row.get(3)?,
                leased_at: row.get(4)?,
                expires_at: row.get(5)?,
                work_json: sqlite_json_value(row.get::<_, String>(6)?)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let patch_attempts = connection
        .prepare(
            "
        SELECT cluster_id, lease_id, install_id, outcome, state, summary, bundle_json, created_at
        FROM patch_attempts
        ",
        )?
        .query_map([], |row| {
            Ok(LegacyPatchAttempt {
                cluster_id: row.get(0)?,
                lease_id: row.get(1)?,
                install_id: row.get(2)?,
                outcome: row.get(3)?,
                state: row.get(4)?,
                summary: row.get(5)?,
                bundle_json: sqlite_json_value(row.get::<_, String>(6)?)?,
                created_at: row.get(7)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let evidence_requests = connection
        .prepare(
            "
        SELECT issue_id, requested_by_install_id, reason, requested_fields_json, requested_at, response_json
        FROM evidence_requests
        ",
        )?
        .query_map([], |row| {
            Ok(LegacyEvidenceRequest {
                issue_id: row.get(0)?,
                requested_by_install_id: row.get(1)?,
                reason: row.get(2)?,
                requested_fields_json: sqlite_json_value(row.get::<_, String>(3)?)?,
                requested_at: row.get(4)?,
                response_json: row
                    .get::<_, Option<String>>(5)?
                    .map(sqlite_json_value)
                    .transpose()?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let rate_events = connection
        .prepare(
            "
        SELECT scope_kind, scope_value, event_kind, created_at
        FROM rate_events
        ",
        )?
        .query_map([], |row| {
            Ok(LegacyRateEvent {
                scope_kind: row.get(0)?,
                scope_value: row.get(1)?,
                event_kind: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(LegacyServerState {
        submissions,
        issue_clusters,
        cluster_reports,
        worker_leases,
        patch_attempts,
        evidence_requests,
        rate_events,
    })
}

fn sqlite_json_value(raw: String) -> rusqlite::Result<Value> {
    serde_json::from_str(&raw).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

fn migrate_legacy_state(
    legacy: LegacyServerState,
    quarantine_corroboration_threshold: i64,
) -> Result<MigratedServerState> {
    let submission_id_map = legacy
        .submissions
        .iter()
        .map(|submission| (submission.id, new_server_id()))
        .collect::<HashMap<_, _>>();
    let submissions = legacy
        .submissions
        .iter()
        .map(|submission| MigratedSubmission {
            id: submission_id_map
                .get(&submission.id)
                .expect("submission id mapped")
                .clone(),
            install_id: submission.install_id.clone(),
            content_hash: submission.content_hash.clone(),
            payload_hash: submission.payload_hash.clone(),
            received_at: submission.received_at.clone(),
            remote_addr: submission.remote_addr.clone(),
            quarantined: submission.quarantined,
            bundle_json: submission.bundle_json.clone(),
        })
        .collect::<Vec<_>>();

    let mut grouped_clusters = BTreeMap::<String, ClusterAccumulator>::new();
    for row in &legacy.issue_clusters {
        let representative: SharedOpportunity =
            serde_json::from_value(row.representative_json.clone())?;
        let cluster_key = cluster_key_for(&representative);
        let public_fields = build_public_issue_fields(&representative);
        grouped_clusters
            .entry(cluster_key)
            .and_modify(|group| group.absorb(row, &public_fields))
            .or_insert_with(|| ClusterAccumulator::new(row, &public_fields));
    }

    let mut legacy_cluster_id_map = HashMap::<i64, String>::new();
    let mut issue_clusters = grouped_clusters
        .into_iter()
        .map(|(cluster_key, group)| {
            let id = new_server_id();
            for legacy_id in &group.legacy_ids {
                legacy_cluster_id_map.insert(*legacy_id, id.clone());
            }
            MigratedIssueCluster {
                id,
                cluster_key,
                kind: group.kind,
                title: group.title,
                summary: group.summary,
                public_title: group.public_title,
                public_summary: group.public_summary,
                public_visible: group.public_visible,
                package_name: group.package_name,
                source_package: group.source_package,
                ecosystem: group.ecosystem,
                severity: group.severity,
                score: group.score,
                corroboration_count: 0,
                quarantined: true,
                promoted: group.any_promoted,
                representative_json: group.representative_json,
                best_patch_json: group.fallback_best_patch_json,
                best_triage_json: group.fallback_best_triage_json,
                last_seen: group.last_seen,
            }
        })
        .collect::<Vec<_>>();

    let lease_id_map = legacy
        .worker_leases
        .iter()
        .map(|lease| (lease.id.clone(), new_server_id()))
        .collect::<HashMap<_, _>>();

    let worker_leases = legacy
        .worker_leases
        .iter()
        .filter_map(|lease| {
            let cluster_id = legacy_cluster_id_map.get(&lease.cluster_id)?.clone();
            let new_lease_id = lease_id_map.get(&lease.id)?.clone();
            Some(MigratedWorkerLease {
                id: new_lease_id.clone(),
                cluster_id: cluster_id.clone(),
                install_id: lease.install_id.clone(),
                state: lease.state.clone(),
                leased_at: lease.leased_at.clone(),
                expires_at: lease.expires_at.clone(),
                work_json: rewrite_work_lease_json(
                    lease.work_json.clone(),
                    &cluster_id,
                    &new_lease_id,
                ),
            })
        })
        .collect::<Vec<_>>();

    let patch_attempts = legacy
        .patch_attempts
        .iter()
        .filter_map(|attempt| {
            let cluster_id = legacy_cluster_id_map.get(&attempt.cluster_id)?.clone();
            let lease_id = attempt
                .lease_id
                .as_ref()
                .and_then(|legacy_id| lease_id_map.get(legacy_id))
                .cloned();
            let rewritten_bundle = rewrite_worker_result_json(
                attempt.bundle_json.clone(),
                &cluster_id,
                lease_id.as_deref(),
            );
            let canonical_bundle = serde_json::from_value::<WorkerResultEnvelope>(rewritten_bundle)
                .ok()
                .map(canonicalize_worker_result_envelope);
            Some(MigratedPatchAttempt {
                id: new_server_id(),
                cluster_id: cluster_id.clone(),
                lease_id: lease_id.clone(),
                install_id: attempt.install_id.clone(),
                outcome: canonical_bundle
                    .as_ref()
                    .map(|bundle| bundle.attempt.outcome.clone())
                    .unwrap_or_else(|| attempt.outcome.clone()),
                state: canonical_bundle
                    .as_ref()
                    .map(|bundle| bundle.attempt.state.clone())
                    .unwrap_or_else(|| attempt.state.clone()),
                summary: canonical_bundle
                    .as_ref()
                    .map(|bundle| bundle.attempt.summary.clone())
                    .unwrap_or_else(|| attempt.summary.clone()),
                bundle_json: canonical_bundle
                    .map(serde_json::to_value)
                    .transpose()
                    .ok()?
                    .unwrap_or_else(|| {
                        rewrite_worker_result_json(
                            attempt.bundle_json.clone(),
                            &cluster_id,
                            lease_id.as_deref(),
                        )
                    }),
                created_at: attempt.created_at.clone(),
            })
        })
        .collect::<Vec<_>>();

    let evidence_requests = legacy
        .evidence_requests
        .iter()
        .filter_map(|request| {
            let issue_id = legacy_cluster_id_map.get(&request.issue_id)?.clone();
            Some(MigratedEvidenceRequest {
                id: new_server_id(),
                issue_id,
                requested_by_install_id: request.requested_by_install_id.clone(),
                reason: request.reason.clone(),
                requested_fields_json: request.requested_fields_json.clone(),
                requested_at: request.requested_at.clone(),
                response_json: request.response_json.clone(),
            })
        })
        .collect::<Vec<_>>();

    let rate_events = legacy
        .rate_events
        .iter()
        .map(|event| MigratedRateEvent {
            id: new_server_id(),
            scope_kind: event.scope_kind.clone(),
            scope_value: event.scope_value.clone(),
            event_kind: event.event_kind.clone(),
            created_at: event.created_at.clone(),
        })
        .collect::<Vec<_>>();

    let mut cluster_report_map = HashMap::<(String, String), MigratedClusterReport>::new();
    for report in &legacy.cluster_reports {
        let Some(cluster_id) = legacy_cluster_id_map.get(&report.cluster_id) else {
            continue;
        };
        let Some(submission_id) = submission_id_map.get(&report.submission_id) else {
            continue;
        };
        let key = (cluster_id.clone(), report.install_id.clone());
        match cluster_report_map.get_mut(&key) {
            Some(existing) if report.created_at > existing.created_at => {
                existing.submission_id = submission_id.clone();
                existing.created_at = report.created_at.clone();
            }
            Some(_) => {}
            None => {
                cluster_report_map.insert(
                    key,
                    MigratedClusterReport {
                        cluster_id: cluster_id.clone(),
                        install_id: report.install_id.clone(),
                        submission_id: submission_id.clone(),
                        created_at: report.created_at.clone(),
                    },
                );
            }
        }
    }
    let cluster_reports = cluster_report_map.into_values().collect::<Vec<_>>();

    let mut patch_attempt_best = HashMap::<String, (&str, Value)>::new();
    let mut triage_attempt_best = HashMap::<String, (&str, Value)>::new();
    for attempt in &patch_attempts {
        if attempt.state != "ready" {
            continue;
        }
        let payload = attempt
            .bundle_json
            .get("attempt")
            .cloned()
            .unwrap_or_else(|| {
                json!({
                    "cluster_id": attempt.cluster_id,
                    "install_id": attempt.install_id,
                    "outcome": attempt.outcome,
                    "state": attempt.state,
                    "summary": attempt.summary,
                    "bundle_path": Value::Null,
                    "output_path": Value::Null,
                    "validation_status": Value::Null,
                    "details": {},
                    "created_at": attempt.created_at,
                })
            });
        if attempt.outcome == "patch" {
            patch_attempt_best
                .entry(attempt.cluster_id.clone())
                .and_modify(|existing| {
                    if attempt.created_at.as_str() > existing.0 {
                        *existing = (attempt.created_at.as_str(), payload.clone());
                    }
                })
                .or_insert((attempt.created_at.as_str(), payload.clone()));
        }
        if attempt.outcome == "triage" {
            triage_attempt_best
                .entry(attempt.cluster_id.clone())
                .and_modify(|existing| {
                    if attempt.created_at.as_str() > existing.0 {
                        *existing = (attempt.created_at.as_str(), payload.clone());
                    }
                })
                .or_insert((attempt.created_at.as_str(), payload));
        }
    }

    let mut issue_counts = HashMap::<String, i64>::new();
    for report in &cluster_reports {
        *issue_counts.entry(report.cluster_id.clone()).or_default() += 1;
    }
    for issue in &mut issue_clusters {
        issue.corroboration_count = *issue_counts.get(&issue.id).unwrap_or(&0);
        issue.promoted =
            issue.promoted || issue.corroboration_count >= quarantine_corroboration_threshold;
        issue.quarantined = !issue.promoted;
        if let Some((_, best_patch)) = patch_attempt_best.get(&issue.id) {
            issue.best_patch_json = Some(best_patch.clone());
        } else if let Some(best_patch) = issue.best_patch_json.clone() {
            let best_patch = rewrite_patch_attempt_json(best_patch, &issue.id);
            if let Ok(attempt) = serde_json::from_value::<PatchAttempt>(best_patch) {
                let attempt = canonicalize_patch_attempt(attempt);
                if attempt.state == "ready" && attempt.outcome == "patch" {
                    issue.best_patch_json = Some(serde_json::to_value(attempt)?);
                } else {
                    issue.best_patch_json = None;
                }
            } else {
                issue.best_patch_json = None;
            }
        }
        if let Some((_, best_triage)) = triage_attempt_best.get(&issue.id) {
            issue.best_triage_json = Some(best_triage.clone());
        } else if let Some(best_triage) = issue.best_triage_json.clone() {
            let best_triage = rewrite_patch_attempt_json(best_triage, &issue.id);
            if let Ok(attempt) = serde_json::from_value::<PatchAttempt>(best_triage) {
                let attempt = canonicalize_patch_attempt(attempt);
                if attempt.state == "ready" && attempt.outcome == "triage" {
                    issue.best_triage_json = Some(serde_json::to_value(attempt)?);
                } else {
                    issue.best_triage_json = None;
                }
            } else {
                issue.best_triage_json = None;
            }
        }
    }

    Ok(MigratedServerState {
        submissions,
        issue_clusters,
        cluster_reports,
        worker_leases,
        patch_attempts,
        evidence_requests,
        rate_events,
    })
}

fn rewrite_patch_attempt_json(mut value: Value, cluster_id: &str) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.insert("cluster_id".to_string(), json!(cluster_id));
    }
    value
}

fn rewrite_work_lease_json(mut value: Value, cluster_id: &str, lease_id: &str) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.insert("lease_id".to_string(), json!(lease_id));
        if let Some(issue) = object.get_mut("issue").and_then(Value::as_object_mut) {
            issue.insert("id".to_string(), json!(cluster_id));
            if let Some(best_patch) = issue.get_mut("best_patch") {
                *best_patch = rewrite_patch_attempt_json(best_patch.clone(), cluster_id);
            }
        }
    }
    value
}

fn rewrite_worker_result_json(mut value: Value, cluster_id: &str, lease_id: Option<&str>) -> Value {
    if let Some(object) = value.as_object_mut() {
        if let Some(lease_id) = lease_id {
            object.insert("lease_id".to_string(), json!(lease_id));
        }
        if let Some(attempt) = object.get_mut("attempt") {
            *attempt = rewrite_patch_attempt_json(attempt.clone(), cluster_id);
        }
        if let Some(evidence_request) = object
            .get_mut("evidence_request")
            .and_then(Value::as_object_mut)
        {
            evidence_request.insert("issue_id".to_string(), json!(cluster_id));
        }
    }
    value
}

async fn drop_legacy_server_tables(db: &ServerDb) -> Result<()> {
    match db {
        ServerDb::Postgres(db) => {
            db.batch_execute(
                "
            DROP TABLE IF EXISTS cluster_reports;
            DROP TABLE IF EXISTS patch_attempts;
            DROP TABLE IF EXISTS evidence_requests;
            DROP TABLE IF EXISTS worker_leases;
            DROP TABLE IF EXISTS issue_clusters;
            DROP TABLE IF EXISTS submissions;
            DROP TABLE IF EXISTS rate_events;
            ",
            )
            .await?;
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            connection.execute_batch(
                "
            PRAGMA foreign_keys = OFF;
            DROP TABLE IF EXISTS cluster_reports;
            DROP TABLE IF EXISTS patch_attempts;
            DROP TABLE IF EXISTS evidence_requests;
            DROP TABLE IF EXISTS worker_leases;
            DROP TABLE IF EXISTS issue_clusters;
            DROP TABLE IF EXISTS submissions;
            DROP TABLE IF EXISTS rate_events;
            PRAGMA foreign_keys = ON;
            ",
            )?;
        }
    }
    Ok(())
}

async fn write_migrated_state(db: &ServerDb, state: &MigratedServerState) -> Result<()> {
    match db {
        ServerDb::Postgres(db) => {
            for submission in &state.submissions {
                db.execute(
                    "
                INSERT INTO submissions (id, install_id, content_hash, payload_hash, received_at, remote_addr, quarantined, bundle_json)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ",
                    &[
                        &submission.id,
                        &submission.install_id,
                        &submission.content_hash,
                        &submission.payload_hash,
                        &parse_timestamp(&submission.received_at).unwrap_or_else(Utc::now),
                        &submission.remote_addr,
                        &submission.quarantined,
                        &submission.bundle_json,
                    ],
                )
                .await?;
            }
            for issue in &state.issue_clusters {
                db.execute(
                    "
                INSERT INTO issue_clusters
                    (id, cluster_key, kind, title, summary, public_title, public_summary, public_visible,
                     package_name, source_package, ecosystem, severity, score, corroboration_count,
                     quarantined, promoted, representative_json, best_patch_json, best_triage_json, last_seen)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
                ",
                    &[
                        &issue.id,
                        &issue.cluster_key,
                        &issue.kind,
                        &issue.title,
                        &issue.summary,
                        &issue.public_title,
                        &issue.public_summary,
                        &issue.public_visible,
                        &issue.package_name,
                        &issue.source_package,
                        &issue.ecosystem,
                        &issue.severity,
                        &issue.score,
                        &issue.corroboration_count,
                        &issue.quarantined,
                        &issue.promoted,
                        &issue.representative_json,
                        &issue.best_patch_json,
                        &issue.best_triage_json,
                        &parse_timestamp(&issue.last_seen).unwrap_or_else(Utc::now),
                    ],
                )
                .await?;
            }
            for report in &state.cluster_reports {
                db.execute(
                    "
                INSERT INTO cluster_reports (cluster_id, install_id, submission_id, created_at)
                VALUES ($1, $2, $3, $4)
                ",
                    &[
                        &report.cluster_id,
                        &report.install_id,
                        &report.submission_id,
                        &parse_timestamp(&report.created_at).unwrap_or_else(Utc::now),
                    ],
                )
                .await?;
            }
            for lease in &state.worker_leases {
                db.execute(
                    "
                INSERT INTO worker_leases (id, cluster_id, install_id, state, leased_at, expires_at, work_json)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ",
                    &[
                        &lease.id,
                        &lease.cluster_id,
                        &lease.install_id,
                        &lease.state,
                        &parse_timestamp(&lease.leased_at).unwrap_or_else(Utc::now),
                        &parse_timestamp(&lease.expires_at).unwrap_or_else(Utc::now),
                        &lease.work_json,
                    ],
                )
                .await?;
            }
            for attempt in &state.patch_attempts {
                db.execute(
                    "
                INSERT INTO patch_attempts (id, cluster_id, lease_id, install_id, outcome, state, summary, bundle_json, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ",
                    &[
                        &attempt.id,
                        &attempt.cluster_id,
                        &attempt.lease_id,
                        &attempt.install_id,
                        &attempt.outcome,
                        &attempt.state,
                        &attempt.summary,
                        &attempt.bundle_json,
                        &parse_timestamp(&attempt.created_at).unwrap_or_else(Utc::now),
                    ],
                )
                .await?;
            }
            for request in &state.evidence_requests {
                db.execute(
                    "
                INSERT INTO evidence_requests (id, issue_id, requested_by_install_id, reason, requested_fields_json, requested_at, response_json)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ",
                    &[
                        &request.id,
                        &request.issue_id,
                        &request.requested_by_install_id,
                        &request.reason,
                        &request.requested_fields_json,
                        &parse_timestamp(&request.requested_at).unwrap_or_else(Utc::now),
                        &request.response_json,
                    ],
                )
                .await?;
            }
            for event in &state.rate_events {
                db.execute(
                    "
                INSERT INTO rate_events (id, scope_kind, scope_value, event_kind, created_at)
                VALUES ($1, $2, $3, $4, $5)
                ",
                    &[
                        &event.id,
                        &event.scope_kind,
                        &event.scope_value,
                        &event.event_kind,
                        &parse_timestamp(&event.created_at).unwrap_or_else(Utc::now),
                    ],
                )
                .await?;
            }
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            for submission in &state.submissions {
                connection.execute(
                    "
                INSERT INTO submissions (id, install_id, content_hash, payload_hash, received_at, remote_addr, quarantined, bundle_json)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ",
                    params![
                        submission.id,
                        submission.install_id,
                        submission.content_hash,
                        submission.payload_hash,
                        submission.received_at,
                        submission.remote_addr,
                        submission.quarantined,
                        serde_json::to_string(&submission.bundle_json)?,
                    ],
                )?;
            }
            for issue in &state.issue_clusters {
                connection.execute(
                    "
                INSERT INTO issue_clusters
                    (id, cluster_key, kind, title, summary, public_title, public_summary, public_visible,
                     package_name, source_package, ecosystem, severity, score, corroboration_count,
                     quarantined, promoted, representative_json, best_patch_json, best_triage_json, last_seen)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
                ",
                    params![
                        issue.id,
                        issue.cluster_key,
                        issue.kind,
                        issue.title,
                        issue.summary,
                        issue.public_title,
                        issue.public_summary,
                        issue.public_visible,
                        issue.package_name,
                        issue.source_package,
                        issue.ecosystem,
                        issue.severity,
                        issue.score,
                        issue.corroboration_count,
                        issue.quarantined,
                        issue.promoted,
                        serde_json::to_string(&issue.representative_json)?,
                        issue.best_patch_json.as_ref().map(serde_json::to_string).transpose()?,
                        issue.best_triage_json
                            .as_ref()
                            .map(serde_json::to_string)
                            .transpose()?,
                        issue.last_seen,
                    ],
                )?;
            }
            for report in &state.cluster_reports {
                connection.execute(
                    "
                INSERT INTO cluster_reports (cluster_id, install_id, submission_id, created_at)
                VALUES (?1, ?2, ?3, ?4)
                ",
                    params![
                        report.cluster_id,
                        report.install_id,
                        report.submission_id,
                        report.created_at
                    ],
                )?;
            }
            for lease in &state.worker_leases {
                connection.execute(
                    "
                INSERT INTO worker_leases (id, cluster_id, install_id, state, leased_at, expires_at, work_json)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ",
                    params![
                        lease.id,
                        lease.cluster_id,
                        lease.install_id,
                        lease.state,
                        lease.leased_at,
                        lease.expires_at,
                        serde_json::to_string(&lease.work_json)?,
                    ],
                )?;
            }
            for attempt in &state.patch_attempts {
                connection.execute(
                    "
                INSERT INTO patch_attempts (id, cluster_id, lease_id, install_id, outcome, state, summary, bundle_json, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ",
                    params![
                        attempt.id,
                        attempt.cluster_id,
                        attempt.lease_id,
                        attempt.install_id,
                        attempt.outcome,
                        attempt.state,
                        attempt.summary,
                        serde_json::to_string(&attempt.bundle_json)?,
                        attempt.created_at,
                    ],
                )?;
            }
            for request in &state.evidence_requests {
                connection.execute(
                    "
                INSERT INTO evidence_requests (id, issue_id, requested_by_install_id, reason, requested_fields_json, requested_at, response_json)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ",
                    params![
                        request.id,
                        request.issue_id,
                        request.requested_by_install_id,
                        request.reason,
                        serde_json::to_string(&request.requested_fields_json)?,
                        request.requested_at,
                        request.response_json.as_ref().map(serde_json::to_string).transpose()?,
                    ],
                )?;
            }
            for event in &state.rate_events {
                connection.execute(
                    "
                INSERT INTO rate_events (id, scope_kind, scope_value, event_kind, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5)
                ",
                    params![
                        event.id,
                        event.scope_kind,
                        event.scope_value,
                        event.event_kind,
                        event.created_at
                    ],
                )?;
            }
        }
    }
    Ok(())
}

async fn ensure_install(
    db: &ServerDb,
    request: &ClientHello,
    remote_addr: String,
    _config: &FixerConfig,
) -> Result<()> {
    let now = Utc::now();
    match db {
        ServerDb::Postgres(db) => {
            db.execute(
                "
        INSERT INTO installs (install_id, first_seen, last_seen, mode, hostname, version, has_codex, capabilities_json, last_ip, patch_driver, patch_model)
        VALUES ($1, $2, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (install_id) DO UPDATE SET
            last_seen = EXCLUDED.last_seen,
            mode = EXCLUDED.mode,
            hostname = EXCLUDED.hostname,
            version = EXCLUDED.version,
            has_codex = EXCLUDED.has_codex,
            capabilities_json = EXCLUDED.capabilities_json,
            last_ip = EXCLUDED.last_ip,
            patch_driver = EXCLUDED.patch_driver,
            patch_model = EXCLUDED.patch_model
        ",
                &[
                    &request.install_id,
                    &now,
                    &request.mode.as_str(),
                    &request.hostname,
                    &request.version,
                    &request.has_codex,
                    &serde_json::to_value(&request.capabilities)?,
                    &remote_addr,
                    &request.patch_driver,
                    &request.patch_model,
                ],
            )
            .await?;
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            connection.execute(
                "
        INSERT INTO installs (install_id, first_seen, last_seen, mode, hostname, version, has_codex, capabilities_json, last_ip, patch_driver, patch_model)
        VALUES (?1, ?2, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        ON CONFLICT(install_id) DO UPDATE SET
            last_seen = excluded.last_seen,
            mode = excluded.mode,
            hostname = excluded.hostname,
            version = excluded.version,
            has_codex = excluded.has_codex,
            capabilities_json = excluded.capabilities_json,
            last_ip = excluded.last_ip,
            patch_driver = excluded.patch_driver,
            patch_model = excluded.patch_model
        ",
                params![
                    request.install_id,
                    now.to_rfc3339(),
                    request.mode.as_str(),
                    request.hostname,
                    request.version,
                    request.has_codex,
                    serde_json::to_string(&request.capabilities)?,
                    remote_addr,
                    request.patch_driver,
                    request.patch_model,
                ],
            )?;
        }
    }
    Ok(())
}

fn reject_incompatible_client(request: &ClientHello) -> Result<(), ApiError> {
    let compatibility = evaluate_client_compatibility(request.protocol_version, &request.version);
    if compatibility.upgrade_required {
        return Err(ApiError::new(
            StatusCode::UPGRADE_REQUIRED,
            compatibility.upgrade_message,
        ));
    }
    Ok(())
}

async fn install_trust(
    db: &ServerDb,
    install_id: &str,
) -> Result<(i64, i64, Option<DateTime<Utc>>)> {
    match db {
        ServerDb::Postgres(db) => {
            let row = db
                .query_one(
                    "
        SELECT submission_trust_score, worker_trust_score, banned_until
        FROM installs
        WHERE install_id = $1
        ",
                    &[&install_id],
                )
                .await?;
            Ok((row.get(0), row.get(1), row.get(2)))
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let row = connection.query_row(
                "
        SELECT submission_trust_score, worker_trust_score, banned_until
        FROM installs
        WHERE install_id = ?1
        ",
                [install_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )?;
            Ok((row.0, row.1, row.2.as_deref().and_then(parse_timestamp)))
        }
    }
}

async fn rate_limited(
    db: &ServerDb,
    event_kind: &str,
    install_id: &str,
    remote_addr: &str,
    limit: i64,
) -> Result<bool> {
    let window_start = Utc::now() - Duration::hours(1);
    match db {
        ServerDb::Postgres(db) => {
            let install_count: i64 = db
                .query_one(
                    "
        SELECT COUNT(*) FROM rate_events
        WHERE event_kind = $1 AND scope_kind = 'install' AND scope_value = $2 AND created_at >= $3
        ",
                    &[&event_kind, &install_id, &window_start],
                )
                .await?
                .get(0);
            if install_count >= limit {
                return Ok(true);
            }
            let ip_count: i64 = db
                .query_one(
                    "
        SELECT COUNT(*) FROM rate_events
        WHERE event_kind = $1 AND scope_kind = 'ip' AND scope_value = $2 AND created_at >= $3
        ",
                    &[&event_kind, &remote_addr, &window_start],
                )
                .await?
                .get(0);
            Ok(ip_count >= limit)
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let window_start = window_start.to_rfc3339();
            let install_count: i64 = connection.query_row(
                "
        SELECT COUNT(*) FROM rate_events
        WHERE event_kind = ?1 AND scope_kind = 'install' AND scope_value = ?2 AND created_at >= ?3
        ",
                params![event_kind, install_id, window_start],
                |row| row.get(0),
            )?;
            if install_count >= limit {
                return Ok(true);
            }
            let ip_count: i64 = connection.query_row(
                "
        SELECT COUNT(*) FROM rate_events
        WHERE event_kind = ?1 AND scope_kind = 'ip' AND scope_value = ?2 AND created_at >= ?3
        ",
                params![event_kind, remote_addr, window_start],
                |row| row.get(0),
            )?;
            Ok(ip_count >= limit)
        }
    }
}

async fn note_rate_event(
    db: &ServerDb,
    event_kind: &str,
    install_id: &str,
    remote_addr: &str,
) -> Result<()> {
    let now = Utc::now();
    match db {
        ServerDb::Postgres(db) => {
            for (scope_kind, scope_value) in [("install", install_id), ("ip", remote_addr)] {
                let event_id = new_server_id();
                db.execute(
                    "
            INSERT INTO rate_events (id, scope_kind, scope_value, event_kind, created_at)
            VALUES ($1, $2, $3, $4, $5)
            ",
                    &[&event_id, &scope_kind, &scope_value, &event_kind, &now],
                )
                .await?;
            }
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let now = now.to_rfc3339();
            for (scope_kind, scope_value) in [("install", install_id), ("ip", remote_addr)] {
                let event_id = new_server_id();
                connection.execute(
                    "
            INSERT INTO rate_events (id, scope_kind, scope_value, event_kind, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ",
                    params![event_id, scope_kind, scope_value, event_kind, now],
                )?;
            }
        }
    }
    Ok(())
}

async fn record_abuse(
    db: &ServerDb,
    install_id: &str,
    reason: &str,
    config: &FixerConfig,
) -> Result<()> {
    let now = Utc::now();
    match db {
        ServerDb::Postgres(db) => {
            db.execute(
                "
        INSERT INTO installs (install_id, first_seen, last_seen, mode, hostname, version, has_codex, capabilities_json, last_ip)
        VALUES ($1, $2, $2, 'local-only', NULL, 'unknown', FALSE, '[]'::jsonb, NULL)
        ON CONFLICT (install_id) DO NOTHING
        ",
                &[&install_id, &now],
            )
            .await?;
            db.execute(
                "
        UPDATE installs
        SET abuse_events = abuse_events + 1,
            banned_until = CASE
                WHEN abuse_events + 1 >= $2 THEN $3
                ELSE banned_until
            END
        WHERE install_id = $1
        ",
                &[
                    &install_id,
                    &config.server.max_abuse_events_before_ban,
                    &(now + Duration::hours(1)),
                ],
            )
            .await?;
        }
        ServerDb::Sqlite(path) => {
            let mut connection = sqlite_connection(path)?;
            let tx = connection.transaction()?;
            tx.execute(
                "
        INSERT INTO installs (install_id, first_seen, last_seen, mode, hostname, version, has_codex, capabilities_json, last_ip)
        VALUES (?1, ?2, ?2, 'local-only', NULL, 'unknown', 0, '[]', NULL)
        ON CONFLICT(install_id) DO NOTHING
        ",
                params![install_id, now.to_rfc3339()],
            )?;
            let existing_abuse: i64 = tx.query_row(
                "SELECT abuse_events FROM installs WHERE install_id = ?1",
                [install_id],
                |row| row.get(0),
            )?;
            let updated_abuse = existing_abuse + 1;
            let banned_until = if updated_abuse >= config.server.max_abuse_events_before_ban {
                Some((now + Duration::hours(1)).to_rfc3339())
            } else {
                None
            };
            tx.execute(
                "
        UPDATE installs
        SET abuse_events = ?2,
            banned_until = COALESCE(?3, banned_until)
        WHERE install_id = ?1
        ",
                params![install_id, updated_abuse, banned_until],
            )?;
            tx.commit()?;
        }
    }
    tracing::warn!(install_id, reason, "recorded abusive request");
    Ok(())
}

async fn find_submission_by_content_hash(
    db: &ServerDb,
    content_hash: &str,
) -> Result<Option<String>> {
    match db {
        ServerDb::Postgres(db) => Ok(db
            .query_opt(
                "SELECT id FROM submissions WHERE content_hash = $1",
                &[&content_hash],
            )
            .await?
            .map(|row| row.get::<_, String>(0))),
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            connection
                .query_row(
                    "SELECT id FROM submissions WHERE content_hash = ?1",
                    [content_hash],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(Into::into)
        }
    }
}

async fn insert_submission(
    db: &ServerDb,
    install_id: &str,
    content_hash: &str,
    payload_hash: &str,
    received_at: DateTime<Utc>,
    remote_ip: &str,
    bundle_json: &Value,
) -> Result<String> {
    let submission_id = new_server_id();
    match db {
        ServerDb::Postgres(db) => {
            db.execute(
                "
            INSERT INTO submissions (id, install_id, content_hash, payload_hash, received_at, remote_addr, quarantined, bundle_json)
            VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7)
            ",
                &[
                    &submission_id,
                    &install_id,
                    &content_hash,
                    &payload_hash,
                    &received_at,
                    &remote_ip,
                    bundle_json,
                ],
            )
            .await?;
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            connection.execute(
                "
            INSERT INTO submissions (id, install_id, content_hash, payload_hash, received_at, remote_addr, quarantined, bundle_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)
            ",
                params![
                    submission_id,
                    install_id,
                    content_hash,
                    payload_hash,
                    received_at.to_rfc3339(),
                    remote_ip,
                    serde_json::to_string(bundle_json)?,
                ],
            )?;
        }
    }
    Ok(submission_id)
}

async fn mark_submission_received(
    db: &ServerDb,
    install_id: &str,
    received_at: DateTime<Utc>,
) -> Result<()> {
    match db {
        ServerDb::Postgres(db) => {
            db.execute(
                "
            UPDATE installs
            SET submission_count = submission_count + 1,
                last_seen = $2
            WHERE install_id = $1
            ",
                &[&install_id, &received_at],
            )
            .await?;
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            connection.execute(
                "
            UPDATE installs
            SET submission_count = submission_count + 1,
                last_seen = ?2
            WHERE install_id = ?1
            ",
                params![install_id, received_at.to_rfc3339()],
            )?;
        }
    }
    Ok(())
}

async fn is_issue_promoted(db: &ServerDb, issue_id: &str) -> Result<bool> {
    match db {
        ServerDb::Postgres(db) => Ok(db
            .query_one(
                "SELECT promoted FROM issue_clusters WHERE id = $1",
                &[&issue_id],
            )
            .await?
            .get(0)),
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let promoted: i64 = connection.query_row(
                "SELECT promoted FROM issue_clusters WHERE id = ?1",
                [issue_id],
                |row| row.get(0),
            )?;
            Ok(promoted != 0)
        }
    }
}

async fn bump_submission_trust(db: &ServerDb, install_id: &str) -> Result<()> {
    match db {
        ServerDb::Postgres(db) => {
            db.execute(
                "
                UPDATE installs
                SET submission_trust_score = submission_trust_score + 1
                WHERE install_id = $1
                ",
                &[&install_id],
            )
            .await?;
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            connection.execute(
                "
                UPDATE installs
                SET submission_trust_score = submission_trust_score + 1
                WHERE install_id = ?1
                ",
                [install_id],
            )?;
        }
    }
    Ok(())
}

async fn insert_worker_lease(
    db: &ServerDb,
    lease: &WorkLease,
    install_id: &str,
    cluster_id: &str,
    leased_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<()> {
    match db {
        ServerDb::Postgres(db) => {
            db.execute(
                "
            INSERT INTO worker_leases (id, cluster_id, install_id, state, leased_at, expires_at, work_json)
            VALUES ($1, $2, $3, 'leased', $4, $5, $6)
            ",
                &[
                    &lease.lease_id,
                    &cluster_id,
                    &install_id,
                    &leased_at,
                    &expires_at,
                    &serde_json::to_value(lease)?,
                ],
            )
            .await?;
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            connection.execute(
                "
            INSERT INTO worker_leases (id, cluster_id, install_id, state, leased_at, expires_at, work_json)
            VALUES (?1, ?2, ?3, 'leased', ?4, ?5, ?6)
            ",
                params![
                    lease.lease_id,
                    cluster_id,
                    install_id,
                    leased_at.to_rfc3339(),
                    expires_at.to_rfc3339(),
                    serde_json::to_string(lease)?,
                ],
            )?;
        }
    }
    Ok(())
}

async fn active_worker_lease(
    db: &ServerDb,
    lease_id: &str,
) -> Result<Option<(String, String, DateTime<Utc>)>> {
    match db {
        ServerDb::Postgres(db) => Ok(db
            .query_opt(
                "
            SELECT cluster_id, install_id, expires_at
            FROM worker_leases
            WHERE id = $1 AND state = 'leased'
            ",
                &[&lease_id],
            )
            .await?
            .map(|row| (row.get(0), row.get(1), row.get(2)))),
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let row = connection
                .query_row(
                    "
            SELECT cluster_id, install_id, expires_at
            FROM worker_leases
            WHERE id = ?1 AND state = 'leased'
            ",
                    [lease_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()?;
            Ok(row.and_then(|(cluster_id, install_id, expires_at)| {
                parse_timestamp(&expires_at).map(|ts| (cluster_id, install_id, ts))
            }))
        }
    }
}

async fn store_worker_result(
    db: &ServerDb,
    cluster_id: &str,
    result: &WorkerResultEnvelope,
) -> Result<()> {
    let successful_ready_result = result.attempt.state == "ready"
        && matches!(result.attempt.outcome.as_str(), "patch" | "triage");
    match db {
        ServerDb::Postgres(db) => {
            let patch_attempt_id = new_server_id();
            db.execute(
                "
            INSERT INTO patch_attempts (id, cluster_id, lease_id, install_id, outcome, state, summary, bundle_json, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ",
                &[
                    &patch_attempt_id,
                    &cluster_id,
                    &result.lease_id,
                    &result.attempt.install_id,
                    &result.attempt.outcome,
                    &result.attempt.state,
                    &result.attempt.summary,
                    &serde_json::to_value(result)?,
                    &Utc::now(),
                ],
            )
            .await?;
            db.execute(
                "
            UPDATE worker_leases
            SET state = 'completed'
            WHERE id = $1
            ",
                &[&result.lease_id],
            )
            .await?;
            refresh_issue_cluster_best_results(db, cluster_id).await?;
            if successful_ready_result {
                db.execute(
                    "
                UPDATE installs
                SET worker_trust_score = worker_trust_score + 1,
                    worker_result_count = worker_result_count + 1
                WHERE install_id = $1
                ",
                    &[&result.attempt.install_id],
                )
                .await?;
            }
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let patch_attempt_id = new_server_id();
            connection.execute(
                "
            INSERT INTO patch_attempts (id, cluster_id, lease_id, install_id, outcome, state, summary, bundle_json, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ",
                params![
                    patch_attempt_id,
                    cluster_id,
                    result.lease_id,
                    result.attempt.install_id,
                    result.attempt.outcome,
                    result.attempt.state,
                    result.attempt.summary,
                    serde_json::to_string(result)?,
                    Utc::now().to_rfc3339(),
                ],
            )?;
            connection.execute(
                "
            UPDATE worker_leases
            SET state = 'completed'
            WHERE id = ?1
            ",
                [result.lease_id.as_str()],
            )?;
            refresh_issue_cluster_best_results_sqlite(&connection, cluster_id)?;
            if successful_ready_result {
                connection.execute(
                    "
                UPDATE installs
                SET worker_trust_score = worker_trust_score + 1,
                    worker_result_count = worker_result_count + 1
                WHERE install_id = ?1
                ",
                    [result.attempt.install_id.as_str()],
                )?;
            }
        }
    }
    Ok(())
}

async fn store_submitted_proposal_result(
    db: &ServerDb,
    cluster_id: &str,
    result: &WorkerResultEnvelope,
) -> Result<()> {
    let mut submitted = canonicalize_worker_result_envelope(result.clone());
    submitted.lease_id.clear();
    submitted.attempt.cluster_id = cluster_id.to_string();
    match db {
        ServerDb::Postgres(db) => {
            let already_stored = db
                .query_opt(
                    "
                SELECT 1
                FROM patch_attempts
                WHERE cluster_id = $1
                  AND install_id = $2
                  AND outcome = $3
                  AND state = $4
                  AND created_at = $5
                LIMIT 1
                ",
                    &[
                        &cluster_id,
                        &submitted.attempt.install_id,
                        &submitted.attempt.outcome,
                        &submitted.attempt.state,
                        &parse_timestamp(&submitted.attempt.created_at).unwrap_or_else(Utc::now),
                    ],
                )
                .await?
                .is_some();
            if already_stored {
                return Ok(());
            }
            let patch_attempt_id = new_server_id();
            db.execute(
                "
            INSERT INTO patch_attempts (id, cluster_id, lease_id, install_id, outcome, state, summary, bundle_json, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ",
                &[
                    &patch_attempt_id,
                    &cluster_id,
                    &Option::<String>::None,
                    &submitted.attempt.install_id,
                    &submitted.attempt.outcome,
                    &submitted.attempt.state,
                    &submitted.attempt.summary,
                    &serde_json::to_value(&submitted)?,
                    &parse_timestamp(&submitted.attempt.created_at)
                        .unwrap_or_else(Utc::now),
                ],
            )
            .await?;
            refresh_issue_cluster_best_results(db, cluster_id).await?;
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let already_stored = connection
                .query_row(
                    "
                SELECT 1
                FROM patch_attempts
                WHERE cluster_id = ?1
                  AND install_id = ?2
                  AND outcome = ?3
                  AND state = ?4
                  AND created_at = ?5
                LIMIT 1
                ",
                    params![
                        cluster_id,
                        submitted.attempt.install_id,
                        submitted.attempt.outcome,
                        submitted.attempt.state,
                        submitted.attempt.created_at,
                    ],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if already_stored {
                return Ok(());
            }
            let patch_attempt_id = new_server_id();
            connection.execute(
                "
            INSERT INTO patch_attempts (id, cluster_id, lease_id, install_id, outcome, state, summary, bundle_json, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ",
                params![
                    patch_attempt_id,
                    cluster_id,
                    Option::<String>::None,
                    submitted.attempt.install_id,
                    submitted.attempt.outcome,
                    submitted.attempt.state,
                    submitted.attempt.summary,
                    serde_json::to_string(&submitted)?,
                    submitted.attempt.created_at.clone(),
                ],
            )?;
            refresh_issue_cluster_best_results_sqlite(&connection, cluster_id)?;
        }
    }
    Ok(())
}

fn compare_attempt_created_at(left: &PatchAttempt, right: &PatchAttempt) -> Ordering {
    parse_timestamp(&left.created_at)
        .cmp(&parse_timestamp(&right.created_at))
        .then_with(|| left.created_at.cmp(&right.created_at))
}

fn select_best_attempt(candidates: &[PatchAttempt], outcome: &str) -> Option<PatchAttempt> {
    candidates
        .iter()
        .filter(|attempt| attempt.state == "ready" && attempt.outcome == outcome)
        .cloned()
        .max_by(compare_attempt_created_at)
}

fn validation_quality_rank(attempt: &PatchAttempt) -> i32 {
    match attempt
        .details
        .get("validation_quality")
        .and_then(Value::as_str)
    {
        Some("passed") => 4,
        Some("partial") => 3,
        Some("blocked") => 2,
        Some("not-run") => 1,
        _ if attempt.validation_status.as_deref() == Some("ready") => 2,
        _ => 0,
    }
}

fn review_rounds_completed(attempt: &PatchAttempt) -> i64 {
    attempt
        .details
        .get("review_rounds_completed")
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

fn review_findings_resolved(attempt: &PatchAttempt) -> i64 {
    attempt
        .details
        .get("review_findings_resolved")
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

fn attempt_supersedes_patch(attempt: &PatchAttempt, patch: &PatchAttempt) -> bool {
    if !attempt
        .details
        .get("supersedes_best_patch")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return false;
    }
    if let Some(created_at) = attempt
        .details
        .get("supersedes_patch_created_at")
        .and_then(Value::as_str)
    {
        return created_at == patch.created_at;
    }
    compare_attempt_created_at(attempt, patch) != Ordering::Less
}

fn compare_patch_attempt_quality(left: &PatchAttempt, right: &PatchAttempt) -> Ordering {
    validation_quality_rank(left)
        .cmp(&validation_quality_rank(right))
        .then_with(|| review_findings_resolved(left).cmp(&review_findings_resolved(right)))
        .then_with(|| review_rounds_completed(left).cmp(&review_rounds_completed(right)))
        .then_with(|| compare_attempt_created_at(left, right))
}

fn attempt_invalidates_patch(attempt: &PatchAttempt, patch: &PatchAttempt) -> bool {
    if !attempt
        .details
        .get("invalidates_best_patch")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return false;
    }
    if let Some(created_at) = attempt
        .details
        .get("invalidates_patch_created_at")
        .and_then(Value::as_str)
    {
        return created_at == patch.created_at;
    }
    compare_attempt_created_at(attempt, patch) != Ordering::Less
}

fn select_best_patch_attempt(candidates: &[PatchAttempt]) -> Option<PatchAttempt> {
    let mut visible = candidates
        .iter()
        .filter(|attempt| attempt.state == "ready" && attempt.outcome == "patch")
        .filter(|patch| {
            !candidates
                .iter()
                .any(|attempt| attempt_invalidates_patch(attempt, patch))
        })
        .cloned()
        .collect::<Vec<_>>();
    if visible.is_empty() {
        return None;
    }
    let superseded_created_at = visible
        .iter()
        .filter_map(|patch| {
            visible
                .iter()
                .any(|other| {
                    other.created_at != patch.created_at && attempt_supersedes_patch(other, patch)
                })
                .then(|| patch.created_at.clone())
        })
        .collect::<std::collections::HashSet<_>>();
    visible.retain(|patch| !superseded_created_at.contains(&patch.created_at));
    visible
        .into_iter()
        .max_by(|left, right| compare_patch_attempt_quality(left, right))
}

fn repeated_workspace_blocked_triage_attempt(candidates: &[PatchAttempt]) -> Option<PatchAttempt> {
    let mut repeated_reports = candidates
        .iter()
        .filter(|attempt| {
            attempt.state == "ready"
                && attempt.outcome == "report"
                && !hidden_kernel_workspace_attempt(attempt)
                && attempt
                    .details
                    .get("report_only_reason")
                    .and_then(Value::as_str)
                    == Some("workspace-acquisition")
                && attempt
                    .details
                    .get("handoff")
                    .and_then(Value::as_object)
                    .is_some()
        })
        .cloned()
        .collect::<Vec<_>>();
    if repeated_reports.len() < 2 {
        return None;
    }
    repeated_reports.sort_by(compare_attempt_created_at);
    let mut attempt = repeated_reports.pop()?;
    attempt.outcome = "triage".to_string();
    attempt.summary =
        "A diagnosis report and external handoff were created locally because no patchable workspace was available.".to_string();
    if let Some(object) = attempt.details.as_object_mut() {
        object
            .entry("report_only_reason".to_string())
            .or_insert_with(|| json!("workspace-acquisition"));
    }
    Some(attempt)
}

fn best_attempts_from_candidates(
    candidates: Vec<PatchAttempt>,
) -> (Option<PatchAttempt>, Option<PatchAttempt>) {
    let candidates = candidates
        .into_iter()
        .filter(publicly_visible_attempt)
        .collect::<Vec<_>>();
    let best_triage = select_best_attempt(&candidates, "triage")
        .into_iter()
        .chain(repeated_workspace_blocked_triage_attempt(&candidates))
        .max_by(compare_attempt_created_at);
    (select_best_patch_attempt(&candidates), best_triage)
}

async fn load_latest_patch_context_for_worker(
    db: &ServerDb,
    cluster_id: &str,
) -> Result<Option<PatchAttempt>> {
    match db {
        ServerDb::Postgres(db) => {
            let rows = db
                .query(
                    "
                SELECT bundle_json
                FROM patch_attempts
                WHERE cluster_id = $1
                ORDER BY created_at DESC
                LIMIT 64
                ",
                    &[&cluster_id],
                )
                .await?;
            let candidates = rows
                .into_iter()
                .filter_map(|row| {
                    let bundle_json: Value = row.get(0);
                    serde_json::from_value::<WorkerResultEnvelope>(bundle_json)
                        .ok()
                        .map(canonicalize_worker_result_envelope)
                        .map(|envelope| envelope.attempt)
                        .filter(publicly_visible_attempt)
                })
                .collect::<Vec<_>>();
            Ok(select_best_attempt(&candidates, "patch"))
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let mut stmt = connection.prepare(
                "
                SELECT bundle_json
                FROM patch_attempts
                WHERE cluster_id = ?1
                ORDER BY created_at DESC
                LIMIT 64
                ",
            )?;
            let rows = stmt.query_map([cluster_id], |row| row.get::<_, String>(0))?;
            let candidates = rows
                .filter_map(|row| {
                    row.ok()
                        .and_then(|raw| serde_json::from_str::<WorkerResultEnvelope>(&raw).ok())
                        .map(canonicalize_worker_result_envelope)
                        .map(|envelope| envelope.attempt)
                        .filter(publicly_visible_attempt)
                })
                .collect::<Vec<_>>();
            Ok(select_best_attempt(&candidates, "patch"))
        }
    }
}

async fn refresh_issue_cluster_best_results(db: &Client, cluster_id: &str) -> Result<()> {
    let rows = db
        .query(
            "
        SELECT bundle_json
        FROM patch_attempts
        WHERE cluster_id = $1
        ",
            &[&cluster_id],
        )
        .await?;
    let candidates = rows
        .into_iter()
        .filter_map(|row| {
            let bundle_json: Value = row.get(0);
            serde_json::from_value::<WorkerResultEnvelope>(bundle_json)
                .ok()
                .map(canonicalize_worker_result_envelope)
                .map(|envelope| envelope.attempt)
                .filter(publicly_visible_attempt)
        })
        .collect::<Vec<_>>();
    let (best_patch, best_triage) = best_attempts_from_candidates(candidates);
    db.execute(
        "
        UPDATE issue_clusters
        SET best_patch_json = $2,
            best_triage_json = $3
        WHERE id = $1
        ",
        &[
            &cluster_id,
            &best_patch.as_ref().map(serde_json::to_value).transpose()?,
            &best_triage.as_ref().map(serde_json::to_value).transpose()?,
        ],
    )
    .await?;
    Ok(())
}

fn refresh_issue_cluster_best_results_sqlite(
    connection: &Connection,
    cluster_id: &str,
) -> Result<()> {
    let mut stmt = connection.prepare(
        "
        SELECT bundle_json
        FROM patch_attempts
        WHERE cluster_id = ?1
        ",
    )?;
    let rows = stmt.query_map([cluster_id], |row| row.get::<_, String>(0))?;
    let candidates = rows
        .filter_map(|row| {
            row.ok()
                .and_then(|raw| serde_json::from_str::<WorkerResultEnvelope>(&raw).ok())
                .map(canonicalize_worker_result_envelope)
                .map(|envelope| envelope.attempt)
                .filter(publicly_visible_attempt)
        })
        .collect::<Vec<_>>();
    let (best_patch, best_triage) = best_attempts_from_candidates(candidates);
    connection.execute(
        "
        UPDATE issue_clusters
        SET best_patch_json = ?2,
            best_triage_json = ?3
        WHERE id = ?1
        ",
        params![
            cluster_id,
            best_patch.as_ref().map(serde_json::to_string).transpose()?,
            best_triage
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
        ],
    )?;
    Ok(())
}

async fn store_evidence_request(
    db: &ServerDb,
    request: &crate::models::EvidenceUpgradeRequest,
) -> Result<()> {
    match db {
        ServerDb::Postgres(db) => {
            let request_id = new_server_id();
            db.execute(
                "
                INSERT INTO evidence_requests (id, issue_id, requested_by_install_id, reason, requested_fields_json, requested_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                ",
                &[
                    &request_id,
                    &request.issue_id,
                    &request.requested_by_install_id,
                    &request.reason,
                    &serde_json::to_value(&request.requested_fields)?,
                    &parse_timestamp(&request.requested_at).unwrap_or_else(Utc::now),
                ],
            )
            .await?;
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let request_id = new_server_id();
            connection.execute(
                "
                INSERT INTO evidence_requests (id, issue_id, requested_by_install_id, reason, requested_fields_json, requested_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ",
                params![
                    request_id,
                    request.issue_id,
                    request.requested_by_install_id,
                    request.reason,
                    serde_json::to_string(&request.requested_fields)?,
                    parse_timestamp(&request.requested_at)
                        .unwrap_or_else(Utc::now)
                        .to_rfc3339(),
                ],
            )?;
        }
    }
    Ok(())
}

async fn respond_evidence_request_storage(
    db: &ServerDb,
    id: &str,
    response: &Value,
) -> Result<bool> {
    match db {
        ServerDb::Postgres(db) => Ok(db
            .execute(
                "
            UPDATE evidence_requests
            SET response_json = $2
            WHERE id = $1
            ",
                &[&id, response],
            )
            .await?
            > 0),
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            Ok(connection.execute(
                "
            UPDATE evidence_requests
            SET response_json = ?2
            WHERE id = ?1
            ",
                params![id, serde_json::to_string(response)?],
            )? > 0)
        }
    }
}

async fn upsert_issue_cluster(
    db: &ServerDb,
    item: &SharedOpportunity,
    cluster_key: &str,
    submission_id: &str,
    install_id: &str,
    submission_trust: i64,
    config: &FixerConfig,
) -> Result<String> {
    let now = Utc::now();
    let representative_json = serde_json::to_value(item)?;
    let public_fields = build_public_issue_fields(item);
    let package_name = item.finding.package_name.clone();
    let source_package = inferred_public_source_package(item);
    match db {
        ServerDb::Postgres(db) => {
            let existing_id = db
                .query_opt(
                    "SELECT id FROM issue_clusters WHERE cluster_key = $1",
                    &[&cluster_key],
                )
                .await?
                .map(|row| row.get::<_, String>(0));
            let issue_id = if let Some(existing_id) = existing_id {
                db.execute(
                    "
            UPDATE issue_clusters
            SET title = $2,
                summary = $3,
                public_title = $4,
                public_summary = $5,
                public_visible = $6,
                package_name = COALESCE($7, package_name),
                source_package = COALESCE($8, source_package),
                ecosystem = COALESCE($9, ecosystem),
                severity = COALESCE($10, severity),
                score = GREATEST(score, $11),
                representative_json = CASE
                    WHEN $11 >= score THEN $12
                    ELSE representative_json
                END,
                last_seen = $13
            WHERE id = $1
            ",
                    &[
                        &existing_id,
                        &item.opportunity.title,
                        &item.opportunity.summary,
                        &public_fields.title,
                        &public_fields.summary,
                        &public_fields.visible,
                        &package_name,
                        &source_package,
                        &item.opportunity.ecosystem,
                        &Some(item.finding.severity.clone()),
                        &item.opportunity.score,
                        &representative_json,
                        &now,
                    ],
                )
                .await?;
                existing_id
            } else {
                let issue_id = new_server_id();
                db.execute(
                    "
            INSERT INTO issue_clusters
                (id, cluster_key, kind, title, summary, public_title, public_summary, public_visible,
                 package_name, source_package, ecosystem, severity, score, corroboration_count,
                 quarantined, promoted, representative_json, last_seen)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 0, TRUE, FALSE, $14, $15)
            ",
                    &[
                        &issue_id,
                        &cluster_key,
                        &item.opportunity.kind,
                        &item.opportunity.title,
                        &item.opportunity.summary,
                        &public_fields.title,
                        &public_fields.summary,
                        &public_fields.visible,
                        &package_name,
                        &source_package,
                        &item.opportunity.ecosystem,
                        &Some(item.finding.severity.clone()),
                        &item.opportunity.score,
                        &representative_json,
                        &now,
                    ],
                )
                .await?;
                issue_id
            };
            db.execute(
                "
        INSERT INTO cluster_reports (cluster_id, install_id, submission_id, created_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (cluster_id, install_id) DO NOTHING
        ",
                &[&issue_id, &install_id, &submission_id, &now],
            )
            .await?;
            let corroboration_count: i64 = db
                .query_one(
                    "
            SELECT COUNT(*) FROM cluster_reports WHERE cluster_id = $1
            ",
                    &[&issue_id],
                )
                .await?
                .get(0);
            let promoted = corroboration_count >= config.server.quarantine_corroboration_threshold
                || submission_trust >= config.server.quarantine_corroboration_threshold;
            db.execute(
                "
        UPDATE issue_clusters
        SET corroboration_count = $2,
            promoted = $3,
            quarantined = NOT $3
        WHERE id = $1
        ",
                &[&issue_id, &corroboration_count, &promoted],
            )
            .await?;
            Ok(issue_id)
        }
        ServerDb::Sqlite(path) => {
            let mut connection = sqlite_connection(path)?;
            let tx = connection.transaction()?;
            let existing_id = tx
                .query_row(
                    "SELECT id FROM issue_clusters WHERE cluster_key = ?1",
                    [cluster_key],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            let issue_id = if let Some(existing_id) = existing_id {
                tx.execute(
                    "
            UPDATE issue_clusters
            SET title = ?2,
                summary = ?3,
                public_title = ?4,
                public_summary = ?5,
                public_visible = ?6,
                package_name = COALESCE(?7, package_name),
                source_package = COALESCE(?8, source_package),
                ecosystem = COALESCE(?9, ecosystem),
                severity = COALESCE(?10, severity),
                score = MAX(score, ?11),
                representative_json = CASE
                    WHEN ?11 >= score THEN ?12
                    ELSE representative_json
                END,
                last_seen = ?13
            WHERE id = ?1
            ",
                    params![
                        existing_id,
                        item.opportunity.title,
                        item.opportunity.summary,
                        public_fields.title,
                        public_fields.summary,
                        public_fields.visible,
                        package_name,
                        source_package,
                        item.opportunity.ecosystem,
                        item.finding.severity,
                        item.opportunity.score,
                        serde_json::to_string(&representative_json)?,
                        now.to_rfc3339(),
                    ],
                )?;
                existing_id
            } else {
                let issue_id = new_server_id();
                tx.execute(
                    "
            INSERT INTO issue_clusters
                (id, cluster_key, kind, title, summary, public_title, public_summary, public_visible,
                 package_name, source_package, ecosystem, severity, score, corroboration_count,
                 quarantined, promoted, representative_json, last_seen)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0, 1, 0, ?14, ?15)
            ",
                    params![
                        issue_id,
                        cluster_key,
                        item.opportunity.kind,
                        item.opportunity.title,
                        item.opportunity.summary,
                        public_fields.title,
                        public_fields.summary,
                        public_fields.visible,
                        package_name,
                        source_package,
                        item.opportunity.ecosystem,
                        item.finding.severity,
                        item.opportunity.score,
                        serde_json::to_string(&representative_json)?,
                        now.to_rfc3339(),
                    ],
                )?;
                issue_id
            };
            tx.execute(
                "
        INSERT INTO cluster_reports (cluster_id, install_id, submission_id, created_at)
        VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(cluster_id, install_id) DO NOTHING
        ",
                params![issue_id, install_id, submission_id, now.to_rfc3339()],
            )?;
            let corroboration_count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM cluster_reports WHERE cluster_id = ?1",
                [issue_id.as_str()],
                |row| row.get(0),
            )?;
            let promoted = corroboration_count >= config.server.quarantine_corroboration_threshold
                || submission_trust >= config.server.quarantine_corroboration_threshold;
            tx.execute(
                "
        UPDATE issue_clusters
        SET corroboration_count = ?2,
            promoted = ?3,
            quarantined = CASE WHEN ?3 THEN 0 ELSE 1 END
        WHERE id = ?1
        ",
                params![issue_id, corroboration_count, promoted],
            )?;
            tx.commit()?;
            Ok(issue_id)
        }
    }
}

struct WorkerCandidate {
    issue: IssueCluster,
    has_foreign_reports: bool,
    last_attempt_at: Option<DateTime<Utc>>,
    last_attempt_model: Option<String>,
    latest_attempt: Option<PatchAttempt>,
}

async fn next_issue_for_worker(
    db: &ServerDb,
    worker_install_id: &str,
    worker_attempt_cooldown_seconds: u64,
    worker_model: Option<String>,
) -> Result<Option<IssueCluster>> {
    let candidate_limit: i64 = 256;
    match db {
        ServerDb::Postgres(db) => {
            let rows = db
                .query(
                    "
        SELECT id, cluster_key, kind, title, summary, package_name, source_package, ecosystem,
               severity, score, corroboration_count, quarantined, promoted, representative_json,
               best_patch_json, last_seen,
               EXISTS (
                    SELECT 1
                    FROM cluster_reports report
                    WHERE report.cluster_id = issue.id
                      AND report.install_id <> $1
               ) AS has_foreign_reports,
               (
                    SELECT MAX(attempt.created_at)
                    FROM patch_attempts attempt
                    WHERE attempt.cluster_id = issue.id
               ) AS last_attempt_at,
               (
                    SELECT bundle_json
                    FROM patch_attempts attempt
                    WHERE attempt.cluster_id = issue.id
                    ORDER BY attempt.created_at DESC
                    LIMIT 1
               ) AS latest_attempt_json
        FROM issue_clusters issue
        WHERE promoted = TRUE
          AND public_visible = TRUE
          AND best_triage_json IS NULL
          AND NOT EXISTS (
                SELECT 1
                FROM worker_leases lease
                WHERE lease.cluster_id = issue.id
                  AND lease.state = 'leased'
                  AND lease.expires_at > NOW()
          )
        ORDER BY score DESC, last_seen DESC
        LIMIT $2
        ",
                    &[&worker_install_id, &candidate_limit],
                )
                .await?;
            let candidates = rows
                .into_iter()
                .map(worker_candidate_from_row)
                .collect::<Result<Vec<_>>>()?;
            Ok(select_worker_candidate(
                candidates,
                worker_attempt_cooldown_seconds,
                worker_model.as_deref(),
            ))
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let now = Utc::now().to_rfc3339();
            let mut stmt = connection.prepare(
                "
        SELECT id, cluster_key, kind, title, summary, package_name, source_package, ecosystem,
               severity, score, corroboration_count, quarantined, promoted, representative_json,
               best_patch_json, last_seen,
               EXISTS (
                    SELECT 1
                    FROM cluster_reports report
                    WHERE report.cluster_id = issue.id
                      AND report.install_id <> ?1
               ) AS has_foreign_reports,
               (
                    SELECT MAX(attempt.created_at)
                    FROM patch_attempts attempt
                    WHERE attempt.cluster_id = issue.id
               ) AS last_attempt_at,
               (
                    SELECT bundle_json
                    FROM patch_attempts attempt
                    WHERE attempt.cluster_id = issue.id
                    ORDER BY attempt.created_at DESC
                    LIMIT 1
               ) AS latest_attempt_json
        FROM issue_clusters issue
        WHERE promoted = 1
          AND public_visible = 1
          AND best_triage_json IS NULL
          AND NOT EXISTS (
                SELECT 1
                FROM worker_leases lease
                WHERE lease.cluster_id = issue.id
                  AND lease.state = 'leased'
                  AND lease.expires_at > ?2
          )
        ORDER BY score DESC, last_seen DESC
        LIMIT ?3
        ",
            )?;
            let rows = stmt.query_map(
                params![worker_install_id, now.as_str(), candidate_limit],
                |row| {
                    let issue = issue_from_sqlite_row(row)?;
                    let has_foreign_reports = row.get::<_, i64>(16)? != 0;
                    let last_attempt_at = row
                        .get::<_, Option<String>>(17)?
                        .as_deref()
                        .and_then(parse_timestamp);
                    let latest_attempt = row
                        .get::<_, Option<String>>(18)?
                        .and_then(|raw| latest_attempt_from_json_str(&raw).ok());
                    let last_attempt_model = patch_attempt_model(issue.best_patch.as_ref());
                    Ok(WorkerCandidate {
                        issue,
                        has_foreign_reports,
                        last_attempt_at,
                        last_attempt_model,
                        latest_attempt,
                    })
                },
            )?;
            let candidates = rows.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(select_worker_candidate(
                candidates,
                worker_attempt_cooldown_seconds,
                worker_model.as_deref(),
            ))
        }
    }
}

fn candidate_model_differs(candidate: &WorkerCandidate, worker_model: Option<&str>) -> bool {
    match (worker_model, candidate.last_attempt_model.as_deref()) {
        (Some(wm), Some(lm)) => wm != lm,
        _ => false,
    }
}

fn select_worker_candidate(
    candidates: Vec<WorkerCandidate>,
    worker_attempt_cooldown_seconds: u64,
    worker_model: Option<&str>,
) -> Option<IssueCluster> {
    let cooldown_cutoff = (worker_attempt_cooldown_seconds > 0)
        .then(|| Utc::now() - Duration::seconds(worker_attempt_cooldown_seconds as i64));
    let mut sorted_candidates = candidates.iter().collect::<Vec<_>>();
    sorted_candidates.sort_by(compare_worker_candidate_priority);
    // Model-rotation tiers: prefer issues whose last attempt used a different model
    sorted_candidates
        .iter()
        .find(|candidate| {
            !candidate_is_in_recent_attempt_cooldown(candidate, cooldown_cutoff)
                && candidate.has_foreign_reports
                && candidate_needs_patch_refresh(candidate)
                && candidate_model_differs(candidate, worker_model)
        })
        .map(|candidate| candidate.issue.clone())
        .or_else(|| {
            sorted_candidates
                .iter()
                .find(|candidate| {
                    !candidate_is_in_recent_attempt_cooldown(candidate, cooldown_cutoff)
                        && candidate.has_foreign_reports
                        && issue_is_available_for_worker(&candidate.issue)
                        && candidate_model_differs(candidate, worker_model)
                })
                .map(|candidate| candidate.issue.clone())
        })
        .or_else(|| {
            sorted_candidates
                .iter()
                .find(|candidate| {
                    !candidate_is_in_recent_attempt_cooldown(candidate, cooldown_cutoff)
                        && candidate_needs_patch_refresh(candidate)
                        && candidate_model_differs(candidate, worker_model)
                })
                .map(|candidate| candidate.issue.clone())
        })
        .or_else(|| {
            sorted_candidates
                .iter()
                .find(|candidate| {
                    !candidate_is_in_recent_attempt_cooldown(candidate, cooldown_cutoff)
                        && issue_is_available_for_worker(&candidate.issue)
                        && candidate_model_differs(candidate, worker_model)
                })
                .map(|candidate| candidate.issue.clone())
        })
        // Fall through to standard tiers (same-model fallback for single-model deployments)
        .or_else(|| {
            sorted_candidates
                .iter()
                .find(|candidate| {
                    !candidate_is_in_recent_attempt_cooldown(candidate, cooldown_cutoff)
                        && candidate.has_foreign_reports
                        && candidate_needs_patch_refresh(candidate)
                })
                .map(|candidate| candidate.issue.clone())
        })
        .or_else(|| {
            sorted_candidates
                .iter()
                .find(|candidate| {
                    !candidate_is_in_recent_attempt_cooldown(candidate, cooldown_cutoff)
                        && candidate.has_foreign_reports
                        && issue_is_available_for_worker(&candidate.issue)
                })
                .map(|candidate| candidate.issue.clone())
        })
        .or_else(|| {
            sorted_candidates
                .iter()
                .find(|candidate| {
                    !candidate_is_in_recent_attempt_cooldown(candidate, cooldown_cutoff)
                        && candidate_needs_patch_refresh(candidate)
                })
                .map(|candidate| candidate.issue.clone())
        })
        .or_else(|| {
            sorted_candidates
                .iter()
                .find(|candidate| {
                    !candidate_is_in_recent_attempt_cooldown(candidate, cooldown_cutoff)
                        && issue_is_available_for_worker(&candidate.issue)
                })
                .map(|candidate| candidate.issue.clone())
        })
        .or_else(|| {
            sorted_candidates
                .iter()
                .filter(|candidate| {
                    candidate.has_foreign_reports && candidate_needs_patch_refresh(candidate)
                })
                .min_by(|left, right| compare_worker_candidate_attempt_age(*left, *right))
                .map(|candidate| candidate.issue.clone())
        })
        .or_else(|| {
            sorted_candidates
                .iter()
                .filter(|candidate| {
                    candidate.has_foreign_reports && issue_is_available_for_worker(&candidate.issue)
                })
                .min_by(|left, right| compare_worker_candidate_attempt_age(*left, *right))
                .map(|candidate| candidate.issue.clone())
        })
        .or_else(|| {
            sorted_candidates
                .iter()
                .filter(|candidate| candidate_needs_patch_refresh(candidate))
                .min_by(|left, right| compare_worker_candidate_attempt_age(*left, *right))
                .map(|candidate| candidate.issue.clone())
        })
        .or_else(|| {
            sorted_candidates
                .iter()
                .filter(|candidate| issue_is_available_for_worker(&candidate.issue))
                .min_by(|left, right| compare_worker_candidate_attempt_age(*left, *right))
                .map(|candidate| candidate.issue.clone())
        })
}

fn compare_worker_candidate_priority(
    left: &&WorkerCandidate,
    right: &&WorkerCandidate,
) -> Ordering {
    compare_issue_priority_for_representatives(
        &left.issue.kind,
        left.issue.package_name.as_deref(),
        left.issue.source_package.as_deref(),
        left.issue.score,
        left.issue.corroboration_count,
        left.issue.best_patch.is_some(),
        false,
        &left.issue.last_seen,
        &left.issue.representative,
        &right.issue.kind,
        right.issue.package_name.as_deref(),
        right.issue.source_package.as_deref(),
        right.issue.score,
        right.issue.corroboration_count,
        right.issue.best_patch.is_some(),
        false,
        &right.issue.last_seen,
        &right.issue.representative,
    )
    .then_with(|| compare_worker_candidate_attempt_age(left, right))
}

fn compare_worker_candidate_attempt_age(
    left: &&WorkerCandidate,
    right: &&WorkerCandidate,
) -> Ordering {
    match (&left.last_attempt_at, &right.last_attempt_at) {
        (Some(left), Some(right)) => left.cmp(right),
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn candidate_is_in_recent_attempt_cooldown(
    candidate: &WorkerCandidate,
    cooldown_cutoff: Option<DateTime<Utc>>,
) -> bool {
    if let (Some(last_attempt_at), Some(latest_attempt)) =
        (candidate.last_attempt_at, candidate.latest_attempt.as_ref())
    {
        if let Some(seconds) = attempt_blocker_cooldown_seconds(latest_attempt) {
            let blocker_cutoff = Utc::now() - Duration::seconds(seconds as i64);
            if last_attempt_at >= blocker_cutoff {
                return true;
            }
        }
    }
    let Some(cooldown_cutoff) = cooldown_cutoff else {
        return false;
    };
    candidate
        .last_attempt_at
        .map(|attempted_at| attempted_at >= cooldown_cutoff)
        .unwrap_or(false)
}

fn candidate_needs_patch_refresh(candidate: &WorkerCandidate) -> bool {
    candidate
        .issue
        .best_patch
        .as_ref()
        .is_some_and(patch_attempt_needs_worker_refresh)
}

fn issue_is_available_for_worker(issue: &IssueCluster) -> bool {
    match issue.best_patch.as_ref() {
        None => true,
        Some(best_patch) => patch_attempt_needs_worker_refresh(best_patch),
    }
}

fn patch_attempt_needs_worker_refresh(attempt: &PatchAttempt) -> bool {
    if attempt.state != "ready" || attempt.outcome != "patch" {
        return false;
    }
    match patch_attempt_fixer_version(attempt) {
        Some(version) => is_binary_upgrade_available(version, current_binary_version()),
        None => true,
    }
}

fn patch_attempt_fixer_version(attempt: &PatchAttempt) -> Option<&str> {
    attempt
        .details
        .get("worker_fixer_version")
        .and_then(Value::as_str)
        .or_else(|| attempt.details.get("fixer_version").and_then(Value::as_str))
}

fn normalize_attempt_text(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn attempt_blocker_reason_from_summary(summary: &str) -> Option<String> {
    let summary = normalize_attempt_text(summary);
    if let Some(rest) = summary.strip_prefix("Worker could not make a safe patch: ") {
        return Some(rest.to_string());
    }
    if let Some((_, rest)) = summary.rsplit_once(": ") {
        if summary.contains("patch attempt failed to run cleanly") {
            return Some(rest.to_string());
        }
    }
    if summary.ends_with("patch proposal did not complete cleanly.") {
        return Some("patch proposal did not complete cleanly".to_string());
    }
    None
}

fn attempt_blocker_reason(attempt: &PatchAttempt) -> Option<String> {
    for key in [
        "report_only_reason",
        "patch_failure_kind",
        "workspace_failure_kind",
        "patch_refresh_failure_kind",
    ] {
        if let Some(reason) = attempt
            .details
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(reason.to_string());
        }
    }
    if let Some(reason) = attempt
        .details
        .get("handoff")
        .and_then(|value| value.get("reason"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(reason.to_string());
    }
    attempt_blocker_reason_from_summary(&attempt.summary)
}

fn attempt_blocker_cooldown_seconds(attempt: &PatchAttempt) -> Option<u64> {
    match attempt_blocker_reason(attempt).as_deref() {
        Some("codex-auth-unavailable") => Some(60 * 60),
        Some("workspace-acquisition") => Some(30 * 60),
        Some("review") => Some(20 * 60),
        Some("api") | Some("execution") | Some("auth") | Some("rate-limit") => Some(15 * 60),
        _ => None,
    }
}

fn build_public_attempt_summary(attempts: &[PublicAttempt]) -> PublicAttemptSummary {
    let mut summary = PublicAttemptSummary {
        total_attempt_count: attempts.len(),
        ..PublicAttemptSummary::default()
    };
    let mut blocker_counts = HashMap::<String, usize>::new();
    for attempt in attempts {
        match (attempt.outcome.as_str(), attempt.state.as_str()) {
            ("patch", "ready") => summary.ready_patch_count += 1,
            ("triage", "ready") => summary.ready_triage_count += 1,
            ("report", "ready") => summary.ready_report_count += 1,
            ("patch", "failed") => summary.failed_patch_count += 1,
            ("impossible", "explained") => summary.explained_impossible_count += 1,
            _ => summary.other_attempt_count += 1,
        }
        if let Some(label) = attempt.blocker_reason.as_deref() {
            *blocker_counts.entry(label.to_string()).or_default() += 1;
        }
    }
    let mut top_blockers = blocker_counts
        .into_iter()
        .map(|(label, count)| PublicAttemptBlocker { label, count })
        .collect::<Vec<_>>();
    top_blockers.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.label.cmp(&right.label))
    });
    top_blockers.truncate(5);
    summary.top_blockers = top_blockers;
    summary
}

async fn load_public_attempt_totals(db: &ServerDb) -> Result<(i64, i64, i64), ApiError> {
    let mut ready_report_count = 0_i64;
    let mut failed_patch_attempt_count = 0_i64;
    let mut explained_impossible_count = 0_i64;
    match db {
        ServerDb::Postgres(client) => {
            let rows = client
                .query(
                    "
                SELECT pa.bundle_json
                FROM patch_attempts pa
                JOIN issue_clusters ic ON ic.id = pa.cluster_id
                WHERE ic.promoted = TRUE
                  AND ic.public_visible = TRUE
                ",
                    &[],
                )
                .await
                .map_err(ApiError::internal)?;
            for row in rows {
                let raw: Value = row.get(0);
                let envelope = serde_json::from_value::<WorkerResultEnvelope>(raw)
                    .map_err(ApiError::internal)?;
                let attempt = canonicalize_worker_result_envelope(envelope).attempt;
                if !publicly_visible_attempt(&attempt) {
                    continue;
                }
                match (attempt.outcome.as_str(), attempt.state.as_str()) {
                    ("report", "ready") => ready_report_count += 1,
                    ("patch", "failed") => failed_patch_attempt_count += 1,
                    ("impossible", "explained") => explained_impossible_count += 1,
                    _ => {}
                }
            }
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path).map_err(ApiError::internal)?;
            let mut stmt = connection
                .prepare(
                    "
                SELECT pa.bundle_json
                FROM patch_attempts pa
                JOIN issue_clusters ic ON ic.id = pa.cluster_id
                WHERE ic.promoted = 1
                  AND ic.public_visible = 1
                ",
                )
                .map_err(ApiError::internal)?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(ApiError::internal)?;
            for row in rows {
                let raw = row.map_err(ApiError::internal)?;
                let envelope = serde_json::from_str::<WorkerResultEnvelope>(&raw)
                    .map_err(ApiError::internal)?;
                let attempt = canonicalize_worker_result_envelope(envelope).attempt;
                if !publicly_visible_attempt(&attempt) {
                    continue;
                }
                match (attempt.outcome.as_str(), attempt.state.as_str()) {
                    ("report", "ready") => ready_report_count += 1,
                    ("patch", "failed") => failed_patch_attempt_count += 1,
                    ("impossible", "explained") => explained_impossible_count += 1,
                    _ => {}
                }
            }
        }
    }
    Ok((
        ready_report_count,
        failed_patch_attempt_count,
        explained_impossible_count,
    ))
}

fn issue_from_row(row: Row) -> Result<IssueCluster> {
    let representative: SharedOpportunity = serde_json::from_value(row.get::<_, Value>(13))?;
    let best_patch = row
        .get::<_, Option<Value>>(14)
        .map(serde_json::from_value::<PatchAttempt>)
        .transpose()?;
    let last_seen: DateTime<Utc> = row.get(15);
    Ok(IssueCluster {
        id: row.get(0),
        cluster_key: row.get(1),
        kind: row.get(2),
        title: row.get(3),
        summary: row.get(4),
        package_name: row.get(5),
        source_package: row.get(6),
        ecosystem: row.get(7),
        severity: row.get(8),
        score: row.get(9),
        corroboration_count: row.get(10),
        quarantined: row.get(11),
        promoted: row.get(12),
        representative,
        best_patch,
        last_seen: last_seen.to_rfc3339(),
    })
}

fn worker_candidate_from_row(row: Row) -> Result<WorkerCandidate> {
    let has_foreign_reports: bool = row.get(16);
    let last_attempt_at: Option<DateTime<Utc>> = row.get(17);
    let latest_attempt = row
        .get::<_, Option<Value>>(18)
        .map(latest_attempt_from_json_value)
        .transpose()?;
    let issue = issue_from_row(row)?;
    let last_attempt_model = patch_attempt_model(latest_attempt.as_ref())
        .or_else(|| patch_attempt_model(issue.best_patch.as_ref()));
    Ok(WorkerCandidate {
        issue,
        has_foreign_reports,
        last_attempt_at,
        last_attempt_model,
        latest_attempt,
    })
}

fn latest_attempt_from_json_value(raw: Value) -> Result<PatchAttempt> {
    Ok(
        canonicalize_worker_result_envelope(serde_json::from_value::<WorkerResultEnvelope>(raw)?)
            .attempt,
    )
}

fn latest_attempt_from_json_str(raw: &str) -> Result<PatchAttempt> {
    Ok(
        canonicalize_worker_result_envelope(serde_json::from_str::<WorkerResultEnvelope>(raw)?)
            .attempt,
    )
}

fn patch_attempt_model(attempt: Option<&PatchAttempt>) -> Option<String> {
    attempt
        .and_then(|a| a.details.get("worker_model"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn issue_from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<IssueCluster> {
    let representative: SharedOpportunity =
        serde_json::from_str::<SharedOpportunity>(&row.get::<_, String>(13)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                13,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    let best_patch = row
        .get::<_, Option<String>>(14)?
        .map(|value| serde_json::from_str::<PatchAttempt>(&value))
        .transpose()
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                14,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    Ok(IssueCluster {
        id: row.get(0)?,
        cluster_key: row.get(1)?,
        kind: row.get(2)?,
        title: row.get(3)?,
        summary: row.get(4)?,
        package_name: row.get(5)?,
        source_package: row.get(6)?,
        ecosystem: row.get(7)?,
        severity: row.get(8)?,
        score: row.get(9)?,
        corroboration_count: row.get(10)?,
        quarantined: row.get::<_, i64>(11)? != 0,
        promoted: row.get::<_, i64>(12)? != 0,
        representative,
        best_patch,
        last_seen: row.get(15)?,
    })
}

async fn load_dashboard_snapshot(db: &ServerDb) -> Result<DashboardSnapshot, ApiError> {
    match db {
        ServerDb::Postgres(client) => {
            let row = client
                .query_one(
                    "
            SELECT
                (SELECT COUNT(*) FROM installs),
                (SELECT COUNT(*) FROM submissions),
                (SELECT COUNT(*) FROM issue_clusters WHERE promoted = TRUE),
                (SELECT COUNT(*) FROM issue_clusters WHERE promoted = FALSE),
                (SELECT COUNT(*) FROM issue_clusters WHERE best_patch_json IS NOT NULL),
                (SELECT COUNT(*) FROM issue_clusters WHERE best_patch_json IS NULL AND best_triage_json IS NOT NULL),
                (SELECT COUNT(*) FROM issue_clusters WHERE promoted = TRUE AND public_visible = TRUE AND corroboration_count >= 2),
                (SELECT COALESCE(MAX(corroboration_count), 0) FROM issue_clusters WHERE promoted = TRUE AND public_visible = TRUE),
                (SELECT MAX(received_at) FROM submissions)
            ",
                    &[],
                )
                .await
                .map_err(ApiError::internal)?;
            let (ready_report_count, failed_patch_attempt_count, explained_impossible_count) =
                load_public_attempt_totals(db).await?;
            let last_submission_at = row
                .get::<_, Option<DateTime<Utc>>>(8)
                .map(|value| value.to_rfc3339());
            Ok(DashboardSnapshot {
                install_count: row.get(0),
                submission_count: row.get(1),
                promoted_issue_count: row.get(2),
                quarantined_issue_count: row.get(3),
                ready_patch_count: row.get(4),
                ready_triage_count: row.get(5),
                ready_report_count,
                failed_patch_attempt_count,
                explained_impossible_count,
                corroborated_public_issue_count: row.get(6),
                largest_public_cluster_size: row.get(7),
                last_submission_at,
                top_issues: load_public_issue_candidates(db, 8).await?,
            })
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path).map_err(ApiError::internal)?;
            let install_count: i64 = connection
                .query_row("SELECT COUNT(*) FROM installs", [], |row| row.get(0))
                .map_err(ApiError::internal)?;
            let submission_count: i64 = connection
                .query_row("SELECT COUNT(*) FROM submissions", [], |row| row.get(0))
                .map_err(ApiError::internal)?;
            let promoted_issue_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM issue_clusters WHERE promoted = 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(ApiError::internal)?;
            let quarantined_issue_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM issue_clusters WHERE promoted = 0",
                    [],
                    |row| row.get(0),
                )
                .map_err(ApiError::internal)?;
            let ready_patch_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM issue_clusters WHERE best_patch_json IS NOT NULL",
                    [],
                    |row| row.get(0),
                )
                .map_err(ApiError::internal)?;
            let ready_triage_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM issue_clusters WHERE best_patch_json IS NULL AND best_triage_json IS NOT NULL",
                    [],
                    |row| row.get(0),
                )
                .map_err(ApiError::internal)?;
            let corroborated_public_issue_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM issue_clusters WHERE promoted = 1 AND public_visible = 1 AND corroboration_count >= 2",
                    [],
                    |row| row.get(0),
                )
                .map_err(ApiError::internal)?;
            let (ready_report_count, failed_patch_attempt_count, explained_impossible_count) =
                load_public_attempt_totals(db).await?;
            let largest_public_cluster_size: i64 = connection
                .query_row(
                    "SELECT COALESCE(MAX(corroboration_count), 0) FROM issue_clusters WHERE promoted = 1 AND public_visible = 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(ApiError::internal)?;
            let last_submission_at = connection
                .query_row("SELECT MAX(received_at) FROM submissions", [], |row| {
                    row.get::<_, Option<String>>(0)
                })
                .optional()
                .map_err(ApiError::internal)?
                .flatten();
            Ok(DashboardSnapshot {
                install_count,
                submission_count,
                promoted_issue_count,
                quarantined_issue_count,
                ready_patch_count,
                ready_triage_count,
                ready_report_count,
                failed_patch_attempt_count,
                explained_impossible_count,
                corroborated_public_issue_count,
                largest_public_cluster_size,
                last_submission_at,
                top_issues: load_public_issue_candidates(db, 8).await?,
            })
        }
    }
}

async fn load_public_issues(db: &ServerDb, limit: i64) -> Result<Vec<PublicIssue>, ApiError> {
    let issues = load_public_issue_candidates(db, limit).await?;
    Ok(issues.into_iter().map(|entry| entry.issue).collect())
}

async fn load_public_issue_candidates(
    db: &ServerDb,
    limit: i64,
) -> Result<Vec<PublicIssueCandidate>, ApiError> {
    let fetch_limit = (limit.max(32) * 4).clamp(64, 512);
    match db {
        ServerDb::Postgres(db) => {
            let rows = db
                .query(
                    "
            SELECT id, kind, public_title, public_summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count,
                   (best_patch_json IS NOT NULL) AS best_patch_available,
                   (best_triage_json IS NOT NULL) AS best_triage_available,
                   last_seen, representative_json
            FROM issue_clusters
            WHERE promoted = TRUE AND public_visible = TRUE
            ORDER BY score DESC, last_seen DESC
            LIMIT $1
            ",
                    &[&fetch_limit],
                )
                .await
                .map_err(ApiError::internal)?;
            let mut issues = rows
                .into_iter()
                .map(public_issue_candidate_from_row)
                .collect::<Result<Vec<_>, _>>()?;
            issues.sort_by(compare_public_issue_priority);
            issues.truncate(limit.max(0) as usize);
            Ok(issues)
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path).map_err(ApiError::internal)?;
            let mut stmt = connection
                .prepare(
                    "
            SELECT id, kind, public_title, public_summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count,
                   (best_patch_json IS NOT NULL) AS best_patch_available,
                   (best_triage_json IS NOT NULL) AS best_triage_available,
                   last_seen, representative_json
            FROM issue_clusters
            WHERE promoted = 1 AND public_visible = 1
            ORDER BY score DESC, last_seen DESC
            LIMIT ?1
            ",
                )
                .map_err(ApiError::internal)?;
            let rows = stmt
                .query_map([fetch_limit], public_issue_candidate_from_sqlite_row)
                .map_err(ApiError::internal)?;
            let mut issues = rows
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(ApiError::internal)?;
            issues.sort_by(compare_public_issue_priority);
            issues.truncate(limit.max(0) as usize);
            Ok(issues)
        }
    }
}

async fn load_public_issue_detail(
    db: &ServerDb,
    id: String,
    show_all_attempts: bool,
) -> Result<PublicIssueDetail, ApiError> {
    let candidate = load_duplicate_candidate_by_id(db, &id).await?;
    let technical_snapshot = build_public_technical_snapshot(&candidate.representative);
    let issue = candidate.issue;
    let best_patch = load_public_issue_best_patch(db, &id).await?;
    let best_triage = if best_patch.is_some() {
        None
    } else {
        load_public_issue_best_triage(db, &id).await?
    };
    let best_patch_diff_url = public_best_patch_diff_url(&id, best_patch.as_ref());
    let possible_duplicates = load_possible_duplicates(db, &id, &issue, 6).await?;
    let all_attempts = load_public_attempts(db, &id, 1024).await?;
    let attempt_summary = build_public_attempt_summary(&all_attempts);
    let displayed_attempt_count = if show_all_attempts { 1024 } else { 25 };
    let attempts_omitted_count = all_attempts.len().saturating_sub(displayed_attempt_count);
    let attempts = all_attempts
        .into_iter()
        .take(displayed_attempt_count)
        .collect();
    Ok(PublicIssueDetail {
        id: issue.id,
        kind: issue.kind,
        title: issue.title,
        summary: issue.summary,
        package_name: issue.package_name,
        source_package: issue.source_package,
        ecosystem: issue.ecosystem,
        severity: issue.severity,
        score: issue.score,
        corroboration_count: issue.corroboration_count,
        best_patch_available: issue.best_patch_available,
        best_triage_available: issue.best_triage_available && best_patch.is_none(),
        best_patch_diff_url,
        best_patch,
        best_triage_handoff: best_triage
            .as_ref()
            .and_then(|attempt| attempt.handoff.clone()),
        best_triage,
        last_seen: issue.last_seen,
        technical_snapshot,
        possible_duplicates,
        attempt_summary,
        attempts_omitted_count,
        attempts,
        showing_all_attempts: show_all_attempts,
    })
}

async fn load_possible_duplicates(
    db: &ServerDb,
    id: &str,
    issue: &PublicIssue,
    limit: usize,
) -> Result<Vec<PublicPossibleDuplicate>, ApiError> {
    let target = load_duplicate_candidate_by_id(db, id).await?;
    let target_features = duplicate_match_features(&target.issue, &target.representative);
    let candidates = load_duplicate_candidates(db, &issue.kind, id, 256).await?;
    let mut matches = candidates
        .into_iter()
        .filter_map(|candidate| build_possible_duplicate(&target_features, candidate))
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| {
        right
            .similarity_score
            .partial_cmp(&left.similarity_score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| right.corroboration_count.cmp(&left.corroboration_count))
            .then_with(|| parse_timestamp(&right.last_seen).cmp(&parse_timestamp(&left.last_seen)))
    });
    matches.truncate(limit);
    Ok(matches)
}

async fn load_duplicate_candidate_by_id(
    db: &ServerDb,
    id: &str,
) -> Result<DuplicateCandidateIssue, ApiError> {
    match db {
        ServerDb::Postgres(db) => {
            let row = db
                .query_opt(
                    "
            SELECT id, kind, public_title, public_summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count,
                   (best_patch_json IS NOT NULL) AS best_patch_available,
                   (best_triage_json IS NOT NULL) AS best_triage_available,
                   last_seen, representative_json
            FROM issue_clusters
            WHERE id = $1 AND promoted = TRUE AND public_visible = TRUE
            ",
                    &[&id],
                )
                .await
                .map_err(ApiError::internal)?;
            let Some(row) = row else {
                return Err(ApiError::new(StatusCode::NOT_FOUND, "issue not found"));
            };
            duplicate_candidate_from_row(row)
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path).map_err(ApiError::internal)?;
            connection
                .query_row(
                    "
            SELECT id, kind, public_title, public_summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count,
                   (best_patch_json IS NOT NULL) AS best_patch_available,
                   (best_triage_json IS NOT NULL) AS best_triage_available,
                   last_seen, representative_json
            FROM issue_clusters
            WHERE id = ?1 AND promoted = 1 AND public_visible = 1
            ",
                    [id],
                    duplicate_candidate_from_sqlite_row,
                )
                .optional()
                .map_err(ApiError::internal)?
                .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "issue not found"))
        }
    }
}

async fn load_duplicate_candidates(
    db: &ServerDb,
    kind: &str,
    exclude_id: &str,
    limit: i64,
) -> Result<Vec<DuplicateCandidateIssue>, ApiError> {
    match db {
        ServerDb::Postgres(db) => {
            let rows = db
                .query(
                    "
            SELECT id, kind, public_title, public_summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count,
                   (best_patch_json IS NOT NULL) AS best_patch_available,
                   (best_triage_json IS NOT NULL) AS best_triage_available,
                   last_seen, representative_json
            FROM issue_clusters
            WHERE promoted = TRUE
              AND public_visible = TRUE
              AND kind = $1
              AND id <> $2
            ORDER BY score DESC, last_seen DESC
            LIMIT $3
            ",
                    &[&kind, &exclude_id, &limit],
                )
                .await
                .map_err(ApiError::internal)?;
            rows.into_iter().map(duplicate_candidate_from_row).collect()
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path).map_err(ApiError::internal)?;
            let mut stmt = connection
                .prepare(
                    "
            SELECT id, kind, public_title, public_summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count,
                   (best_patch_json IS NOT NULL) AS best_patch_available,
                   (best_triage_json IS NOT NULL) AS best_triage_available,
                   last_seen, representative_json
            FROM issue_clusters
            WHERE promoted = 1
              AND public_visible = 1
              AND kind = ?1
              AND id <> ?2
            ORDER BY score DESC, last_seen DESC
            LIMIT ?3
            ",
                )
                .map_err(ApiError::internal)?;
            let rows = stmt
                .query_map(
                    params![kind, exclude_id, limit],
                    duplicate_candidate_from_sqlite_row,
                )
                .map_err(ApiError::internal)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(ApiError::internal)
        }
    }
}

async fn load_public_issue_best_patch(
    db: &ServerDb,
    id: &str,
) -> Result<Option<PublicAttempt>, ApiError> {
    match db {
        ServerDb::Postgres(db) => {
            let row = db
                .query_opt(
                    "
            SELECT best_patch_json
            FROM issue_clusters
            WHERE id = $1
              AND promoted = TRUE
              AND public_visible = TRUE
              AND best_patch_json IS NOT NULL
            ",
                    &[&id],
                )
                .await
                .map_err(ApiError::internal)?;
            row.map(|row| {
                let best_patch_json: Value = row.get(0);
                serde_json::from_value::<PatchAttempt>(best_patch_json)
                    .map(public_attempt_from_patch_attempt)
                    .map_err(ApiError::internal)
            })
            .transpose()
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path).map_err(ApiError::internal)?;
            connection
                .query_row(
                    "
            SELECT best_patch_json
            FROM issue_clusters
            WHERE id = ?1
              AND promoted = 1
              AND public_visible = 1
              AND best_patch_json IS NOT NULL
            ",
                    [id],
                    |row| {
                        let best_patch =
                            serde_json::from_str::<PatchAttempt>(&row.get::<_, String>(0)?)
                                .map(public_attempt_from_patch_attempt)
                                .map_err(|error| {
                                    rusqlite::Error::FromSqlConversionFailure(
                                        0,
                                        rusqlite::types::Type::Text,
                                        Box::new(error),
                                    )
                                })?;
                        Ok(best_patch)
                    },
                )
                .optional()
                .map_err(ApiError::internal)
        }
    }
}

async fn load_public_issue_best_triage(
    db: &ServerDb,
    id: &str,
) -> Result<Option<PublicAttempt>, ApiError> {
    match db {
        ServerDb::Postgres(db) => {
            let row = db
                .query_opt(
                    "
            SELECT best_triage_json
            FROM issue_clusters
            WHERE id = $1
              AND promoted = TRUE
              AND public_visible = TRUE
              AND best_triage_json IS NOT NULL
            ",
                    &[&id],
                )
                .await
                .map_err(ApiError::internal)?;
            row.map(|row| {
                let best_triage_json: Value = row.get(0);
                serde_json::from_value::<PatchAttempt>(best_triage_json)
                    .map(|attempt| {
                        (!hidden_kernel_workspace_attempt(&attempt))
                            .then(|| public_attempt_from_patch_attempt(attempt))
                    })
                    .map_err(ApiError::internal)
            })
            .transpose()
            .map(Option::flatten)
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path).map_err(ApiError::internal)?;
            connection
                .query_row(
                    "
            SELECT best_triage_json
            FROM issue_clusters
            WHERE id = ?1
              AND promoted = 1
              AND public_visible = 1
              AND best_triage_json IS NOT NULL
            ",
                    [id],
                    |row| {
                        let best_triage =
                            serde_json::from_str::<PatchAttempt>(&row.get::<_, String>(0)?)
                                .map(|attempt| {
                                    (!hidden_kernel_workspace_attempt(&attempt))
                                        .then(|| public_attempt_from_patch_attempt(attempt))
                                })
                                .map_err(|error| {
                                    rusqlite::Error::FromSqlConversionFailure(
                                        0,
                                        rusqlite::types::Type::Text,
                                        Box::new(error),
                                    )
                                })?;
                        Ok(best_triage)
                    },
                )
                .optional()
                .map_err(ApiError::internal)
                .map(Option::flatten)
        }
    }
}

async fn load_public_patches(db: &ServerDb, limit: i64) -> Result<Vec<PublicPatchEntry>, ApiError> {
    let mut patches = match db {
        ServerDb::Postgres(db) => {
            let rows = db
                .query(
                    "
            SELECT id, kind, public_title, public_summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count, best_patch_json, last_seen
            FROM issue_clusters
            WHERE promoted = TRUE
              AND public_visible = TRUE
              AND best_patch_json IS NOT NULL
            ORDER BY last_seen DESC, score DESC
            LIMIT $1
            ",
                    &[&limit],
                )
                .await
                .map_err(ApiError::internal)?;
            rows.into_iter()
                .map(public_patch_from_row)
                .collect::<Result<Vec<_>, _>>()?
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path).map_err(ApiError::internal)?;
            let mut stmt = connection
                .prepare(
                    "
            SELECT id, kind, public_title, public_summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count, best_patch_json, last_seen
            FROM issue_clusters
            WHERE promoted = 1
              AND public_visible = 1
              AND best_patch_json IS NOT NULL
            ORDER BY last_seen DESC, score DESC
            LIMIT ?1
            ",
                )
                .map_err(ApiError::internal)?;
            let rows = stmt
                .query_map([limit], public_patch_from_sqlite_row)
                .map_err(ApiError::internal)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(ApiError::internal)?
        }
    };
    patches.sort_by(|left, right| {
        parse_timestamp(&right.best_patch.created_at)
            .cmp(&parse_timestamp(&left.best_patch.created_at))
            .then_with(|| right.score.cmp(&left.score))
    });
    Ok(patches)
}

async fn load_public_triage(db: &ServerDb, limit: i64) -> Result<Vec<PublicTriageEntry>, ApiError> {
    let mut triage = match db {
        ServerDb::Postgres(db) => {
            let rows = db
                .query(
                    "
            SELECT id, kind, public_title, public_summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count, best_triage_json, last_seen
            FROM issue_clusters
            WHERE promoted = TRUE
              AND public_visible = TRUE
              AND best_patch_json IS NULL
              AND best_triage_json IS NOT NULL
            ORDER BY last_seen DESC, score DESC
            LIMIT $1
            ",
                    &[&limit],
                )
                .await
                .map_err(ApiError::internal)?;
            rows.into_iter()
                .filter_map(|row| public_triage_from_row(row).transpose())
                .collect::<Result<Vec<_>, _>>()?
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path).map_err(ApiError::internal)?;
            let mut stmt = connection
                .prepare(
                    "
            SELECT id, kind, public_title, public_summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count, best_triage_json, last_seen
            FROM issue_clusters
            WHERE promoted = 1
              AND public_visible = 1
              AND best_patch_json IS NULL
              AND best_triage_json IS NOT NULL
            ORDER BY last_seen DESC, score DESC
            LIMIT ?1
            ",
                )
                .map_err(ApiError::internal)?;
            let rows = stmt
                .query_map([limit], public_triage_from_sqlite_row)
                .map_err(ApiError::internal)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(ApiError::internal)?
                .into_iter()
                .flatten()
                .collect()
        }
    };
    triage.sort_by(|left, right| {
        parse_timestamp(&right.best_triage.created_at)
            .cmp(&parse_timestamp(&left.best_triage.created_at))
            .then_with(|| right.score.cmp(&left.score))
    });
    Ok(triage)
}

async fn load_public_attempts(
    db: &ServerDb,
    cluster_id: &str,
    limit: i64,
) -> Result<Vec<PublicAttempt>, ApiError> {
    match db {
        ServerDb::Postgres(db) => {
            let rows = db
                .query(
                    "
            SELECT bundle_json
            FROM patch_attempts
            WHERE cluster_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            ",
                    &[&cluster_id, &limit],
                )
                .await
                .map_err(ApiError::internal)?;
            let mut attempts = Vec::new();
            for row in rows {
                let bundle_json: Value = row.get(0);
                let envelope = serde_json::from_value::<WorkerResultEnvelope>(bundle_json)
                    .map_err(ApiError::internal)?;
                let envelope = canonicalize_worker_result_envelope(envelope);
                if publicly_visible_attempt(&envelope.attempt) {
                    attempts.push(public_attempt_from_patch_attempt(envelope.attempt));
                }
            }
            Ok(attempts)
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path).map_err(ApiError::internal)?;
            let mut stmt = connection
                .prepare(
                    "
            SELECT bundle_json
            FROM patch_attempts
            WHERE cluster_id = ?1
            ORDER BY created_at DESC
            LIMIT ?2
            ",
                )
                .map_err(ApiError::internal)?;
            let rows = stmt
                .query_map(params![cluster_id, limit], |row| row.get::<_, String>(0))
                .map_err(ApiError::internal)?;
            let mut attempts = Vec::new();
            for row in rows {
                let raw = row.map_err(ApiError::internal)?;
                let envelope = serde_json::from_str::<WorkerResultEnvelope>(&raw)
                    .map_err(ApiError::internal)?;
                let envelope = canonicalize_worker_result_envelope(envelope);
                if publicly_visible_attempt(&envelope.attempt) {
                    attempts.push(public_attempt_from_patch_attempt(envelope.attempt));
                }
            }
            Ok(attempts)
        }
    }
}

fn attempt_board_filter_from_query(raw: Option<&str>) -> Result<AttemptBoardFilter, ApiError> {
    match raw.unwrap_or("all") {
        "all" => Ok(AttemptBoardFilter::All),
        "reports" | "report" => Ok(AttemptBoardFilter::Reports),
        "failures" | "failed" => Ok(AttemptBoardFilter::Failures),
        "impossible" => Ok(AttemptBoardFilter::Impossible),
        other => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("unknown attempt filter: {other}"),
        )),
    }
}

fn attempt_matches_filter(filter: AttemptBoardFilter, attempt: &PatchAttempt) -> bool {
    match filter {
        AttemptBoardFilter::All => true,
        AttemptBoardFilter::Reports => attempt.outcome == "report" && attempt.state == "ready",
        AttemptBoardFilter::Failures => attempt.outcome == "patch" && attempt.state == "failed",
        AttemptBoardFilter::Impossible => {
            attempt.outcome == "impossible" && attempt.state == "explained"
        }
    }
}

async fn load_public_attempt_entries(
    db: &ServerDb,
    filter: AttemptBoardFilter,
    limit: i64,
) -> Result<Vec<PublicAttemptEntry>, ApiError> {
    match db {
        ServerDb::Postgres(db) => {
            let rows = db
                .query(
                    "
            SELECT ic.id, ic.kind, ic.public_title, ic.public_summary, ic.package_name,
                   ic.source_package, ic.ecosystem, ic.severity, ic.score, ic.corroboration_count,
                   (ic.best_patch_json IS NOT NULL) AS best_patch_available,
                   (ic.best_triage_json IS NOT NULL) AS best_triage_available,
                   pa.bundle_json
            FROM patch_attempts pa
            JOIN issue_clusters ic ON ic.id = pa.cluster_id
            WHERE ic.promoted = TRUE
              AND ic.public_visible = TRUE
            ORDER BY pa.created_at DESC
            ",
                    &[],
                )
                .await
                .map_err(ApiError::internal)?;
            let mut entries = Vec::new();
            for row in rows {
                let attempt_json: Value = row.get(12);
                let envelope = serde_json::from_value::<WorkerResultEnvelope>(attempt_json)
                    .map_err(ApiError::internal)?;
                let envelope = canonicalize_worker_result_envelope(envelope);
                if !publicly_visible_attempt(&envelope.attempt) {
                    continue;
                }
                if !attempt_matches_filter(filter, &envelope.attempt) {
                    continue;
                }
                entries.push(PublicAttemptEntry {
                    issue_id: row.get(0),
                    kind: row.get(1),
                    issue_title: row.get(2),
                    issue_summary: row.get(3),
                    package_name: row.get(4),
                    source_package: row.get(5),
                    ecosystem: row.get(6),
                    severity: row.get(7),
                    score: row.get(8),
                    corroboration_count: row.get(9),
                    best_patch_available: row.get(10),
                    best_triage_available: {
                        let best_patch_available: bool = row.get(10);
                        let best_triage_available: bool = row.get(11);
                        best_triage_available && !best_patch_available
                    },
                    attempt: public_attempt_from_patch_attempt(envelope.attempt),
                });
                if entries.len() >= limit as usize {
                    break;
                }
            }
            Ok(entries)
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path).map_err(ApiError::internal)?;
            let mut stmt = connection
                .prepare(
                    "
            SELECT ic.id, ic.kind, ic.public_title, ic.public_summary, ic.package_name,
                   ic.source_package, ic.ecosystem, ic.severity, ic.score, ic.corroboration_count,
                   (ic.best_patch_json IS NOT NULL) AS best_patch_available,
                   (ic.best_triage_json IS NOT NULL) AS best_triage_available,
                   pa.bundle_json
            FROM patch_attempts pa
            JOIN issue_clusters ic ON ic.id = pa.cluster_id
            WHERE ic.promoted = 1
              AND ic.public_visible = 1
            ORDER BY pa.created_at DESC
            ",
                )
                .map_err(ApiError::internal)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, i64>(10)?,
                        row.get::<_, i64>(11)?,
                        row.get::<_, String>(12)?,
                    ))
                })
                .map_err(ApiError::internal)?;
            let mut entries = Vec::new();
            for row in rows {
                let (
                    issue_id,
                    kind,
                    issue_title,
                    issue_summary,
                    package_name,
                    source_package,
                    ecosystem,
                    severity,
                    score,
                    corroboration_count,
                    best_patch_available,
                    best_triage_available,
                    raw,
                ) = row.map_err(ApiError::internal)?;
                let envelope = serde_json::from_str::<WorkerResultEnvelope>(&raw)
                    .map_err(ApiError::internal)?;
                let envelope = canonicalize_worker_result_envelope(envelope);
                if !publicly_visible_attempt(&envelope.attempt) {
                    continue;
                }
                if !attempt_matches_filter(filter, &envelope.attempt) {
                    continue;
                }
                entries.push(PublicAttemptEntry {
                    issue_id,
                    kind,
                    issue_title,
                    issue_summary,
                    package_name,
                    source_package,
                    ecosystem,
                    severity,
                    score,
                    corroboration_count,
                    best_patch_available: best_patch_available != 0,
                    best_triage_available: (best_triage_available != 0)
                        && (best_patch_available == 0),
                    attempt: public_attempt_from_patch_attempt(envelope.attempt),
                });
                if entries.len() >= limit as usize {
                    break;
                }
            }
            Ok(entries)
        }
    }
}

fn public_issue_from_row(row: Row) -> Result<PublicIssue, ApiError> {
    let last_seen: DateTime<Utc> = row.get(12);
    let best_patch_available: bool = row.get(10);
    let best_triage_available: bool = row.get::<_, bool>(11) && !best_patch_available;
    Ok(PublicIssue {
        id: row.get(0),
        kind: row.get(1),
        title: row.get(2),
        summary: row.get(3),
        package_name: row.get(4),
        source_package: row.get(5),
        ecosystem: row.get(6),
        severity: row.get(7),
        score: row.get(8),
        corroboration_count: row.get(9),
        best_patch_available,
        best_triage_available,
        last_seen: last_seen.to_rfc3339(),
    })
}

fn public_patch_from_row(row: Row) -> Result<PublicPatchEntry, ApiError> {
    let id: String = row.get(0);
    let best_patch_json: Value = row.get(10);
    let best_patch = serde_json::from_value::<PatchAttempt>(best_patch_json)
        .map(public_attempt_from_patch_attempt)
        .map_err(ApiError::internal)?;
    let last_seen: DateTime<Utc> = row.get(11);
    Ok(PublicPatchEntry {
        id: id.clone(),
        kind: row.get(1),
        title: row.get(2),
        summary: row.get(3),
        package_name: row.get(4),
        source_package: row.get(5),
        ecosystem: row.get(6),
        severity: row.get(7),
        score: row.get(8),
        corroboration_count: row.get(9),
        last_seen: last_seen.to_rfc3339(),
        best_patch_diff_url: public_best_patch_diff_url(&id, Some(&best_patch)),
        best_patch,
    })
}

fn public_triage_from_row(row: Row) -> Result<Option<PublicTriageEntry>, ApiError> {
    let best_triage_json: Value = row.get(10);
    let best_triage_attempt =
        serde_json::from_value::<PatchAttempt>(best_triage_json).map_err(ApiError::internal)?;
    if hidden_kernel_workspace_attempt(&best_triage_attempt) {
        return Ok(None);
    }
    let best_triage = public_attempt_from_patch_attempt(best_triage_attempt);
    let handoff = best_triage
        .handoff
        .clone()
        .ok_or_else(|| ApiError::internal("triage result missing public handoff"))?;
    let last_seen: DateTime<Utc> = row.get(11);
    Ok(Some(PublicTriageEntry {
        id: row.get(0),
        kind: row.get(1),
        title: row.get(2),
        summary: row.get(3),
        package_name: row.get(4),
        source_package: row.get(5),
        ecosystem: row.get(6),
        severity: row.get(7),
        score: row.get(8),
        corroboration_count: row.get(9),
        last_seen: last_seen.to_rfc3339(),
        best_triage,
        handoff,
    }))
}

fn compare_public_issue_priority(
    left: &PublicIssueCandidate,
    right: &PublicIssueCandidate,
) -> Ordering {
    let left_impact = issue_user_impact_score_for_signals(&left.issue, &left.signals);
    let right_impact = issue_user_impact_score_for_signals(&right.issue, &right.signals);
    right_impact
        .cmp(&left_impact)
        .then_with(|| {
            right
                .issue
                .corroboration_count
                .cmp(&left.issue.corroboration_count)
        })
        .then_with(|| {
            compare_issue_priority_for_signals(
                &left.issue.kind,
                left.issue.package_name.as_deref(),
                left.issue.source_package.as_deref(),
                left.issue.score,
                left.issue.corroboration_count,
                left.issue.best_patch_available,
                left.issue.best_triage_available,
                &left.issue.last_seen,
                &left.signals,
                &right.issue.kind,
                right.issue.package_name.as_deref(),
                right.issue.source_package.as_deref(),
                right.issue.score,
                right.issue.corroboration_count,
                right.issue.best_patch_available,
                right.issue.best_triage_available,
                &right.issue.last_seen,
                &right.signals,
            )
        })
}

fn issue_user_impact_score_for_signals(issue: &PublicIssue, signals: &IssuePrioritySignals) -> i64 {
    let subsystem = signals.subsystem.as_deref();
    let kernelish_target = signals
        .target_name
        .as_deref()
        .is_some_and(is_kernelish_target_name);
    let mut score = match issue.kind.as_str() {
        "crash" => 92,
        "hotspot" => 44,
        "warning" => 18,
        "investigation" => match subsystem {
            Some("desktop-graphics-session") => 98,
            Some("desktop-resume") => 100,
            Some("oom-kill") => 88,
            Some("runaway-process") => 82,
            Some("stuck-process") if kernelish_target => 68,
            Some("stuck-process") => 78,
            _ => 62,
        },
        _ => 50,
    };
    score += match issue.severity.as_deref() {
        Some("critical") => 8,
        Some("high") => 6,
        Some("medium" | "moderate") => 3,
        _ => 0,
    };
    score += (issue.corroboration_count.saturating_sub(1)).min(3) * 4;
    if issue.kind == "hotspot" && kernelish_target {
        score -= 8;
    }
    if issue.kind == "investigation"
        && subsystem != Some("desktop-resume")
        && subsystem != Some("desktop-graphics-session")
        && issue
            .source_package
            .as_deref()
            .or(issue.package_name.as_deref())
            .is_some_and(is_kernelish_package_name)
    {
        score -= 6;
    }
    score
}

fn issue_human_context(issue: &PublicIssue, signals: &IssuePrioritySignals) -> IssueHumanContext {
    let impact_score = issue_user_impact_score_for_signals(issue, signals);
    let subsystem = signals.subsystem.as_deref();
    let target = signals
        .target_name
        .clone()
        .unwrap_or_else(|| issue.title.clone());
    let kind_label = match (issue.kind.as_str(), subsystem) {
        ("crash", _) => "App crash",
        ("hotspot", _) => "High CPU hotspot",
        ("warning", _) => "System warning",
        ("investigation", Some("desktop-graphics-session")) => "Desktop graphics failure",
        ("investigation", Some("runaway-process")) => "Runaway CPU",
        ("investigation", Some("oom-kill")) => "Out of memory kill",
        ("investigation", Some("desktop-resume")) => "Wake-from-sleep failure",
        ("investigation", Some("stuck-process")) => "Hung process",
        ("investigation", _) => "System investigation",
        _ => "Issue",
    }
    .to_string();
    let (impact_label, impact_class) = if impact_score >= 92 {
        ("very disruptive", "impact-high")
    } else if impact_score >= 76 {
        ("disruptive", "impact-medium")
    } else if impact_score >= 52 {
        ("noticeable", "impact-low")
    } else {
        ("background", "impact-low")
    };
    let impact_summary = match (issue.kind.as_str(), subsystem) {
        ("crash", _) => format!(
            "{} likely crashed or disappeared unexpectedly.",
            humanize_target_name(&target)
        ),
        ("investigation", Some("desktop-graphics-session")) => {
            "The desktop graphics session likely felt broadly broken: multiple apps may have failed to launch, windows may have stopped painting correctly, or the session may have become unstable."
                .to_string()
        }
        ("investigation", Some("desktop-resume")) => {
            "After wake-from-sleep, the desktop likely came back blank, broken, or dropped the user back to login."
                .to_string()
        }
        ("investigation", Some("oom-kill")) => format!(
            "The system likely ran out of memory and killed {}, so work in that app or task may have vanished.",
            humanize_target_name(&target)
        ),
        ("investigation", Some("runaway-process")) => format!(
            "{} likely made the app or machine feel hot, loud, or sluggish by burning CPU continuously.",
            humanize_target_name(&target)
        ),
        ("investigation", Some("stuck-process"))
            if is_kernelish_target_name(&target) =>
        {
            "The machine likely felt hung, stalled, or slow to recover while the kernel waited on something it could not finish."
                .to_string()
        }
        ("investigation", Some("stuck-process")) => format!(
            "{} likely looked hung or stopped making progress.",
            humanize_target_name(&target)
        ),
        ("hotspot", _) => {
            "This likely shows up as wasted CPU, fan noise, heat, or sluggishness even if nothing visibly crashes."
                .to_string()
        }
        ("warning", _) => {
            "This is probably less visible to users unless they are already hitting the affected subsystem."
                .to_string()
        }
        _ => "This looks user-visible enough that it may affect normal day-to-day use.".to_string(),
    };
    IssueHumanContext {
        kind_label,
        impact_label: impact_label.to_string(),
        impact_class: impact_class.to_string(),
        impact_summary,
    }
}

fn humanize_target_name(raw: &str) -> String {
    match raw.trim() {
        "" => "this process".to_string(),
        "python" | "python3" | "python3.13" => "a Python workload".to_string(),
        "postgres" => "PostgreSQL".to_string(),
        "plasmashell" => "Plasma Shell".to_string(),
        "Xorg" => "Xorg".to_string(),
        other => other.to_string(),
    }
}

fn issue_seen_summary(corroboration_count: i64) -> String {
    match corroboration_count {
        1 => "seen on 1 host".to_string(),
        count => format!("seen on {count} hosts"),
    }
}

fn cluster_size_summary(corroboration_count: i64) -> String {
    match corroboration_count {
        count if count <= 0 => "not corroborated yet".to_string(),
        1 => "single-host issue family".to_string(),
        2 => "2-host issue family".to_string(),
        count => format!("{count}-host issue family"),
    }
}

fn render_issue_queue_tags(issue: &PublicIssue, context: &IssueHumanContext) -> String {
    let mut tags = vec![format!(
        "<span class=\"tag {}\">impact: {}</span>",
        html_escape(&context.impact_class),
        html_escape(&context.impact_label)
    )];
    tags.push(format!(
        "<span class=\"tag\">{}</span>",
        html_escape(&issue_seen_summary(issue.corroboration_count))
    ));
    if let Some(package_name) = issue.package_name.as_deref() {
        tags.push(format!(
            "<span class=\"tag\">package: {}</span>",
            html_escape(package_name)
        ));
    }
    if let Some(source_package) = issue.source_package.as_deref() {
        tags.push(format!(
            "<span class=\"tag\">source: {}</span>",
            html_escape(source_package)
        ));
    }
    if issue.best_patch_available {
        tags.push("<span class=\"tag patch\">patch ready</span>".to_string());
    }
    if issue.best_triage_available {
        tags.push("<span class=\"tag triage\">triage ready</span>".to_string());
    }
    tags.join("")
}

fn render_issue_queue_card(entry: &PublicIssueCandidate) -> String {
    let issue = &entry.issue;
    let context = issue_human_context(issue, &entry.signals);
    format!(
        r#"<article class="issue-card">
            <div class="issue-topline">
                <div>
                    <p class="eyebrow">{}</p>
                    <h3><a href="/issues/{}">{}</a></h3>
                </div>
                <span class="tag {}">{}</span>
            </div>
            <p class="issue-summary">{}</p>
            <p class="impact-summary"><strong>Likely user impact.</strong> {}</p>
            <div class="meta">{}</div>
            <p class="fine-print"><strong>Cluster size:</strong> {}. Last seen {}. <a href="/issues/{}">Details</a> · <a href="/v1/issues/{}">JSON</a></p>
        </article>"#,
        html_escape(&context.kind_label),
        issue.id,
        html_escape(&issue.title),
        html_escape(&context.impact_class),
        html_escape(&context.impact_label),
        html_escape(&issue.summary),
        html_escape(&context.impact_summary),
        render_issue_queue_tags(issue, &context),
        html_escape(&cluster_size_summary(issue.corroboration_count)),
        html_escape(&format_timestamp(&issue.last_seen)),
        issue.id,
        issue.id
    )
}

fn compare_issue_priority_for_signals(
    left_kind: &str,
    left_package_name: Option<&str>,
    left_source_package: Option<&str>,
    left_score: i64,
    left_corroboration_count: i64,
    left_best_patch_available: bool,
    left_best_triage_available: bool,
    left_last_seen: &str,
    left_signals: &IssuePrioritySignals,
    right_kind: &str,
    right_package_name: Option<&str>,
    right_source_package: Option<&str>,
    right_score: i64,
    right_corroboration_count: i64,
    right_best_patch_available: bool,
    right_best_triage_available: bool,
    right_last_seen: &str,
    right_signals: &IssuePrioritySignals,
) -> Ordering {
    let left_priority = left_score
        + issue_fixability_adjustment_for_signals(
            left_kind,
            left_package_name,
            left_source_package,
            left_corroboration_count,
            left_best_patch_available,
            left_best_triage_available,
            left_signals,
        );
    let right_priority = right_score
        + issue_fixability_adjustment_for_signals(
            right_kind,
            right_package_name,
            right_source_package,
            right_corroboration_count,
            right_best_patch_available,
            right_best_triage_available,
            right_signals,
        );
    right_priority
        .cmp(&left_priority)
        .then_with(|| right_corroboration_count.cmp(&left_corroboration_count))
        .then_with(|| parse_timestamp(right_last_seen).cmp(&parse_timestamp(left_last_seen)))
        .then_with(|| right_score.cmp(&left_score))
}

fn compare_issue_priority_for_representatives(
    left_kind: &str,
    left_package_name: Option<&str>,
    left_source_package: Option<&str>,
    left_score: i64,
    left_corroboration_count: i64,
    left_best_patch_available: bool,
    left_best_triage_available: bool,
    left_last_seen: &str,
    left_representative: &SharedOpportunity,
    right_kind: &str,
    right_package_name: Option<&str>,
    right_source_package: Option<&str>,
    right_score: i64,
    right_corroboration_count: i64,
    right_best_patch_available: bool,
    right_best_triage_available: bool,
    right_last_seen: &str,
    right_representative: &SharedOpportunity,
) -> Ordering {
    let left_priority = left_score
        + issue_fixability_adjustment_for_representative(
            left_kind,
            left_package_name,
            left_source_package,
            left_corroboration_count,
            left_best_patch_available,
            left_best_triage_available,
            left_representative,
        );
    let right_priority = right_score
        + issue_fixability_adjustment_for_representative(
            right_kind,
            right_package_name,
            right_source_package,
            right_corroboration_count,
            right_best_patch_available,
            right_best_triage_available,
            right_representative,
        );
    right_priority
        .cmp(&left_priority)
        .then_with(|| right_corroboration_count.cmp(&left_corroboration_count))
        .then_with(|| parse_timestamp(right_last_seen).cmp(&parse_timestamp(left_last_seen)))
        .then_with(|| right_score.cmp(&left_score))
}

fn issue_fixability_adjustment_for_representative(
    kind: &str,
    package_name: Option<&str>,
    source_package: Option<&str>,
    corroboration_count: i64,
    best_patch_available: bool,
    best_triage_available: bool,
    representative: &SharedOpportunity,
) -> i64 {
    let mut adjustment = 0;
    adjustment += match (source_package, package_name) {
        (Some(_), _) => 14,
        (None, Some(_)) => 10,
        (None, None) => -12,
    };
    if source_package
        .or(package_name)
        .is_some_and(is_kernelish_package_name)
    {
        adjustment -= 18;
    }
    if best_patch_available {
        adjustment += 6;
    }
    if best_triage_available {
        adjustment -= 8;
    }
    adjustment += (corroboration_count.saturating_sub(1)).min(3) * 3;

    match kind {
        "crash" => adjustment += 16,
        "hotspot" => adjustment -= 10,
        "warning" => adjustment -= 12,
        "investigation" => match representative_subsystem(representative) {
            Some("desktop-graphics-session") => adjustment -= 24,
            Some("runaway-process") => adjustment += 16,
            Some("oom-kill") => adjustment -= 10,
            Some("desktop-resume") => adjustment -= 18,
            Some("stuck-process") => adjustment -= 30,
            _ => {}
        },
        _ => {}
    }

    if representative_likely_external_root_cause(representative) {
        adjustment -= 16;
    }
    if let Some(target_name) = representative_fixability_target_name(representative) {
        if is_kernelish_target_name(&target_name) {
            adjustment -= 18;
        }
    }
    adjustment
}

fn issue_fixability_adjustment_for_signals(
    kind: &str,
    package_name: Option<&str>,
    source_package: Option<&str>,
    corroboration_count: i64,
    best_patch_available: bool,
    best_triage_available: bool,
    signals: &IssuePrioritySignals,
) -> i64 {
    let mut adjustment = 0;
    adjustment += match (source_package, package_name) {
        (Some(_), _) => 14,
        (None, Some(_)) => 10,
        (None, None) => -12,
    };
    if source_package
        .or(package_name)
        .is_some_and(is_kernelish_package_name)
    {
        adjustment -= 18;
    }
    if best_patch_available {
        adjustment += 6;
    }
    if best_triage_available {
        adjustment -= 8;
    }
    adjustment += (corroboration_count.saturating_sub(1)).min(3) * 3;

    match kind {
        "crash" => adjustment += 16,
        "hotspot" => adjustment -= 10,
        "warning" => adjustment -= 12,
        "investigation" => match signals.subsystem.as_deref() {
            Some("desktop-graphics-session") => adjustment -= 24,
            Some("runaway-process") => adjustment += 16,
            Some("oom-kill") => adjustment -= 10,
            Some("desktop-resume") => adjustment -= 18,
            Some("stuck-process") => adjustment -= 30,
            _ => {}
        },
        _ => {}
    }

    if signals.likely_external_root_cause {
        adjustment -= 16;
    }
    if signals
        .target_name
        .as_deref()
        .is_some_and(is_kernelish_target_name)
    {
        adjustment -= 18;
    }
    adjustment
}

fn representative_subsystem(representative: &SharedOpportunity) -> Option<&str> {
    representative
        .finding
        .details
        .get("subsystem")
        .and_then(Value::as_str)
}

fn representative_likely_external_root_cause(representative: &SharedOpportunity) -> bool {
    representative
        .finding
        .details
        .get("likely_external_root_cause")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn representative_fixability_target_name(representative: &SharedOpportunity) -> Option<String> {
    if representative.finding.kind == "investigation" {
        return Some(normalized_investigation_target_name(representative));
    }
    representative
        .finding
        .details
        .get("process_name")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| representative.finding.artifact_name.clone())
}

fn is_kernelish_package_name(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.starts_with("linux-image")
        || normalized.starts_with("linux-headers")
        || normalized.starts_with("linux-modules")
        || normalized == "linux"
}

fn canonical_public_source_package(
    package_name: Option<&str>,
    source_package: Option<String>,
) -> Option<String> {
    let source_package = source_package
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if let Some(source_package) = source_package {
        if source_package
            .to_ascii_lowercase()
            .starts_with("linux-signed")
        {
            return Some("linux".to_string());
        }
        return Some(source_package);
    }
    if package_name.is_some_and(is_kernelish_package_name) {
        return Some("linux".to_string());
    }
    None
}

fn inferred_public_source_package(item: &SharedOpportunity) -> Option<String> {
    canonical_public_source_package(
        item.finding.package_name.as_deref(),
        item.opportunity
            .evidence
            .get("source_package")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .or_else(|| {
                item.opportunity
                    .evidence
                    .get("details")
                    .and_then(|details| details.get("package_metadata"))
                    .and_then(|metadata| metadata.get("source_package"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            }),
    )
    .or_else(|| {
        item.finding
            .details
            .get("profile_target")
            .and_then(|target| target.get("name"))
            .and_then(Value::as_str)
            .filter(|target| is_kernelish_target_name(target))
            .map(|_| "linux".to_string())
    })
}

fn is_kernelish_target_name(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.starts_with("kworker")
        || normalized.starts_with("jbd2/")
        || normalized.starts_with("kswapd")
        || normalized.starts_with("kcompactd")
        || normalized.starts_with("ksoftirqd")
        || normalized.starts_with("migration/")
        || normalized.starts_with("rcu")
        || normalized.starts_with("watchdog/")
        || normalized.starts_with("writeback")
}

fn public_issue_from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PublicIssue> {
    Ok(PublicIssue {
        id: row.get(0)?,
        kind: row.get(1)?,
        title: row.get(2)?,
        summary: row.get(3)?,
        package_name: row.get(4)?,
        source_package: row.get(5)?,
        ecosystem: row.get(6)?,
        severity: row.get(7)?,
        score: row.get(8)?,
        corroboration_count: row.get(9)?,
        best_patch_available: row.get::<_, i64>(10)? != 0,
        best_triage_available: row.get::<_, i64>(11)? != 0,
        last_seen: row.get(12)?,
    })
}

fn public_issue_candidate_from_row(row: Row) -> Result<PublicIssueCandidate, ApiError> {
    let issue = public_issue_from_row(row.clone())?;
    let signals = issue_priority_signals_from_value(&row.get::<_, Value>(13));
    Ok(PublicIssueCandidate { issue, signals })
}

fn public_issue_candidate_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PublicIssueCandidate> {
    let issue = public_issue_from_sqlite_row(row)?;
    let signals = issue_priority_signals_from_str(&row.get::<_, String>(13)?);
    Ok(PublicIssueCandidate { issue, signals })
}

fn duplicate_candidate_from_row(row: Row) -> Result<DuplicateCandidateIssue, ApiError> {
    let issue = public_issue_from_row(row.clone())?;
    let representative = serde_json::from_value::<SharedOpportunity>(row.get::<_, Value>(13))
        .map_err(ApiError::internal)?;
    Ok(DuplicateCandidateIssue {
        issue,
        representative,
    })
}

fn issue_priority_signals_from_str(raw: &str) -> IssuePrioritySignals {
    serde_json::from_str::<Value>(raw)
        .map(|value| issue_priority_signals_from_value(&value))
        .unwrap_or_default()
}

fn issue_priority_signals_from_value(value: &Value) -> IssuePrioritySignals {
    let details = value
        .get("finding")
        .and_then(|finding| finding.get("details"));
    let subsystem = details
        .and_then(|details| details.get("subsystem"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let likely_external_root_cause = details
        .and_then(|details| details.get("likely_external_root_cause"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let target_name = if value
        .get("finding")
        .and_then(|finding| finding.get("kind"))
        .and_then(Value::as_str)
        == Some("investigation")
    {
        normalized_investigation_target_name_from_value(value)
    } else {
        details
            .and_then(|details| details.get("process_name"))
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .or_else(|| {
                value
                    .get("finding")
                    .and_then(|finding| finding.get("artifact_name"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
    };
    IssuePrioritySignals {
        subsystem,
        target_name,
        likely_external_root_cause,
    }
}

fn duplicate_candidate_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<DuplicateCandidateIssue> {
    let issue = public_issue_from_sqlite_row(row)?;
    let representative = serde_json::from_str::<SharedOpportunity>(&row.get::<_, String>(13)?)
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                13,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    Ok(DuplicateCandidateIssue {
        issue,
        representative,
    })
}

fn duplicate_match_features(
    issue: &PublicIssue,
    representative: &SharedOpportunity,
) -> DuplicateMatchFeatures {
    DuplicateMatchFeatures {
        kind: issue.kind.clone(),
        normalized_title: normalize_duplicate_match_text(&issue.title),
        normalized_summary: normalize_duplicate_match_text(&issue.summary),
        package_name: issue.package_name.clone(),
        source_package: issue.source_package.clone(),
        ecosystem: issue.ecosystem.clone(),
        subsystem: representative
            .finding
            .details
            .get("subsystem")
            .and_then(Value::as_str)
            .map(normalize_duplicate_field),
        classification: representative
            .finding
            .details
            .get("loop_classification")
            .and_then(Value::as_str)
            .map(normalize_duplicate_field),
        wchan: representative
            .finding
            .details
            .get("wchan")
            .and_then(Value::as_str)
            .map(normalize_duplicate_field),
        target_name: Some(normalize_duplicate_field(
            &normalized_investigation_target_name(representative),
        )),
        primary_signature: duplicate_primary_signature(representative),
    }
}

fn duplicate_primary_signature(item: &SharedOpportunity) -> Option<String> {
    match item.finding.kind.as_str() {
        "crash" => normalized_primary_stack_signature(item),
        "investigation" => {
            let subsystem = item
                .finding
                .details
                .get("subsystem")
                .and_then(Value::as_str)
                .unwrap_or("-");
            match subsystem {
                "stuck-process" => item
                    .finding
                    .details
                    .get("stack_excerpt")
                    .and_then(Value::as_str)
                    .and_then(|excerpt| excerpt.lines().next())
                    .map(normalize_stack_frame)
                    .filter(|value| !value.is_empty()),
                "runaway-process" => item
                    .finding
                    .details
                    .get("top_hot_symbols")
                    .and_then(Value::as_array)
                    .and_then(|symbols| symbols.first())
                    .and_then(Value::as_str)
                    .map(normalize_stack_frame)
                    .filter(|value| !value.is_empty())
                    .or_else(|| {
                        item.finding
                            .details
                            .get("hot_path_dso")
                            .and_then(Value::as_str)
                            .map(normalize_duplicate_field)
                            .filter(|value| !value.is_empty())
                    }),
                "desktop-resume" => item
                    .finding
                    .details
                    .get("gpu_error_lines")
                    .and_then(Value::as_array)
                    .and_then(|lines| lines.first())
                    .and_then(Value::as_str)
                    .map(normalize_duplicate_field)
                    .filter(|value| !value.is_empty())
                    .or_else(|| {
                        item.finding
                            .details
                            .get("crashed_processes")
                            .and_then(Value::as_array)
                            .map(|processes| {
                                let mut normalized = processes
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .map(normalize_duplicate_field)
                                    .filter(|value| !value.is_empty())
                                    .collect::<Vec<_>>();
                                normalized.sort();
                                normalized.join("|")
                            })
                            .filter(|value| !value.is_empty())
                    }),
                _ => None,
            }
        }
        _ => None,
    }
}

fn build_possible_duplicate(
    target: &DuplicateMatchFeatures,
    candidate: DuplicateCandidateIssue,
) -> Option<PublicPossibleDuplicate> {
    let candidate_features = duplicate_match_features(&candidate.issue, &candidate.representative);
    let (similarity_score, match_reasons) = duplicate_match_score(target, &candidate_features);
    if similarity_score < 0.45 {
        return None;
    }
    Some(PublicPossibleDuplicate {
        id: candidate.issue.id,
        kind: candidate.issue.kind,
        title: candidate.issue.title,
        summary: candidate.issue.summary,
        package_name: candidate.issue.package_name,
        source_package: candidate.issue.source_package,
        ecosystem: candidate.issue.ecosystem,
        severity: candidate.issue.severity,
        score: candidate.issue.score,
        corroboration_count: candidate.issue.corroboration_count,
        best_patch_available: candidate.issue.best_patch_available,
        best_triage_available: candidate.issue.best_triage_available,
        last_seen: candidate.issue.last_seen,
        similarity_score,
        match_reasons,
    })
}

fn duplicate_match_score(
    target: &DuplicateMatchFeatures,
    candidate: &DuplicateMatchFeatures,
) -> (f64, Vec<String>) {
    if target.kind != candidate.kind {
        return (0.0, Vec::new());
    }

    let title_similarity =
        trigram_similarity(&target.normalized_title, &candidate.normalized_title);
    let summary_similarity =
        trigram_similarity(&target.normalized_summary, &candidate.normalized_summary);
    let strong_structured_match =
        matching_optional_field(&target.package_name, &candidate.package_name)
            || matching_optional_field(&target.source_package, &candidate.source_package)
            || matching_optional_field(&target.wchan, &candidate.wchan)
            || matching_optional_field(&target.target_name, &candidate.target_name)
            || matching_optional_field(&target.primary_signature, &candidate.primary_signature);
    let mut score = (title_similarity * 0.55) + (summary_similarity * 0.45);
    let mut reasons = Vec::new();

    if !strong_structured_match && title_similarity < 0.75 {
        return (0.0, Vec::new());
    }

    if title_similarity >= 0.98 {
        score += 0.08;
        reasons.push("same public title".to_string());
    }
    if summary_similarity >= 0.75 {
        score += 0.06;
        reasons.push("very similar public summary".to_string());
    }
    if matching_optional_field(&target.package_name, &candidate.package_name) {
        score += 0.10;
        reasons.push("same package".to_string());
    }
    if matching_optional_field(&target.source_package, &candidate.source_package) {
        score += 0.08;
        reasons.push("same source package".to_string());
    }
    if matching_optional_field(&target.ecosystem, &candidate.ecosystem) {
        score += 0.03;
    }
    if matching_optional_field(&target.subsystem, &candidate.subsystem) {
        score += 0.08;
        reasons.push("same subsystem".to_string());
    }
    if matching_optional_field(&target.classification, &candidate.classification) {
        score += 0.08;
        reasons.push("same classification".to_string());
    }
    if matching_optional_field(&target.wchan, &candidate.wchan) {
        score += 0.09;
        reasons.push("same wait site".to_string());
    }
    if matching_optional_field(&target.target_name, &candidate.target_name) {
        score += 0.07;
        reasons.push("same target".to_string());
    }
    if matching_optional_field(&target.primary_signature, &candidate.primary_signature) {
        score += 0.12;
        reasons.push("same stack or hot path signature".to_string());
    }

    if different_non_empty_field(&target.package_name, &candidate.package_name) {
        score -= 0.04;
    }
    if different_non_empty_field(&target.subsystem, &candidate.subsystem) {
        score -= 0.04;
    }
    if different_non_empty_field(&target.classification, &candidate.classification) {
        score -= 0.03;
    }

    if title_similarity < 0.2 && summary_similarity < 0.2 {
        return (0.0, Vec::new());
    }

    reasons.sort();
    reasons.dedup();
    (score.clamp(0.0, 0.99), reasons)
}

fn normalize_duplicate_match_text(raw: &str) -> String {
    let sanitized = sanitize_public_text(raw);
    let mut normalized = String::with_capacity(sanitized.len());
    let mut previous_space = true;
    for ch in sanitized.chars().flat_map(char::to_lowercase) {
        let is_word = ch.is_alphanumeric();
        if is_word {
            normalized.push(ch);
            previous_space = false;
        } else if !previous_space {
            normalized.push(' ');
            previous_space = true;
        }
    }
    normalized.trim().to_string()
}

fn normalize_duplicate_field(raw: &str) -> String {
    normalize_duplicate_match_text(raw)
}

fn matching_optional_field(left: &Option<String>, right: &Option<String>) -> bool {
    matches!((left, right), (Some(left), Some(right)) if !left.is_empty() && left == right)
}

fn different_non_empty_field(left: &Option<String>, right: &Option<String>) -> bool {
    matches!((left, right), (Some(left), Some(right)) if !left.is_empty() && !right.is_empty() && left != right)
}

fn trigram_similarity(left: &str, right: &str) -> f64 {
    let left_ngrams = trigram_set(left);
    let right_ngrams = trigram_set(right);
    if left_ngrams.is_empty() || right_ngrams.is_empty() {
        return 0.0;
    }
    let intersection = left_ngrams.intersection(&right_ngrams).count() as f64;
    let union = left_ngrams.union(&right_ngrams).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

fn trigram_set(raw: &str) -> HashSet<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return HashSet::new();
    }
    let padded = format!("  {trimmed}  ");
    let chars = padded.chars().collect::<Vec<_>>();
    chars
        .windows(3)
        .map(|window| window.iter().collect::<String>())
        .collect()
}

fn public_patch_from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PublicPatchEntry> {
    let id: String = row.get(0)?;
    let best_patch = serde_json::from_str::<PatchAttempt>(&row.get::<_, String>(10)?)
        .map(public_attempt_from_patch_attempt)
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                10,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    Ok(PublicPatchEntry {
        id: id.clone(),
        kind: row.get(1)?,
        title: row.get(2)?,
        summary: row.get(3)?,
        package_name: row.get(4)?,
        source_package: row.get(5)?,
        ecosystem: row.get(6)?,
        severity: row.get(7)?,
        score: row.get(8)?,
        corroboration_count: row.get(9)?,
        last_seen: row.get(11)?,
        best_patch_diff_url: public_best_patch_diff_url(&id, Some(&best_patch)),
        best_patch,
    })
}

fn public_triage_from_sqlite_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Option<PublicTriageEntry>> {
    let best_triage_attempt = serde_json::from_str::<PatchAttempt>(&row.get::<_, String>(10)?)
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                10,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    if hidden_kernel_workspace_attempt(&best_triage_attempt) {
        return Ok(None);
    }
    let best_triage = public_attempt_from_patch_attempt(best_triage_attempt);
    let handoff = best_triage.handoff.clone().ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            10,
            rusqlite::types::Type::Text,
            "triage result missing public handoff".into(),
        )
    })?;
    Ok(Some(PublicTriageEntry {
        id: row.get(0)?,
        kind: row.get(1)?,
        title: row.get(2)?,
        summary: row.get(3)?,
        package_name: row.get(4)?,
        source_package: row.get(5)?,
        ecosystem: row.get(6)?,
        severity: row.get(7)?,
        score: row.get(8)?,
        corroboration_count: row.get(9)?,
        last_seen: row.get(11)?,
        best_triage,
        handoff,
    }))
}

fn public_attempt_from_patch_attempt(attempt: PatchAttempt) -> PublicAttempt {
    let attempt = canonicalize_patch_attempt(attempt);
    let published_session = published_session_from_attempt_details(&attempt.details);
    let handoff = public_triage_handoff_from_attempt(&attempt, published_session.as_ref());
    let blocker_reason = attempt_blocker_reason(&attempt);
    let failure_diagnostics = public_failure_diagnostics_from_attempt(&attempt);
    let failure_context =
        public_failure_context_from_attempt(&attempt, failure_diagnostics.is_some());
    PublicAttempt {
        outcome: attempt.outcome,
        state: attempt.state,
        summary: attempt.summary,
        validation_status: attempt.validation_status,
        created_at: attempt.created_at,
        published_session,
        handoff,
        blocker_reason,
        failure_diagnostics,
        failure_context,
    }
}

fn public_failure_diagnostics_from_attempt(
    attempt: &PatchAttempt,
) -> Option<PublicFailureDiagnostics> {
    let failure_kind = attempt
        .details
        .get("patch_failure_kind")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let review_failure_category = attempt
        .details
        .get("patch_review_failure_category")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let exit_status = attempt
        .details
        .get("patch_exit_status")
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok());
    let error = attempt
        .details
        .get("patch_error")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let last_stderr_excerpt = attempt
        .details
        .get("patch_last_stderr_excerpt")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    if failure_kind.is_none()
        && review_failure_category.is_none()
        && exit_status.is_none()
        && error.is_none()
        && last_stderr_excerpt.is_none()
    {
        return None;
    }
    Some(PublicFailureDiagnostics {
        failure_kind,
        review_failure_category,
        exit_status,
        error,
        last_stderr_excerpt,
    })
}

fn public_failure_context_from_attempt(
    attempt: &PatchAttempt,
    has_structured_failure_diagnostics: bool,
) -> Option<PublicFailureContext> {
    if attempt.outcome != "patch" || attempt.state != "failed" {
        return None;
    }
    let diagnosis = attempt.details.get("diagnosis").and_then(Value::as_object);
    let workspace = attempt.details.get("workspace").and_then(Value::as_object);

    let backtrace_capture_status = diagnosis
        .and_then(|value| value.get("backtrace_capture_status"))
        .and_then(Value::as_str)
        .map(sanitize_public_text)
        .filter(|value| !value.is_empty());
    let backtrace_capture_error = diagnosis
        .and_then(|value| value.get("backtrace_capture_error"))
        .and_then(Value::as_str)
        .map(sanitize_public_text)
        .filter(|value| !value.is_empty());
    let note = if let Some(status) = backtrace_capture_status.as_deref() {
        match (status, backtrace_capture_error.as_deref()) {
            ("failed", Some(error)) => Some(format!(
                "Thread backtrace capture failed on the worker: {error}."
            )),
            ("unavailable", _) => Some(
                "Thread backtrace capture was unavailable on the worker, so this attempt fell back to perf, strace, and /proc evidence."
                    .to_string(),
            ),
            ("disabled", _) => Some(
                "Thread backtrace capture was disabled on the worker for this attempt."
                    .to_string(),
            ),
            _ if has_structured_failure_diagnostics => None,
            _ => Some(
                "This older failed attempt predates structured patch failure capture, so Fixer only retained the diagnosis and workspace context."
                    .to_string(),
            ),
        }
    } else if has_structured_failure_diagnostics {
        None
    } else {
        Some(
            "This older failed attempt predates structured patch failure capture, so Fixer only retained the diagnosis and workspace context.".to_string(),
        )
    };
    let subsystem = diagnosis
        .and_then(|value| value.get("subsystem"))
        .and_then(Value::as_str)
        .map(sanitize_public_text)
        .filter(|value| !value.is_empty());
    let loop_classification = diagnosis
        .and_then(|value| value.get("loop_classification"))
        .and_then(Value::as_str)
        .map(sanitize_public_text)
        .filter(|value| !value.is_empty());
    let hot_path_symbol = diagnosis
        .and_then(|value| value.get("hot_path_symbol"))
        .and_then(Value::as_str)
        .map(sanitize_public_text)
        .filter(|value| !value.is_empty());
    let command_line = diagnosis
        .and_then(|value| value.get("command_line"))
        .and_then(Value::as_str)
        .map(sanitize_public_text)
        .filter(|value| !value.is_empty());
    let loop_explanation = diagnosis
        .and_then(|value| value.get("loop_explanation"))
        .and_then(Value::as_str)
        .map(sanitize_public_text)
        .filter(|value| !value.is_empty());
    let thread_backtrace_summary = diagnosis
        .and_then(|value| value.get("thread_backtrace_summary"))
        .and_then(Value::as_str)
        .map(sanitize_public_text)
        .filter(|value| !value.is_empty());
    let raw_backtrace_excerpt = diagnosis
        .and_then(|value| value.get("raw_backtrace_excerpt"))
        .and_then(Value::as_str)
        .map(sanitize_public_text)
        .filter(|value| !value.is_empty());
    let representative_backtraces = diagnosis
        .and_then(|value| value.get("representative_backtraces"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_object)
                .take(4)
                .filter_map(|trace| {
                    let count = trace.get("thread_count").and_then(Value::as_u64)?;
                    let frames = trace
                        .get("frames")
                        .and_then(Value::as_array)?
                        .iter()
                        .filter_map(Value::as_str)
                        .take(4)
                        .map(sanitize_public_text)
                        .collect::<Vec<_>>();
                    (!frames.is_empty())
                        .then(|| format!("{count} thread(s): {}", frames.join(" -> ")))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let common_frame_clusters = diagnosis
        .and_then(|value| value.get("common_frame_clusters"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_object)
                .take(4)
                .filter_map(|cluster| {
                    let count = cluster.get("thread_count").and_then(Value::as_u64)?;
                    let frames = cluster
                        .get("frames")
                        .and_then(Value::as_array)?
                        .iter()
                        .filter_map(Value::as_str)
                        .take(4)
                        .map(sanitize_public_text)
                        .collect::<Vec<_>>();
                    (!frames.is_empty())
                        .then(|| format!("{count} thread(s): {}", frames.join(" -> ")))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let lock_contention_signals = diagnosis
        .and_then(|value| value.get("lock_contention_signals"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(sanitize_public_text)
                .filter(|value| !value.is_empty())
                .take(8)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let implicated_packages = diagnosis
        .and_then(|value| value.get("implicated_package_names"))
        .and_then(Value::as_array)
        .map(|packages| {
            packages
                .iter()
                .filter_map(Value::as_str)
                .map(sanitize_public_text)
                .filter(|value| !value.is_empty())
                .take(6)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let source_package = workspace
        .and_then(|value| value.get("source_package"))
        .and_then(Value::as_str)
        .map(sanitize_public_text)
        .filter(|value| !value.is_empty());
    let source_kind = workspace
        .and_then(|value| value.get("source_kind"))
        .and_then(Value::as_str)
        .map(sanitize_public_text)
        .filter(|value| !value.is_empty());
    let acquisition_note = workspace
        .and_then(|value| value.get("acquisition_note"))
        .and_then(Value::as_str)
        .map(sanitize_public_text)
        .filter(|value| !value.is_empty());
    let homepage = workspace
        .and_then(|value| value.get("homepage"))
        .and_then(Value::as_str)
        .map(sanitize_public_text)
        .filter(|value| !value.is_empty());

    if note.is_none()
        && subsystem.is_none()
        && loop_classification.is_none()
        && hot_path_symbol.is_none()
        && command_line.is_none()
        && loop_explanation.is_none()
        && thread_backtrace_summary.is_none()
        && raw_backtrace_excerpt.is_none()
        && representative_backtraces.is_empty()
        && common_frame_clusters.is_empty()
        && lock_contention_signals.is_empty()
        && implicated_packages.is_empty()
        && source_package.is_none()
        && source_kind.is_none()
        && acquisition_note.is_none()
        && homepage.is_none()
    {
        return None;
    }

    Some(PublicFailureContext {
        note,
        subsystem,
        loop_classification,
        hot_path_symbol,
        command_line,
        loop_explanation,
        thread_backtrace_summary,
        raw_backtrace_excerpt,
        representative_backtraces,
        common_frame_clusters,
        lock_contention_signals,
        implicated_packages,
        source_package,
        source_kind,
        acquisition_note,
        homepage,
    })
}

fn public_attempt_diff(attempt: &PublicAttempt) -> Option<&str> {
    attempt
        .published_session
        .as_ref()
        .and_then(|session| session.diff.as_deref())
        .filter(|diff| !diff.trim().is_empty())
}

fn public_best_patch_diff_url(
    issue_id: &str,
    best_patch: Option<&PublicAttempt>,
) -> Option<String> {
    public_attempt_diff(best_patch?).map(|_| format!("/issues/{issue_id}/best.patch"))
}

fn public_best_patch_raw_diff_url(
    issue_id: &str,
    best_patch: Option<&PublicAttempt>,
) -> Option<String> {
    public_attempt_diff(best_patch?).map(|_| format!("/issues/{issue_id}/best.diff"))
}

fn build_public_patch_cover(
    title: &str,
    summary: &str,
    package_name: Option<&str>,
    source_package: Option<&str>,
    corroboration_count: i64,
    last_seen: &str,
    attempt: &PublicAttempt,
) -> Option<PublicPatchCover> {
    let diff = public_attempt_diff(attempt)?;
    let changed_files = patch_changed_files(diff);
    let issue_phrase = concise_issue_phrase(summary, title);
    let response_metadata = attempt
        .published_session
        .as_ref()
        .and_then(|session| session.response.as_deref())
        .map(extract_patch_response_metadata)
        .unwrap_or_default();
    let keyboard_layout_context = is_keyboard_layout_issue_context(title, summary, &changed_files);
    let subject = response_metadata
        .subject
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            patch_subject(package_name, source_package, &changed_files, &issue_phrase)
        });
    let raw_commit_message = response_metadata
        .commit_message
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| patch_commit_message(attempt, diff, &changed_files, &issue_phrase));
    let raw_issue_connection = response_metadata
        .issue_connection
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| patch_issue_connection(diff, &changed_files, &issue_phrase));
    let commit_message = clarify_public_patch_commit_message(
        &raw_commit_message,
        keyboard_layout_context,
        &changed_files,
    );
    let issue_connection = clarify_public_patch_issue_connection(
        &raw_issue_connection,
        keyboard_layout_context,
        &changed_files,
    );
    let validation_notes = patch_validation_notes(
        corroboration_count,
        last_seen,
        attempt,
        &changed_files,
        &response_metadata.validation_notes,
    );
    Some(PublicPatchCover {
        subject,
        commit_message,
        problem: clarify_public_problem(summary, keyboard_layout_context),
        issue_connection,
        changed_files,
        validation_notes,
    })
}

fn render_public_patch_email(issue: &PublicIssueDetail, attempt: &PublicAttempt) -> Option<String> {
    let diff = normalize_published_diff(public_attempt_diff(attempt)?);
    let cover = build_public_patch_cover(
        &issue.title,
        &issue.summary,
        issue.package_name.as_deref(),
        issue.source_package.as_deref(),
        issue.corroboration_count,
        &issue.last_seen,
        attempt,
    )?;
    let mut patch = String::new();
    let _ = write!(
        patch,
        "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\nFrom: Fixer <fixer@maumap.com>\nDate: {}\nSubject: [PATCH] {}\n\nProblem:\n{}\n\nCommit message:\n{}\n",
        format_patch_email_date(&attempt.created_at),
        cover.subject,
        cover.problem,
        cover.commit_message
    );
    let _ = write!(
        patch,
        "\nHow this patch connects to the issue:\n{}\n",
        cover.issue_connection
    );
    if !cover.changed_files.is_empty() {
        patch.push_str("\nFiles touched:\n");
        for path in &cover.changed_files {
            let _ = writeln!(patch, "- {}", path);
        }
    }
    if !cover.validation_notes.is_empty() {
        patch.push_str("\nValidation:\n");
        for note in &cover.validation_notes {
            let _ = writeln!(patch, "- {}", note);
        }
    }
    let _ = write!(
        patch,
        "\nIssue: https://fixer.maumap.com/issues/{}\n\n---\n{}",
        issue.id, diff
    );
    Some(patch)
}

fn patch_changed_files(diff: &str) -> Vec<String> {
    let mut files = Vec::new();
    for line in diff.lines() {
        let Some(path) = line.strip_prefix("+++ b/") else {
            continue;
        };
        let path = strip_patch_header_metadata(path);
        if path.is_empty() || path == "/dev/null" {
            continue;
        }
        if !files.iter().any(|existing| existing == path) {
            files.push(path.to_string());
        }
    }
    files
}

fn patch_subject(
    package_name: Option<&str>,
    source_package: Option<&str>,
    changed_files: &[String],
    issue_phrase: &str,
) -> String {
    let package = source_package
        .or(package_name)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("fixer");
    let subject = if let Some(file_name) = changed_files
        .first()
        .and_then(|path| Path::new(path).file_name())
        .and_then(|name| name.to_str())
    {
        format!("{package}: update {file_name} for {issue_phrase}")
    } else {
        format!("{package}: address {issue_phrase}")
    };
    truncate_patch_subject(&subject, 72)
}

#[derive(Debug, Default, Clone)]
struct PatchResponseMetadata {
    subject: Option<String>,
    commit_message: Option<String>,
    issue_connection: Option<String>,
    validation_notes: Vec<String>,
}

fn concise_issue_phrase(summary: &str, title: &str) -> String {
    let clause = summary
        .split([':', '.'])
        .next()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(title)
        .trim();
    let simplified = clause
        .split_once(" is ")
        .map(|(_, rest)| rest)
        .or_else(|| clause.split_once(" has ").map(|(_, rest)| rest))
        .unwrap_or(clause)
        .trim();
    for prefix in [
        "stuck in a likely ",
        "stuck in an ",
        "stuck in a ",
        "stuck in ",
        "showing a likely ",
        "showing ",
        "a likely ",
        "likely ",
    ] {
        if simplified
            .to_ascii_lowercase()
            .starts_with(&prefix.to_ascii_lowercase())
        {
            return ensure_sentence(simplified[prefix.len()..].trim())
                .trim_end_matches('.')
                .to_string();
        }
    }
    ensure_sentence(simplified)
        .trim_end_matches('.')
        .to_string()
}

fn is_keyboard_layout_issue_context(title: &str, summary: &str, changed_files: &[String]) -> bool {
    let lowered = format!("{title} {summary}").to_ascii_lowercase();
    changed_files
        .iter()
        .any(|path| path.starts_with("kcms/keyboard/"))
        && ["keyboard", "layout", "caps lock", "spare layout", "switch"]
            .iter()
            .any(|needle| lowered.contains(needle))
}

fn clarify_public_problem(summary: &str, keyboard_layout_context: bool) -> String {
    if keyboard_layout_context {
        return "On KDE Wayland, Plasma is configured with three keyboard layouts but only two should stay in the normal switch cycle. Instead, the spare-layout path leaks into the public layout order, so direct selection and the last-used-layout shortcut can act on the wrong slot.".to_string();
    }
    ensure_sentence(summary)
}

fn explanation_needs_keyboard_clarity_pass(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("xkb")
        || lower.contains("logical layout")
        || lower.contains("runtime xkb list")
        || lower.contains("layoutloopcount")
        || lower.contains("transient spare-layout runtime shuffle")
        || lower.contains("xkb loop")
        || lower.contains("logical slot")
}

fn clarify_public_patch_commit_message(
    text: &str,
    keyboard_layout_context: bool,
    changed_files: &[String],
) -> String {
    if keyboard_layout_context && explanation_needs_keyboard_clarity_pass(text) {
        if changed_files.iter().any(|path| {
            path.ends_with("keyboard_daemon.cpp") || path.ends_with("keyboard_daemon.h")
        }) {
            return "Keep Plasma's public layout order aligned with the order saved in its keyboard settings, and remember the previous layout before rebuilding the live layout list for Spare Layouts.".to_string();
        }
        return "Keep Plasma's public layout order aligned with its saved keyboard settings when Spare Layouts is enabled.".to_string();
    }
    ensure_sentence(text)
}

fn clarify_public_patch_issue_connection(
    text: &str,
    keyboard_layout_context: bool,
    changed_files: &[String],
) -> String {
    if keyboard_layout_context && explanation_needs_keyboard_clarity_pass(text) {
        let last_used_clause = if changed_files.iter().any(|path| {
            path.ends_with("keyboard_daemon.cpp") || path.ends_with("keyboard_daemon.h")
        }) {
            " It also remembers the previous layout before rebuilding the live list, so the 'last used layout' action still returns to the layout the user actually came from."
        } else {
            ""
        };
        return format!(
            "Plasma stores three layouts here, but only two should stay in the normal switching cycle while the third remains spare. The bug was that Plasma leaked its temporary live reordering back into the layout list and indices seen by the applet and shortcuts, so selecting a spare layout could confuse direct selection. This patch keeps the public order in the configured order while letting the internal live switcher keep doing its temporary spare-layout swap.{}",
            last_used_clause
        );
    }
    ensure_sentence(text)
}

fn patch_commit_message(
    attempt: &PublicAttempt,
    diff: &str,
    changed_files: &[String],
    issue_phrase: &str,
) -> String {
    if let Some(rationale) = extract_added_comment_rationale(diff) {
        return ensure_sentence(&rationale);
    }
    if let Some(response) = attempt
        .published_session
        .as_ref()
        .and_then(|session| session.response.as_deref())
        .and_then(latest_patch_authoring_response)
        .as_deref()
        .and_then(meaningful_patch_response)
    {
        return ensure_sentence(&response);
    }
    if is_informative_patch_summary(&attempt.summary) {
        return ensure_sentence(&attempt.summary);
    }
    let touched = if changed_files.is_empty() {
        "the affected code paths".to_string()
    } else {
        format!("the affected code in {}", changed_files.join(", "))
    };
    ensure_sentence(&format!(
        "Fixer observed {} and is proposing a concrete upstream starting point by updating {}",
        issue_phrase, touched
    ))
}

fn patch_issue_connection(diff: &str, changed_files: &[String], issue_phrase: &str) -> String {
    let touched = if changed_files.is_empty() {
        "the affected code path".to_string()
    } else {
        changed_files.join(", ")
    };
    if let Some(rationale) = extract_added_comment_rationale(diff) {
        return ensure_sentence(&format!(
            "Fixer observed {}. This patch updates {} so {}",
            issue_phrase,
            touched,
            lower_sentence_fragment(&rationale)
        ));
    }
    ensure_sentence(&format!(
        "Fixer observed {}. This patch updates {} to remove or narrow the failing path behind that behavior",
        issue_phrase, touched
    ))
}

fn patch_validation_notes(
    corroboration_count: i64,
    last_seen: &str,
    attempt: &PublicAttempt,
    changed_files: &[String],
    author_notes: &[String],
) -> Vec<String> {
    let mut notes = Vec::new();
    let status = attempt
        .validation_status
        .as_deref()
        .unwrap_or(&attempt.state);
    notes.push(format!(
        "Fixer marked this proposal `{}` on {}.",
        status,
        format_timestamp(&attempt.created_at)
    ));
    notes.push(format!(
        "The underlying issue cluster has {} report(s) and was last seen {}.",
        corroboration_count,
        format_timestamp(last_seen)
    ));
    if !changed_files.is_empty() {
        notes.push(format!(
            "The published diff touches {}.",
            changed_files.join(", ")
        ));
    }
    for note in author_notes {
        if !note.trim().is_empty() {
            notes.push(ensure_sentence(note));
        }
    }
    notes
}

fn extract_patch_response_metadata(response: &str) -> PatchResponseMetadata {
    let authoring_response =
        latest_patch_authoring_response(response).unwrap_or_else(|| response.trim().to_string());
    let validation_notes = extract_markdown_section_raw(&authoring_response, "Validation")
        .map(|section| parse_validation_notes(&section))
        .unwrap_or_default();
    PatchResponseMetadata {
        subject: extract_labeled_line(&authoring_response, "Subject:"),
        commit_message: extract_markdown_section_raw(&authoring_response, "Commit Message"),
        issue_connection: extract_markdown_section_raw(&authoring_response, "Issue Connection"),
        validation_notes,
    }
}

fn extract_added_comment_rationale(diff: &str) -> Option<String> {
    let mut block = Vec::new();
    let mut in_block = false;
    for line in diff.lines() {
        let Some(rest) = line.strip_prefix('+') else {
            if in_block && !block.is_empty() {
                break;
            }
            continue;
        };
        let trimmed = rest.trim_start();
        if !in_block {
            if trimmed.starts_with("/*") {
                in_block = true;
                let fragment = trim_added_comment_fragment(trimmed);
                if !fragment.is_empty() {
                    block.push(fragment);
                }
                if trimmed.contains("*/") {
                    break;
                }
            } else if let Some(comment) = trimmed.strip_prefix("//") {
                let comment = comment.trim();
                if !comment.is_empty() {
                    return Some(comment.to_string());
                }
            }
            continue;
        }
        let fragment = trim_added_comment_fragment(trimmed);
        if !fragment.is_empty() {
            block.push(fragment);
        }
        if trimmed.contains("*/") {
            break;
        }
    }
    if block.is_empty() {
        None
    } else {
        Some(block.join(" "))
    }
}

fn strip_patch_header_metadata(path: &str) -> &str {
    path.split('\t').next().unwrap_or(path).trim()
}

fn normalize_published_diff(diff: &str) -> String {
    let mut normalized = diff
        .lines()
        .map(|line| {
            if let Some(path) = line.strip_prefix("--- a/") {
                format!("--- a/{}", strip_patch_header_metadata(path))
            } else if let Some(path) = line.strip_prefix("+++ b/") {
                format!("+++ b/{}", strip_patch_header_metadata(path))
            } else if let Some(path) = line.strip_prefix("--- ") {
                format!("--- {}", strip_patch_header_metadata(path))
            } else if let Some(path) = line.strip_prefix("+++ ") {
                format!("+++ {}", strip_patch_header_metadata(path))
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    if diff.ends_with('\n') {
        normalized.push('\n');
    }
    normalized
}

fn trim_added_comment_fragment(text: &str) -> String {
    let mut fragment = text.trim();
    if matches!(fragment, "/*" | "*/") {
        return String::new();
    }
    if let Some(rest) = fragment.strip_prefix("/*") {
        fragment = rest.trim();
    }
    if let Some(rest) = fragment.strip_prefix('*') {
        fragment = rest.trim();
    }
    if let Some(rest) = fragment.strip_suffix("*/") {
        fragment = rest.trim();
    }
    if fragment == "/" {
        String::new()
    } else {
        fragment.to_string()
    }
}

fn latest_patch_authoring_response(response: &str) -> Option<String> {
    let mut saw_heading = false;
    let mut current_label: Option<String> = None;
    let mut current_lines = Vec::new();
    let mut selected: Option<String> = None;
    let finalize_section =
        |label: Option<&str>, lines: &mut Vec<String>, selected: &mut Option<String>| {
            let content = lines.join("\n").trim().to_string();
            if label.is_some_and(is_patch_authoring_stage) && !content.is_empty() {
                *selected = Some(content);
            }
            lines.clear();
        };
    for line in response.lines() {
        if let Some(label) = line.strip_prefix("## ") {
            let label = label.trim();
            if is_codex_stage_heading(label) {
                saw_heading = true;
                finalize_section(current_label.as_deref(), &mut current_lines, &mut selected);
                current_label = Some(label.to_string());
                continue;
            }
        }
        current_lines.push(line.to_string());
    }
    finalize_section(current_label.as_deref(), &mut current_lines, &mut selected);
    if selected.is_some() {
        selected
    } else if saw_heading {
        None
    } else {
        let trimmed = response.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }
}

fn is_patch_authoring_stage(label: &str) -> bool {
    label == "Patch Pass" || label.starts_with("Refinement Pass ")
}

fn is_codex_stage_heading(label: &str) -> bool {
    label == "Plan Pass"
        || label == "Patch Pass"
        || label.starts_with("Review Pass ")
        || label.starts_with("Refinement Pass ")
        || label == "Workflow Note"
}

fn meaningful_patch_response(response: &str) -> Option<String> {
    response
        .split("\n\n")
        .map(str::trim)
        .find(|paragraph| {
            !paragraph.is_empty()
                && !paragraph.starts_with("## ")
                && !paragraph.starts_with("[Patch Pass]")
                && !paragraph.starts_with("[Review Pass]")
                && !paragraph.starts_with("[Refinement Pass]")
                && !paragraph.starts_with("Subject:")
        })
        .map(str::to_string)
}

fn extract_labeled_line(text: &str, prefix: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.trim()
            .strip_prefix(prefix)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

fn extract_markdown_section_raw(text: &str, heading: &str) -> Option<String> {
    let mut in_section = false;
    let mut lines = Vec::new();
    for line in text.lines() {
        if let Some(current_heading) = line.strip_prefix("## ") {
            let current_heading = current_heading.trim();
            if in_section {
                break;
            }
            if current_heading == heading {
                in_section = true;
            }
            continue;
        }
        if in_section {
            lines.push(line);
        }
    }
    let content = lines.join("\n");
    if content.trim().is_empty() {
        None
    } else {
        Some(content.trim().to_string())
    }
}

fn normalize_patch_response_text(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_validation_notes(section: &str) -> Vec<String> {
    let bullet_notes = section
        .lines()
        .map(str::trim)
        .filter_map(|line| {
            line.strip_prefix("- ")
                .or_else(|| line.strip_prefix("* "))
                .map(str::trim)
        })
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if !bullet_notes.is_empty() {
        bullet_notes
    } else {
        let normalized = normalize_patch_response_text(section);
        if normalized.is_empty() {
            Vec::new()
        } else {
            vec![normalized]
        }
    }
}

fn render_patch_response_markup(text: &str) -> String {
    let mut blocks = Vec::new();
    let mut paragraph_lines = Vec::new();
    let mut list_items = Vec::new();
    let flush_paragraph = |blocks: &mut Vec<String>, paragraph_lines: &mut Vec<String>| {
        if paragraph_lines.is_empty() {
            return;
        }
        let content = paragraph_lines
            .iter()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if !content.is_empty() {
            blocks.push(format!(
                "<p class=\"issue-summary\">{}</p>",
                html_escape(&content)
            ));
        }
        paragraph_lines.clear();
    };
    let flush_list = |blocks: &mut Vec<String>, list_items: &mut Vec<String>| {
        if list_items.is_empty() {
            return;
        }
        let items = list_items
            .iter()
            .map(|item| format!("<li>{}</li>", html_escape(item)))
            .collect::<Vec<_>>()
            .join("");
        blocks.push(format!("<ul class=\"attempt-list\">{items}</ul>"));
        list_items.clear();
    };

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            flush_paragraph(&mut blocks, &mut paragraph_lines);
            flush_list(&mut blocks, &mut list_items);
            continue;
        }
        if let Some(item) = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "))
        {
            flush_paragraph(&mut blocks, &mut paragraph_lines);
            list_items.push(item.trim().to_string());
            continue;
        }
        if !list_items.is_empty() {
            if let Some(last) = list_items.last_mut() {
                last.push(' ');
                last.push_str(trimmed);
            }
            continue;
        }
        paragraph_lines.push(trimmed.to_string());
    }

    flush_paragraph(&mut blocks, &mut paragraph_lines);
    flush_list(&mut blocks, &mut list_items);

    if blocks.is_empty() {
        format!(
            "<p class=\"issue-summary\">{}</p>",
            html_escape(&normalize_patch_response_text(text))
        )
    } else {
        blocks.join("")
    }
}

fn lower_sentence_fragment(text: &str) -> String {
    let trimmed = text.trim().trim_end_matches('.');
    let mut chars = trimmed.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut lowered = first.to_lowercase().collect::<String>();
    lowered.push_str(chars.as_str());
    lowered
}

fn is_informative_patch_summary(summary: &str) -> bool {
    let lowered = summary.to_ascii_lowercase();
    ![
        "patch proposal created locally",
        "review it and submit it upstream",
        "diagnosis report and patch proposal were created locally",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

fn ensure_sentence(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if matches!(trimmed.chars().last(), Some('.' | '!' | '?')) {
        trimmed.to_string()
    } else {
        format!("{trimmed}.")
    }
}

fn truncate_patch_subject(subject: &str, max_len: usize) -> String {
    if subject.len() <= max_len {
        return subject.to_string();
    }
    let mut boundary = max_len.saturating_sub(1);
    while boundary > 0 && !subject.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let truncated = subject[..boundary].trim_end();
    format!("{truncated}…")
}

fn format_patch_email_date(timestamp: &str) -> String {
    DateTime::parse_from_rfc3339(timestamp)
        .map(|value| value.to_rfc2822())
        .unwrap_or_else(|_| timestamp.to_string())
}

fn published_session_from_attempt_details(details: &Value) -> Option<PublishedAttemptSession> {
    details
        .get("published_session")
        .cloned()
        .and_then(|value| serde_json::from_value::<PublishedAttemptSession>(value).ok())
}

fn attempt_response_text(attempt: &PatchAttempt) -> Option<&str> {
    attempt
        .details
        .get("published_session")
        .and_then(|value| value.get("response"))
        .and_then(Value::as_str)
}

fn attempt_diff_text(attempt: &PatchAttempt) -> Option<&str> {
    attempt
        .details
        .get("published_session")
        .and_then(|value| value.get("diff"))
        .and_then(Value::as_str)
        .filter(|diff| !diff.trim().is_empty())
}

fn attempt_has_public_diff(attempt: &PatchAttempt) -> bool {
    attempt_diff_text(attempt).is_some()
}

fn response_marks_successful_triage(response: &str) -> bool {
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

fn inferred_triage_reason(attempt: &PatchAttempt) -> Option<String> {
    if let Some(reason) = attempt
        .details
        .get("report_only_reason")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        return Some(reason.to_string());
    }
    let response = attempt_response_text(attempt)?;
    if !response_marks_successful_triage(response) {
        return None;
    }
    if response.contains("outside this repository") || response.contains("outside this source tree")
    {
        return Some("likely-external-root-cause".to_string());
    }
    Some("no-safe-local-change".to_string())
}

fn canonical_triage_summary(summary: &str) -> String {
    summary
        .replace(
            "A diagnosis report and patch proposal were created locally.",
            "A diagnosis report and external handoff were created locally.",
        )
        .replace(
            "Patch proposal created locally. Review it and submit it upstream if it looks correct.",
            "A diagnosis and external handoff were created locally. Review it and report it to the likely owner.",
        )
}

fn canonicalize_patch_attempt(mut attempt: PatchAttempt) -> PatchAttempt {
    attempt.summary = canonical_attempt_summary_text(&attempt.summary);
    if attempt.state != "ready" {
        return attempt;
    }
    if attempt_has_public_diff(&attempt) {
        attempt.outcome = "patch".to_string();
        return attempt;
    }
    if let Some(reason) = inferred_triage_reason(&attempt) {
        attempt.outcome = "triage".to_string();
        attempt.summary = canonical_triage_summary(&attempt.summary);
        if let Some(object) = attempt.details.as_object_mut() {
            object
                .entry("report_only_reason".to_string())
                .or_insert_with(|| json!(reason));
        }
        return attempt;
    }
    if attempt.outcome == "patch" {
        attempt.outcome = "report".to_string();
    }
    attempt
}

fn canonical_attempt_summary_text(summary: &str) -> String {
    summary
        .replace("unknown userspace loop loop", "unclassified userspace loop")
        .replace(
            "unknown uninterruptible wait wait",
            "unclassified uninterruptible wait",
        )
        .replace("a unclassified", "an unclassified")
        .replace("a unknown", "an unknown")
}

fn text_describes_local_codex_auth_issue(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("codex auth lease has expired")
        || lower.contains("codex auth lease is paused")
        || lower.contains("current codex auth lease has expired")
        || lower.contains("current codex auth lease is paused")
        || lower.contains("auto-paused after 3 recent codex failures")
}

fn hidden_local_auth_bookkeeping_attempt(attempt: &PatchAttempt) -> bool {
    if !matches!(attempt.outcome.as_str(), "report" | "triage") || attempt.state != "ready" {
        return false;
    }
    if attempt
        .details
        .get("report_only_reason")
        .and_then(Value::as_str)
        == Some("codex-auth-unavailable")
    {
        return true;
    }
    if attempt
        .details
        .get("automatic_patch_blocker_kind")
        .and_then(Value::as_str)
        == Some("codex-auth")
    {
        return true;
    }
    for key in ["patch_error", "workspace_error", "error"] {
        if attempt
            .details
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(text_describes_local_codex_auth_issue)
        {
            return true;
        }
    }
    text_describes_local_codex_auth_issue(&attempt.summary)
}

fn hidden_kernel_workspace_attempt(attempt: &PatchAttempt) -> bool {
    if !matches!(attempt.outcome.as_str(), "report" | "triage") {
        return false;
    }
    let report_only_reason = attempt
        .details
        .get("report_only_reason")
        .and_then(Value::as_str);
    if report_only_reason != Some("workspace-acquisition")
        && !attempt
            .summary
            .contains("no patchable workspace was available")
    {
        return false;
    }
    if attempt
        .details
        .get("workspace_classification")
        .and_then(Value::as_str)
        == Some("kernel-source-unavailable")
    {
        return true;
    }
    if attempt
        .details
        .get("diagnosis")
        .and_then(|value| value.get("profile_target"))
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .is_some_and(is_kernelish_target_name)
    {
        return true;
    }
    attempt
        .details
        .get("handoff")
        .and_then(|value| value.get("target"))
        .and_then(Value::as_str)
        .is_some_and(is_kernelish_package_name)
}

fn text_describes_internal_storage_issue(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("foreign key constraint failed")
        || lower.contains("failed to create diagnostic report")
        || lower.contains("failed to create diagnostic report: permission denied")
        || lower.contains("sqlitefailure")
        || lower.contains("database disk image is malformed")
}

fn hidden_internal_error_attempt(attempt: &PatchAttempt) -> bool {
    if attempt
        .details
        .get("internal_only")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return true;
    }
    if attempt
        .details
        .get("internal_error")
        .and_then(Value::as_str)
        .is_some_and(text_describes_internal_storage_issue)
    {
        return true;
    }
    if attempt
        .details
        .get("error")
        .and_then(Value::as_str)
        .is_some_and(text_describes_internal_storage_issue)
    {
        return true;
    }
    text_describes_internal_storage_issue(&attempt.summary)
}

fn publicly_visible_attempt(attempt: &PatchAttempt) -> bool {
    !hidden_local_auth_bookkeeping_attempt(attempt)
        && !hidden_kernel_workspace_attempt(attempt)
        && !hidden_internal_error_attempt(attempt)
}

fn canonicalize_worker_result_envelope(mut result: WorkerResultEnvelope) -> WorkerResultEnvelope {
    result.attempt = canonicalize_patch_attempt(result.attempt);
    result
}

fn public_triage_handoff_from_attempt(
    attempt: &PatchAttempt,
    published_session: Option<&PublishedAttemptSession>,
) -> Option<PublicTriageHandoff> {
    let reason = inferred_triage_reason(attempt)?;
    let target = attempt
        .details
        .get("handoff")
        .and_then(|value| value.get("target"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| infer_external_target_from_response(published_session?.response.as_deref()?))
        .unwrap_or_else(|| {
            "external dependency or workload outside the current source tree".to_string()
        });
    let report_url = attempt
        .details
        .get("handoff")
        .and_then(|value| value.get("report_url"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .filter(|value| !value.trim().is_empty());
    let next_steps = attempt
        .details
        .get("handoff")
        .and_then(|value| value.get("next_steps"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| default_triage_next_steps(&target));
    Some(PublicTriageHandoff {
        reason,
        target,
        report_url,
        next_steps,
    })
}

fn infer_external_target_from_response(response: &str) -> Option<String> {
    let shared_object_re =
        Regex::new(r"\b([A-Za-z0-9_.+-]+\.so)\b").expect("valid shared object regex");
    shared_object_re
        .captures(response)
        .and_then(|captures| captures.get(1))
        .map(|value| format!("module `{}` or the workload driving it", value.as_str()))
}

fn default_triage_next_steps(target: &str) -> Vec<String> {
    vec![
        format!(
            "Confirm the hotspot still points at {target} with a fresh perf sample before filing the bug."
        ),
        "Capture the actual hot backend or child process rather than the parent service wrapper if the issue recurs.".to_string(),
        format!(
            "Map {target} to its owning package or project and file an upstream or distro bug with the summarized evidence."
        ),
        "If the owner is still unclear, collect another short strace plus `/proc/<pid>/maps` at the moment of the spike.".to_string(),
    ]
}

#[derive(Debug, Clone)]
struct PublicIssueFields {
    title: String,
    summary: String,
    visible: bool,
}

fn cluster_key_for(item: &SharedOpportunity) -> String {
    match item.finding.kind.as_str() {
        "crash" => normalized_crash_cluster_key(item),
        "hotspot" => normalized_hotspot_cluster_key(item),
        "warning" => normalized_warning_cluster_key(item),
        "investigation" => normalized_investigation_cluster_key(item),
        _ => hash_text(format!(
            "{}|{}|{}|{}",
            item.finding.kind,
            item.finding.package_name.as_deref().unwrap_or("-"),
            item.opportunity.ecosystem.as_deref().unwrap_or("-"),
            sanitize_public_text(&item.opportunity.summary),
        )),
    }
}

fn normalized_hotspot_cluster_key(item: &SharedOpportunity) -> String {
    let details = &item.finding.details;
    let target = normalized_hotspot_target_name(item);
    let dso = normalized_hotspot_dso(details);
    let symbol = details
        .get("hot_path_symbol")
        .and_then(Value::as_str)
        .map(normalized_perf_hotspot_symbol)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| sanitize_public_text(&item.opportunity.summary));
    hash_text(format!(
        "hotspot|{}|{}|{}|{}|{}",
        item.finding.package_name.as_deref().unwrap_or("-"),
        item.opportunity.ecosystem.as_deref().unwrap_or("-"),
        target,
        dso,
        symbol,
    ))
}

fn normalized_crash_cluster_key(item: &SharedOpportunity) -> String {
    let signal = item
        .finding
        .details
        .get("signal_name")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            item.finding
                .details
                .get("signal_number")
                .and_then(Value::as_i64)
                .map(|value| value.to_string())
        })
        .unwrap_or_else(|| "-".to_string());
    let executable = item
        .finding
        .details
        .get("executable")
        .and_then(Value::as_str)
        .map(file_name_or_self)
        .or_else(|| item.finding.package_name.as_deref())
        .unwrap_or(item.opportunity.title.as_str());
    let stack_signature = normalized_primary_stack_signature(item)
        .unwrap_or_else(|| sanitize_public_text(&item.opportunity.summary));
    hash_text(format!(
        "crash|{}|{}|{}|{}|{}",
        item.finding.package_name.as_deref().unwrap_or("-"),
        item.opportunity.ecosystem.as_deref().unwrap_or("-"),
        executable,
        signal,
        stack_signature,
    ))
}

fn normalized_warning_cluster_key(item: &SharedOpportunity) -> String {
    if item.finding.title == "Kernel warning" {
        let module = item
            .finding
            .details
            .get("kernel_module")
            .and_then(Value::as_str)
            .unwrap_or("-");
        let raw_line = item
            .finding
            .details
            .get("line")
            .and_then(Value::as_str)
            .unwrap_or(item.finding.summary.as_str());
        return hash_text(format!(
            "warning|kernel|{}|{}",
            module,
            normalize_kernel_warning_message(raw_line),
        ));
    }
    if matches!(
        item.finding
            .details
            .get("subsystem")
            .and_then(Value::as_str),
        Some("apparmor")
    ) {
        let profile = item
            .finding
            .details
            .get("profile")
            .and_then(Value::as_str)
            .unwrap_or("-");
        let operation = item
            .finding
            .details
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or("-");
        let class = item
            .finding
            .details
            .get("class")
            .and_then(Value::as_str)
            .unwrap_or("-");
        let name = item
            .finding
            .details
            .get("name")
            .and_then(Value::as_str)
            .map(normalize_proc_path)
            .unwrap_or_else(|| "-".to_string());
        return hash_text(format!(
            "warning|apparmor|{}|{}|{}|{}",
            profile, operation, class, name,
        ));
    }
    hash_text(format!(
        "warning|{}|{}|{}",
        item.finding.title,
        item.finding.package_name.as_deref().unwrap_or("-"),
        sanitize_public_text(&item.finding.summary),
    ))
}

fn normalized_investigation_cluster_key(item: &SharedOpportunity) -> String {
    let subsystem = item
        .finding
        .details
        .get("subsystem")
        .and_then(Value::as_str)
        .unwrap_or("-");
    match subsystem {
        "stuck-process" => {
            let target = normalized_investigation_target_name(item);
            let classification = item
                .finding
                .details
                .get("loop_classification")
                .and_then(Value::as_str)
                .unwrap_or("-");
            let wchan = item
                .finding
                .details
                .get("wchan")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("-");
            let stack_signature = item
                .finding
                .details
                .get("stack_excerpt")
                .and_then(Value::as_str)
                .and_then(|excerpt| excerpt.lines().next())
                .map(normalize_stack_frame)
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "-".to_string());
            hash_text(format!(
                "investigation|stuck-process|{}|{}|{}|{}",
                target, classification, wchan, stack_signature,
            ))
        }
        "runaway-process" => {
            let target = normalized_investigation_target_name(item);
            let classification = item
                .finding
                .details
                .get("loop_classification")
                .and_then(Value::as_str)
                .unwrap_or("-");
            let hot_symbol = item
                .finding
                .details
                .get("top_hot_symbols")
                .and_then(Value::as_array)
                .and_then(|symbols| symbols.first())
                .and_then(Value::as_str)
                .map(normalize_stack_frame)
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "-".to_string());
            let dominant_sequence = item
                .finding
                .details
                .get("dominant_sequence")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .take(3)
                        .collect::<Vec<_>>()
                        .join("|")
                })
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "-".to_string());
            hash_text(format!(
                "investigation|runaway-process|{}|{}|{}|{}",
                target, classification, hot_symbol, dominant_sequence,
            ))
        }
        "oom-kill" => {
            let target = normalized_investigation_target_name(item);
            let constraint = item
                .finding
                .details
                .get("constraint")
                .and_then(Value::as_str)
                .unwrap_or("-");
            let cgroup_target = item
                .finding
                .details
                .get("task_memcg_target")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("-");
            hash_text(format!(
                "investigation|oom-kill|{}|{}|{}|{}",
                target,
                item.finding.package_name.as_deref().unwrap_or("-"),
                cgroup_target,
                constraint,
            ))
        }
        "desktop-resume" => {
            let target = normalized_investigation_target_name(item);
            let driver = item
                .finding
                .details
                .get("driver")
                .and_then(Value::as_str)
                .unwrap_or("-");
            let session_type = item
                .finding
                .details
                .get("session_type")
                .and_then(Value::as_str)
                .unwrap_or("-");
            let display_manager = item
                .finding
                .details
                .get("display_manager")
                .and_then(Value::as_str)
                .unwrap_or("-");
            hash_text(format!(
                "investigation|desktop-resume|{}|{}|{}|{}",
                target, driver, session_type, display_manager,
            ))
        }
        "desktop-graphics-session" => {
            let target = normalized_investigation_target_name(item);
            let driver = item
                .finding
                .details
                .get("driver")
                .and_then(Value::as_str)
                .unwrap_or("-");
            let session_type = item
                .finding
                .details
                .get("session_type")
                .and_then(Value::as_str)
                .unwrap_or("-");
            let compositor = item
                .finding
                .details
                .get("compositor")
                .and_then(Value::as_str)
                .unwrap_or("-");
            hash_text(format!(
                "investigation|desktop-graphics-session|{}|{}|{}|{}",
                target, driver, session_type, compositor,
            ))
        }
        _ => hash_text(format!(
            "investigation|{}|{}|{}|{}",
            subsystem,
            item.finding.package_name.as_deref().unwrap_or("-"),
            item.opportunity.ecosystem.as_deref().unwrap_or("-"),
            sanitize_public_text(&item.opportunity.summary),
        )),
    }
}

fn normalized_primary_stack_signature(item: &SharedOpportunity) -> Option<String> {
    let frames = item
        .finding
        .details
        .get("primary_stack")
        .and_then(Value::as_array)?;
    let normalized = frames
        .iter()
        .filter_map(Value::as_str)
        .map(normalize_stack_frame)
        .filter(|frame| !frame.is_empty())
        .take(6)
        .collect::<Vec<_>>();
    (!normalized.is_empty()).then(|| normalized.join("|"))
}

fn build_public_issue_fields(item: &SharedOpportunity) -> PublicIssueFields {
    if let Some(fields) = hotspot_public_issue_fields(item) {
        return fields;
    }
    if let Some(fields) = investigation_public_issue_fields(item) {
        return fields;
    }
    PublicIssueFields {
        title: sanitize_public_text(&item.opportunity.title),
        summary: sanitize_public_text(&item.opportunity.summary),
        visible: is_publicly_visible(item),
    }
}

fn hotspot_public_issue_fields(item: &SharedOpportunity) -> Option<PublicIssueFields> {
    if item.finding.kind != "hotspot" {
        return None;
    }
    let details = &item.finding.details;
    let target = normalized_hotspot_target_name(item);
    let symbol = details
        .get("hot_path_symbol")
        .and_then(Value::as_str)
        .map(normalized_perf_hotspot_symbol)
        .filter(|value| !value.is_empty())?;
    let dso = normalized_hotspot_dso(details);
    let symbol_display = symbol.replace('-', " ");
    let title = if dso == "-" {
        format!("CPU hotspot in {target}: {symbol_display}")
    } else {
        format!("CPU hotspot in {target}: {symbol_display} in {dso}")
    };
    Some(PublicIssueFields {
        title,
        summary: sanitize_public_text(&item.opportunity.summary),
        visible: is_publicly_visible(item),
    })
}

fn investigation_public_issue_fields(item: &SharedOpportunity) -> Option<PublicIssueFields> {
    if item.finding.kind != "investigation" {
        return None;
    }
    let subsystem = item
        .finding
        .details
        .get("subsystem")
        .and_then(Value::as_str)?;
    match subsystem {
        "stuck-process" => {
            let target = normalized_investigation_target_name(item);
            let classification = item
                .finding
                .details
                .get("loop_classification")
                .and_then(Value::as_str)
                .unwrap_or("unknown-uninterruptible-wait")
                .replace('-', " ");
            let wait_point = item
                .finding
                .details
                .get("wchan")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("an unknown wait point");
            Some(PublicIssueFields {
                title: format!("Stuck D-state investigation for {target}"),
                summary: format!(
                    "{} shows a repeated `D`-state wait, likely blocked in {} via {}.",
                    target, classification, wait_point
                ),
                visible: is_publicly_visible(item),
            })
        }
        "oom-kill" => {
            let target = normalized_investigation_target_name(item);
            let anon_rss_mib = item
                .finding
                .details
                .get("anon_rss_kb")
                .and_then(Value::as_u64)
                .map(|value| value as f64 / 1024.0)
                .unwrap_or_default();
            let scope = item
                .finding
                .details
                .get("task_memcg_target")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(|value| format!(" in `{value}`"))
                .unwrap_or_default();
            Some(PublicIssueFields {
                title: format!("OOM kill investigation for {target}"),
                summary: format!(
                    "{target} was killed by the kernel OOM killer after reaching about {:.0} MiB anonymous RSS{}.",
                    anon_rss_mib, scope
                ),
                visible: is_publicly_visible(item),
            })
        }
        "desktop-resume" => {
            let target = normalized_investigation_target_name(item);
            let display_manager = item
                .finding
                .details
                .get("display_manager")
                .and_then(Value::as_str)
                .unwrap_or("the display manager");
            let crashed = item
                .finding
                .details
                .get("crashed_processes")
                .and_then(Value::as_array)
                .map(|processes| {
                    processes
                        .iter()
                        .filter_map(Value::as_str)
                        .take(4)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "desktop processes".to_string());
            Some(PublicIssueFields {
                title: format!("Desktop resume failure investigation for {target}"),
                summary: format!(
                    "After suspend/resume, {target} failed: {crashed} crashed after GPU/display errors, and {display_manager} restarted the display stack."
                ),
                visible: is_publicly_visible(item),
            })
        }
        "desktop-graphics-session" => {
            let target = normalized_investigation_target_name(item);
            let apps = item
                .finding
                .details
                .get("affected_apps")
                .and_then(Value::as_array)
                .map(|apps| {
                    apps.iter()
                        .filter_map(Value::as_str)
                        .take(5)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "multiple desktop apps".to_string());
            Some(PublicIssueFields {
                title: format!("Desktop graphics/session failure investigation for {target}"),
                summary: format!(
                    "Repeated EGL/Mesa/Qt desktop warnings affected {apps} on {target}, suggesting a shared compositor or graphics-session failure."
                ),
                visible: is_publicly_visible(item),
            })
        }
        _ => None,
    }
}

fn is_publicly_visible(item: &SharedOpportunity) -> bool {
    match item.finding.kind.as_str() {
        "crash" => true,
        "hotspot" => true,
        "investigation" => true,
        "complaint" => false,
        "warning" => {
            if item.finding.title == "Kernel warning" {
                return false;
            }
            if matches!(
                item.finding
                    .details
                    .get("subsystem")
                    .and_then(Value::as_str),
                Some("apparmor")
            ) {
                return false;
            }
            item.finding.package_name.is_some() || item.opportunity.ecosystem.is_some()
        }
        _ => true,
    }
}

fn sanitize_public_text(raw: &str) -> String {
    let mut text = strip_syslog_prefix(raw);
    if text.is_empty() {
        text = raw.trim().to_string();
    }
    text = sanitize_bracketed_paths(&text);
    text = normalize_proc_path(&text);
    let home_re = Regex::new(r"/home/[^/\s]+").expect("valid home path regex");
    text = home_re.replace_all(&text, "/home/<user>").to_string();
    let pid_re = Regex::new(r"\bpid \d+\b").expect("valid pid regex");
    text = pid_re.replace_all(&text, "pid <pid>").to_string();
    canonical_attempt_summary_text(&text)
}

fn strip_syslog_prefix(raw: &str) -> String {
    if let Some((_, message)) = raw.split_once(" kernel: ") {
        return message.trim().to_string();
    }
    if let Some((_, message)) = raw.split_once("]: ") {
        return message.trim().to_string();
    }
    raw.trim().to_string()
}

fn sanitize_bracketed_paths(raw: &str) -> String {
    let bracketed_path_re = Regex::new(r"\[([^\]]+/)?([^/\]]+)\]").expect("valid path regex");
    bracketed_path_re.replace_all(raw, "[$2]").to_string()
}

fn normalize_proc_path(raw: &str) -> String {
    let proc_pid_re = Regex::new(r"/proc/\d+").expect("valid /proc pid regex");
    proc_pid_re.replace_all(raw, "/proc/<pid>").to_string()
}

fn normalize_deleted_file_marker(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("(deleted) ")
        .trim_end_matches(" (deleted)")
        .trim()
        .to_string()
}

fn normalized_hotspot_target_name(item: &SharedOpportunity) -> String {
    item.finding
        .details
        .get("profile_target")
        .and_then(|value| value.get("path"))
        .and_then(Value::as_str)
        .map(file_name_or_self)
        .or_else(|| {
            item.finding
                .details
                .get("profile_target")
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
        })
        .or(item.finding.artifact_name.as_deref())
        .map(normalize_deleted_file_marker)
        .filter(|value| !value.is_empty())
        .or_else(|| item.finding.package_name.clone())
        .unwrap_or_else(|| sanitize_public_text(&item.opportunity.title))
}

fn normalized_hotspot_dso(details: &Value) -> String {
    details
        .get("hot_path_dso_path")
        .and_then(Value::as_str)
        .map(file_name_or_self)
        .or_else(|| details.get("hot_path_dso").and_then(Value::as_str))
        .map(normalize_deleted_file_marker)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "-".to_string())
}

fn normalized_perf_hotspot_symbol(raw: &str) -> String {
    let mut normalized = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    while let Some(stripped) = normalized.strip_suffix(" - -") {
        normalized = stripped.trim_end().to_string();
    }
    if let Some(stripped) = normalized.strip_prefix("(deleted) [.] ") {
        normalized = stripped.trim_start().to_string();
    }
    let bare_address_re = Regex::new(r"^0x[0-9a-fA-F]+$").expect("valid perf address regex");
    let thread_address_re =
        Regex::new(r"^tid\s+\d+\s+\[.\]\s+0x[0-9a-fA-F]+$").expect("valid perf JIT address regex");
    let deleted_address_re =
        Regex::new(r"\(deleted\)\s+\[.\]\s+0x[0-9a-fA-F]+$").expect("valid deleted address regex");
    if bare_address_re.is_match(&normalized)
        || thread_address_re.is_match(&normalized)
        || deleted_address_re.is_match(&normalized)
    {
        return "unresolved-offset".to_string();
    }
    normalize_stack_frame(&normalized)
}

fn normalize_stack_frame(frame: &str) -> String {
    let offset_re = Regex::new(r"\+0x[0-9a-fA-F]+").expect("valid frame offset regex");
    sanitize_public_text(&offset_re.replace_all(frame, "").to_string())
}

fn normalized_investigation_target_name(item: &SharedOpportunity) -> String {
    let path_target = item
        .finding
        .details
        .get("profile_target")
        .and_then(|value| value.get("path"))
        .and_then(Value::as_str)
        .map(file_name_or_self)
        .filter(|value| !value.trim().is_empty());
    let named_target = item
        .finding
        .details
        .get("profile_target")
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .or_else(|| item.finding.artifact_name.as_deref())
        .filter(|value| !value.trim().is_empty())
        .map(normalize_kernel_worker_target_name);
    path_target
        .map(ToString::to_string)
        .or(named_target)
        .or_else(|| item.finding.package_name.clone())
        .unwrap_or_else(|| sanitize_public_text(&item.opportunity.title))
}

fn normalized_investigation_target_name_from_value(item: &Value) -> Option<String> {
    let finding = item.get("finding")?;
    let details = finding.get("details");
    let path_target = details
        .and_then(|details| details.get("profile_target"))
        .and_then(|target| target.get("path"))
        .and_then(Value::as_str)
        .map(file_name_or_self)
        .filter(|value| !value.trim().is_empty());
    let named_target = details
        .and_then(|details| details.get("profile_target"))
        .and_then(|target| target.get("name"))
        .and_then(Value::as_str)
        .or_else(|| finding.get("artifact_name").and_then(Value::as_str))
        .filter(|value| !value.trim().is_empty())
        .map(normalize_kernel_worker_target_name);
    path_target
        .map(ToString::to_string)
        .or(named_target)
        .or_else(|| {
            finding
                .get("package_name")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .or_else(|| {
            item.get("opportunity")
                .and_then(|opportunity| opportunity.get("title"))
                .and_then(Value::as_str)
                .map(sanitize_public_text)
        })
}

fn normalize_kernel_worker_target_name(raw: &str) -> String {
    let trimmed = raw.trim();
    if !trimmed.starts_with("kworker") {
        return sanitize_public_text(trimmed);
    }
    if let Some((_, suffix)) = trimmed.split_once('+') {
        let suffix = suffix.trim();
        if !suffix.is_empty() {
            return format!("kworker+{}", sanitize_public_text(suffix));
        }
    }
    "kworker".to_string()
}

fn normalize_kernel_warning_message(raw: &str) -> String {
    let mut text = strip_syslog_prefix(raw);
    let pci_re =
        Regex::new(r"\b[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9]\b").expect("valid pci regex");
    text = pci_re.replace_all(&text, "<pci>").to_string();
    let usb_path_re =
        Regex::new(r"\busb(?:\s+usb)?\s+\d+-[\d.:-]+(?:-port\d+)?").expect("valid usb path regex");
    text = usb_path_re.replace_all(&text, "usb <path>").to_string();
    let address_re = Regex::new(r"\baddress \d+\b").expect("valid address regex");
    text = address_re.replace_all(&text, "address <n>").to_string();
    let number_fields_re = Regex::new(
        r"\b(missed_beacons|missed_beacons_since_rx|process|callbacks suppressed):?\d+\b",
    )
    .expect("valid number field regex");
    text = number_fields_re.replace_all(&text, "$1:<n>").to_string();
    let callbacks_re = Regex::new(r"\b\d+ callbacks suppressed\b").expect("valid callbacks regex");
    text = callbacks_re
        .replace_all(&text, "<n> callbacks suppressed")
        .to_string();
    normalize_proc_path(&text)
}

fn build_public_technical_snapshot(item: &SharedOpportunity) -> Option<PublicTechnicalSnapshot> {
    match item.finding.kind.as_str() {
        "crash" => build_public_crash_snapshot(item),
        "investigation" => build_public_investigation_snapshot(item),
        _ => None,
    }
}

fn format_package_highlight(name: Option<String>, version: Option<String>) -> Option<String> {
    match (name, version) {
        (Some(n), Some(v)) => Some(format!("Package: {n} {v}")),
        (Some(n), None) => Some(format!("Package: {n}")),
        _ => None,
    }
}

fn push_env_highlights(details: &Value, highlights: &mut Vec<String>) {
    let pkg = details
        .get("package_name")
        .or_else(|| {
            details
                .get("profile_target")
                .and_then(|t| t.get("package_name"))
        })
        .and_then(Value::as_str)
        .map(sanitize_public_text);
    let ver = details
        .get("installed_package_version")
        .and_then(Value::as_str)
        .map(sanitize_public_text);
    if let Some(h) = format_package_highlight(pkg, ver) {
        highlights.push(h);
    }
    if let Some(r) = details.get("kernel_release").and_then(Value::as_str) {
        highlights.push(format!("Kernel: {}", sanitize_public_text(r)));
    }
    let id = details.get("distro_id").and_then(Value::as_str);
    let ver = details.get("distro_version_id").and_then(Value::as_str);
    match (id, ver) {
        (Some(id), Some(ver)) => {
            highlights.push(format!(
                "Distribution: {}",
                sanitize_public_text(&format!("{id} {ver}"))
            ));
        }
        (Some(id), None) => {
            highlights.push(format!("Distribution: {}", sanitize_public_text(id)));
        }
        _ => {}
    }
}

fn build_public_crash_snapshot(item: &SharedOpportunity) -> Option<PublicTechnicalSnapshot> {
    let details = &item.finding.details;
    let frames = sanitize_snapshot_frames(
        details
            .get("primary_stack")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        14,
    );
    if frames.is_empty() {
        return None;
    }
    let signal = details
        .get("signal_name")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            details
                .get("signal_number")
                .and_then(Value::as_i64)
                .map(|value| format!("signal {value}"))
        });
    let executable = details
        .get("executable")
        .and_then(Value::as_str)
        .map(file_name_or_self)
        .or_else(|| item.finding.package_name.as_deref())
        .map(sanitize_public_text);
    let mut highlights = Vec::new();
    if let Some(executable) = executable {
        highlights.push(format!("Process: {executable}"));
    }
    if let Some(signal) = signal {
        highlights.push(format!("Signal: {}", sanitize_public_text(&signal)));
    }
    push_env_highlights(details, &mut highlights);
    Some(PublicTechnicalSnapshot {
        title: "Crashing thread stack trace".to_string(),
        summary:
            "Fixer kept the most informative crashing thread and shows the top stack frames below."
                .to_string(),
        frames,
        highlights,
    })
}

fn build_public_investigation_snapshot(
    item: &SharedOpportunity,
) -> Option<PublicTechnicalSnapshot> {
    let details = &item.finding.details;
    let subsystem = details
        .get("subsystem")
        .and_then(Value::as_str)
        .unwrap_or("runaway-process");
    match subsystem {
        "runaway-process" => {
            let representative_frames = details
                .get("representative_backtraces")
                .and_then(Value::as_array)
                .and_then(|items| items.first())
                .and_then(Value::as_object)
                .and_then(|trace| trace.get("frames"))
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let frames = sanitize_snapshot_frames(
                if representative_frames.is_empty() {
                    details
                        .get("stack_excerpt")
                        .and_then(Value::as_str)
                        .into_iter()
                        .flat_map(|excerpt| excerpt.lines())
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                } else {
                    representative_frames
                },
                12,
            );
            let mut highlights = Vec::new();
            if let Some(command_line) = details.get("command_line").and_then(Value::as_str) {
                highlights.push(format!("Command: {}", sanitize_public_text(command_line)));
            }
            if let Some(explanation) = details
                .get("loop_explanation")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            {
                highlights.push(format!(
                    "Why Fixer classified it this way: {}",
                    sanitize_public_text(explanation)
                ));
            }
            if let Some(summary) = details
                .get("thread_backtrace_summary")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            {
                highlights.push(format!("Thread summary: {}", sanitize_public_text(summary)));
            } else if let Some(wchan) = details.get("wchan").and_then(Value::as_str) {
                highlights.push(format!("Wait site: {}", normalize_stack_frame(wchan)));
            }
            if let Some(signals) = details
                .get("lock_contention_signals")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .take(3)
                        .map(sanitize_public_text)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|value| !value.is_empty())
            {
                highlights.push(format!("Contention signals: {signals}"));
            } else if let Some(symbol) = details
                .get("hot_path_symbol")
                .and_then(Value::as_str)
                .map(normalize_stack_frame)
            {
                let percent = details
                    .get("hot_path_percent")
                    .and_then(Value::as_f64)
                    .map(|value| format!("{value:.2}% sampled CPU"))
                    .unwrap_or_else(|| "sampled hot path".to_string());
                highlights.push(format!("Hot path: {symbol} ({percent})"));
            } else if let Some(symbol) = details
                .get("top_hot_symbols")
                .and_then(Value::as_array)
                .and_then(|items| items.first())
                .and_then(Value::as_str)
            {
                highlights.push(format!("Hot path: {}", normalize_stack_frame(symbol)));
            }
            if let Some(sequence) = details
                .get("dominant_sequence")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .take(4)
                        .map(normalize_stack_frame)
                        .filter(|value| !value.is_empty())
                        .collect::<Vec<_>>()
                        .join(" -> ")
                })
                .filter(|value| !value.is_empty())
            {
                highlights.push(format!("Repeated loop: {sequence}"));
            }
            if let Some(syscalls) = details
                .get("top_syscalls")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_object)
                        .take(4)
                        .filter_map(|entry| {
                            let name = entry.get("name").and_then(Value::as_str)?;
                            let count = entry.get("count").and_then(Value::as_i64)?;
                            Some(format!("{} x{}", normalize_stack_frame(name), count))
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|value| !value.is_empty())
            {
                highlights.push(format!("Top syscalls: {syscalls}"));
            }
            push_env_highlights(details, &mut highlights);
            if frames.is_empty() && highlights.is_empty() {
                return None;
            }
            Some(PublicTechnicalSnapshot {
                title: if details.get("representative_backtraces").is_some() {
                    "Representative thread backtrace".to_string()
                } else if frames.is_empty() {
                    "Observed runtime evidence".to_string()
                } else {
                    "Sampled wait stack".to_string()
                },
                summary: if details.get("representative_backtraces").is_some() {
                    "This is the clearest retained userspace thread cluster Fixer captured while the process was spinning."
                        .to_string()
                } else if frames.is_empty() {
                    "Fixer did not retain a representative backtrace for this issue, but it did retain the strongest public runtime signals that drove the diagnosis and patch attempt."
                        .to_string()
                } else {
                    "This is the stack-shaped slice and hot path Fixer captured while the process was spinning.".to_string()
                },
                frames,
                highlights,
            })
        }
        "stuck-process" => {
            let frames = sanitize_snapshot_frames(
                details
                    .get("stack_excerpt")
                    .and_then(Value::as_str)
                    .into_iter()
                    .flat_map(|excerpt| excerpt.lines())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                12,
            );
            if frames.is_empty() {
                return None;
            }
            let mut highlights = Vec::new();
            if let Some(state) = details.get("process_state").and_then(Value::as_str) {
                highlights.push(format!("State: {}", sanitize_public_text(state)));
            }
            if let Some(wchan) = details.get("wchan").and_then(Value::as_str) {
                highlights.push(format!("Wait site: {}", normalize_stack_frame(wchan)));
            }
            push_env_highlights(details, &mut highlights);
            Some(PublicTechnicalSnapshot {
                title: "Kernel wait stack".to_string(),
                summary: "This is where Fixer saw the sampled task blocked in the kernel."
                    .to_string(),
                frames,
                highlights,
            })
        }
        "desktop-graphics-session" => {
            let frames = sanitize_snapshot_frames(
                details
                    .get("warning_lines")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .chain(
                        details
                            .get("crash_lines")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                            .map(ToString::to_string),
                    )
                    .collect::<Vec<_>>(),
                10,
            );
            let mut highlights = Vec::new();
            if let Some(apps) = details
                .get("affected_apps")
                .and_then(Value::as_array)
                .map(|apps| {
                    apps.iter()
                        .filter_map(Value::as_str)
                        .take(6)
                        .map(sanitize_public_text)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|value| !value.is_empty())
            {
                highlights.push(format!("Affected apps: {apps}"));
            }
            if let Some(driver) = details.get("driver").and_then(Value::as_str) {
                highlights.push(format!("Graphics driver: {}", sanitize_public_text(driver)));
            }
            if let Some(compositor) = details.get("compositor").and_then(Value::as_str) {
                highlights.push(format!("Compositor: {}", sanitize_public_text(compositor)));
            }
            if let Some(explanation) = details
                .get("loop_explanation")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            {
                highlights.push(format!(
                    "Why Fixer classified it this way: {}",
                    sanitize_public_text(explanation)
                ));
            }
            push_env_highlights(details, &mut highlights);
            if frames.is_empty() && highlights.is_empty() {
                return None;
            }
            Some(PublicTechnicalSnapshot {
                title: "Desktop graphics/session markers".to_string(),
                summary: "These are the public-safe log lines and high-level signals Fixer kept while correlating a shared desktop graphics/session failure.".to_string(),
                frames,
                highlights,
            })
        }
        _ => None,
    }
}

fn sanitize_snapshot_frames(raw_frames: Vec<String>, limit: usize) -> Vec<String> {
    let mut frames = Vec::new();
    for frame in raw_frames {
        let normalized = normalize_stack_frame(frame.trim());
        if normalized.is_empty() || frames.contains(&normalized) {
            continue;
        }
        frames.push(normalized);
        if frames.len() >= limit {
            break;
        }
    }
    frames
}

fn file_name_or_self(raw: &str) -> &str {
    Path::new(raw)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(raw)
}

fn parse_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|value| value.with_timezone(&Utc))
        .ok()
}

fn new_server_id() -> String {
    Uuid::now_v7().to_string()
}

fn validate_uuid_param(raw: &str, label: &str) -> Result<(), ApiError> {
    Uuid::parse_str(raw)
        .map(|_| ())
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, format!("invalid {label}")))
}

fn render_landing_page(config: &FixerConfig, snapshot: &DashboardSnapshot) -> String {
    let canonical_url = config.network.server_url.trim_end_matches('/');
    let github_url = "https://github.com/maumaps/fixer";
    let repo_key_url = format!("{canonical_url}/apt/fixer-archive-keyring.gpg");
    let apt_repo_url = format!("{canonical_url}/apt/");
    let apt_snippet = format!(
        "sudo curl -fsSL {repo_key_url} -o /usr/share/keyrings/fixer-archive-keyring.gpg\n\
echo \"deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/fixer-archive-keyring.gpg] {apt_repo_url} stable main\" | \\\n\
  sudo tee /etc/apt/sources.list.d/fixer.list >/dev/null\n\
sudo apt update\n\
sudo apt install fixer"
    );
    let last_submission = snapshot
        .last_submission_at
        .as_deref()
        .map(format_timestamp)
        .unwrap_or_else(|| "No submissions yet".to_string());
    let queue_tagline = if snapshot.promoted_issue_count == 0 {
        "The shared queue is quiet right now."
    } else if snapshot.ready_patch_count > 0 {
        "There is live work in the queue and at least one diff-ready attempt."
    } else if snapshot.ready_report_count > 0 {
        "The queue is active, but most worker output is still diagnosis-only rather than diff-ready."
    } else if snapshot.ready_triage_count > 0 {
        "The queue is active and some issues already have clean public handoffs."
    } else {
        "The queue is active and waiting for the next solid patch attempt."
    };
    let top_issue_markup = if snapshot.top_issues.is_empty() {
        "<p class=\"fine-print\">No promoted issues yet. Once at least two opted-in hosts corroborate the same failure, it moves into the shared worker queue.</p>".to_string()
    } else {
        snapshot
            .top_issues
            .iter()
            .map(render_issue_queue_card)
            .collect::<Vec<_>>()
            .join("")
    };

    let body = format!(
        r#"
        <section class="hero home-hero">
            <div class="hero-grid">
                <div class="hero-copy">
                    <p class="tag">Crowd-mode Linux repair, but opt-in and honest</p>
                    <h1>Fix real breakage together, not one machine at a time.</h1>
                    <p class="lede">Fixer turns recurring Linux failures into shared repair work. Quiet participants can submit sanitized evidence. Workers with a coding agent can investigate, ship a diff when there really is one, or publish a clean handoff when pretending to have a patch would be dishonest.</p>
                    <div class="hero-actions">
                        <a class="button primary" href="/issues">Browse promoted issues</a>
                        <a class="button soft" href="/patches">See successful patches</a>
                        <a class="button soft" href="/triage">See successful triage</a>
                        <a class="button" href="{apt_repo_url}">Install from APT</a>
                        <a class="button" href="{github_url}">Read the code</a>
                    </div>
                    <div class="mini-badges">
                        <span class="mini-badge"><strong>Default:</strong> local-only until the user opts in</span>
                        <span class="mini-badge"><strong>Public:</strong> sanitized issue families, not raw host evidence</span>
                        <span class="mini-badge"><strong>Outputs:</strong> real diffs or explicit triage</span>
                    </div>
                </div>
                <aside class="live-board">
                    <p class="eyebrow">Live network snapshot</p>
                    <h2>{}</h2>
                    <p class="fine-print">This front page is the public, sanitized layer. Internal evidence can stay private while the shared queue stays useful.</p>
                    <div class="snapshot-grid">
                        <div class="snapshot-stat">
                            <strong>{}</strong>
                            <span>opted-in installs seen</span>
                        </div>
                        <div class="snapshot-stat">
                            <strong>{}</strong>
                            <span>submission bundles processed</span>
                        </div>
                        <div class="snapshot-stat">
                            <strong>{}</strong>
                            <span>promoted issue families</span>
                        </div>
                        <div class="snapshot-stat">
                            <strong><a href="/patches">{}</a></strong>
                            <span>diff-ready patch attempts</span>
                        </div>
                        <div class="snapshot-stat">
                            <strong><a href="/triage">{}</a></strong>
                            <span>successful public triage handoffs</span>
                        </div>
                        <div class="snapshot-stat">
                            <strong><a href="/attempts?kind=reports">{}</a></strong>
                            <span>diagnosis-only reports</span>
                        </div>
                        <div class="snapshot-stat">
                            <strong><a href="/attempts?kind=failures">{}</a></strong>
                            <span>failed patch attempts</span>
                        </div>
                        <div class="snapshot-stat">
                            <strong><a href="/attempts?kind=impossible">{}</a></strong>
                            <span>explained impossible attempts</span>
                        </div>
                        <div class="snapshot-stat">
                            <strong>{}</strong>
                            <span>still quarantined against spam</span>
                        </div>
                    </div>
                    <div class="snapshot-foot">
                        <p><strong>Last submission:</strong> {last_submission}</p>
                        <p class="fine-print">Fixer promotes corroborated or trusted issues, then lets workers pull from the public queue. When workers cannot land an honest diff, the public issue page now shows diagnosis-only and blocked attempts instead of hiding them.</p>
                    </div>
                </aside>
            </div>
        </section>

        <section class="grid feature-grid section">
            <article class="feature-card">
                <h3>Shared queue, not private guessing</h3>
                <p>When multiple hosts hit the same failure, the work can converge in one public issue family instead of being rediscovered from scratch.</p>
            </article>
            <article class="feature-card">
                <h3>Better than fake certainty</h3>
                <p>If a patch would be hand-wavy or wrong, Fixer can publish triage, handoff targets, and next steps instead of pretending the diff is ready.</p>
            </article>
            <article class="feature-card">
                <h3>Upstream-friendly by design</h3>
                <p>Patches are pushed toward plan-first reasoning, review, and git-friendly writeups so the result is easier to understand and submit upstream.</p>
            </article>
        </section>

        <section class="grid columns section">
            <article class="panel">
                <h2>How crowd mode works</h2>
                <p class="section-intro">The system tries to stay useful without being creepy, noisy, or overconfident.</p>
                <div class="journey-list">
                    <div class="journey-step">
                        <strong>1. Collect locally first.</strong>
                        Hosts collect findings on their own machine. Nothing joins the network until the user explicitly opts in.
                    </div>
                    <div class="journey-step">
                        <strong>2. Promote only the believable stuff.</strong>
                        New clusters start quarantined. Corroborated or trusted submissions move into the shared queue where other workers can see them.
                    </div>
                    <div class="journey-step">
                        <strong>3. Produce a patch or an honest handoff.</strong>
                        Workers with Codex can attempt a fix, review it, improve it, or publish a strong diagnosis when the source tree is not the real owner.
                    </div>
                </div>
            </article>
            <article class="panel">
                <h2>Install first, opt in later</h2>
                <p class="section-intro">The package can live quietly on a machine before anyone decides to join the network. Local mode stays the default.</p>
                <pre class="code-block"><code>{}</code></pre>
                <div class="callout">
                    <p><strong>APT repo:</strong> <a href="{apt_repo_url}">{apt_repo_url}</a><br><strong>Signing key:</strong> <a href="{repo_key_url}">{repo_key_url}</a></p>
                </div>
            </article>
        </section>

        <section class="panel section">
            <h2>Privacy and consent</h2>
            <p class="section-intro">{}</p>
            <p class="fine-print">Public pages and public issue JSON expose only aggregate sanitized metadata. They do not expose hostnames, install IDs, raw command lines, or private evidence bundles.</p>
        </section>

        <section class="grid columns section">
            <article class="panel">
                <h2>How the queue is sorted</h2>
                <p class="section-intro">The homepage is meant to answer the human question first: what is likely to hurt someone the most right now, and how widely is it happening?</p>
                <div class="journey-list">
                    <div class="journey-step">
                        <strong>1. User impact comes first.</strong>
                        Wake-from-sleep failures, crashes, and OOM kills rise above background hotspots even when the lower-impact issue looks more immediately patchable.
                    </div>
                    <div class="journey-step">
                        <strong>2. Bigger issue families rise next.</strong>
                        When the same failure is seen on more hosts, the family moves upward because it is less likely to be a one-off.
                    </div>
                    <div class="journey-step">
                        <strong>3. Fixability and freshness break ties.</strong>
                        Package-backed issues, ready patches, triage handoffs, and recent activity still matter, but they come after impact and cluster size.
                    </div>
                </div>
            </article>
            <article class="panel">
                <h2>Cluster size right now</h2>
                <p class="section-intro">These numbers help explain whether the queue is mostly single-host sightings or already-converging public issue families.</p>
                <div class="snapshot-grid">
                    <div class="snapshot-stat">
                        <strong>{}</strong>
                        <span>public issue families seen on 2+ hosts</span>
                    </div>
                    <div class="snapshot-stat">
                        <strong>{}</strong>
                        <span>largest public issue family right now</span>
                    </div>
                </div>
                <div class="snapshot-foot">
                    <p class="fine-print">Each issue card now spells out its cluster size directly, for example <em>single-host issue family</em> or <em>4-host issue family</em>.</p>
                </div>
            </article>
        </section>

        <section class="panel section">
            <h2>Promoted issues right now</h2>
            <p class="section-intro">This is the work that already made it through quarantine and into the public queue. These cards are sorted by likely user impact first, then by how large the issue family is, then by fixability and freshness.</p>
            <div class="issue-list">{top_issue_markup}</div>
        </section>
        "#,
        html_escape(queue_tagline),
        snapshot.install_count,
        snapshot.submission_count,
        snapshot.promoted_issue_count,
        snapshot.ready_patch_count,
        snapshot.ready_triage_count,
        snapshot.ready_report_count,
        snapshot.failed_patch_attempt_count,
        snapshot.explained_impossible_count,
        snapshot.quarantined_issue_count,
        html_escape(&apt_snippet),
        html_escape(PRIVACY_WARNING),
        snapshot.corroborated_public_issue_count,
        snapshot.largest_public_cluster_size,
    );

    render_page(
        "Fixer",
        "Public Fixer issue federation, APT repository, and worker queue",
        NavPage::Home,
        body,
        snapshot.quarantined_issue_count,
        true,
    )
}

fn render_triage_page(entries: &[PublicTriageEntry]) -> String {
    let triage_markup = if entries.is_empty() {
        "<p class=\"fine-print\">No successful public triage handoffs are available yet.</p>"
            .to_string()
    } else {
        entries
            .iter()
            .map(render_public_triage_card)
            .collect::<Vec<_>>()
            .join("")
    };
    let body = format!(
        r#"
        <section class="hero">
            <p class="tag">Public triage board</p>
            <h1>Successful triage</h1>
            <p class="lede">These issues have a credible public diagnosis and clear next steps, but no honest diff-backed fix in the current source tree. Each card preserves the handoff target so repeat sightings can converge on the real owner.</p>
            <p class="fine-print">Public JSON: <a href="/v1/triage">/v1/triage</a></p>
        </section>

        <section class="panel section">
            <h2>Ready handoffs</h2>
            <div class="issue-list">{triage_markup}</div>
        </section>
        "#
    );
    render_page(
        "Fixer Triage",
        "Successful public Fixer triage handoffs",
        NavPage::Triage,
        body,
        0,
        true,
    )
}

fn render_attempts_page(filter: AttemptBoardFilter, entries: &[PublicAttemptEntry]) -> String {
    let hero_title = match filter {
        AttemptBoardFilter::All => "Published worker attempts",
        AttemptBoardFilter::Reports => "Diagnosis-only reports",
        AttemptBoardFilter::Failures => "Failed patch attempts",
        AttemptBoardFilter::Impossible => "Explained impossible attempts",
    };
    let hero_lede = match filter {
        AttemptBoardFilter::All => {
            "This board exposes the public worker history across promoted issues, including stalled runs. It is meant to make failure modes visible without exposing raw private evidence."
        }
        AttemptBoardFilter::Reports => {
            "These attempts produced a public diagnosis but no honest diff. They are useful for seeing where work repeatedly stops and which clusters are still mostly investigative."
        }
        AttemptBoardFilter::Failures => {
            "These are the public patch attempts that failed before becoming a ready diff. The goal is transparency: you should be able to see where review, execution, workspace, or model failures are accumulating."
        }
        AttemptBoardFilter::Impossible => {
            "These attempts ended with an explicit public explanation that no honest fix was available in the current source tree or operating conditions."
        }
    };
    let api_suffix = match filter {
        AttemptBoardFilter::All => String::new(),
        AttemptBoardFilter::Reports => "?kind=reports".to_string(),
        AttemptBoardFilter::Failures => "?kind=failures".to_string(),
        AttemptBoardFilter::Impossible => "?kind=impossible".to_string(),
    };
    let attempts_markup = if entries.is_empty() {
        "<p class=\"fine-print\">No public attempts match this filter yet.</p>".to_string()
    } else {
        entries
            .iter()
            .map(render_public_attempt_entry_card)
            .collect::<Vec<_>>()
            .join("")
    };
    let filters_markup = render_attempt_filter_links(filter);
    let body = format!(
        r#"
        <section class="hero">
            <p class="tag">Public attempt board</p>
            <h1>{hero_title}</h1>
            <p class="lede">{hero_lede}</p>
            <div class="hero-actions">{filters_markup}</div>
            <p class="fine-print">Public JSON: <a href="/v1/attempts{api_suffix}">/v1/attempts{api_suffix}</a></p>
        </section>

        <section class="panel section">
            <h2>Recent public attempts</h2>
            <div class="issue-list">{attempts_markup}</div>
        </section>
        "#
    );
    render_page(
        "Fixer Attempts",
        "Public worker attempt history across Fixer issues",
        NavPage::Attempts,
        body,
        0,
        true,
    )
}

fn render_issues_page(issues: &[PublicIssueCandidate]) -> String {
    let issue_markup = if issues.is_empty() {
        "<p class=\"fine-print\">There are no public issues yet.</p>".to_string()
    } else {
        issues
            .iter()
            .map(render_issue_queue_card)
            .collect::<Vec<_>>()
            .join("")
    };
    let body = format!(
        r#"
        <section class="hero">
            <p class="tag">Public issue board</p>
            <h1>Problems people are most likely to feel first</h1>
            <p class="lede">This page is sorted by likely user impact first, then by corroboration and fixability. The goal is to answer the human question before the technical one: what probably broke, how bad it feels, and whether there is already a patch or triage result.</p>
            <p class="fine-print">Only sanitized aggregate data is shown here. Raw evidence, hostnames, install identities, and richer artifacts stay out of the public surface.</p>
        </section>

        <section class="panel section">
            <h2>Current issues</h2>
            <div class="issue-list">{issue_markup}</div>
        </section>
        "#
    );
    render_page(
        "Fixer Issues",
        "Promoted and corroborated Fixer issue clusters",
        NavPage::Issues,
        body,
        0,
        true,
    )
}

fn render_patches_page(patches: &[PublicPatchEntry]) -> String {
    let patch_markup = if patches.is_empty() {
        "<p class=\"fine-print\">No successful public patch attempts are available yet.</p>"
            .to_string()
    } else {
        patches
            .iter()
            .map(render_public_patch_card)
            .collect::<Vec<_>>()
            .join("")
    };
    let body = format!(
        r#"
        <section class="hero">
            <p class="tag">Public patch board</p>
            <h1>Successful patches</h1>
            <p class="lede">These are the promoted issues with a ready public patch attempt. Each card points back to the issue detail page so you can inspect the full published session, prompt, and sanitized artifacts.</p>
            <p class="fine-print">Public JSON: <a href="/v1/patches">/v1/patches</a></p>
        </section>

        <section class="panel section">
            <h2>Ready patch attempts</h2>
            <div class="issue-list">{patch_markup}</div>
        </section>
        "#
    );
    render_page(
        "Fixer Patches",
        "Ready public Fixer patch attempts",
        NavPage::Patches,
        body,
        0,
        true,
    )
}

fn render_issue_detail_page(issue: &PublicIssueDetail) -> String {
    let best_result_markup = render_best_result_panel(issue);
    let technical_snapshot_markup = render_technical_snapshot_section(issue);
    let duplicates_markup = render_possible_duplicates_section(issue);
    let attempt_summary_markup = render_attempt_summary_section(issue);
    let attempts_markup = if issue.attempts.is_empty() {
        "<p class=\"fine-print\">No public attempts have been published for this issue yet.</p>"
            .to_string()
    } else {
        issue
            .attempts
            .iter()
            .map(render_public_attempt_card)
            .collect::<Vec<_>>()
            .join("")
    };
    let body = format!(
        r#"
        <section class="hero">
            <p class="tag">Public issue detail</p>
            <h1>{}</h1>
            <p class="lede">{}</p>
            <div class="meta">{}</div>
            <p class="fine-print">Last seen: {}. Public JSON: <a href="/v1/issues/{}">/v1/issues/{}</a></p>
        </section>

        {}
        {}
        {}
        {}

        <section class="panel section">
            <h2>Published attempts</h2>
            <div class="issue-list">{}</div>
        </section>
        "#,
        html_escape(&issue.title),
        html_escape(&issue.summary),
        render_issue_tags(
            issue.kind.as_str(),
            issue.package_name.as_deref(),
            issue.source_package.as_deref(),
            issue.ecosystem.as_deref(),
            issue.severity.as_deref(),
            issue.score,
            issue.corroboration_count,
            issue.best_patch_available,
            issue.best_triage_available,
        ),
        html_escape(&format_timestamp(&issue.last_seen)),
        issue.id,
        issue.id,
        best_result_markup,
        technical_snapshot_markup,
        duplicates_markup,
        attempt_summary_markup,
        attempts_markup,
    );
    render_page(
        &format!("Fixer Issue {}", issue.id),
        &issue.title,
        NavPage::Issues,
        body,
        0,
        true,
    )
}

fn render_attempt_summary_section(issue: &PublicIssueDetail) -> String {
    let summary = &issue.attempt_summary;
    if summary.total_attempt_count == 0 {
        return String::new();
    }
    let blocker_markup = if summary.top_blockers.is_empty() {
        String::new()
    } else {
        format!(
            "<section class=\"patch-summary\"><h4>Most common blockers</h4><ul class=\"attempt-list\">{}</ul></section>",
            summary
                .top_blockers
                .iter()
                .map(|blocker| format!(
                    "<li><strong>{}</strong> <span class=\"fine-print\">({} attempt{})</span></li>",
                    html_escape(&blocker.label),
                    blocker.count,
                    if blocker.count == 1 { "" } else { "s" }
                ))
                .collect::<Vec<_>>()
                .join("")
        )
    };
    let omitted_note = if issue.showing_all_attempts {
        "<p class=\"fine-print\">Showing the full published public attempt history for this issue.</p>"
            .to_string()
    } else if issue.attempts_omitted_count == 0 {
        String::new()
    } else {
        format!(
            "<p class=\"fine-print\">Showing the 25 most recent attempts below and summarizing {} older attempt{} here. <a href=\"/issues/{}?all_attempts=1\">Show all published attempts for this issue</a>.</p>",
            issue.attempts_omitted_count,
            if issue.attempts_omitted_count == 1 {
                ""
            } else {
                "s"
            },
            issue.id
        )
    };
    format!(
        r#"<section class="panel section">
            <h2>Worker outcome summary</h2>
            <p class="section-intro">This issue has {total} recorded worker attempt{plural}. Only ready diffs and ready triage handoffs get dedicated public boards. Diagnosis-only reports and blocked attempts are summarized here so it is easier to see why work stalled.</p>
            <div class="snapshot-grid">
                <div class="snapshot-stat">
                    <strong>{ready_patch}</strong>
                    <span>ready patch attempts</span>
                </div>
                <div class="snapshot-stat">
                    <strong>{ready_triage}</strong>
                    <span>ready triage handoffs</span>
                </div>
                <div class="snapshot-stat">
                    <strong>{ready_report}</strong>
                    <span>diagnosis-only reports</span>
                </div>
                <div class="snapshot-stat">
                    <strong>{failed_patch}</strong>
                    <span>failed patch attempts</span>
                </div>
                <div class="snapshot-stat">
                    <strong>{explained_impossible}</strong>
                    <span>explained impossible attempts</span>
                </div>
                <div class="snapshot-stat">
                    <strong>{other}</strong>
                    <span>other attempt states</span>
                </div>
            </div>
            {blocker_markup}
            {omitted_note}
        </section>"#,
        total = summary.total_attempt_count,
        plural = if summary.total_attempt_count == 1 {
            ""
        } else {
            "s"
        },
        ready_patch = summary.ready_patch_count,
        ready_triage = summary.ready_triage_count,
        ready_report = summary.ready_report_count,
        failed_patch = summary.failed_patch_count,
        explained_impossible = summary.explained_impossible_count,
        other = summary.other_attempt_count,
        blocker_markup = blocker_markup,
        omitted_note = omitted_note,
    )
}

fn render_best_result_panel(issue: &PublicIssueDetail) -> String {
    if let Some(panel) = render_best_patch_panel(issue) {
        return panel;
    }
    if let Some(panel) = render_best_triage_panel(issue) {
        return panel;
    }
    render_best_report_panel(issue).unwrap_or_default()
}

fn render_technical_snapshot_section(issue: &PublicIssueDetail) -> String {
    let Some(snapshot) = issue.technical_snapshot.as_ref() else {
        return String::new();
    };
    let highlight_markup = if snapshot.highlights.is_empty() {
        String::new()
    } else {
        let items = snapshot
            .highlights
            .iter()
            .map(|highlight| format!("<li>{}</li>", html_escape(highlight)))
            .collect::<Vec<_>>()
            .join("");
        format!("<ul class=\"attempt-list\">{items}</ul>")
    };
    let frames_markup = if snapshot.frames.is_empty() {
        String::new()
    } else {
        format!(
            "<pre class=\"code-block\"><code>{}</code></pre>",
            html_escape(&snapshot.frames.join("\n"))
        )
    };
    format!(
        r#"<section class="panel section">
            <h2>Technical snapshot</h2>
            <p class="issue-summary">{}</p>
            <section class="patch-summary">
                <h4>{}</h4>
                {}
                {}
            </section>
        </section>"#,
        html_escape(&snapshot.summary),
        html_escape(&snapshot.title),
        highlight_markup,
        frames_markup,
    )
}

fn render_possible_duplicates_section(issue: &PublicIssueDetail) -> String {
    if issue.possible_duplicates.is_empty() {
        return String::new();
    }
    let duplicate_markup = issue
        .possible_duplicates
        .iter()
        .map(render_possible_duplicate_card)
        .collect::<Vec<_>>()
        .join("");
    format!(
        r#"<section class="panel section">
            <h2>Possible duplicates</h2>
            <p class="fine-print">These are suggestions based on sanitized trigram similarity plus structured fields like package, subsystem, classification, and wait site. They are not auto-merged.</p>
            <div class="issue-list">{}</div>
        </section>"#,
        duplicate_markup
    )
}

fn render_best_patch_panel(issue: &PublicIssueDetail) -> Option<String> {
    let Some(best_patch) = issue.best_patch.as_ref() else {
        return None;
    };
    let Some(diff) = public_attempt_diff(best_patch) else {
        return None;
    };
    let diff = normalize_published_diff(diff);
    let Some(patch_url) = issue.best_patch_diff_url.as_deref() else {
        return None;
    };
    let raw_diff_url = public_best_patch_raw_diff_url(&issue.id, Some(best_patch));
    let cover = build_public_patch_cover(
        &issue.title,
        &issue.summary,
        issue.package_name.as_deref(),
        issue.source_package.as_deref(),
        issue.corroboration_count,
        &issue.last_seen,
        best_patch,
    )?;
    let validation = best_patch
        .validation_status
        .as_deref()
        .map(|status| {
            format!(
                "<span class=\"tag\">validation: {}</span>",
                html_escape(status)
            )
        })
        .unwrap_or_default();
    let changed_files = if cover.changed_files.is_empty() {
        String::new()
    } else {
        format!(
            "<section class=\"patch-summary\"><h4>Files touched</h4><ul class=\"attempt-list\">{}</ul></section>",
            cover
                .changed_files
                .iter()
                .map(|path| format!("<li><code>{}</code></li>", html_escape(path)))
                .collect::<Vec<_>>()
                .join("")
        )
    };
    let validation_notes = if cover.validation_notes.is_empty() {
        String::new()
    } else {
        format!(
            "<section class=\"patch-summary\"><h4>Validation</h4><ul class=\"attempt-list\">{}</ul></section>",
            cover
                .validation_notes
                .iter()
                .map(|note| format!("<li>{}</li>", html_escape(note)))
                .collect::<Vec<_>>()
                .join("")
        )
    };
    let raw_diff_button = raw_diff_url
        .as_deref()
        .map(|url| {
            format!(
                "<a class=\"button\" href=\"{}\" download=\"fixer-{}.diff\">Raw diff</a>",
                url, issue.id
            )
        })
        .unwrap_or_default();
    Some(format!(
        r#"<section class="panel section patch-panel">
            <h2>Pull-request-ready diff</h2>
            <p class="fine-print">This is the current best public patch attempt for the issue. The downloadable <code>.patch</code> now includes a short cover letter so it reads like something you could send upstream with <code>git am</code>. If you only want the raw diff, grab the <code>.diff</code> instead.</p>
            <div class="meta"><span class="tag patch">best patch</span><span class="tag">created: {}</span>{}</div>
            <p class="issue-summary">{}</p>
            <section class="patch-summary">
                <h4>Suggested subject</h4>
                <pre class="code-block"><code>{}</code></pre>
                <p class="issue-summary"><strong>Commit message.</strong></p>
                <div class="patch-copy">{}</div>
                <p class="issue-summary"><strong>Problem.</strong> {}</p>
                <p class="issue-summary"><strong>How this patch connects to the issue.</strong></p>
                <div class="patch-copy">{}</div>
            </section>
            {}
            {}
            <div class="hero-actions">
                <a class="button primary" href="{}" download="fixer-{}.patch">Download .patch</a>
                {}
                <a class="button" href="/patches">Browse successful patches</a>
            </div>
            <pre class="code-block"><code>{}</code></pre>
        </section>"#,
        html_escape(&format_timestamp(&best_patch.created_at)),
        validation,
        html_escape(&best_patch.summary),
        html_escape(&cover.subject),
        render_patch_response_markup(&cover.commit_message),
        html_escape(&cover.problem),
        render_patch_response_markup(&cover.issue_connection),
        changed_files,
        validation_notes,
        patch_url,
        issue.id,
        raw_diff_button,
        html_escape(&diff)
    ))
}

fn render_best_triage_panel(issue: &PublicIssueDetail) -> Option<String> {
    if issue.best_patch.is_some() {
        return None;
    }
    let best_triage = issue.best_triage.as_ref()?;
    let handoff = issue.best_triage_handoff.as_ref()?;
    let validation = best_triage
        .validation_status
        .as_deref()
        .map(|status| {
            format!(
                "<span class=\"tag\">validation: {}</span>",
                html_escape(status)
            )
        })
        .unwrap_or_default();
    let report_url = handoff
        .report_url
        .as_deref()
        .map(|url| {
            format!(
                "<p class=\"fine-print\">Suggested bug target: <a href=\"{0}\">{0}</a></p>",
                html_escape(url)
            )
        })
        .unwrap_or_default();
    let next_steps = handoff
        .next_steps
        .iter()
        .map(|step| format!("<li>{}</li>", html_escape(step)))
        .collect::<Vec<_>>()
        .join("");
    Some(format!(
        r#"<section class="panel section patch-panel">
            <h2>Successful triage</h2>
            <p class="fine-print">Fixer did not find an honest diff-backed change in this source tree. Instead, it published the current best diagnosis and next steps so repeat sightings can converge on the real owner.</p>
            <div class="meta"><span class="tag triage">best triage</span><span class="tag">created: {}</span>{}</div>
            <p class="issue-summary">{}</p>
            <section class="patch-summary">
                <h4>Likely owner</h4>
                <p class="issue-summary">{}</p>
                <p class="fine-print">Reason: {}</p>
                {}
                <h4>Next steps</h4>
                <ul class="attempt-list">{}</ul>
            </section>
            <div class="hero-actions">
                <a class="button" href="/triage">Browse successful triage</a>
            </div>
        </section>"#,
        html_escape(&format_timestamp(&best_triage.created_at)),
        validation,
        html_escape(&best_triage.summary),
        html_escape(&handoff.target),
        html_escape(&handoff.reason),
        report_url,
        next_steps,
    ))
}

fn render_best_report_panel(issue: &PublicIssueDetail) -> Option<String> {
    let best_report = issue
        .attempts
        .iter()
        .find(|attempt| attempt.outcome == "report" && attempt.state == "ready")?;
    let validation = best_report
        .validation_status
        .as_deref()
        .map(|status| {
            format!(
                "<span class=\"tag\">validation: {}</span>",
                html_escape(status)
            )
        })
        .unwrap_or_default();
    Some(format!(
        r#"<section class="panel section patch-panel">
            <h2>Best Available Diagnosis</h2>
            <p class="fine-print">Fixer does not have a ready diff or triage handoff for this issue yet, but it does have a published diagnosis-only result. This is the clearest current explanation of what workers found.</p>
            <div class="meta"><span class="tag">diagnosis available</span><span class="tag">created: {}</span>{}</div>
            <p class="issue-summary">{}</p>
            {}
        </section>"#,
        html_escape(&format_timestamp(&best_report.created_at)),
        validation,
        html_escape(&best_report.summary),
        render_public_attempt_sections(best_report),
    ))
}

fn render_page(
    title: &str,
    description: &str,
    nav_page: NavPage,
    body: String,
    quarantined_count: i64,
    indexable: bool,
) -> String {
    let home_class = if matches!(nav_page, NavPage::Home) {
        "active"
    } else {
        ""
    };
    let issues_class = if matches!(nav_page, NavPage::Issues) {
        "active"
    } else {
        ""
    };
    let triage_class = if matches!(nav_page, NavPage::Triage) {
        "active"
    } else {
        ""
    };
    let patches_class = if matches!(nav_page, NavPage::Patches) {
        "active"
    } else {
        ""
    };
    let attempts_class = if matches!(nav_page, NavPage::Attempts) {
        "active"
    } else {
        ""
    };
    let footer_note = if quarantined_count > 0 {
        format!(
            "{} issue clusters are still quarantined while they wait for corroboration or a trusted submitter.",
            quarantined_count
        )
    } else {
        "Quarantine stays on by default so the public queue is harder to spam.".to_string()
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{}</title>
    <meta name="description" content="{}">
    {}
    <link rel="stylesheet" href="/assets/app.css">
</head>
<body>
    <div class="shell">
        <nav class="nav">
            <a class="brand" href="/">Fixer</a>
            <div class="nav-links">
                <a class="{}" href="/">Overview</a>
                <a class="{}" href="/issues">Issues</a>
                <a class="{}" href="/attempts">Attempts</a>
                <a class="{}" href="/triage">Triage</a>
                <a class="{}" href="/patches">Patches</a>
                <span class="nav-status" id="health-indicator" aria-live="polite" title="Health: checking">⚪ Health</span>
                <a href="https://github.com/maumaps/fixer">GitHub</a>
                <a href="/apt/">APT</a>
            </div>
        </nav>
        {}
        <p class="footer">{}</p>
    </div>
    {}
</body>
</html>"#,
        html_escape(title),
        html_escape(description),
        if indexable {
            String::new()
        } else {
            "<meta name=\"robots\" content=\"noindex,follow\">".to_string()
        },
        home_class,
        issues_class,
        attempts_class,
        triage_class,
        patches_class,
        body,
        html_escape(&footer_note),
        HEALTH_INDICATOR_SCRIPT
    )
}

fn public_attempt_heading(attempt: &PublicAttempt) -> &'static str {
    match (attempt.outcome.as_str(), attempt.state.as_str()) {
        ("patch", "ready") => "ready patch attempt",
        ("triage", "ready") => "ready triage handoff",
        ("report", "ready") => "diagnosis-only report",
        ("patch", "failed") => "failed patch attempt",
        ("impossible", "explained") => "explained impossible attempt",
        _ => "worker attempt",
    }
}

fn render_attempt_filter_links(active: AttemptBoardFilter) -> String {
    [
        (AttemptBoardFilter::All, "/attempts", "All attempts"),
        (
            AttemptBoardFilter::Reports,
            "/attempts?kind=reports",
            "Diagnosis-only",
        ),
        (
            AttemptBoardFilter::Failures,
            "/attempts?kind=failures",
            "Failed patches",
        ),
        (
            AttemptBoardFilter::Impossible,
            "/attempts?kind=impossible",
            "Impossible",
        ),
    ]
    .into_iter()
    .map(|(filter, href, label)| {
        let class = if filter == active {
            "button primary"
        } else {
            "button soft"
        };
        format!("<a class=\"{class}\" href=\"{href}\">{label}</a>")
    })
    .collect::<Vec<_>>()
    .join("")
}

fn render_public_attempt_entry_card(entry: &PublicAttemptEntry) -> String {
    let preview = render_patch_preview(entry.attempt.published_session.as_ref());
    format!(
        r#"<article class="issue-card patch-card">
            <div class="issue-topline">
                <h3><a href="/issues/{}">{}</a></h3>
                <span class="tag">{}</span>
            </div>
            <p class="issue-summary">{}</p>
            <div class="meta">{}<span class="tag">attempted: {}</span></div>
            <section class="patch-summary">
                <h4>Attempt summary</h4>
                <p class="issue-summary">{}</p>
            </section>
            {}
            {}
            <p class="fine-print">Issue page: <a href="/issues/{}">/issues/{}</a>. Issue JSON: <a href="/v1/issues/{}">/v1/issues/{}</a></p>
        </article>"#,
        entry.issue_id,
        html_escape(&entry.issue_title),
        html_escape(public_attempt_heading(&entry.attempt)),
        html_escape(&entry.issue_summary),
        render_issue_tags(
            entry.kind.as_str(),
            entry.package_name.as_deref(),
            entry.source_package.as_deref(),
            entry.ecosystem.as_deref(),
            entry.severity.as_deref(),
            entry.score,
            entry.corroboration_count,
            entry.best_patch_available,
            entry.best_triage_available,
        ),
        html_escape(&format_timestamp(&entry.attempt.created_at)),
        html_escape(&entry.attempt.summary),
        render_public_attempt_sections(&entry.attempt),
        preview,
        entry.issue_id,
        entry.issue_id,
        entry.issue_id,
        entry.issue_id,
    )
}

fn render_public_attempt_sections(attempt: &PublicAttempt) -> String {
    let mut sections = Vec::new();
    if let Some(session) = &attempt.published_session {
        sections.push(format!(
            "<h4>Prompt</h4><pre class=\"code-block\"><code>{}</code></pre>",
            html_escape(&session.prompt)
        ));
        if let Some(response) = session.response.as_deref() {
            sections.push(format!(
                "<h4>Response</h4><pre class=\"code-block\"><code>{}</code></pre>",
                html_escape(response)
            ));
        }
        if let Some(diff) = session.diff.as_deref() {
            sections.push(format!(
                "<h4>Diff</h4><pre class=\"code-block\"><code>{}</code></pre>",
                html_escape(diff)
            ));
        }
    }
    let session_markup = if sections.is_empty() {
        String::new()
    } else {
        format!(
            "<details class=\"attempt-session\"><summary>Published session</summary>{}</details>",
            sections.join("")
        )
    };
    let handoff_markup = attempt
        .handoff
        .as_ref()
        .map(|handoff| {
            let next_steps = handoff
                .next_steps
                .iter()
                .map(|step| format!("<li>{}</li>", html_escape(step)))
                .collect::<Vec<_>>()
                .join("");
            let report_url = handoff
                .report_url
                .as_deref()
                .map(|url| {
                    format!(
                        "<p class=\"fine-print\">Suggested bug target: <a href=\"{0}\">{0}</a></p>",
                        html_escape(url)
                    )
                })
                .unwrap_or_default();
            format!(
                "<section class=\"patch-summary\"><h4>Handoff</h4><p class=\"issue-summary\">Likely owner: {}</p><p class=\"fine-print\">Reason: {}</p>{}<ul class=\"attempt-list\">{}</ul></section>",
                html_escape(&handoff.target),
                html_escape(&handoff.reason),
                report_url,
                next_steps
            )
        })
        .unwrap_or_default();
    let blocker_markup = attempt
        .blocker_reason
        .as_deref()
        .map(|reason| {
            format!(
                "<section class=\"patch-summary\"><h4>Why it stopped</h4><p class=\"issue-summary\">{}</p></section>",
                html_escape(reason)
            )
        })
        .unwrap_or_default();
    let failure_markup = attempt
        .failure_diagnostics
        .as_ref()
        .map(render_failure_diagnostics_section)
        .unwrap_or_default();
    let failure_context_markup = attempt
        .failure_context
        .as_ref()
        .map(render_failure_context_section)
        .unwrap_or_default();

    format!(
        r#"<div class="meta"><span class="tag">state: {}</span><span class="tag">created: {}</span>{}</div>
        {}
        {}
        {}
        {}
        {}"#,
        html_escape(&attempt.state),
        html_escape(&format_timestamp(&attempt.created_at)),
        attempt
            .validation_status
            .as_deref()
            .map(|status| format!(
                "<span class=\"tag\">validation: {}</span>",
                html_escape(status)
            ))
            .unwrap_or_default(),
        blocker_markup,
        handoff_markup,
        failure_markup,
        failure_context_markup,
        session_markup
    )
}

fn render_failure_diagnostics_section(diagnostics: &PublicFailureDiagnostics) -> String {
    let mut items = Vec::new();
    if let Some(kind) = diagnostics.failure_kind.as_deref() {
        items.push(format!(
            "<li><strong>Failure kind:</strong> {}</li>",
            html_escape(kind)
        ));
    }
    if let Some(category) = diagnostics.review_failure_category.as_deref() {
        items.push(format!(
            "<li><strong>Review category:</strong> {}</li>",
            html_escape(category)
        ));
    }
    if let Some(status) = diagnostics.exit_status {
        items.push(format!("<li><strong>Exit status:</strong> {}</li>", status));
    }
    if let Some(error) = diagnostics.error.as_deref() {
        items.push(format!(
            "<li><strong>Error:</strong> {}</li>",
            html_escape(error)
        ));
    }
    let stderr_markup = diagnostics
        .last_stderr_excerpt
        .as_deref()
        .map(|stderr| {
            format!(
                "<h4>stderr excerpt</h4><pre class=\"code-block\"><code>{}</code></pre>",
                html_escape(stderr)
            )
        })
        .unwrap_or_default();
    if items.is_empty() && stderr_markup.is_empty() {
        return String::new();
    }
    format!(
        "<section class=\"patch-summary\"><h4>Failure details</h4><ul class=\"attempt-list\">{}</ul>{}</section>",
        items.join(""),
        stderr_markup
    )
}

fn render_failure_context_section(context: &PublicFailureContext) -> String {
    let mut items = Vec::new();
    if let Some(note) = context.note.as_deref() {
        items.push(format!("<li>{}</li>", html_escape(note)));
    }
    if let Some(subsystem) = context.subsystem.as_deref() {
        items.push(format!(
            "<li><strong>Subsystem:</strong> {}</li>",
            html_escape(subsystem)
        ));
    }
    if let Some(classification) = context.loop_classification.as_deref() {
        items.push(format!(
            "<li><strong>Diagnosis family:</strong> {}</li>",
            html_escape(classification)
        ));
    }
    if let Some(symbol) = context.hot_path_symbol.as_deref() {
        items.push(format!(
            "<li><strong>Hot path:</strong> {}</li>",
            html_escape(symbol)
        ));
    }
    if let Some(command_line) = context.command_line.as_deref() {
        items.push(format!(
            "<li><strong>Command:</strong> <code>{}</code></li>",
            html_escape(command_line)
        ));
    }
    if let Some(summary) = context.thread_backtrace_summary.as_deref() {
        items.push(format!(
            "<li><strong>Thread backtrace summary:</strong> {}</li>",
            html_escape(summary)
        ));
    }
    if let Some(source_package) = context.source_package.as_deref() {
        items.push(format!(
            "<li><strong>Source package:</strong> {}</li>",
            html_escape(source_package)
        ));
    }
    if let Some(source_kind) = context.source_kind.as_deref() {
        items.push(format!(
            "<li><strong>Workspace source:</strong> {}</li>",
            html_escape(source_kind)
        ));
    }
    if let Some(acquisition_note) = context.acquisition_note.as_deref() {
        items.push(format!(
            "<li><strong>Workspace acquisition:</strong> {}</li>",
            html_escape(acquisition_note)
        ));
    }
    if let Some(homepage) = context.homepage.as_deref() {
        items.push(format!(
            "<li><strong>Homepage:</strong> <a href=\"{0}\">{0}</a></li>",
            html_escape(homepage)
        ));
    }
    if !context.implicated_packages.is_empty() {
        items.push(format!(
            "<li><strong>Implicated packages:</strong> {}</li>",
            html_escape(&context.implicated_packages.join(", "))
        ));
    }
    if !context.lock_contention_signals.is_empty() {
        items.push(format!(
            "<li><strong>Contention signals:</strong> {}</li>",
            html_escape(&context.lock_contention_signals.join(", "))
        ));
    }
    let explanation_markup = context
        .loop_explanation
        .as_deref()
        .map(|explanation| {
            format!(
                "<p class=\"issue-summary\">{}</p>",
                html_escape(explanation)
            )
        })
        .unwrap_or_default();
    let representative_markup = if context.representative_backtraces.is_empty() {
        String::new()
    } else {
        format!(
            "<h4>Representative threads</h4><ul class=\"attempt-list\">{}</ul>",
            context
                .representative_backtraces
                .iter()
                .map(|trace| format!("<li>{}</li>", html_escape(trace)))
                .collect::<Vec<_>>()
                .join("")
        )
    };
    let cluster_markup = if context.common_frame_clusters.is_empty() {
        String::new()
    } else {
        format!(
            "<h4>Common frame clusters</h4><ul class=\"attempt-list\">{}</ul>",
            context
                .common_frame_clusters
                .iter()
                .map(|cluster| format!("<li>{}</li>", html_escape(cluster)))
                .collect::<Vec<_>>()
                .join("")
        )
    };
    let raw_backtrace_markup = context
        .raw_backtrace_excerpt
        .as_deref()
        .map(|backtrace| {
            format!(
                "<h4>Raw thread backtrace</h4><pre class=\"code-block\"><code>{}</code></pre>",
                html_escape(backtrace)
            )
        })
        .unwrap_or_default();
    if items.is_empty()
        && explanation_markup.is_empty()
        && representative_markup.is_empty()
        && cluster_markup.is_empty()
        && raw_backtrace_markup.is_empty()
    {
        return String::new();
    }
    format!(
        "<section class=\"patch-summary\"><h4>Collected context</h4><ul class=\"attempt-list\">{}</ul>{}{}{}{}</section>",
        items.join(""),
        explanation_markup,
        representative_markup,
        cluster_markup,
        raw_backtrace_markup
    )
}

fn render_public_attempt_card(attempt: &PublicAttempt) -> String {
    format!(
        r#"<article class="issue-card">
            <div class="issue-topline">
                <h3>{}</h3>
                <span class="tag">{}</span>
            </div>
            <p class="issue-summary">{}</p>
            {}
        </article>"#,
        html_escape(public_attempt_heading(attempt)),
        html_escape(&attempt.outcome),
        html_escape(&attempt.summary),
        render_public_attempt_sections(attempt)
    )
}

fn render_public_patch_card(entry: &PublicPatchEntry) -> String {
    let cover = build_public_patch_cover(
        &entry.title,
        &entry.summary,
        entry.package_name.as_deref(),
        entry.source_package.as_deref(),
        entry.corroboration_count,
        &entry.last_seen,
        &entry.best_patch,
    );
    let preview = render_patch_preview(entry.best_patch.published_session.as_ref());
    let actions = entry
        .best_patch_diff_url
        .as_deref()
        .map(|url| {
            format!(
                "<div class=\"hero-actions\"><a class=\"button primary\" href=\"{}\" download=\"fixer-{}.patch\">Download .patch</a>{}</div>",
                url,
                entry.id,
                public_best_patch_raw_diff_url(&entry.id, Some(&entry.best_patch))
                    .map(|raw_url| format!(
                        "<a class=\"button\" href=\"{}\" download=\"fixer-{}.diff\">Raw diff</a>",
                        raw_url, entry.id
                    ))
                    .unwrap_or_default()
            )
        })
        .unwrap_or_default();
    let mut patch_tags = render_issue_tags(
        entry.kind.as_str(),
        entry.package_name.as_deref(),
        entry.source_package.as_deref(),
        entry.ecosystem.as_deref(),
        entry.severity.as_deref(),
        entry.score,
        entry.corroboration_count,
        true,
        false,
    );
    let _ = write!(
        patch_tags,
        "<span class=\"tag patch\">patched: {}</span>",
        html_escape(&format_timestamp(&entry.best_patch.created_at))
    );
    if let Some(status) = entry.best_patch.validation_status.as_deref() {
        let _ = write!(
            patch_tags,
            "<span class=\"tag\">validation: {}</span>",
            html_escape(status)
        );
    }

    format!(
        r#"<article class="issue-card patch-card">
            <div class="issue-topline">
                <h3><a href="/issues/{}">{}</a></h3>
                <span class="tag patch">successful patch</span>
            </div>
            <p class="issue-summary">{}</p>
            <div class="meta">{}</div>
            <section class="patch-summary">
                <h4>Attempt Summary</h4>
                <p class="issue-summary">{}</p>
            </section>
            {}
            {}
            {}
            <p class="fine-print">Full published attempt: <a href="/issues/{}">/issues/{}</a>. Issue JSON: <a href="/v1/issues/{}">/v1/issues/{}</a></p>
        </article>"#,
        entry.id,
        html_escape(&entry.title),
        html_escape(&entry.summary),
        patch_tags,
        html_escape(&entry.best_patch.summary),
        cover
            .as_ref()
            .map(|cover| format!(
                "<section class=\"patch-summary\"><h4>Suggested subject</h4><pre class=\"code-block\"><code>{}</code></pre><p class=\"issue-summary\"><strong>Commit message.</strong></p><div class=\"patch-copy\">{}</div><p class=\"issue-summary\"><strong>Issue connection.</strong></p><div class=\"patch-copy\">{}</div></section>",
                html_escape(&cover.subject),
                render_patch_response_markup(&cover.commit_message),
                render_patch_response_markup(&cover.issue_connection)
            ))
            .unwrap_or_default(),
        actions,
        preview,
        entry.id,
        entry.id,
        entry.id,
        entry.id
    )
}

fn render_public_triage_card(entry: &PublicTriageEntry) -> String {
    let preview = render_patch_preview(entry.best_triage.published_session.as_ref());
    let next_steps = entry
        .handoff
        .next_steps
        .iter()
        .map(|step| format!("<li>{}</li>", html_escape(step)))
        .collect::<Vec<_>>()
        .join("");
    let report_url = entry
        .handoff
        .report_url
        .as_deref()
        .map(|url| {
            format!(
                "<p class=\"fine-print\">Suggested bug target: <a href=\"{0}\">{0}</a></p>",
                html_escape(url)
            )
        })
        .unwrap_or_default();
    let mut triage_tags = render_issue_tags(
        entry.kind.as_str(),
        entry.package_name.as_deref(),
        entry.source_package.as_deref(),
        entry.ecosystem.as_deref(),
        entry.severity.as_deref(),
        entry.score,
        entry.corroboration_count,
        false,
        true,
    );
    let _ = write!(
        triage_tags,
        "<span class=\"tag triage\">triaged: {}</span>",
        html_escape(&format_timestamp(&entry.best_triage.created_at))
    );
    if let Some(status) = entry.best_triage.validation_status.as_deref() {
        let _ = write!(
            triage_tags,
            "<span class=\"tag\">validation: {}</span>",
            html_escape(status)
        );
    }
    format!(
        r#"<article class="issue-card patch-card">
            <div class="issue-topline">
                <h3><a href="/issues/{}">{}</a></h3>
                <span class="tag triage">successful triage</span>
            </div>
            <p class="issue-summary">{}</p>
            <div class="meta">{}</div>
            <section class="patch-summary">
                <h4>Attempt Summary</h4>
                <p class="issue-summary">{}</p>
                <h4>Likely owner</h4>
                <p class="issue-summary">{}</p>
                <p class="fine-print">Reason: {}</p>
                {}
                <h4>Next steps</h4>
                <ul class="attempt-list">{}</ul>
            </section>
            {}
            <p class="fine-print">Full published attempt: <a href="/issues/{}">/issues/{}</a>. Issue JSON: <a href="/v1/issues/{}">/v1/issues/{}</a></p>
        </article>"#,
        entry.id,
        html_escape(&entry.title),
        html_escape(&entry.summary),
        triage_tags,
        html_escape(&entry.best_triage.summary),
        html_escape(&entry.handoff.target),
        html_escape(&entry.handoff.reason),
        report_url,
        next_steps,
        preview,
        entry.id,
        entry.id,
        entry.id,
        entry.id
    )
}

fn render_possible_duplicate_card(issue: &PublicPossibleDuplicate) -> String {
    let reasons = if issue.match_reasons.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=\"fine-print\">Why this looks related: {}</p>",
            html_escape(&issue.match_reasons.join(", "))
        )
    };
    format!(
        r#"<article class="issue-card">
            <div class="issue-topline">
                <h3><a href="/issues/{}">{}</a></h3>
                <span class="tag">possible duplicate</span>
            </div>
            <p class="issue-summary">{}</p>
            <div class="meta">{}<span class="tag">similarity: {}%</span></div>
            {}
            <p class="fine-print">Last seen: {}. Public page: <a href="/issues/{}">/issues/{}</a>. Public JSON: <a href="/v1/issues/{}">/v1/issues/{}</a></p>
        </article>"#,
        issue.id,
        html_escape(&issue.title),
        html_escape(&issue.summary),
        render_issue_tags(
            issue.kind.as_str(),
            issue.package_name.as_deref(),
            issue.source_package.as_deref(),
            issue.ecosystem.as_deref(),
            issue.severity.as_deref(),
            issue.score,
            issue.corroboration_count,
            issue.best_patch_available,
            issue.best_triage_available,
        ),
        format_similarity_percent(issue.similarity_score),
        reasons,
        html_escape(&format_timestamp(&issue.last_seen)),
        issue.id,
        issue.id,
        issue.id,
        issue.id
    )
}

fn render_patch_preview(session: Option<&PublishedAttemptSession>) -> String {
    let Some(session) = session else {
        return String::new();
    };
    let (label, content) =
        if let Some(diff) = session.diff.as_deref().filter(|value| !value.is_empty()) {
            ("Diff Excerpt", diff)
        } else if let Some(response) = session
            .response
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            ("Published Session Excerpt", response)
        } else {
            ("Prompt Excerpt", session.prompt.as_str())
        };
    format!(
        "<section class=\"patch-preview\"><h4>{}</h4><pre class=\"code-block\"><code>{}</code></pre></section>",
        html_escape(label),
        html_escape(&truncate_patch_preview(content, 2400))
    )
}

fn truncate_patch_preview(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        return text.to_string();
    }
    let mut boundary = max_len;
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}\n\n[truncated]", &text[..boundary])
}

fn render_issue_tags(
    _kind: &str,
    package_name: Option<&str>,
    source_package: Option<&str>,
    ecosystem: Option<&str>,
    severity: Option<&str>,
    score: i64,
    corroboration_count: i64,
    best_patch_available: bool,
    best_triage_available: bool,
) -> String {
    let mut tags = Vec::new();
    if let Some(severity) = severity {
        tags.push(format!(
            "<span class=\"tag severity-{}\">{}</span>",
            html_escape(&severity_class(severity)),
            html_escape(severity)
        ));
    }
    if let Some(package_name) = package_name {
        tags.push(format!(
            "<span class=\"tag\">package: {}</span>",
            html_escape(package_name)
        ));
    }
    if let Some(source_package) = source_package {
        tags.push(format!(
            "<span class=\"tag\">source: {}</span>",
            html_escape(source_package)
        ));
    }
    if let Some(ecosystem) = ecosystem {
        tags.push(format!(
            "<span class=\"tag\">ecosystem: {}</span>",
            html_escape(ecosystem)
        ));
    }
    tags.push(format!("<span class=\"tag\">score: {}</span>", score));
    tags.push(format!(
        "<span class=\"tag\">reports: {}</span>",
        corroboration_count
    ));
    if best_patch_available {
        tags.push("<span class=\"tag patch\">patch attempt ready</span>".to_string());
    }
    if best_triage_available {
        tags.push("<span class=\"tag triage\">successful triage</span>".to_string());
    }
    tags.join("")
}

fn severity_class(value: &str) -> String {
    match value.to_ascii_lowercase().as_str() {
        "critical" | "high" => "high".to_string(),
        "medium" | "moderate" => "medium".to_string(),
        _ => "low".to_string(),
    }
}

fn format_timestamp(raw: &str) -> String {
    parse_timestamp(raw)
        .map(|value| value.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| raw.to_string())
}

fn format_similarity_percent(score: f64) -> u32 {
    (score.clamp(0.0, 0.99) * 100.0).round() as u32
}

fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[derive(Copy, Clone)]
enum NavPage {
    Home,
    Issues,
    Attempts,
    Triage,
    Patches,
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn internal(error: impl ToString) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FixerConfig;
    use crate::models::{
        ClientHello, FindingBundle, FindingRecord, OpportunityRecord, ParticipationMode,
        PatchAttempt, StatusSnapshot, SubmissionEnvelope, SubmittedProposal, WorkerResultEnvelope,
    };
    use crate::pow::mine_pow;
    use crate::util::hash_text;
    use tempfile::tempdir;
    use tokio::runtime::Runtime;

    fn sample_crash(process_name: &str, summary: &str, stack_frames: &[&str]) -> SharedOpportunity {
        SharedOpportunity {
            local_opportunity_id: 1,
            opportunity: OpportunityRecord {
                id: 1,
                finding_id: 1,
                kind: "crash".to_string(),
                title: format!("Crash with stack trace in {process_name}"),
                score: 98,
                state: "open".to_string(),
                summary: summary.to_string(),
                evidence: json!({}),
                repo_root: None,
                ecosystem: None,
                created_at: "2026-03-29T11:00:00Z".to_string(),
                updated_at: "2026-03-29T11:00:00Z".to_string(),
            },
            finding: FindingRecord {
                id: 1,
                kind: "crash".to_string(),
                title: format!("Crash with stack trace in {process_name}"),
                severity: "high".to_string(),
                fingerprint: "legacy-fingerprint".to_string(),
                summary: summary.to_string(),
                details: json!({
                    "signal_name": "SIGSEGV",
                    "executable": format!("/opt/{process_name}/{process_name}"),
                    "primary_stack": stack_frames,
                }),
                artifact_name: Some(process_name.to_string()),
                artifact_path: None,
                package_name: Some(process_name.to_string()),
                repo_root: None,
                ecosystem: None,
                first_seen: "2026-03-29T11:00:00Z".to_string(),
                last_seen: "2026-03-29T11:00:00Z".to_string(),
            },
        }
    }

    fn sample_stuck_process_investigation(
        target: &str,
        runtime_seconds: u64,
        last_seen: &str,
    ) -> SharedOpportunity {
        SharedOpportunity {
            local_opportunity_id: 1,
            opportunity: OpportunityRecord {
                id: 1,
                finding_id: 1,
                kind: "investigation".to_string(),
                title: format!("Stuck D-state investigation for {target}"),
                score: 110,
                state: "open".to_string(),
                summary: format!(
                    "{target} has 1 process(es) stuck in `D` state for at least {runtime_seconds}s, likely blocked in unknown uninterruptible wait via drm_atomic_helper_wait_for_flip_done."
                ),
                evidence: json!({}),
                repo_root: None,
                ecosystem: None,
                created_at: last_seen.to_string(),
                updated_at: last_seen.to_string(),
            },
            finding: FindingRecord {
                id: 1,
                kind: "investigation".to_string(),
                title: format!("Stuck D-state investigation for {target}"),
                severity: "high".to_string(),
                fingerprint: "legacy-fingerprint".to_string(),
                summary: format!(
                    "{target} has 1 process(es) stuck in `D` state for at least {runtime_seconds}s, likely blocked in unknown uninterruptible wait via drm_atomic_helper_wait_for_flip_done."
                ),
                details: json!({
                    "subsystem": "stuck-process",
                    "profile_target": {
                        "name": target,
                        "path": Value::Null,
                        "package_name": Value::Null,
                        "process_count": 1,
                    },
                    "sampled_pid_count": 1,
                    "runtime_seconds": runtime_seconds,
                    "wchan": "drm_atomic_helper_wait_for_flip_done",
                    "stack_excerpt": "drm_atomic_helper_wait_for_flip_done\n__schedule",
                    "loop_classification": "unknown-uninterruptible-wait",
                }),
                artifact_name: Some(target.to_string()),
                artifact_path: None,
                package_name: None,
                repo_root: None,
                ecosystem: None,
                first_seen: last_seen.to_string(),
                last_seen: last_seen.to_string(),
            },
        }
    }

    fn sample_oom_kill_investigation(target: &str, cgroup_target: &str) -> SharedOpportunity {
        SharedOpportunity {
            local_opportunity_id: 1,
            opportunity: OpportunityRecord {
                id: 1,
                finding_id: 1,
                kind: "investigation".to_string(),
                title: format!("OOM kill investigation for {target}"),
                score: 108,
                state: "open".to_string(),
                summary: format!(
                    "{target} was killed by the kernel OOM killer after reaching about 200 MiB anonymous RSS in `{cgroup_target}`."
                ),
                evidence: json!({}),
                repo_root: None,
                ecosystem: None,
                created_at: "2026-03-29T20:50:00Z".to_string(),
                updated_at: "2026-03-29T20:50:00Z".to_string(),
            },
            finding: FindingRecord {
                id: 1,
                kind: "investigation".to_string(),
                title: format!("OOM kill investigation for {target}"),
                severity: "high".to_string(),
                fingerprint: format!("oom-kill-{target}"),
                summary: format!(
                    "{target} was killed by the kernel OOM killer after reaching about 200 MiB anonymous RSS in `{cgroup_target}`."
                ),
                details: json!({
                    "subsystem": "oom-kill",
                    "profile_target": { "name": target },
                    "loop_classification": "kernel-oom-kill",
                    "constraint": "CONSTRAINT_NONE",
                    "task_memcg_target": cgroup_target,
                    "anon_rss_kb": 204948u64,
                }),
                artifact_name: Some(target.to_string()),
                artifact_path: None,
                package_name: Some(cgroup_target.to_string()),
                repo_root: None,
                ecosystem: None,
                first_seen: "2026-03-29T20:50:00Z".to_string(),
                last_seen: "2026-03-29T20:50:00Z".to_string(),
            },
        }
    }

    fn sample_runaway_investigation(target: &str, package_name: Option<&str>) -> SharedOpportunity {
        SharedOpportunity {
            local_opportunity_id: 1,
            opportunity: OpportunityRecord {
                id: 1,
                finding_id: 1,
                kind: "investigation".to_string(),
                title: format!("Runaway CPU investigation for {target}"),
                score: 106,
                state: "open".to_string(),
                summary: format!(
                    "{target} is stuck in a likely busy loop with repeated recvfrom x120, sendto x120, epoll_wait x120."
                ),
                evidence: json!({}),
                repo_root: None,
                ecosystem: None,
                created_at: "2026-03-30T10:00:00Z".to_string(),
                updated_at: "2026-03-30T10:00:00Z".to_string(),
            },
            finding: FindingRecord {
                id: 1,
                kind: "investigation".to_string(),
                title: format!("Runaway CPU investigation for {target}"),
                severity: "high".to_string(),
                fingerprint: format!("runaway-{target}"),
                summary: format!(
                    "{target} is stuck in a likely busy loop with repeated recvfrom x120, sendto x120, epoll_wait x120."
                ),
                details: json!({
                    "subsystem": "runaway-process",
                    "profile_target": {
                        "name": target,
                        "package_name": package_name,
                    },
                    "loop_classification": "dbus-spin",
                    "repeated_syscalls": ["recvfrom", "sendto", "epoll_wait"],
                }),
                artifact_name: Some(target.to_string()),
                artifact_path: None,
                package_name: package_name.map(ToOwned::to_owned),
                repo_root: None,
                ecosystem: None,
                first_seen: "2026-03-30T10:00:00Z".to_string(),
                last_seen: "2026-03-30T10:00:00Z".to_string(),
            },
        }
    }

    fn sample_hotspot(
        target: &str,
        dso: &str,
        symbol: &str,
        package_name: &str,
    ) -> SharedOpportunity {
        SharedOpportunity {
            local_opportunity_id: 1,
            opportunity: OpportunityRecord {
                id: 1,
                finding_id: 1,
                kind: "hotspot".to_string(),
                title: format!("CPU hotspot in {target}: {symbol}"),
                score: 75,
                state: "open".to_string(),
                summary: format!("7.10% of sampled CPU in {target} went through {symbol} ({dso})"),
                evidence: json!({}),
                repo_root: None,
                ecosystem: None,
                created_at: "2026-04-30T10:00:00Z".to_string(),
                updated_at: "2026-04-30T10:00:00Z".to_string(),
            },
            finding: FindingRecord {
                id: 1,
                kind: "hotspot".to_string(),
                title: format!("CPU hotspot in {target}: {symbol}"),
                severity: "medium".to_string(),
                fingerprint: format!("hotspot-{target}-{dso}-{symbol}"),
                summary: format!("7.10% of sampled CPU in {target} went through {symbol} ({dso})"),
                details: json!({
                    "subsystem": "perf-hotspot",
                    "profile_target": {
                        "name": target,
                        "path": format!("/usr/bin/{target}"),
                        "package_name": package_name,
                    },
                    "hot_path_symbol": symbol,
                    "hot_path_dso": dso,
                    "hot_path_dso_path": format!("/usr/lib/x86_64-linux-gnu/{dso}"),
                }),
                artifact_name: Some(target.to_string()),
                artifact_path: Some(PathBuf::from(format!("/usr/bin/{target}"))),
                package_name: Some(package_name.to_string()),
                repo_root: None,
                ecosystem: None,
                first_seen: "2026-04-30T10:00:00Z".to_string(),
                last_seen: "2026-04-30T10:00:00Z".to_string(),
            },
        }
    }

    fn sample_desktop_resume_investigation(
        target: &str,
        crashed_processes: &[&str],
        last_seen: &str,
    ) -> SharedOpportunity {
        SharedOpportunity {
            local_opportunity_id: 1,
            opportunity: OpportunityRecord {
                id: 1,
                finding_id: 1,
                kind: "investigation".to_string(),
                title: format!("Desktop resume failure investigation for {target}"),
                score: 109,
                state: "open".to_string(),
                summary: format!(
                    "After suspend/resume, {target} failed: {} crashed after GPU/display errors, and sddm restarted the display stack.",
                    crashed_processes.join(", ")
                ),
                evidence: json!({}),
                repo_root: None,
                ecosystem: None,
                created_at: last_seen.to_string(),
                updated_at: last_seen.to_string(),
            },
            finding: FindingRecord {
                id: 1,
                kind: "investigation".to_string(),
                title: format!("Desktop resume failure investigation for {target}"),
                severity: "high".to_string(),
                fingerprint: format!("desktop-resume-{target}"),
                summary: format!(
                    "After suspend/resume, {target} failed: {} crashed after GPU/display errors, and sddm restarted the display stack.",
                    crashed_processes.join(", ")
                ),
                details: json!({
                    "subsystem": "desktop-resume",
                    "profile_target": { "name": target },
                    "loop_classification": "resume-display-failure",
                    "driver": "radeon",
                    "session_type": "x11",
                    "display_manager": "sddm",
                    "crashed_processes": crashed_processes,
                    "gpu_error_lines": [
                        "Mar 30 01:38:57 tinycat kernel: radeon 0000:01:05.0: ring 0 stalled for more than 10240msec",
                        "Mar 30 01:38:57 tinycat kernel: [drm:radeon_resume_kms [radeon]] *ERROR* ib ring test failed (-35)."
                    ],
                }),
                artifact_name: Some(target.to_string()),
                artifact_path: None,
                package_name: Some("linux-image-6.19.8+deb14-amd64".to_string()),
                repo_root: None,
                ecosystem: None,
                first_seen: last_seen.to_string(),
                last_seen: last_seen.to_string(),
            },
        }
    }

    fn sample_desktop_graphics_session_investigation(
        target: &str,
        affected_apps: &[&str],
        last_seen: &str,
    ) -> SharedOpportunity {
        SharedOpportunity {
            local_opportunity_id: 1,
            opportunity: OpportunityRecord {
                id: 1,
                finding_id: 1,
                kind: "investigation".to_string(),
                title: format!("Desktop graphics/session failure investigation for {target}"),
                score: 118,
                state: "open".to_string(),
                summary: format!(
                    "Repeated EGL/Mesa/Qt desktop warnings affected {} on {target}, suggesting a shared compositor or graphics-session failure.",
                    affected_apps.join(", ")
                ),
                evidence: json!({}),
                repo_root: None,
                ecosystem: None,
                created_at: last_seen.to_string(),
                updated_at: last_seen.to_string(),
            },
            finding: FindingRecord {
                id: 1,
                kind: "investigation".to_string(),
                title: format!("Desktop graphics/session failure investigation for {target}"),
                severity: "high".to_string(),
                fingerprint: format!("desktop-graphics-session-{target}"),
                summary: format!(
                    "Repeated EGL/Mesa/Qt desktop warnings affected {} on {target}, suggesting a shared compositor or graphics-session failure.",
                    affected_apps.join(", ")
                ),
                details: json!({
                    "subsystem": "desktop-graphics-session",
                    "profile_target": { "name": target },
                    "loop_classification": "desktop-graphics-session-failure",
                    "driver": "nvidia",
                    "session_type": "wayland",
                    "current_desktop": "KDE",
                    "compositor": "kwin_wayland",
                    "affected_apps": affected_apps,
                    "warning_lines": [
                        "Apr 03 14:00:01 nucat spectacle[1144]: libEGL warning: failed to get driver name for fd -1",
                        "Apr 03 14:00:01 nucat spectacle[1144]: libEGL warning: MESA-LOADER: failed to retrieve device information"
                    ],
                    "crash_lines": [
                        "Apr 03 14:00:04 nucat systemd-coredump[1600]: Process 1144 (spectacle) of user 1000 terminated abnormally with signal 6/ABRT, processing..."
                    ],
                    "loop_explanation": "Fixer correlated repeated EGL/Mesa/Qt warnings across multiple desktop apps with compositor or session instability."
                }),
                artifact_name: Some(target.to_string()),
                artifact_path: None,
                package_name: Some("kwin-wayland".to_string()),
                repo_root: None,
                ecosystem: None,
                first_seen: last_seen.to_string(),
                last_seen: last_seen.to_string(),
            },
        }
    }

    fn public_issue_for_test(id: &str, opportunity: &SharedOpportunity) -> PublicIssue {
        let public = build_public_issue_fields(opportunity);
        PublicIssue {
            id: id.to_string(),
            kind: opportunity.opportunity.kind.clone(),
            title: public.title,
            summary: public.summary,
            package_name: opportunity.finding.package_name.clone(),
            source_package: opportunity.finding.package_name.clone(),
            ecosystem: opportunity.opportunity.ecosystem.clone(),
            severity: Some(opportunity.finding.severity.clone()),
            score: opportunity.opportunity.score,
            corroboration_count: 1,
            best_patch_available: false,
            best_triage_available: false,
            last_seen: opportunity.finding.last_seen.clone(),
        }
    }

    fn public_issue_candidate_for_test(
        id: &str,
        opportunity: &SharedOpportunity,
    ) -> PublicIssueCandidate {
        PublicIssueCandidate {
            issue: public_issue_for_test(id, opportunity),
            signals: IssuePrioritySignals {
                subsystem: representative_subsystem(opportunity).map(ToString::to_string),
                target_name: representative_fixability_target_name(opportunity),
                likely_external_root_cause: representative_likely_external_root_cause(opportunity),
            },
        }
    }

    fn test_runtime() -> Runtime {
        Runtime::new().expect("tokio runtime")
    }

    fn init_test_server_db() -> (tempfile::TempDir, ServerDb) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("server.sqlite3");
        let db = ServerDb::Sqlite(path);
        test_runtime()
            .block_on(init_db(&db, &FixerConfig::default()))
            .unwrap();
        (dir, db)
    }

    fn sqlite_test_connection(db: &ServerDb) -> Connection {
        match db {
            ServerDb::Sqlite(path) => sqlite_connection(path).unwrap(),
            ServerDb::Postgres(_) => panic!("expected sqlite test db"),
        }
    }

    fn insert_test_install(connection: &Connection, install_id: &str, seen_at: &str) {
        connection
            .execute(
                "
                INSERT INTO installs
                    (install_id, first_seen, last_seen, mode, hostname, version, has_codex, capabilities_json)
                VALUES (?1, ?2, ?2, 'submitter-worker', NULL, '0.0.0-test', 1, '[]')
                ",
                rusqlite::params![install_id, seen_at],
            )
            .unwrap();
    }

    fn insert_test_issue(
        connection: &Connection,
        issue_id: &str,
        cluster_key: &str,
        score: i64,
        last_seen: &str,
        representative: &SharedOpportunity,
        report_install_ids: &[&str],
    ) {
        connection
            .execute(
                "
                INSERT INTO issue_clusters
                    (id, cluster_key, kind, title, summary, public_title, public_summary, public_visible,
                     package_name, source_package, ecosystem, severity, score, corroboration_count,
                     quarantined, promoted, representative_json, best_patch_json, best_triage_json, last_seen)
                VALUES
                    (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10, ?11, ?12, ?13, 0, 1, ?14, NULL, NULL, ?15)
                ",
                rusqlite::params![
                    issue_id,
                    cluster_key,
                    &representative.opportunity.kind,
                    &representative.opportunity.title,
                    &representative.opportunity.summary,
                    sanitize_public_text(&representative.opportunity.title),
                    sanitize_public_text(&representative.opportunity.summary),
                    representative.finding.package_name.as_deref(),
                    representative.finding.package_name.as_deref(),
                    representative.opportunity.ecosystem.as_deref(),
                    &representative.finding.severity,
                    score,
                    report_install_ids.len() as i64,
                    serde_json::to_string(representative).unwrap(),
                    last_seen,
                ],
            )
            .unwrap();

        for (index, install_id) in report_install_ids.iter().enumerate() {
            insert_test_install(connection, install_id, last_seen);
            let submission_id = format!("{issue_id}-submission-{index}");
            connection
                .execute(
                    "
                    INSERT INTO submissions
                        (id, install_id, content_hash, payload_hash, received_at, remote_addr, quarantined, bundle_json)
                    VALUES (?1, ?2, ?3, ?4, ?5, NULL, 0, '{}')
                    ",
                    rusqlite::params![
                        submission_id,
                        install_id,
                        format!("{issue_id}-content-{index}"),
                        format!("{issue_id}-payload-{index}"),
                        last_seen,
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "
                    INSERT INTO cluster_reports (cluster_id, install_id, submission_id, created_at)
                    VALUES (?1, ?2, ?3, ?4)
                    ",
                    rusqlite::params![issue_id, install_id, submission_id, last_seen],
                )
                .unwrap();
        }
    }

    #[test]
    fn submit_bundle_publishes_ready_local_patch_attempts() {
        let (_dir, db) = init_test_server_db();
        let mut config = FixerConfig::default();
        if let ServerDb::Sqlite(path) = &db {
            config.server.postgres_url = format!("sqlite://{}", path.display());
        }
        let state = Arc::new(ServerState {
            config: config.clone(),
            db,
        });
        let item = sample_desktop_graphics_session_investigation(
            "plasma-desktop",
            &["systemsettings"],
            "2026-04-04T12:00:00Z",
        );
        let result = WorkerResultEnvelope {
            lease_id: String::new(),
            attempt: PatchAttempt {
                cluster_id: String::new(),
                install_id: "submitter-1".to_string(),
                outcome: "patch".to_string(),
                state: "ready".to_string(),
                summary: "Patch proposal created locally.".to_string(),
                bundle_path: Some("/tmp/bundle".to_string()),
                output_path: Some("/tmp/bundle/codex-output.txt".to_string()),
                validation_status: Some("ready".to_string()),
                details: json!({
                    "submitted_via_sync": true,
                    "published_session": {
                        "prompt": "Patch the keyboard daemon.",
                        "response": "Applied a bounded fix.",
                        "diff": "diff --git a/kcms/keyboard/keyboard_daemon.cpp b/kcms/keyboard/keyboard_daemon.cpp\n--- a/kcms/keyboard/keyboard_daemon.cpp\n+++ b/kcms/keyboard/keyboard_daemon.cpp\n@@\n-old\n+new\n",
                        "model": "codex-default",
                        "models_used": ["codex-default"],
                        "rate_limit_fallback_used": false
                    }
                }),
                created_at: "2026-04-04T12:05:00Z".to_string(),
            },
            impossible_reason: None,
            evidence_request: None,
        };
        let bundle = FindingBundle {
            captured_at: "2026-04-04T12:06:00Z".to_string(),
            policy_version: "2026-03-29".to_string(),
            richer_evidence_allowed: false,
            status: StatusSnapshot {
                capabilities: 1,
                artifacts: 1,
                findings: 1,
                opportunities: 1,
                proposals: 1,
            },
            capabilities: Vec::new(),
            items: vec![item.clone()],
            proposals: vec![SubmittedProposal {
                local_opportunity_id: item.local_opportunity_id,
                local_proposal_id: 42,
                remote_issue_id: None,
                result,
            }],
            redactions: Vec::new(),
        };
        let client = ClientHello {
            install_id: "submitter-1".to_string(),
            version: current_binary_version().to_string(),
            protocol_version: CURRENT_PROTOCOL_VERSION,
            mode: ParticipationMode::SubmitterWorker,
            hostname: Some("test-host".to_string()),
            capabilities: Vec::new(),
            has_codex: true,
            richer_evidence_allowed: false,
            patch_driver: Some("codex".to_string()),
            patch_model: Some("codex-default".to_string()),
        };
        let content_hash = hash_text(serde_json::to_vec(&bundle).unwrap());
        let proof_of_work = mine_pow(
            &client.install_id,
            &content_hash,
            config.server.submission_pow_difficulty,
        );
        let envelope = SubmissionEnvelope {
            client,
            content_hash,
            proof_of_work,
            bundle,
        };

        let receipt = match test_runtime().block_on(submit_bundle(
            State(state.clone()),
            ConnectInfo("127.0.0.1:43210".parse().unwrap()),
            Json(envelope),
        )) {
            Ok(value) => value.0,
            Err(error) => panic!("submit_bundle failed: {}", error.message),
        };
        assert_eq!(receipt.issue_ids.len(), 1);

        let connection = sqlite_test_connection(&state.db);
        let best_patch_json: Option<String> = connection
            .query_row(
                "SELECT best_patch_json FROM issue_clusters WHERE id = ?1",
                [receipt.issue_ids[0].as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let best_patch: PatchAttempt =
            serde_json::from_str(&best_patch_json.expect("best_patch_json should be set")).unwrap();
        let diff = best_patch
            .details
            .get("published_session")
            .and_then(|value| value.get("diff"))
            .and_then(Value::as_str)
            .unwrap();
        assert!(diff.contains("keyboard_daemon.cpp"));
        let patch_attempt_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM patch_attempts WHERE cluster_id = ?1",
                [receipt.issue_ids[0].as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(patch_attempt_count, 1);
    }

    #[test]
    fn submit_bundle_publishes_ready_local_patch_attempts_to_remote_issue_without_items() {
        let (_dir, db) = init_test_server_db();
        let mut config = FixerConfig::default();
        if let ServerDb::Sqlite(path) = &db {
            config.server.postgres_url = format!("sqlite://{}", path.display());
        }
        let state = Arc::new(ServerState {
            config: config.clone(),
            db,
        });
        let item = sample_desktop_graphics_session_investigation(
            "plasma-desktop",
            &["systemsettings"],
            "2026-04-04T12:00:00Z",
        );
        let existing_issue_id = "issue-existing-public";
        let connection = sqlite_test_connection(&state.db);
        insert_test_issue(
            &connection,
            existing_issue_id,
            "cluster-existing-public",
            110,
            "2026-04-04T12:00:00Z",
            &item,
            &["other-install"],
        );

        let result = WorkerResultEnvelope {
            lease_id: String::new(),
            attempt: PatchAttempt {
                cluster_id: String::new(),
                install_id: "submitter-1".to_string(),
                outcome: "patch".to_string(),
                state: "ready".to_string(),
                summary: "Patch proposal created locally.".to_string(),
                bundle_path: Some("/tmp/bundle".to_string()),
                output_path: Some("/tmp/bundle/codex-output.txt".to_string()),
                validation_status: Some("ready".to_string()),
                details: json!({
                    "submitted_via_sync": true,
                    "published_session": {
                        "prompt": "Patch the keyboard daemon.",
                        "response": "Ran `cmake --build build-fix --target kded_keyboard -j2` successfully.",
                        "diff": "diff --git a/kcms/keyboard/keyboard_daemon.cpp b/kcms/keyboard/keyboard_daemon.cpp\n--- a/kcms/keyboard/keyboard_daemon.cpp\n+++ b/kcms/keyboard/keyboard_daemon.cpp\n@@\n-old\n+new\n",
                        "model": "codex-default",
                        "models_used": ["codex-default"],
                        "rate_limit_fallback_used": false
                    },
                    "validation_quality": "passed",
                    "supersedes_best_patch": true,
                    "remote_issue_id": existing_issue_id
                }),
                created_at: "2026-04-04T12:05:00Z".to_string(),
            },
            impossible_reason: None,
            evidence_request: None,
        };
        let bundle = FindingBundle {
            captured_at: "2026-04-04T12:06:00Z".to_string(),
            policy_version: "2026-03-29".to_string(),
            richer_evidence_allowed: false,
            status: StatusSnapshot {
                capabilities: 1,
                artifacts: 1,
                findings: 1,
                opportunities: 1,
                proposals: 1,
            },
            capabilities: Vec::new(),
            items: Vec::new(),
            proposals: vec![SubmittedProposal {
                local_opportunity_id: item.local_opportunity_id,
                local_proposal_id: 42,
                remote_issue_id: Some(existing_issue_id.to_string()),
                result,
            }],
            redactions: Vec::new(),
        };
        let client = ClientHello {
            install_id: "submitter-1".to_string(),
            version: current_binary_version().to_string(),
            protocol_version: CURRENT_PROTOCOL_VERSION,
            mode: ParticipationMode::SubmitterWorker,
            hostname: Some("test-host".to_string()),
            capabilities: Vec::new(),
            has_codex: true,
            richer_evidence_allowed: false,
            patch_driver: Some("codex".to_string()),
            patch_model: Some("codex-default".to_string()),
        };
        let content_hash = hash_text(serde_json::to_vec(&bundle).unwrap());
        let proof_of_work = mine_pow(
            &client.install_id,
            &content_hash,
            config.server.submission_pow_difficulty,
        );
        let envelope = SubmissionEnvelope {
            client,
            content_hash,
            proof_of_work,
            bundle,
        };

        match test_runtime().block_on(submit_bundle(
            State(state.clone()),
            ConnectInfo("127.0.0.1:43210".parse().unwrap()),
            Json(envelope),
        )) {
            Ok(_) => {}
            Err(error) => panic!("submit_bundle failed: {}", error.message),
        };

        let best_patch_json: Option<String> = connection
            .query_row(
                "SELECT best_patch_json FROM issue_clusters WHERE id = ?1",
                [existing_issue_id],
                |row| row.get(0),
            )
            .unwrap();
        let best_patch: PatchAttempt =
            serde_json::from_str(&best_patch_json.expect("best_patch_json should be set")).unwrap();
        assert_eq!(best_patch.cluster_id, existing_issue_id);
        assert_eq!(
            best_patch
                .details
                .get("remote_issue_id")
                .and_then(Value::as_str),
            Some(existing_issue_id)
        );
    }

    fn insert_test_attempt(
        connection: &Connection,
        attempt_id: &str,
        lease_id: &str,
        attempt: &PatchAttempt,
        created_at: &str,
    ) {
        insert_test_install(connection, &attempt.install_id, created_at);
        let envelope = WorkerResultEnvelope {
            lease_id: lease_id.to_string(),
            attempt: attempt.clone(),
            impossible_reason: None,
            evidence_request: None,
        };
        connection
            .execute(
                "
                INSERT INTO patch_attempts
                    (id, cluster_id, lease_id, install_id, outcome, state, summary, bundle_json, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ",
                rusqlite::params![
                    attempt_id,
                    attempt.cluster_id,
                    lease_id,
                    attempt.install_id,
                    attempt.outcome,
                    attempt.state,
                    attempt.summary,
                    serde_json::to_string(&envelope).unwrap(),
                    created_at,
                ],
            )
            .unwrap();
    }

    #[test]
    fn html_escape_handles_reserved_characters() {
        assert_eq!(
            html_escape(r#"<tag attr="value">&"</tag>"#),
            "&lt;tag attr=&quot;value&quot;&gt;&amp;&quot;&lt;/tag&gt;"
        );
    }

    #[test]
    fn humane_issue_queue_card_explains_user_impact() {
        let candidate = public_issue_candidate_for_test(
            "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8",
            &sample_desktop_resume_investigation(
                "radeon",
                &["plasmashell", "Xorg"],
                "2026-03-30T01:39:07Z",
            ),
        );

        let markup = render_issue_queue_card(&candidate);
        assert!(markup.contains("Wake-from-sleep failure"));
        assert!(markup.contains("Likely user impact."));
        assert!(markup.contains("very disruptive"));
        assert!(markup.contains("Cluster size:"));
        assert!(markup.contains("Details"));
        assert!(markup.contains("JSON"));
    }

    #[test]
    fn issues_page_mentions_user_impact_sorting() {
        let candidate = public_issue_candidate_for_test(
            "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8",
            &sample_runaway_investigation("kdeconnectd", Some("kdeconnect")),
        );

        let markup = render_issues_page(&[candidate]);
        assert!(markup.contains("sorted by likely user impact first"));
        assert!(markup.contains("human question before the technical one"));
    }

    #[test]
    fn public_issue_sort_prefers_desktop_breakage_over_fixable_cpu_loop() {
        let desktop = public_issue_candidate_for_test(
            "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8",
            &sample_desktop_resume_investigation(
                "radeon",
                &["plasmashell", "Xorg"],
                "2026-03-30T01:39:07Z",
            ),
        );
        let runaway = public_issue_candidate_for_test(
            "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f9",
            &sample_runaway_investigation("htop", Some("htop")),
        );

        assert_eq!(
            compare_public_issue_priority(&desktop, &runaway),
            Ordering::Less
        );
    }

    #[test]
    fn render_page_uses_live_health_indicator_in_nav() {
        let markup = render_page(
            "Fixer",
            "Public Fixer issue federation",
            NavPage::Home,
            "<section>body</section>".to_string(),
            0,
            true,
        );

        assert!(markup.contains("id=\"health-indicator\""));
        assert!(markup.contains("⚪ Health"));
        assert!(markup.contains("fetch(\"/healthz\""));
        assert!(!markup.contains("href=\"/healthz\""));
    }

    #[test]
    fn render_page_marks_patches_nav_active() {
        let markup = render_page(
            "Fixer Patches",
            "Ready public Fixer patch attempts",
            NavPage::Patches,
            "<section>body</section>".to_string(),
            0,
            true,
        );

        assert!(markup.contains("<a class=\"active\" href=\"/patches\">Patches</a>"));
    }

    #[test]
    fn render_page_marks_triage_nav_active() {
        let markup = render_page(
            "Fixer Triage",
            "Successful public triage handoffs",
            NavPage::Triage,
            "<section>body</section>".to_string(),
            0,
            true,
        );

        assert!(markup.contains("<a class=\"active\" href=\"/triage\">Triage</a>"));
    }

    #[test]
    fn render_attempts_page_includes_filters_and_issue_links() {
        let markup = render_attempts_page(
            AttemptBoardFilter::Reports,
            &[PublicAttemptEntry {
                issue_id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8".to_string(),
                issue_title: "Runaway CPU investigation for postgres".to_string(),
                issue_summary: "Postgres burned CPU across multiple hosts.".to_string(),
                kind: "investigation".to_string(),
                package_name: Some("postgresql-18".to_string()),
                source_package: Some("postgresql-18".to_string()),
                ecosystem: Some("debian".to_string()),
                severity: Some("high".to_string()),
                score: 106,
                corroboration_count: 2,
                best_patch_available: false,
                best_triage_available: true,
                attempt: PublicAttempt {
                    outcome: "report".to_string(),
                    state: "ready".to_string(),
                    summary: "Diagnosis captured without an honest diff.".to_string(),
                    validation_status: Some("ready".to_string()),
                    created_at: "2026-03-29T00:00:00Z".to_string(),
                    published_session: None,
                    handoff: None,
                    blocker_reason: Some("workspace acquisition failed".to_string()),
                    failure_diagnostics: None,
                    failure_context: None,
                },
            }],
        );

        assert!(markup.contains("Diagnosis-only reports"));
        assert!(markup.contains("/attempts?kind=reports"));
        assert!(markup.contains("/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8"));
        assert!(markup.contains("workspace acquisition failed"));
    }

    #[test]
    fn robots_txt_blocks_machine_endpoints_and_allows_human_boards() {
        let response = test_runtime().block_on(robots_txt());
        let rt = test_runtime();
        let body = rt.block_on(async move {
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("robots body");
            String::from_utf8(body.to_vec()).expect("utf8 robots body")
        });

        assert!(body.contains("Allow: /issues"));
        assert!(body.contains("Allow: /attempts"));
        assert!(body.contains("Disallow: /v1/"));
        assert!(body.contains("Disallow: /issues/*/best.diff"));
    }

    #[test]
    fn landing_page_highlights_live_snapshot_and_install_flow() {
        let mut config = FixerConfig::default();
        config.network.server_url = "https://fixer.maumap.com".to_string();
        let snapshot = DashboardSnapshot {
            install_count: 4,
            submission_count: 27,
            promoted_issue_count: 9,
            quarantined_issue_count: 3,
            ready_patch_count: 2,
            ready_triage_count: 1,
            ready_report_count: 7,
            failed_patch_attempt_count: 3,
            explained_impossible_count: 2,
            corroborated_public_issue_count: 4,
            largest_public_cluster_size: 6,
            last_submission_at: Some("2026-03-30T00:00:00Z".to_string()),
            top_issues: Vec::new(),
        };

        let markup = render_landing_page(&config, &snapshot);
        assert!(markup.contains("Live network snapshot"));
        assert!(markup.contains("Install first, opt in later"));
        assert!(markup.contains("Shared queue, not private guessing"));
        assert!(markup.contains("sanitized issue families, not raw host evidence"));
        assert!(markup.contains("How the queue is sorted"));
        assert!(markup.contains("public issue families seen on 2+ hosts"));
        assert!(markup.contains("largest public issue family right now"));
    }

    #[test]
    fn public_attempt_uses_published_session_only() {
        let public_attempt = public_attempt_from_patch_attempt(PatchAttempt {
            cluster_id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8".to_string(),
            install_id: "install-1".to_string(),
            outcome: "patch".to_string(),
            state: "ready".to_string(),
            summary: "Patch proposal created locally.".to_string(),
            bundle_path: Some("/var/lib/fixer/proposals/example".to_string()),
            output_path: Some("/var/lib/fixer/proposals/example/codex-output.txt".to_string()),
            validation_status: Some("ready".to_string()),
            details: json!({
                "diagnosis": {
                    "command_line": "/usr/bin/postgres --bad",
                },
                "published_session": {
                    "prompt": "Read ./evidence.json",
                    "response": "Patched ./workspace/src/file.c",
                    "diff": "--- a/src/file.c\n+++ b/src/file.c\n",
                }
            }),
            created_at: "2026-03-29T00:00:00Z".to_string(),
        });

        assert_eq!(public_attempt.outcome, "patch");
        assert!(public_attempt.summary.contains("Patch proposal"));
        assert_eq!(
            public_attempt
                .published_session
                .as_ref()
                .and_then(|session| session.response.as_deref()),
            Some("Patched ./workspace/src/file.c")
        );
    }

    #[test]
    fn failed_patch_attempt_exposes_structured_failure_diagnostics() {
        let public_attempt = public_attempt_from_patch_attempt(PatchAttempt {
            cluster_id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8".to_string(),
            install_id: "install-1".to_string(),
            outcome: "patch".to_string(),
            state: "failed".to_string(),
            summary: "The diagnosis was captured, but the patch proposal did not complete cleanly."
                .to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: Some("failed".to_string()),
            details: json!({
                "patch_failure_kind": "execution",
                "patch_review_failure_category": "test-regression",
                "patch_exit_status": 2,
                "patch_error": "cargo test failed in the workspace",
                "patch_last_stderr_excerpt": "thread 'main' panicked at src/lib.rs:42"
            }),
            created_at: "2026-03-29T00:00:00Z".to_string(),
        });

        let markup = render_public_attempt_card(&public_attempt);

        assert!(markup.contains("Failure details"));
        assert!(markup.contains("Failure kind:"));
        assert!(markup.contains("execution"));
        assert!(markup.contains("Review category:"));
        assert!(markup.contains("test-regression"));
        assert!(markup.contains("Exit status:"));
        assert!(markup.contains("cargo test failed in the workspace"));
        assert!(markup.contains("stderr excerpt"));
        assert!(markup.contains("thread &#39;main&#39; panicked"));
    }

    #[test]
    fn legacy_failed_patch_attempt_exposes_collected_context() {
        let public_attempt = public_attempt_from_patch_attempt(PatchAttempt {
            cluster_id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8".to_string(),
            install_id: "install-1".to_string(),
            outcome: "patch".to_string(),
            state: "failed".to_string(),
            summary: "The diagnosis was captured, but the patch proposal did not complete cleanly."
                .to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: Some("failed".to_string()),
            details: json!({
                "diagnosis": {
                    "subsystem": "runaway-process",
                    "loop_classification": "unknown-userspace-loop",
                    "hot_path_symbol": "lock_next_vma",
                    "command_line": "/usr/bin/htop --sort-key PERCENT_CPU",
                    "loop_explanation": "The process is CPU-hot, but the trace does not yet identify a single stable loop.",
                    "implicated_package_names": ["linux-image-6.19.8+deb14-amd64"]
                },
                "workspace": {
                    "source_package": "htop",
                    "source_kind": "debian-source",
                    "acquisition_note": "Fetched Debian source package via apt-get source.",
                    "homepage": "https://htop.dev/"
                }
            }),
            created_at: "2026-03-29T00:00:00Z".to_string(),
        });

        let markup = render_public_attempt_card(&public_attempt);

        assert!(markup.contains("Collected context"));
        assert!(markup.contains("predates structured patch failure capture"));
        assert!(markup.contains("runaway-process"));
        assert!(markup.contains("unknown-userspace-loop"));
        assert!(markup.contains("lock_next_vma"));
        assert!(markup.contains("htop"));
        assert!(markup.contains("debian-source"));
        assert!(markup.contains("Fetched Debian source package via apt-get source."));
        assert!(markup.contains("https://htop.dev/"));
    }

    #[test]
    fn auth_blocked_report_is_not_publicly_visible_attempt() {
        let attempt = PatchAttempt {
            cluster_id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8".to_string(),
            install_id: "install-1".to_string(),
            outcome: "report".to_string(),
            state: "ready".to_string(),
            summary: "the current Codex auth lease has expired".to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: Some("ready".to_string()),
            details: json!({
                "report_only_reason": "codex-auth-unavailable",
                "automatic_patch_blocker_kind": "codex-auth",
                "patch_error": "the current Codex auth lease is paused: auto-paused after 3 recent Codex failures"
            }),
            created_at: "2026-03-29T00:00:00Z".to_string(),
        };

        assert!(hidden_local_auth_bookkeeping_attempt(&attempt));
        assert!(!publicly_visible_attempt(&attempt));
    }

    #[test]
    fn auth_blocked_triage_is_not_publicly_visible_attempt() {
        let attempt = PatchAttempt {
            cluster_id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8".to_string(),
            install_id: "install-1".to_string(),
            outcome: "triage".to_string(),
            state: "ready".to_string(),
            summary: "A diagnosis report was created, but Fixer could not start the automated patch attempt because Codex auth on this host is unavailable: the current Codex auth lease is already using 1 active jobs".to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: Some("ready".to_string()),
            details: json!({
                "report_only_reason": "codex-auth-unavailable",
                "automatic_patch_blocker_kind": "codex-auth",
                "patch_error": "the current Codex auth lease is already using 1 active jobs",
                "handoff": {
                    "reason": "codex-auth-unavailable",
                    "target": "external dependency or workload outside the current source tree",
                    "next_steps": ["wait for auth capacity"]
                }
            }),
            created_at: "2026-04-01T22:42:02Z".to_string(),
        };

        assert!(hidden_local_auth_bookkeeping_attempt(&attempt));
        assert!(!publicly_visible_attempt(&attempt));
    }

    #[test]
    fn internal_storage_error_attempt_is_not_publicly_visible() {
        let attempt = PatchAttempt {
            cluster_id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8".to_string(),
            install_id: "install-1".to_string(),
            outcome: "impossible".to_string(),
            state: "explained".to_string(),
            summary: "Worker could not make a safe patch: FOREIGN KEY constraint failed"
                .to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: None,
            details: json!({
                "internal_only": true,
                "internal_error_category": "workspace-acquisition",
                "internal_error": "could not prepare workspace; failed to create diagnostic report: FOREIGN KEY constraint failed"
            }),
            created_at: "2026-03-29T00:00:00Z".to_string(),
        };

        assert!(hidden_internal_error_attempt(&attempt));
        assert!(!publicly_visible_attempt(&attempt));
    }

    #[test]
    fn best_attempt_selection_ignores_auth_blocked_reports() {
        let auth_blocked = PatchAttempt {
            cluster_id: "issue-1".to_string(),
            install_id: "install-1".to_string(),
            outcome: "report".to_string(),
            state: "ready".to_string(),
            summary: "the current Codex auth lease has expired".to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: Some("ready".to_string()),
            details: json!({
                "report_only_reason": "codex-auth-unavailable",
                "automatic_patch_blocker_kind": "codex-auth"
            }),
            created_at: "2026-03-29T00:00:00Z".to_string(),
        };
        let visible_triage = PatchAttempt {
            cluster_id: "issue-1".to_string(),
            install_id: "install-2".to_string(),
            outcome: "triage".to_string(),
            state: "ready".to_string(),
            summary: "A diagnosis and external handoff were created locally.".to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: Some("ready".to_string()),
            details: json!({
                "report_only_reason": "workspace-unavailable-external-package",
                "handoff": {
                    "reason": "workspace-unavailable-external-package",
                    "target": "upstream owner",
                    "next_steps": ["file upstream"]
                }
            }),
            created_at: "2026-03-29T01:00:00Z".to_string(),
        };

        let (best_patch, best_triage) =
            best_attempts_from_candidates(vec![auth_blocked, visible_triage.clone()]);
        assert!(best_patch.is_none());
        assert_eq!(
            best_triage.expect("visible triage survives").summary,
            visible_triage.summary
        );
    }

    #[test]
    fn diffless_ready_patch_is_reported_as_successful_triage() {
        let public_attempt = public_attempt_from_patch_attempt(PatchAttempt {
            cluster_id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8".to_string(),
            install_id: "install-1".to_string(),
            outcome: "patch".to_string(),
            state: "ready".to_string(),
            summary: "A diagnosis report and patch proposal were created locally.".to_string(),
            bundle_path: Some("/var/lib/fixer/proposals/example".to_string()),
            output_path: Some("/var/lib/fixer/proposals/example/codex-output.txt".to_string()),
            validation_status: Some("ready".to_string()),
            details: json!({
                "published_session": {
                    "prompt": "Read ./evidence.json",
                    "response": "No source change landed. The hotspot appears outside this repository in h3_postgis.so.",
                    "diff": null,
                }
            }),
            created_at: "2026-03-29T00:00:00Z".to_string(),
        });

        assert_eq!(public_attempt.outcome, "triage");
        assert!(public_attempt.summary.contains("external handoff"));
        assert_eq!(
            public_attempt
                .handoff
                .as_ref()
                .map(|handoff| handoff.reason.as_str()),
            Some("likely-external-root-cause")
        );
    }

    #[test]
    fn render_public_patch_card_includes_preview_and_issue_links() {
        let card = render_public_patch_card(&PublicPatchEntry {
            id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8".to_string(),
            kind: "investigation".to_string(),
            title: "Runaway CPU investigation for postgres".to_string(),
            summary: "Postgres burned CPU across multiple hosts.".to_string(),
            package_name: Some("postgresql-18".to_string()),
            source_package: Some("postgresql-18".to_string()),
            ecosystem: Some("debian".to_string()),
            severity: Some("high".to_string()),
            score: 106,
            corroboration_count: 2,
            last_seen: "2026-03-29T00:00:00Z".to_string(),
            best_patch_diff_url: Some(
                "/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8/best.patch".to_string(),
            ),
            best_patch: PublicAttempt {
                outcome: "patch".to_string(),
                state: "ready".to_string(),
                summary: "Patch proposal created locally.".to_string(),
                validation_status: Some("ready".to_string()),
                created_at: "2026-03-29T00:00:00Z".to_string(),
                published_session: Some(PublishedAttemptSession {
                    prompt: "Read ./evidence.json".to_string(),
                    response: Some("Patched ./workspace/src/file.c".to_string()),
                    diff: Some(
                        "--- a/src/file.c\n+++ b/src/file.c\n@@\n+/* Avoid the retry loop on missing files. */\n"
                            .to_string(),
                    ),
                    model: Some("gpt-5.4".to_string()),
                    models_used: vec!["gpt-5.4".to_string()],
                    rate_limit_fallback_used: false,
                }),
                handoff: None,
                blocker_reason: None,
                failure_diagnostics: None,
                failure_context: None,
            },
        });

        assert!(card.contains("successful patch"));
        assert!(card.contains("Suggested subject"));
        assert!(card.contains("Avoid the retry loop on missing files."));
        assert!(card.contains("Diff Excerpt"));
        assert!(card.contains("/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8/best.patch"));
        assert!(card.contains("/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8/best.diff"));
        assert!(card.contains("/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8"));
        assert!(card.contains("/v1/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8"));
    }

    #[test]
    fn render_public_patch_card_preserves_markdown_lists() {
        let card = render_public_patch_card(&PublicPatchEntry {
            id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5fa".to_string(),
            kind: "investigation".to_string(),
            title: "Runaway CPU investigation for perl".to_string(),
            summary: "Perl burned CPU across multiple hosts.".to_string(),
            package_name: Some("perl-base".to_string()),
            source_package: Some("perl".to_string()),
            ecosystem: Some("debian".to_string()),
            severity: Some("high".to_string()),
            score: 106,
            corroboration_count: 1,
            last_seen: "2026-04-01T21:38:00Z".to_string(),
            best_patch_diff_url: Some(
                "/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5fa/best.patch".to_string(),
            ),
            best_patch: PublicAttempt {
                outcome: "patch".to_string(),
                state: "ready".to_string(),
                summary: "Patch proposal created locally.".to_string(),
                validation_status: Some("ready".to_string()),
                created_at: "2026-04-01T21:38:00Z".to_string(),
                published_session: Some(PublishedAttemptSession {
                    prompt: "Read ./evidence.json".to_string(),
                    response: Some(
                        "## Refinement Pass 1\n\nSubject: perl: make tiny positive select timeouts block\n\n## Commit Message\nThe loop now keeps a positive timeout blocking.\n\n- Fix the zero-timeout truncation.\n- Keep positive delays positive.\n\n## Issue Connection\nThe issue matches repeated `pselect6` wakeups.\n\n- `pselect6` keeps returning immediately.\n- A rounded-down timeout explains that behavior.\n\n## Validation\n- perl -I./lib -c t/op/sselect.t\n".to_string(),
                    ),
                    diff: Some("--- a/pp_sys.c\n+++ b/pp_sys.c\n@@\n+/* Keep tiny positive timeouts from becoming polls. */\n".to_string()),
                    model: Some("gpt-5.3-codex-spark".to_string()),
                    models_used: vec!["gpt-5.3-codex-spark".to_string()],
                    rate_limit_fallback_used: false,
                }),
                handoff: None,
                blocker_reason: None,
                failure_diagnostics: None,
                failure_context: None,
            },
        });

        assert!(card.contains("<ul class=\"attempt-list\">"));
        assert!(card.contains("Fix the zero-timeout truncation."));
        assert!(card.contains("A rounded-down timeout explains that behavior."));
    }

    #[test]
    fn render_issue_detail_page_includes_best_patch_download() {
        let issue = PublicIssueDetail {
            id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8".to_string(),
            kind: "investigation".to_string(),
            title: "Runaway CPU investigation for postgres".to_string(),
            summary: "Postgres burned CPU across multiple hosts.".to_string(),
            package_name: Some("postgresql-18".to_string()),
            source_package: Some("postgresql-18".to_string()),
            ecosystem: Some("debian".to_string()),
            severity: Some("high".to_string()),
            score: 106,
            corroboration_count: 2,
            best_patch_available: true,
            best_triage_available: false,
            best_patch_diff_url: Some(
                "/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8/best.patch".to_string(),
            ),
            best_patch: Some(PublicAttempt {
                outcome: "patch".to_string(),
                state: "ready".to_string(),
                summary: "Patch proposal created locally.".to_string(),
                validation_status: Some("ready".to_string()),
                created_at: "2026-03-29T00:00:00Z".to_string(),
                published_session: Some(PublishedAttemptSession {
                    prompt: "Read ./evidence.json".to_string(),
                    response: Some("Patched ./workspace/src/file.c".to_string()),
                    diff: Some(
                        "--- a/src/file.c\n+++ b/src/file.c\n@@\n+/* Avoid the retry loop on missing files. */\n"
                            .to_string(),
                    ),
                    model: Some("gpt-5.4".to_string()),
                    models_used: vec!["gpt-5.4".to_string()],
                    rate_limit_fallback_used: false,
                }),
                handoff: None,
                blocker_reason: None,
                failure_diagnostics: None,
                failure_context: None,
            }),
            best_triage: None,
            best_triage_handoff: None,
            last_seen: "2026-03-29T00:00:00Z".to_string(),
            technical_snapshot: None,
            possible_duplicates: Vec::new(),
            attempt_summary: PublicAttemptSummary::default(),
            attempts_omitted_count: 0,
            attempts: Vec::new(),
            showing_all_attempts: false,
        };

        let markup = render_issue_detail_page(&issue);

        assert!(markup.contains("Pull-request-ready diff"));
        assert!(markup.contains("/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8/best.patch"));
        assert!(markup.contains("/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8/best.diff"));
        assert!(markup.contains("Download .patch"));
        assert!(markup.contains("Suggested subject"));
        assert!(markup.contains("Commit message."));
        assert!(markup.contains("How this patch connects to the issue."));
        assert!(markup.contains("Avoid the retry loop on missing files."));
    }

    #[test]
    fn render_issue_detail_page_hides_best_triage_when_best_patch_exists() {
        let issue = PublicIssueDetail {
            id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8".to_string(),
            kind: "investigation".to_string(),
            title: "Runaway CPU investigation for htop".to_string(),
            summary: "htop burned CPU across multiple hosts.".to_string(),
            package_name: Some("htop".to_string()),
            source_package: Some("htop".to_string()),
            ecosystem: Some("debian".to_string()),
            severity: Some("high".to_string()),
            score: 106,
            corroboration_count: 2,
            best_patch_available: true,
            best_triage_available: true,
            best_patch_diff_url: Some(
                "/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8/best.patch".to_string(),
            ),
            best_patch: Some(PublicAttempt {
                outcome: "patch".to_string(),
                state: "ready".to_string(),
                summary: "Patch proposal created locally.".to_string(),
                validation_status: Some("ready".to_string()),
                created_at: "2026-03-29T00:00:00Z".to_string(),
                published_session: Some(PublishedAttemptSession {
                    prompt: "Read ./evidence.json".to_string(),
                    response: Some("Patched ./workspace/linux/LinuxProcessTable.c".to_string()),
                    diff: Some(
                        "--- a/linux/LinuxProcessTable.c\n+++ b/linux/LinuxProcessTable.c\n@@\n+/* preserve deleted-library state */\n"
                            .to_string(),
                    ),
                    model: Some("gpt-5.4".to_string()),
                    models_used: vec!["gpt-5.4".to_string()],
                    rate_limit_fallback_used: false,
                }),
                handoff: None,
                blocker_reason: None,
                failure_diagnostics: None,
                failure_context: None,
            }),
            best_triage: Some(PublicAttempt {
                outcome: "triage".to_string(),
                state: "ready".to_string(),
                summary: "A diagnosis and external handoff were created locally.".to_string(),
                validation_status: Some("ready".to_string()),
                created_at: "2026-03-29T00:10:00Z".to_string(),
                published_session: None,
                handoff: Some(PublicTriageHandoff {
                    reason: "workspace-acquisition".to_string(),
                    target: "htop".to_string(),
                    report_url: Some("https://htop.dev/".to_string()),
                    next_steps: vec!["File an upstream issue.".to_string()],
                }),
                blocker_reason: None,
                failure_diagnostics: None,
                failure_context: None,
            }),
            best_triage_handoff: Some(PublicTriageHandoff {
                reason: "workspace-acquisition".to_string(),
                target: "htop".to_string(),
                report_url: Some("https://htop.dev/".to_string()),
                next_steps: vec!["File an upstream issue.".to_string()],
            }),
            last_seen: "2026-03-29T00:00:00Z".to_string(),
            technical_snapshot: None,
            possible_duplicates: Vec::new(),
            attempt_summary: PublicAttemptSummary::default(),
            attempts_omitted_count: 0,
            attempts: Vec::new(),
            showing_all_attempts: false,
        };

        let markup = render_issue_detail_page(&issue);

        assert!(markup.contains("Pull-request-ready diff"));
        assert!(!markup.contains("Successful triage"));
        assert!(!markup.contains("Likely owner"));
    }

    #[test]
    fn render_issue_tags_hide_triage_when_patch_exists() {
        let tags = render_issue_tags(
            "investigation",
            Some("htop"),
            Some("htop"),
            Some("debian"),
            Some("high"),
            106,
            2,
            true,
            true,
        );

        assert!(tags.contains("tag patch"));
        assert!(!tags.contains("triage ready"));
    }

    #[test]
    fn render_issue_detail_page_includes_possible_duplicates() {
        let issue = PublicIssueDetail {
            id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8".to_string(),
            kind: "investigation".to_string(),
            title: "Runaway CPU investigation for postgres".to_string(),
            summary: "Postgres burned CPU across multiple hosts.".to_string(),
            package_name: Some("postgresql-18".to_string()),
            source_package: Some("postgresql-18".to_string()),
            ecosystem: Some("debian".to_string()),
            severity: Some("high".to_string()),
            score: 106,
            corroboration_count: 2,
            best_patch_available: false,
            best_triage_available: true,
            best_patch_diff_url: None,
            best_patch: None,
            best_triage: Some(PublicAttempt {
                outcome: "triage".to_string(),
                state: "ready".to_string(),
                summary: "A diagnosis and external handoff were created locally.".to_string(),
                validation_status: Some("ready".to_string()),
                created_at: "2026-03-29T00:00:00Z".to_string(),
                published_session: None,
                handoff: Some(PublicTriageHandoff {
                    reason: "likely-external-root-cause".to_string(),
                    target: "module `h3_postgis.so` or the workload driving it".to_string(),
                    report_url: None,
                    next_steps: vec!["Capture a fresh backend sample.".to_string()],
                }),
                blocker_reason: None,
                failure_diagnostics: None,
                failure_context: None,
            }),
            best_triage_handoff: Some(PublicTriageHandoff {
                reason: "likely-external-root-cause".to_string(),
                target: "module `h3_postgis.so` or the workload driving it".to_string(),
                report_url: None,
                next_steps: vec!["Capture a fresh backend sample.".to_string()],
            }),
            last_seen: "2026-03-29T00:00:00Z".to_string(),
            technical_snapshot: None,
            possible_duplicates: vec![PublicPossibleDuplicate {
                id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f9".to_string(),
                kind: "investigation".to_string(),
                title: "Runaway CPU investigation for postgres".to_string(),
                summary: "postgres is stuck in a likely busy poll loop via do_epoll_wait."
                    .to_string(),
                package_name: Some("postgresql-18".to_string()),
                source_package: Some("postgresql-18".to_string()),
                ecosystem: Some("debian".to_string()),
                severity: Some("high".to_string()),
                score: 106,
                corroboration_count: 1,
                best_patch_available: false,
                best_triage_available: true,
                last_seen: "2026-03-29T00:10:00Z".to_string(),
                similarity_score: 0.82,
                match_reasons: vec!["same package".to_string(), "same wait site".to_string()],
            }],
            attempt_summary: PublicAttemptSummary::default(),
            attempts_omitted_count: 0,
            attempts: Vec::new(),
            showing_all_attempts: false,
        };

        let markup = render_issue_detail_page(&issue);

        assert!(markup.contains("Possible duplicates"));
        assert!(markup.contains("similarity: 82%"));
        assert!(markup.contains("same package, same wait site"));
        assert!(markup.contains("/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f9"));
    }

    #[test]
    fn render_issue_detail_page_includes_best_report_panel() {
        let issue = PublicIssueDetail {
            id: "019d3a5e-e969-7133-80b6-4d2eee964254".to_string(),
            kind: "investigation".to_string(),
            title: "Stuck D-state investigation for kworker+i915_flip".to_string(),
            summary: "The worker appears stuck in kernel wait.".to_string(),
            package_name: Some("linux-image-6.19.8+deb14-amd64".to_string()),
            source_package: Some("linux".to_string()),
            ecosystem: Some("debian".to_string()),
            severity: Some("high".to_string()),
            score: 110,
            corroboration_count: 2,
            best_patch_available: false,
            best_triage_available: false,
            best_patch_diff_url: None,
            best_patch: None,
            best_triage: None,
            best_triage_handoff: None,
            last_seen: "2026-03-29T20:38:00Z".to_string(),
            technical_snapshot: None,
            possible_duplicates: Vec::new(),
            attempt_summary: PublicAttemptSummary::default(),
            attempts_omitted_count: 0,
            attempts: vec![PublicAttempt {
                outcome: "report".to_string(),
                state: "ready".to_string(),
                summary: "A diagnosis report was created even though no patchable workspace was available.".to_string(),
                validation_status: Some("ready".to_string()),
                created_at: "2026-03-29T20:38:00Z".to_string(),
                published_session: Some(PublishedAttemptSession {
                    prompt: "Investigate the wait stack.".to_string(),
                    response: Some("The sampled task is blocked in drm_atomic_helper_wait_for_flip_done.".to_string()),
                    diff: None,
                    model: Some("gpt-5.4".to_string()),
                    models_used: vec!["gpt-5.4".to_string()],
                    rate_limit_fallback_used: false,
                }),
                handoff: None,
                blocker_reason: Some("no patchable workspace was available".to_string()),
                failure_diagnostics: None,
                failure_context: None,
            }],
            showing_all_attempts: false,
        };

        let markup = render_issue_detail_page(&issue);

        assert!(markup.contains("Best Available Diagnosis"));
        assert!(markup.contains("diagnosis available"));
        assert!(markup.contains("Why it stopped"));
        assert!(markup.contains("no patchable workspace was available"));
        assert!(markup.contains("drm_atomic_helper_wait_for_flip_done"));
    }

    #[test]
    fn render_issue_detail_page_includes_technical_snapshot() {
        let issue = PublicIssueDetail {
            id: "019d3d49-57e6-7123-8e0d-6d7e9c8e7b19".to_string(),
            kind: "investigation".to_string(),
            title: "Runaway CPU investigation for kwin_x11".to_string(),
            summary: "kwin_x11 is stuck in a likely busy poll loop.".to_string(),
            package_name: Some("kwin-x11".to_string()),
            source_package: Some("kwin-x11".to_string()),
            ecosystem: Some("debian".to_string()),
            severity: Some("high".to_string()),
            score: 104,
            corroboration_count: 1,
            best_patch_available: false,
            best_triage_available: false,
            best_patch_diff_url: None,
            best_patch: None,
            best_triage: None,
            best_triage_handoff: None,
            last_seen: "2026-03-29T00:00:00Z".to_string(),
            technical_snapshot: Some(PublicTechnicalSnapshot {
                title: "Sampled wait stack".to_string(),
                summary:
                    "This is the stack-shaped slice and hot path Fixer captured while the process was spinning."
                        .to_string(),
                frames: vec![
                    "futex_do_wait".to_string(),
                    "__futex_wait".to_string(),
                    "futex_wait".to_string(),
                ],
                highlights: vec![
                    "Command: /usr/bin/kwin_x11 --replace".to_string(),
                    "Wait site: futex_do_wait".to_string(),
                    "Hot path: i915_gem_do_execbuffer (5.22% sampled CPU)".to_string(),
                ],
            }),
            possible_duplicates: Vec::new(),
            attempt_summary: PublicAttemptSummary::default(),
            attempts_omitted_count: 0,
            attempts: Vec::new(),
            showing_all_attempts: false,
        };

        let markup = render_issue_detail_page(&issue);

        assert!(markup.contains("Technical snapshot"));
        assert!(markup.contains("Sampled wait stack"));
        assert!(markup.contains("Command: /usr/bin/kwin_x11 --replace"));
        assert!(markup.contains("futex_do_wait"));
        assert!(markup.contains("i915_gem_do_execbuffer (5.22% sampled CPU)"));
    }

    #[test]
    fn render_issue_detail_page_includes_highlights_only_snapshot() {
        let issue = PublicIssueDetail {
            id: "019d4017-20f8-7752-9734-0bcd71623118".to_string(),
            kind: "investigation".to_string(),
            title: "Runaway CPU investigation for perl".to_string(),
            summary: "perl is stuck in a likely busy poll loop.".to_string(),
            package_name: Some("perl-base".to_string()),
            source_package: Some("perl".to_string()),
            ecosystem: Some("debian".to_string()),
            severity: Some("high".to_string()),
            score: 106,
            corroboration_count: 1,
            best_patch_available: false,
            best_triage_available: false,
            best_patch_diff_url: None,
            best_patch: None,
            best_triage: None,
            best_triage_handoff: None,
            last_seen: "2026-04-01T21:38:00Z".to_string(),
            technical_snapshot: Some(PublicTechnicalSnapshot {
                title: "Observed runtime evidence".to_string(),
                summary: "Fixer retained syscall and hot-path evidence even though no representative backtrace was kept.".to_string(),
                frames: Vec::new(),
                highlights: vec![
                    "Why Fixer classified it this way: repeated pselect6 wakeups with no progress".to_string(),
                    "Hot path: Perl_runops_standard (100.00% sampled CPU)".to_string(),
                    "Top syscalls: pselect6 x4".to_string(),
                ],
            }),
            possible_duplicates: Vec::new(),
            attempt_summary: PublicAttemptSummary::default(),
            attempts_omitted_count: 0,
            attempts: Vec::new(),
            showing_all_attempts: false,
        };

        let markup = render_issue_detail_page(&issue);

        assert!(markup.contains("Observed runtime evidence"));
        assert!(markup.contains("Top syscalls: pselect6 x4"));
        assert!(!markup.contains("<pre class=\"code-block\"><code></code></pre>"));
    }

    #[test]
    fn render_public_patch_email_includes_cover_letter_and_diff() {
        let issue = PublicIssueDetail {
            id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8".to_string(),
            kind: "investigation".to_string(),
            title: "Runaway CPU investigation for postgres".to_string(),
            summary: "postgres is stuck in a likely file not found retry loop: repeated open/read/close churn.".to_string(),
            package_name: Some("postgresql-18".to_string()),
            source_package: Some("postgresql-18".to_string()),
            ecosystem: Some("debian".to_string()),
            severity: Some("high".to_string()),
            score: 106,
            corroboration_count: 2,
            best_patch_available: true,
            best_triage_available: false,
            best_patch_diff_url: Some(
                "/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8/best.patch".to_string(),
            ),
            best_patch: Some(PublicAttempt {
                outcome: "patch".to_string(),
                state: "ready".to_string(),
                summary: "Patch proposal created locally.".to_string(),
                validation_status: Some("ready".to_string()),
                created_at: "2026-03-29T00:00:00Z".to_string(),
                published_session: Some(PublishedAttemptSession {
                    prompt: "Read ./evidence.json".to_string(),
                    response: Some(
                        "## Patch Pass\n\nSubject: postgresql-18: dfmgr: prefer DLSUFFIX path before fallback\n\n## Commit Message\nTry the suffixed library path before the historical unsuffixed lookup when MODULE_PATHNAME expands to \"$libdir/foo\".\n\n## Issue Connection\nThe sampled issue shows postgres burning CPU in a file-not-found retry loop while repeatedly touching the extension-loading path. Preferring the suffixed name removes one guaranteed failed probe while preserving the old fallback if only the legacy path exists.\n\n## Validation\n- Not run in this retained bundle.\n"
                            .to_string(),
                    ),
                    diff: Some(
                        "--- a/src/backend/utils/fmgr/dfmgr.c\t2026-02-24 01:56:43.000000000 +0400\n+++ b/src/backend/utils/fmgr/dfmgr.c\t2026-03-29 20:11:53.195108902 +0400\n@@\n+/* Prefer the suffixed shared library name first to avoid a guaranteed failed probe. */\n"
                            .to_string(),
                    ),
                    model: Some("gpt-5.4".to_string()),
                    models_used: vec!["gpt-5.4".to_string()],
                    rate_limit_fallback_used: false,
                }),
                handoff: None,
                blocker_reason: None,
                failure_diagnostics: None,
                failure_context: None,
            }),
            best_triage: None,
            best_triage_handoff: None,
            last_seen: "2026-03-29T00:00:00Z".to_string(),
            technical_snapshot: None,
            possible_duplicates: Vec::new(),
            attempt_summary: PublicAttemptSummary::default(),
            attempts_omitted_count: 0,
            attempts: Vec::new(),
            showing_all_attempts: false,
        };

        let patch = render_public_patch_email(&issue, issue.best_patch.as_ref().unwrap()).unwrap();

        assert!(patch.contains(
            "Subject: [PATCH] postgresql-18: dfmgr: prefer DLSUFFIX path before fallback"
        ));
        assert!(patch.contains("Problem:\npostgres is stuck in a likely file not found retry loop: repeated open/read/close churn."));
        assert!(patch.contains("Commit message:\nTry the suffixed library path before the historical unsuffixed lookup when MODULE_PATHNAME expands to \"$libdir/foo\"."));
        assert!(patch.contains("How this patch connects to the issue:\nThe sampled issue shows postgres burning CPU in a file-not-found retry loop while repeatedly touching the extension-loading path. Preferring the suffixed name removes one guaranteed failed probe while preserving the old fallback if only the legacy path exists."));
        assert!(patch.contains("Files touched:\n- src/backend/utils/fmgr/dfmgr.c"));
        assert!(patch.contains("Validation:\n- Fixer marked this proposal `ready` on 2026-03-29 00:00 UTC.\n- The underlying issue cluster has 2 report(s) and was last seen 2026-03-29 00:00 UTC.\n- The published diff touches src/backend/utils/fmgr/dfmgr.c.\n- Not run in this retained bundle."));
        assert!(patch.contains(
            "Issue: https://fixer.maumap.com/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8"
        ));
        assert!(patch.contains("--- a/src/backend/utils/fmgr/dfmgr.c"));
        assert!(!patch.contains("src/backend/utils/fmgr/dfmgr.c\t2026-03-29"));
    }

    #[test]
    fn render_public_patch_email_rewrites_keyboard_jargon_into_plain_language() {
        let issue = PublicIssueDetail {
            id: "019d5954-5300-75b1-b0a0-16d9cf5259e1".to_string(),
            kind: "investigation".to_string(),
            title: "KDE keyboard layout config investigation for KDE Wayland keyboard layout stack"
                .to_string(),
            summary: "KDE keyboard layout config enables 3 layout(s) with Spare Layouts loop count 2 and Caps Lock is configured as a layout switch, while /etc/default/keyboard still describes a different XKB layout set, which points at plasma-desktop keyboard layout handling rather than a generic Wayland graphics failure.".to_string(),
            package_name: Some("plasma-desktop".to_string()),
            source_package: Some("plasma-desktop".to_string()),
            ecosystem: Some("debian".to_string()),
            severity: Some("medium".to_string()),
            score: 98,
            corroboration_count: 1,
            best_patch_available: true,
            best_triage_available: false,
            best_patch_diff_url: Some(
                "/issues/019d5954-5300-75b1-b0a0-16d9cf5259e1/best.patch".to_string(),
            ),
            best_patch: Some(PublicAttempt {
                outcome: "patch".to_string(),
                state: "ready".to_string(),
                summary: "Patch proposal created locally.".to_string(),
                validation_status: Some("ready".to_string()),
                created_at: "2026-04-04T19:47:30Z".to_string(),
                published_session: Some(PublishedAttemptSession {
                    prompt: "Read ./evidence.json".to_string(),
                    response: Some(
                        "## Refinement Pass 1\n\nSubject: kcms/keyboard: preserve last-used layout across spare-layout swaps\n\n## Commit Message\nKeep `kcms/keyboard`’s public layout order tied to the saved `kxkbrc` configuration when spare layouts are enabled, and preserve the previously active logical layout before rebuilding the runtime XKB list.\n\n## Issue Connection\nThe evidence shows Plasma is managing three configured layouts with `LayoutLoopCount=2`, so one layout is spare and can be swapped into the live two-layout XKB loop. The original bug was that Plasma exposed that transient runtime shuffle back through its public layout APIs, so UI and shortcut indices stopped matching the saved config order.\n\nThis refinement also fixes the review’s regression: when a spare layout was active and the user directly selected a main layout, `setLayout(uint)` could rebuild the runtime XKB list before remembering the previous logical layout.\n\n## Validation\n- git diff --check -- kcms/keyboard/keyboard_daemon.cpp kcms/keyboard/keyboard_daemon.h\n"
                            .to_string(),
                    ),
                    diff: Some(
                        "--- a/kcms/keyboard/keyboard_daemon.cpp\n+++ b/kcms/keyboard/keyboard_daemon.cpp\n@@\n+// Keep the public layout order stable even when the live switcher temporarily swaps in a spare layout.\n"
                            .to_string(),
                    ),
                    model: Some("codex-default".to_string()),
                    models_used: vec!["codex-default".to_string()],
                    rate_limit_fallback_used: false,
                }),
                handoff: None,
                blocker_reason: None,
                failure_diagnostics: None,
                failure_context: None,
            }),
            best_triage: None,
            best_triage_handoff: None,
            last_seen: "2026-04-05T15:50:00Z".to_string(),
            technical_snapshot: None,
            possible_duplicates: Vec::new(),
            attempt_summary: PublicAttemptSummary::default(),
            attempts_omitted_count: 0,
            attempts: Vec::new(),
            showing_all_attempts: false,
        };

        let patch = render_public_patch_email(&issue, issue.best_patch.as_ref().unwrap()).unwrap();

        assert!(patch.contains(
            "Problem:\nOn KDE Wayland, Plasma is configured with three keyboard layouts but only two should stay in the normal switch cycle."
        ));
        assert!(patch.contains(
            "Commit message:\nKeep Plasma's public layout order aligned with the order saved in its keyboard settings"
        ));
        assert!(patch.contains(
            "How this patch connects to the issue:\nPlasma stores three layouts here, but only two should stay in the normal switching cycle while the third remains spare."
        ));
        assert!(!patch.contains("runtime XKB list"));
        assert!(!patch.contains("transient runtime shuffle"));
    }

    #[test]
    fn possible_duplicate_matching_prefers_nearby_investigation_family() {
        let target = sample_stuck_process_investigation(
            "kworker/u33:0+i915_flip",
            152,
            "2026-03-29T17:52:00Z",
        );
        let duplicate = sample_stuck_process_investigation(
            "kworker/u33:3+i915_flip",
            2141,
            "2026-03-29T17:52:30Z",
        );
        let mut unrelated =
            sample_stuck_process_investigation("jbd2/sda3-8", 592299, "2026-03-29T18:42:59Z");
        unrelated.opportunity.summary =
            "jbd2/sda3-8 has 1 process(es) stuck in `D` state for at least 592299s, likely blocked in unknown uninterruptible wait via kjournald2.".to_string();
        unrelated.finding.summary = unrelated.opportunity.summary.clone();
        unrelated.finding.details["wchan"] = json!("kjournald2");
        unrelated.finding.details["stack_excerpt"] = json!("kjournald2\n__schedule");

        let target_features =
            duplicate_match_features(&public_issue_for_test("issue-a", &target), &target);
        let duplicate_match = build_possible_duplicate(
            &target_features,
            DuplicateCandidateIssue {
                issue: public_issue_for_test("issue-b", &duplicate),
                representative: duplicate.clone(),
            },
        )
        .unwrap();
        let unrelated_match = build_possible_duplicate(
            &target_features,
            DuplicateCandidateIssue {
                issue: public_issue_for_test("issue-c", &unrelated),
                representative: unrelated.clone(),
            },
        );

        assert!(duplicate_match.similarity_score >= 0.45);
        assert!(
            duplicate_match
                .match_reasons
                .contains(&"same wait site".to_string())
        );
        assert!(unrelated_match.is_none());
    }

    #[test]
    fn legacy_best_patch_is_available_for_worker_refresh() {
        let legacy_patch = PatchAttempt {
            cluster_id: "issue-1".to_string(),
            install_id: "install-1".to_string(),
            outcome: "patch".to_string(),
            state: "ready".to_string(),
            summary: "Legacy patch proposal created locally.".to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: Some("ready".to_string()),
            details: json!({
                "published_session": {
                    "prompt": "legacy prompt",
                    "response": "legacy response",
                    "diff": "--- a/src/file.c\n+++ b/src/file.c\n",
                }
            }),
            created_at: "2026-03-29T00:00:00Z".to_string(),
        };
        let current_patch = PatchAttempt {
            details: json!({
                "worker_fixer_version": current_binary_version(),
                "published_session": {
                    "prompt": "new prompt",
                    "response": "new response",
                    "diff": "--- a/src/file.c\n+++ b/src/file.c\n",
                }
            }),
            ..legacy_patch.clone()
        };

        assert!(patch_attempt_needs_worker_refresh(&legacy_patch));
        assert!(!patch_attempt_needs_worker_refresh(&current_patch));
    }

    #[test]
    fn repeated_workspace_blocked_reports_promote_to_triage() {
        let report_attempt = |created_at: &str| PatchAttempt {
            cluster_id: "issue-1".to_string(),
            install_id: "install-1".to_string(),
            outcome: "report".to_string(),
            state: "ready".to_string(),
            summary:
                "A diagnosis report was created even though no patchable workspace was available."
                    .to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: Some("ready".to_string()),
            details: json!({
                "report_only_reason": "workspace-acquisition",
                "workspace_classification": "external-package",
                "handoff": {
                    "target": "google-chrome-stable",
                    "report_url": "https://bugs.example.test/chrome",
                    "next_steps": ["File upstream issue"]
                }
            }),
            created_at: created_at.to_string(),
        };

        let (_, best_triage) = best_attempts_from_candidates(vec![
            report_attempt("2026-03-30T00:00:00Z"),
            report_attempt("2026-03-31T00:00:00Z"),
        ]);

        let best_triage = best_triage.expect("workspace reports should promote to triage");
        assert_eq!(best_triage.outcome, "triage");
        assert_eq!(
            best_triage
                .details
                .get("report_only_reason")
                .and_then(Value::as_str),
            Some("workspace-acquisition")
        );
        assert!(best_triage.summary.contains("external handoff"));
    }

    #[test]
    fn worker_queue_accepts_legacy_patch_issue_for_improvement() {
        let issue = IssueCluster {
            id: "issue-1".to_string(),
            cluster_key: "cluster-1".to_string(),
            kind: "investigation".to_string(),
            title: "Runaway CPU investigation for postgres".to_string(),
            summary: "postgres is stuck in a likely file not found retry loop".to_string(),
            package_name: Some("postgresql-18".to_string()),
            source_package: Some("postgresql-18".to_string()),
            ecosystem: Some("debian".to_string()),
            severity: Some("high".to_string()),
            score: 110,
            corroboration_count: 2,
            quarantined: false,
            promoted: true,
            representative: sample_crash(
                "postgres",
                "postgres is stuck in a likely file not found retry loop",
                &["internal_load_library+0x20"],
            ),
            best_patch: Some(PatchAttempt {
                cluster_id: "issue-1".to_string(),
                install_id: "install-1".to_string(),
                outcome: "patch".to_string(),
                state: "ready".to_string(),
                summary: "Legacy patch proposal created locally.".to_string(),
                bundle_path: None,
                output_path: None,
                validation_status: Some("ready".to_string()),
                details: json!({
                    "published_session": {
                        "prompt": "legacy prompt",
                        "response": null,
                        "diff": "--- a/src/backend/utils/fmgr/dfmgr.c\n+++ b/src/backend/utils/fmgr/dfmgr.c\n",
                    }
                }),
                created_at: "2026-03-29T00:00:00Z".to_string(),
            }),
            last_seen: "2026-03-29T16:13:42Z".to_string(),
        };

        assert!(issue_is_available_for_worker(&issue));
    }

    #[test]
    fn invalidation_report_clears_public_best_patch() {
        let legacy_patch = PatchAttempt {
            cluster_id: "issue-1".to_string(),
            install_id: "worker-install".to_string(),
            outcome: "patch".to_string(),
            state: "ready".to_string(),
            summary: "Legacy patch proposal created locally.".to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: Some("ready".to_string()),
            details: json!({
                "published_session": {
                    "prompt": "legacy prompt",
                    "response": "legacy response",
                    "diff": "--- a/src/file.c\n+++ b/src/file.c\n",
                }
            }),
            created_at: "2026-03-29T00:00:00Z".to_string(),
        };
        let invalidation = PatchAttempt {
            cluster_id: "issue-1".to_string(),
            install_id: "reviewer-install".to_string(),
            outcome: "report".to_string(),
            state: "ready".to_string(),
            summary: "Previous patch was re-reviewed and reopened.".to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: Some("review-rejected".to_string()),
            details: json!({
                "invalidates_best_patch": true,
                "invalidates_patch_created_at": legacy_patch.created_at.clone(),
                "patch_refresh_failure_kind": "review",
            }),
            created_at: "2026-03-30T00:00:00Z".to_string(),
        };

        let (best_patch, best_triage) =
            best_attempts_from_candidates(vec![legacy_patch, invalidation]);

        assert!(best_patch.is_none());
        assert!(best_triage.is_none());
    }

    #[test]
    fn superseding_ready_patch_replaces_older_public_best_patch() {
        let legacy_patch = PatchAttempt {
            cluster_id: "issue-1".to_string(),
            install_id: "worker-install".to_string(),
            outcome: "patch".to_string(),
            state: "ready".to_string(),
            summary: "Older patch proposal created locally.".to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: Some("ready".to_string()),
            details: json!({
                "published_session": {
                    "prompt": "legacy prompt",
                    "response": "Applied a patch.",
                    "diff": "--- a/src/file.c\n+++ b/src/file.c\n",
                },
                "validation_quality": "partial",
                "review_rounds_completed": 1,
                "review_findings_resolved": 0
            }),
            created_at: "2026-03-29T00:00:00Z".to_string(),
        };
        let replacement_patch = PatchAttempt {
            cluster_id: "issue-1".to_string(),
            install_id: "reviewer-install".to_string(),
            outcome: "patch".to_string(),
            state: "ready".to_string(),
            summary: "Newer patch proposal created locally.".to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: Some("ready".to_string()),
            details: json!({
                "published_session": {
                    "prompt": "new prompt",
                    "response": "Ran `cmake --build build-fix --target kded_keyboard -j2` successfully.",
                    "diff": "--- a/src/file.c\n+++ b/src/file.c\n@@\n-old\n+new\n",
                },
                "validation_quality": "passed",
                "review_rounds_completed": 2,
                "review_findings_resolved": 1,
                "supersedes_best_patch": true,
                "supersedes_patch_created_at": legacy_patch.created_at.clone()
            }),
            created_at: "2026-03-30T00:00:00Z".to_string(),
        };

        let (best_patch, _) =
            best_attempts_from_candidates(vec![legacy_patch.clone(), replacement_patch.clone()]);

        let best_patch = best_patch.expect("replacement patch should remain public best patch");
        assert_eq!(best_patch.summary, replacement_patch.summary);
        assert_eq!(best_patch.created_at, replacement_patch.created_at);
    }

    #[test]
    fn worker_context_keeps_latest_patch_after_public_invalidation() {
        let (_dir, db) = init_test_server_db();
        let connection = sqlite_test_connection(&db);
        let representative = sample_crash(
            "postgres",
            "Top frame: internal_load_library [postgres]",
            &["internal_load_library [postgres]"],
        );
        insert_test_issue(
            &connection,
            "issue-1",
            "cluster-1",
            110,
            "2026-03-30T00:00:00Z",
            &representative,
            &["other-install"],
        );
        let legacy_patch = PatchAttempt {
            cluster_id: "issue-1".to_string(),
            install_id: "worker-install".to_string(),
            outcome: "patch".to_string(),
            state: "ready".to_string(),
            summary: "Legacy patch proposal created locally.".to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: Some("ready".to_string()),
            details: json!({
                "published_session": {
                    "prompt": "legacy prompt",
                    "response": "legacy response",
                    "diff": "--- a/src/backend/utils/fmgr/dfmgr.c\n+++ b/src/backend/utils/fmgr/dfmgr.c\n",
                }
            }),
            created_at: "2026-03-29T00:00:00Z".to_string(),
        };
        let invalidation = PatchAttempt {
            cluster_id: "issue-1".to_string(),
            install_id: "reviewer-install".to_string(),
            outcome: "report".to_string(),
            state: "ready".to_string(),
            summary: "Previous patch was re-reviewed and reopened.".to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: Some("review-rejected".to_string()),
            details: json!({
                "invalidates_best_patch": true,
                "invalidates_patch_created_at": legacy_patch.created_at.clone(),
                "patch_refresh_failure_kind": "review",
            }),
            created_at: "2026-03-30T00:00:00Z".to_string(),
        };
        insert_test_attempt(
            &connection,
            "attempt-patch",
            "lease-patch",
            &legacy_patch,
            "2026-03-29T00:00:00Z",
        );
        insert_test_attempt(
            &connection,
            "attempt-report",
            "lease-report",
            &invalidation,
            "2026-03-30T00:00:00Z",
        );

        refresh_issue_cluster_best_results_sqlite(&connection, "issue-1").unwrap();
        let best_patch_json: Option<String> = connection
            .query_row(
                "SELECT best_patch_json FROM issue_clusters WHERE id = ?1",
                ["issue-1"],
                |row| row.get(0),
            )
            .unwrap();
        assert!(best_patch_json.is_none());

        let worker_context = test_runtime()
            .block_on(load_latest_patch_context_for_worker(&db, "issue-1"))
            .unwrap()
            .unwrap();
        assert_eq!(worker_context.summary, legacy_patch.summary);
        assert_eq!(worker_context.created_at, legacy_patch.created_at);
    }

    #[test]
    fn worker_queue_prefers_public_issue_from_other_install() {
        let (_dir, db) = init_test_server_db();
        let connection = sqlite_test_connection(&db);
        let self_issue = sample_crash(
            "self-only",
            "Top frame: self_only_frame [self-only.so]",
            &["self_only_frame [self-only.so]"],
        );
        let shared_issue = sample_crash(
            "shared",
            "Top frame: shared_frame [shared.so]",
            &["shared_frame [shared.so]"],
        );

        insert_test_issue(
            &connection,
            "issue-self",
            "cluster-self",
            200,
            "2026-03-29T18:00:00Z",
            &self_issue,
            &["worker-install"],
        );
        insert_test_issue(
            &connection,
            "issue-shared",
            "cluster-shared",
            100,
            "2026-03-29T17:00:00Z",
            &shared_issue,
            &["other-install"],
        );

        let issue = test_runtime()
            .block_on(next_issue_for_worker(&db, "worker-install", 3600, None))
            .unwrap()
            .unwrap();

        assert_eq!(issue.id, "issue-shared");
    }

    #[test]
    fn worker_queue_prefers_fixable_runaway_issue_over_kernel_stuck_process() {
        let (_dir, db) = init_test_server_db();
        let connection = sqlite_test_connection(&db);
        let stuck_issue = sample_stuck_process_investigation(
            "kworker/u33:2+i915_flip",
            2141,
            "2026-03-30T16:53:47Z",
        );
        let runaway_issue = sample_runaway_investigation("kdeconnectd", Some("kdeconnect"));

        insert_test_issue(
            &connection,
            "issue-stuck",
            "cluster-stuck",
            110,
            "2026-03-30T16:53:47Z",
            &stuck_issue,
            &["other-install-a"],
        );
        insert_test_issue(
            &connection,
            "issue-runaway",
            "cluster-runaway",
            106,
            "2026-03-30T16:53:47Z",
            &runaway_issue,
            &["other-install-b"],
        );

        let issue = test_runtime()
            .block_on(next_issue_for_worker(&db, "worker-install", 3600, None))
            .unwrap()
            .unwrap();

        assert_eq!(issue.id, "issue-runaway");
    }

    #[test]
    fn public_priority_prefers_fixable_user_space_issue_over_kernel_hang() {
        let stuck = sample_stuck_process_investigation(
            "kworker/u33:2+i915_flip",
            2141,
            "2026-03-30T16:53:47Z",
        );
        let runaway = sample_runaway_investigation("kdeconnectd", Some("kdeconnect"));
        let mut entries = vec![
            public_issue_candidate_for_test("issue-stuck", &stuck),
            public_issue_candidate_for_test("issue-runaway", &runaway),
        ];

        entries.sort_by(compare_public_issue_priority);

        assert_eq!(entries[0].issue.id, "issue-runaway");
    }

    #[test]
    fn worker_queue_falls_back_to_self_reported_issue_when_shared_queue_is_empty() {
        let (_dir, db) = init_test_server_db();
        let connection = sqlite_test_connection(&db);
        let self_issue = sample_crash(
            "self-only",
            "Top frame: self_only_frame [self-only.so]",
            &["self_only_frame [self-only.so]"],
        );

        insert_test_issue(
            &connection,
            "issue-self",
            "cluster-self",
            200,
            "2026-03-29T18:00:00Z",
            &self_issue,
            &["worker-install"],
        );

        let issue = test_runtime()
            .block_on(next_issue_for_worker(&db, "worker-install", 3600, None))
            .unwrap()
            .unwrap();

        assert_eq!(issue.id, "issue-self");
    }

    #[test]
    fn worker_queue_skips_recently_attempted_issue_when_other_shared_work_exists() {
        let (_dir, db) = init_test_server_db();
        let connection = sqlite_test_connection(&db);
        let hot_issue = sample_crash(
            "postgres",
            "Top frame: hot_issue_frame [postgres]",
            &["hot_issue_frame [postgres]"],
        );
        let alternate_issue = sample_crash(
            "qbittorrent",
            "Top frame: alternate_issue_frame [qbittorrent]",
            &["alternate_issue_frame [qbittorrent]"],
        );
        let now = Utc::now();
        let recent_attempt_at = (now - Duration::minutes(5)).to_rfc3339();
        let last_seen = now.to_rfc3339();

        insert_test_issue(
            &connection,
            "issue-hot",
            "cluster-hot",
            200,
            &last_seen,
            &hot_issue,
            &["other-install-a"],
        );
        insert_test_issue(
            &connection,
            "issue-alt",
            "cluster-alt",
            180,
            &last_seen,
            &alternate_issue,
            &["other-install-b"],
        );
        insert_test_attempt(
            &connection,
            "attempt-hot",
            "lease-hot",
            &PatchAttempt {
                cluster_id: "issue-hot".to_string(),
                install_id: "reviewer-install".to_string(),
                outcome: "report".to_string(),
                state: "ready".to_string(),
                summary: "A fresh attempt was just recorded.".to_string(),
                bundle_path: None,
                output_path: None,
                validation_status: Some("ready".to_string()),
                details: json!({}),
                created_at: recent_attempt_at.clone(),
            },
            &recent_attempt_at,
        );

        let issue = test_runtime()
            .block_on(next_issue_for_worker(&db, "worker-install", 3600, None))
            .unwrap()
            .unwrap();

        assert_eq!(issue.id, "issue-alt");
    }

    #[test]
    fn worker_queue_falls_back_to_oldest_recent_attempt_when_everything_is_cooling_down() {
        let (_dir, db) = init_test_server_db();
        let connection = sqlite_test_connection(&db);
        let first_issue = sample_crash(
            "postgres",
            "Top frame: first_issue_frame [postgres]",
            &["first_issue_frame [postgres]"],
        );
        let second_issue = sample_crash(
            "qbittorrent",
            "Top frame: second_issue_frame [qbittorrent]",
            &["second_issue_frame [qbittorrent]"],
        );
        let now = Utc::now();
        let newer_attempt_at = (now - Duration::minutes(5)).to_rfc3339();
        let older_attempt_at = (now - Duration::minutes(15)).to_rfc3339();
        let last_seen = now.to_rfc3339();

        insert_test_issue(
            &connection,
            "issue-newer",
            "cluster-newer",
            220,
            &last_seen,
            &first_issue,
            &["other-install-a"],
        );
        insert_test_issue(
            &connection,
            "issue-older",
            "cluster-older",
            180,
            &last_seen,
            &second_issue,
            &["other-install-b"],
        );
        insert_test_attempt(
            &connection,
            "attempt-newer",
            "lease-newer",
            &PatchAttempt {
                cluster_id: "issue-newer".to_string(),
                install_id: "reviewer-install-a".to_string(),
                outcome: "report".to_string(),
                state: "ready".to_string(),
                summary: "A very recent attempt was recorded.".to_string(),
                bundle_path: None,
                output_path: None,
                validation_status: Some("ready".to_string()),
                details: json!({}),
                created_at: newer_attempt_at.clone(),
            },
            &newer_attempt_at,
        );
        insert_test_attempt(
            &connection,
            "attempt-older",
            "lease-older",
            &PatchAttempt {
                cluster_id: "issue-older".to_string(),
                install_id: "reviewer-install-b".to_string(),
                outcome: "report".to_string(),
                state: "ready".to_string(),
                summary: "An older recent attempt was recorded.".to_string(),
                bundle_path: None,
                output_path: None,
                validation_status: Some("ready".to_string()),
                details: json!({}),
                created_at: older_attempt_at.clone(),
            },
            &older_attempt_at,
        );

        let issue = test_runtime()
            .block_on(next_issue_for_worker(&db, "worker-install", 3600, None))
            .unwrap()
            .unwrap();

        assert_eq!(issue.id, "issue-older");
    }

    #[test]
    fn sanitize_public_text_removes_syslog_prefix_and_local_paths() {
        let sanitized = sanitize_public_text(
            "Mar 29 14:35:42 nucat kernel: usb 1-4.2.4.1: device descriptor read/64, error -71 [/home/kom/.zoom/data/file.so]",
        );
        assert!(!sanitized.contains("nucat"));
        assert!(!sanitized.contains("Mar 29"));
        assert!(!sanitized.contains("/home/kom"));
        assert!(sanitized.contains("[file.so]"));
    }

    #[test]
    fn kernel_and_apparmor_findings_are_hidden_from_public_queue() {
        let kernel = SharedOpportunity {
            local_opportunity_id: 1,
            opportunity: OpportunityRecord {
                id: 1,
                finding_id: 1,
                kind: "warning".to_string(),
                title: "Kernel warning".to_string(),
                score: 64,
                state: "open".to_string(),
                summary: "Mar 29 14:35:42 nucat kernel: usb 1-4.2.4.1: device descriptor read/64, error -71".to_string(),
                evidence: json!({}),
                repo_root: None,
                ecosystem: None,
                created_at: "2026-03-29T11:00:00Z".to_string(),
                updated_at: "2026-03-29T11:00:00Z".to_string(),
            },
            finding: FindingRecord {
                id: 1,
                kind: "warning".to_string(),
                title: "Kernel warning".to_string(),
                severity: "medium".to_string(),
                fingerprint: "x".to_string(),
                summary: "Mar 29 14:35:42 nucat kernel: usb 1-4.2.4.1: device descriptor read/64, error -71".to_string(),
                details: json!({"line": "Mar 29 14:35:42 nucat kernel: usb 1-4.2.4.1: device descriptor read/64, error -71"}),
                artifact_name: None,
                artifact_path: None,
                package_name: None,
                repo_root: None,
                ecosystem: None,
                first_seen: "2026-03-29T11:00:00Z".to_string(),
                last_seen: "2026-03-29T11:00:00Z".to_string(),
            },
        };
        let apparmor = SharedOpportunity {
            local_opportunity_id: 2,
            opportunity: OpportunityRecord {
                id: 2,
                finding_id: 2,
                kind: "warning".to_string(),
                title: "AppArmor denial in cupsd".to_string(),
                score: 64,
                state: "open".to_string(),
                summary: "AppArmor denied cupsd: open /proc/9019/mounts".to_string(),
                evidence: json!({}),
                repo_root: None,
                ecosystem: None,
                created_at: "2026-03-29T11:00:00Z".to_string(),
                updated_at: "2026-03-29T11:00:00Z".to_string(),
            },
            finding: FindingRecord {
                id: 2,
                kind: "warning".to_string(),
                title: "AppArmor denial in cupsd".to_string(),
                severity: "medium".to_string(),
                fingerprint: "y".to_string(),
                summary: "AppArmor denied cupsd: open /proc/9019/mounts".to_string(),
                details: json!({"subsystem": "apparmor", "profile": "/usr/sbin/cupsd", "operation": "open", "name": "/proc/9019/mounts"}),
                artifact_name: None,
                artifact_path: None,
                package_name: Some("cups-daemon".to_string()),
                repo_root: None,
                ecosystem: None,
                first_seen: "2026-03-29T11:00:00Z".to_string(),
                last_seen: "2026-03-29T11:00:00Z".to_string(),
            },
        };

        assert!(!build_public_issue_fields(&kernel).visible);
        assert!(!build_public_issue_fields(&apparmor).visible);
    }

    #[test]
    fn complaint_findings_are_hidden_from_public_queue() {
        let complaint = SharedOpportunity {
            local_opportunity_id: 3,
            opportunity: OpportunityRecord {
                id: 3,
                finding_id: 3,
                kind: "complaint".to_string(),
                title: "User complaint: spectacle crashes on Wayland".to_string(),
                score: 50,
                state: "open".to_string(),
                summary: "spectacle fails to start and prints libEGL warnings".to_string(),
                evidence: json!({}),
                repo_root: None,
                ecosystem: None,
                created_at: "2026-04-03T00:00:00Z".to_string(),
                updated_at: "2026-04-03T00:00:00Z".to_string(),
            },
            finding: FindingRecord {
                id: 3,
                kind: "complaint".to_string(),
                title: "User complaint: spectacle crashes on Wayland".to_string(),
                severity: "medium".to_string(),
                fingerprint: "complaint".to_string(),
                summary: "spectacle fails to start and prints libEGL warnings".to_string(),
                details: json!({"subsystem": "user-complaint"}),
                artifact_name: None,
                artifact_path: None,
                package_name: Some("spectacle".to_string()),
                repo_root: None,
                ecosystem: None,
                first_seen: "2026-04-03T00:00:00Z".to_string(),
                last_seen: "2026-04-03T00:00:00Z".to_string(),
            },
        };

        assert!(!build_public_issue_fields(&complaint).visible);
    }

    #[test]
    fn crash_cluster_key_ignores_event_specific_noise() {
        let a = sample_crash(
            "zoom",
            "Top frame: _ZN9QtPrivate... [/opt/zoom/zoom]",
            &[
                "_ZN9QtPrivate25QMetaTypeInterfaceWrapperIbE24IsConstMetaTypeInterfaceE+0x1af131d [/opt/zoom/zoom]",
            ],
        );
        let b = sample_crash(
            "zoom",
            "Top frame: _ZN9QtPrivate... [/home/kom/.zoom/data/cache/zoom]",
            &[
                "_ZN9QtPrivate25QMetaTypeInterfaceWrapperIbE24IsConstMetaTypeInterfaceE+0x9 [/home/kom/.zoom/data/cache/zoom]",
            ],
        );

        assert_eq!(cluster_key_for(&a), cluster_key_for(&b));
    }

    #[test]
    fn hotspot_cluster_key_collapses_unresolved_offsets() {
        let a = sample_hotspot(
            "redis-check-rdb",
            "libc.so.6",
            "0x000000000017c318",
            "libc6",
        );
        let b = sample_hotspot(
            "redis-check-rdb",
            "libc.so.6",
            "0x000000000017b73b",
            "libc6",
        );
        let c = sample_hotspot(
            "redis-check-rdb",
            "libjemalloc.so.2",
            "(deleted) [.] 0x0000000000009150",
            "redis-tools",
        );
        let d = sample_hotspot("node", "[JIT]", "tid 1310 [.] 0x000071d33b3f2f00", "nodejs");
        let e = sample_hotspot("node", "[JIT]", "tid 1310 [.] 0x000071d33b3f30ab", "nodejs");

        assert_eq!(cluster_key_for(&a), cluster_key_for(&b));
        assert_ne!(cluster_key_for(&a), cluster_key_for(&c));
        assert_eq!(cluster_key_for(&d), cluster_key_for(&e));
        assert_eq!(
            build_public_issue_fields(&c).title,
            "CPU hotspot in redis-check-rdb: unresolved offset in libjemalloc.so.2"
        );
        assert_eq!(
            build_public_issue_fields(&d).title,
            "CPU hotspot in node: unresolved offset in [JIT]"
        );
    }

    #[test]
    fn stuck_process_cluster_key_ignores_kworker_slot_and_runtime_noise() {
        let a = sample_stuck_process_investigation(
            "kworker/u33:0+i915_flip",
            152,
            "2026-03-29T17:52:00Z",
        );
        let b = sample_stuck_process_investigation(
            "kworker/u33:3+i915_flip",
            2141,
            "2026-03-29T17:52:00Z",
        );

        assert_eq!(cluster_key_for(&a), cluster_key_for(&b));

        let public = build_public_issue_fields(&a);
        assert_eq!(
            public.title,
            "Stuck D-state investigation for kworker+i915_flip"
        );
        assert!(public.summary.contains("kworker+i915_flip"));
        assert!(!public.summary.contains("152s"));
        assert_eq!(inferred_public_source_package(&a).as_deref(), Some("linux"));
    }

    #[test]
    fn canonical_patch_attempt_summary_removes_legacy_duplicate_loop_words() {
        assert_eq!(
            canonical_attempt_summary_text(
                "htop likely remains stuck in a unknown userspace loop loop."
            ),
            "htop likely remains stuck in an unclassified userspace loop."
        );
        assert_eq!(
            canonical_attempt_summary_text(
                "jbd2/sda3-8 likely remains stuck in a unknown uninterruptible wait wait."
            ),
            "jbd2/sda3-8 likely remains stuck in an unclassified uninterruptible wait."
        );
    }

    #[test]
    fn public_text_uses_canonical_loop_wording() {
        assert_eq!(
            sanitize_public_text(
                "htop is stuck in a likely unknown userspace loop loop: repeated recvfrom x120."
            ),
            "htop is stuck in a likely unclassified userspace loop: repeated recvfrom x120."
        );
    }

    #[test]
    fn oom_kill_cluster_key_prefers_target_and_memcg_family() {
        let a = sample_oom_kill_investigation("chrome", "google-chrome");
        let mut b = sample_oom_kill_investigation("chrome", "google-chrome");
        b.finding.summary = "chrome was killed by the kernel OOM killer after reaching about 6400 MiB anonymous RSS in `google-chrome`.".to_string();
        b.finding.details["anon_rss_kb"] = json!(6676808u64);
        b.opportunity.summary = b.finding.summary.clone();

        assert_eq!(cluster_key_for(&a), cluster_key_for(&b));

        let public = build_public_issue_fields(&a);
        assert_eq!(public.title, "OOM kill investigation for chrome");
        assert!(public.summary.contains("kernel OOM killer"));
        assert!(public.summary.contains("google-chrome"));
    }

    #[test]
    fn desktop_resume_cluster_key_prefers_graphics_stack_family() {
        let a = sample_desktop_resume_investigation(
            "radeon X11 desktop",
            &["Xorg", "kwin_x11"],
            "2026-03-30T01:38:58Z",
        );
        let b = sample_desktop_resume_investigation(
            "radeon X11 desktop",
            &["kwin_x11", "Xorg"],
            "2026-03-30T01:39:03Z",
        );

        assert_eq!(cluster_key_for(&a), cluster_key_for(&b));

        let public = build_public_issue_fields(&a);
        assert_eq!(
            public.title,
            "Desktop resume failure investigation for radeon X11 desktop"
        );
        assert!(public.summary.contains("suspend/resume"));
        assert!(public.summary.contains("Xorg, kwin_x11"));
    }

    #[test]
    fn desktop_graphics_session_cluster_key_prefers_shared_session_family() {
        let a = sample_desktop_graphics_session_investigation(
            "KDE Wayland desktop",
            &["spectacle", "dolphin", "kate"],
            "2026-04-03T10:00:00Z",
        );
        let b = sample_desktop_graphics_session_investigation(
            "KDE Wayland desktop",
            &["kate", "spectacle", "dolphin"],
            "2026-04-03T10:00:02Z",
        );

        assert_eq!(cluster_key_for(&a), cluster_key_for(&b));

        let public = build_public_issue_fields(&a);
        assert_eq!(
            public.title,
            "Desktop graphics/session failure investigation for KDE Wayland desktop"
        );
        assert!(
            public
                .summary
                .contains("shared compositor or graphics-session failure")
        );
    }

    #[test]
    fn desktop_graphics_session_issue_cards_explain_broad_user_impact() {
        let candidate = public_issue_candidate_for_test(
            "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5fa",
            &sample_desktop_graphics_session_investigation(
                "KDE Wayland desktop",
                &["spectacle", "dolphin", "kate"],
                "2026-04-03T10:00:00Z",
            ),
        );

        let markup = render_issue_queue_card(&candidate);
        assert!(markup.contains("Desktop graphics failure"));
        assert!(markup.contains("multiple apps may have failed to launch"));
    }

    #[test]
    fn recluster_issue_state_merges_duplicate_stuck_process_investigations() {
        let a = sample_stuck_process_investigation(
            "kworker/u33:0+i915_flip",
            152,
            "2026-03-29T17:52:00Z",
        );
        let b = sample_stuck_process_investigation(
            "kworker/u33:3+i915_flip",
            2141,
            "2026-03-29T17:52:30Z",
        );
        let state = CurrentIssueState {
            issue_clusters: vec![
                CurrentIssueCluster {
                    id: "issue-a".to_string(),
                    cluster_key: hash_text("legacy-a"),
                    kind: a.opportunity.kind.clone(),
                    title: a.opportunity.title.clone(),
                    summary: a.opportunity.summary.clone(),
                    public_title: sanitize_public_text(&a.opportunity.title),
                    public_summary: sanitize_public_text(&a.opportunity.summary),
                    public_visible: true,
                    package_name: None,
                    source_package: Some("".to_string()),
                    ecosystem: None,
                    severity: Some("high".to_string()),
                    score: a.opportunity.score,
                    corroboration_count: 1,
                    quarantined: true,
                    promoted: false,
                    representative_json: serde_json::to_value(&a).unwrap(),
                    best_patch_json: None,
                    best_triage_json: None,
                    last_seen: "2026-03-29T17:52:00Z".to_string(),
                },
                CurrentIssueCluster {
                    id: "issue-b".to_string(),
                    cluster_key: hash_text("legacy-b"),
                    kind: b.opportunity.kind.clone(),
                    title: b.opportunity.title.clone(),
                    summary: b.opportunity.summary.clone(),
                    public_title: sanitize_public_text(&b.opportunity.title),
                    public_summary: sanitize_public_text(&b.opportunity.summary),
                    public_visible: true,
                    package_name: None,
                    source_package: None,
                    ecosystem: None,
                    severity: Some("high".to_string()),
                    score: b.opportunity.score,
                    corroboration_count: 2,
                    quarantined: false,
                    promoted: true,
                    representative_json: serde_json::to_value(&b).unwrap(),
                    best_patch_json: None,
                    best_triage_json: None,
                    last_seen: "2026-03-29T17:52:30Z".to_string(),
                },
            ],
            cluster_reports: vec![
                CurrentClusterReport {
                    cluster_id: "issue-a".to_string(),
                    install_id: "install-a".to_string(),
                    submission_id: "sub-a".to_string(),
                    created_at: "2026-03-29T17:52:00Z".to_string(),
                },
                CurrentClusterReport {
                    cluster_id: "issue-b".to_string(),
                    install_id: "install-b".to_string(),
                    submission_id: "sub-b".to_string(),
                    created_at: "2026-03-29T17:52:30Z".to_string(),
                },
            ],
            worker_leases: Vec::new(),
            patch_attempts: Vec::new(),
            evidence_requests: Vec::new(),
        };

        let reclustered = recluster_issue_state(state, 2).unwrap().unwrap();

        assert_eq!(reclustered.issue_clusters.len(), 1);
        assert_eq!(reclustered.cluster_reports.len(), 2);
        assert_eq!(reclustered.issue_clusters[0].id, "issue-b");
        assert_eq!(reclustered.issue_clusters[0].corroboration_count, 2);
        assert!(reclustered.issue_clusters[0].promoted);
        assert_eq!(
            reclustered.issue_clusters[0].public_title,
            "Stuck D-state investigation for kworker+i915_flip"
        );
        assert_eq!(
            reclustered.issue_clusters[0].source_package.as_deref(),
            Some("linux")
        );
    }

    #[test]
    fn legacy_migration_merges_duplicate_crashes_and_emits_uuid_ids() {
        let representative = sample_crash(
            "zoom",
            "Top frame: _ZN9QtPrivate... [/opt/zoom/zoom]",
            &[
                "_ZN9QtPrivate25QMetaTypeInterfaceWrapperIbE24IsConstMetaTypeInterfaceE+0x1af131d [/opt/zoom/zoom]",
            ],
        );
        let legacy = LegacyServerState {
            submissions: vec![
                LegacySubmission {
                    id: 1,
                    install_id: "install-a".to_string(),
                    content_hash: "a".to_string(),
                    payload_hash: "pa".to_string(),
                    received_at: "2026-03-29T11:00:00Z".to_string(),
                    remote_addr: None,
                    quarantined: false,
                    bundle_json: json!({}),
                },
                LegacySubmission {
                    id: 2,
                    install_id: "install-b".to_string(),
                    content_hash: "b".to_string(),
                    payload_hash: "pb".to_string(),
                    received_at: "2026-03-29T11:01:00Z".to_string(),
                    remote_addr: None,
                    quarantined: false,
                    bundle_json: json!({}),
                },
            ],
            issue_clusters: vec![
                LegacyIssueCluster {
                    id: 10,
                    kind: "crash".to_string(),
                    title: representative.opportunity.title.clone(),
                    summary: representative.opportunity.summary.clone(),
                    package_name: Some("zoom".to_string()),
                    source_package: None,
                    ecosystem: None,
                    severity: Some("high".to_string()),
                    score: 98,
                    promoted: true,
                    representative_json: serde_json::to_value(&representative).unwrap(),
                    best_patch_json: None,
                    last_seen: "2026-03-29T11:02:00Z".to_string(),
                },
                LegacyIssueCluster {
                    id: 11,
                    kind: "crash".to_string(),
                    title: representative.opportunity.title.clone(),
                    summary: representative.opportunity.summary.clone(),
                    package_name: Some("zoom".to_string()),
                    source_package: None,
                    ecosystem: None,
                    severity: Some("high".to_string()),
                    score: 97,
                    promoted: true,
                    representative_json: serde_json::to_value(&representative).unwrap(),
                    best_patch_json: None,
                    last_seen: "2026-03-29T11:03:00Z".to_string(),
                },
            ],
            cluster_reports: vec![
                LegacyClusterReport {
                    cluster_id: 10,
                    install_id: "install-a".to_string(),
                    submission_id: 1,
                    created_at: "2026-03-29T11:02:00Z".to_string(),
                },
                LegacyClusterReport {
                    cluster_id: 11,
                    install_id: "install-b".to_string(),
                    submission_id: 2,
                    created_at: "2026-03-29T11:03:00Z".to_string(),
                },
            ],
            worker_leases: Vec::new(),
            patch_attempts: Vec::new(),
            evidence_requests: Vec::new(),
            rate_events: Vec::new(),
        };

        let migrated = migrate_legacy_state(legacy, 2).unwrap();
        assert_eq!(migrated.issue_clusters.len(), 1);
        assert_eq!(migrated.cluster_reports.len(), 2);
        assert_eq!(migrated.issue_clusters[0].corroboration_count, 2);
        assert!(Uuid::parse_str(&migrated.issue_clusters[0].id).is_ok());
        assert!(Uuid::parse_str(&migrated.submissions[0].id).is_ok());
    }

    #[test]
    fn install_hello_warns_for_older_compatible_clients() {
        let compatibility = evaluate_client_compatibility(CURRENT_PROTOCOL_VERSION, "0.0.1");
        assert!(compatibility.upgrade_available);
        assert!(!compatibility.upgrade_required);
    }

    #[test]
    fn incompatible_clients_are_rejected_on_mutating_endpoints() {
        let request = ClientHello {
            install_id: "install-a".to_string(),
            version: "0.0.1".to_string(),
            protocol_version: MIN_SUPPORTED_PROTOCOL_VERSION.saturating_sub(1),
            mode: crate::models::ParticipationMode::Submitter,
            hostname: None,
            capabilities: Vec::new(),
            has_codex: false,
            richer_evidence_allowed: false,
            patch_driver: None,
            patch_model: None,
        };

        let error = reject_incompatible_client(&request).unwrap_err();
        assert_eq!(error.status, StatusCode::UPGRADE_REQUIRED);
        assert!(error.message.contains("Upgrade fixer"));
    }
}
