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
    evaluate_client_compatibility,
};
use crate::util::{hash_text, now_rfc3339};
use anyhow::{Context, Result};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path as AxumPath, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
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

.nav-links a {
    padding: 0.55rem 0.9rem;
    border-radius: 999px;
    border: 1px solid transparent;
}

.nav-links a.active,
.nav-links a:hover {
    border-color: var(--line);
    background: rgba(255, 255, 255, 0.5);
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
}
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
    last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublishedAttemptSession {
    prompt: String,
    response: Option<String>,
    diff: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PublicAttempt {
    outcome: String,
    state: String,
    summary: String,
    validation_status: Option<String>,
    created_at: String,
    published_session: Option<PublishedAttemptSession>,
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
    last_seen: String,
    attempts: Vec<PublicAttempt>,
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
    last_submission_at: Option<String>,
    top_issues: Vec<PublicIssue>,
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
    init_db(&db, &config).await?;
    let state = Arc::new(ServerState {
        config: config.clone(),
        db,
    });

    let app = Router::new()
        .route("/", get(landing_page))
        .route("/issues", get(public_issues_page))
        .route("/issues/{id}", get(public_issue_detail_page))
        .route("/healthz", get(healthz))
        .route("/assets/app.css", get(stylesheet))
        .route("/v1/install/hello", post(install_hello))
        .route("/v1/submissions", post(submit_bundle))
        .route("/v1/work/pull", post(pull_work))
        .route("/v1/work/{lease_id}/result", post(submit_work_result))
        .route("/v1/issues", get(list_issues))
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
    let issues = load_public_issues(&state.db, 100).await?;
    Ok(Html(render_issues_page(&issues)))
}

async fn public_issue_detail_page(
    State(state): State<Arc<ServerState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Html<String>, ApiError> {
    validate_uuid_param(&id, "issue id")?;
    let issue = load_public_issue_detail(&state.db, id).await?;
    Ok(Html(render_issue_detail_page(&issue)))
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
        issue_ids.push(issue_id);
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

    let Some(issue) = next_issue_for_worker(&state.db)
        .await
        .map_err(ApiError::internal)?
    else {
        return Ok(Json(WorkOffer {
            message: "no promoted work is currently available".to_string(),
            lease: None,
        }));
    };
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
    let result_clone = result.clone();
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

async fn get_issue(
    State(state): State<Arc<ServerState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<PublicIssueDetail>, ApiError> {
    validate_uuid_param(&id, "issue id")?;
    let issue = load_public_issue_detail(&state.db, id).await?;
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
            banned_until TIMESTAMPTZ
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
            banned_until TEXT
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
    Ok(())
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
            Some(MigratedPatchAttempt {
                id: new_server_id(),
                cluster_id: cluster_id.clone(),
                lease_id: lease_id.clone(),
                install_id: attempt.install_id.clone(),
                outcome: attempt.outcome.clone(),
                state: attempt.state.clone(),
                summary: attempt.summary.clone(),
                bundle_json: rewrite_worker_result_json(
                    attempt.bundle_json.clone(),
                    &cluster_id,
                    lease_id.as_deref(),
                ),
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
    for attempt in &patch_attempts {
        if attempt.outcome == "patch" && attempt.state == "ready" {
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
            patch_attempt_best
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
            issue.best_patch_json = Some(rewrite_patch_attempt_json(best_patch, &issue.id));
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
                     quarantined, promoted, representative_json, best_patch_json, last_seen)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
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
                     quarantined, promoted, representative_json, best_patch_json, last_seen)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
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
        INSERT INTO installs (install_id, first_seen, last_seen, mode, hostname, version, has_codex, capabilities_json, last_ip)
        VALUES ($1, $2, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (install_id) DO UPDATE SET
            last_seen = EXCLUDED.last_seen,
            mode = EXCLUDED.mode,
            hostname = EXCLUDED.hostname,
            version = EXCLUDED.version,
            has_codex = EXCLUDED.has_codex,
            capabilities_json = EXCLUDED.capabilities_json,
            last_ip = EXCLUDED.last_ip
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
                ],
            )
            .await?;
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            connection.execute(
                "
        INSERT INTO installs (install_id, first_seen, last_seen, mode, hostname, version, has_codex, capabilities_json, last_ip)
        VALUES (?1, ?2, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT(install_id) DO UPDATE SET
            last_seen = excluded.last_seen,
            mode = excluded.mode,
            hostname = excluded.hostname,
            version = excluded.version,
            has_codex = excluded.has_codex,
            capabilities_json = excluded.capabilities_json,
            last_ip = excluded.last_ip
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
            if result.attempt.outcome == "patch" && result.attempt.state == "ready" {
                db.execute(
                    "
                UPDATE issue_clusters
                SET best_patch_json = $2
                WHERE id = $1
                ",
                    &[&cluster_id, &serde_json::to_value(&result.attempt)?],
                )
                .await?;
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
            if result.attempt.outcome == "patch" && result.attempt.state == "ready" {
                connection.execute(
                    "
                UPDATE issue_clusters
                SET best_patch_json = ?2
                WHERE id = ?1
                ",
                    params![cluster_id, serde_json::to_string(&result.attempt)?],
                )?;
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
    let source_package = item
        .opportunity
        .evidence
        .get("source_package")
        .and_then(Value::as_str)
        .map(ToString::to_string);
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

async fn next_issue_for_worker(db: &ServerDb) -> Result<Option<IssueCluster>> {
    match db {
        ServerDb::Postgres(db) => {
            let row = db
                .query_opt(
                    "
        SELECT id, cluster_key, kind, title, summary, package_name, source_package, ecosystem,
               severity, score, corroboration_count, quarantined, promoted, representative_json,
               best_patch_json, last_seen
        FROM issue_clusters issue
        WHERE promoted = TRUE
          AND public_visible = TRUE
          AND NOT EXISTS (
                SELECT 1
                FROM worker_leases lease
                WHERE lease.cluster_id = issue.id
                  AND lease.state = 'leased'
                  AND lease.expires_at > NOW()
          )
        ORDER BY
            (best_patch_json IS NOT NULL) ASC,
            CASE kind
                WHEN 'investigation' THEN 0
                WHEN 'crash' THEN 1
                WHEN 'warning' THEN 2
                ELSE 3
            END ASC,
            score DESC,
            last_seen DESC
        LIMIT 1
        ",
                    &[],
                )
                .await?;
            row.map(issue_from_row).transpose()
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path)?;
            let now = Utc::now().to_rfc3339();
            let row = connection
                .query_row(
                    "
        SELECT id, cluster_key, kind, title, summary, package_name, source_package, ecosystem,
               severity, score, corroboration_count, quarantined, promoted, representative_json,
               best_patch_json, last_seen
        FROM issue_clusters issue
        WHERE promoted = 1
          AND public_visible = 1
          AND NOT EXISTS (
                SELECT 1
                FROM worker_leases lease
                WHERE lease.cluster_id = issue.id
                  AND lease.state = 'leased'
                  AND lease.expires_at > ?1
          )
        ORDER BY
            CASE WHEN best_patch_json IS NOT NULL THEN 1 ELSE 0 END ASC,
            CASE kind
                WHEN 'investigation' THEN 0
                WHEN 'crash' THEN 1
                WHEN 'warning' THEN 2
                ELSE 3
            END ASC,
            score DESC,
            last_seen DESC
        LIMIT 1
        ",
                    [now],
                    issue_from_sqlite_row,
                )
                .optional()?;
            Ok(row)
        }
    }
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
                (SELECT MAX(received_at) FROM submissions)
            ",
                    &[],
                )
                .await
                .map_err(ApiError::internal)?;
            let last_submission_at = row
                .get::<_, Option<DateTime<Utc>>>(5)
                .map(|value| value.to_rfc3339());
            Ok(DashboardSnapshot {
                install_count: row.get(0),
                submission_count: row.get(1),
                promoted_issue_count: row.get(2),
                quarantined_issue_count: row.get(3),
                ready_patch_count: row.get(4),
                last_submission_at,
                top_issues: load_public_issues(db, 8).await?,
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
                last_submission_at,
                top_issues: load_public_issues(db, 8).await?,
            })
        }
    }
}

async fn load_public_issues(db: &ServerDb, limit: i64) -> Result<Vec<PublicIssue>, ApiError> {
    match db {
        ServerDb::Postgres(db) => {
            let rows = db
                .query(
                    "
            SELECT id, kind, public_title, public_summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count, (best_patch_json IS NOT NULL) AS best_patch_available,
                   last_seen
            FROM issue_clusters
            WHERE promoted = TRUE AND public_visible = TRUE
            ORDER BY score DESC, last_seen DESC
            LIMIT $1
            ",
                    &[&limit],
                )
                .await
                .map_err(ApiError::internal)?;
            rows.into_iter().map(public_issue_from_row).collect()
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path).map_err(ApiError::internal)?;
            let mut stmt = connection
                .prepare(
                    "
            SELECT id, kind, public_title, public_summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count, (best_patch_json IS NOT NULL) AS best_patch_available,
                   last_seen
            FROM issue_clusters
            WHERE promoted = 1 AND public_visible = 1
            ORDER BY score DESC, last_seen DESC
            LIMIT ?1
            ",
                )
                .map_err(ApiError::internal)?;
            let rows = stmt
                .query_map([limit], public_issue_from_sqlite_row)
                .map_err(ApiError::internal)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(ApiError::internal)
        }
    }
}

async fn load_public_issue(db: &ServerDb, id: String) -> Result<PublicIssue, ApiError> {
    match db {
        ServerDb::Postgres(db) => {
            let row = db
                .query_opt(
                    "
            SELECT id, kind, public_title, public_summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count, (best_patch_json IS NOT NULL) AS best_patch_available,
                   last_seen
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
            public_issue_from_row(row)
        }
        ServerDb::Sqlite(path) => {
            let connection = sqlite_connection(path).map_err(ApiError::internal)?;
            let row = connection
                .query_row(
                    "
            SELECT id, kind, public_title, public_summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count, (best_patch_json IS NOT NULL) AS best_patch_available,
                   last_seen
            FROM issue_clusters
            WHERE id = ?1 AND promoted = 1 AND public_visible = 1
            ",
                    [id.as_str()],
                    public_issue_from_sqlite_row,
                )
                .optional()
                .map_err(ApiError::internal)?;
            row.ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "issue not found"))
        }
    }
}

async fn load_public_issue_detail(
    db: &ServerDb,
    id: String,
) -> Result<PublicIssueDetail, ApiError> {
    let issue = load_public_issue(db, id.clone()).await?;
    let attempts = load_public_attempts(db, &id, 10).await?;
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
        last_seen: issue.last_seen,
        attempts,
    })
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
            rows.into_iter().map(public_attempt_from_row).collect()
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
                .query_map(params![cluster_id, limit], public_attempt_from_sqlite_row)
                .map_err(ApiError::internal)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(ApiError::internal)
        }
    }
}

fn public_issue_from_row(row: Row) -> Result<PublicIssue, ApiError> {
    let last_seen: DateTime<Utc> = row.get(11);
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
        best_patch_available: row.get(10),
        last_seen: last_seen.to_rfc3339(),
    })
}

fn public_attempt_from_row(row: Row) -> Result<PublicAttempt, ApiError> {
    let bundle_json: Value = row.get(0);
    let envelope =
        serde_json::from_value::<WorkerResultEnvelope>(bundle_json).map_err(ApiError::internal)?;
    Ok(public_attempt_from_patch_attempt(envelope.attempt))
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
        last_seen: row.get(11)?,
    })
}

fn public_attempt_from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PublicAttempt> {
    let raw: String = row.get(0)?;
    let envelope = serde_json::from_str::<WorkerResultEnvelope>(&raw).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(public_attempt_from_patch_attempt(envelope.attempt))
}

fn public_attempt_from_patch_attempt(attempt: PatchAttempt) -> PublicAttempt {
    let published_session = attempt
        .details
        .get("published_session")
        .cloned()
        .and_then(|value| serde_json::from_value::<PublishedAttemptSession>(value).ok());
    PublicAttempt {
        outcome: attempt.outcome,
        state: attempt.state,
        summary: attempt.summary,
        validation_status: attempt.validation_status,
        created_at: attempt.created_at,
        published_session,
    }
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
        "warning" => normalized_warning_cluster_key(item),
        _ => hash_text(format!(
            "{}|{}|{}|{}",
            item.finding.kind,
            item.finding.package_name.as_deref().unwrap_or("-"),
            item.opportunity.ecosystem.as_deref().unwrap_or("-"),
            sanitize_public_text(&item.opportunity.summary),
        )),
    }
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
    PublicIssueFields {
        title: sanitize_public_text(&item.opportunity.title),
        summary: sanitize_public_text(&item.opportunity.summary),
        visible: is_publicly_visible(item),
    }
}

fn is_publicly_visible(item: &SharedOpportunity) -> bool {
    match item.finding.kind.as_str() {
        "crash" => true,
        "hotspot" => true,
        "investigation" => true,
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
    text
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

fn normalize_stack_frame(frame: &str) -> String {
    let offset_re = Regex::new(r"\+0x[0-9a-fA-F]+").expect("valid frame offset regex");
    sanitize_public_text(&offset_re.replace_all(frame, "").to_string())
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
        "curl -fsSL {repo_key_url} | sudo gpg --dearmor -o /usr/share/keyrings/fixer-archive-keyring.gpg\n\
echo \"deb [signed-by=/usr/share/keyrings/fixer-archive-keyring.gpg] {apt_repo_url} stable main\" | \\\n\
  sudo tee /etc/apt/sources.list.d/fixer.list >/dev/null\n\
sudo apt update\n\
sudo apt install fixer"
    );
    let last_submission = snapshot
        .last_submission_at
        .as_deref()
        .map(format_timestamp)
        .unwrap_or_else(|| "No submissions yet".to_string());
    let top_issue_markup = if snapshot.top_issues.is_empty() {
        "<p class=\"fine-print\">No promoted issues yet. Once at least two opted-in hosts corroborate the same failure, it moves into the shared worker queue.</p>".to_string()
    } else {
        snapshot
            .top_issues
            .iter()
            .map(render_issue_card)
            .collect::<Vec<_>>()
            .join("")
    };

    let body = format!(
        r#"
        <section class="hero">
            <p class="tag">Opt-in federation for Linux failures</p>
            <h1>Fixer turns corroborated breakage into patchable work.</h1>
            <p class="lede">Hosts with no Codex can still upload findings. Willing participants with Codex can pull promoted issues, attempt a patch, or explain why a patch is not honest yet. When Fixer produces a patch, it nudges the user to review it and send it upstream.</p>
            <div class="hero-actions">
                <a class="button primary" href="/issues">Browse promoted issues</a>
                <a class="button" href="{github_url}">GitHub</a>
                <a class="button" href="{apt_repo_url}">APT repository</a>
            </div>
        </section>

        <section class="grid stats section">
            <article class="panel stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Opted-in installs seen</div>
            </article>
            <article class="panel stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Submission bundles processed</div>
            </article>
            <article class="panel stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Promoted issue clusters</div>
            </article>
            <article class="panel stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Ready patch attempts</div>
            </article>
        </section>

        <section class="grid columns section">
            <article class="panel">
                <h2>Privacy and consent</h2>
                <p>{}</p>
                <p class="fine-print">Network participation is disabled until the user explicitly opts in. Public pages and public issue JSON only expose aggregate sanitized metadata, never hostnames, install IDs, raw command lines, or evidence bundles.</p>
            </article>
            <article class="panel">
                <h2>How the network works</h2>
                <p>1. Hosts collect findings locally and opt in before uploading.</p>
                <p>2. The server quarantines new issue clusters and promotes only corroborated or trusted submissions.</p>
                <p>3. Volunteer workers with Codex pull promoted work, produce a patch or a reason it is not patchable yet, and affected users are encouraged to submit the result upstream.</p>
                <p class="fine-print">Last submission processed: {last_submission}</p>
            </article>
        </section>

        <section class="panel section">
            <h2>Install from APT</h2>
            <p>Add the public Fixer repository and install the package with normal APT tooling.</p>
            <pre class="code-block"><code>{}</code></pre>
            <p class="fine-print">The repository lives at <a href="{apt_repo_url}">{apt_repo_url}</a>. The public signing key is published at <a href="{repo_key_url}">{repo_key_url}</a>.</p>
        </section>

        <section class="panel section">
            <h2>Promoted issues right now</h2>
            <div class="issue-list">{top_issue_markup}</div>
        </section>
        "#,
        snapshot.install_count,
        snapshot.submission_count,
        snapshot.promoted_issue_count,
        snapshot.ready_patch_count,
        html_escape(PRIVACY_WARNING),
        html_escape(&apt_snippet),
    );

    render_page(
        "Fixer",
        "Public Fixer issue federation, APT repository, and worker queue",
        NavPage::Home,
        body,
        snapshot.quarantined_issue_count,
    )
}

fn render_issues_page(issues: &[PublicIssue]) -> String {
    let issue_markup = if issues.is_empty() {
        "<p class=\"fine-print\">There are no promoted issues yet.</p>".to_string()
    } else {
        issues
            .iter()
            .map(render_issue_card)
            .collect::<Vec<_>>()
            .join("")
    };
    let body = format!(
        r#"
        <section class="hero">
            <p class="tag">Public aggregate view</p>
            <h1>Promoted Fixer issues</h1>
            <p class="lede">Only sanitized aggregate data is shown here. Raw evidence, hostnames, install identities, and richer artifacts stay out of the public surface.</p>
        </section>

        <section class="panel section">
            <h2>Current queue</h2>
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
    )
}

fn render_issue_detail_page(issue: &PublicIssueDetail) -> String {
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
        ),
        html_escape(&format_timestamp(&issue.last_seen)),
        issue.id,
        issue.id,
        attempts_markup,
    );
    render_page(
        &format!("Fixer Issue {}", issue.id),
        &issue.title,
        NavPage::Issues,
        body,
        0,
    )
}

fn render_page(
    title: &str,
    description: &str,
    nav_page: NavPage,
    body: String,
    quarantined_count: i64,
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
    <link rel="stylesheet" href="/assets/app.css">
</head>
<body>
    <div class="shell">
        <nav class="nav">
            <a class="brand" href="/">Fixer</a>
            <div class="nav-links">
                <a class="{}" href="/">Overview</a>
                <a class="{}" href="/issues">Issues</a>
                <a href="/healthz">Health</a>
                <a href="https://github.com/maumaps/fixer">GitHub</a>
                <a href="/apt/">APT</a>
            </div>
        </nav>
        {}
        <p class="footer">{}</p>
    </div>
</body>
</html>"#,
        html_escape(title),
        html_escape(description),
        home_class,
        issues_class,
        body,
        html_escape(&footer_note)
    )
}

fn render_issue_card(issue: &PublicIssue) -> String {
    let mut extra = String::new();
    let _ = write!(
        extra,
        "<p class=\"fine-print\">Last seen: {}. Public page: <a href=\"/issues/{}\">/issues/{}</a>. Public JSON: <a href=\"/v1/issues/{}\">/v1/issues/{}</a></p>",
        html_escape(&format_timestamp(&issue.last_seen)),
        issue.id,
        issue.id,
        issue.id,
        issue.id
    );

    format!(
        r#"<article class="issue-card">
            <div class="issue-topline">
                <h3><a href="/issues/{}">{}</a></h3>
                <span class="tag">{}</span>
            </div>
            <p class="issue-summary">{}</p>
            <div class="meta">{}</div>
            {}
        </article>"#,
        issue.id,
        html_escape(&issue.title),
        html_escape(&issue.kind),
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
        ),
        extra
    )
}

fn render_public_attempt_card(attempt: &PublicAttempt) -> String {
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

    format!(
        r#"<article class="issue-card">
            <div class="issue-topline">
                <h3>{}</h3>
                <span class="tag">{}</span>
            </div>
            <p class="issue-summary">{}</p>
            <div class="meta"><span class="tag">state: {}</span><span class="tag">created: {}</span>{}</div>
            {}
        </article>"#,
        html_escape(&format!("{} attempt", attempt.outcome)),
        html_escape(&attempt.outcome),
        html_escape(&attempt.summary),
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
        sections.join("")
    )
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
    use crate::models::{FindingRecord, OpportunityRecord};

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

    #[test]
    fn html_escape_handles_reserved_characters() {
        assert_eq!(
            html_escape(r#"<tag attr="value">&"</tag>"#),
            "&lt;tag attr=&quot;value&quot;&gt;&amp;&quot;&lt;/tag&gt;"
        );
    }

    #[test]
    fn render_issue_card_marks_patch_ready() {
        let issue = PublicIssue {
            id: "0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8".to_string(),
            kind: "warning".to_string(),
            title: "AppArmor denied cupsd".to_string(),
            summary: "cupsd cannot read /etc/paperspecs".to_string(),
            package_name: Some("cups-daemon".to_string()),
            source_package: Some("cups".to_string()),
            ecosystem: Some("debian".to_string()),
            severity: Some("high".to_string()),
            score: 93,
            corroboration_count: 3,
            best_patch_available: true,
            last_seen: "2026-03-29T00:00:00Z".to_string(),
        };

        let markup = render_issue_card(&issue);
        assert!(markup.contains("patch attempt ready"));
        assert!(markup.contains("/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8"));
        assert!(markup.contains("/v1/issues/0195e5cc-c1ef-7c4e-a4f9-3bb0b44df5f8"));
        assert!(!markup.contains("representative_json"));
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
                    "diff": "--- ./source/src/file.c\n+++ ./workspace/src/file.c\n",
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
        };

        let error = reject_incompatible_client(&request).unwrap_err();
        assert_eq!(error.status, StatusCode::UPGRADE_REQUIRED);
        assert!(error.message.contains("Upgrade fixer"));
    }
}
