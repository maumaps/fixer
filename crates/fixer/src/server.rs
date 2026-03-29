use crate::config::FixerConfig;
use crate::models::{
    ClientHello, IssueCluster, PatchAttempt, ServerHello, SharedOpportunity, SubmissionEnvelope,
    SubmissionReceipt, WorkLease, WorkOffer, WorkPullRequest, WorkerResultEnvelope,
};
use crate::network::verify_worker_pull_pow;
use crate::pow::verify_pow;
use crate::privacy::PRIVACY_WARNING;
use crate::util::{hash_text, now_rfc3339};
use anyhow::{Context, Result};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path as AxumPath, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
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
    db: Arc<Client>,
}

#[derive(Debug, Clone, Serialize)]
struct PublicIssue {
    id: i64,
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

pub async fn serve(config: FixerConfig) -> Result<()> {
    let (client, connection) = tokio_postgres::connect(&config.server.postgres_url, NoTls)
        .await
        .with_context(|| format!("failed to connect to {}", config.server.postgres_url))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::error!(?error, "postgres connection failed");
        }
    });
    init_db(&client).await?;
    let state = Arc::new(ServerState {
        config: config.clone(),
        db: Arc::new(client),
    });

    let app = Router::new()
        .route("/", get(landing_page))
        .route("/issues", get(public_issues_page))
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
    let snapshot = load_dashboard_snapshot(state.db.as_ref()).await?;
    Ok(Html(render_landing_page(&state.config, &snapshot)))
}

async fn public_issues_page(
    State(state): State<Arc<ServerState>>,
) -> Result<Html<String>, ApiError> {
    let issues = load_public_issues(state.db.as_ref(), 100).await?;
    Ok(Html(render_issues_page(&issues)))
}

async fn healthz(State(state): State<Arc<ServerState>>) -> Result<Json<Healthz>, ApiError> {
    let _: i32 = state
        .db
        .query_one("SELECT 1", &[])
        .await
        .map_err(ApiError::internal)?
        .get(0);
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
    ensure_install(state.db.as_ref(), &request, remote_ip, &config)
        .await
        .map_err(ApiError::internal)?;
    let (submission_trust, worker_trust, banned_until) =
        install_trust(state.db.as_ref(), &install_id)
            .await
            .map_err(ApiError::internal)?;
    if banned_until.map(|ts| ts > Utc::now()).unwrap_or(false) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "install is temporarily banned due to repeated abusive requests",
        ));
    }
    let worker_allowed = request.mode.can_work()
        && request.has_codex
        && (worker_trust >= state.config.server.worker_trust_minimum
            || submission_trust >= state.config.server.worker_trust_minimum);
    Ok(Json(ServerHello {
        policy_version: state.config.privacy.policy_version.clone(),
        submission_pow_difficulty: state.config.server.submission_pow_difficulty,
        worker_pow_difficulty: state.config.server.worker_pow_difficulty,
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
        record_abuse(
            state.db.as_ref(),
            &install_id,
            "invalid-submission-pow",
            &config,
        )
        .await
        .map_err(ApiError::internal)?;
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "invalid or stale proof-of-work",
        ));
    }

    ensure_install(
        state.db.as_ref(),
        &envelope.client,
        remote_ip.clone(),
        &config,
    )
    .await
    .map_err(ApiError::internal)?;

    let rate_limited_submission = rate_limited(
        state.db.as_ref(),
        "submission",
        &install_id,
        &remote_ip,
        state.config.server.max_submissions_per_hour,
    )
    .await
    .map_err(ApiError::internal)?;
    if rate_limited_submission {
        record_abuse(
            state.db.as_ref(),
            &install_id,
            "submission-rate-limit",
            &config,
        )
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
    if let Some(existing_id) = state
        .db
        .query_opt(
            "SELECT id FROM submissions WHERE content_hash = $1",
            &[&content_hash],
        )
        .await
        .map_err(ApiError::internal)?
        .map(|row| row.get::<_, i64>(0))
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
    let submission_id: i64 = state
        .db
        .query_one(
            "
            INSERT INTO submissions (install_id, content_hash, payload_hash, received_at, remote_addr, quarantined, bundle_json)
            VALUES ($1, $2, $3, $4, $5, TRUE, $6)
            RETURNING id
            ",
            &[
                &install_id,
                &content_hash,
                &payload_hash,
                &received_at,
                &remote_ip,
                &bundle_json,
            ],
        )
        .await
        .map_err(ApiError::internal)?
        .get(0);

    state
        .db
        .execute(
            "
            UPDATE installs
            SET submission_count = submission_count + 1,
                last_seen = $2
            WHERE install_id = $1
            ",
            &[&install_id, &received_at],
        )
        .await
        .map_err(ApiError::internal)?;
    note_rate_event(state.db.as_ref(), "submission", &install_id, &remote_ip)
        .await
        .map_err(ApiError::internal)?;

    let submission_trust = install_trust(state.db.as_ref(), &install_id)
        .await
        .map_err(ApiError::internal)?
        .0;
    let mut issue_ids = Vec::new();
    let mut promoted_clusters = 0_usize;
    for item in &envelope.bundle.items {
        let cluster_key = cluster_key_for(item);
        let issue_id = upsert_issue_cluster(
            state.db.as_ref(),
            item,
            &cluster_key,
            submission_id,
            &install_id,
            submission_trust,
            &state.config,
        )
        .await
        .map_err(ApiError::internal)?;
        let promoted: bool = state
            .db
            .query_one(
                "SELECT promoted FROM issue_clusters WHERE id = $1",
                &[&issue_id],
            )
            .await
            .map_err(ApiError::internal)?
            .get(0);
        if promoted {
            promoted_clusters += 1;
        }
        issue_ids.push(issue_id);
    }
    if promoted_clusters > 0 {
        state
            .db
            .execute(
                "
                UPDATE installs
                SET submission_trust_score = submission_trust_score + 1
                WHERE install_id = $1
                ",
                &[&install_id],
            )
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
        record_abuse(
            state.db.as_ref(),
            &install_id,
            "invalid-worker-pow",
            &config,
        )
        .await
        .map_err(ApiError::internal)?;
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "invalid or stale worker proof-of-work",
        ));
    }

    ensure_install(
        state.db.as_ref(),
        &request.client,
        remote_ip.clone(),
        &config,
    )
    .await
    .map_err(ApiError::internal)?;

    let rate_limited_pull = rate_limited(
        state.db.as_ref(),
        "work-pull",
        &install_id,
        &remote_ip,
        state.config.server.max_work_pulls_per_hour,
    )
    .await
    .map_err(ApiError::internal)?;
    if rate_limited_pull {
        record_abuse(state.db.as_ref(), &install_id, "worker-rate-limit", &config)
            .await
            .map_err(ApiError::internal)?;
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "worker pull rate limit exceeded",
        ));
    }

    note_rate_event(state.db.as_ref(), "work-pull", &install_id, &remote_ip)
        .await
        .map_err(ApiError::internal)?;
    let (submission_trust, worker_trust, banned_until) =
        install_trust(state.db.as_ref(), &install_id)
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

    let Some(issue) = next_issue_for_worker(state.db.as_ref())
        .await
        .map_err(ApiError::internal)?
    else {
        return Ok(Json(WorkOffer {
            message: "no promoted work is currently available".to_string(),
            lease: None,
        }));
    };
    let lease_id = Uuid::new_v4().to_string();
    let leased_at = Utc::now();
    let expires_at = leased_at + Duration::seconds(state.config.server.lease_seconds as i64);
    let lease = WorkLease {
        lease_id: lease_id.clone(),
        issued_at: leased_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        issue: issue.clone(),
    };
    state
        .db
        .execute(
            "
            INSERT INTO worker_leases (id, cluster_id, install_id, state, leased_at, expires_at, work_json)
            VALUES ($1, $2, $3, 'leased', $4, $5, $6)
            ",
            &[
                &lease_id,
                &issue.id,
                &install_id,
                &leased_at,
                &expires_at,
                &serde_json::to_value(&lease).map_err(ApiError::internal)?,
            ],
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
    let lease_row = state
        .db
        .query_opt(
            "
            SELECT cluster_id, install_id, expires_at
            FROM worker_leases
            WHERE id = $1 AND state = 'leased'
            ",
            &[&lease_id],
        )
        .await
        .map_err(ApiError::internal)?;
    let Some(lease_row) = lease_row else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "lease was not found or is no longer active",
        ));
    };
    let cluster_id: i64 = lease_row.get(0);
    let install_id: String = lease_row.get(1);
    let expires_at: DateTime<Utc> = lease_row.get(2);
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

    state
        .db
        .execute(
            "
            INSERT INTO patch_attempts (cluster_id, lease_id, install_id, outcome, state, summary, bundle_json, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ",
            &[
                &cluster_id,
                &lease_id,
                &result.attempt.install_id,
                &result.attempt.outcome,
                &result.attempt.state,
                &result.attempt.summary,
                &serde_json::to_value(&result).map_err(ApiError::internal)?,
                &Utc::now(),
            ],
        )
        .await
        .map_err(ApiError::internal)?;
    state
        .db
        .execute(
            "
            UPDATE worker_leases
            SET state = 'completed'
            WHERE id = $1
            ",
            &[&lease_id],
        )
        .await
        .map_err(ApiError::internal)?;
    if result.attempt.outcome == "patch" && result.attempt.state == "ready" {
        state
            .db
            .execute(
                "
                UPDATE issue_clusters
                SET best_patch_json = $2
                WHERE id = $1
                ",
                &[
                    &cluster_id,
                    &serde_json::to_value(&result.attempt).map_err(ApiError::internal)?,
                ],
            )
            .await
            .map_err(ApiError::internal)?;
        state
            .db
            .execute(
                "
                UPDATE installs
                SET worker_trust_score = worker_trust_score + 1,
                    worker_result_count = worker_result_count + 1
                WHERE install_id = $1
                ",
                &[&result.attempt.install_id],
            )
            .await
            .map_err(ApiError::internal)?;
    }
    if let Some(request) = &result.evidence_request {
        state
            .db
            .execute(
                "
                INSERT INTO evidence_requests (issue_id, requested_by_install_id, reason, requested_fields_json, requested_at)
                VALUES ($1, $2, $3, $4, $5)
                ",
                &[
                    &request.issue_id,
                    &request.requested_by_install_id,
                    &request.reason,
                    &serde_json::to_value(&request.requested_fields).map_err(ApiError::internal)?,
                    &parse_timestamp(&request.requested_at).unwrap_or_else(Utc::now),
                ],
            )
            .await
            .map_err(ApiError::internal)?;
    }
    Ok(Json(result_clone))
}

async fn list_issues(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<Vec<PublicIssue>>, ApiError> {
    let issues = load_public_issues(state.db.as_ref(), 100).await?;
    Ok(Json(issues))
}

async fn get_issue(
    State(state): State<Arc<ServerState>>,
    AxumPath(id): AxumPath<i64>,
) -> Result<Json<PublicIssue>, ApiError> {
    let issue = load_public_issue(state.db.as_ref(), id).await?;
    Ok(Json(issue))
}

async fn respond_evidence_request(
    State(state): State<Arc<ServerState>>,
    AxumPath(id): AxumPath<i64>,
    Json(response): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let updated = state
        .db
        .execute(
            "
            UPDATE evidence_requests
            SET response_json = $2
            WHERE id = $1
            ",
            &[&id, &response],
        )
        .await
        .map_err(ApiError::internal)?;
    if updated == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "evidence request not found",
        ));
    }
    Ok(Json(json!({"id": id, "stored": true})))
}

async fn init_db(client: &Client) -> Result<()> {
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
            id BIGSERIAL PRIMARY KEY,
            install_id TEXT NOT NULL REFERENCES installs(install_id),
            content_hash TEXT NOT NULL UNIQUE,
            payload_hash TEXT NOT NULL,
            received_at TIMESTAMPTZ NOT NULL,
            remote_addr TEXT,
            quarantined BOOLEAN NOT NULL DEFAULT TRUE,
            bundle_json JSONB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS issue_clusters (
            id BIGSERIAL PRIMARY KEY,
            cluster_key TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
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
            cluster_id BIGINT NOT NULL REFERENCES issue_clusters(id) ON DELETE CASCADE,
            install_id TEXT NOT NULL REFERENCES installs(install_id),
            submission_id BIGINT NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (cluster_id, install_id)
        );

        CREATE TABLE IF NOT EXISTS worker_leases (
            id TEXT PRIMARY KEY,
            cluster_id BIGINT NOT NULL REFERENCES issue_clusters(id) ON DELETE CASCADE,
            install_id TEXT NOT NULL REFERENCES installs(install_id),
            state TEXT NOT NULL,
            leased_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            work_json JSONB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS patch_attempts (
            id BIGSERIAL PRIMARY KEY,
            cluster_id BIGINT NOT NULL REFERENCES issue_clusters(id) ON DELETE CASCADE,
            lease_id TEXT REFERENCES worker_leases(id),
            install_id TEXT NOT NULL REFERENCES installs(install_id),
            outcome TEXT NOT NULL,
            state TEXT NOT NULL,
            summary TEXT NOT NULL,
            bundle_json JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL
        );

        CREATE TABLE IF NOT EXISTS evidence_requests (
            id BIGSERIAL PRIMARY KEY,
            issue_id BIGINT NOT NULL REFERENCES issue_clusters(id) ON DELETE CASCADE,
            requested_by_install_id TEXT,
            reason TEXT NOT NULL,
            requested_fields_json JSONB NOT NULL,
            requested_at TIMESTAMPTZ NOT NULL,
            response_json JSONB
        );

        CREATE TABLE IF NOT EXISTS rate_events (
            id BIGSERIAL PRIMARY KEY,
            scope_kind TEXT NOT NULL,
            scope_value TEXT NOT NULL,
            event_kind TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL
        );
        ",
        )
        .await?;
    Ok(())
}

async fn ensure_install(
    db: &Client,
    request: &ClientHello,
    remote_addr: String,
    _config: &FixerConfig,
) -> Result<()> {
    let now = Utc::now();
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
    Ok(())
}

async fn install_trust(db: &Client, install_id: &str) -> Result<(i64, i64, Option<DateTime<Utc>>)> {
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

async fn rate_limited(
    db: &Client,
    event_kind: &str,
    install_id: &str,
    remote_addr: &str,
    limit: i64,
) -> Result<bool> {
    let window_start = Utc::now() - Duration::hours(1);
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

async fn note_rate_event(
    db: &Client,
    event_kind: &str,
    install_id: &str,
    remote_addr: &str,
) -> Result<()> {
    let now = Utc::now();
    for (scope_kind, scope_value) in [("install", install_id), ("ip", remote_addr)] {
        db.execute(
            "
            INSERT INTO rate_events (scope_kind, scope_value, event_kind, created_at)
            VALUES ($1, $2, $3, $4)
            ",
            &[&scope_kind, &scope_value, &event_kind, &now],
        )
        .await?;
    }
    Ok(())
}

async fn record_abuse(
    db: &Client,
    install_id: &str,
    reason: &str,
    config: &FixerConfig,
) -> Result<()> {
    let now = Utc::now();
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
    tracing::warn!(install_id, reason, "recorded abusive request");
    Ok(())
}

async fn upsert_issue_cluster(
    db: &Client,
    item: &SharedOpportunity,
    cluster_key: &str,
    submission_id: i64,
    install_id: &str,
    submission_trust: i64,
    config: &FixerConfig,
) -> Result<i64> {
    let now = Utc::now();
    let representative_json = serde_json::to_value(item)?;
    let package_name = item.finding.package_name.clone();
    let source_package = item
        .opportunity
        .evidence
        .get("source_package")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let existing_id = db
        .query_opt(
            "SELECT id FROM issue_clusters WHERE cluster_key = $1",
            &[&cluster_key],
        )
        .await?
        .map(|row| row.get::<_, i64>(0));
    let issue_id = if let Some(existing_id) = existing_id {
        db.execute(
            "
            UPDATE issue_clusters
            SET title = $2,
                summary = $3,
                package_name = COALESCE($4, package_name),
                source_package = COALESCE($5, source_package),
                ecosystem = COALESCE($6, ecosystem),
                severity = COALESCE($7, severity),
                score = GREATEST(score, $8),
                representative_json = CASE
                    WHEN $8 >= score THEN $9
                    ELSE representative_json
                END,
                last_seen = $10
            WHERE id = $1
            ",
            &[
                &existing_id,
                &item.opportunity.title,
                &item.opportunity.summary,
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
        db.query_one(
            "
            INSERT INTO issue_clusters
                (cluster_key, kind, title, summary, package_name, source_package, ecosystem, severity,
                 score, corroboration_count, quarantined, promoted, representative_json, last_seen)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, TRUE, FALSE, $10, $11)
            RETURNING id
            ",
            &[
                &cluster_key,
                &item.opportunity.kind,
                &item.opportunity.title,
                &item.opportunity.summary,
                &package_name,
                &source_package,
                &item.opportunity.ecosystem,
                &Some(item.finding.severity.clone()),
                &item.opportunity.score,
                &representative_json,
                &now,
            ],
        )
        .await?
        .get(0)
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

async fn next_issue_for_worker(db: &Client) -> Result<Option<IssueCluster>> {
    let row = db
        .query_opt(
            "
        SELECT id, cluster_key, kind, title, summary, package_name, source_package, ecosystem,
               severity, score, corroboration_count, quarantined, promoted, representative_json,
               best_patch_json, last_seen
        FROM issue_clusters issue
        WHERE promoted = TRUE
          AND NOT EXISTS (
                SELECT 1
                FROM worker_leases lease
                WHERE lease.cluster_id = issue.id
                  AND lease.state = 'leased'
                  AND lease.expires_at > NOW()
          )
        ORDER BY (best_patch_json IS NOT NULL) ASC, score DESC, last_seen DESC
        LIMIT 1
        ",
            &[],
        )
        .await?;
    row.map(issue_from_row).transpose()
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

async fn load_dashboard_snapshot(db: &Client) -> Result<DashboardSnapshot, ApiError> {
    let row = db
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

async fn load_public_issues(db: &Client, limit: i64) -> Result<Vec<PublicIssue>, ApiError> {
    let rows = db
        .query(
            "
            SELECT id, kind, title, summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count, (best_patch_json IS NOT NULL) AS best_patch_available,
                   last_seen
            FROM issue_clusters
            WHERE promoted = TRUE
            ORDER BY score DESC, last_seen DESC
            LIMIT $1
            ",
            &[&limit],
        )
        .await
        .map_err(ApiError::internal)?;
    rows.into_iter().map(public_issue_from_row).collect()
}

async fn load_public_issue(db: &Client, id: i64) -> Result<PublicIssue, ApiError> {
    let row = db
        .query_opt(
            "
            SELECT id, kind, title, summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count, (best_patch_json IS NOT NULL) AS best_patch_available,
                   last_seen
            FROM issue_clusters
            WHERE id = $1 AND promoted = TRUE
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

fn cluster_key_for(item: &SharedOpportunity) -> String {
    let stack_signature = item
        .finding
        .details
        .get("primary_stack")
        .and_then(Value::as_array)
        .map(|frames| {
            frames
                .iter()
                .take(6)
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("|")
        })
        .filter(|value| !value.is_empty())
        .or_else(|| {
            item.finding
                .details
                .get("kernel_module")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| item.finding.title.clone());
    hash_text(format!(
        "{}|{}|{}|{}|{}",
        item.finding.kind,
        item.finding.fingerprint,
        item.finding.package_name.as_deref().unwrap_or("-"),
        item.opportunity.ecosystem.as_deref().unwrap_or("-"),
        stack_signature
    ))
}

fn parse_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|value| value.with_timezone(&Utc))
        .ok()
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
    let mut tags = Vec::new();
    if let Some(severity) = issue.severity.as_deref() {
        tags.push(format!(
            "<span class=\"tag severity-{}\">{}</span>",
            html_escape(&severity_class(severity)),
            html_escape(severity)
        ));
    }
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
    if let Some(ecosystem) = issue.ecosystem.as_deref() {
        tags.push(format!(
            "<span class=\"tag\">ecosystem: {}</span>",
            html_escape(ecosystem)
        ));
    }
    tags.push(format!("<span class=\"tag\">score: {}</span>", issue.score));
    tags.push(format!(
        "<span class=\"tag\">reports: {}</span>",
        issue.corroboration_count
    ));
    if issue.best_patch_available {
        tags.push("<span class=\"tag patch\">patch attempt ready</span>".to_string());
    }

    let mut extra = String::new();
    let _ = write!(
        extra,
        "<p class=\"fine-print\">Last seen: {}. Public JSON: <a href=\"/v1/issues/{}\">/v1/issues/{}</a></p>",
        html_escape(&format_timestamp(&issue.last_seen)),
        issue.id,
        issue.id
    );

    format!(
        r#"<article class="issue-card">
            <div class="issue-topline">
                <h3>{}</h3>
                <span class="tag">{}</span>
            </div>
            <p class="issue-summary">{}</p>
            <div class="meta">{}</div>
            {}
        </article>"#,
        html_escape(&issue.title),
        html_escape(&issue.kind),
        html_escape(&issue.summary),
        tags.join(""),
        extra
    )
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
            id: 7,
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
        assert!(markup.contains("/v1/issues/7"));
        assert!(!markup.contains("representative_json"));
    }
}
