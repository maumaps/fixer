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
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use postgres::{Client, NoTls, Row};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone)]
struct ServerState {
    config: FixerConfig,
    db: Arc<Mutex<Client>>,
}

pub async fn serve(config: FixerConfig) -> Result<()> {
    let mut client = Client::connect(&config.server.postgres_url, NoTls)
        .with_context(|| format!("failed to connect to {}", config.server.postgres_url))?;
    init_db(&mut client)?;
    let state = Arc::new(ServerState {
        config: config.clone(),
        db: Arc::new(Mutex::new(client)),
    });
    let app = Router::new()
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

async fn install_hello(
    State(state): State<Arc<ServerState>>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Json(request): Json<ClientHello>,
) -> Result<Json<ServerHello>, ApiError> {
    let mut db = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    ensure_install(
        &mut db,
        &request,
        remote_addr.ip().to_string(),
        &state.config,
    )
    .map_err(ApiError::internal)?;
    let (submission_trust, worker_trust, banned_until) =
        install_trust(&mut db, &request.install_id).map_err(ApiError::internal)?;
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
    if !verify_pow(
        &envelope.client.install_id,
        &envelope.proof_of_work,
        &envelope.content_hash,
        state.config.server.submission_pow_difficulty,
        30,
    ) {
        let mut db = state
            .db
            .lock()
            .map_err(|_| ApiError::internal("database lock poisoned"))?;
        record_abuse(
            &mut db,
            &envelope.client.install_id,
            "invalid-submission-pow",
            &state.config,
        )
        .map_err(ApiError::internal)?;
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "invalid or stale proof-of-work",
        ));
    }

    let mut db = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    ensure_install(
        &mut db,
        &envelope.client,
        remote_addr.ip().to_string(),
        &state.config,
    )
    .map_err(ApiError::internal)?;
    if rate_limited(
        &mut db,
        "submission",
        &envelope.client.install_id,
        &remote_addr.ip().to_string(),
        state.config.server.max_submissions_per_hour,
    )
    .map_err(ApiError::internal)?
    {
        record_abuse(
            &mut db,
            &envelope.client.install_id,
            "submission-rate-limit",
            &state.config,
        )
        .map_err(ApiError::internal)?;
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "submission rate limit exceeded",
        ));
    }

    if let Some(existing_id) = db
        .query_opt(
            "SELECT id FROM submissions WHERE content_hash = $1",
            &[&envelope.content_hash],
        )
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
    let submission_id: i64 = db
        .query_one(
            "
            INSERT INTO submissions (install_id, content_hash, payload_hash, received_at, remote_addr, quarantined, bundle_json)
            VALUES ($1, $2, $3, $4, $5, TRUE, $6)
            RETURNING id
            ",
            &[
                &envelope.client.install_id,
                &envelope.content_hash,
                &envelope.proof_of_work.payload_hash,
                &received_at,
                &remote_addr.ip().to_string(),
                &serde_json::to_value(&envelope.bundle).map_err(ApiError::internal)?,
            ],
        )
        .map_err(ApiError::internal)?
        .get(0);

    db.execute(
        "
        UPDATE installs
        SET submission_count = submission_count + 1,
            last_seen = $2
        WHERE install_id = $1
        ",
        &[&envelope.client.install_id, &received_at],
    )
    .map_err(ApiError::internal)?;
    note_rate_event(
        &mut db,
        "submission",
        &envelope.client.install_id,
        &remote_addr.ip().to_string(),
    )
    .map_err(ApiError::internal)?;

    let mut issue_ids = Vec::new();
    let mut promoted_clusters = 0_usize;
    let submission_trust = install_trust(&mut db, &envelope.client.install_id)
        .map_err(ApiError::internal)?
        .0;
    for item in &envelope.bundle.items {
        let cluster_key = cluster_key_for(item);
        let issue_id = upsert_issue_cluster(
            &mut db,
            item,
            &cluster_key,
            submission_id,
            &envelope.client.install_id,
            submission_trust,
            &state.config,
        )
        .map_err(ApiError::internal)?;
        let promoted: bool = db
            .query_one(
                "SELECT promoted FROM issue_clusters WHERE id = $1",
                &[&issue_id],
            )
            .map_err(ApiError::internal)?
            .get(0);
        if promoted {
            promoted_clusters += 1;
        }
        issue_ids.push(issue_id);
    }
    if promoted_clusters > 0 {
        db.execute(
            "
            UPDATE installs
            SET submission_trust_score = submission_trust_score + 1
            WHERE install_id = $1
            ",
            &[&envelope.client.install_id],
        )
        .map_err(ApiError::internal)?;
    }
    Ok(Json(SubmissionReceipt {
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
    }))
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
    if !verify_worker_pull_pow(
        &request.client.install_id,
        &request,
        state.config.server.worker_pow_difficulty,
    ) {
        let mut db = state
            .db
            .lock()
            .map_err(|_| ApiError::internal("database lock poisoned"))?;
        record_abuse(
            &mut db,
            &request.client.install_id,
            "invalid-worker-pow",
            &state.config,
        )
        .map_err(ApiError::internal)?;
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "invalid or stale worker proof-of-work",
        ));
    }

    let mut db = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    ensure_install(
        &mut db,
        &request.client,
        remote_addr.ip().to_string(),
        &state.config,
    )
    .map_err(ApiError::internal)?;
    if rate_limited(
        &mut db,
        "work-pull",
        &request.client.install_id,
        &remote_addr.ip().to_string(),
        state.config.server.max_work_pulls_per_hour,
    )
    .map_err(ApiError::internal)?
    {
        record_abuse(
            &mut db,
            &request.client.install_id,
            "worker-rate-limit",
            &state.config,
        )
        .map_err(ApiError::internal)?;
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "worker pull rate limit exceeded",
        ));
    }
    note_rate_event(
        &mut db,
        "work-pull",
        &request.client.install_id,
        &remote_addr.ip().to_string(),
    )
    .map_err(ApiError::internal)?;

    let (submission_trust, worker_trust, banned_until) =
        install_trust(&mut db, &request.client.install_id).map_err(ApiError::internal)?;
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

    let Some(issue) = next_issue_for_worker(&mut db).map_err(ApiError::internal)? else {
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
    db.execute(
        "
        INSERT INTO worker_leases (id, cluster_id, install_id, state, leased_at, expires_at, work_json)
        VALUES ($1, $2, $3, 'leased', $4, $5, $6)
        ",
        &[
            &lease_id,
            &issue.id,
            &request.client.install_id,
            &leased_at,
            &expires_at,
            &serde_json::to_value(&lease).map_err(ApiError::internal)?,
        ],
    )
    .map_err(ApiError::internal)?;
    Ok(Json(WorkOffer {
        message: "lease granted".to_string(),
        lease: Some(lease),
    }))
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
    let mut db = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let lease_row = db
        .query_opt(
            "
            SELECT cluster_id, install_id, expires_at
            FROM worker_leases
            WHERE id = $1 AND state = 'leased'
            ",
            &[&lease_id],
        )
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

    db.execute(
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
    .map_err(ApiError::internal)?;
    db.execute(
        "
        UPDATE worker_leases
        SET state = 'completed'
        WHERE id = $1
        ",
        &[&lease_id],
    )
    .map_err(ApiError::internal)?;
    if result.attempt.outcome == "patch" && result.attempt.state == "ready" {
        db.execute(
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
        .map_err(ApiError::internal)?;
        db.execute(
            "
            UPDATE installs
            SET worker_trust_score = worker_trust_score + 1,
                worker_result_count = worker_result_count + 1
            WHERE install_id = $1
            ",
            &[&result.attempt.install_id],
        )
        .map_err(ApiError::internal)?;
    }
    if let Some(request) = &result.evidence_request {
        db.execute(
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
        .map_err(ApiError::internal)?;
    }
    Ok(Json(result))
}

async fn list_issues(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<Vec<IssueCluster>>, ApiError> {
    let mut db = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let rows = db
        .query(
            "
            SELECT id, cluster_key, kind, title, summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count, quarantined, promoted, representative_json,
                   best_patch_json, last_seen
            FROM issue_clusters
            WHERE promoted = TRUE
            ORDER BY score DESC, last_seen DESC
            LIMIT 100
            ",
            &[],
        )
        .map_err(ApiError::internal)?;
    rows.into_iter()
        .map(issue_from_row)
        .collect::<Result<Vec<_>>>()
        .map(Json)
        .map_err(ApiError::internal)
}

async fn get_issue(
    State(state): State<Arc<ServerState>>,
    AxumPath(id): AxumPath<i64>,
) -> Result<Json<IssueCluster>, ApiError> {
    let mut db = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let row = db
        .query_opt(
            "
            SELECT id, cluster_key, kind, title, summary, package_name, source_package, ecosystem,
                   severity, score, corroboration_count, quarantined, promoted, representative_json,
                   best_patch_json, last_seen
            FROM issue_clusters
            WHERE id = $1
            ",
            &[&id],
        )
        .map_err(ApiError::internal)?;
    let Some(row) = row else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "issue not found"));
    };
    issue_from_row(row).map(Json).map_err(ApiError::internal)
}

async fn respond_evidence_request(
    State(state): State<Arc<ServerState>>,
    AxumPath(id): AxumPath<i64>,
    Json(response): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let mut db = state
        .db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let updated = db
        .execute(
            "
            UPDATE evidence_requests
            SET response_json = $2
            WHERE id = $1
            ",
            &[&id, &response],
        )
        .map_err(ApiError::internal)?;
    if updated == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "evidence request not found",
        ));
    }
    Ok(Json(json!({"id": id, "stored": true})))
}

fn init_db(client: &mut Client) -> Result<()> {
    client.batch_execute(
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
    )?;
    Ok(())
}

fn ensure_install(
    db: &mut Client,
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
            &serde_json::to_value(&request.mode)?,
            &request.hostname,
            &request.version,
            &request.has_codex,
            &serde_json::to_value(&request.capabilities)?,
            &remote_addr,
        ],
    )?;
    Ok(())
}

fn install_trust(db: &mut Client, install_id: &str) -> Result<(i64, i64, Option<DateTime<Utc>>)> {
    let row = db.query_one(
        "
        SELECT submission_trust_score, worker_trust_score, banned_until
        FROM installs
        WHERE install_id = $1
        ",
        &[&install_id],
    )?;
    Ok((row.get(0), row.get(1), row.get(2)))
}

fn rate_limited(
    db: &mut Client,
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
        )?
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
        )?
        .get(0);
    Ok(ip_count >= limit)
}

fn note_rate_event(
    db: &mut Client,
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
        )?;
    }
    Ok(())
}

fn record_abuse(
    db: &mut Client,
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
    )?;
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
    )?;
    tracing::warn!(install_id, reason, "recorded abusive request");
    Ok(())
}

fn upsert_issue_cluster(
    db: &mut Client,
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
        )?
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
        )?;
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
        )?
        .get(0)
    };
    db.execute(
        "
        INSERT INTO cluster_reports (cluster_id, install_id, submission_id, created_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (cluster_id, install_id) DO NOTHING
        ",
        &[&issue_id, &install_id, &submission_id, &now],
    )?;
    let corroboration_count: i64 = db
        .query_one(
            "
            SELECT COUNT(*) FROM cluster_reports WHERE cluster_id = $1
            ",
            &[&issue_id],
        )?
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
    )?;
    Ok(issue_id)
}

fn next_issue_for_worker(db: &mut Client) -> Result<Option<IssueCluster>> {
    let row = db.query_opt(
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
    )?;
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
