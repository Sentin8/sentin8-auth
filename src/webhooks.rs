// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Webhook delivery - outbox + signed delivery.
//!
//! Implements a custom webhook delivery system with an outbox table. Auth
//! events (user.created, session.started, password.reset, mfa.enrolled,
//! passkey.enrolled, etc.) are appended to `sentin8_auth_webhook_outbox`; a relay
//! worker reads pending rows, signs each payload with HMAC-SHA256 using the
//! endpoint's secret, POSTs to the endpoint URL, and records the attempt.
//!
//! ## Endpoints
//!
//! Admin API:
//! - `GET /v1/admin/webhooks/endpoints`
//! - `POST /v1/admin/webhooks/endpoints`
//! - `GET /v1/admin/webhooks/endpoints/{id}`
//! - `DELETE /v1/admin/webhooks/endpoints/{id}`
//! - `GET /v1/admin/webhooks/outbox` - list recent outbox entries
//! - `GET /v1/admin/webhooks/attempts/{outbox_id}` - list delivery attempts
//!
//! The relay worker runs in-process as a tokio task spawned by the server.

use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::config::AuthConfig;
use crate::handlers::AppState;

/// Relay worker tick interval (1 second).
const RELAY_TICK: Duration = Duration::from_secs(1);
/// Max rows to deliver per tick.
const RELAY_BATCH: i64 = 25;
/// Base retry backoff (seconds, doubled each retry).
const RETRY_BASE_SECS: i64 = 30;

type HmacSha256 = Hmac<Sha256>;

// ── Admin API: requests / responses ───────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for createendpoint.
pub struct CreateEndpointRequest {
    /// The URL.
    pub url: String,
    #[serde(default)]
    /// The name.
    pub name: Option<String>,
    #[serde(default)]
    /// env identifier.
    pub env_id: Option<Uuid>,
    /// Event types to subscribe to ('*' = all).
    #[serde(default)]
    /// The event types.
    pub event_types: Option<Vec<String>>,
}

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for endpoint.
pub struct EndpointResponse {
    /// Identifier.
    pub id: Uuid,
    /// The URL.
    pub url: String,
    /// The name.
    pub name: String,
    /// The status.
    pub status: String,
    /// env identifier.
    pub env_id: Option<Uuid>,
    /// The event types.
    pub event_types: Vec<String>,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
/// The listendpointsquery type.
pub struct ListEndpointsQuery {
    #[serde(default)]
    /// env identifier.
    pub env_id: Option<Uuid>,
}

// ── Admin API: handlers ────────────────────────────────────────────────

/// `GET /v1/admin/webhooks/endpoints` - list webhook endpoints.
#[utoipa::path(
    get,
    path = "/v1/admin/webhooks/endpoints",
    params(("env_id" = Option<Uuid>, Query, description = "Filter by env ID")),
    responses(
        (status = 200, description = "Webhook endpoints", body = [EndpointResponse]),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List endpoints.
pub async fn list_endpoints(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(_q): Query<ListEndpointsQuery>,
) -> Result<Json<Vec<EndpointResponse>>, (StatusCode, String)> {
    // admin guard + tenant scoping. The previous
    // `WHERE ($1::uuid IS NULL OR env_id = $1)` listed EVERY tenant's
    // webhook endpoints when env_id was omitted - a cross-tenant leak.
    let auth = crate::sentin8or_auth::require_sentin8or_access(&state, &headers).await?;
    let rows = sqlx::query!(
        r#"SELECT id, url, name, status, env_id, event_types, created_at
           FROM webhook_endpoints
           WHERE env_id = $1
           ORDER BY created_at DESC"#,
        auth.env_id,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let endpoints = rows
        .into_iter()
        .map(|r| EndpointResponse {
            id: r.id,
            url: r.url,
            name: r.name,
            status: r.status,
            env_id: r.env_id,
            event_types: r.event_types,
            created_at: r.created_at,
        })
        .collect();
    Ok(Json(endpoints))
}

/// `POST /v1/admin/webhooks/endpoints` - create a webhook endpoint.
#[utoipa::path(
    post,
    path = "/v1/admin/webhooks/endpoints",
    request_body = CreateEndpointRequest,
    responses(
        (status = 200, description = "Webhook endpoint created (includes signing secret)"),
        (status = 400, description = "url must be an http(s) URL"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Create endpoint.
pub async fn create_endpoint(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateEndpointRequest>,
) -> Result<Response, (StatusCode, String)> {
    // admin guard + tenant scoping.
    let auth =
        crate::sentin8or_auth::require_sentin8or_access_write(&state, &headers, None).await?;
    if req.url.is_empty() || (!req.url.starts_with("https://") && !req.url.starts_with("http://")) {
        return Err((StatusCode::BAD_REQUEST, "url must be an http(s) URL".into()));
    }
    // Generate a random signing secret, encrypt it for storage.
    let raw_secret = random_hex(32);
    let cipher = encrypt_secret(&state.config, &raw_secret);

    let event_types = req.event_types.unwrap_or_else(|| vec!["*".to_string()]);
    // the row is created in the CALLER's env; a
    // request-supplied env_id is ignored (it could target another tenant).
    // tenant context on the same connection (design ).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(auth.env_id)
        .execute(&mut *conn)
        .await;
    let row = sqlx::query!(
        r#"INSERT INTO webhook_endpoints
             (env_id, url, name, status, secret_cipher, event_types)
           VALUES ($1, $2, $3, 'active', $4, $5)
           RETURNING id, url, name, status, env_id, event_types, created_at"#,
        auth.env_id,
        req.url,
        req.name.unwrap_or_default(),
        &cipher,
        &event_types,
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    crate::events::emit_event_tx(
        &mut conn,
        row.env_id.unwrap_or(crate::config::SYSTEM_ENV_ID),
        "sentin8:auth:webhook:created",
        serde_json::json!({
            "endpoint_id": row.id,
            "url": &row.url,
        }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = conn.commit().await;

    Ok(Json(serde_json::json!({
           "endpoint": {
               "id": row.id,
               "url": row.url,
               "name": row.name,
               "status": row.status,
               "env_id": row.env_id,
               "event_types": row.event_types,
               "created_at": row.created_at,
           },
    // The signing secret is returned ONCE on creation. The admin must
    // share it with the endpoint owner out-of-band.
           "secret": raw_secret,
       }))
    .into_response())
}

/// `GET /v1/admin/webhooks/endpoints/{id}` - get a webhook endpoint.
#[utoipa::path(
    get,
    path = "/v1/admin/webhooks/endpoints/{id}",
    params(("id" = Uuid, Path, description = "Endpoint ID")),
    responses(
        (status = 200, description = "Webhook endpoint", body = EndpointResponse),
        (status = 404, description = "endpoint not found"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Fetch endpoint.
pub async fn get_endpoint(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<EndpointResponse>, (StatusCode, String)> {
    // admin guard + tenant scoping: the row must belong
    // to the caller's env (otherwise a tenant could read another
    // tenant's webhook by id).
    let auth = crate::sentin8or_auth::require_sentin8or_access(&state, &headers).await?;
    let r = sqlx::query!(
        r#"SELECT id, url, name, status, env_id, event_types, created_at
           FROM webhook_endpoints WHERE id = $1 AND env_id = $2"#,
        id,
        auth.env_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "endpoint not found".into()))?;

    Ok(Json(EndpointResponse {
        id: r.id,
        url: r.url,
        name: r.name,
        status: r.status,
        env_id: r.env_id,
        event_types: r.event_types,
        created_at: r.created_at,
    }))
}

/// `DELETE /v1/admin/webhooks/endpoints/{id}` - delete a webhook endpoint.
#[utoipa::path(
    delete,
    path = "/v1/admin/webhooks/endpoints/{id}",
    params(("id" = Uuid, Path, description = "Endpoint ID")),
    responses(
        (status = 204, description = "Endpoint deleted"),
        (status = 404, description = "endpoint not found"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Delete endpoint.
pub async fn delete_endpoint(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    // admin guard + tenant scoping.
    let auth =
        crate::sentin8or_auth::require_sentin8or_access_write(&state, &headers, None).await?;
    // tenant context on the same connection (design ).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(auth.env_id)
        .execute(&mut *conn)
        .await;
    let result = sqlx::query!(
        r#"DELETE FROM webhook_endpoints WHERE id = $1 AND env_id = $2"#,
        id,
        auth.env_id,
    )
    .execute(&mut *conn)
    .await;
    match result {
        Ok(r) if r.rows_affected() > 0 => {
            crate::events::emit_event_tx(
                &mut conn,
                auth.env_id,
                "sentin8:auth:webhook:deleted",
                serde_json::json!({ "endpoint_id": id }),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let _ = conn.commit().await;
            Ok(StatusCode::NO_CONTENT)
        }
        Ok(_) => Err((StatusCode::NOT_FOUND, "endpoint not found".into())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

// ── Outbox inspection ───────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for outboxentry.
pub struct OutboxEntryResponse {
    /// Identifier.
    pub id: Uuid,
    /// endpoint identifier.
    pub endpoint_id: Uuid,
    /// The event type.
    pub event_type: String,
    /// The payload.
    pub payload: serde_json::Value,
    /// The retry count.
    pub retry_count: i32,
    /// The delivered at.
    pub delivered_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The failed at.
    pub failed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/admin/webhooks/outbox` - list recent outbox entries.
#[utoipa::path(
    get,
    path = "/v1/admin/webhooks/outbox",
    params(("env_id" = Option<Uuid>, Query, description = "Filter by env ID")),
    responses(
        (status = 200, description = "Outbox entries", body = [OutboxEntryResponse]),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List outbox.
pub async fn list_outbox(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(_q): Query<ListEndpointsQuery>,
) -> Result<Json<Vec<OutboxEntryResponse>>, (StatusCode, String)> {
    // admin guard + tenant scoping (caller's env only).
    let auth = crate::sentin8or_auth::require_sentin8or_access(&state, &headers).await?;
    let rows = sqlx::query!(
        r#"SELECT id, endpoint_id, event_type, payload, retry_count, delivered_at, failed_at, created_at
           FROM webhook_outbox
           WHERE env_id = $1
           ORDER BY created_at DESC
           LIMIT 50"#,
        auth.env_id,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let entries = rows
        .into_iter()
        .map(|r| OutboxEntryResponse {
            id: r.id,
            endpoint_id: r.endpoint_id,
            event_type: r.event_type,
            payload: r.payload,
            retry_count: r.retry_count,
            delivered_at: r.delivered_at,
            failed_at: r.failed_at,
            created_at: r.created_at,
        })
        .collect();
    Ok(Json(entries))
}

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for attempt.
pub struct AttemptResponse {
    /// Identifier.
    pub id: Uuid,
    /// outbox identifier.
    pub outbox_id: Uuid,
    /// The status code.
    pub status_code: Option<i32>,
    /// The error.
    pub error: Option<String>,
    /// The duration ms.
    pub duration_ms: Option<i32>,
    /// The attempted at.
    pub attempted_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/admin/webhooks/attempts/{outbox_id}` - list delivery attempts for an outbox entry.
#[utoipa::path(
    get,
    path = "/v1/admin/webhooks/attempts/{outbox_id}",
    params(("outbox_id" = Uuid, Path, description = "Outbox entry ID")),
    responses(
        (status = 200, description = "Delivery attempts", body = [AttemptResponse]),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List attempts.
pub async fn list_attempts(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(outbox_id): Path<Uuid>,
) -> Result<Json<Vec<AttemptResponse>>, (StatusCode, String)> {
    // admin guard + tenant scoping: only attempts for
    // outbox rows in the caller's env are visible.
    let auth = crate::sentin8or_auth::require_sentin8or_access(&state, &headers).await?;
    let rows = sqlx::query!(
        r#"SELECT a.id, a.outbox_id, a.status_code, a.error, a.duration_ms, a.attempted_at
           FROM webhook_attempts a
           JOIN webhook_outbox o ON o.id = a.outbox_id
           WHERE a.outbox_id = $1 AND o.env_id = $2
           ORDER BY a.attempted_at DESC"#,
        outbox_id,
        auth.env_id,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let attempts = rows
        .into_iter()
        .map(|r| AttemptResponse {
            id: r.id,
            outbox_id: r.outbox_id,
            status_code: r.status_code,
            error: r.error,
            duration_ms: r.duration_ms,
            attempted_at: r.attempted_at,
        })
        .collect();
    Ok(Json(attempts))
}

/// `POST /v1/admin/webhooks/attempts/{outbox_id}/replay` - reset a failed
/// webhook delivery to pending (mirrors post's `replay_dlq`, auth DESIGN
/// §10). Admin-gated; the relay picks the row up on its next tick.
#[utoipa::path(
    post,
    path = "/v1/admin/webhooks/attempts/{outbox_id}/replay",
    params(("outbox_id" = Uuid, Path, description = "Outbox entry ID")),
    responses(
        (status = 204, description = "Delivery reset to pending"),
        (status = 404, description = "Outbox entry not found in this env"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Replay a failed webhook delivery.
pub async fn replay_failed(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(outbox_id): Path<Uuid>,
) -> Result<axum::http::StatusCode, (axum::http::StatusCode, String)> {
    let auth = crate::sentin8or_auth::require_sentin8or_access(&state, &headers).await?;
    // Tenant-scoped: only rows in the caller's env can be replayed.
    let result = sqlx::query!(
        r#"UPDATE webhook_outbox
              SET failed_at = NULL, next_attempt_at = now(), retry_count = 0
            WHERE id = $1 AND env_id = $2"#,
        outbox_id,
        auth.env_id,
    )
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "outbox entry not found".into()));
    }
    tracing::info!(outbox_id = %outbox_id, "auth: webhook delivery replayed");
    Ok(StatusCode::NO_CONTENT)
}

// ── Enqueue helper (used by other Auth modules to emit events) ────────

/// Enqueue a webhook event for delivery. Called by sign-in, sign-up,
/// password reset, MFA enrollment, etc. - anywhere an event should be
/// delivered to registered endpoints. Returns the outbox row id.
/// Enqueue event.
pub async fn enqueue_event(
    pool: &sqlx::PgPool,
    config: &AuthConfig,
    env_id: Option<Uuid>,
    event_type: &str,
    payload: serde_json::Value,
) -> Result<Vec<Uuid>, sqlx::Error> {
    // Find matching endpoints.
    let rows = sqlx::query!(
        r#"SELECT id, event_types
           FROM webhook_endpoints
           WHERE ($1::uuid IS NULL OR env_id = $1)
             AND status = 'active'"#,
        env_id,
    )
    .fetch_all(pool)
    .await?;

    let mut outbox_ids = Vec::new();
    for ep in rows {
        let event_types = ep.event_types;
        if !event_types.iter().any(|t| t == "*" || t == event_type) {
            continue;
        }
        let outbox_id = Uuid::new_v4();
        sqlx::query!(
            r#"INSERT INTO webhook_outbox
                 (id, endpoint_id, env_id, event_type, payload)
               VALUES ($1, $2, $3, $4, $5)"#,
            outbox_id,
            ep.id,
            env_id,
            event_type,
            &payload,
        )
        .execute(pool)
        .await?;
        outbox_ids.push(outbox_id);
    }
    let _ = config; // reserved for future signing metadata
    Ok(outbox_ids)
}

// ── Relay worker ────────────────────────────────────────────────────────

/// Spawn the webhook relay worker as a background tokio task. Reads the
/// outbox every `RELAY_TICK`, delivers up to `RELAY_BATCH` rows per tick,
/// and records attempts.
/// Spawn relay.
pub fn spawn_relay(state: AppState) {
    tokio::spawn(async move {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client");
        loop {
            if let Err(e) = relay_tick(&state, &http).await {
                tracing::error!(error = %e, "webhook relay tick failed");
            }
            tokio::time::sleep(RELAY_TICK).await;
        }
    });
}

async fn relay_tick(state: &AppState, http: &reqwest::Client) -> Result<(), anyhow::Error> {
    // Claim a batch of pending rows.
    let rows = sqlx::query!(
        r#"SELECT id, endpoint_id, event_type, payload, retry_count, max_retries
           FROM webhook_outbox
           WHERE delivered_at IS NULL
             AND failed_at IS NULL
             AND next_attempt_at <= now()
           ORDER BY next_attempt_at
           LIMIT $1"#,
        RELAY_BATCH,
    )
    .fetch_all(&state.pool)
    .await?;

    for row in rows {
        // Fetch the endpoint + decrypt the secret.
        let endpoint = sqlx::query!(
            r#"SELECT url, secret_cipher, status FROM webhook_endpoints WHERE id = $1"#,
            row.endpoint_id,
        )
        .fetch_optional(&state.pool)
        .await?;
        let Some(endpoint) = endpoint else {
            // Endpoint was deleted - mark outbox row failed.
            let _ = sqlx::query!(
                r#"UPDATE webhook_outbox SET failed_at = now() WHERE id = $1"#,
                row.id,
            )
            .execute(&state.pool)
            .await;
            continue;
        };
        if endpoint.status != "active" {
            // Skip delivery for disabled endpoints; leave in outbox.
            continue;
        }
        let secret = String::from_utf8(decrypt_secret(&state.config, &endpoint.secret_cipher))
            .unwrap_or_default();
        let payload = row.payload;
        let body = serde_json::to_vec(&serde_json::json!({
            "event_type": row.event_type,
            "payload": &payload,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }))?;
        let signature = sign_payload(&secret, &body);

        let start = std::time::Instant::now();
        let res = http
            .post(&endpoint.url)
            .header("content-type", "application/json")
            .header("x-sentin8-signature", format!("sha256={signature}"))
            .header("x-sentin8-event", &row.event_type)
            .body(body)
            .send()
            .await;
        let duration_ms = start.elapsed().as_millis() as i32;

        match res {
            Ok(r) if r.status().is_success() => {
                let status = r.status().as_u16() as i32;
                let body_text = r.text().await.unwrap_or_default();
                record_attempt(
                    &state.pool,
                    row.id,
                    Some(status),
                    None,
                    Some(body_text),
                    duration_ms,
                )
                .await;
                mark_delivered(&state.pool, row.id).await;
            }
            Ok(r) => {
                let status = r.status().as_u16() as i32;
                let body_text = r.text().await.unwrap_or_default();
                record_attempt(
                    &state.pool,
                    row.id,
                    Some(status),
                    None,
                    Some(body_text),
                    duration_ms,
                )
                .await;
                schedule_retry(&state.pool, row.id, row.retry_count, row.max_retries).await;
            }
            Err(e) => {
                record_attempt(
                    &state.pool,
                    row.id,
                    None,
                    Some(e.to_string()),
                    None,
                    duration_ms,
                )
                .await;
                schedule_retry(&state.pool, row.id, row.retry_count, row.max_retries).await;
            }
        }
    }
    Ok(())
}

async fn record_attempt(
    pool: &sqlx::PgPool,
    outbox_id: Uuid,
    status_code: Option<i32>,
    error: Option<String>,
    response_body: Option<String>,
    duration_ms: i32,
) {
    let _ = sqlx::query!(
        r#"INSERT INTO webhook_attempts
             (outbox_id, status_code, response_body, error, duration_ms)
           VALUES ($1, $2, $3, $4, $5)"#,
        outbox_id,
        status_code,
        response_body,
        error,
        duration_ms,
    )
    .execute(pool)
    .await;
}

async fn mark_delivered(pool: &sqlx::PgPool, outbox_id: Uuid) {
    let _ = sqlx::query!(
        r#"UPDATE webhook_outbox SET delivered_at = now() WHERE id = $1"#,
        outbox_id,
    )
    .execute(pool)
    .await;
}

async fn schedule_retry(pool: &sqlx::PgPool, outbox_id: Uuid, retry_count: i32, max_retries: i32) {
    if retry_count + 1 >= max_retries {
        let _ = sqlx::query!(
            r#"UPDATE webhook_outbox
               SET retry_count = $2, failed_at = now()
               WHERE id = $1"#,
            outbox_id,
            retry_count + 1,
        )
        .execute(pool)
        .await;
        return;
    }
    let backoff = RETRY_BASE_SECS * 2i64.pow(retry_count as u32);
    let _ = sqlx::query!(
        r#"UPDATE webhook_outbox
           SET retry_count = $2,
               next_attempt_at = now() + ($3 || ' seconds')::interval
           WHERE id = $1"#,
        outbox_id,
        retry_count + 1,
        backoff.to_string(),
    )
    .execute(pool)
    .await;
}

// ── Internal helpers ───────────────────────────────────────────────────

/// Compute the HMAC-SHA256 signature of the body with the endpoint secret.
fn sign_payload(secret: &str, body: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body);
    hex_encode(&mac.finalize().into_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

/// Encrypt the endpoint signing secret with the shared AES-256-GCM envelope
/// (`v2:` prefix, SEC-). Legacy XOR fallback only when no master key
/// is configured (test mode).
fn encrypt_secret(config: &AuthConfig, secret: &str) -> Vec<u8> {
    let mk = match crate::jwks::master_key() {
        Some(mk) => mk,
        None if std::env::var("SENTIN8_AUTH_DEV_INSECURE_KEY").is_ok() => {
            sentin8::crypto::derive_key(b"sentin8-auth-dev-insecure-key")
        }
        None => return xor_encrypt_secret(config, secret),
    };
    sentin8::crypto::seal(&mk, secret.as_bytes())
        .map(|s| s.into_bytes())
        .unwrap_or_else(|_| xor_encrypt_secret(config, secret))
}

fn decrypt_secret(config: &AuthConfig, cipher: &[u8]) -> Vec<u8> {
    if sentin8::crypto::is_envelope(cipher) {
        let mk = match crate::jwks::master_key() {
            Some(mk) => mk,
            None => sentin8::crypto::derive_key(b"sentin8-auth-dev-insecure-key"),
        };
        return sentin8::crypto::open(&mk, cipher).unwrap_or_default();
    }
    xor_decrypt_secret(config, cipher)
}

/// Legacy XOR-with-issuer scheme - kept only to read pre-envelope rows.
fn xor_encrypt_secret(config: &AuthConfig, secret: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(config.issuer.as_bytes());
    hasher.update(b"auth-webhook-key");
    let key = hasher.finalize();
    secret
        .as_bytes()
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

fn xor_decrypt_secret(config: &AuthConfig, cipher: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(config.issuer.as_bytes());
    hasher.update(b"auth-webhook-key");
    let key = hasher.finalize();
    cipher
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_payload_is_hmac_sha256_hex() {
        let sig = sign_payload("secret", b"hello");
        assert_eq!(sig.len(), 64); // 32 bytes hex
                                   // Verify against a manual computation.
        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(b"hello");
        assert_eq!(sig, hex_encode(&mac.finalize().into_bytes()));
    }

    #[test]
    fn sign_payload_changes_with_secret() {
        let a = sign_payload("a", b"hello");
        let b = sign_payload("b", b"hello");
        assert_ne!(a, b);
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let cfg = AuthConfig::for_testing();
        let secret = "webhook-secret-1234567890";
        let cipher = encrypt_secret(&cfg, secret);
        assert_ne!(cipher, secret.as_bytes());
        let decrypted = decrypt_secret(&cfg, &cipher);
        assert_eq!(decrypted, secret.as_bytes());
    }

    #[test]
    fn random_hex_is_unique() {
        assert_ne!(random_hex(16), random_hex(16));
    }

    #[test]
    fn hex_encode_known() {
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
    }
}
