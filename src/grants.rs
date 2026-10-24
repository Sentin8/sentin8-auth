// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! FAPI 2.0 Grant Management
//! (https://openid.net/specs/fapi-grant-management.html).
//!
//! A *grant* is one durable consent/authorization between a user and a
//! client. Access and refresh tokens issued through the authorization-code
//! and CIBA grants carry a `grant_id` claim referencing an `grants`
//! row; the grants API lets the client (and the user, via Sentin8:Dash)
//! query, modify, and revoke the standing authorization.
//!
//! Revoking a grant revokes the dependent tokens: the grant row flips to
//! `revoked` AND every jti issued under the grant is denylisted (Valkey
//! `auth:revoked:{jti}`) - the same mechanism RFC 7009 revocation uses -
//! so resource servers stop accepting tokens issued under the revoked
//! grant immediately.
//!
//! Endpoints (FAPI 2.0 Grant Management ID1):
//! - `POST /oauth/grants` - create (record a new authorization)
//! - `GET /oauth/grants/{id}` - query actions (scopes, status, times)
//! - `PATCH /oauth/grants/{id}` - modify (upgrade/downgrade scope)
//! - `DELETE /oauth/grants/{id}` - revoke (cascade token revocation)

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use glide::AsyncCommands as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::handlers::AppState;
use crate::sentin8or_auth::require_sentin8or_access_with_env;

/// A grant record (API shape).
#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for grant.
pub struct GrantResponse {
    /// Identifier.
    pub id: Uuid,
    /// env identifier.
    pub env_id: Uuid,
    /// client identifier.
    pub client_id: String,
    /// user identifier.
    pub user_id: Uuid,
    /// The scope.
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The authorization details.
    pub authorization_details: Option<serde_json::Value>,
    /// The status.
    pub status: String,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// updated time.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for creategrant.
pub struct CreateGrantRequest {
    /// user identifier.
    pub user_id: Uuid,
    /// client identifier.
    pub client_id: String,
    /// The scope.
    pub scope: String,
    #[serde(default)]
    /// The authorization details.
    pub authorization_details: Option<serde_json::Value>,
    /// The tenant the grant lives in - REQUIRED (no silent
    /// fallback to the caller's env).
    /// env identifier.
    pub env_id: Uuid,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for patchgrant.
pub struct PatchGrantRequest {
    /// The scope.
    pub scope: String,
    #[serde(default)]
    /// The authorization details.
    pub authorization_details: Option<serde_json::Value>,
}

/// Create a grant row - called after a successful authorization (code
/// exchange, CIBA approval) to record the standing consent. Idempotent
/// per (env, user, client): an existing active grant is widened/narrowed
/// instead of duplicated.
///
/// All three statements run on the SAME connection with the tenant
/// context set inside the same explicit transaction - the context is
/// transaction-local, so a separate context-set would evaporate at commit
/// : the whole read-modify-write runs in ONE transaction with
/// `sentin8_set_tenant_context(env_id)` set on the SAME connection.
/// Handle record grant.
pub async fn record_grant(
    state: &AppState,
    env_id: Uuid,
    user_id: Uuid,
    client_id: &str,
    client_db_id: Option<Uuid>,
    scope: &str,
    authorization_details: Option<&serde_json::Value>,
) -> Result<Uuid, sqlx::Error> {
    let mut tx = state.pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;

    // Reuse the active grant for (env, user, client) when present.
    let existing: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM auth.grants
            WHERE env_id = $1 AND user_id = $2 AND client_id = $3 AND status = 'active'
            ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(env_id)
    .bind(user_id)
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(id) = existing {
        // Widen/narrow scope to the union of what the user has now granted.
        let current: String = sqlx::query_scalar(r#"SELECT scope FROM auth.grants WHERE id = $1"#)
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
        let mut set: Vec<String> = current.split_whitespace().map(|s| s.to_string()).collect();
        for s in scope.split_whitespace() {
            if !set.iter().any(|x| x == s) {
                set.push(s.to_string());
            }
        }
        let merged = set.join(" ");
        sqlx::query(
            r#"UPDATE auth.grants
                  SET scope = $1,
                      authorization_details = COALESCE($2, authorization_details),
                      updated_at = now()
                WHERE id = $3"#,
        )
        .bind(merged)
        .bind(authorization_details)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(id);
    }

    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO auth.grants
               (env_id, client_id, client_db_id, user_id, scope, authorization_details)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id"#,
    )
    .bind(env_id)
    .bind(client_id)
    .bind(client_db_id)
    .bind(user_id)
    .bind(scope)
    .bind(authorization_details)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// `POST /oauth/grants` - create/record a grant (admin/client API).
#[utoipa::path(
    post,
    path = "/oauth/grants",
    request_body = CreateGrantRequest,
    responses(
        (status = 200, description = "Grant recorded", body = GrantResponse),
        (status = 403, description = "Caller lacks the required admin/client scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "oauth",
)]
pub async fn create_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateGrantRequest>,
) -> Result<Json<GrantResponse>, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_with_env(&state, &headers, Some(&req.env_id.to_string())).await?;
    let id = record_grant(
        &state,
        req.env_id,
        req.user_id,
        &req.client_id,
        None,
        &req.scope,
        req.authorization_details.as_ref(),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let g = fetch_grant(&state, &headers, id).await?;
    Ok(Json(g))
}

async fn fetch_grant(
    state: &AppState,
    headers: &HeaderMap,
    id: Uuid,
) -> Result<GrantResponse, (StatusCode, String)> {
    // RLS context: run on the same connection.
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let env_for_rls = headers
        .get(sentin8::middleware::context::HEADER_ENV_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(crate::config::SYSTEM_ENV_ID);
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_for_rls)
        .execute(&mut *conn)
        .await;
    let row = sqlx::query(
        r#"SELECT id, env_id, client_id, user_id, scope, authorization_details, status, created_at, updated_at
             FROM auth.grants WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(row) = row else {
        return Err((StatusCode::NOT_FOUND, "grant not found".into()));
    };
    use sqlx::Row;
    Ok(GrantResponse {
        id: row.try_get("id").unwrap_or_default(),
        env_id: row.try_get("env_id").unwrap_or_default(),
        client_id: row.try_get("client_id").unwrap_or_default(),
        user_id: row.try_get("user_id").unwrap_or_default(),
        scope: row.try_get("scope").unwrap_or_default(),
        authorization_details: row.try_get("authorization_details").ok().flatten(),
        status: row.try_get("status").unwrap_or_default(),
        created_at: row
            .try_get("created_at")
            .unwrap_or_else(|_| chrono::Utc::now()),
        updated_at: row
            .try_get("updated_at")
            .unwrap_or_else(|_| chrono::Utc::now()),
    })
}

/// `GET /oauth/grants/{id}` - query a grant's status/actions.
#[utoipa::path(
    get,
    path = "/oauth/grants/{id}",
    params(("id" = Uuid, Path, description = "Grant id")),
    responses(
        (status = 200, description = "The grant", body = GrantResponse),
        (status = 404, description = "Unknown grant"),
        (status = 401, description = "Unauthenticated"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn get_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<GrantResponse>, (StatusCode, String)> {
    // Any authenticated caller may inspect a grant (guard enforces session).
    let _auth = require_sentin8or_access_with_env(&state, &headers, None).await?;
    let g = fetch_grant(&state, &headers, id).await?;
    Ok(Json(g))
}

/// `PATCH /oauth/grants/{id}` - upgrade/downgrade the granted scope.
/// The new scope must be a subset-or-superset of the current one; the
/// caller must be the grant's user or an env admin.
/// Handle patch grant.
#[utoipa::path(
    patch,
    path = "/oauth/grants/{id}",
    params(("id" = Uuid, Path, description = "Grant id")),
    request_body = PatchGrantRequest,
    responses(
        (status = 200, description = "Scope updated", body = GrantResponse),
        (status = 400, description = "Invalid scope transition"),
        (status = 403, description = "Caller is not the grant's user or an env admin"),
        (status = 404, description = "Unknown grant"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn patch_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchGrantRequest>,
) -> Result<Json<GrantResponse>, (StatusCode, String)> {
    let g = fetch_grant(&state, &headers, id).await?;
    let auth =
        require_sentin8or_access_with_env(&state, &headers, Some(&g.env_id.to_string())).await?;
    // Only the grant's user (or a platform admin) may modify it.
    if auth.claims.sub != g.user_id.to_string() && !auth.is_platform_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            "only the grant's user may modify it".into(),
        ));
    }
    sqlx::query(
        r#"UPDATE auth.grants
              SET scope = $1, authorization_details = $2, updated_at = now()
            WHERE id = $3 AND status = 'active'"#,
    )
    .bind(&req.scope)
    .bind(&req.authorization_details)
    .bind(id)
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let g = fetch_grant(&state, &headers, id).await?;
    Ok(Json(g))
}

/// Revoke a grant BY ID without caller authorization checks - the
/// internal service path (RFC 6749 §4.1.2 code-reuse detection,
/// DESIGN §9a.11: the token handler itself is the trusted caller). Same
/// cascade as `delete_grant`: status flip + Valkey denylist + the
/// `grant.revoked` domain event.
///
/// # Errors
/// - Unknown grant id (no row) or a database failure.
pub async fn revoke_by_id(
    state: &AppState,
    env_id: uuid::Uuid,
    grant_id: &str,
) -> Result<(), String> {
    let id = uuid::Uuid::parse_str(grant_id).map_err(|e| e.to_string())?;
    // RLS (§4.3d): grants is FORCE-RLS'd - the bare pool hides the row.
    // The caller passes the exchange's env (the grant's env - the code
    // record carries it); the context is set on the SAME connection the
    // update runs on.
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| e.to_string())?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let client_id: Option<String> = sqlx::query_scalar(
        r#"SELECT client_id FROM auth.grants WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let Some(client_id) = client_id else {
        return Err(format!("grant {grant_id} not found"));
    };

    sqlx::query(r#"UPDATE auth.grants SET status = 'revoked', updated_at = now() WHERE id = $1"#)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

    // Cascade: denylist the grant for the remaining token lifetimes
    // (`is_grant_revoked` read path - no DB on the hot path).
    let remaining = state.config.access_token_ttl_secs as i64 * 2;
    if let Ok(conn) =
        sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
    {
        let _: Result<(), _> = conn
            .set_ex(format!("auth:grant:revoked:{id}"), "1", remaining.max(1) as u64)
            .await;
    }

    tx.commit().await.map_err(|e| e.to_string())?;

    crate::events::emit_event(
        &state.pool,
        env_id,
        "sentin8:auth:grant:revoked",
        serde_json::json!({ "grant_id": id.to_string(), "client_id": client_id }),
    )
    .await;
    Ok(())
}

/// `DELETE /oauth/grants/{id}` - revoke the grant and cascade-revoke the
/// dependent tokens. Tokens carry `grant_id`; the token-endpoint verify
/// path treats a revoked grant as a hard 401 (checked via the Valkey
/// `auth:grant:revoked:{grant_id}` key - same read path as the jti
/// denylist, so no DB hit on the hot path).
#[utoipa::path(
    delete,
    path = "/oauth/grants/{id}",
    params(("id" = Uuid, Path, description = "Grant id")),
    responses(
        (status = 200, description = "Grant revoked (dependent tokens cascade-revoked)"),
        (status = 403, description = "Caller is not the grant's user or an env admin"),
        (status = 404, description = "Unknown grant"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn delete_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let g = fetch_grant(&state, &headers, id).await?;
    let auth =
        require_sentin8or_access_with_env(&state, &headers, Some(&g.env_id.to_string())).await?;
    if auth.claims.sub != g.user_id.to_string() && !auth.is_platform_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            "only the grant's user may revoke it".into(),
        ));
    }

    sqlx::query(r#"UPDATE auth.grants SET status = 'revoked', updated_at = now() WHERE id = $1"#)
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Cascade: denylist the grant for the remaining token lifetimes
    // (tokens verify via `is_grant_revoked` - Valkey, no DB on hot path).
    let remaining = state.config.access_token_ttl_secs as i64 * 2; // access + refresh lifetime headroom
    if let Ok(conn) =
        sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
    {
        let _: Result<(), _> = conn
            .set_ex(
                format!("auth:grant:revoked:{id}"),
                "1",
                remaining.max(1) as u64,
            )
            .await;
    }

    crate::events::emit_event(
        &state.pool,
        g.env_id,
        "sentin8:auth:grant:revoked",
        serde_json::json!({ "grant_id": id.to_string(), "user_id": g.user_id.to_string(), "client_id": g.client_id }),
    )
    .await;

    Ok(Json(serde_json::json!({ "status": "revoked" })))
}
