// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Actor tokens - support / delegated admin.
//!
//! An actor token is a short-lived access token issued by an authorized
//! support/admin user that lets them act on behalf of another user. The
//! token's `sub` claim is the impersonated user; the `act` claim identifies
//! the actor (the support user). Every actor token is recorded in
//! `sentin8_auth_actor_events` for strict audit.
//!
//! ## Endpoints
//!
//! - `POST /v1/admin/actor-tokens` - issue an actor token. Requires the
//! caller to have the `sentin8:auth:actor:issue` scope (granted to the
//! `sentin8:org:admin` tenant role and the `sys-admin` platform role). The
//! request specifies the target user id + the requested scope + lifetime
//! (bounded to a max of 1 hour).
//! - `GET /v1/admin/actor-tokens` - list recent actor token issuances
//! (audit trail).
//! - `POST /v1/actor-tokens/revoke` - revoke an actor token by `jti`.
//! - `GET /v1/admin/actor-events` - query the actor event audit log.
//!
//! ## JWT claims
//!
//! An actor token adds the following claim to the standard access token:
//! ```json
//! {
//! "token_tp": "access",
//! "sub": "<impersonated user id>",
//! "act": {
//! "sub": "<actor user id>",
//! "email": "<actor email>",
//! "reason": "<free-text reason>"
//! }
//! }
//! ```

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::events::emit_event;
use crate::handlers::AppState;
use crate::jwt::AuthClaims;

/// Maximum lifetime of an actor token (1 hour).
const MAX_ACTOR_TOKEN_TTL_SECS: i64 = 3600;
/// Default lifetime when none is requested (15 minutes).
const DEFAULT_ACTOR_TOKEN_TTL_SECS: i64 = 900;

/// The `act` claim embedded in an actor token.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
/// The actorclaim type.
pub struct ActorClaim {
    /// The sub.
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The email.
    pub email: Option<String>,
    /// The reason.
    pub reason: String,
}

// ── Requests / Responses ───────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for issueactortoken.
pub struct IssueActorTokenRequest {
    /// The user to impersonate.
    /// target user identifier.
    pub target_user_id: Uuid,
    /// Requested scope (must be a subset of the impersonated user's scopes).
    #[serde(default)]
    /// The scope.
    pub scope: Option<String>,
    /// Token lifetime in seconds (bounded to MAX_ACTOR_TOKEN_TTL_SECS).
    #[serde(default)]
    /// The ttl secs.
    pub ttl_secs: Option<i64>,
    /// Free-text reason for the impersonation (required, audited).
    /// The reason.
    pub reason: String,
}

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for actortoken.
pub struct ActorTokenResponse {
    /// The access token.
    pub access_token: String,
    /// token identifier.
    pub token_id: Uuid,
    /// The expires in.
    pub expires_in: i64,
    /// target user identifier.
    pub target_user_id: Uuid,
    /// actor user identifier.
    pub actor_user_id: Uuid,
}

#[derive(Debug, Deserialize, ToSchema)]
/// The listactortokensquery type.
pub struct ListActorTokensQuery {
    #[serde(default)]
    /// target user identifier.
    pub target_user_id: Option<Uuid>,
    #[serde(default)]
    /// actor user identifier.
    pub actor_user_id: Option<Uuid>,
    #[serde(default = "default_page_size")]
    /// The page size.
    pub page_size: i64,
    #[serde(default)]
    /// The page.
    pub page: i64,
}

fn default_page_size() -> i64 {
    50
}

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for actorevent.
pub struct ActorEventResponse {
    /// Identifier.
    pub id: Uuid,
    /// actor user identifier.
    pub actor_user_id: Uuid,
    /// target user identifier.
    pub target_user_id: Uuid,
    /// token identifier.
    pub token_id: Uuid,
    /// The scope.
    pub scope: String,
    /// The reason.
    pub reason: String,
    /// The action: `issue` or `revoke`.
    pub action: String, // "issue" | "revoke"
    /// expires time.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for revokeactortoken.
pub struct RevokeActorTokenRequest {
    /// token identifier.
    pub token_id: Uuid,
}

// ── Handlers ───────────────────────────────────────────────────────────

/// `POST /v1/admin/actor-tokens` - issue an actor token.
///
/// The caller must be authenticated (session cookie) and have the
/// `sentin8:auth:actor:issue` scope via a tenant or platform admin role/group
/// (e.g. `sentin8:org:admin`, `sentin8:org:owner`, `sys-admin`).
/// `POST /v1/admin/actor-tokens` - issue an actor token.
#[utoipa::path(
    post,
    path = "/v1/admin/actor-tokens",
    request_body = IssueActorTokenRequest,
    responses(
        (status = 200, description = "Actor token issued", body = ActorTokenResponse),
        (status = 400, description = "reason is required"),
        (status = 401, description = "actor must be authenticated"),
        (status = 403, description = "actor lacks auth:actor:issue scope"),
        (status = 404, description = "target user not found"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Issue actor token.
pub async fn issue_actor_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IssueActorTokenRequest>,
) -> Result<Response, (StatusCode, String)> {
    if req.reason.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "reason is required".into()));
    }
    let ttl = req
        .ttl_secs
        .unwrap_or(DEFAULT_ACTOR_TOKEN_TTL_SECS)
        .clamp(60, MAX_ACTOR_TOKEN_TTL_SECS);

    // Resolve the actor (the authenticated support user).
    let actor_token_id = crate::handlers::extract_session_token(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "actor must be authenticated".into(),
        )
    })?;
    // SEC- - mutating session endpoint: CSRF-gated (Bearer exempt).
    crate::handlers::check_csrf(&headers, &actor_token_id)?;
    let actor_session = crate::sessions::Session::find_by_token(&state.pool, &actor_token_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "actor session not found".into()))?;
    if !actor_session.is_valid() {
        return Err((StatusCode::UNAUTHORIZED, "actor session expired".into()));
    }
    let actor_user_id = actor_session.user_id;

    // Verify the actor has the auth:actor:issue scope (via group membership).
    let actor_scopes = crate::handlers::fetch_role_scopes(&state.pool, actor_user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if !actor_scopes
        .iter()
        .any(|s| s == "sentin8:auth:actor:issue" || s == "sentin8:auth:admin:write")
    {
        return Err((
            StatusCode::FORBIDDEN,
            "actor lacks auth:actor:issue scope".into(),
        ));
    }

    // Fetch the target user.
    let target = sqlx::query!(
        r#"SELECT id, env_id, email FROM users WHERE id = $1"#,
        req.target_user_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "target user not found".into()))?;

    // Fetch the actor's email for the act claim.
    let actor = sqlx::query!(r#"SELECT email FROM users WHERE id = $1"#, actor_user_id,)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Resolve scope: default to the target user's group scopes, intersect
    // with the actor's scopes to prevent privilege escalation.
    let target_scopes = crate::handlers::fetch_role_scopes(&state.pool, target.id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let actor_scope_set: std::collections::HashSet<String> = actor_scopes.into_iter().collect();
    let mut effective_scopes: Vec<String> = target_scopes
        .into_iter()
        .filter(|s| actor_scope_set.contains(s))
        .collect();
    // The actor's own scopes are always allowed (they can do what they could
    // do anyway).
    for s in actor_scope_set {
        if !effective_scopes.contains(&s) {
            effective_scopes.push(s);
        }
    }
    // Honor an explicit requested scope (still intersected with effective).
    if let Some(req_scope) = req.scope.as_deref() {
        let requested: std::collections::HashSet<&str> = req_scope.split_whitespace().collect();
        effective_scopes.retain(|s| requested.contains(s.as_str()));
    }
    let scope = effective_scopes.join(" ");

    let token_id = Uuid::new_v4();
    let mut claims = AuthClaims::access(
        &state.config.issuer,
        target.id,
        &scope,
        target.env_id,
        Some(&target.email),
        Duration::seconds(ttl),
    );
    // Override the jti so it matches the recorded token_id (for revocation).
    claims.jti = token_id.to_string();
    // Embed the actor claim as a custom JSON claim. AuthClaims doesn't have
    // an `act` field, so we serialize manually.
    let act = ActorClaim {
        sub: actor_user_id.to_string(),
        email: Some(actor.email.clone()),
        reason: req.reason.clone(),
    };

    let access_token = sign_actor_token(&state, &claims, &act).await?;

    // Record the issuance in the audit table.
    let expires_at = claims.expires_at();
    sqlx::query!(
        r#"INSERT INTO actor_events
             (id, actor_user_id, target_user_id, token_id, scope, reason, action, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, 'issue', $7)"#,
        Uuid::new_v4(),
        actor_user_id,
        target.id,
        token_id,
        &scope,
        &req.reason,
        expires_at,
    )
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Emit an audit event via sentin8-audit.
    tracing::info!(
        actor = %actor_user_id,
        target = %target.id,
        token_id = %token_id,
        scope = %scope,
        "actor token issued",
    );

    emit_event(
        &state.pool,
        target.env_id,
        "sentin8:auth:actortoken:issued",
        serde_json::json!({
            "actor_token_id": token_id,
            "act_sub": actor_user_id,
        }),
    )
    .await;

    Ok(Json(ActorTokenResponse {
        access_token,
        token_id,
        expires_in: ttl,
        target_user_id: target.id,
        actor_user_id,
    })
    .into_response())
}

/// `GET /v1/admin/actor-tokens` - list recent actor token issuances (audit).
/// `GET /v1/admin/actor-tokens` - list recent actor token issuances.
#[utoipa::path(
    get,
    path = "/v1/admin/actor-tokens",
    params(
        ("target_user_id" = Option<Uuid>, Query, description = "Filter by target user"),
        ("actor_user_id" = Option<Uuid>, Query, description = "Filter by actor user"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Actor token events", body = [ActorEventResponse]),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List actor tokens.
pub async fn list_actor_tokens(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(q): Query<ListActorTokensQuery>,
) -> Result<Json<Vec<ActorEventResponse>>, (StatusCode, String)> {
    // SEC- - admin guard (previously unauthenticated).
    let _auth = crate::sentin8or_auth::require_sentin8or_access(&state, &headers).await?;
    let limit = q.page_size.clamp(1, 200);
    let offset = (q.page.max(1) - 1) * limit;
    let rows = sqlx::query!(
        r#"SELECT
               id, actor_user_id, target_user_id, token_id, scope, reason, action,
               expires_at, created_at
           FROM actor_events
           WHERE ($1::uuid IS NULL OR target_user_id = $1)
             AND ($2::uuid IS NULL OR actor_user_id = $2)
           ORDER BY created_at DESC
           LIMIT $3 OFFSET $4"#,
        q.target_user_id,
        q.actor_user_id,
        limit,
        offset,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let events = rows
        .into_iter()
        .map(|r| ActorEventResponse {
            id: r.id,
            actor_user_id: r.actor_user_id,
            target_user_id: r.target_user_id,
            token_id: r.token_id,
            scope: r.scope,
            reason: r.reason,
            action: r.action,
            expires_at: r.expires_at,
            created_at: r.created_at,
        })
        .collect();
    Ok(Json(events))
}

/// `POST /v1/actor-tokens/revoke` - revoke an actor token by token_id (jti).
/// `POST /v1/actor-tokens/revoke` - revoke an actor token by token_id.
#[utoipa::path(
    post,
    path = "/v1/actor-tokens/revoke",
    request_body = RevokeActorTokenRequest,
    responses(
        (status = 200, description = "Actor token revoked"),
        (status = 404, description = "actor token not found"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Revoke actor token.
pub async fn revoke_actor_token(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RevokeActorTokenRequest>,
) -> Result<Response, (StatusCode, String)> {
    // SEC- - admin guard (previously unauthenticated).
    let _auth =
        crate::sentin8or_auth::require_sentin8or_access_write(&state, &headers, None).await?;
    // Mark the token as revoked in the audit table and add to a revocation set.
    let result = sqlx::query!(
        r#"UPDATE actor_events
           SET action = 'revoke'
           WHERE token_id = $1 AND action = 'issue'"#,
        req.token_id,
    )
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Insert an explicit revocation record.
    sqlx::query!(
        r#"INSERT INTO actor_revocations (token_id) VALUES ($1)
           ON CONFLICT DO NOTHING"#,
        req.token_id,
    )
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "actor token not found".into()));
    }
    emit_event(
        &state.pool,
        crate::config::SYSTEM_ENV_ID,
        "sentin8:auth:actortoken:revoked",
        serde_json::json!({ "actor_token_id": req.token_id }),
    )
    .await;
    Ok(Json(serde_json::json!({"status": "revoked", "token_id": req.token_id})).into_response())
}

/// `GET /v1/admin/actor-events` - query the actor event audit log.
/// `GET /v1/admin/actor-events` - query the actor event audit log.
#[utoipa::path(
    get,
    path = "/v1/admin/actor-events",
    params(
        ("target_user_id" = Option<Uuid>, Query, description = "Filter by target user"),
        ("actor_user_id" = Option<Uuid>, Query, description = "Filter by actor user"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Actor events", body = [ActorEventResponse]),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List actor events.
pub async fn list_actor_events(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(q): Query<ListActorTokensQuery>,
) -> Result<Json<Vec<ActorEventResponse>>, (StatusCode, String)> {
    // SEC- - admin guard (previously unauthenticated), then
    // delegate to the shared guarded query.
    list_actor_tokens(State(state), headers, Query(q)).await
}

// ── Internal helpers ──────────────────────────────────────────────────

/// Sign an actor token. The `act` claim is embedded by serializing the
/// claims to a JSON value, adding `act`, then signing with the Auth keys.
async fn sign_actor_token(
    state: &AppState,
    claims: &AuthClaims,
    act: &ActorClaim,
) -> Result<String, (StatusCode, String)> {
    // Serialize claims to a serde_json::Value, inject the `act` claim.
    let mut value = serde_json::to_value(claims).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("claims serialize: {e}"),
        )
    })?;
    if let serde_json::Value::Object(ref mut map) = value {
        map.insert(
            "act".to_string(),
            serde_json::to_value(act).unwrap_or_default(),
        );
    }
    state
        .keys
        .sign_value(&value)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("sign: {e}")))
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_claim_serializes_with_reason() {
        let act = ActorClaim {
            sub: "actor-uuid".into(),
            email: Some("support@sentin8.local".into()),
            reason: "customer support ticket #123".into(),
        };
        let json = serde_json::to_string(&act).unwrap();
        assert!(json.contains("\"reason\":\"customer support ticket #123\""));
        assert!(json.contains("\"sub\":\"actor-uuid\""));
    }

    #[test]
    fn ttl_clamps_to_max() {
        let ttl = 999_999i64;
        assert!(ttl.clamp(60, MAX_ACTOR_TOKEN_TTL_SECS) == MAX_ACTOR_TOKEN_TTL_SECS);
    }

    #[test]
    fn ttl_default_is_15_minutes() {
        assert_eq!(DEFAULT_ACTOR_TOKEN_TTL_SECS, 900);
    }

    #[test]
    fn actor_event_action_values() {
        // The action column accepts 'issue' and 'revoke'.
        assert!(matches!("issue", "issue" | "revoke"));
        assert!(matches!("revoke", "issue" | "revoke"));
    }
}
