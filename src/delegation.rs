// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Delegation Gateway endpoint
//!
//! `POST /delegate/access-token` - BFF (Delegation Gateway) requests a
//! cert-bound delegated token for cross-env access (platform → env).
//!
//! BFF authenticates with its cert-bound M2M token (cnf-validated). Auth
//! validates `may_act` for the staff user (`act_sub`), downscopes, and mints
//! a delegated token with `token_tp: "delegated"`, `sub: bff-delegator`,
//! `act: {sub, email}`, `cnf` (cert-bound), `aud` (target service).
//!
//! Replaces the old RFC 8693 `sys → org` access-token exchange. The
//! federated-credentials branch of RFC 8693 (external JWT → M2M) is retained
//! in `oauth.rs::handle_federated_token_exchange`.
//!
//! Design: ,
//!

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::handlers::AppState;
use crate::jwt::AuthClaims;

/// Request body for `POST /delegate/access-token`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for delegateaccesstoken.
pub struct DelegateAccessTokenRequest {
    /// The staff user's Auth user ID (the `act.sub`).
    /// The act sub.
    pub act_sub: String,
    /// The staff user's email (for the `act` claim).
    /// The act email.
    pub act_email: Option<String>,
    /// Target env_id for the delegated token.
    #[serde(default)]
    /// env identifier.
    pub env_id: Option<String>,
    /// Requested scopes (space-separated, will be downscoped).
    /// The scope.
    pub scope: String,
    /// Target audience (RFC 8707 resource indicator, e.g. `https://ledger.local.sentin8.dev`).
    /// The audience.
    pub audience: String,
}

/// Response - same shape as OAuth token response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for delegateaccesstoken.
pub struct DelegateAccessTokenResponse {
    /// The access token.
    pub access_token: String,
    /// The token type.
    pub token_type: String,
    /// The expires in.
    pub expires_in: u64,
    /// The scope.
    pub scope: Option<String>,
}

/// `POST /delegate/access-token` - issue a cert-bound delegated token.
///
/// The caller (BFF) presents EITHER its workload certificate (the
/// `bff-delegator` identity - the TLS layer CA-verifies and injects the
/// subject; the boot-loaded registry map grants `sentin8:delegate:read`,
/// auth DESIGN §4.3f; group DESIGN.md §3.1) OR a valid M2M Bearer token
/// with `sentin8:delegate:read` scope. A cert-bound M2M token keeps its
/// `cnf` propagated to the delegated token so it inherits the binding.
/// Handle delegate access token.
#[utoipa::path(
    post,
    path = "/delegate/access-token",
    request_body = DelegateAccessTokenRequest,
    responses(
        (status = 200, description = "Delegated token issued (act claim carried, downscoped)", body = DelegateAccessTokenResponse),
        (status = 400, description = "Malformed request"),
        (status = 401, description = "Caller not authorized to delegate (BFF cert + scope, or M2M bearer with sentin8:delegate:read)"),
    ),
    security(),
    tag = "delegation",
)]
pub async fn delegate_access_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DelegateAccessTokenRequest>,
) -> Result<Json<DelegateAccessTokenResponse>, (StatusCode, String)> {
    // 1a. Certificate-only platform-workload path (auth DESIGN §4.3f):
    // when no Bearer is present but the TLS layer injected a CA-verified
    // client-certificate subject, the registry map resolves the caller.
    // The certificate IS the authentication; the map IS the
    // authorization record (`sentin8:delegate:read` required).
    let has_bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.starts_with("Bearer "));
    let mut sentin8_bff_client_id: Option<String> = None;
    let mut cnf: Option<serde_json::Value> = None;
    if !has_bearer {
        let subject = headers
            .get("x-sentin8-client-cert-subject")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty());
        let Some(subject) = subject else {
            return Err((StatusCode::UNAUTHORIZED, "missing Bearer token".into()));
        };
        let Some(workload) = subject.strip_prefix("m2m-").filter(|w| !w.is_empty()) else {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("certificate CN '{subject}' is not a platform workload identity"),
            ));
        };
        let Some(rec) = state.workload_registry.get(workload).await else {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("workload '{workload}' is not enrolled"),
            ));
        };
        if !rec.enabled {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("workload '{workload}' is disabled"),
            ));
        }
        if !rec.scopes.iter().any(|s| s == "sentin8:delegate:read") {
            return Err((StatusCode::FORBIDDEN, "missing scope: delegate:read".into()));
        }
        // The certificate thumbprint binds the delegated token (RFC 8705
        // `cnf x5t#S256`) - a delegated token minted through the cert
        // path is cert-bound by construction.
        let thumbprint = headers
            .get("x-sentin8-client-cert-thumbprint")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if !thumbprint.is_empty() {
            cnf = Some(serde_json::json!({ "x5t#S256": thumbprint }));
        }
        sentin8_bff_client_id = Some(workload.to_string());
    }

    // 1b. Bearer path - verify the BFF's M2M token.
    let sentin8_bff_client_id = match sentin8_bff_client_id {
        Some(id) => id,
        None => {
            let bearer = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing Bearer token".into()))?;

            // Verify the JWT signature using Auth's own signing keys.
            // This prevents forged tokens - the caller must present a real M2M token
            // issued by this Auth instance.
            let m2m_claims = verify_m2m_token(&state.keys, &state.config, bearer)
                .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid or forged token".into()))?;

            // Must be an M2M token.
            if m2m_claims.get("token_tp").and_then(|v| v.as_str()) != Some("m2m") {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "token must be M2M (client_credentials)".into(),
                ));
            }

            // Must have delegate:read scope.
            let token_scopes: Vec<&str> = m2m_claims
                .get("scope")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .split_whitespace()
                .collect();
            if !token_scopes.contains(&"sentin8:delegate:read") {
                return Err((StatusCode::FORBIDDEN, "missing scope: delegate:read".into()));
            }

            // Extract the BFF client_id from the M2M token's sub.
            let sub = m2m_claims
                .get("sub")
                .and_then(|v| v.as_str())
                .ok_or_else(|| (StatusCode::UNAUTHORIZED, "M2M token missing sub".into()))?
                .to_string();

            // Extract cnf from M2M token and validate against the request's mTLS cert.
            // The cnf claim (x5t#S256) must match the X-Sentin8-Client-Cert-Thumbprint
            // header injected by TLS from the TLS handshake.
            let token_cnf = m2m_claims.get("cnf").cloned();
            if let Some(ref cnf_val) = token_cnf {
                let expected_thumbprint = cnf_val.get("x5t#S256").and_then(|v| v.as_str());
                let presented_thumbprint = headers
                    .get("x-sentin8-client-cert-thumbprint")
                    .and_then(|v| v.to_str().ok());
                match (expected_thumbprint, presented_thumbprint) {
                    (Some(expected), Some(presented)) if expected == presented => {
                        // cnf matches - cert-bound token is valid.
                    }
                    (Some(expected), Some(presented)) => {
                        tracing::warn!(
                            expected = %expected,
                            presented = %presented,
                            "delegation: mTLS cert thumbprint mismatch"
                        );
                        return Err((StatusCode::UNAUTHORIZED, "mTLS certificate mismatch".into()));
                    }
                    (Some(_), None) => {
                        // the token is cert-bound but no mTLS cert
                        // header was presented: the request bypassed TLS or mTLS
                        // wasn't used. This is now a HARD REJECT - a stolen cert-bound
                        // token must be useless. `SENTIN8_AUTH_DEV_NO_MTLS=1` is the
                        // explicit local-dev escape hatch.
                        if std::env::var("SENTIN8_AUTH_DEV_NO_MTLS").is_ok() {
                            tracing::warn!(
                                "delegation: cert-bound token without mTLS header ALLOWED via SENTIN8_AUTH_DEV_NO_MTLS (dev/test only)"
                            );
                        } else {
                            tracing::warn!(
                                "delegation: M2M token has cnf but no mTLS cert header - REJECTED \
                                 (set SENTIN8_AUTH_DEV_NO_MTLS=1 only for local dev without mTLS)"
                            );
                            return Err((
                                StatusCode::UNAUTHORIZED,
                                "certificate-bound token requires the client certificate".into(),
                            ));
                        }
                    }
                    _ => {}
                }
            }
            cnf = token_cnf;
            sub
        }
    };

    // 2. Parse target env.
    let target_env_id: Uuid = req
        .env_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(crate::config::SYSTEM_ENV_ID);

    // 3. Parse the staff user (act_sub) and verify it's a real user.
    let act_user_id: Uuid = Uuid::parse_str(&req.act_sub)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid act_sub".into()))?;

    // Verify act_sub is a row in sentin8_auth_users (not a machine/client UUID).
    //
    // : the pre-mint reads run
    // inside ONE `pool.begin` transaction with
    // `sentin8_set_tenant_context(SYSTEM_ENV_ID)` set on the same connection.
    // On a bare pool connection the FORCE-RLS SELECT policy's
    // `sentin8_context_initialized` gate hides every row - a real platform
    // user resolved to "not a valid user" (400) and every delegated mint
    // failed. Role resolution is platform-level (roles span the user's org
    // envs + the SYSTEM_ENV_ID role catalog), so the context is SYSTEM_ENV_ID,
    // mirroring `fetch_role_scopes`/`has_org_env_access` ( rule 2).
    let mut ctx_tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(crate::config::SYSTEM_ENV_ID)
        .execute(&mut *ctx_tx)
        .await;

    let user_exists: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE id = $1")
        .bind(act_user_id)
        .fetch_optional(&mut *ctx_tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if user_exists.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "act_sub is not a valid user".into(),
        ));
    }

    // 4. may_act check - the staff user must have access to the target
    // env via the RBAC group/role model, unless they have sys:admin
    // scope. The env check prevents cross-env escalation.
    // org_id is resolved from env_id via sentin8_sys_environments (no longer in JWT).
    // This read rides the SAME context transaction.
    let target_org_id: uuid::Uuid =
        sqlx::query_scalar(r#"SELECT org_id FROM sys.environments WHERE id = $1"#)
            .bind(target_env_id)
            .fetch_optional(&mut *ctx_tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .unwrap_or(uuid::Uuid::nil());
    ctx_tx
        .commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let has_admin = check_admin_scope(&state.pool, act_user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    if !has_admin {
        let has_access = crate::handlers::has_org_env_access(
            &state.pool,
            act_user_id,
            target_org_id,
            target_env_id,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if !has_access {
            return Err((
                StatusCode::FORBIDDEN,
                "act_sub does not have access to the target environment".into(),
            ));
        }
    }

    // 5. Downscope: intersect requested scope with the staff user's entitled scopes.
    let staff_scopes = crate::handlers::fetch_role_scopes(&state.pool, act_user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let staff_scope_set: std::collections::HashSet<&str> =
        staff_scopes.iter().map(|s| s.as_str()).collect();
    let delegated_scope: String = req
        .scope
        .split_whitespace()
        .filter(|s| staff_scope_set.contains(*s))
        .collect::<Vec<_>>()
        .join(" ");

    // 6. Build the delegated token.
    let act = serde_json::json!({
        "sub": req.act_sub,
        "email": req.act_email,
    });

    let claims = AuthClaims::delegated(
        &state.config.issuer,
        &sentin8_bff_client_id,
        &delegated_scope,
        target_env_id.to_string(),
        Duration::seconds(state.config.access_token_ttl_secs as i64),
        &act,
        cnf,
        Some(req.audience.clone()),
    );

    let token = state
        .keys
        .sign(&claims)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 7. Audit log.
    // tenant context on the same connection (design ).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(target_env_id)
        .execute(&mut *conn)
        .await;
    let _ = sqlx::query!(
        r#"INSERT INTO actor_events
             (id, actor_user_id, target_user_id, token_id, scope, reason, action, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, 'delegation', $7)"#,
        Uuid::new_v4(),
        act_user_id,
        act_user_id,
        Uuid::parse_str(&claims.jti).unwrap_or_else(|_| Uuid::new_v4()),
        &delegated_scope,
        &format!("Delegation Gateway: env {}", target_env_id),
        claims.expires_at(),
    )
    .execute(&mut *conn)
    .await;
    let _ = conn.commit().await;

    tracing::info!(
        actor = %req.act_sub,
        sentin8_bff_client = %sentin8_bff_client_id,
        target_org = %target_org_id,
        target_env = %target_env_id,
        audience = %req.audience,
        scope = %delegated_scope,
        "Delegation Gateway: delegated token issued",
    );

    Ok(Json(DelegateAccessTokenResponse {
        access_token: token,
        token_type: "Bearer".into(),
        expires_in: state.config.access_token_ttl_secs,
        scope: if delegated_scope.is_empty() {
            None
        } else {
            Some(delegated_scope)
        },
    }))
}

/// Check if a user has the `sentin8:sys:admin` scope (bypasses membership check).
async fn check_admin_scope(pool: &sqlx::PgPool, user_id: Uuid) -> Result<bool, String> {
    let scopes = crate::handlers::fetch_role_scopes(pool, user_id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(scopes.iter().any(|s| s == "sentin8:sys:admin"))
}

/// Verify an M2M JWT using Auth's own signing keys.
/// This prevents forged tokens - the caller must present a real M2M token
/// issued by this Auth instance.
fn verify_m2m_token(
    keys: &crate::jwks::SigningKeys,
    config: &crate::config::AuthConfig,
    token: &str,
) -> Option<serde_json::Value> {
    // Verify the ML-DSA-65 signature and decode claims.
    let claims = keys.verify_raw(token).ok()?;
    if claims.get("iss")?.as_str()? != config.issuer {
        return None;
    }
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
        if chrono::Utc::now().timestamp() > exp {
            return None;
        }
    }
    Some(claims)
}
