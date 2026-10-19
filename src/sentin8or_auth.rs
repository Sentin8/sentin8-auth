// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Sentin8or API authentication and authorization - tenant-scoped guards.
//!
//! "Sentin8or" is the term for platform operators who manage the
//! platform through Dash. Only users with admin scopes can access Dash
//! admin endpoints - non-admin users are rejected.
//!
//! This module guards all Dash admin/management endpoints with the same
//! pattern as Sys's `auth::verify_token` + `authorize_org`:
//!
//! 1. Verify the Bearer token's signature using Auth's own signing keys.
//! 2. Reject non-admin tokens - only users with admin scopes can access Dash.
//! 3. Extract the target env from the token's `env_id` claim. org_id is
//! resolved from env_id via `sentin8_sys_environments`. For tokens issued
//! via the Delegation Gateway (BFF), the claims carry the target env.
//! For direct platform tokens, the claims carry SystemEnvID.
//! 4. Verify the caller has access to the target org (via the RBAC group/role
//! model - `has_org_access` checks sentin8_auth_user_roles + sentin8_auth_group_members)
//! unless the caller has the `sentin8:sys:admin` scope (platform admin bypass).
//! Note: if the token was issued via the Delegation Gateway, the may_act
//! check was already done at delegation time - this is defense-in-depth.
//!
//! ## Scoping rules
//!
//! - **Platform admin (sys:admin)**: users with `sentin8:sys:admin` scope bypass
//! the membership check. Other admin users must have a role or group in
//! the target org (checked via `has_org_access` - RBAC group/role model).
//! The token's `env_id` claim determines the data scope.

use axum::http::{HeaderMap, StatusCode};
use uuid::Uuid;

use crate::config::{AuthConfig, SYSTEM_ENV_ID, SYSTEM_ORG_ID};
use crate::handlers::AppState;
use crate::jwks::SigningKeys;
use crate::jwt::AuthClaims;

/// Verified token + tenant context for a sentin8or (admin) request.
pub struct Sentin8orAuthContext {
    /// The verified claims of the caller's token.
    pub claims: AuthClaims,
    /// The org the caller is managing (resolved from the token's `env_id` claim
    /// via `sentin8_sys_environments`). For delegated tokens, this is the target
    /// org. For direct platform tokens, this is SystemOrgID.
    pub org_id: Uuid,
    /// The env the caller is managing (from the token's `env_id` claim).
    /// For delegated tokens, this is the target env. For direct platform tokens,
    /// this is SystemEnvID.
    pub env_id: Uuid,
}

impl Sentin8orAuthContext {
    /// Check if the caller is a platform admin - permission-based, not
    /// identity-based. Returns true if the token has the `sentin8:sys:admin`
    /// scope (granted via `org:sys:admins` group → `sentin8:org:sys:admin` →
    /// `sentin8:sys:admin` nesting). See auth design
    pub fn is_platform_admin(&self) -> bool {
        self.claims
            .scope
            .split_whitespace()
            .any(|s| s == "sentin8:sys:admin")
    }

    /// The caller's user id (parsed from the `sub` claim).
    pub fn user_id(&self) -> Uuid {
        Uuid::parse_str(&self.claims.sub).unwrap_or(Uuid::nil())
    }
}

/// Access mode for the read/write scope split (SEC-).
///
/// - `Read` endpoints (GET) accept `sentin8:auth:admin:read` OR `sentin8:auth:admin:write`
///
/// plus the platform-admin scopes.
/// - `Write` endpoints (POST/PUT/DELETE/PATCH) accept `sentin8:auth:admin:write`
///
/// plus the platform-admin scopes - a read-only operator can no longer
/// mutate admin resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    /// Read endpoints (GET): `read` OR `write` scope accepted.
    Read,
    /// Write endpoints (POST/PUT/DELETE/PATCH): `write` scope required.
    Write,
}

impl AccessMode {
    /// Infer the access mode from the HTTP method.
    pub fn from_method(method: &str) -> Self {
        match method {
            "GET" | "HEAD" | "OPTIONS" => AccessMode::Read,
            _ => AccessMode::Write,
        }
    }
}

/// Resolve a certificate-only platform-workload caller (auth DESIGN
/// §4.3f; group DESIGN.md §3.1). The TLS layer CA-verifies the presented
/// Acme client certificate and injects
/// `X-Sentin8-Client-Cert-Subject/-Thumbprint` (client-supplied copies
/// stripped). The boot-loaded registry map (`m2m:workloads`) is the
/// authorization record: scopes + vertical + `enabled`.
///
/// Returns `None` when no certificate identity is present (the caller
/// falls through to the Bearer path). Enrolled-but-disabled or
/// scope-insufficient identities fail closed with 401/403.
async fn resolve_certificate_context(
    state: &AppState,
    headers: &HeaderMap,
    target_env_id: Option<&str>,
    mode: AccessMode,
) -> Result<Option<Sentin8orAuthContext>, (StatusCode, String)> {
    let Some(subject) = headers
        .get("x-sentin8-client-cert-subject")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    else {
        return Ok(None); // no client certificate presented
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

    // The SAME scope/mode gate the Bearer path runs - against the map's
    // granted scopes. `auth-sys` carries `sentin8:sys:memberships:admin`
    // (an is_platform_admin class grant); the Shield policy check below
    // still decides the precise action.
    let scopes: Vec<&str> = rec.scopes.iter().map(|s| s.as_str()).collect();
    let is_platform_admin = scopes.iter().any(|s| {
        *s == "sentin8:dash:admin"
            || *s == "sentin8:sys:admin"
            || *s == "sentin8:sys:org:admin"
            || *s == "sentin8:sys:env:admin"
            || *s == "sentin8:sys:memberships:admin"
    });
    let can_read = is_platform_admin
        || scopes.contains(&"sentin8:auth:admin:read")
        || scopes.contains(&"sentin8:auth:admin:write");
    let can_write = is_platform_admin || scopes.contains(&"sentin8:auth:admin:write");
    let has_admin_scope = match mode {
        AccessMode::Read => can_read,
        AccessMode::Write => can_write,
    };
    if !has_admin_scope {
        return Err((
            StatusCode::FORBIDDEN,
            "certificate workload lacks the admin scope for this endpoint".to_string(),
        ));
    }

    // The Shield policy gate - same target as the Bearer path, fed the
    // synthetic workload context (the map's scopes).
    let now = chrono::Utc::now().timestamp();
    let sdk_claims = sentin8::auth::client::VerifiedClaims {
        sub: format!("m2m-{workload}"),
        iss: state.config.issuer.clone(),
        aud: String::new(),
        jti: "cert".to_string(),
        iat: now,
        exp: i64::MAX,
        token_tp: "m2m".to_string(),
        scope: rec.scopes.join(" "),
        env_id: Some(
            target_env_id
                .filter(|s| !s.is_empty())
                .unwrap_or(&sentin8::config::SYSTEM_ENV_ID.to_string())
                .to_string(),
        ),
        email: None,
        act: None,
        vertical: Some(rec.vertical.clone()),
        service_type: Some(rec.service_type.clone()),
    };
    crate::policy::require_policy(
        &state.policy,
        &sentin8::auth::client::AuthContext {
            claims: sdk_claims.clone(),
            workload: Some(sentin8::auth::client::WorkloadIdentity {
                workload: workload.to_string(),
                scopes: rec.scopes.clone(),
                vertical: Some(rec.vertical.clone()),
                service_type: Some(rec.service_type.clone()),
                thumbprint: headers
                    .get("x-sentin8-client-cert-thumbprint")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string(),
            }),
        },
        headers,
        sentin8::shield::EvalTarget::new(match mode {
            AccessMode::Read => "sentin8:auth:admin:read",
            AccessMode::Write => "sentin8:auth:admin:write",
        }),
    )
    .await?;

    // Resolve the target env (same contract as the Bearer path:
    // provisioning callers pass `x-sentin8-target-env-id`).
    let env_id = target_env_id
        .filter(|s| !s.is_empty())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(sentin8::config::SYSTEM_ENV_ID);
    let org_id = if env_id == SYSTEM_ENV_ID {
        SYSTEM_ORG_ID
    } else {
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        crate::admin::set_tenant_context(&mut tx, env_id).await;
        let resolved = sqlx::query_scalar(r#"SELECT org_id FROM sys.environments WHERE id = $1"#)
            .bind(env_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        resolved.unwrap_or(SYSTEM_ORG_ID)
    };

    // Synthetic local claims mirroring the token shape (request-scoped;
    // nothing persists or caches them).
    let claims = crate::jwt::AuthClaims {
        sub: format!("m2m-{workload}"),
        iss: state.config.issuer.clone(),
        aud: None,
        jti: "cert".to_string(),
        iat: now,
        exp: i64::MAX,
        token_tp: "m2m".to_string(),
        scope: rec.scopes.join(" "),
        env_id: Some(env_id.to_string()),
        email: None,
        client_id: Some(workload.to_string()),
        grant_id: None,
        act: None,
        cnf: None,
        vertical: Some(rec.vertical.clone()),
        service_type: Some(rec.service_type.clone()),
    };
    Ok(Some(Sentin8orAuthContext {
        claims,
        org_id,
        env_id,
    }))
}

/// Verify the Bearer token and resolve the target tenant scope.
///
/// This is the auth equivalent of Sys's `verify_token` + `authorize_org`.
/// All Dash admin/management list/get/create/update/delete handlers should
/// call this at the top of the handler.
pub async fn require_sentin8or_access(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Sentin8orAuthContext, (StatusCode, String)> {
    require_sentin8or_access_with_env(state, headers, None).await
}

/// Same as `require_sentin8or_access` but accepts an optional `target_env_id`
/// from the `target_env_id` query param (forwarded by BFF proxy). When present,
/// this overrides the token's env_id - the BFF-proxied request targets a
/// specific env, but the token carries SYSTEM_ENV_ID.
pub async fn require_sentin8or_access_with_env(
    state: &AppState,
    headers: &HeaderMap,
    target_env_id: Option<&str>,
) -> Result<Sentin8orAuthContext, (StatusCode, String)> {
    require_sentin8or_access_mode(state, headers, target_env_id, AccessMode::Read).await
}

/// Same as [`require_sentin8or_access_with_env`] but requires the
/// `sentin8:auth:admin:write` scope (mutating endpoints, SEC-).
pub async fn require_sentin8or_access_write(
    state: &AppState,
    headers: &HeaderMap,
    target_env_id: Option<&str>,
) -> Result<Sentin8orAuthContext, (StatusCode, String)> {
    require_sentin8or_access_mode(state, headers, target_env_id, AccessMode::Write).await
}

/// Same as [`require_sentin8or_access_with_env`] with an explicit access
/// mode (SEC-). Read handlers pass `AccessMode::Read`;
/// mutating handlers pass `AccessMode::Write`.
pub async fn require_sentin8or_access_mode(
    state: &AppState,
    headers: &HeaderMap,
    target_env_id: Option<&str>,
    mode: AccessMode,
) -> Result<Sentin8orAuthContext, (StatusCode, String)> {
    // Certificate-only platform-workload path (auth DESIGN §4.3f; group
    // DESIGN.md §3.1): when no Bearer is present but the TLS layer
    // injected a CA-verified client-certificate subject, the registry
    // map resolves the workload - the certificate IS the
    // authentication, the map IS the authorization record. The token
    // model is retired for platform workloads; without this path the
    // sys provisioning delegation (`auth-sys` certificate) 401s and
    // org access-model provisioning fails (the e2e incident). The
    // scope/mode/policy checks below run IDENTICALLY on the map's
    // granted scopes.
    if !headers.contains_key(axum::http::header::AUTHORIZATION)
        && !headers.contains_key("authorization")
    {
        if let Some(ctx) = resolve_certificate_context(state, headers, target_env_id, mode).await? {
            return Ok(ctx);
        }
    }

    // 1. Extract and verify the Bearer token.
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "missing Authorization header".to_string(),
            )
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "expected Bearer token".to_string(),
        )
    })?;

    let claims = verify_token(&state.keys, &state.config, token)?;

    // SEC- - actor-token revocation check. A token whose `jti`
    // appears in `actor_revocations` is refused even though its
    // signature/expiry are valid.
    if is_actor_token_revoked(&state.pool, &claims.jti).await {
        return Err((
            StatusCode::UNAUTHORIZED,
            "token has been revoked".to_string(),
        ));
    }

    // 2. Accept either:
    // - platform tokens (sentin8or direct call), OR
    // - delegated tokens issued via the Delegation Gateway (carries
    // the target env in the claims).
    // Both carry a `sub` (user id) and a tenant claim (`env_id`).
    // Customer tokens from sign-in are rejected - those have a
    // different `sub` semantics (subject user) and no `sentin8or` intent.
    //
    // Authorization is scope-based: the caller must have an admin scope.
    // `sentin8:dash:admin` is the platform-wide admin scope (platform admins via
    // sys-admin nesting). For delegated tokens issued via the Delegation
    // Gateway, BFF requests only the service-specific admin scopes
    // (e.g. `sentin8:auth:admin:read`), so we also accept those. Customer
    // tokens never carry any admin scope, so they're rejected.
    //
    // SEC- - the read/write split: `sentin8:auth:admin:read` alone does
    // NOT authorize mutating endpoints.
    let scopes: Vec<&str> = claims.scope.split_whitespace().collect();
    let is_platform_admin = scopes.iter().any(|s| {
        *s == "sentin8:dash:admin"
            || *s == "sentin8:sys:admin"
            || *s == "sentin8:sys:org:admin"
            || *s == "sentin8:sys:env:admin"
    });
    let can_read = is_platform_admin
        || scopes.contains(&"sentin8:auth:admin:read")
        || scopes.contains(&"sentin8:auth:admin:write");
    let can_write = is_platform_admin || scopes.contains(&"sentin8:auth:admin:write");
    let has_admin_scope = match mode {
        AccessMode::Read => can_read,
        AccessMode::Write => can_write,
    };
    if !has_admin_scope {
        return Err((
            StatusCode::FORBIDDEN,
            match mode {
                AccessMode::Read => {
                    "missing admin scope - not authorized for Dash admin endpoints".to_string()
                }
                AccessMode::Write => {
                    "missing auth:admin:write scope - not authorized for mutating admin endpoints"
                        .to_string()
                }
            },
        ));
    }
    // ── Step 5 - the ONLY access gate (design ).
    // The JWT scope snapshot above is only the coarse pre-filter; the Shield
    // scope-mirror set over LIVE effective scopes decides. The headers pass
    // through so the raw Bearer drives live identity resolution. The local
    // `AuthClaims` converts to the SDK `VerifiedClaims` the runtime consumes.
    let sdk_claims = sentin8::auth::client::VerifiedClaims {
        sub: claims.sub.clone(),
        iss: claims.iss.clone(),
        aud: claims.aud.clone().unwrap_or_default(),
        jti: claims.jti.clone(),
        iat: claims.iat,
        exp: claims.exp,
        token_tp: claims.token_tp.clone(),
        scope: claims.scope.clone(),
        env_id: claims.env_id.clone(),
        email: claims.email.clone(),
        act: claims.act.clone(),
        vertical: claims.vertical.clone(),
        service_type: claims.service_type.clone(),
    };
    crate::policy::require_policy(
        &state.policy,
        &sentin8::auth::client::AuthContext {
            claims: sdk_claims,
            workload: None,
        },
        headers,
        sentin8::shield::EvalTarget::new(match mode {
            AccessMode::Read => "sentin8:auth:admin:read",
            AccessMode::Write => "sentin8:auth:admin:write",
        }),
    )
    .await?;
    // 3. Resolve the target env.
    // Resolve env_id from target_env_id query param (BFF proxy).
    // No fallback - if target_env_id is missing, the request fails.
    // Auth is always env-scoped; there is no org-level auth.
    let env_id = target_env_id
        .filter(|s| !s.is_empty())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "missing target_env_id - auth is env-scoped".to_string(),
            )
        })?;

    // Resolve org_id from env_id via sentin8_sys_environments.
    //
    // The lookup needs the caller's tenant context on the SAME connection
    // (auth design §6.3): `sys.environments` is FORCE-RLS'd on
    // (context_initialized, env) and a bare-pool SELECT runs context-less -
    // the row is invisible and org_id silently defaulted to SystemOrgID,
    // which then failed every downstream org check with 403 "not a member".
    let org_id = if env_id == SYSTEM_ENV_ID {
        SYSTEM_ORG_ID
    } else {
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        crate::admin::set_tenant_context(&mut tx, env_id).await;
        let resolved = sqlx::query_scalar(r#"SELECT org_id FROM sys.environments WHERE id = $1"#)
            .bind(env_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        resolved.unwrap_or(SYSTEM_ORG_ID)
    };

    // 4. Access check - only for tokens targeting a real org
    // (not SystemOrgID). Uses the RBAC group/role model. Users with
    // `sentin8:sys:admin` scope bypass.
    //
    // Delegated tokens (Delegation Gateway, `token_tp: "delegated"`) carry
    // the target env in their claims. If the token is delegated,
    // the Delegation Gateway already validated RBAC access - accept.
    let has_admin_scope = claims
        .scope
        .split_whitespace()
        .any(|s| s == "sentin8:sys:admin");
    let is_delegated = claims.token_tp == "delegated";
    // M2M service tokens (`token_tp: "m2m"`) are machine identities: their
    // authorization is the SCOPE gate above (e.g. `sentin8:auth:admin:write`
    // for the provisioning surface) - never the user-membership probe, which
    // would only test a client_id against org groups and always fail. The
    // acting user, where one exists, rides the body of the call.
    let is_m2m = claims.token_tp == "m2m";
    if !has_admin_scope && !is_delegated && !is_m2m && org_id != SYSTEM_ORG_ID {
        let user_id = Uuid::parse_str(&claims.sub).unwrap_or(Uuid::nil());
        let has_access = crate::handlers::has_org_access(&state.pool, user_id, org_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if !has_access {
            return Err((
                StatusCode::FORBIDDEN,
                "not a member of this organization".to_string(),
            ));
        }
    }

    Ok(Sentin8orAuthContext {
        claims,
        org_id,
        env_id,
    })
}

/// Check whether a token `jti` has been revoked as an actor token
/// (SEC- - `actor_revocations`).
async fn is_actor_token_revoked(pool: &sqlx::PgPool, jti: &str) -> bool {
    if jti.is_empty() {
        return false;
    }
    sqlx::query_scalar(
        r#"SELECT EXISTS(
               SELECT 1 FROM actor_revocations WHERE token_id::text = $1
           )"#,
    )
    .bind(jti)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .unwrap_or(false)
}

/// SEC- - backstop check for the route-guard middleware:
/// verify a Bearer token's signature/issuer/expiry and confirm it carries
/// any admin scope. Returns `Ok` when the token may proceed to the
/// per-handler guard (which performs the full tenant resolution).
pub fn verify_bearer_admin(state: &AppState, token: &str) -> Result<(), String> {
    let claims = verify_token(&state.keys, &state.config, token).map_err(|(_status, msg)| msg)?;
    let has_admin_scope = claims.scope.split_whitespace().any(|s| {
        s == "sentin8:dash:admin"
            || s == "sentin8:auth:admin:read"
            || s == "sentin8:auth:admin:write"
            || s == "sentin8:sys:admin"
            || s == "sentin8:sys:org:admin"
            || s == "sentin8:sys:env:admin"
    });
    if !has_admin_scope {
        return Err("missing admin scope".to_string());
    }
    Ok(())
}

/// Verify a JWT using Auth's own signing keys.
fn verify_token(
    keys: &SigningKeys,
    config: &AuthConfig,
    token: &str,
) -> Result<AuthClaims, (StatusCode, String)> {
    // Verify the ML-DSA-65 signature and decode claims.
    let claims = keys.verify(token).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            format!("token verification failed: {e}"),
        )
    })?;

    // Validate issuer and expiry (previously done by jsonwebtoken::Validation).
    if claims.iss != config.issuer {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!(
                "token issuer mismatch: expected {}, got {}",
                config.issuer, claims.iss
            ),
        ));
    }

    // Check expiry.
    let now = chrono::Utc::now().timestamp();
    if now > claims.exp {
        return Err((StatusCode::UNAUTHORIZED, "token expired".to_string()));
    }

    Ok(claims)
}
