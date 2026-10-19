// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! HTTP handlers for Auth's frontend and admin APIs.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bcrypt::{hash as bcrypt_hash, verify as bcrypt_verify, DEFAULT_COST};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::config::{AuthConfig, SYSTEM_ENV_ID, SYSTEM_ORG_ID};
use crate::events::emit_event;
use crate::jwks::SigningKeys;
use crate::jwt::AuthClaims;
use crate::sessions::Session;

#[derive(Clone)]
/// app state.
pub struct AppState {
    /// The config.
    pub config: Arc<AuthConfig>,
    /// The keys.
    pub keys: Arc<SigningKeys>,
    /// The pool.
    pub pool: PgPool,
    /// Shield engine (Phase ): step 5 gates the ADMIN
    /// API surface. Protocol endpoints (token issuance, JWKS) stay exempt by
    /// design - the identity plane must not depend on its own policy table
    /// (circular risk, policy design note).
    /// The policy.
    pub policy: Arc<crate::policy::Engine>,
    /// auth DESIGN §4.3f: the boot-loaded workload registry map -
    /// the authorization record for certificate-only platform-workload
    /// calls (sys's provisioning delegation presents the `auth-sys`
    /// certificate; scopes ride the map, not a token).
    pub workload_registry: sentin8::auth::workload_registry::WorkloadMap,
    /// Shared Sentin8:Policy admin surface.
    /// The admin.
    pub admin: sentin8::shield::admin::SharedAdminState,
}

// ── Sign-in ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for signin.
pub struct SignInRequest {
    /// The email.
    pub email: String,
    /// The password.
    pub password: String,
}

#[derive(Serialize, utoipa::ToSchema)]
/// Response payload for signin.
pub struct SignInResponse {
    /// user identifier.
    pub user_id: Uuid,
    /// session identifier.
    pub session_id: Uuid,
    /// Session token (also set as the `__session` HttpOnly cookie).
    /// Included in the JSON body so the Flutter Web UI can pass it
    /// to `POST /oauth/authorize/continue` (the cookie is HttpOnly
    /// and cannot be read by JavaScript).
    /// The token.
    pub token: String,
    /// The email.
    pub email: String,
    /// The first name.
    pub first_name: Option<String>,
    /// The last name.
    pub last_name: Option<String>,
}

/// Sign in.
#[utoipa::path(
    post,
    path = "/v1/sign-in",
    request_body = SignInRequest,
    responses(
        (status = 200, description = "Session established (also set as the `__session` HttpOnly cookie)", body = SignInResponse),
        (status = 400, description = "Email and password are required"),
        (status = 401, description = "Unknown email or wrong password"),
        (status = 429, description = "Sign-in rate limit (bot protection) exceeded"),
    ),
    security(),
    tag = "auth",
)]
pub async fn sign_in(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SignInRequest>,
) -> Result<Response, (StatusCode, String)> {
    if req.email.is_empty() || req.password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "email and password are required".into(),
        ));
    }

    //bot protection: per-IP + per-email rate limit.
    let ip = crate::bot_protection::extract_client_ip(&headers);
    crate::bot_protection::check_signin_rate(&state, &ip, &req.email).await?;

    // Resolve the current tenant from the request's Host / TLS headers.
    // The same email can exist as a different user in each tenant, so the
    // lookup MUST be scoped to env_id - otherwise a sign-in on
    // iFintech would silently match an iBank user with the same email.
    let (org_id, env_id) = resolve_tenant_from_headers(&state.pool, &headers).await;
    tracing::info!(
        resolved_org_id = %org_id,
        resolved_env_id = %env_id,
        email = %req.email,
        "auth: sign_in resolved tenant context"
    );

    // Look up the user by email, scoped to the current tenant.
    // RLS is enabled on sentin8_auth_users, so we must set the tenant context
    // on the connection before querying. We use a transaction so the
    // transaction-local GUCs set by sentin8_set_tenant_context persist
    // across queries on the same connection.
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;

    let user = sqlx::query!(
        r#"SELECT id, env_id, email, password_hash,
                  first_name, last_name, status, email_verified
             FROM users
            WHERE email = $1
              AND env_id = $2"#,
        req.email.to_lowercase(),
        env_id,
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Commit (or rollback) to release the connection.
    let _ = tx.commit().await;

    let user = match user {
        Some(u) => u,
        None => {
            // SEC- - timing-safe rejection: run a dummy bcrypt
            // verify so the nonexistent-user path costs the same as the
            // wrong-password path. Without this, a timing side channel
            // enumerates registered emails (bcrypt ≈ 100ms vs ~0ms).
            const DUMMY_HASH: &str = "$2b$12$LJ3m4sMV0uV1ZpT1YyV1qOELQwXG5uYyY3nZcQcQK5cC4qP5oP5uS";
            let _ = bcrypt_verify(&req.password, DUMMY_HASH);
            return Err((StatusCode::UNAUTHORIZED, "invalid credentials".into()));
        }
    };

    //account lockout check.
    crate::bot_protection::check_account_lockout(&state, user.id).await?;

    if user.status != "active" {
        return Err((StatusCode::FORBIDDEN, "account is not active".into()));
    }

    // Verify bcrypt password hash.
    let valid = user
        .password_hash
        .as_ref()
        .map(|h| bcrypt_verify(&req.password, h).unwrap_or(false))
        .unwrap_or(false);
    if !valid {
        // EUDI. - app-password fallback: the presented credential may
        // be one of the user's scoped-down device credentials. A match
        // issues a DOWNSCOPED token (whitelist ∩ role scopes) with
        // token_tp = "app_password" and no session (short-lived by
        // design; devices re-present the credential).
        match crate::app_passwords::try_app_password_sign_in(
            &state.pool,
            &state.config,
            &state.keys,
            user.id,
            user.env_id,
            &user.email,
            &req.password,
        )
        .await
        {
            Ok(Some((access_token, scope))) => {
                return Ok(Json(serde_json::json!({
                    "status": "ok",
                    "token_tp": "app_password",
                    "scope": scope,
                    "access_token": access_token,
                }))
                .into_response());
            }
            Ok(None) => {}
            Err((code, msg)) => return Err((code, msg)),
        }
        //record the failed attempt (may lock the account).
        let _ = crate::bot_protection::record_failed_signin(&state, user.id).await;
        return Err((StatusCode::UNAUTHORIZED, "invalid credentials".into()));
    }

    //reset the failed-attempt counter on success.
    let _ = crate::bot_protection::reset_failed_signins(&state, user.id).await;

    // Create a session. SEC- - run inside a transaction with the
    // tenant context on the same connection (RLS insert under the app role).
    let token_id = Uuid::new_v4().to_string();
    let mut session_tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(user.env_id)
        .execute(&mut *session_tx)
        .await;
    let session = Session::create(
        &mut *session_tx,
        user.id,
        user.env_id,
        &token_id,
        None,
        Duration::seconds(state.config.session_ttl_secs as i64),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = session_tx.commit().await;

    //MFA (TOTP) enforcement. If the user has an active TOTP
    // factor, hold the session pending MFA verification: create a challenge
    // and return `status: "needs_mfa"` with the `pending_token_id` instead of
    // a fully-activated session cookie. The client submits the TOTP code to
    // `POST /v1/mfa/verify` with `pending_token_id` to activate the session.
    if let Some(factor_id) = crate::mfa::user_requires_mfa(&state.pool, user.id).await {
        let _challenge_id =
            crate::mfa::create_signin_challenge(&state.pool, user.id, factor_id, &token_id)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        return Ok(Json(serde_json::json!({
            "status": "needs_mfa",
            "pending_token_id": token_id,
            "factor_id": factor_id,
        }))
        .into_response());
    }

    // Issue an access token - merge role permissions into scope .
    let role_scopes = fetch_role_scopes(&state.pool, user.id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let scope = merge_scopes("openid profile email", &role_scopes);

    let claims = AuthClaims::access(
        &state.config.issuer,
        user.id,
        &scope,
        user.env_id,
        Some(&user.email),
        Duration::seconds(state.config.access_token_ttl_secs as i64),
    );
    let _access_token = state
        .keys
        .sign(&claims)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resp_body = SignInResponse {
        user_id: user.id,
        session_id: session.id,
        token: token_id.clone(),
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
    };

    let cookie_domain =
        crate::sessions::cookie_domain_from_headers(&headers, &state.config.sentin8_domain);
    Ok((
        StatusCode::OK,
        [("set-cookie", session.cookie(&cookie_domain))],
        Json(resp_body),
    )
        .into_response())
}

// ── Sign-up ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for signup.
pub struct SignUpRequest {
    /// The email.
    pub email: String,
    /// The password.
    pub password: String,
    #[serde(default)]
    /// The first name.
    pub first_name: Option<String>,
    #[serde(default)]
    /// The last name.
    pub last_name: Option<String>,
}

/// Sign up.
#[utoipa::path(
    post,
    path = "/v1/sign-up",
    request_body = SignUpRequest,
    responses(
        (status = 200, description = "User created and signed in (session cookie set)", body = SignInResponse),
        (status = 400, description = "Invalid email or password"),
        (status = 409, description = "Email already registered for this environment"),
    ),
    security(),
    tag = "auth",
)]
pub async fn sign_up(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SignUpRequest>,
) -> Result<Response, (StatusCode, String)> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let env_hdr = headers
        .get("x-sentin8-env-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let hostname_hdr = headers
        .get("x-sentin8-hostname")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    tracing::info!(
        %host,
        env_id = %env_hdr,
        hostname = %hostname_hdr,
        email = %req.email,
        "auth: sign_up received request"
    );
    if req.email.is_empty() || req.password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "email and password are required".into(),
        ));
    }
    if req.password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            "password must be at least 8 characters".into(),
        ));
    }

    // Resolve org/env from TLS headers .
    let (org_id, env_id) = resolve_tenant_from_headers(&state.pool, &headers).await;
    tracing::info!(
        resolved_org_id = %org_id,
        resolved_env_id = %env_id,
        email = %req.email,
        "auth: sign_up resolved tenant context"
    );

    let email = req.email.to_lowercase();
    let password_hash = bcrypt_hash(&req.password, DEFAULT_COST)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let user_id = Uuid::new_v4();
    // SEC- - set the tenant context on this connection via a
    // transaction, then run the INSERT on the SAME connection. Without the
    // context, FORCE ROW LEVEL SECURITY blocks the insert for the app role
    // (the 500 sign-up failures under the NOBYPASSRLS role).
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let result = sqlx::query!(
        r#"INSERT INTO users
             (id, env_id, email, password_hash, first_name, last_name, status, email_verified)
           VALUES ($1, $2, $3, $4, $5, $6, 'active', false)
           RETURNING id"#,
        user_id,
        env_id,
        email,
        password_hash,
        req.first_name,
        req.last_name,
    )
    .fetch_one(&mut *tx)
    .await;
    // Commit the user insert (and context) - errors roll back atomically.
    let user_id = match result {
        Ok(row) => {
            let _ = tx.commit().await;
            tracing::info!(
                user_id = %row.id,
                %org_id,
                %env_id,
                email = %email,
                "auth: sign_up user created successfully"
            );
            row.id
        }
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
            let _ = tx.rollback().await;
            tracing::warn!(email = %email, "auth: sign_up email already registered");
            return Err((StatusCode::CONFLICT, "email already registered".into()));
        }
        Err(e) => {
            let _ = tx.rollback().await;
            return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
        }
    };

    // Auto-assign the new user to the "sentin8:sys:users" role so they get
    // basic scopes like dash:org:create (needed to create their first org).
    // Best-effort - if the role doesn't exist, the user just gets no extra
    // scopes (they can still sign in).
    //
    // AUTH-4 (org-creation e2e): the previous autocommit form
    // ran on a pool connection with NO tenant context and silently inserted
    // 0 rows under FORCE RLS - self-service users got no baseline scopes and
    // Shield denied /v1/bootstrap + org-create. The context is
    // transaction-local : both statements must run in ONE explicit
    // transaction on the SAME connection. Track the outcome so a zero-
    // closure sign-up is visible (the warn below).
    let mut closure_provisioned = false;
    let role_assign = async {
        let mut tx = state.pool.begin().await.map_err(|e| e.to_string())?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        let res = sqlx::query(
            r#"INSERT INTO user_roles (role_id, user_id, env_id)
               SELECT r.id, $1, r.env_id
               FROM roles r
               WHERE r.name = 'sentin8:sys:users'
                 AND NOT EXISTS (
                   SELECT 1 FROM user_roles ur
                   WHERE ur.role_id = r.id AND ur.user_id = $1
                 )"#,
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok::<u64, String>(res.rows_affected())
    }
    .await;
    match role_assign {
        Ok(n) if n > 0 => {
            closure_provisioned = true;
        }
        Ok(_) => {
            tracing::warn!(user_id = %user_id, "auth: sign_up sentin8:sys:users role not assigned (role absent or already member)");
        }
        Err(e) => {
            tracing::warn!(error = %e, user_id = %user_id, "auth: sign_up failed to assign sentin8:sys:users role");
        }
    }

    //auto-add new env users to all customer-mode app
    // instance groups for this org/env. Each installed app instance has a
    // group named `sentin8:app:{instance_id}` . Best-effort: log
    // errors but don't fail the sign-up.
    if env_id != SYSTEM_ENV_ID {
        closure_provisioned |= auto_add_to_app_groups(&state.pool, user_id, env_id).await;
    }

    // AUTH-4: a sign-up that provisions NO closure (no app-group membership
    // AND no direct role) bricks the user - their token carries only the
    // OIDC baseline and Shield denies every platform read. Silent zero-scope
    // sign-ups are a defect, not an acceptable degrade (design ).
    if !closure_provisioned {
        tracing::warn!(
            user_id = %user_id,
            %env_id,
            "auth: sign_up provisioned NO permission closure - user will deny on every platform endpoint (check roles + app instance groups)"
        );
    }

    //- emit user.created event to Bus outbox.
    emit_event(
        &state.pool,
        env_id,
        "sentin8:auth:user:created",
        serde_json::json!({
            "user_id": user_id,
            "email": email,
        }),
    )
    .await;

    // Create a session for the new user. SEC- - same-connection
    // tenant context: reuse a transaction so the RLS INSERT succeeds under
    // the app role.
    let token_id = Uuid::new_v4().to_string();
    let mut session_tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *session_tx)
        .await;
    let session = Session::create(
        &mut *session_tx,
        user_id,
        env_id,
        &token_id,
        None,
        Duration::seconds(state.config.session_ttl_secs as i64),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = session_tx.commit().await;

    let resp_body = SignInResponse {
        user_id,
        session_id: session.id,
        token: token_id.clone(),
        email,
        first_name: req.first_name,
        last_name: req.last_name,
    };

    let cookie_domain =
        crate::sessions::cookie_domain_from_headers(&headers, &state.config.sentin8_domain);
    Ok((
        StatusCode::CREATED,
        [("set-cookie", session.cookie(&cookie_domain))],
        Json(resp_body),
    )
        .into_response())
}

// ── Session ────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
/// session information.
pub struct SessionInfo {
    /// user identifier.
    pub user_id: Uuid,
    /// session identifier.
    pub session_id: Uuid,
    /// env identifier.
    pub env_id: Uuid,
    /// expires time.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Session token id - the CSRF header value (SEC-) for
    /// cookie-authenticated SPA mutations after a page reload. Same-origin
    /// exposure only, identical to the sign-in response body. Optional so
    /// older internal callers parsing this struct stay compatible.
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The session token.
    pub session_token: Option<String>,
    /// Operator email (greeting on the device-approval page). Optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The email.
    pub email: Option<String>,
}

/// Fetch session.
#[utoipa::path(
    get,
    path = "/v1/session",
    responses(
        (status = 200, description = "The caller's session", body = SessionInfo),
        (status = 401, description = "No session or the session expired"),
    ),
    security(),
    tag = "auth",
)]
pub async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionInfo>, (StatusCode, String)> {
    let token_id = match extract_session_token(&headers) {
        Some(t) => t,
        None => return Err((StatusCode::UNAUTHORIZED, "no session".into())),
    };

    let session = Session::find_by_token(&state.pool, &token_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match session {
        Some(s) if s.is_valid() => {
            // Same-origin SPA use only (SEC-): the token id is the CSRF
            // header value for cookie-authenticated mutations after a page
            // reload (the sign-in response body is not in flight anymore).
            // Same exposure as the sign-in response body - never a new
            // secret. email rides along so pages can greet the operator.
            let email = sqlx::query!(r#"SELECT email FROM users WHERE id = $1"#, s.user_id,)
                .fetch_optional(&state.pool)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .map(|u| u.email);
            Ok(Json(SessionInfo {
                user_id: s.user_id,
                session_id: s.id,
                env_id: s.env_id,
                expires_at: s.expires_at,
                session_token: Some(s.token_id.clone()),
                email,
            }))
        }
        _ => Err((
            StatusCode::UNAUTHORIZED,
            "session invalid or expired".into(),
        )),
    }
}

// ── Sign-out ────────────────────────────────────────────────────────────

/// Sign out.
#[utoipa::path(
    post,
    path = "/v1/sign-out",
    responses(
        (status = 200, description = "Session revoked"),
        (status = 403, description = "Missing X-Sentin8-CSRF header for a cookie-authenticated call"),
    ),
    security(),
    tag = "auth",
)]
pub async fn sign_out(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token_id) = extract_session_token(&headers) {
        // SEC- - mutating session endpoint: CSRF-gated (Bearer exempt).
        if crate::handlers::check_csrf(&headers, &token_id).is_err() {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "X-Sentin8-CSRF header required"})),
            )
                .into_response();
        }
        let _ = Session::revoke(&state.pool, &token_id).await;
    }
    let cookie_domain =
        crate::sessions::cookie_domain_from_headers(&headers, &state.config.sentin8_domain);
    (
        StatusCode::OK,
        [("set-cookie", Session::clear_cookie(&cookie_domain))],
        Json(serde_json::json!({"status": "signed out"})),
    )
        .into_response()
}

// ── Branding ────────────────────────────────────────────────────────────

///resolve tenant from TLS-injected headers first, falling
/// back to hostname-based DB lookup only when TLS headers are absent
/// (non-proxied direct calls, e.g. local dev).
///
///hostname-based lookup is gated behind the
/// `SENTIN8_AUTH_ALLOW_HOSTNAME_FALLBACK` env var (default: enabled for backward
/// compatibility during the TLS migration). Once all callers route through
/// TLS, set `SENTIN8_AUTH_ALLOW_HOSTNAME_FALLBACK=0` to disable the legacy path.
/// Resolve tenant from headers.
pub async fn resolve_tenant_from_headers(pool: &PgPool, headers: &HeaderMap) -> (Uuid, Uuid) {
    // 1. Prefer TLS-injected `X-Sentin8-Env-Id` header. `org_id` is resolved
    // from `env_id` via `sentin8_sys_environments` when needed.
    let sentin8_tls_env = headers
        .get(sentin8::middleware::context::HEADER_ENV_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .and_then(|s| Uuid::parse_str(s).ok());

    tracing::info!(
        sentin8_tls_env = ?sentin8_tls_env,
        "auth: resolve_tenant_from_headers checking tls headers"
    );

    if let Some(env_id) = sentin8_tls_env {
        // Resolve org_id from env_id via DB lookup.
        let org_id =
            sqlx::query_scalar::<_, Uuid>(r#"SELECT org_id FROM sys.environments WHERE id = $1"#)
                .bind(env_id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten()
                .unwrap_or(SYSTEM_ORG_ID);
        tracing::info!(%org_id, %env_id, "auth: resolve_tenant_from_headers using tls headers");
        return (org_id, env_id);
    }

    // 2. Legacy fallback: hostname-based DB lookup (disabled when
    // SENTIN8_AUTH_ALLOW_HOSTNAME_FALLBACK=0).
    let allow_hostname_fallback = std::env::var("SENTIN8_AUTH_ALLOW_HOSTNAME_FALLBACK")
        .unwrap_or_else(|_| "1".to_string())
        != "0";
    if !allow_hostname_fallback {
        return (SYSTEM_ORG_ID, SYSTEM_ENV_ID);
    }

    //emit a deprecation warning when the hostname fallback
    // is used. This code path will be removed once all callers route through
    // TLS and the migration is validated.
    tracing::warn!(
        "hostname-based tenant resolution fallback is unsafe; \
         set SENTIN8_AUTH_ALLOW_HOSTNAME_FALLBACK=0 to disable and route through TLS"
    );

    let host = headers
        .get(sentin8::middleware::context::HEADER_HOSTNAME)
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get(axum::http::header::HOST)
                .and_then(|v| v.to_str().ok())
        })
        .unwrap_or("");
    tracing::info!(%host, "auth: resolve_tenant_from_headers falling back to hostname lookup");
    resolve_tenant_from_hostname(pool, host).await
}

/// Legacy hostname-based tenant resolution.
///
/// Queries `sentin8_sys_app_instances` to find the org/env for the given hostname.
/// Falls back to System org/env when the table doesn't exist or no match is found.
/// Resolve tenant from hostname.
pub async fn resolve_tenant_from_hostname(pool: &PgPool, hostname: &str) -> (Uuid, Uuid) {
    let result = sqlx::query!(
        r#"SELECT org_id, env_id
           FROM app_instances
           WHERE hostname = $1 AND status = 'active'
           LIMIT 1"#,
        hostname,
    )
    .fetch_optional(pool)
    .await;

    match result {
        Ok(Some(row)) => {
            tracing::info!(%hostname, org_id = %row.org_id, env_id = %row.env_id, "auth: hostname lookup found instance");
            (row.org_id, row.env_id)
        }
        _ => {
            tracing::warn!(%hostname, "auth: hostname lookup no match, falling back to System Org/Env");
            (SYSTEM_ORG_ID, SYSTEM_ENV_ID)
        }
    }
}

///auto-add a new user to all customer-mode app instance
/// groups for the given org/env. Each installed app instance has a group
/// named `sentin8:app:{instance_id}` ( - the name embeds the instance
/// UUID that app setup_instance provisions and the BFF app-group gate
/// checks; the display-name snake_case form is retired - its drift caused
/// AUTH-3). Best-effort: logs errors but never fails the
/// caller (sign-up or SSO).
///
/// AUTH-4 (org-creation e2e): both statements below ran on pool
/// connections with NO tenant context and silently inserted 0 rows under
/// FORCE RLS - the `sys.app_instances` read (the role's search_path is
/// `auth, public`) and the membership INSERT. The context is
/// transaction-local : every statement runs in an explicit
/// transaction with `sentin8_set_tenant_context(env_id)` set on the SAME
/// connection.
///
/// Returns `true` when at least one membership row was provisioned - the
/// sign-up caller uses this to warn when the user got NO permission closure
/// (design ).
pub(crate) async fn auto_add_to_app_groups(pool: &PgPool, user_id: Uuid, env_id: Uuid) -> bool {
    // DBX §6.6a (auth DESIGN invariant 12): the customer-mode instance
    // enumeration rides Sentin8:App's OWNER API - auth holds no grant on
    // `sys.app_instances` (the sys.* grants are retired; the former direct
    // read failed RLS grantless and provisioned NO closure on every
    // customer-env sign-up). auth DESIGN §4.3f: the
    // `sentin8:auth` CERTIFICATE is the identity - the cert-presenting
    // transport authenticates at App's TLS layer; the registry map
    // authorizes `sentin8:app:instances:read`.
    //
    // Fail-soft without the platform CA (`try_platform_ca_path`): the
    // closure provisioning is BEST-EFFORT (this fn's doc) - a missing CA
    // (bare `cargo test` / dev harness without captain's env propagation)
    // degrades to "closure not provisioned" + warning, never a sign-up
    // panic.
    let app_url = sentin8::config::Sentin8Config::from_env().sentin8_app_url();
    let instances: Option<Vec<Uuid>> = (async {
        let issuer = sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer();
        let ca_cert_path = sentin8::auth::m2m::try_platform_ca_path()?;
        let cert =
            sentin8::auth::m2m::ensure_workload_certificate(&issuer, "sentin8:auth", &ca_cert_path)
                .await
                .ok()?;
        let mtls = sentin8::middleware::mtls::MtlsConfig::new(
            &cert.ca_cert_path,
            &cert.cert_path,
            &cert.key_path,
        );
        let http = sentin8::middleware::mtls::build_mtls_client(&mtls).ok()?;
        let url = format!(
            "{}/v1/app/instances/customer-mode?env_id={}",
            app_url.trim_end_matches('/'),
            env_id
        );
        let resp = http.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            tracing::warn!(status = %resp.status(), %env_id,
                "auth: customer-mode instance discovery failed (owner API)");
            return None;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        Some(
            body.get("instances")?
                .as_array()?
                .iter()
                .filter_map(|v| v.get("instance_id").and_then(|x| x.as_str()))
                .filter_map(|s| uuid::Uuid::parse_str(s).ok())
                .collect(),
        )
    })
    .await;

    let instances = match instances {
        Some(rows) => rows,
        None => {
            tracing::warn!(error = "instance discovery failed", %env_id,
                "auth: failed to query app instances for auto-membership (owner API)");
            return false;
        }
    };

    let mut provisioned = false;
    for instance_id in instances {
        let group_name = format!("sentin8:app:{instance_id}");

        // Find the group and add the user as a member. The group catalog
        // is env-scoped - match on env_id ( fix; the previous
        // `g.org_id` filter referenced a nonexistent column). Context-first
        // write : the context rides the same transaction as the
        // INSERT.
        let result = async {
            let mut tx = pool.begin().await?;
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                .bind(env_id)
                .execute(&mut *tx)
                .await;
            let res = sqlx::query(
                r#"INSERT INTO group_members (group_id, user_id, env_id)
                   SELECT g.id, $2, g.env_id
                     FROM groups g
                    WHERE g.env_id = $1 AND g.name = $3
                   ON CONFLICT (group_id, user_id) DO NOTHING"#,
            )
            .bind(env_id)
            .bind(user_id)
            .bind(&group_name)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok::<_, sqlx::Error>(res)
        }
        .await;

        match result {
            Ok(res) => {
                if res.rows_affected() > 0 {
                    provisioned = true;
                    tracing::info!(user_id = %user_id, group = %group_name, "auth: auto-added user to app instance group");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, group = %group_name, "auth: failed to auto-add user to app instance group");
            }
        }
    }
    if provisioned {
        // Identity-cache invalidation (auth DESIGN §7.1): the sign-up just
        // provisioned access - every service's policy runtime must drop its
        // cached pre-grant identity NOW, not after the 30s TTL. SYSTEM-env
        // `policy` row; the tenant env to sweep rides the payload.
        if let Ok(mut tx) = pool.begin().await {
            crate::events::emit_identity_invalidation_tx(
                &mut tx,
                env_id,
                user_id,
                "sentin8:auth:membership:created",
            )
            .await;
            if let Err(e) = tx.commit().await {
                tracing::warn!(error = %e, "auth: invalidation row commit failed (degrades to 30s TTL)");
            }
        }
    }
    provisioned
}

/// Handle branding.
/// Merged org→env branding for the hosted Auth UI (env overrides org per-field).
#[utoipa::path(
    get,
    path = "/v1/branding",
    responses(
        (status = 200, description = "The merged branding payload for the resolved tenant", body = crate::dtos::BrandingResponse),
        (status = 401, description = "No valid tenant context could be resolved from the request"),
    ),
    security(),
    tag = "auth",
)]
pub async fn branding(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<crate::dtos::BrandingResponse> {
    //resolve tenant from TLS headers (fallback to hostname).
    let (org_id, env_id) = resolve_tenant_from_headers(&state.pool, &headers).await;

    // Query merged org+env branding from sentin8_sys_branding (mirrors the App
    // server's `fetch_merged_branding` logic - env overrides org per-field,
    // non-empty wins). Falls back to safe defaults when the sentin8_sys_branding
    // table is absent (e.g. fresh dev DB) so the hosted UI still renders.
    let b = fetch_merged_branding(&state.pool, org_id, env_id)
        .await
        .unwrap_or_default();
    let org_name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM sys.organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten()
            .filter(|s: &String| !s.is_empty());

    Json(crate::dtos::BrandingResponse {
        organization_name: org_name,
        logo_url: b.logo_url,
        logo_icon_url: b.logo_icon_url,
        primary_color: b.primary_color,
        accent_color: b.accent_color,
        theme_mode: Some(b.theme_mode.unwrap_or_else(|| "dark".to_string())),
        font_family: b.font_family,
        custom_css: b.custom_css,
        sign_in_text: b.sign_in_text,
    })
}

/// Merged org→env branding from `sentin8_sys_branding`. Env overrides org per-field
/// (non-empty wins). Used by the `GET /v1/branding` handler to drive the
/// hosted Auth UI theme without a separate round-trip to Sys.
#[derive(Debug, Clone, Default)]
struct MergedBranding {
    logo_url: Option<String>,
    logo_icon_url: Option<String>,
    primary_color: Option<String>,
    accent_color: Option<String>,
    font_family: Option<String>,
    theme_mode: Option<String>,
    custom_css: Option<String>,
    sign_in_text: Option<String>,
}

/// Fetch merged org→env branding from `sentin8_sys_branding`. Returns `Ok(default)`
/// (all-`None`) when the table does not exist so the hosted UI still renders
/// with the platform defaults.
async fn fetch_merged_branding(
    pool: &PgPool,
    org_id: Uuid,
    env_id: Uuid,
) -> Result<MergedBranding, sqlx::Error> {
    // Org-level branding (scope='org', env_id IS NULL).
    let org_row = sqlx::query(
        r#"SELECT logo_url, logo_icon_url, primary_color, accent_color, font_family, theme_mode, custom_css, sign_in_text
             FROM branding
            WHERE org_id = $1 AND scope = 'org' AND env_id IS NULL"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await?;
    // Env-level branding (scope='env', env_id = $2).
    let env_row = sqlx::query(
        r#"SELECT logo_url, logo_icon_url, primary_color, accent_color, font_family, theme_mode, custom_css, sign_in_text
             FROM branding
            WHERE org_id = $1 AND env_id = $2 AND scope = 'env'"#,
    )
    .bind(org_id)
    .bind(env_id)
    .fetch_optional(pool)
    .await?;
    let pick = |org: &Option<sqlx::postgres::PgRow>,
                env: &Option<sqlx::postgres::PgRow>,
                col: &str|
     -> Option<String> {
        env.as_ref()
            .and_then(|r| r.try_get::<Option<String>, _>(col).ok())
            .flatten()
            .or_else(|| {
                org.as_ref()
                    .and_then(|r| r.try_get::<Option<String>, _>(col).ok())
                    .flatten()
            })
    };
    Ok(MergedBranding {
        logo_url: pick(&org_row, &env_row, "logo_url"),
        logo_icon_url: pick(&org_row, &env_row, "logo_icon_url"),
        primary_color: pick(&org_row, &env_row, "primary_color"),
        accent_color: pick(&org_row, &env_row, "accent_color"),
        font_family: pick(&org_row, &env_row, "font_family"),
        theme_mode: pick(&org_row, &env_row, "theme_mode"),
        custom_css: pick(&org_row, &env_row, "custom_css"),
        sign_in_text: pick(&org_row, &env_row, "sign_in_text"),
    })
}

// ── Health ──────────────────────────────────────────────────────────────

/// Handle health.
/// Liveness (captain monitor payload: status, service, version, build).
#[utoipa::path(
    get,
    path = "/v1/health",
    responses(
        (status = 200, description = "The service is live", body = sentin8::middleware::health::LiveHealth),
    ),
    security(),
    tag = "meta",
)]
pub async fn health() -> Json<serde_json::Value> {
    let mut payload = serde_json::json!({"status": "ok", "version": sentin8::build_info::id(), "build": sentin8::build_info::build_hash()});
    if let Some(n) = sentin8::middleware::traffic_counter::process_active_connections() {
        payload["active_connections"] = serde_json::json!(n);
    }
    Json(payload)
}

// ── Consent accounts (FDX UX Guidelines "Select Accounts") ───────

/// Query params for `GET /v1/auth/consent/accounts` - fetch the customer's
/// accounts at this Data Provider so the consent screen can show
/// them for selection.
#[derive(Debug, serde::Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The consentaccountsquery type.
pub struct ConsentAccountsQuery {
    /// The session token (from the sign-in flow) to authenticate the request.
    /// The session token.
    pub session_token: String,
    /// The user_id (from the sign-in response).
    /// user identifier.
    pub user_id: Uuid,
}

/// `GET /v1/auth/consent/accounts` - fetch the authenticated customer's accounts
/// from consent data providers registered via `sentin8-cli vertical enroll`.
///
/// This endpoint is called by the Auth Flutter consent page (served on the
/// provider's auth domain, e.g. `auth.ibank.local`) to fetch the customer's
/// accounts at this Data Provider. The accounts are displayed with
/// checkboxes so the customer can select which ones to share (FDX UX
/// Guidelines "Select Accounts").
///
/// Auth looks up consent data providers from the `sentin8_consent_providers`
/// table (populated at runtime by `sentin8-cli vertical enroll`). For each
/// provider, auth mints a short-lived JWT with the registered scope and
/// calls the registered service via its platform domain URL.
/// No vertical service URLs, paths, or scopes are hardcoded in auth.
/// Handle consent accounts.
#[utoipa::path(
    get,
    path = "/v1/auth/consent/accounts",
    params(ConsentAccountsQuery),
    responses(
        (status = 200, description = "The consent flow's customer accounts (per scope selection)", body = crate::dtos::ConsentAccountsResponse),
        (status = 401, description = "Session invalid or expired"),
    ),
    security(),
    tag = "auth",
)]
pub async fn consent_accounts(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<ConsentAccountsQuery>,
) -> Result<Json<crate::dtos::ConsentAccountsResponse>, (StatusCode, String)> {
    // Verify the session is valid.
    let session = Session::find_by_token(&state.pool, &q.session_token)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let session = match session {
        Some(s) if s.is_valid() && s.user_id == q.user_id => s,
        _ => return Err((StatusCode::UNAUTHORIZED, "invalid session".into())),
    };

    // Look up consent data providers from the registry.
    // Multiple domains can register providers for the same feature/data_type.
    let providers = sqlx::query(
        r#"SELECT service_type, platform_domain_key, endpoint, scope, response_key
             FROM consent_providers
            WHERE feature = 'fdx' AND data_type = 'accounts'"#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("consent providers query: {e}"),
        )
    })?;

    if providers.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            "no consent data providers registered for fdx/accounts".into(),
        ));
    }

    let cfg = sentin8::config::Sentin8Config::from_env();
    let http = reqwest::Client::builder().build().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("http client: {e}"),
        )
    })?;

    let mut all_data: Vec<serde_json::Value> = Vec::new();

    for row in &providers {
        let service_type: String = row.get("service_type");
        let platform_domain_key: String = row.get("platform_domain_key");
        let endpoint: String = row.get("endpoint");
        let scope: String = row.get("scope");
        let resp_key: String = row.get("response_key");

        // Build the service URL from the platform domain key (e.g.
        // "bank8:ledger" → "https://bank8-ledger.ops.sys.sentin8.local").
        let base_url = format!("https://{}", cfg.platform_domain(&platform_domain_key));

        // Mint a short-lived JWT (60s) with the registered scope.
        let claims = AuthClaims::access(
            &state.config.issuer,
            session.user_id,
            &scope,
            session.env_id,
            None,
            Duration::seconds(60),
        );
        let service_token = state.keys.sign(&claims).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("token sign: {e}"),
            )
        })?;

        tracing::info!(
            service = %service_type,
            url = %format!("{}{}", base_url, endpoint),
            scope = %scope,
            "auth: consent_accounts calling registered provider"
        );

        let resp = http
            .get(format!("{}{}", base_url, endpoint))
            .bearer_auth(&service_token)
            .send()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("{service_type}: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(service = %service_type, status = %status, body = %body, "auth: consent provider returned error");
            continue;
        }

        let body: serde_json::Value = resp.json().await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("{service_type} decode: {e}"),
            )
        })?;

        // Extract the data array from the registered response key.
        if let Some(arr) = body.get(&resp_key).and_then(|v| v.as_array()) {
            all_data.extend(arr.clone());
        } else if let Some(obj) = body.get(&resp_key) {
            all_data.push(obj.clone());
        }
    }

    Ok(Json(crate::dtos::ConsentAccountsResponse {
        accounts: all_data,
    }))
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Fetch all scopes for a user by resolving the full Role/Group graph
/// . Returns a deduplicated list of scope strings.
/// Collect every scope granted to a user, resolving the full Role/Group
/// graph:
///
/// 1. Direct roles: rows in `sentin8_auth_user_roles` for the user.
/// 2. Group roles: roles attached to any group the user is a member of
///
/// (`sentin8_auth_group_members` → `sentin8_auth_group_roles`).
/// 3. Nested roles: `sentin8_auth_role_nesting` lets a parent Role inherit the
/// scopes of its child Roles; we expand the closure of every role
/// reachable from the user's direct + group roles.
///
/// The final scope set is the union of `permissions` over all roles in
/// that closure. Uses `sqlx::query` (not the `query!` macro) to avoid
/// compile-time DB validation against tables that may not exist at macro
/// expansion time.
/// Fetch role scopes.
pub async fn fetch_role_scopes(pool: &PgPool, user_id: Uuid) -> Result<Vec<String>, sqlx::Error> {
    // (F1 activation) - the RBAC tables are RLS'd; under a
    // NOBYPASSRLS per-service role the read requires a tenant context.
    // Role resolution is platform-level (a user's roles span their org's
    // envs + the SYSTEM_ENV_ID role catalog), so the context is SYSTEM_ENV_ID
    // on this helper's own transaction ( rule 2: same-connection
    // context).
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;
    let rows = sqlx::query(
        r#"WITH RECURSIVE
        -- Roles assigned directly to the user.
        direct_roles AS (
            SELECT r.id FROM roles r
            JOIN user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = $1
        ),
        -- Roles attached to any group the user is a member of. The TABLE is
        -- schema-qualified - under WITH RECURSIVE an unqualified `group_roles`
        -- resolves to the CTE itself (self-reference ⇒ malformed recursion).
        grp_roles AS (
            SELECT gr.role_id AS id
            FROM group_members gm
            JOIN auth.group_roles gr ON gr.group_id = gm.group_id
            WHERE gm.user_id = $1
        ),
        -- Seed roles = direct ∪ group-assigned.
        seed_roles AS (
            SELECT id FROM direct_roles
            UNION ALL
            SELECT id FROM grp_roles
        ),
        -- Recursive closure over role nesting (parent → child).
        role_closure AS (
            SELECT id FROM seed_roles
            UNION ALL
            SELECT child.id
            FROM roles child
            JOIN role_nesting nest ON nest.child_role_id = child.id
            JOIN role_closure parent ON parent.id = nest.parent_role_id
        )
        SELECT DISTINCT unnest(r.permissions) AS scope
        FROM roles r
        JOIN role_closure c ON c.id = r.id"#,
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;

    let scopes: Vec<String> = rows
        .into_iter()
        .filter_map(|r| r.try_get::<Option<String>, _>("scope").ok().flatten())
        .collect();
    Ok(scopes)
}

/// Check if a user has access to a target org via the RBAC group/role model.
///
/// Returns `true` if the user has ANY role or group membership in the target
/// org. This replaces the old `sentin8_sys_memberships` table lookup - the same
/// information now lives in Auth's RBAC system (groups like
/// `org:{slug}:owners`, roles like `org-admin`, etc.).
///
/// A user has org access if:
/// - They have a direct role assignment (`sentin8_auth_user_roles`) for a role
///
/// scoped to the target org, OR
/// - They are a member of a group (`sentin8_auth_group_members`) that is scoped
///
/// to the target org.
///
/// Platform admins (users with `sentin8:sys:admin` scope) should bypass this check
/// - the caller is responsible for checking that before calling this function.
/// Handle has org access.
pub async fn has_org_access(
    pool: &PgPool,
    user_id: Uuid,
    org_id: Uuid,
) -> Result<bool, sqlx::Error> {
    if org_id == crate::config::SYSTEM_ORG_ID {
        return Ok(false);
    }
    // - platform-level membership probe: SYSTEM_ENV_ID context
    // on this helper's own transaction ( rule 2).
    //
    // RLS alignment (auth design §6.2): the sys-realm org groups
    // (`sentin8:org:{org_id}:owners/admins/viewers`, created by sys's
    // provision_org_access_tx at SYSTEM_ENV_ID) are org-scoped BY NAME -
    // the row's `env_id` is the provisioning realm, not the org. The old
    // predicate joined `sys.environments` on `g.env_id`/`r.env_id` and
    // compared `e.org_id` - that match can only hit env-scoped rows
    // (realms other than SYSTEM_ENV_ID), so org-level owners/admins were
    // never visible and every direct (non-admin) caller was denied with
    // "not a member of this organization". The probe now matches the
    // platform convention directly: org-embedded group names + the
    // org-scoped role vocabulary.
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;
    let row: Option<bool> = sqlx::query_scalar(
        r#"SELECT EXISTS(
            SELECT 1 FROM group_members gm
            JOIN groups g ON g.id = gm.group_id
            WHERE gm.user_id = $1
              AND g.env_id = sentin8_current_env_id()
              AND (g.name = 'sentin8:org:' || $2::text || ':owners'
                   OR g.name = 'sentin8:org:' || $2::text || ':admins'
                   OR g.name = 'sentin8:org:' || $2::text || ':viewers')
            UNION
            SELECT 1 FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = $1
              AND r.env_id = sentin8_current_env_id()
              AND (r.name = 'sentin8:org:owner'
                   OR r.name = 'sentin8:org:admin'
                   OR r.name = 'sentin8:org:viewer')
        )"#,
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.unwrap_or(false))
}

/// Like `has_org_access`, but also checks that the user has a role or group
/// scoped to the specific `env_id`. Used by the Delegation Gateway to
/// prevent cross-env escalation within the same org.
///
/// Org-admin roles have `env_id = SYSTEM_ENV_ID` (they are org-level, not
/// env-level) - they pass the env check automatically. Platform admins
/// should be checked by the caller before calling this function.
/// Handle has org env access.
pub async fn has_org_env_access(
    pool: &PgPool,
    user_id: Uuid,
    org_id: Uuid,
    env_id: Uuid,
) -> Result<bool, sqlx::Error> {
    if org_id == crate::config::SYSTEM_ORG_ID {
        return Ok(false);
    }
    // If env_id is the System Env, fall back to org-level check (org-admin
    // roles are scoped to System Env).
    if env_id == crate::config::SYSTEM_ENV_ID {
        return has_org_access(pool, user_id, org_id).await;
    }
    // - same-connection tenant context ( rule 2): the probe
    // spans the env's rows + the SYSTEM_ENV_ID org-admin role, so the
    // context is the target env (RLS policies on roles/
    // groups are env-scoped; the SYSTEM_ENV_ID role rows are visible
    // to any env context via the role-catalog read path below).
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;
    let row: Option<bool> = sqlx::query_scalar(
        r#"SELECT EXISTS(
            -- Env-scoped role (direct match, env realm)
            SELECT 1 FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = $1 AND r.env_id = $3
              AND r.name IN ('sentin8:env:admin', 'sentin8:env:viewer')
            UNION
            -- Env-scoped group membership (env realm)
            SELECT 1 FROM group_members gm
            JOIN groups g ON g.id = gm.group_id
            WHERE gm.user_id = $1 AND g.env_id = $3
              AND (g.name = 'sentin8:env:' || $3::text || ':admins'
                   OR g.name = 'sentin8:env:' || $3::text || ':viewers')
            UNION
            -- Org-level access at the system realm (sentin8:org:* names
            -- embed the org UUID - prov-org-access_tx at SYSTEM_ENV_ID)
            SELECT 1 FROM group_members gm
            JOIN groups g ON g.id = gm.group_id
            WHERE gm.user_id = $1
              AND g.env_id = $4
              AND (g.name = 'sentin8:org:' || $2::text || ':owners'
                   OR g.name = 'sentin8:org:' || $2::text || ':admins'
                   OR g.name = 'sentin8:org:' || $2::text || ':viewers')
            UNION
            -- Org-scoped role vocabulary at the system realm
            SELECT 1 FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = $1 AND r.env_id = $4
              AND r.name IN ('sentin8:org:owner', 'sentin8:org:admin', 'sentin8:org:viewer')
        )"#,
    )
    .bind(user_id)
    .bind(org_id)
    .bind(env_id)
    .bind(crate::config::SYSTEM_ENV_ID)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.unwrap_or(false))
}

/// Mint a delegated token for a cross-service proxy hop (RFC 8693 `act`
/// semantics). The caller's USER access token is verified with auth's own
/// keys, and the minted token carries:
/// - `sub` = the auth-sys delegator client_id (the proxy's M2M identity),
/// - `act.sub` = the original user (Sys's org-membership check resolves the
///   acting user from `act.sub` - a plain M2M sub is a client_id, not a user),
/// - `token_tp: "delegated"`, the requested scope, and the user's `env_id`
///   (tenant binding preserved).
///
/// The delegator identity is `auth-sys` - the cert-bound M2M workload the
/// invitation/membership proxy registers. TTL is 5 minutes: the token is a
/// single-hop credential, never persisted client-side.
pub(crate) async fn exchange_for_delegated(
    user_token: &str,
    requested_scope: &str,
) -> Result<String, String> {
    let cfg = AuthConfig::from_env();
    let pool = sentin8::config::pg_pool::connect(&cfg.database_url)
        .await
        .map_err(|e| format!("pool: {e}"))?;
    let keys = SigningKeys::load_or_generate(&pool)
        .await
        .map_err(|e| format!("signing keys: {e}"))?;
    // Verify the caller's user token (signature + issuer + expiry) - the
    // delegated mint is only as trustworthy as this check.
    // Verify the caller's user token (signature + issuer + expiry) - the
    // delegated mint is only as trustworthy as this check. The Bearer may
    // itself be a delegated token (Dash → BFF proxy): in that case the
    // ACTING user is `act.sub`, not `sub` (which is the delegator's
    // client_id - a hex string that parses as a UUID, so the plain parse
    // would silently mint a delegated token naming a client as the user).
    let claims = keys
        .verify(user_token)
        .map_err(|e| format!("verify: {e}"))?;
    if claims.iss != cfg.issuer {
        return Err("issuer mismatch".into());
    }
    if claims.exp < chrono::Utc::now().timestamp() {
        return Err("token expired".into());
    }
    let user_id = claims
        .act
        .as_ref()
        .and_then(|a| a.get("sub").and_then(|v| v.as_str()))
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .or_else(|| match claims.token_tp.as_str() {
            "access" | "id" | "refresh" => uuid::Uuid::parse_str(&claims.sub).ok(),
            _ => None,
        })
        .ok_or_else(|| "subject is not a user id".to_string())?;
    let env_id = claims
        .env_id
        .as_ref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .unwrap_or(crate::config::SYSTEM_ENV_ID);

    let delegator = "auth-sys";
    let act = serde_json::json!({ "sub": user_id.to_string() });
    let delegated = crate::jwt::AuthClaims::delegated(
        &cfg.issuer,
        delegator,
        requested_scope,
        env_id.to_string(),
        chrono::Duration::seconds(300),
        &act,
        None,
        None,
    );
    keys.sign(&delegated).map_err(|e| format!("sign: {e}"))
}

/// Merge base scopes with role scopes, deduplicating.
/// Handle merge scopes.
pub fn merge_scopes(base: &str, role_scopes: &[String]) -> String {
    let mut all: Vec<&str> = base.split_whitespace().collect();
    for s in role_scopes {
        if !all.contains(&s.as_str()) {
            all.push(s);
        }
    }
    all.join(" ")
}

/// Resolve every scope granted to an OAuth client (service principal),
/// for the `client_credentials` grant. Unions the client's own
/// `sentin8_auth_oauth_clients.scopes` with the `permissions` of every Role
/// assigned to the client (`sentin8_auth_client_roles`), resolved recursively
/// over `sentin8_auth_role_nesting`. See auth design.
/// Fetch client role scopes.
pub async fn fetch_client_role_scopes(
    pool: &PgPool,
    client_db_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    // - same-connection tenant context ( rule 2): client
    // role resolution spans the client's env + the SYSTEM_ENV_ID role
    // catalog (nesting closure); SYSTEM_ENV_ID context covers both.
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;
    let rows = sqlx::query(
        r#"WITH RECURSIVE
        -- Roles assigned directly to the client.
        seed_roles AS (
            SELECT r.id FROM roles r
            JOIN client_roles cr ON cr.role_id = r.id
            WHERE cr.client_id = $1
        ),
        -- Recursive closure over role nesting (parent → child).
        role_closure AS (
            SELECT id FROM seed_roles
            UNION ALL
            SELECT child.id
            FROM roles child
            JOIN role_nesting nest ON nest.child_role_id = child.id
            JOIN role_closure parent ON parent.id = nest.parent_role_id
        )
        SELECT DISTINCT unnest(r.permissions) AS scope
        FROM roles r
        JOIN role_closure c ON c.id = r.id"#,
    )
    .bind(client_db_id)
    .fetch_all(&mut *tx)
    .await?;

    let role_scopes: Vec<String> = rows
        .into_iter()
        .filter_map(|r| r.try_get::<Option<String>, _>("scope").ok().flatten())
        .collect();

    // Union with the client's own registered scopes.
    let own_scopes: Vec<String> = sqlx::query_scalar::<_, String>(
        r#"SELECT unnest(scopes) FROM oauth_clients WHERE id = $1"#,
    )
    .bind(client_db_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;

    let mut all: Vec<String> = Vec::new();
    for s in own_scopes.into_iter().chain(role_scopes) {
        if !all.contains(&s) {
            all.push(s);
        }
    }
    Ok(all)
}

/// Resolved Role names for a user (direct roles ∪ group-assigned roles,
/// expanded over sentin8_auth_role_nesting). Used by `/oauth/userinfo` and the
/// admin `GET /v1/admin/users/{id}/roles` introspection endpoint.
/// Handle user role names.
pub async fn user_role_names(pool: &PgPool, user_id: Uuid) -> Result<Vec<String>, sqlx::Error> {
    // ( rule 2) - the RBAC tables are RLS'd; under a
    // NOBYPASSRLS per-service role the read requires a tenant context.
    // Role resolution is platform-level (a user's roles span their org's
    // envs + the SYSTEM_ENV_ID role catalog), so the context is
    // SYSTEM_ENV_ID on this helper's own transaction. A bare-pool read here
    // silently returns 0 rows under FORCE RLS (:
    // userinfo reported roles:[] for every user and Shield denied).
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;
    let rows = sqlx::query(
        r#"WITH RECURSIVE direct_roles AS (
                SELECT r.id, r.name FROM roles r
                JOIN user_roles ur ON ur.role_id = r.id
                WHERE ur.user_id = $1
            ),
            -- TABLE schema-qualified: under WITH RECURSIVE an unqualified
            -- `group_roles` resolves to the CTE (self-reference ⇒ malformed
            -- recursion). CTE renamed to grp_roles.
            grp_roles AS (
                SELECT gr.role_id AS id, r.name
                FROM group_members gm
                JOIN auth.group_roles gr ON gr.group_id = gm.group_id
                JOIN roles r ON r.id = gr.role_id
                WHERE gm.user_id = $1
            ),
            seed_roles AS (
                SELECT id, name FROM direct_roles
                UNION ALL
                SELECT id, name FROM grp_roles
            ),
            role_closure AS (
                SELECT id, name FROM seed_roles
                UNION ALL
                SELECT child.id, child.name
                FROM roles child
                JOIN role_nesting nest ON nest.child_role_id = child.id
                JOIN role_closure parent ON parent.id = nest.parent_role_id
            )
            SELECT DISTINCT name FROM role_closure ORDER BY name"#,
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| r.try_get::<Option<String>, _>("name").ok().flatten())
        .collect())
}

/// Direct Group names a user is a member of (not transitive). Used by
/// `/oauth/userinfo` and `GET /v1/admin/users/{id}/groups`.
/// Handle user group names.
pub async fn user_group_names(pool: &PgPool, user_id: Uuid) -> Result<Vec<String>, sqlx::Error> {
    // Same-connection tenant context ( rule 2) - groups/group_members
    // are RLS'd; a bare-pool read silently returns 0 rows under FORCE RLS.
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;
    let rows = sqlx::query(
        r#"SELECT g.name FROM groups g
           JOIN group_members gm ON gm.group_id = g.id
           WHERE gm.user_id = $1 ORDER BY g.name"#,
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| r.try_get::<Option<String>, _>("name").ok().flatten())
        .collect())
}

/// Resolved Role names assigned to an OAuth client (service principal),
/// expanded over sentin8_auth_role_nesting. Used by `/oauth/userinfo` (M2M branch)
/// and `GET /v1/admin/oauth-clients/{id}/roles`.
/// Handle client role names.
pub async fn client_role_names(
    pool: &PgPool,
    client_db_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    // Same-connection tenant context ( rule 2) - SYSTEM_ENV_ID covers
    // the client's env + the role catalog (nesting closure).
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;
    let rows = sqlx::query(
        r#"WITH RECURSIVE seed_roles AS (
                SELECT r.id, r.name FROM roles r
                JOIN client_roles cr ON cr.role_id = r.id
                WHERE cr.client_id = $1
            ),
            role_closure AS (
                SELECT id, name FROM seed_roles
                UNION ALL
                SELECT child.id, child.name
                FROM roles child
                JOIN role_nesting nest ON nest.child_role_id = child.id
                JOIN role_closure parent ON parent.id = nest.parent_role_id
            )
            SELECT DISTINCT name FROM role_closure ORDER BY name"#,
    )
    .bind(client_db_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| r.try_get::<Option<String>, _>("name").ok().flatten())
        .collect())
}

/// Extract the session token from the `__session` cookie header.
/// SEC- - run a read/write against RLS tables with the tenant
/// context set on the same connection.
///
/// `sentin8_set_tenant_context` uses `set_config(..., true)` which is
/// TRANSACTION-local - on a bare pooled connection it evaporates before
/// the next statement. This helper opens a transaction, sets the context,
/// runs the closure on that connection, and commits (persisting writes).
///
/// The env is resolved from the TLS `X-Sentin8-Env-Id` header when present,
/// falling back to the platform system env.
/// Handle with tenant context.
pub async fn with_tenant_context<T, F>(
    state: &AppState,
    headers: &HeaderMap,
    f: F,
) -> Result<T, (StatusCode, String)>
where
    F: for<'c> FnOnce(
        &'c mut sqlx::PgConnection,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<T, (StatusCode, String)>> + Send + 'c>,
    >,
{
    let env_id = headers
        .get(sentin8::middleware::context::HEADER_ENV_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(crate::config::SYSTEM_ENV_ID);

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let out = f(&mut tx).await?;
    let _ = tx.commit().await;
    Ok(out)
}

/// Extract session token.
pub fn extract_session_token(headers: &HeaderMap) -> Option<String> {
    // SEC- - also accept `Authorization: Bearer <session_token>`
    // so non-browser clients (e2e fixtures, the authenticator app) can
    // drive session-authenticated endpoints without cookies.
    if let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            return Some(token.to_string());
        }
    }
    let cookie_header = headers.get(axum::http::header::COOKIE)?;
    let cookie_str = cookie_header.to_str().ok()?;
    for part in cookie_str.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("__session=") {
            return Some(val.to_string());
        }
    }
    None
}

/// SEC- - CSRF defense on mutating session-authenticated endpoints.
///
/// A cross-site form POST cannot set custom headers, so requiring the
/// `X-Sentin8-CSRF` header defeats it. Bearer-token callers are exempt -
/// the `Authorization` header is itself a custom header a form cannot set.
/// The header value is the session token id (the SPA reads it from the
/// sign-in response body); the server compares it against the resolved
/// session inside the handler via [`require_csrf_or_bearer`].
///
/// Returns `Err(403)` when the request is cookie-authenticated and the
/// header is missing, or present but does not match the session token.
/// Check CSRF.
pub fn check_csrf(headers: &HeaderMap, session_token: &str) -> Result<(), (StatusCode, String)> {
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    if bearer.is_some() {
        return Ok(());
    }
    match headers
        .get("X-Sentin8-CSRF")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
    {
        None => Err((
            StatusCode::FORBIDDEN,
            "X-Sentin8-CSRF header required for cookie-authenticated mutations".into(),
        )),
        Some(v) if v == session_token => Ok(()),
        Some(_) => Err((StatusCode::FORBIDDEN, "X-Sentin8-CSRF mismatch".into())),
    }
}

/// Resolve the session token then enforce the CSRF rule in one step.
/// Handlers that already resolved the session may call [`check_csrf`]
/// directly with the token id.
/// Handle require CSRF for session.
pub fn require_csrf_for_session(headers: &HeaderMap) -> Result<String, (StatusCode, String)> {
    let token = extract_session_token(headers)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "no session".into()))?;
    check_csrf(headers, &token)?;
    Ok(token)
}
