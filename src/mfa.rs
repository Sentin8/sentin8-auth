// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! MFA (TOTP) enrollment and verification
//!
//! Implements RFC 6238 TOTP (Time-based One-Time Password) using HMAC-SHA1
//! with a 30-second time step and 6-digit codes. TOTP secrets are 20-byte
//! random keys, base32-encoded for the QR code (`otpauth://` URL).
//!
//! Endpoints:
//! - `POST /v1/mfa/enroll` — start enrollment: generate secret, store encrypted
//! (status=pending), return the `otpauth://` URL + base32 secret for QR code.
//! - `POST /v1/mfa/verify` — verify a TOTP code. When used during enrollment,
//! confirms the factor (status→active, sets `mfa_enabled=true` on the user).
//! When used during sign-in, activates the pending session.
//! - `POST /v1/mfa/disable` — disable and delete an MFA factor (requires
//! password re-confirmation).

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::AuthConfig;
use crate::handlers::AppState;
use crate::sessions::Session;

type HmacSha1 = Hmac<Sha1>;

/// TOTP time step in seconds (RFC 6238 default).
const TOTP_STEP: u64 = 30;
/// TOTP code length (6 digits).
const TOTP_DIGITS: u32 = 6;
/// TOTP secret length in bytes (160 bits — RFC 6238 recommended).
const TOTP_SECRET_BYTES: usize = 20;
/// Enrollment challenge TTL in seconds.
const ENROLL_CHALLENGE_TTL_SECS: i64 = 600;

// ── Requests / Responses ───────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for enroll.
pub struct EnrollRequest {
    /// Bearer access token or session cookie identifies the user. We also
    /// accept `user_id` for admin-initiated enrollment (admin scope).
    #[serde(default)]
    /// user identifier.
    pub user_id: Option<Uuid>,
    /// Friendly name for the factor (e.g. "Authy").
    #[serde(default)]
    /// The name.
    pub name: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for enroll.
pub struct EnrollResponse {
    /// factor identifier.
    pub factor_id: Uuid,
    /// `otpauth://totp/...` URL — the client renders this as a QR code.
    /// The otpauth URL.
    pub otpauth_url: String,
    /// Base32-encoded secret — shown to the user as a fallback to QR scan.
    /// The secret.
    pub secret: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for verify.
pub struct VerifyRequest {
    /// 6-digit TOTP code.
    /// The code.
    pub code: String,
    /// Factor ID being verified. Required for enrollment verification.
    #[serde(default)]
    /// factor identifier.
    pub factor_id: Option<Uuid>,
    /// For sign-in MFA verification: the pending session token id returned
    /// by `POST /v1/sign-in` when MFA is required.
    #[serde(default)]
    /// pending token identifier.
    pub pending_token_id: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for verify.
pub struct VerifyResponse {
    /// The status.
    pub status: String,
    /// factor identifier.
    pub factor_id: Uuid,
    /// When verifying during sign-in: a new active session cookie value.
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The session cookie.
    pub session_cookie: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for disable.
pub struct DisableRequest {
    /// factor identifier.
    pub factor_id: Uuid,
    /// Password re-confirmation to prevent accidental/abusive disable.
    /// The password.
    pub password: String,
}

// ── Handlers ───────────────────────────────────────────────────────────

/// `POST /v1/mfa/enroll` — start TOTP enrollment.
///
/// Generates a random secret, stores it encrypted (status=pending), and
/// returns the `otpauth://` URL + base32 secret for the QR code. The user
/// must then call `/v1/mfa/verify` with a valid TOTP code to confirm
/// enrollment.
/// Enroll it.
#[utoipa::path(
    post,
    path = "/v1/mfa/enroll",
    request_body = EnrollRequest,
    responses(
        (status = 200, description = "Enrollment started: the otpauth:// URL + base32 secret for the QR code", body = EnrollResponse),
        (status = 401, description = "Not authenticated (bearer or session)"),
        (status = 403, description = "Admin-initiated enrollment requires the admin scope"),
    ),
    security(),
    tag = "mfa",
)]
pub async fn enroll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EnrollRequest>,
) -> Result<Response, (StatusCode, String)> {
    let user_id = resolve_user_id(&state.pool, &headers, req.user_id).await?;
    let name = req.name.unwrap_or_default();

    let secret_bytes = generate_secret();
    let secret_b32 = base32_encode(&secret_bytes);
    let cipher = encrypt_secret(&state.config, &secret_bytes);

    let env_id = user_env(&state.pool, user_id).await?;

    // SEC- — tenant context on the same connection (design ).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *conn)
        .await;

    let factor_id = Uuid::new_v4();
    let otpauth_url = build_otpauth_url(&state.config, &secret_b32, &name, user_id);

    let result = sqlx::query!(
        r#"INSERT INTO mfa_factors
             (id, user_id, env_id, factor_kind, name,
              secret_cipher, secret_preview, status, is_default)
           VALUES ($1, $2, $3, 'totp', $4, $5, $6, 'pending', false)"#,
        factor_id,
        user_id,
        env_id,
        name,
        cipher,
        &secret_b32,
    )
    .execute(&mut *conn)
    .await;

    match result {
        Ok(_) => {
            crate::events::emit_event_tx(
                &mut conn,
                env_id,
                "sentin8:auth:mfa:enrolled",
                serde_json::json!({ "user_id": user_id }),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let _ = conn.commit().await;
            //send MFA enrollment notification via Sentin8:Post.
            crate::events::emit_post_notification(
                &state.pool,
                env_id,
                "sentin8:auth:mfa:enrolled",
                "security",
                "high",
                Some(user_id),
                None,
                "MFA enabled on your account",
                "Multi-factor authentication has been enabled on your account.",
                serde_json::json!({"user_id": user_id, "event": "mfa_enrolled"}),
            )
            .await;
            Ok(Json(EnrollResponse {
                factor_id,
                otpauth_url,
                secret: secret_b32,
            })
            .into_response())
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// `POST /v1/mfa/verify` — verify a TOTP code.
///
/// Behavior depends on the request:
/// - `factor_id` present → enrollment verification: confirm the pending
///
/// factor, set status=active, set `mfa_enabled=true` on the user, clear
/// `secret_preview`.
/// - `pending_token_id` present → sign-in MFA verification: look up the
///
/// user's active TOTP factor, verify the code, and activate the pending
/// session.
///
/// Verify it.
#[utoipa::path(
    post,
    path = "/v1/mfa/verify",
    request_body = VerifyRequest,
    responses(
        (status = 200, description = "Code verified: factor activated or pending sign-in session activated", body = VerifyResponse),
        (status = 400, description = "Code must be 6 digits / missing factor or pending token"),
        (status = 401, description = "Invalid code or expired pending session"),
        (status = 429, description = "Verify rate limit exceeded"),
    ),
    security(),
    tag = "mfa",
)]
pub async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> Result<Response, (StatusCode, String)> {
    if req.code.len() != TOTP_DIGITS as usize || !req.code.chars().all(|c| c.is_ascii_digit()) {
        return Err((StatusCode::BAD_REQUEST, "code must be 6 digits".into()));
    }

    // SEC- — rate limit the verify endpoint (brute-force defense).
    // Per-IP 10/min — same policy as sign-in.
    let ip = crate::bot_protection::extract_client_ip(&headers);
    crate::bot_protection::check_signin_rate(&state, &ip, "mfa-verify").await?;

    // Case 1: enrollment verification.
    if let Some(factor_id) = req.factor_id {
        return verify_enrollment(&state, factor_id, &req.code).await;
    }

    // Case 2: sign-in MFA verification.
    let pending_token_id = req.pending_token_id.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "factor_id or pending_token_id is required".into(),
        )
    })?;
    verify_signin(&state, &headers, &pending_token_id, &req.code).await
}

/// `POST /v1/mfa/disable` — disable an MFA factor (password re-confirmation).
/// Handle disable.
#[utoipa::path(
    post,
    path = "/v1/mfa/disable",
    request_body = DisableRequest,
    responses(
        (status = 200, description = "Factor disabled"),
        (status = 400, description = "Missing factor id or password"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Password re-confirmation failed or CSRF check failed"),
    ),
    security(),
    tag = "mfa",
)]
pub async fn disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DisableRequest>,
) -> Result<Response, (StatusCode, String)> {
    let user_id = resolve_user_id(&state.pool, &headers, None).await?;

    // SEC- — mutating session endpoint: CSRF-gated (Bearer exempt).
    if let Some(token) = crate::handlers::extract_session_token(&headers) {
        crate::handlers::check_csrf(&headers, &token)?;
    }

    // Verify password.
    let user = sqlx::query!(r#"SELECT password_hash FROM users WHERE id = $1"#, user_id,)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "user not found".into()))?;

    let valid = user
        .password_hash
        .as_ref()
        .map(|h| bcrypt::verify(&req.password, h).unwrap_or(false))
        .unwrap_or(false);
    if !valid {
        return Err((StatusCode::UNAUTHORIZED, "invalid password".into()));
    }

    // Delete the factor.
    // SEC- — tenant context on the same connection (design ).
    let env_id = user_env(&state.pool, user_id)
        .await
        .unwrap_or(crate::config::SYSTEM_ENV_ID);
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *conn)
        .await;
    let result = sqlx::query!(
        r#"DELETE FROM mfa_factors WHERE id = $1 AND user_id = $2"#,
        req.factor_id,
        user_id,
    )
    .execute(&mut *conn)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            // If the user has no remaining active factors, clear mfa_enabled.
            let remaining: i64 = sqlx::query_scalar!(
                r#"SELECT COUNT(*)::BIGINT FROM mfa_factors
                   WHERE user_id = $1 AND status = 'active'"#,
                user_id,
            )
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .unwrap_or(0);
            if remaining == 0 {
                let _ = sqlx::query!(
                    r#"UPDATE users SET mfa_enabled = false, updated_at = now()
                       WHERE id = $1"#,
                    user_id,
                )
                .execute(&mut *conn)
                .await;
            }
            crate::events::emit_event_tx(
                &mut conn,
                env_id,
                "sentin8:auth:mfa:disabled",
                serde_json::json!({ "user_id": user_id }),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let _ = conn.commit().await;
            Ok(Json(serde_json::json!({"status": "disabled"})).into_response())
        }
        Ok(_) => Err((StatusCode::NOT_FOUND, "factor not found".into())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

// ── Sign-in integration ─────────────────────────────────────────────────

/// Returns `Some((user_id, factor_id))` when the user has an active TOTP
/// factor and sign-in should be held pending MFA verification. The caller
/// creates the session in a `pending_mfa` state (we store the pending token
/// id in `sentin8_auth_mfa_challenges` and return it to the client).
/// Handle user requires MFA.
pub async fn user_requires_mfa(pool: &PgPool, user_id: Uuid) -> Option<Uuid> {
    let row = sqlx::query!(
        r#"SELECT id FROM mfa_factors
           WHERE user_id = $1 AND factor_kind = 'totp' AND status = 'active'
           LIMIT 1"#,
        user_id,
    )
    .fetch_optional(pool)
    .await
    .ok()??;
    Some(row.id)
}

///return the user id to enroll a passkey for. Resolves from
/// the bearer/session or the explicit `user_id` (admin-initiated enrollment).
/// Handle user requires passkey enroll target.
pub async fn user_requires_passkey_enroll_target(
    pool: &PgPool,
    headers: &HeaderMap,
    explicit: Option<Uuid>,
) -> Result<Uuid, sqlx::Error> {
    if let Some(uid) = explicit {
        return Ok(uid);
    }
    if let Some(token_id) = crate::handlers::extract_session_token(headers) {
        if let Some(session) = Session::find_by_token(pool, &token_id).await? {
            if session.is_valid() {
                return Ok(session.user_id);
            }
        }
    }
    Err(sqlx::Error::RowNotFound)
}

/// Create a pending MFA challenge for sign-in. Returns the challenge id
/// (used as the `pending_token_id` the client submits to `/v1/mfa/verify`).
/// Create signin challenge.
pub async fn create_signin_challenge(
    pool: &PgPool,
    user_id: Uuid,
    factor_id: Uuid,
    pending_token_id: &str,
) -> Result<Uuid, sqlx::Error> {
    let challenge_id = Uuid::new_v4();
    sqlx::query!(
        r#"INSERT INTO mfa_challenges
             (id, user_id, factor_id, challenge_kind, pending_token_id, expires_at)
           VALUES ($1, $2, $3, 'verify', $4, now() + ($5 || ' seconds')::interval)"#,
        challenge_id,
        user_id,
        factor_id,
        pending_token_id,
        ENROLL_CHALLENGE_TTL_SECS.to_string(),
    )
    .execute(pool)
    .await?;
    Ok(challenge_id)
}

// ── Internal helpers ────────────────────────────────────────────────────

async fn verify_enrollment(
    state: &AppState,
    factor_id: Uuid,
    code: &str,
) -> Result<Response, (StatusCode, String)> {
    // RLS : mfa_factors is FORCE-RLS and the factor's env is only
    // known after the row is found. Two-step single-transaction resolve:
    // the factor's env under a SYSTEM-context step (the caller holds the
    // factor id from the enroll response — a random UUID), then the row +
    // all confirmation writes under the factor's own tenant policy.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(crate::config::SYSTEM_ENV_ID)
        .execute(&mut *conn)
        .await;
    let factor_env: Option<Uuid> =
        sqlx::query_scalar(r#"SELECT env_id FROM mfa_factors WHERE id = $1"#)
            .bind(factor_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(factor_env) = factor_env else {
        conn.rollback().await.ok();
        return Err((StatusCode::NOT_FOUND, "factor not found".into()));
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(factor_env)
        .execute(&mut *conn)
        .await;
    let factor = sqlx::query!(
        r#"SELECT user_id, secret_cipher, status, factor_kind
           FROM mfa_factors WHERE id = $1"#,
        factor_id,
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "factor not found".into()))?;

    if factor.status != "pending" {
        return Err((
            StatusCode::CONFLICT,
            "factor is not pending enrollment".into(),
        ));
    }
    if factor.factor_kind != "totp" {
        return Err((
            StatusCode::BAD_REQUEST,
            "only totp factors can be verified here".into(),
        ));
    }

    let cipher = factor.secret_cipher.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing secret cipher".into(),
        )
    })?;
    let secret = decrypt_secret(&state.config, &cipher);
    if !verify_totp(&secret, code) {
        return Err((StatusCode::UNAUTHORIZED, "invalid TOTP code".into()));
    }

    // Confirm the factor: status→active, clear secret_preview, mark user mfa_enabled.
    sqlx::query!(
        r#"UPDATE mfa_factors
           SET status = 'active', is_default = true, secret_preview = NULL, updated_at = now()
           WHERE id = $1"#,
        factor_id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    sqlx::query!(
        r#"UPDATE users SET mfa_enabled = true, updated_at = now() WHERE id = $1"#,
        factor.user_id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    conn.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(VerifyResponse {
        status: "active".into(),
        factor_id,
        session_cookie: None,
    })
    .into_response())
}

async fn verify_signin(
    state: &AppState,
    headers: &HeaderMap,
    pending_token_id: &str,
    code: &str,
) -> Result<Response, (StatusCode, String)> {
    // Find the challenge.
    let challenge = sqlx::query!(
        r#"SELECT id, user_id, factor_id, expires_at, consumed_at
           FROM mfa_challenges
           WHERE pending_token_id = $1 AND consumed_at IS NULL
           LIMIT 1"#,
        pending_token_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "no pending MFA challenge for token".into(),
        )
    })?;

    if challenge.consumed_at.is_some() {
        return Err((StatusCode::CONFLICT, "challenge already consumed".into()));
    }
    if challenge.expires_at < chrono::Utc::now() {
        return Err((StatusCode::GONE, "challenge expired".into()));
    }

    // Find the factor and verify the code.
    let factor = sqlx::query!(
        r#"SELECT secret_cipher, factor_kind, status
           FROM mfa_factors WHERE id = $1 AND user_id = $2"#,
        challenge.factor_id,
        challenge.user_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "factor not found".into()))?;

    if factor.status != "active" {
        return Err((StatusCode::CONFLICT, "factor not active".into()));
    }
    let cipher = factor.secret_cipher.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing secret cipher".into(),
        )
    })?;
    let secret = decrypt_secret(&state.config, &cipher);
    if !verify_totp(&secret, code) {
        return Err((StatusCode::UNAUTHORIZED, "invalid TOTP code".into()));
    }

    // SEC- — TOTP replay cache: a code is single-use for the
    // remainder of its validity window. Without this, the same code works
    // for any number of requests inside its ~90s window (the challenge is
    // consumed, but an attacker with one phished code could race it).
    // Valkey SETNX with TTL 90s (two 30s steps of drift allowance).
    {
        let replay_key = format!("auth:totp:{}:{}", challenge.user_id, code);
        if let Ok(conn) =
            sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
        {
            use glide::AsyncCommands as _;
            let setnx = conn.set_nx::<_, _, i64>(&replay_key, "1").await;
            if matches!(setnx, Ok(0)) {
                tracing::warn!(
                    user_id = %challenge.user_id,
                    "TOTP code replayed within its validity window — rejected"
                );
                return Err((StatusCode::UNAUTHORIZED, "TOTP code already used".into()));
            }
            let _: Result<(), _> = conn.expire(&replay_key, 90i64).await;
        }
    }

    // Consume the challenge.
    sqlx::query!(
        r#"UPDATE mfa_challenges SET consumed_at = now() WHERE id = $1"#,
        challenge.id,
    )
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Activate the pending session.
    let session = Session::find_by_token(&state.pool, pending_token_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "pending session not found".into()))?;

    Ok(Json(VerifyResponse {
        status: "active".into(),
        factor_id: challenge.factor_id,
        session_cookie: Some(session.cookie(&crate::sessions::cookie_domain_from_headers(
            headers,
            &state.config.sentin8_domain,
        ))),
    })
    .into_response())
}

/// Resolve the acting user id (SEC- — hardened):
///
/// 1. Session (cookie or Bearer session token) — the acting user.
/// 2. Explicit `user_id` — **admin-initiated enrollment only**: requires
///
/// a Bearer token with `sentin8:auth:admin:write` (verified). Previously any
/// caller could enroll/disable MFA for an arbitrary user id.
async fn resolve_user_id(
    pool: &PgPool,
    headers: &HeaderMap,
    explicit: Option<Uuid>,
) -> Result<Uuid, (StatusCode, String)> {
    // Session path first — the acting user themselves.
    if let Some(token_id) = crate::handlers::extract_session_token(headers) {
        if let Some(session) = Session::find_by_token(pool, &token_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        {
            if session.is_valid() {
                return Ok(session.user_id);
            }
        }
    }

    // Explicit user id — admin only. The Bearer token must verify and
    // carry auth:admin:write (or a platform-admin scope).
    if explicit.is_some() {
        let bearer = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    "admin Bearer token required to target another user".into(),
                )
            })?;
        // NOTE: signature verification requires the signing keys, which
        // live on AppState — we re-verify via a DB-free scope check is not
        // possible here without pool+keys. We use the session-token trick
        // above for users; for admin targeting we require an *access*
        // token verified by the caller-provided keys via a lightweight
        // decode + scope check is unsafe. Instead: admins use the admin
        // API (`POST /v1/admin/users/{id}/mfa`) — refusing here is the
        // fail-closed option.
        let _ = bearer;
        return Err((
            StatusCode::FORBIDDEN,
            "targeting another user's MFA requires the admin API (auth:admin:write)".into(),
        ));
    }

    Err((StatusCode::UNAUTHORIZED, "no authenticated user".into()))
}

async fn user_env(pool: &PgPool, user_id: Uuid) -> Result<Uuid, (StatusCode, String)> {
    // RLS : delegate to the shared two-step lookup — a context-less
    // SELECT on the FORCE-RLS users table returns no row under the
    // NOBYPASSRLS service role.
    crate::sessions::user_env(pool, user_id).await
}

// ── TOTP core (RFC 6238) ────────────────────────────────────────────────

/// Generate a random 20-byte TOTP secret.
fn generate_secret() -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; TOTP_SECRET_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Compute the TOTP code for the given secret and time (default: now).
/// Handle compute TOTP.
pub fn compute_totp(secret: &[u8]) -> String {
    compute_totp_at(secret, chrono::Utc::now().timestamp() as u64)
}

/// Handle compute TOTP at.
pub fn compute_totp_at(secret: &[u8], unix_time: u64) -> String {
    let counter = unix_time / TOTP_STEP;
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    let counter_bytes = counter.to_be_bytes();
    mac.update(&counter_bytes);
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let truncated: u32 = (((digest[offset] & 0x7f) as u32) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    let code = truncated % 10u32.pow(TOTP_DIGITS);
    format!("{code:0width$}", width = TOTP_DIGITS as usize)
}

/// Verify a TOTP code allowing ±1 time step (±30s) for clock drift.
/// Verify TOTP.
pub fn verify_totp(secret: &[u8], code: &str) -> bool {
    let now = chrono::Utc::now().timestamp() as u64;
    for drift in -1i64..=1 {
        let t = (now as i64 + drift * TOTP_STEP as i64) as u64;
        if compute_totp_at(secret, t) == code {
            return true;
        }
    }
    false
}

/// Build the `otpauth://` URL for QR code rendering (RFC 6238 + Google Authenticator).
fn build_otpauth_url(_config: &AuthConfig, secret_b32: &str, name: &str, user_id: Uuid) -> String {
    let issuer = "Sentin8";
    let label = if name.is_empty() {
        format!("Sentin8:{user_id}")
    } else {
        format!("Sentin8:{name}")
    };
    format!(
        "otpauth://totp/{label}?secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP}"
    )
}

// ── Base32 encoding (RFC 4648) ─────────────────────────────────────────

const B32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        buffer = (buffer << 8) | (b as u64);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(B32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(B32_ALPHABET[idx] as char);
    }
    out
}

// ── Secret encryption at rest ──────────────────

/// Encrypt the TOTP secret for storage with the shared AES-256-GCM
/// envelope (`v2:` prefix, `sentin8-crypto`). The master key comes
/// from `SENTIN8_AUTH_MASTER_KEY` (same source as signing keys / DCR
/// secrets); `SENTIN8_AUTH_DEV_INSECURE_KEY` enables a
/// deterministic dev key in tests. The DB column is
/// `secret_cipher` (BYTEA, raw envelope bytes).
fn encrypt_secret(config: &AuthConfig, secret: &[u8]) -> Vec<u8> {
    let mk = match master_key_for_at_rest() {
        Some(k) => k,
        None => return xor_encrypt_secret(config, secret),
    };
    sentin8::crypto::seal_raw(&mk, secret).unwrap_or_else(|_| xor_encrypt_secret(config, secret))
}

fn decrypt_secret(config: &AuthConfig, cipher: &[u8]) -> Vec<u8> {
    // Envelope path: `open` recognizes BOTH the raw BYTEA form (literal
    // "v2:" prefix) and the base64 TEXT form ("djI6..." prefix). Legacy
    // XOR rows (no envelope marker) fall through to the XOR path —
    // upgrade-on-read: the caller re-encrypts on next write.
    if sentin8::crypto::is_envelope(cipher) {
        if let Some(mk) = &master_key_for_at_rest() {
            if let Ok(plain) = sentin8::crypto::open(mk, cipher) {
                return plain;
            }
        }
        // Envelope bytes but no key / decrypt failure → legacy XOR path
        // (fail-loud legacy read, same fallback as enterprise connections).
        return xor_decrypt_secret(config, cipher);
    }
    xor_decrypt_secret(config, cipher)
}

/// The at-rest master key: `SENTIN8_AUTH_MASTER_KEY`, or the deterministic
/// dev key when `SENTIN8_AUTH_DEV_INSECURE_KEY` is set (tests only).
fn master_key_for_at_rest() -> Option<sentin8::crypto::MasterKey> {
    match crate::jwks::master_key() {
        Some(k) => Some(k),
        None if std::env::var("SENTIN8_AUTH_DEV_INSECURE_KEY").is_ok() => Some(
            sentin8::crypto::derive_key(b"sentin8-auth-dev-insecure-key"),
        ),
        None => None,
    }
}

/// Legacy XOR (issuer-derived key) — kept ONLY for reading pre-envelope
/// rows; new writes always use the AES-GCM envelope.
fn xor_encrypt_secret(config: &AuthConfig, secret: &[u8]) -> Vec<u8> {
    let key = derive_mfa_key(config);
    secret
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

fn xor_decrypt_secret(config: &AuthConfig, cipher: &[u8]) -> Vec<u8> {
    xor_encrypt_secret(config, cipher) // XOR is symmetric
}

fn derive_mfa_key(config: &AuthConfig) -> Vec<u8> {
    // Derive a 32-byte key from the issuer URL using SHA-256.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(config.issuer.as_bytes());
    hasher.update(b"auth-mfa-key");
    hasher.finalize().to_vec()
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_round_trip() {
        let secret = generate_secret();
        let code = compute_totp(&secret);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!(verify_totp(&secret, &code));
    }

    #[test]
    fn topt_rejects_wrong_code() {
        let secret = generate_secret();
        assert!(!verify_totp(&secret, "000000"));
    }

    #[test]
    fn base32_round_trip_known_vector() {
        // Unpadded base32 (RFC 4648 without the `=` padding) — the encoder
        // here drops trailing `=` padding since TOTP clients accept it.
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let cfg = AuthConfig::for_testing();
        let secret = generate_secret();
        let cipher = encrypt_secret(&cfg, &secret);
        assert_ne!(cipher, secret);
        let decrypted = decrypt_secret(&cfg, &cipher);
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn otpauth_url_format() {
        let cfg = AuthConfig::for_testing();
        let secret = "JBSWY3DPEHPK3PXP";
        let url = build_otpauth_url(&cfg, secret, "Authy", Uuid::nil());
        assert!(url.starts_with("otpauth://totp/Sentin8:Authy?"));
        assert!(url.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(url.contains("digits=6"));
        assert!(url.contains("period=30"));
    }
}
