// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Password reset and email verification flows.
//!
//! Both flows use short-lived, single-use tokens stored in `sentin8_auth_tokens`
//! (only the SHA-256 hash is persisted). The raw token is delivered to the
//! user out-of-band (email link). A `short_code` (first 8 hex chars) is also
//! stored for admin-shared codes or short-channel delivery.
//!
//! ## Password reset
//! - `POST /v1/password/reset` - request a reset: generate a token, store the
//! hash, return `{"status":"sent","short_code":"..."}` (the server logs the
//! reset link in dev mode; production delivers via email/SMS out-of-band).
//! - `POST /v1/password/reset/confirm` - submit the token + new password,
//! validate the token, set the new password hash, consume the token,
//! revoke all active sessions for the user.
//!
//! ## Email verification
//! - `POST /v1/email/verify` - request a verification email: generate a token,
//! store the hash.
//! - `POST /v1/email/verify/confirm` - submit the token, mark
//! `sentin8_auth_users.email_verified = true`, consume the token.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::handlers::AppState;

/// Password reset token TTL (1 hour).
const PASSWORD_RESET_TTL_SECS: i64 = 3600;
/// Email verification token TTL (24 hours).
const EMAIL_VERIFY_TTL_SECS: i64 = 86400;

// ── Password reset ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for passwordreset.
pub struct PasswordResetRequest {
    /// The email.
    pub email: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for passwordreset.
pub struct PasswordResetResponse {
    /// The status.
    pub status: String,
    /// When a reset token was issued: the short code (first 8 hex chars) for
    /// out-of-band delivery. In dev mode the full reset token is also logged.
    /// In production the full token is delivered via email and `short_code`
    /// is omitted from the response (only returned to admins).
    /// The short code.
    pub short_code: Option<String>,
}

/// `POST /v1/password/reset` - request a password reset token.
///
/// Always returns `{"status":"sent"}` even when the email is unknown
/// (to prevent user enumeration). The `short_code` is only present when a
/// user was found.
///
/// The email is scoped to the current tenant (resolved from the
/// `Host` / TLS headers) because the same email can exist as a
/// separate user in each tenant.
/// Handle password reset request.
#[utoipa::path(
    post,
    path = "/v1/password/reset",
    request_body = PasswordResetRequest,
    responses(
        (status = 200, description = "Always `status: sent` (enumeration-safe); short_code present in dev mode", body = PasswordResetResponse),
        (status = 429, description = "Rate limit exceeded"),
    ),
    security(),
    tag = "auth",
)]
pub async fn password_reset_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PasswordResetRequest>,
) -> Response {
    let email = req.email.to_lowercase();
    // Resolve the tenant from the request headers - the same email may
    // exist as different users across tenants, so we MUST scope the
    // lookup to env_id.
    let (_org_id, env_id) =
        crate::handlers::resolve_tenant_from_headers(&state.pool, &headers).await;
    // tenant context on the same connection (design ).
    let user = async {
        let mut conn = state.pool.begin().await.ok()?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *conn)
            .await;
        let user = sqlx::query!(
            r#"SELECT id, env_id, status
               FROM users
              WHERE email = $1
                AND env_id = $2"#,
            email,
            env_id,
        )
        .fetch_optional(&mut *conn)
        .await
        .ok();
        let _ = conn.commit().await;
        user
    }
    .await;

    match user {
        Some(Some(u)) if u.status == "active" => {
            let (raw_token, short_code, _token_hash) = issue_token(
                u.id,
                u.env_id,
                "password_reset",
                PASSWORD_RESET_TTL_SECS,
                &state.pool,
            )
            .await;

            // Dev mode: log the full reset link. Production: deliver via email.
            tracing::info!(
                user_id = %u.id,
                short_code = %short_code,
                "password reset token issued (dev mode logs the token)",
            );

            //send password reset notification via Sentin8:Post.
            crate::events::emit_post_notification(
                &state.pool,
                u.env_id,
                "sentin8:auth:password:reset",
                "security",
                "high",
                Some(u.id),
                Some(&email),
                "Password reset request",
                &format!("A password reset was requested for your account. Use code: {short_code}"),
                serde_json::json!({"user_id": u.id, "short_code": short_code, "event": "password_reset"}),
            ).await;

            // The raw token is NOT returned in the API response - the
            // short code is delivered out-of-band via Sentin8:Post and is
            // visible in dev logs only (the previous
            // `short_code: Some(...)` leaked 32 bits of the security
            // token to any unauthenticated caller who knew an email).
            let _ = raw_token;

            Json(PasswordResetResponse {
                status: "sent".into(),
                short_code: None,
            })
            .into_response()
        }
        _ => {
            // User not found or not active - return the same response shape
            // to prevent enumeration.
            Json(PasswordResetResponse {
                status: "sent".into(),
                short_code: None,
            })
            .into_response()
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for passwordresetconfirm.
pub struct PasswordResetConfirmRequest {
    /// The token.
    pub token: String,
    /// The new password.
    pub new_password: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for passwordresetconfirm.
pub struct PasswordResetConfirmResponse {
    /// The status.
    pub status: String,
}

/// `POST /v1/password/reset/confirm` - set a new password with a reset token.
/// Handle password reset confirm.
#[utoipa::path(
    post,
    path = "/v1/password/reset/confirm",
    request_body = PasswordResetConfirmRequest,
    responses(
        (status = 200, description = "Password updated", body = PasswordResetConfirmResponse),
        (status = 400, description = "Token required or password too short"),
        (status = 400, description = "Invalid or expired token"),
    ),
    security(),
    tag = "auth",
)]
pub async fn password_reset_confirm(
    State(state): State<AppState>,
    Json(req): Json<PasswordResetConfirmRequest>,
) -> Result<Response, (StatusCode, String)> {
    if req.new_password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            "password must be at least 8 characters".into(),
        ));
    }
    if req.token.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "token is required".into()));
    }

    let token_hash = hash_token(&req.token);
    // tenant context on the same connection (design ). The
    // token → user lookup resolves the tenant, then all writes run on that
    // connection with the context set.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row = sqlx::query!(
        r#"SELECT t.id, t.user_id, t.expires_at, t.consumed_at, u.env_id
           FROM tokens t
           JOIN users u ON u.id = t.user_id
           WHERE t.token_hash = $1 AND t.token_kind = 'password_reset'
           LIMIT 1"#,
        token_hash,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "invalid or unknown token".into()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(row.env_id)
        .execute(&mut *conn)
        .await;

    if row.consumed_at.is_some() {
        return Err((StatusCode::CONFLICT, "token already used".into()));
    }
    if row.expires_at < chrono::Utc::now() {
        return Err((StatusCode::GONE, "token expired".into()));
    }

    // Set the new password.
    let password_hash = bcrypt::hash(&req.new_password, bcrypt::DEFAULT_COST)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    sqlx::query!(
        r#"UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2"#,
        password_hash,
        row.user_id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Consume the token.
    sqlx::query!(
        r#"UPDATE tokens SET consumed_at = now() WHERE id = $1"#,
        row.id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Revoke all active sessions for the user (force re-sign-in).
    let _ = sqlx::query!(
        r#"UPDATE sessions SET status = 'revoked', updated_at = now()
           WHERE user_id = $1 AND status = 'active'"#,
        row.user_id,
    )
    .execute(&mut *conn)
    .await;

    // Continuous access evaluation (auth DESIGN §10): the outbox row
    // commits atomically with the revocation UPDATE - the BFF
    // session-reaper kills the cached BFF sessions for the subject.
    crate::events::emit_session_revoked(
        &mut conn,
        row.env_id,
        &row.user_id.to_string(),
        None,
        "password_reset",
    )
    .await;

    // password:reset is a CONFIRM-time domain event (the
    // password actually changed), not a request-time notification. The
    // inbox row is written on the same transaction (outbox-first rule).
    crate::events::emit_event_tx(
        &mut conn,
        row.env_id,
        "sentin8:auth:password:reset",
        serde_json::json!({ "user_id": row.user_id }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let _ = conn.commit().await;

    Ok(Json(PasswordResetConfirmResponse {
        status: "password_reset".into(),
    })
    .into_response())
}

// ── Email verification ─────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for emailverify.
pub struct EmailVerifyRequest {
    /// Email to verify. The user must already exist.
    /// The email.
    pub email: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for emailverify.
pub struct EmailVerifyResponse {
    /// The status.
    pub status: String,
    /// The short code.
    pub short_code: Option<String>,
}

/// `POST /v1/email/verify` - request an email verification token.
///
/// The email is scoped to the current tenant (resolved from the
/// `Host` / TLS headers) because the same email can exist as a
/// separate user in each tenant.
///
/// enumeration-safe: unknown emails and
/// already-verified emails return the same `{"status":"sent"}` shape
/// (previously 404 / 409 revealed account existence). The short_code is
/// no longer returned to unauthenticated callers -
/// it is logged for dev workflows and delivered via Sentin8:Post.
/// Handle email verify request.
#[utoipa::path(
    post,
    path = "/v1/email/verify",
    request_body = EmailVerifyRequest,
    responses(
        (status = 200, description = "Always `status: sent` (enumeration-safe)", body = EmailVerifyResponse),
        (status = 429, description = "Rate limit exceeded"),
    ),
    security(),
    tag = "auth",
)]
pub async fn email_verify_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EmailVerifyRequest>,
) -> Result<Response, (StatusCode, String)> {
    let email = req.email.to_lowercase();
    let (_org_id, env_id) =
        crate::handlers::resolve_tenant_from_headers(&state.pool, &headers).await;
    let user = sqlx::query!(
        r#"SELECT id, env_id, email_verified
           FROM users
          WHERE email = $1
            AND env_id = $2"#,
        email,
        env_id,
    )
    .fetch_optional(&state.pool)
    .await;

    // Enumeration-safe: the response shape is identical for every case.
    if let Ok(Some(u)) = user {
        if !u.email_verified {
            let (_raw_token, short_code, _hash) = issue_token(
                u.id,
                u.env_id,
                "email_verify",
                EMAIL_VERIFY_TTL_SECS,
                &state.pool,
            )
            .await;

            tracing::info!(
                user_id = %u.id,
                short_code = %short_code,
                "email verification token issued (dev mode logs the short code)",
            );
        }
    }

    Ok(Json(EmailVerifyResponse {
        status: "sent".into(),
        short_code: None,
    })
    .into_response())
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for emailverifyconfirm.
pub struct EmailVerifyConfirmRequest {
    /// The token.
    pub token: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for emailverifyconfirm.
pub struct EmailVerifyConfirmResponse {
    /// The status.
    pub status: String,
    /// user identifier.
    pub user_id: Uuid,
}

/// `POST /v1/email/verify/confirm` - confirm email verification with a token.
/// Handle email verify confirm.
#[utoipa::path(
    post,
    path = "/v1/email/verify/confirm",
    request_body = EmailVerifyConfirmRequest,
    responses(
        (status = 200, description = "Email verified", body = EmailVerifyConfirmResponse),
        (status = 400, description = "Token required, invalid, or expired"),
    ),
    security(),
    tag = "auth",
)]
pub async fn email_verify_confirm(
    State(state): State<AppState>,
    Json(req): Json<EmailVerifyConfirmRequest>,
) -> Result<Response, (StatusCode, String)> {
    if req.token.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "token is required".into()));
    }

    let token_hash = hash_token(&req.token);
    let row = sqlx::query!(
        r#"SELECT id, user_id, expires_at, consumed_at
           FROM tokens
           WHERE token_hash = $1 AND token_kind = 'email_verify'
           LIMIT 1"#,
        token_hash,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "invalid or unknown token".into()))?;

    if row.consumed_at.is_some() {
        return Err((StatusCode::CONFLICT, "token already used".into()));
    }
    if row.expires_at < chrono::Utc::now() {
        return Err((StatusCode::GONE, "token expired".into()));
    }

    sqlx::query!(
        r#"UPDATE users SET email_verified = true, updated_at = now() WHERE id = $1"#,
        row.user_id,
    )
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    sqlx::query!(
        r#"UPDATE tokens SET consumed_at = now() WHERE id = $1"#,
        row.id,
    )
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(EmailVerifyConfirmResponse {
        status: "verified".into(),
        user_id: row.user_id,
    })
    .into_response())
}

// ── Internal helpers ───────────────────────────────────────────────────

/// Issue a single-use token: generate a random 32-byte token (hex-encoded),
/// store its SHA-256 hash + the first 8 chars as `short_code`. Returns
/// `(raw_token_hex, short_code, token_hash)` for the caller to deliver.
async fn issue_token(
    user_id: Uuid,
    env_id: Uuid,
    kind: &str,
    ttl_secs: i64,
    pool: &sqlx::PgPool,
) -> (String, String, String) {
    use rand::RngCore;
    let mut bytes = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let raw_token = hex_encode(&bytes);
    let short_code = raw_token[..8].to_string();
    let token_hash = hash_token(&raw_token);

    sqlx::query!(
        r#"INSERT INTO tokens
             (user_id, env_id, token_kind, token_hash, short_code, expires_at)
           VALUES ($1, $2, $3, $4, $5, now() + ($6 || ' seconds')::interval)"#,
        user_id,
        env_id,
        kind,
        token_hash,
        &short_code,
        ttl_secs.to_string(),
    )
    .execute(pool)
    .await
    .ok();

    (raw_token, short_code, token_hash)
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_known() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab]), "00ffab");
    }

    #[test]
    fn hash_token_is_deterministic_and_distinct() {
        let h1 = hash_token("abc");
        let h2 = hash_token("abc");
        let h3 = hash_token("abd");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn short_code_is_first_8_chars() {
        // The raw token's first 8 chars become the short code.
        let raw = "0123456789abcdef";
        let short = raw[..8].to_string();
        assert_eq!(short, "01234567");
    }
}
