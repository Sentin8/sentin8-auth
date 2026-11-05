// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Identifier-first sign-in (IDFIRST-1) - the email-only step.
//!
//! `POST /v1/sign-in/identify` answers with an HMAC continuation token
//! plus the account's auth-method hints so the hosted UI can render the
//! right credential step (password / passkey / MFA expectation). DESIGN
//! §2 (identifier-first sequence diagram) and §5 (disclosure posture):
//!
//! - The identify step rides the SAME per-IP/per-email Valkey windows as
//!   `POST /v1/sign-in` (bulk probing stays throttled), but it never
//!   checks account lockout and never records a failed attempt - those
//!   belong to the credential step, and identify reveals nothing about
//!   credentials.
//! - Per-user hints are the industry pattern by decision: the existence
//!   leak equals the sign-up 409 oracle. Unknown emails answer the
//!   identical 200 shape - a synthetic continuation token over a null
//!   user with default methods - so the response differentiates nothing
//!   but the throttled hints.
//! - The continuation token reuses the `login_page.rs` HMAC-SHA256 blob
//!   pattern (`context_key()`, base64url signature, constant-time
//!   compare): `email|env_id|user_id-or-null|exp`, 10-minute TTL,
//!   stateless - no new secrets, no server-side storage.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::handlers::AppState;

/// Continuation token TTL (seconds) - matches the `/oauth/login` context
/// blob's 10-minute window: the credential step must start promptly.
pub const CONTINUATION_TTL_SECS: i64 = 600;

/// The null-user marker inside a synthetic (unknown-email) token.
const NULL_USER: &str = "\u{0}null";

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for sign-in identify.
pub struct IdentifyRequest {
    /// The email address the user wants to sign in with.
    pub email: String,
}

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for sign-in identify.
pub struct IdentifyResponse {
    /// HMAC-signed continuation token (email|env_id|user_id|exp). Opaque
    /// to the client; consumed by the passkey-first begin endpoint.
    pub continuation_token: String,
    /// Auth methods the account can use, in preference order.
    /// `password` is always present (bcrypt accounts always have one);
    /// `passkey` appears when an active WebAuthn factor exists.
    pub methods: Vec<String>,
    /// True when the account has an active TOTP factor - the credential
    /// step can label the MFA expectation before the password is typed.
    pub mfa_required: bool,
}

/// The verified continuation payload - the identify answer for the
/// credential step's own use (passkey begin).
#[derive(Debug, Clone)]
pub struct Continuation {
    /// The email the user identified with.
    pub email: String,
    /// The tenant environment the lookup was scoped to.
    pub env_id: Uuid,
    /// The user id (None on a synthetic token for an unknown email).
    pub user_id: Option<Uuid>,
}

fn continuation_key() -> Vec<u8> {
    // Same key material as the /oauth/login context blobs (login_page.rs
    // context_key): the master key posture (dev default when unset) is
    // shared on purpose - one rotation surface for auth's HMAC blobs.
    crate::login_page::context_key_public()
}

/// Build the signed continuation blob: `payload|sig` where the payload is
/// `email|\u1|env_id|\u1|user_id-or-\u0null|\u1|exp`.
fn sign_continuation(email: &str, env_id: Uuid, user_id: Option<Uuid>, exp: i64) -> String {
    let user_part = user_id
        .map(|u| u.to_string())
        .unwrap_or_else(|| NULL_USER.to_string());
    let payload = format!("{email}\u{1}{env_id}\u{1}{user_part}\u{1}{exp}");
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&continuation_key())
        .expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    use base64::Engine;
    let sig =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{payload}|{sig}")
}

/// Verify + unpack a continuation blob. Returns `None` on any signature
/// mismatch, malformed shape, or expiry (the caller treats it as an
/// invalid identifier step - back to email entry).
pub fn verify_continuation(blob: &str) -> Option<Continuation> {
    let (payload, sig) = blob.rsplit_once('|')?;
    use base64::Engine;
    let expected = {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&continuation_key())
            .expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    };
    if !constant_time_eq(expected.as_bytes(), sig.as_bytes()) {
        return None;
    }
    let parts: Vec<&str> = payload.split('\u{1}').collect();
    if parts.len() != 4 {
        return None;
    }
    let exp: i64 = parts[3].parse().ok()?;
    if Utc::now().timestamp() > exp {
        return None;
    }
    let env_id = Uuid::parse_str(parts[1]).ok()?;
    let user_id = if parts[2] == NULL_USER {
        None
    } else {
        Some(Uuid::parse_str(parts[2]).ok()?)
    };
    Some(Continuation {
        email: parts[0].to_string(),
        env_id,
        user_id,
    })
}

/// Constant-time byte comparison (import parity with login_page.rs).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `POST /v1/sign-in/identify` - the identifier-first step.
///
/// Email-only: answers the auth-method hints for the account and a
/// continuation token. Bot-gated with the same windows as sign-in; never
/// locks or records failures (credential steps own those).
#[utoipa::path(
    post,
    path = "/v1/sign-in/identify",
    request_body = IdentifyRequest,
    responses(
        (status = 200, description = "Identify answer: continuation token + auth-method hints (same shape for unknown emails)", body = IdentifyResponse),
        (status = 400, description = "Email is required"),
        (status = 429, description = "Identify rate limit (the same bot-protection windows as sign-in) exceeded"),
    ),
    security(),
    tag = "auth",
)]
pub async fn identify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IdentifyRequest>,
) -> Result<Response, (StatusCode, String)> {
    let email = req.email.trim().to_lowercase();
    if email.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "email is required".into()));
    }

    // Same per-IP + per-email windows as the sign-in credential step.
    let ip = crate::bot_protection::extract_client_ip(&headers);
    crate::bot_protection::check_signin_rate(&state, &ip, &email).await?;

    // Tenant resolution + env-scoped lookup (the same email can exist as
    // a different user in each tenant, so the lookup is env-scoped - the
    // comment in sign_in applies verbatim).
    let (_org_id, env_id) =
        crate::handlers::resolve_tenant_from_headers(&state.pool, &headers).await;

    let user: Option<(Uuid, String)> = {
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        let row = sqlx::query(
            r#"SELECT id, status FROM users WHERE email = $1 AND env_id = $2"#,
        )
        .bind(&email)
        .bind(env_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = tx.commit().await;
        row.map(|r| (r.get::<uuid::Uuid, _>("id"), r.get::<String, _>("status")))
    };

    let exp = (Utc::now() + Duration::seconds(CONTINUATION_TTL_SECS)).timestamp();

    // Per-user hints for known accounts (IDFIRST-1 disclosure posture,
    // DESIGN §5): methods + mfa_required reflect the real factors. For an
    // unknown email the SAME shape answers with the default password-only
    // hint over a null user - a valid signature, indistinguishable shape.
    let (user_id, methods, mfa_required) = match user {
        Some((uid, status)) => {
            if status != "active" {
                // Locked/disabled accounts get the default shape too - the
                // credential step surfaces the real status (403), identify
                // only routes the UI.
                (None, vec!["password".to_string()], false)
            } else {
                let has_passkey: bool = sqlx::query_scalar(
                    r#"SELECT EXISTS(
                         SELECT 1 FROM mfa_factors
                          WHERE user_id = $1 AND factor_kind = 'webauthn'
                            AND status = 'active')"#,
                )
                .bind(uid)
                .fetch_one(&state.pool)
                .await
                .unwrap_or(false);
                let has_totp: bool = sqlx::query_scalar(
                    r#"SELECT EXISTS(
                         SELECT 1 FROM mfa_factors
                          WHERE user_id = $1 AND factor_kind = 'totp'
                            AND status = 'active')"#,
                )
                .bind(uid)
                .fetch_one(&state.pool)
                .await
                .unwrap_or(false);
                let mut methods = vec!["password".to_string()];
                if has_passkey {
                    methods.push("passkey".to_string());
                }
                (Some(uid), methods, has_totp)
            }
        }
        None => (None, vec!["password".to_string()], false),
    };

    let continuation_token = sign_continuation(&email, env_id, user_id, exp);

    Ok(Json(IdentifyResponse {
        continuation_token,
        methods,
        mfa_required,
    })
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(user_id: Option<Uuid>) {
        let email = "user@example.test";
        let env_id = Uuid::new_v4();
        let exp = Utc::now().timestamp() + CONTINUATION_TTL_SECS;
        let blob = sign_continuation(email, env_id, user_id, exp);
        let c = verify_continuation(&blob).expect("valid blob verifies");
        assert_eq!(c.email, email);
        assert_eq!(c.env_id, env_id);
        assert_eq!(c.user_id, user_id);
    }

    #[test]
    fn continuation_roundtrip_known_user() {
        roundtrip(Some(Uuid::new_v4()));
    }

    #[test]
    fn continuation_roundtrip_null_user() {
        roundtrip(None);
    }

    #[test]
    fn continuation_tamper_rejected() {
        let blob = sign_continuation(
            "user@example.test",
            Uuid::new_v4(),
            Some(Uuid::new_v4()),
            Utc::now().timestamp() + CONTINUATION_TTL_SECS,
        );
        let tampered = format!("{}x", blob.trim_end_matches('0'));
        assert!(verify_continuation(&tampered).is_none());
    }

    #[test]
    fn continuation_expiry_rejected() {
        let blob = sign_continuation(
            "user@example.test",
            Uuid::new_v4(),
            None,
            Utc::now().timestamp() - 1,
        );
        assert!(verify_continuation(&blob).is_none());
    }
}
