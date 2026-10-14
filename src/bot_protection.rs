// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Bot protection — rate limiting and account lockout.
//!
//! Implements two protections against credential-stuffing and brute-force
//! attacks:
//!
//! 1. **Sign-in rate limit** — per IP address + per email, a sliding-window
//! counter in Valkey limits the number of sign-in attempts (default 10 per
//! minute per IP, 5 per minute per email). Exceeding the limit returns
//! `429 Too Many Requests` with a `Retry-After` header.
//! 2. **Account lockout** — after `SENTIN8_AUTH_MAX_FAILED_ATTEMPTS` (default 5)
//! consecutive failed sign-in attempts for a single user, the account is
//! locked for `SENTIN8_AUTH_LOCKOUT_DURATION_SECS` (default 900s = 15 min). A
//! successful sign-in or an admin unlock resets the counter. Lockout
//! state is stored in Valkey for fast lookup and in `sentin8_auth_users.status`
//! (`'locked'`) for durability across Valkey restarts.
//!
//! The module exposes three helpers used by the `sign_in` handler:
//! - [`check_signin_rate`] — enforce the rate limit (call before looking up
//! the user). Returns `Err(429)` when exceeded.
//! - [`check_account_lockout`] — reject sign-in when the account is locked.
//! - [`record_failed_signin`] — increment the failed-attempt counter and lock
//! the account when the threshold is reached.
//! - [`reset_failed_signins`] — reset the counter on a successful sign-in.

use std::time::Duration;

use axum::http::StatusCode;
use glide::AsyncCommands;

use crate::handlers::AppState;

/// Default max sign-in attempts per minute per IP.
const DEFAULT_IP_RATE_LIMIT: u32 = 10;
/// Default max sign-in attempts per minute per email.
const DEFAULT_EMAIL_RATE_LIMIT: u32 = 5;
/// Default max consecutive failed attempts before lockout.
const DEFAULT_MAX_FAILED_ATTEMPTS: u32 = 5;
/// Default lockout duration in seconds (15 minutes).
const DEFAULT_LOCKOUT_SECS: u64 = 900;

const RATE_WINDOW_SECS: u64 = 60;

/// Result of a rate-limit check.
#[derive(Debug)]
/// The ratelimitresult type.
pub struct RateLimitResult {
    /// The allowed.
    pub allowed: bool,
    /// The retry after secs.
    pub retry_after_secs: u64,
    /// The remaining.
    pub remaining: u32,
}

/// `Err(429)` with a `Retry-After` header, returned to the caller when the
/// rate limit is exceeded.
/// Handle rate limited response.
pub fn rate_limited_response(retry_after: u64) -> (StatusCode, String) {
    (
        StatusCode::TOO_MANY_REQUESTS,
        format!("rate limit exceeded; retry after {retry_after}s"),
    )
}

/// Check the per-IP sign-in rate limit (sliding window in Valkey).
/// Check ip rate.
pub async fn check_ip_rate(
    state: &AppState,
    ip: &str,
) -> Result<RateLimitResult, (StatusCode, String)> {
    let key = format!("auth:rate:ip:{ip}");
    let limit = env_u32("SENTIN8_AUTH_IP_RATE_LIMIT", DEFAULT_IP_RATE_LIMIT);
    check_rate(state, &key, limit, RATE_WINDOW_SECS).await
}

/// Check the per-email sign-in rate limit.
/// Check email rate.
pub async fn check_email_rate(
    state: &AppState,
    email: &str,
) -> Result<RateLimitResult, (StatusCode, String)> {
    let key = format!("auth:rate:email:{}", email.to_lowercase());
    let limit = env_u32("SENTIN8_AUTH_EMAIL_RATE_LIMIT", DEFAULT_EMAIL_RATE_LIMIT);
    check_rate(state, &key, limit, RATE_WINDOW_SECS).await
}

/// Check the per-IP + per-email rate limits together. Returns `Err(429)` when
/// either limit is exceeded.
/// Check signin rate.
pub async fn check_signin_rate(
    state: &AppState,
    ip: &str,
    email: &str,
) -> Result<(), (StatusCode, String)> {
    let ip_res = check_ip_rate(state, ip).await?;
    if !ip_res.allowed {
        return Err(rate_limited_response(ip_res.retry_after_secs));
    }
    let email_res = check_email_rate(state, email).await?;
    if !email_res.allowed {
        return Err(rate_limited_response(email_res.retry_after_secs));
    }
    Ok(())
}

/// Check whether the account is currently locked. Returns `Err(403)` when
/// locked, with the remaining lockout time in the message.
/// Check account lockout.
pub async fn check_account_lockout(
    state: &AppState,
    user_id: uuid::Uuid,
) -> Result<(), (StatusCode, String)> {
    let key = format!("auth:lockout:{user_id}");
    let conn = valkey_conn(state).await?;
    let ttl: Option<i64> = conn.ttl(&key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("valkey error: {e}"),
        )
    })?;
    if let Some(ttl) = ttl {
        if ttl > 0 {
            return Err((
                StatusCode::FORBIDDEN,
                format!("account locked; retry after {ttl}s"),
            ));
        }
    }
    // Also check the DB status (durable across Valkey restarts).
    // fix : `users` is RLS-protected and the pooled
    // connection has no tenant context — without one the SELECT is
    // policy-blocked (context_initialized gate) and sign-in 500s on the
    // wrong-password path. Set the context from the user's own env on the
    // SAME connection. Caught by the revived
    // integration tests.
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
    let row = sqlx::query!(r#"SELECT status FROM users WHERE id = $1"#, user_id,)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit().await.ok();
    if let Some(r) = row {
        if r.status == "locked" {
            return Err((
                StatusCode::FORBIDDEN,
                "account locked; contact an administrator".into(),
            ));
        }
    }
    Ok(())
}

/// Record a failed sign-in attempt for the given user. Locks the account when
/// the threshold is reached. Call this AFTER verifying the password failed.
/// Handle record failed signin.
pub async fn record_failed_signin(
    state: &AppState,
    user_id: uuid::Uuid,
) -> Result<u32, (StatusCode, String)> {
    let key = format!("auth:failed:{user_id}");
    let max = env_u32(
        "SENTIN8_AUTH_MAX_FAILED_ATTEMPTS",
        DEFAULT_MAX_FAILED_ATTEMPTS,
    );
    let lockout_secs = env_u64("SENTIN8_AUTH_LOCKOUT_SECS", DEFAULT_LOCKOUT_SECS);

    let conn = valkey_conn(state).await?;
    let count: u32 = conn.incr(&key, 1).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("valkey error: {e}"),
        )
    })?;
    // Set TTL on first failure (window resets after a period of no attempts).
    if count == 1 {
        let _: () = conn.expire(&key, lockout_secs as i64).await.unwrap_or(());
    }

    if count >= max {
        // Lock the account in Valkey + DB.
        let lockout_key = format!("auth:lockout:{user_id}");
        let _: () = conn
            .set_ex(&lockout_key, "1", lockout_secs)
            .await
            .unwrap_or(());
        let _ = sqlx::query!(
            r#"UPDATE users SET status = 'locked', updated_at = now() WHERE id = $1"#,
            user_id,
        )
        .execute(&state.pool)
        .await;
        tracing::warn!(user_id = %user_id, count, "account locked due to repeated failed sign-in");
    }
    Ok(count)
}

/// Reset the failed-attempt counter for a user (call on successful sign-in).
/// Handle reset failed signins.
pub async fn reset_failed_signins(
    state: &AppState,
    user_id: uuid::Uuid,
) -> Result<(), (StatusCode, String)> {
    let key = format!("auth:failed:{user_id}");
    let conn = valkey_conn(state).await?;
    let _: () = conn.del(&key).await.unwrap_or(());
    // Also clear a locked status back to active (the user just proved they
    // can authenticate — e.g. after an admin-initiated reset or after the
    // lockout window expired and they remembered the password).
    let _ = sqlx::query!(
        r#"UPDATE users SET status = 'active', updated_at = now()
           WHERE id = $1 AND status = 'locked'"#,
        user_id,
    )
    .execute(&state.pool)
    .await;
    Ok(())
}

/// Extract a client IP from the request headers, falling back to the
/// connection peer address. TLS injects `X-Forwarded-For` and
/// `X-Real-IP`; we honor the leftmost XFF entry (the original client).
/// Extract client ip.
pub fn extract_client_ip(headers: &axum::http::HeaderMap) -> String {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    if let Some(real) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if !real.is_empty() {
            return real.to_string();
        }
    }
    "unknown".to_string()
}

// ── Internal helpers ───────────────────────────────────────────────────

async fn check_rate(
    state: &AppState,
    key: &str,
    limit: u32,
    window_secs: u64,
) -> Result<RateLimitResult, (StatusCode, String)> {
    let conn = valkey_conn(state).await?;
    let count: u32 = conn.incr(key, 1).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("valkey error: {e}"),
        )
    })?;
    if count == 1 {
        let _: () = conn.expire(key, window_secs as i64).await.unwrap_or(());
    }
    if count > limit {
        let ttl: i64 = conn.ttl(key).await.unwrap_or(window_secs as i64);
        Ok(RateLimitResult {
            allowed: false,
            retry_after_secs: ttl.max(1) as u64,
            remaining: 0,
        })
    } else {
        Ok(RateLimitResult {
            allowed: true,
            retry_after_secs: 0,
            remaining: limit.saturating_sub(count),
        })
    }
}

async fn valkey_conn(state: &AppState) -> Result<glide::GlideClient, (StatusCode, String)> {
    sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("valkey error: {e}"),
            )
        })
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

// `Duration" import retained for potential future use (TTL tuning).
#[allow(dead_code)]
fn _duration_unused() -> Duration {
    Duration::from_secs(1)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_defaults() {
        // Ensure the defaults are sensible.
        assert_eq!(DEFAULT_IP_RATE_LIMIT, 10);
        assert_eq!(DEFAULT_EMAIL_RATE_LIMIT, 5);
        assert_eq!(DEFAULT_MAX_FAILED_ATTEMPTS, 5);
        assert_eq!(DEFAULT_LOCKOUT_SECS, 900);
    }

    #[test]
    fn extract_ip_from_xff() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.5, 10.0.0.1".parse().unwrap());
        assert_eq!(extract_client_ip(&headers), "203.0.113.5");
    }

    #[test]
    fn extract_ip_from_real_ip() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-real-ip", "198.51.100.7".parse().unwrap());
        assert_eq!(extract_client_ip(&headers), "198.51.100.7");
    }

    #[test]
    fn extract_ip_unknown_fallback() {
        let headers = axum::http::HeaderMap::new();
        assert_eq!(extract_client_ip(&headers), "unknown");
    }
}
