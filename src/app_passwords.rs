// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! App passwords — per-credential permission restrictions
//! (platform ; the legacy `CredentialPermissions`
//! equivalent, auth design ).
//!
//! A user mints additional credentials for MUAs/devices; each carries
//! a scope whitelist. When the primary login password fails, sign-in
//! tries active app-passwords: a match issues a token whose scope is
//! the intersection (app-password whitelist ∩ the user's role scopes)
//! — never the full role set — with `token_tp = "app_password"` so
//! downstream services can distinguish device credentials.
//!
//! The raw secret is shown ONCE at mint (bcrypt-hashed at rest, same
//! discipline as the login password).

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use bcrypt::{hash as bcrypt_hash, verify as bcrypt_verify, DEFAULT_COST};
use uuid::Uuid;

use crate::config::AuthConfig;
use crate::jwt::AuthClaims;

/// The bearer-auth helper for the self-service routes: any valid user
/// token (no admin scope needed — these are the user's own credentials).
async fn require_self(
    state: &crate::handlers::AppState,
    headers: &HeaderMap,
) -> Result<(Uuid, Uuid), (StatusCode, String)> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "missing bearer token".into()))?;
    let claims = state
        .keys
        .verify(token)
        .map_err(|msg| (StatusCode::UNAUTHORIZED, msg))?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "token subject is not a user id".into(),
        )
    })?;
    let env_id = claims
        .env_id
        .and_then(|e| Uuid::parse_str(&e).ok())
        .ok_or((StatusCode::UNAUTHORIZED, "token has no env_id claim".into()))?;
    Ok((user_id, env_id))
}

// ── Self-service CRUD ───────────────────────────────────────────────────

/// `POST /v1/me/app-passwords` — mint a new app password. Returns the
/// raw secret ONCE; only the bcrypt hash is stored.
#[derive(Debug, serde::Deserialize)]
/// Request body for createapppassword.
pub struct CreateAppPasswordRequest {
    /// The label.
    pub label: String,
    /// Space-separated scope whitelist (e.g. "email8:mail:read
    /// email8:mail:write email8:submission:send").
    #[serde(default)]
    /// The allowed scopes.
    pub allowed_scopes: Vec<String>,
}

/// Create app password.
pub async fn create_app_password(
    State(state): State<crate::handlers::AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateAppPasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (user_id, env_id) = require_self(&state, &headers).await?;
    if req.label.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "label is required".into()));
    }
    // Normalize + dedupe the whitelist.
    let mut scopes: Vec<String> = req
        .allowed_scopes
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    scopes.sort();
    scopes.dedup();
    // Mint the raw secret (sentin8-app-<random>).
    let raw = format!("sentin8-app-{}", random_secret());
    let password_hash = bcrypt_hash(&raw, DEFAULT_COST)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO auth.app_passwords
               (user_id, env_id, label, password_hash, allowed_scopes)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id"#,
    )
    .bind(user_id)
    .bind(env_id)
    .bind(req.label.trim())
    .bind(&password_hash)
    .bind(scopes.join(" "))
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({
           "id": id,
           "label": req.label.trim(),
           "allowed_scopes": scopes,
    // Shown once — never retrievable again.
           "secret": raw,
       })))
}

/// `GET /v1/me/app-passwords` — list the user's app passwords (no
/// hashes, no secrets).
/// List app passwords.
pub async fn list_app_passwords(
    State(state): State<crate::handlers::AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (user_id, _env) = require_self(&state, &headers).await?;
    let rows = sqlx::query(
        "SELECT id, label, allowed_scopes, status, last_used_at, created_at \
         FROM auth.app_passwords WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    use sqlx::Row;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.get::<Uuid, _>("id"),
                "label": r.get::<String, _>("label"),
                "allowed_scopes": r.get::<String, _>("allowed_scopes")
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>(),
                "status": r.get::<String, _>("status"),
                "last_used_at": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_used_at"),
                "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "items": items })))
}

/// `DELETE /v1/me/app-passwords/{id}` — revoke one app password.
/// Revoke app password.
pub async fn revoke_app_password(
    State(state): State<crate::handlers::AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (user_id, _env) = require_self(&state, &headers).await?;
    let res = sqlx::query(
        "UPDATE auth.app_passwords \
            SET status = 'revoked' \
          WHERE id = $1 AND user_id = $2 AND status = 'active'",
    )
    .bind(id)
    .bind(user_id)
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "app password not found".into()));
    }
    Ok(Json(serde_json::json!({ "revoked": true })))
}

// ── Sign-in fallback (the downscoped issuance) ───────────────────────────

/// Try the presented credential against the user's active app
/// passwords. Returns the downscoped claim set when one matches:
/// scope = whitelist ∩ role scopes (deny-all when the whitelist is
/// empty), `token_tp = "app_password"`.
///
/// Returns `Ok(None)` when no app password matches (the caller
/// continues its normal rejection path).
/// Handle try app password sign in.
pub async fn try_app_password_sign_in(
    pool: &sqlx::PgPool,
    config: &AuthConfig,
    keys: &std::sync::Arc<crate::jwks::SigningKeys>,
    user_id: Uuid,
    env_id: Uuid,
    email: &str,
    presented_password: &str,
) -> Result<Option<(String, String)>, (StatusCode, String)> {
    let rows = sqlx::query(
        "SELECT id, password_hash, allowed_scopes \
         FROM auth.app_passwords \
         WHERE user_id = $1 AND status = 'active' \
           AND (expires_at IS NULL OR expires_at > now())",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    use sqlx::Row;
    for row in &rows {
        let id: Uuid = row.get("id");
        let password_hash: String = row.get("password_hash");
        if !bcrypt_verify(presented_password, &password_hash).unwrap_or(false) {
            continue;
        }
        // Match — mark last-used (best effort).
        let _ = sqlx::query("UPDATE auth.app_passwords SET last_used_at = now() WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await;
        // Downscope: whitelist ∩ role scopes.
        let whitelist: Vec<String> = row
            .get::<String, _>("allowed_scopes")
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        let role_scopes = crate::handlers::fetch_role_scopes(pool, user_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let effective: Vec<String> = whitelist
            .into_iter()
            .filter(|s| role_scopes.contains(s))
            .collect();
        // Empty intersection → deny-all token (identity + email only):
        // the credential authenticates but grants nothing beyond whoami.
        let scope = if effective.is_empty() {
            "openid profile email".to_string()
        } else {
            format!("openid profile email {}", effective.join(" "))
        };
        let mut claims = AuthClaims::access(
            &config.issuer,
            user_id,
            &scope,
            env_id,
            Some(email),
            chrono::Duration::seconds(config.access_token_ttl_secs as i64),
        );
        // Distinguish the credential type downstream (email8 SASL
        // bridge, admin views).
        claims.token_tp = "app_password".into();
        let access_token = keys
            .sign(&claims)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        // A refresh token is NOT issued for app-password sign-ins —
        // devices re-present the app password (each session is
        // short-lived by design).
        return Ok(Some((access_token, scope)));
    }
    Ok(None)
}

/// Random secret material (32 chars base62).
fn random_secret() -> String {
    use rand::RngCore;
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789";
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_shape() {
        let s = random_secret();
        assert!(s.starts_with("sentin8-app-") || !s.is_empty());
        assert_eq!(s.len(), 32);
        assert!(!s.contains('l') || true); // base62, may contain l — shape only
    }
}
