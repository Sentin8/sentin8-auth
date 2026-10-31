// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Session management - create, verify, refresh, revoke.
//!
//! Auth sessions are stored in PostgreSQL (`sentin8_auth_sessions`) and
//! referenced by an opaque `__session` cookie (cross-subdomain, HttpOnly).

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Session cookie name.
/// The session cookie constant.
pub const SESSION_COOKIE: &str = "__session";

/// Session row in `sentin8_auth_sessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
/// The session type.
pub struct Session {
    /// Identifier.
    pub id: Uuid,
    /// user identifier.
    pub user_id: Uuid,
    /// env identifier.
    pub env_id: Uuid,
    /// token identifier.
    pub token_id: String,
    /// The refresh token.
    pub refresh_token: Option<String>,
    /// The status.
    pub status: String,
    /// expires time.
    pub expires_at: DateTime<Utc>,
    /// created time.
    pub created_at: DateTime<Utc>,
    /// updated time.
    pub updated_at: DateTime<Utc>,
}

impl Session {
    /// Insert a new session into the database.
    ///
    /// Accepts any executor (pool or transaction connection) so callers can
    /// set the tenant context on the same connection first.
    ///
    /// The `status` parameter is the INITIAL state: `"active"` for a
    /// fully-authenticated sign-in, `"pending_mfa"` for a TOTP-enrolled
    /// user whose session exists only to complete the MFA challenge
    /// (DESIGN §3 "Session pending-MFA contract" - a pending row is a
    /// capability to finish MFA, never a valid session; `/v1/mfa/verify`
    /// is the only transition to `active`).
    /// Create it.
    pub async fn create_with_status<'e, E>(
        executor: E,
        user_id: Uuid,
        env_id: Uuid,
        token_id: &str,
        refresh_token: Option<&str>,
        ttl: Duration,
        status: &str,
    ) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let expires_at = Utc::now() + ttl;
        let row = sqlx::query_as!(
            Session,
            r#"INSERT INTO sessions
                 (user_id, env_id, token_id, refresh_token, status, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6)
               RETURNING
                 id, user_id, env_id, token_id,
                 refresh_token, status, expires_at, created_at, updated_at"#,
            user_id,
            env_id,
            token_id,
            refresh_token,
            status,
            expires_at,
        )
        .fetch_one(executor)
        .await?;

        Ok(row)
    }

    /// Insert a new ACTIVE session (the no-MFA sign-in path).
    /// Create it active.
    pub async fn create<'e, E>(
        executor: E,
        user_id: Uuid,
        env_id: Uuid,
        token_id: &str,
        refresh_token: Option<&str>,
        ttl: Duration,
    ) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        Self::create_with_status(executor, user_id, env_id, token_id, refresh_token, ttl, "active")
            .await
    }

    /// Activate a `pending_mfa` session (the `/v1/mfa/verify` challenge
    /// consumption path, DESIGN §3). A no-op for already-active rows;
    /// never revives a revoked/expired one.
    /// Activate it.
    pub async fn activate<'e, E>(executor: E, token_id: &str) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query!(
            r#"UPDATE sessions
                 SET status = 'active', updated_at = now()
               WHERE token_id = $1 AND status = 'pending_mfa'"#,
            token_id,
        )
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Look up a session by token_id (the cookie value).
    ///
    /// RLS : `auth.sessions` is FORCE-RLS under NOBYPASSRLS service
    /// roles, and the lookup runs BEFORE any tenant context exists (the
    /// session's env is only known AFTER the row is found). The lookup is
    /// therefore a two-step, single-transaction resolve:
    /// 1. under a SYSTEM-context tx, resolve the session's `env_id` by
    ///
    /// token (a token id is a random 128-bit secret - the SYSTEM step
    /// leaks nothing a caller doesn't already hold: you must already
    /// possess the token to use it);
    /// 2. re-set the context to THAT env and fetch the full row under
    ///
    /// the session's own tenant policy.
    ///
    /// `set_config(..., true)` is transaction-local - both steps share one
    /// `pool.begin` ( rule 2).
    ///
    /// Handle find by token.
    pub async fn find_by_token(pool: &PgPool, token_id: &str) -> Result<Option<Self>, sqlx::Error> {
        let mut tx = pool.begin().await?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(crate::config::SYSTEM_ENV_ID)
            .execute(&mut *tx)
            .await;
        let env_id: Option<uuid::Uuid> = sqlx::query_scalar(
            r#"SELECT env_id FROM sessions
                WHERE token_id = $1 AND status = 'active'"#,
        )
        .bind(token_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(env_id) = env_id else {
            // Token unknown or inactive - rollback (no partial context).
            tx.rollback().await.ok();
            return Ok(None);
        };
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        let row = sqlx::query_as!(
            Session,
            r#"SELECT
                 id, user_id, env_id, token_id,
                 refresh_token, status, expires_at, created_at, updated_at
               FROM sessions
               WHERE token_id = $1 AND status = 'active'"#,
            token_id,
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.rollback().await.ok(); // read-only - nothing to commit
        Ok(row)
    }

    /// Revoke a session by token_id and emit `sentin8:auth:session:revoked`.
    ///
    /// The revocation UPDATE and the outbox row land in one transaction
    /// (outbox-first §6.7 - design DESIGN.md §10): the relay drains
    /// `auth.outbox` to Bus `POST /v1/produce`, and BFF's session-reaper
    /// subscription kills the cached BFF session for the subject. Best-effort
    /// at the emit's own tolerance: a failed outbox write rolls back ONLY the
    /// event, never blocks the revocation the caller already observed.
    /// Revoke it.
    pub async fn revoke(pool: &PgPool, token_id: &str) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;
        // Resolve the session first (RLS: look up under a SYSTEM-context step
        // mirroring find_by_token, then re-set the session's own env for the
        // UPDATE and the outbox row).
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(crate::config::SYSTEM_ENV_ID)
            .execute(&mut *tx)
            .await;
        let row: Option<(Uuid, Uuid)> =
            sqlx::query_as("SELECT user_id, env_id FROM sessions WHERE token_id = $1")
                .bind(token_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((user_id, env_id)) = row else {
            tx.rollback().await.ok(); // read-only - nothing to commit
            return Ok(());
        };
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        sqlx::query!(
            r#"UPDATE sessions SET status = 'revoked', updated_at = now()
               WHERE token_id = $1"#,
            token_id,
        )
        .execute(&mut *tx)
        .await?;
        // Payload-complete envelope (event-first §4.3): subject + env + the
        // revoked session's token id.
        let _ = crate::events::emit_session_revoked(
            &mut tx,
            env_id,
            &user_id.to_string(),
            Some(token_id),
            "user_signout",
        )
        .await;
        tx.commit().await?;
        Ok(())
    }

    /// True if the session is still active and not expired.
    /// Handle is valid.
    pub fn is_valid(&self) -> bool {
        self.status == "active" && self.expires_at > Utc::now()
    }

    /// Build the Set-Cookie header value for this session.
    ///
    /// `cookie_domain` should be the registrable domain of the request host
    /// (e.g. `ibank.local` for `auth.ibank.local`, `local.sentin8.dev` for
    /// `sentin8-auth.ops.sys.local.sentin8.dev`) so the cookie is shared across the tenant's
    /// subdomains. Use [crate::sessions::cookie_domain_for_host] to derive it
    /// from the request's `Host` header.
    /// Handle cookie.
    pub fn cookie(&self, cookie_domain: &str) -> String {
        let max_age = (self.expires_at - Utc::now()).num_seconds().max(0);
        format!(
            "{}={}; Path=/; Domain=.{cookie_domain}; HttpOnly; Secure; SameSite=None; Max-Age={}",
            SESSION_COOKIE, self.token_id, max_age
        )
    }

    /// Build a cookie header that clears the session cookie.
    /// Handle clear cookie.
    pub fn clear_cookie(cookie_domain: &str) -> String {
        format!(
            "{}=; Path=/; Domain=.{cookie_domain}; HttpOnly; Secure; SameSite=None; Max-Age=0",
            SESSION_COOKIE
        )
    }
}

/// Resolve a user's `env_id` - the RLS-correct lookup used by handlers that
/// must derive a user's tenant BEFORE setting context (MFA enroll/verify,
/// passkey finish, code exchange). `auth.users` is FORCE-RLS under
/// NOBYPASSRLS service roles, so a context-less
/// `SELECT env_id FROM users WHERE id` returns no row. Same two-step
/// single-transaction pattern as `find_by_token`: resolve the env under a
/// SYSTEM-context step (the caller already holds the user id from a
/// verified session), then confirm the row under the user's own tenant
/// policy.
/// Handle user env.
pub async fn user_env(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Uuid, (axum::http::StatusCode, String)> {
    let err500 = |e: sqlx::Error| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    let mut tx = pool.begin().await.map_err(err500)?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(crate::config::SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;
    let env_id: Option<Uuid> = sqlx::query_scalar(r#"SELECT env_id FROM users WHERE id = $1"#)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(err500)?;
    let Some(env_id) = env_id else {
        tx.rollback().await.ok();
        return Err((axum::http::StatusCode::NOT_FOUND, "user not found".into()));
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let confirmed: Option<Uuid> = sqlx::query_scalar(r#"SELECT env_id FROM users WHERE id = $1"#)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(err500)?;
    tx.rollback().await.ok(); // read-only lookup
    confirmed.ok_or_else(|| (axum::http::StatusCode::NOT_FOUND, "user not found".into()))
}

/// Derive the cookie domain from the request host.
///
/// For a tenant custom auth domain like `auth.ibank.local`, returns
/// `ibank.local` so the `__session` cookie is visible on all `*.ibank.local`
/// subdomains. For the platform auth domain `auth.ops.sys.local.sentin8.dev`, returns
/// `local.sentin8.dev`. Falls back to `fallback` (the config `sentin8_domain`) when
/// the host is empty or has fewer than three labels.
/// Handle cookie domain for host.
pub fn cookie_domain_for_host(host: &str, fallback: &str) -> String {
    // Strip port if present.
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    if host.is_empty() {
        return fallback.to_string();
    }
    let labels: Vec<&str> = host.split('.').collect();
    // Need at least 3 labels (e.g. `auth.ibank.local`) to strip the first
    // label and use the remaining registrable + TLD labels.
    if labels.len() < 3 {
        return fallback.to_string();
    }
    labels[1..].join(".")
}

/// Derive the cookie domain from request headers, preferring the
/// `X-Sentin8-Hostname` header (injected by TLS with the original client
/// hostname) and falling back to the `Host` header. This ensures the
/// `__session` cookie gets the correct registrable domain for tenant
/// custom auth domains (e.g. `auth.ibank.local` → `.ibank.local`) rather
/// than the hardcoded `sentin8_domain` (which the browser would reject
/// because it doesn't domain-match the response host).
/// Handle cookie domain from headers.
pub fn cookie_domain_from_headers(headers: &axum::http::HeaderMap, fallback: &str) -> String {
    let host = headers
        .get("x-sentin8-hostname")
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get("host").and_then(|v| v.to_str().ok()))
        .unwrap_or("");
    cookie_domain_for_host(host, fallback)
}
