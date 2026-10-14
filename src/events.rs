// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//!— Bus event publication helpers for Auth.
//!
//! Provides [`emit_event`] for writing a row directly to the shared
//! `inbox` table. The Bus inbox relay (spawned in bus)
//! drains `inbox` and produces each event to Bus.
//!
//! `emit_event` is best-effort: it logs a warning on failure but never
//! returns an error, so it can be called after a successful domain write
//! without affecting the HTTP response. The inbox row is written in a
//! separate statement (not the domain transaction) — if the DB is down the
//! event is simply lost, which is acceptable for non-critical telemetry
//! events. For strict transactional guarantees, use
//! [`sentin8::bus::outbox::insert_inbox_row`] within the domain transaction instead.

use sqlx::PgPool;
use uuid::Uuid;

/// Append an event to the shared `inbox` table.
///
/// - `env_id` — tenant context (globally unique). Use `Uuid::nil` for
///
/// system-scoped operations with no tenant context.
/// - `event_type` — e.g. `"sentin8:auth:user:created"`.
/// - `payload` — the JSON event payload.
pub async fn emit_event(pool: &PgPool, env_id: Uuid, event_type: &str, payload: serde_json::Value) {
    // DBX : auth's LOCAL outbox (`auth.outbox`, RLS-enabled) — the
    // shell's relay pushes rows to Bus POST /v1/produce. The tenant context
    // is transaction-local (set_config …, true), so the context-set and the
    // INSERT must share ONE transaction — in autocommit the context
    // evaporates before the INSERT and RLS denies the write.
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, event_type = %event_type, "auth: failed to begin transaction for outbox event");
            return;
        }
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let _ = sqlx::query(
        "INSERT INTO outbox (env_id, event_type, stream_family, payload) VALUES ($1, $2, $3, $4)",
    )
    .bind(env_id)
    .bind(event_type)
    .bind("auth")
    .bind(&payload)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, event_type = %event_type, "auth: failed to emit outbox event");
        e
    });
    let _ = tx.commit().await;
}

// ── Session revocation (continuous access evaluation) ──────────────────

/// Build the payload-complete `sentin8:auth:session:revoked` envelope.
///
/// The BFF session-reaper consumes this event and kills every cached BFF
/// session for `subject_id`, so role/consent changes take effect
/// immediately instead of at TTL (design DESIGN.md §10). The envelope is
/// self-contained per the event-first rule — the consumer never calls
/// back: `subject_id`, `env_id`, `session_id` (when a single session was
/// revoked), `revoked_by`, and `reason`.
pub fn session_revoked_payload(
    subject_id: &str,
    env_id: &str,
    session_id: Option<&str>,
    revoked_by: &str,
    reason: &str,
) -> serde_json::Value {
    serde_json::json!({
        "subject_id": subject_id,
        "env_id": env_id,
        "session_id": session_id,
        "revoked_by": revoked_by,
        "reason": reason,
    })
}

/// Emit `sentin8:auth:session:revoked` onto the caller's transaction —
/// the outbox row commits atomically with the revocation UPDATE (§6.7).
///
/// Best-effort: a failed outbox write is logged and swallowed so the
/// revocation the caller is committing is never blocked.
pub async fn emit_session_revoked(
    tx: &mut sqlx::PgConnection,
    env_id: Uuid,
    subject_id: &str,
    session_id: Option<&str>,
    reason: &str,
) {
    let payload =
        session_revoked_payload(subject_id, &env_id.to_string(), session_id, "auth", reason);
    if let Err(e) = emit_event_tx(tx, env_id, "sentin8:auth:session:revoked", payload).await {
        tracing::warn!(error = %e, env_id = %env_id, "auth: failed to emit session:revoked event");
    }
}

/// SEC- — **transactional** inbox emission.
///
/// Writes the `inbox` row on the caller's open transaction connection,
/// so the domain change and the event are committed atomically (the
/// inbox-first pattern per AGENTS.md — the domain write and the inbox row
/// either both land or neither does). Handlers that already hold a
/// transaction for the domain mutation should call this instead of
/// [`emit_event`].
///
/// Sets the tenant context on the same connection first (`set_config` is
/// transaction-local — exactly what we want inside a tx).
pub async fn emit_event_tx(
    tx: &mut sqlx::PgConnection,
    env_id: Uuid,
    event_type: &str,
    payload: serde_json::Value,
) -> Result<(), sqlx::Error> {
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    sqlx::query(
        "INSERT INTO outbox (env_id, event_type, stream_family, payload) VALUES ($1, $2, $3, $4)",
    )
    .bind(env_id)
    .bind(event_type)
    .bind("auth")
    .bind(&payload)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

/// Emit the identity-cache invalidation event for an access-grant
/// mutation (auth DESIGN §7.1).
///
/// Policy consumers (every service's RoleResolver) are registered in the
/// SYSTEM env, so invalidation rides the SYSTEM-env `policy` stream; the
/// shell relay's single SYSTEM-scoped M2M workload cannot carry
/// tenant-env rows (Bus's produce gate rejects an `env_id` that differs
/// from the token env), so the row must carry the SYSTEM env itself and
/// the env to sweep rides the payload. The tenant context on the
/// caller's transaction is switched to SYSTEM for this INSERT
/// (`set_config` is transaction-local) and restored afterwards, so a
/// caller that follows with tenant-plane statements keeps its context.
///
/// Best-effort by contract: a failure logs and degrades to the
/// RoleResolver's 30s TTL — never blocks the domain mutation.
pub async fn emit_identity_invalidation_tx(
    tx: &mut sqlx::PgConnection,
    env_id: Uuid,
    user_id: Uuid,
    event_type: &str,
) {
    let result = async {
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(sentin8::config::SYSTEM_ENV_ID)
            .execute(&mut *tx)
            .await;
        sentin8::bus::outbox::insert_outbox_row(
            &mut *tx,
            sentin8::config::SYSTEM_ENV_ID,
            "policy",
            event_type,
            &serde_json::json!({ "env_id": env_id, "user_id": user_id }),
        )
        .await
        .map_err(|e| sqlx::Error::Configuration(e.to_string().into()))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        Ok::<(), sqlx::Error>(())
    }
    .await;
    if let Err(e) = result {
        tracing::error!(error = %e, %env_id, event_type,
            "auth: failed to emit identity invalidation (degrades to 30s TTL)");
    }
}

/// Insert a notification into auth's LOCAL `post_outbox` for the post
/// pusher to deliver (DBX / DBX-POST-3): the pusher drains it to
/// Sentin8:Post's `POST /v1/send` (M2M, `sentin8:post:write`). Used for
/// welcome emails, password reset notifications, MFA enrollment alerts.
/// Best-effort: logs a warning on failure, never returns an error.
pub async fn emit_post_notification(
    pool: &PgPool,
    env_id: Uuid,
    message_type: &str,
    category: &str,
    priority: &str,
    recipient_user_id: Option<Uuid>,
    recipient_email: Option<&str>,
    subject: &str,
    body: &str,
    metadata: serde_json::Value,
) {
    let mut conn = match pool.acquire().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "auth: failed to acquire connection for post notification");
            return;
        }
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *conn)
        .await;
    let _ = sqlx::query(
        r#"INSERT INTO post_outbox (env_id, message_type, category, priority,
           recipient_user_id, recipient_email, subject, body, metadata)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(env_id)
    .bind(message_type)
    .bind(category)
    .bind(priority)
    .bind(recipient_user_id)
    .bind(recipient_email)
    .bind(subject)
    .bind(body)
    .bind(&metadata)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, message_type = %message_type, "auth: failed to queue post notification");
        e
    });
}

/// Spawn the auth post pusher: drains `auth.post_outbox` and calls
/// Sentin8:Post `POST /v1/send` with an M2M token (`sentin8:post:write`).
/// Failures leave rows unpushed for the next pass — a Post outage never
/// drops notifications.
///
/// The `auth-post` M2M identity (`TokenSource` + Post HTTP client) is
/// resolved ONCE for the process lifetime and reused across passes — the
/// audit-pusher pattern (crates/audit §6.8). A per-pass
/// `register_or_load_m2m_client` load + credential probe + fresh mTLS
/// client would run two PQ TLS handshakes + two token POSTs every pass
/// whose transient allocations ratchet allocator arenas (auth DESIGN §7:
/// idle RSS growth). Stale identities re-establish through the token
/// source's own 401 single-flight self-heal (60s cooldown) — never by
/// rebuilding the client. First-pass DCR failure only retries (rows stay
/// queued), matching the pre-DCR first-boot behavior.
pub fn spawn_post_pusher(pool: PgPool, post_url: String, auth_issuer: String) {
    tokio::spawn(async move {
        // auth DESIGN §4.3f: the `auth-post` CERTIFICATE is
        // the identity — ensure it once (mint retries while Acme comes
        // up), then build the ONE cert-presenting client for the task
        // lifetime (connection reuse across passes; webhook relay
        // pattern — a per-pass client churns pools). No token exists on
        // this path; Post's TLS layer authenticates the handshake.
        let cert = loop {
            match sentin8::auth::m2m::ensure_workload_certificate(
                &auth_issuer,
                "auth-post",
                &sentin8::auth::m2m::platform_ca_path(),
            )
            .await
            {
                Ok(c) => break c,
                Err(e) => {
                    tracing::debug!(error = %e, "auth: post push certificate not ready yet");
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        };
        let mtls = sentin8::middleware::mtls::MtlsConfig::new(
            &cert.ca_cert_path,
            &cert.cert_path,
            &cert.key_path,
        );
        let client = match sentin8::middleware::mtls::build_mtls_client(&mtls) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "auth: post push transport build failed — pusher disabled");
                return;
            }
        };
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            if let Err(e) = drain_and_push_post(pool.clone(), &client, &post_url).await {
                tracing::warn!(error = %e, "auth: post notification push pass failed");
            }
        }
    });
}

/// One drain pass: fetch unpushed rows, push each to POST /v1/send, mark
/// pushed on 2xx. The HTTP client is the cert-presenting transport
/// provided by the caller (the process-lifetime `auth-post` identity —
/// — this function owns only DB access.
async fn drain_and_push_post(
    pool: PgPool,
    client: &reqwest::Client,
    post_url: &str,
) -> anyhow::Result<usize> {
    use sqlx::Row;
    let rows = sqlx::query(
        r#"SELECT id, env_id, message_type, category, priority,
                  recipient_user_id, recipient_email, subject, body, metadata
             FROM post_outbox WHERE pushed = false ORDER BY created_at LIMIT 50"#,
    )
    .fetch_all(&pool)
    .await?;
    let mut pushed = 0usize;
    for row in &rows {
        let env_id: Uuid = row.get("env_id");
        let payload = serde_json::json!({
            "message_type": row.get::<String, _>("message_type"),
            "category": row.get::<String, _>("category"),
            "priority": row.get::<String, _>("priority"),
            "recipient_user_id": row.get::<Option<Uuid>, _>("recipient_user_id"),
            "recipient_email": row.get::<Option<String>, _>("recipient_email"),
            "subject": row.get::<String, _>("subject"),
            "body": row.get::<String, _>("body"),
            "metadata": row.get::<serde_json::Value, _>("metadata"),
        });
        let resp = client
            .post(format!("{}/v1/send", post_url.trim_end_matches('/')))
            .header("X-Sentin8-Env-Id", env_id.to_string())
            .json(&payload)
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => {
                let id: Uuid = row.get("id");
                let _ = sqlx::query(
                    "UPDATE post_outbox SET pushed = true, pushed_at = now() WHERE id = $1",
                )
                .bind(id)
                .execute(&pool)
                .await;
                pushed += 1;
            }
            Ok(r) => {
                tracing::warn!(status = %r.status(), "auth: post send rejected — will retry");
            }
            Err(e) => {
                tracing::warn!(error = %e, "auth: post send failed — will retry");
            }
        }
    }
    Ok(pushed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The envelope the BFF session-reaper parses — the exact JSON shape is
    /// a cross-service contract (auth DESIGN §10 → bff DESIGN §10), so the
    /// builder's output is pinned here.
    #[test]
    fn session_revoked_payload_shape() {
        let payload = session_revoked_payload(
            "0192f0a1-1111-7000-8000-000000000001",
            "0192f0a1-2222-7000-8000-000000000002",
            Some("tok_abc123"),
            "auth",
            "user_signout",
        );

        let obj = payload.as_object().expect("payload must be a JSON object");
        assert_eq!(obj["subject_id"], "0192f0a1-1111-7000-8000-000000000001");
        assert_eq!(obj["env_id"], "0192f0a1-2222-7000-8000-000000000002");
        assert_eq!(obj["session_id"], "tok_abc123");
        assert_eq!(obj["revoked_by"], "auth");
        assert_eq!(obj["reason"], "user_signout");
    }

    /// A subject-scope revocation (no single session) must omit
    /// `session_id` as `null` — the BFF reaper treats `null` as
    /// "kill every cached session for the subject".
    #[test]
    fn session_revoked_payload_without_session() {
        let payload = session_revoked_payload(
            "0192f0a1-1111-7000-8000-000000000001",
            "0192f0a1-2222-7000-8000-000000000002",
            None,
            "auth",
            "password_reset",
        );

        assert!(payload["session_id"].is_null());
        assert_eq!(payload["reason"], "password_reset");
    }
}
