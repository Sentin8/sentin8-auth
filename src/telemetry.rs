// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Auth daily telemetry (SDD §2.6 — MemBus transport, internal timer).
//!
//! Counts of users, roles, groups, active sessions, OAuth clients, API
//! keys, MFA/passkey enrollments, and signups today. Emitted as one
//! metric frame on the shared telemetry path —
//! `sentin8::shield::stat_emit::emit_metric_event` (MemBus
//! `stat:telemetry` Pub/Sub, consumed by Stat's worker; fire-and-forget,
//! log-only on failure).
//!
//! The emitter runs on an internal daily timer (SDD §2.5 posture): auth
//! links no scheduler client, no stat client, and makes no cross-service
//! calls. The shared emitter is initialized by the shell boot
//! (`boot_full` → `init_stat_emitter_for_service("sentin8:auth")`).

/// Telemetry cadence — daily.
const TELEMETRY_TICK: std::time::Duration = std::time::Duration::from_secs(86_400);

/// Spawn the daily telemetry timer (internal, fire-and-forget). A failed
/// query or emission logs and retries on the next tick — never fatal.
pub fn spawn_telemetry_timer(pool: sqlx::PgPool) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(TELEMETRY_TICK).await;
            if let Err(e) = emit_daily_telemetry(&pool).await {
                tracing::warn!(error = %e, "auth daily telemetry failed — retrying next tick");
            }
        }
    });
}

/// Query the daily counts and publish one metric frame
/// (`sentin8:auth:telemetry:daily`).
async fn emit_daily_telemetry(pool: &sqlx::PgPool) -> Result<(), String> {
    // Platform-level counts (auth's own schema, SYSTEM-env plane).
    let users_count: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::BIGINT FROM users")
        .fetch_one(pool)
        .await
        .map_err(|e| format!("count users: {e}"))?;

    let roles_count: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::BIGINT FROM roles")
        .fetch_one(pool)
        .await
        .map_err(|e| format!("count roles: {e}"))?;

    let groups_count: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::BIGINT FROM groups")
        .fetch_one(pool)
        .await
        .map_err(|e| format!("count groups: {e}"))?;

    let active_sessions_count: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::BIGINT FROM sessions WHERE expires_at > now()",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| format!("count sessions: {e}"))?;

    let oauth_clients_count: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::BIGINT FROM oauth_clients WHERE status = 'active'",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| format!("count oauth clients: {e}"))?;

    let api_keys_count: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::BIGINT FROM api_keys WHERE status = 'active'",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| format!("count api keys: {e}"))?;

    let mfa_enrollments: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::BIGINT FROM auth_user_mfa WHERE enabled = true",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| format!("count mfa: {e}"))?;

    let passkey_enrollments: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::BIGINT FROM auth_webauthn_credentials")
            .fetch_one(pool)
            .await
            .map_err(|e| format!("count passkeys: {e}"))?;

    let signups_today: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::BIGINT FROM users WHERE created_at::date = now()::date",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| format!("count signups: {e}"))?;

    // One metric frame on the shared MemBus telemetry path — the shell
    // boot initialized the emitter; a disabled emitter is a no-op.
    sentin8::shield::stat_emit::emit_metric_event(
        "sentin8:auth",
        "sentin8:auth:telemetry:daily",
        serde_json::json!({
            "users.count": users_count,
            "roles.count": roles_count,
            "groups.count": groups_count,
            "sessions.active.count": active_sessions_count,
            "oauth_clients.count": oauth_clients_count,
            "api_keys.count": api_keys_count,
            "mfa.enrollments.count": mfa_enrollments,
            "passkey.enrollments.count": passkey_enrollments,
            "signups.daily.count": signups_today,
        }),
        serde_json::json!({
            "token_tp": "access",
            "scope": "platform",
        }),
    );

    tracing::info!(
        users_count,
        roles_count,
        groups_count,
        active_sessions_count,
        "auth daily telemetry emitted (membus stat:telemetry)"
    );

    Ok(())
}
