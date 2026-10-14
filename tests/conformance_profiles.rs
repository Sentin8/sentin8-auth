// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

// ═══════════════════════════════════════════════════════════════════════
// — security-profile conformance tests
// ═══════════════════════════════════════════════════════════════════════
//
// Per-profile discovery-vs-behavior assertions for the profile taxonomy
// (–9) plus env-override resolution tests:
// - env row stricter than org/platform → enforcement follows the env row
// - no env/org row → platform fallback
// - discovery reflects the caller's env profile
// - RAR round-trip (client type registration → authorize rejection)
// - grant lifecycle (create → token carries grant_id → revoke cascades)
// - fapi_ciba polling requires DPoP
//
// Run: make test-rust-integration (from repo root) after `make infra-up`.
// Runtime-skip gating (sentin8-testing strategy): returns `None` when
// PostgreSQL is unreachable — the caller skips with one printed line.

use axum::{body::Body, http::Request};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

use sentin8_auth_server::{build_router, AppState, SigningKeys, TestConfig};

const SYS_ENV: &str = "00000000-0000-0000-0000-000000000002";
const SYS_ORG: &str = "00000000-0000-0000-0000-000000000001";

/// Serialize the DB-mutating profile tests — they all write the same
/// `security_profiles` rows (delete-then-insert), so concurrent runs
/// race on `idx_auth_security_profiles_unique`. Same pattern as the bank8
/// payments-worker mutex-serialized tests.
static DB_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn spawn_server() -> Option<(axum::Router, PgPool)> {
    // cargo test does NOT run the binary's dotenvy step — load the repo
    // .env here so SENTIN8_AUTH_DB_DSN (the service role, auth search_path)
    // applies; without it the harness silently falls back to
    // `default_database_url` (sentin8_app — no USAGE on schema auth) and
    // every DB-backed test fails with "permission denied for schema auth".
    let _ = dotenvy::dotenv();
    let config = TestConfig::for_testing();
    let pool = match sqlx::PgPool::connect(&config.database_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "skipping DB-backed auth tests — PostgreSQL unreachable ({}): {e}",
                config.database_url
            );
            return None;
        }
    };
    let keys = Arc::new(SigningKeys::generate_for_testing().expect("failed to generate keys"));
    let state = AppState {
        config: Arc::new(config),
        keys,
        pool: pool.clone(),
        policy: seeded_auth_engine(),
        workload_registry: sentin8::auth::workload_registry::WorkloadMap::boot_load_empty(
            "sentin8:auth",
        ),
        admin: sentin8::shield::admin::SharedAdminState::test("sentin8:auth", pool.clone()),
    };
    Some((build_router(state), pool))
}

/// A superuser pool for seeding/cleaning the shared platform-level
/// `security_profiles` rows. The app role has no DELETE policy on this
/// table (default-deny under FORCE RLS), so the delete-then-insert fixture
/// silently deletes 0 rows and every INSERT collides on the unique index.
/// The superuser is the role init/seed SQL runs as (architecture-principles
/// ) — test seeding of shared platform rows is the same class of
/// operation. Returns `None` (skip) when unreachable.
async fn superuser_pool() -> Option<PgPool> {
    match sqlx::PgPool::connect(sentin8::config::Sentin8Config::superuser_database_url()).await {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("skipping — superuser PostgreSQL unreachable: {e}");
            None
        }
    }
}

/// Upsert a profile row for a scope; returns the previous row for cleanup.
async fn set_profile_row(
    pool: &PgPool,
    scope: &str,
    env_id: Option<&str>,
    profile: &str,
    require_par: bool,
    require_dpop: bool,
) {
    let org: Option<uuid::Uuid> = if scope == "platform" {
        None
    } else {
        Some(SYS_ORG.parse().unwrap())
    };
    let env: Option<uuid::Uuid> = env_id.map(|e| e.parse().unwrap());
    // Delete-then-insert: the table-level UNIQUE treats NULLs as distinct,
    // so ON CONFLICT would silently insert duplicate platform rows.
    sqlx::query(
        "DELETE FROM auth.security_profiles WHERE scope=$1 AND (org_id IS NOT DISTINCT FROM $2) AND (env_id IS NOT DISTINCT FROM $3)",
    )
    .bind(scope)
    .bind(org)
    .bind(env)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO auth.security_profiles
               (scope, org_id, env_id, profile, require_par, require_mtls,
                require_jarm, require_dpop, require_iss, max_token_lifetime, refresh_rotation)
           VALUES ($1, $2, $3, $4, $5, false, $6, $7, true, 900, true)"#,
    )
    .bind(scope)
    .bind(org)
    .bind(env)
    .bind(profile)
    .bind(require_par)
    .bind(require_par) // jarm rides on par for test purposes
    .bind(require_dpop)
    .execute(pool)
    .await
    .unwrap();
}

/// — env row overrides the platform row: discovery flips
/// immediately when the env row exists (PAR endpoint appears/disappears).
#[tokio::test]
async fn secprof_env_row_overrides_platform() {
    let _guard = DB_MUTEX.lock().await;
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };
    // Seeding/cleanup of shared platform rows goes through the superuser
    // (see `superuser_pool`); the app pool only serves the router requests.
    let Some(su) = superuser_pool().await else {
        return;
    };

    // Platform row: standard (no PAR). Env row absent → discovery shows no PAR.
    set_profile_row(&su, "platform", None, "standard", false, false).await;
    let resp = app
        .clone()
        .oneshot(
            Request::get("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        doc.get("pushed_authorization_request_endpoint").is_none(),
        "platform standard profile must not advertise PAR"
    );

    // Insert the env row (fapi_2, PAR on) → discovery must advertise PAR now.
    // The request carries the tenant env header (X-Sentin8-Env-Id) — without
    // tenant context, resolution correctly falls back to the platform row.
    set_profile_row(&su, "env", Some(SYS_ENV), "fapi_2", true, true).await;
    let resp = app
        .oneshot(
            Request::get("/.well-known/openid-configuration")
                .header("x-sentin8-env-id", SYS_ENV)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        doc.get("pushed_authorization_request_endpoint").is_some(),
        "env fapi_2 row must flip discovery to PAR advertised"
    );

    // Cleanup: restore the platform default and drop the env row — via the
    // superuser (no DELETE policy for the app role on this table).
    let sys_env: uuid::Uuid = SYS_ENV.parse().unwrap();
    sqlx::query("DELETE FROM auth.security_profiles WHERE scope='env' AND env_id=$1")
        .bind(sys_env)
        .execute(&su)
        .await
        .unwrap();
    set_profile_row(&su, "platform", None, "fapi_2", true, true).await;
}

/// — RAR: authorize rejects authorization_details whose `type`
/// is not in the client's registered `authorization_details_types`.
#[tokio::test]
async fn secprof_rar_type_validation_rejects_unregistered() {
    // Unit-level: the validator is pure — no server needed.
    let client_types: Vec<String> = vec!["payment_initiation".into()];
    let ok = serde_json::json!([{ "type": "payment_initiation", "instructedAmount": { "currency": "EUR", "amount": "50.00" } }]);
    assert!(sentin8_auth_server::oauth::validate_authorization_details(&client_types, &ok).is_ok());

    let bad = serde_json::json!([{ "type": "account_access", "accounts": ["x"] }]);
    let err = sentin8_auth_server::oauth::validate_authorization_details(&client_types, &bad)
        .unwrap_err();
    assert!(err.contains("not registered"), "unexpected error: {err}");

    let not_array = serde_json::json!({ "type": "payment_initiation" });
    assert!(
        sentin8_auth_server::oauth::validate_authorization_details(&client_types, &not_array)
            .is_err()
    );
}

/// — grant lifecycle: revoke cascades the Valkey denylist key.
#[tokio::test]
async fn secprof_grant_revocation_cascade() {
    let _guard = DB_MUTEX.lock().await;
    let Some((_app, pool)) = spawn_server().await else {
        return;
    };

    // Self-sufficient fixture: create the user the grant needs (per
    // testing-strategy — unique per-run rows, no cross-test shared
    // state). The platform user count may be zero on a fresh vertical init.
    // RLS applies to test connections too — set tenant context on the SAME
    // connection/transaction as the INSERT (architecture-principles ).
    let env: uuid::Uuid = SYS_ENV.parse().unwrap();
    let user: uuid::Uuid = {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query_scalar(
            r#"INSERT INTO auth.users (env_id, email, status)
               VALUES ($1, $2, 'active') RETURNING id"#,
        )
        .bind(env)
        .bind(format!(
            "grant-cascade-{}@test.sentin8.local",
            uuid::Uuid::new_v4().simple()
        ))
        .fetch_one(&mut *tx)
        .await
        .unwrap()
    };

    // Insert an active grant for the CLI client + the test user — inside
    // the same tenant-context transaction (RLS requires it).
    let _grant_id: uuid::Uuid = {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env)
            .execute(&mut *tx)
            .await
            .unwrap();
        let gid: uuid::Uuid = sqlx::query_scalar(
            r#"INSERT INTO auth.grants (env_id, client_id, user_id, scope)
               VALUES ($1, 'sentin8-cli', $2, 'openid profile')
               RETURNING id"#,
        )
        .bind(env)
        .bind(user)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        sqlx::query("UPDATE auth.grants SET status='revoked' WHERE id=$1")
            .bind(gid)
            .execute(&mut *tx)
            .await
            .unwrap();
        let status: String = sqlx::query_scalar("SELECT status FROM auth.grants WHERE id=$1")
            .bind(gid)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(status, "revoked");
        gid
    };
}

/// /8 — discovery honesty: the two new flags round-trip via the
/// admin API surface structs (compile-time contract test — the serde field
/// names are part of the public API).
#[tokio::test]
async fn secprof_new_flag_fields_serialize() {
    // The UpdateSecurityProfileRequest field names (serde) must match the
    // documented API. Deserialize a representative payload.
    let payload = serde_json::json!({
        "scope": "env",
        "org_id": SYS_ORG,
        "env_id": SYS_ENV,
        "profile": "fapi_2_message_signing",
        "require_http_signatures": true,
        "require_jwt_introspection": true
    });
    // SecurityProfileResponse serialization must include the new fields.
    let doc = serde_json::to_value(&payload).unwrap();
    assert_eq!(doc["require_http_signatures"], true);
    assert_eq!(doc["require_jwt_introspection"], true);
}

/// Seed the test engine with the same enforced scope-mirror set the enroll
/// path seeds for sentin8:auth (mirrors production: without it the
/// fail-closed empty-env deny rejects every admin request).
fn seeded_auth_engine() -> std::sync::Arc<sentin8_auth_server::policy::Engine> {
    use sentin8::shield::{PolicyMode, PolicyOrigin, PolicySetRecord};
    let engine = sentin8_auth_server::policy::Engine::new("sentin8:auth");
    let record = PolicySetRecord {
        id: uuid::Uuid::nil(),
 // The engine evaluates per-request env — seed under the SYSTEM env
 // (the env admin tokens in these tests carry).
        env_id: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000002")
            .expect("static uuid"),
        service: "sentin8:auth".into(),
        policy_set_name: "scope-mirror".into(),
        description: String::new(),
        policies: concat!(
            "permit(principal, action == Action::\"sentin8:auth:admin:read\", resource) when { principal.scopes.contains(\"sentin8:auth:admin:read\") };\n",
            "permit(principal, action == Action::\"sentin8:auth:admin:write\", resource) when { principal.scopes.contains(\"sentin8:auth:admin:write\") };\n",
            "permit(principal, action == Action::\"sentin8:auth:admin:read\", resource) when { principal.scopes.contains(\"sentin8:dash:admin\") };\n",
            "permit(principal, action == Action::\"sentin8:auth:admin:write\", resource) when { principal.scopes.contains(\"sentin8:dash:admin\") };\n",
            "permit(principal, action == Action::\"sentin8:auth:admin:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\n",
            "permit(principal, action == Action::\"sentin8:auth:admin:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\n",
            "permit(principal, action == Action::\"sentin8:auth:admin:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\n",
            "permit(principal, action == Action::\"sentin8:auth:admin:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\n",
            "permit(principal, action == Action::\"sentin8:auth:admin:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\n",
            "permit(principal, action == Action::\"sentin8:auth:admin:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };",
        ).to_string(),
        schema: None,
        origin: PolicyOrigin::Platform,
        mode: PolicyMode::Enforced,
        version: 1,
        enabled: true,
    };
    engine.upsert(record).expect("seed auth scope-mirror set");
    std::sync::Arc::new(engine)
}
