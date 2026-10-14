// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for Auth auth flows
//!
//! These tests use an in-process Axum server with a real PostgreSQL database.
//! They require a running PostgreSQL with the Sentin8 schema loaded.
//! Set `DATABASE_URL` or `SENTIN8_AUTH_DB_DSN` to point to a test database.
//! The repo `.env` is loaded explicitly here: cargo test does NOT run the
// binary's dotenvy step (that lives in main), so without this the harness
//! silently falls back to `default_database_url` (the `sentin8_app` role —
//! no search_path, no grants) and every DB-backed test 500s with
//! `relation "oauth_clients" does not exist`.
//!
//! Runtime-skip gating (sentin8-testing strategy): each helper returns
//! `None` when PostgreSQL is unreachable — the test prints one skip line and
//! passes. Run the full suite with `make test-rust-integration` (from repo
//! root) after `make infra-up`.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

use sentin8_auth_server::{build_router, AppState, SigningKeys, TestConfig};

/// Spin up an in-process Auth server with a test database pool.

/// A unique client IP for a test — avoids cross-test/cross-run bot-protection
/// rate limits (per-IP 10/min on the shared Valkey).
fn unique_ip() -> String {
    let n = uuid::Uuid::new_v4().as_u128() % 254;
    format!("10.{}.{}.{}", (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff)
}

/// Probe whether the test database is reachable. One connection attempt per
/// process — the result is cached so all tests print at most one skip line.
async fn db_reachable() -> bool {
    use tokio::sync::OnceCell;
    static CACHE: OnceCell<bool> = OnceCell::const_new();
    CACHE
        .get_or_init(|| async {
            // cargo test does NOT run the binary's dotenvy step (it lives in
            // main), so the repo .env must be loaded HERE — otherwise the
            // harness silently falls back to `default_database_url` (the
            // `sentin8_app` role: no search_path, no grants) and every
            // DB-backed test 500s with `relation "..." does not exist`.
            let _ = dotenvy::dotenv();
            let config = TestConfig::for_testing();
            match sqlx::PgPool::connect(&config.database_url).await {
                Ok(pool) => {
                    pool.close().await;
                    true
                }
                Err(e) => {
                    eprintln!(
                        "skipping DB-backed auth tests — PostgreSQL unreachable ({}): {e}",
                        config.database_url
                    );
                    false
                }
            }
        })
        .await
        .to_owned()
}

async fn spawn_server() -> Option<(axum::Router, PgPool)> {
    if !db_reachable().await {
        return None;
    }
    let Some((app, pool, _state)) = spawn_server_with_state().await else {
        return None;
    };
    Some((app, pool))
}

/// — test server that also exposes its AppState so tests can
/// mint admin tokens (the admin API now requires an admin scope).
async fn spawn_server_with_state() -> Option<(axum::Router, PgPool, AppState)> {
    if !db_reachable().await {
        return None;
    }
    let config = TestConfig::for_testing();
    let pool = sqlx::PgPool::connect(&config.database_url)
        .await
        .expect("failed to connect to test database");
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

    let app = build_router(state.clone());
    Some((app, pool, state))
}

/// — mint a platform-admin access token for admin API tests.
fn admin_token(state: &AppState) -> String {
    use sentin8_auth_server::jwt::AuthClaims;
    let claims = AuthClaims::access(
        &state.config.issuer,
        uuid::Uuid::new_v4(),
        "sentin8:dash:admin",
        uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
        Some("admin@test.sentin8.local"),
        chrono::Duration::seconds(900),
    );
    state.keys.sign(&claims).expect("sign admin token")
}

#[tokio::test]
async fn health_endpoint_serves_ok() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn users_sign_up_then_sign_in_returns_tokens() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    // Sign up a new user.
    let email = format!("test_{}@test.sentin8.local", uuid::Uuid::new_v4().simple());
    let signup_body = serde_json::json!({
        "email": email,
        "password": "test_password_123",
        "first_name": "Test",
        "last_name": "User",
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sign-up")
                .header("content-type", "application/json")
                .header("x-forwarded-for", unique_ip())
                .body(Body::from(serde_json::to_vec(&signup_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Sign in with the new user.
    let signin_body = serde_json::json!({
        "email": email,
        "password": "test_password_123",
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sign-in")
                .header("content-type", "application/json")
                .header("x-forwarded-for", unique_ip())
                .body(Body::from(serde_json::to_vec(&signin_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify the response body has user fields.
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["email"], email);
    // (The `realm` claim was removed — tokens are env-scoped via env_id.)
}

#[tokio::test]
async fn users_sign_up_duplicate_email_conflicts() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let email = format!(
        "duptest_{}@test.sentin8.local",
        uuid::Uuid::new_v4().simple()
    );
    let body = serde_json::json!({
        "email": email,
        "password": "test_password_123",
    });

    // First signup should succeed.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sign-up")
                .header("content-type", "application/json")
                .header("x-forwarded-for", unique_ip())
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    if response.status() != StatusCode::CREATED {
        let status = response.status();
        let b = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        panic!(
            "first signup failed: {status} — body: {}",
            String::from_utf8_lossy(&b)
        );
    }
    assert_eq!(response.status(), StatusCode::CREATED);

    // Second signup with same email should fail with 409.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sign-up")
                .header("content-type", "application/json")
                .header("x-forwarded-for", unique_ip())
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

/// — the same email can sign up on multiple tenants
/// (e.g. alice@a.com registers separately on iBank and on iFintech).
/// Email is unique only within (org_id, env_id), not globally.
///
/// Sys-schema fixtures (organizations/environments) are SEEDING, not what
/// the test exercises: the service role holds SELECT-only on sys.* by
/// design (production org creation goes through sys's API — architecture
/// ), so the fixture uses the superuser DSN — never the harness pool.
async fn seed_tenant_fixture(
    super_dsn: &str,
    org_id: uuid::Uuid,
    env_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    let pool = sqlx::PgPool::connect(super_dsn).await?;
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    sqlx::query(
        "INSERT INTO sys.organizations (id, slug, display_name, domain) VALUES ($1, $2, $3, $4)",
    )
    .bind(org_id)
    .bind(format!("test-{}", org_id.simple()))
    .bind(format!("Test Org {}", org_id.simple()))
    .bind(format!("{}-org.sentin8.local", org_id.simple()))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO sys.environments (id, org_id, slug, display_name, status) VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(env_id)
    .bind(org_id)
    .bind(format!("test-env-{}", env_id.simple()))
    .bind(format!("Test Env {}", env_id.simple()))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    pool.close().await;
    Ok(())
}

#[tokio::test]
async fn users_sign_up_same_email_across_tenants_isolated() {
    let Some((app, pool)) = spawn_server().await else {
        return;
    };

    // Create two distinct tenants via direct SQL — the test doesn't
    // depend on auth. These sys-schema fixtures (organizations/environments)
    // are SEEDING, not what the test exercises: the service role holds
    // SELECT-only on sys.* by design (production org creation goes through
    // sys's API, architecture ), so the fixture uses the superuser
    // DSN (DATABASE_URL) — never the harness pool — and sets tenant
    // context per statement .
    let super_dsn = std::env::var("DATABASE_URL")
        .or_else(|_| std::env::var("SENTIN8_TEST_FIXTURE_DSN"))
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".into());
    let tenant_a: (uuid::Uuid, uuid::Uuid) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let tenant_b: (uuid::Uuid, uuid::Uuid) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    for (org_id, env_id) in [tenant_a, tenant_b] {
        seed_tenant_fixture(&super_dsn, org_id, env_id)
            .await
            .expect("seed tenant fixture");
    }

    let email = format!(
        "multitenant_{}@test.sentin8.local",
        uuid::Uuid::new_v4().simple()
    );
    let body = serde_json::json!({
        "email": email,
        "password": "test_password_123",
    });

    // First sign-up on tenant A — should succeed.
    let resp_a = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sign-up")
                .header("content-type", "application/json")
                .header("x-forwarded-for", unique_ip())
                .header("x-sentin8-env-id", tenant_a.1.to_string())
                .header("host", "test-a.sentin8.local")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp_a.status(),
        StatusCode::CREATED,
        "tenant A signup should succeed"
    );

    // Second sign-up on tenant B with the SAME email — should also
    // succeed (per-tenant uniqueness, not global).
    let resp_b = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sign-up")
                .header("content-type", "application/json")
                .header("x-forwarded-for", unique_ip())
                .header("x-sentin8-env-id", tenant_b.1.to_string())
                .header("host", "test-b.sentin8.local")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp_b.status(),
        StatusCode::CREATED,
        "tenant B signup with same email should succeed (per-tenant uniqueness)"
    );

    // Verify both users exist in users and are scoped to their tenants.
    // (org_id was removed from users — verify via the env → org join.)
    // RLS: read each tenant's user under that tenant's context (same-conn).
    // The explicit `u.env_id = $2` filter is defense-in-depth ( rule 4) —
    // correct under the NOBYPASSRLS service role AND under a superuser test
    // connection where RLS is inert.
    let mut users: Vec<(uuid::Uuid, uuid::Uuid, uuid::Uuid, String)> = Vec::new();
    for (_org, env_id) in [tenant_a, tenant_b] {
        let mut tx = pool.begin().await.expect("begin verify tx");
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        let mut rows = sqlx::query_as::<_, (uuid::Uuid, uuid::Uuid, uuid::Uuid, String)>(
            // sys.environments is QUALIFIED: the harness pool runs under the
            // service role whose search_path is `auth, public` (no `sys`) —
            // and the role holds the declared SELECT on sys.* only.
            "SELECT u.id, e.org_id, u.env_id, u.email
               FROM users u
               JOIN sys.environments e ON e.id = u.env_id
              WHERE u.email = $1 AND u.env_id = $2",
        )
        .bind(&email)
        .bind(env_id)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        users.append(&mut rows);
    }
    assert_eq!(users.len(), 2, "should have one user per tenant");
    let orgs: std::collections::HashSet<uuid::Uuid> = users.iter().map(|u| u.1).collect();
    assert!(orgs.contains(&tenant_a.0) && orgs.contains(&tenant_b.0));

    // Cleanup.
    for (org_id, _env_id) in [tenant_a, tenant_b] {
        let _ = sqlx::query("DELETE FROM users WHERE org_id = $1")
            .bind(org_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM sentin8_environments WHERE org_id = $1")
            .bind(org_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM sentin8_organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await;
    }
}

#[tokio::test]
async fn users_sign_in_wrong_password_rejected() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    // First sign up.
    let email = format!(
        "wrongpw_{}@test.sentin8.local",
        uuid::Uuid::new_v4().simple()
    );
    let signup = serde_json::json!({
        "email": email,
        "password": "correct_password",
    });
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sign-up")
                .header("content-type", "application/json")
                .header("x-forwarded-for", unique_ip())
                .body(Body::from(serde_json::to_vec(&signup).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Try to sign in with wrong password.
    let signin = serde_json::json!({
        "email": email,
        "password": "wrong_password",
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sign-in")
                .header("content-type", "application/json")
                .header("x-forwarded-for", unique_ip())
                .body(Body::from(serde_json::to_vec(&signin).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn users_sign_in_unknown_account_rejected() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let signin = serde_json::json!({
        "email": "nonexistent@test.sentin8.local",
        "password": "any_password",
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sign-in")
                .header("content-type", "application/json")
                .header("x-forwarded-for", unique_ip())
                .body(Body::from(serde_json::to_vec(&signin).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn users_sign_up_short_password_rejected() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let body = serde_json::json!({
        "email": format!("shortpw_{}@test.sentin8.local", uuid::Uuid::new_v4().simple()),
        "password": "short",
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sign-up")
                .header("content-type", "application/json")
                .header("x-forwarded-for", unique_ip())
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oidc_discovery_serves_provider_metadata() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify required OIDC discovery fields.
    assert!(json["issuer"].is_string());
    assert!(json["authorization_endpoint"].is_string());
    assert!(json["token_endpoint"].is_string());
    assert!(json["jwks_uri"].is_string());
    assert!(json["response_types_supported"].is_array());
    assert!(json["grant_types_supported"].is_array());
    assert!(json["code_challenge_methods_supported"].is_array());
    assert!(json["scopes_supported"].is_array());
    assert!(json["id_token_signing_alg_values_supported"].is_array());
}

#[tokio::test]
async fn jwks_endpoint_serves_signing_keys() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["keys"].is_array());
    assert!(!json["keys"].as_array().unwrap().is_empty());
    // The active algorithm depends on SENTIN8_TLS_PQ_MODE (default:
    // exclusive → ML-DSA-65/MLWE; classical → RS256/RSA). Assert the
    // document is self-consistent instead of hardcoding one mode.
    let kty = json["keys"][0]["kty"].as_str().unwrap_or_default();
    let alg = json["keys"][0]["alg"].as_str().unwrap_or_default();
    match (kty, alg) {
        ("MLWE", "MLDSA65") => {
            assert!(json["keys"][0]["x"].is_string(), "MLWE key carries x");
        }
        ("RSA", "RS256") => {
            assert!(json["keys"][0]["n"].is_string(), "RSA key carries n");
            assert!(json["keys"][0]["e"].is_string(), "RSA key carries e");
        }
        other => panic!("unexpected JWKS kty/alg: {other:?}"),
    }
    assert!(json["keys"][0]["kid"].is_string(), "keys are kid-indexed");
}

#[tokio::test]
async fn admin_users_list_requires_authentication() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/admin/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // — unauthenticated admin access is REJECTED. (The old
    // test asserted 200 with the comment "when auth middleware is added,
    // this will be 401" — that day has arrived.)
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_users_create_then_list_roundtrip() {
    let Some((app, _pool, state)) = spawn_server_with_state().await else {
        return;
    };
    let token = admin_token(&state);
    // The guard requires target_env_id (auth is env-scoped).
    const ADMIN_Q: &str = "?target_env_id=00000000-0000-0000-0000-000000000002";

    let email = format!(
        "admin_test_{}@test.sentin8.local",
        uuid::Uuid::new_v4().simple()
    );
    let create_body = serde_json::json!({
        "email": email,
        "password": "admin_password_123",
        "first_name": "Admin",
        "last_name": "Test",
        "org_id": "00000000-0000-0000-0000-000000000001",
        "env_id": "00000000-0000-0000-0000-000000000002",
        "realm": "env",
    });

    // Create user.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/admin/users{ADMIN_Q}"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&create_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    if response.status() != StatusCode::CREATED {
        let status = response.status();
        let b = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        panic!(
            "admin create user failed: {status} — body: {}",
            String::from_utf8_lossy(&b)
        );
    }
    assert_eq!(response.status(), StatusCode::CREATED);

    // List users — should contain the new user.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/admin/users{ADMIN_Q}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    if response.status() != StatusCode::OK {
        let status = response.status();
        let b = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        panic!(
            "admin list failed: {status} — body: {}",
            String::from_utf8_lossy(&b)
        );
    }
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["users"].is_array());
    assert!(json["total"].is_number());
}

#[tokio::test]
async fn branding_discovery_serves_org_theme() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/branding")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // theme_mode defaults to "dark" when a branding row exists; with no
    // branding row at all the value is null — accept both.
    assert!(json["themeMode"].is_string() || json["themeMode"].is_null());
}

#[tokio::test]
async fn oauth_authorize_missing_response_type_rejected() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/authorize?response_type=token&client_id=test&redirect_uri=http://localhost:3000/callback")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn users_sign_up_empty_email_rejected() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let body = serde_json::json!({
        "email": "",
        "password": "test_password_123",
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sign-up")
                .header("content-type", "application/json")
                .header("x-forwarded-for", unique_ip())
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn users_sign_in_empty_fields_rejected() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let body = serde_json::json!({
        "email": "",
        "password": "",
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sign-in")
                .header("content-type", "application/json")
                .header("x-forwarded-for", unique_ip())
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_roles_create_roundtrip() {
    let Some((app, _pool, state)) = spawn_server_with_state().await else {
        return;
    };
    let token = admin_token(&state);
    // The guard requires target_env_id (auth is env-scoped).
    const ADMIN_Q: &str = "?target_env_id=00000000-0000-0000-0000-000000000002";

    let body = serde_json::json!({
        "org_id": "00000000-0000-0000-0000-000000000001",
        "env_id": "00000000-0000-0000-0000-000000000002",
        "name": format!("test-role-{}", uuid::Uuid::new_v4().simple()),
        "permissions": ["read:all", "write:all"],
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/admin/roles{ADMIN_Q}"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn admin_api_keys_create_roundtrip() {
    let Some((app, _pool, state)) = spawn_server_with_state().await else {
        return;
    };
    let token = admin_token(&state);
    // The guard requires target_env_id (auth is env-scoped).
    const ADMIN_Q: &str = "?target_env_id=00000000-0000-0000-0000-000000000002";

    let body = serde_json::json!({
        "org_id": "00000000-0000-0000-0000-000000000001",
        "env_id": "00000000-0000-0000-0000-000000000002",
        "name": format!("test-key-{}", uuid::Uuid::new_v4().simple()),
        "scopes": ["read:data"],
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/admin/api-keys{ADMIN_Q}"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let resp_body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(json["key"].as_str().unwrap().starts_with("sentin8_"));
    assert!(json["key_prefix"].is_string());
}
// ── First-Party Consent Bypass ───────────────────────────

#[tokio::test]
async fn consent_bypass_client_consent_required_true_serves_consent() {
    // Register a client with consent_required = true (the default).
    // The /oauth/authorize redirect URL should include consent_required=true.
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let dcr_body = serde_json::json!({
        "client_name": format!("test-consent-true-{}", uuid::Uuid::new_v4().simple()),
        "redirect_uris": ["https://app.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": "openid profile email",
        "application_type": "web",
        "consent_required": true,
    });

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&dcr_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["consent_required"], true);
    let client_id = json["client_id"].as_str().unwrap().to_string();

    // Call /oauth/authorize with PAR (Pushed Authorization Request).
    // RFC 9126 — PAR is form-encoded, not JSON.
    let form_body = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        urlencode(&client_id),
        urlencode("https://app.example.com/callback"),
        urlencode("openid profile email"),
        urlencode("test-state-123"),
        urlencode("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
    );
    let par_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/par")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .unwrap();

    // PAR should succeed and return a request_uri.
    if !par_resp.status().is_success() {
        let status = par_resp.status();
        let b = axum::body::to_bytes(par_resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        panic!(
            "PAR failed: {status} — body: {}",
            String::from_utf8_lossy(&b)
        );
    }
    // RFC 9126 — the PAR response is 200 OK (201 was never the contract).
    let par_body = axum::body::to_bytes(par_resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let par_json: serde_json::Value = serde_json::from_slice(&par_body).unwrap();
    let request_uri = par_json["request_uri"].as_str().unwrap().to_string();

    // Call /oauth/authorize with the request_uri — should redirect to sign-in
    // with consent_required=true in the URL.
    // RFC 9126 — the authorize request carries client_id + request_uri
    // (SEC- — they must match; the old flow overrode silently).
    let auth_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&format!(
                    "/oauth/authorize?client_id={}&request_uri={}",
                    urlencode(&client_id),
                    urlencode(&request_uri)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    if auth_resp.status() != StatusCode::FOUND {
        let status = auth_resp.status();
        let b = axum::body::to_bytes(auth_resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        panic!(
            "authorize failed: {status} — body: {}",
            String::from_utf8_lossy(&b)
        );
    }
    assert_eq!(auth_resp.status(), StatusCode::FOUND);
    let location = auth_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        location.contains("consent_required=true"),
        "redirect URL should contain consent_required=true: {location}"
    );
}

#[tokio::test]
async fn consent_bypass_client_consent_required_false_skips_consent() {
    // Register a first-party client with consent_required = false.
    // The /oauth/authorize redirect URL should include consent_required=false.
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let dcr_body = serde_json::json!({
        "client_name": format!("test-consent-false-{}", uuid::Uuid::new_v4().simple()),
        "redirect_uris": ["https://app.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": "openid profile email",
        "application_type": "web",
        "consent_required": false,
    });

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&dcr_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["consent_required"], false);
    let client_id = json["client_id"].as_str().unwrap().to_string();

    // PAR request — RFC 9126 form-encoded (not JSON).
    let form_body = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        urlencode(&client_id),
        urlencode("https://app.example.com/callback"),
        urlencode("openid profile email"),
        urlencode("test-state-123"),
        urlencode("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
    );
    let par_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/par")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .unwrap();

    // RFC 9126 — the PAR endpoint answers 201 Created (the resource
    // — the request_uri — was created).
    assert_eq!(par_resp.status(), StatusCode::CREATED);
    let par_body = axum::body::to_bytes(par_resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let par_json: serde_json::Value = serde_json::from_slice(&par_body).unwrap();
    let request_uri = par_json["request_uri"].as_str().unwrap().to_string();

    // /oauth/authorize should redirect with consent_required=false. The
    // request carries client_id + request_uri (RFC 9126 — client binding).
    let auth_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&format!(
                    "/oauth/authorize?client_id={}&request_uri={}",
                    urlencode(&client_id),
                    urlencode(&request_uri)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(auth_resp.status(), StatusCode::FOUND);
    let location = auth_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        location.contains("consent_required=false"),
        "redirect URL should contain consent_required=false: {location}"
    );
}

#[tokio::test]
async fn consent_bypass_dcr_default_is_consent_required() {
    // DCR without consent_required should default to true (safe default).
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let dcr_body = serde_json::json!({
        "client_name": format!("test-consent-default-{}", uuid::Uuid::new_v4().simple()),
        "redirect_uris": ["https://app.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": "openid profile email",
        "application_type": "web",
    });

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&dcr_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Default should be true (consent required).
    assert_eq!(json["consent_required"], true);
}

#[tokio::test]
async fn consent_bypass_dcr_update_applies_new_setting() {
    // Register a client with consent_required = true, then update to false via PUT.
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    // Register.
    let dcr_body = serde_json::json!({
        "client_name": format!("test-consent-update-{}", uuid::Uuid::new_v4().simple()),
        "redirect_uris": ["https://app.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": "openid profile email",
        "application_type": "web",
        "consent_required": true,
    });

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&dcr_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["consent_required"], true);
    let client_id = json["client_id"].as_str().unwrap().to_string();
    let rat = json["registration_access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Update consent_required to false.
    let update_body = serde_json::json!({
        "consent_required": false,
    });

    let update_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(&format!("/oauth/register/{}", client_id))
                .header("content-type", "application/json")
                .header("authorization", &format!("Bearer {}", rat))
                .body(Body::from(serde_json::to_vec(&update_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(update_resp.status(), StatusCode::OK);
    let update_body = axum::body::to_bytes(update_resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let update_json: serde_json::Value = serde_json::from_slice(&update_body).unwrap();
    assert_eq!(update_json["consent_required"], false);
}

/// Simple URL-encoding helper for test query params.
fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

// ── — certificate-bound DCR scope gate (auth design
// target state) ─────────────────────────────────────────────────────────

/// POST /oauth/register with `client_credentials` + platform scopes and a
/// certificate CN that has NO grant row: rejected with 400 (fail-closed —
/// tests provision exactly what they exercise).
#[tokio::test]
async fn dcr_m2m_platform_scope_rejected_without_grant() {
    let Some((app, _pool, _state)) = spawn_server_with_state().await else {
        return;
    };
    let dcr_body = serde_json::json!({
        "client_name": format!("gate-test-{}", uuid::Uuid::new_v4().simple()),
        "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "self_signed_tls_client_auth",
        "scope": "sentin8:sys:instances:read sentin8:flow:write",
    });
    // The TLS layer injects the thumbprint only for CA-verified certs; the
    // Subject CN here names a workload with NO grant row → gate rejects.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .header("x-sentin8-client-cert-thumbprint", "ungranted-cert-thumb")
                .header("x-sentin8-client-cert-subject", "gate-test")
                .body(Body::from(serde_json::to_vec(&dcr_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "workload without a grant row must be rejected"
    );
}

/// POST /oauth/register with `client_credentials` + platform scopes and a
/// cert whose CN HAS a grant row → accepted. The test seeds its own grant
/// row (no scout rows, no env fallback — is fail-closed in every
/// environment; tests provision exactly what they exercise).
#[tokio::test]
async fn dcr_m2m_platform_scope_granted_thumbprint_accepted() {
    let Some((app, pool, _state)) = spawn_server_with_state().await else {
        return;
    };
    // Seed a grant row for this test's workload CN (unique per run). The
    // grant is keyed by service_name — the cert Subject CN the gate matches.
    // SEEDING, not what the test exercises: the service role holds
    // SELECT-only on auth.m2m_scope_grants by design (the gate reads; rows
    // are provisioned by `vertical enroll`), so the fixture uses the
    // superuser DSN (DATABASE_URL) — never the harness pool.
    let workload = format!("gate-granted-{}", uuid::Uuid::new_v4().simple());
    let scopes: Vec<String> = vec!["sentin8:sys:instances:read".into()];
    let super_dsn = std::env::var("DATABASE_URL")
        .or_else(|_| std::env::var("SENTIN8_TEST_FIXTURE_DSN"))
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".into());
    let fixture_pool = sqlx::PgPool::connect(&super_dsn)
        .await
        .expect("connect fixture pool (superuser DSN)");
    sqlx::query(
        r#"INSERT INTO auth.m2m_scope_grants
             (service_name, allowed_scopes)
           VALUES ($1, $2)
           ON CONFLICT (service_name) DO UPDATE SET
             allowed_scopes = EXCLUDED.allowed_scopes"#,
    )
    .bind(&workload)
    .bind(&scopes)
    .execute(&fixture_pool)
    .await
    .expect("seed grant row");

    let dcr_body = serde_json::json!({
        "client_name": workload,
        "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "self_signed_tls_client_auth",
        "self_signed_tls_client_auth_thumbprint": format!("thumb-{}", uuid::Uuid::new_v4().simple()),
        "scope": "sentin8:sys:instances:read",
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .header(
                    "x-sentin8-client-cert-thumbprint",
                    format!("granted-thumb-{}", uuid::Uuid::new_v4().simple()),
                )
                .header(
                    "x-sentin8-client-cert-subject",
                    // The TLS layer reports the full CN — Acme mints
                    // `CN=m2m-{workload}`; the gate strips the reserved
                    // `m2m-` prefix before matching the grant row.
                    format!("m2m-{workload}"),
                )
                .body(Body::from(serde_json::to_vec(&dcr_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "granted workload CN must admit the granted scope set"
    );

    // Cleanup via the SAME superuser identity (the pool role can't DELETE).
    let _ = sqlx::query("DELETE FROM auth.m2m_scope_grants WHERE service_name = $1")
        .bind(&workload)
        .execute(
            &sqlx::PgPool::connect(&super_dsn)
                .await
                .expect("connect fixture pool (cleanup)"),
        )
        .await;
}

/// POST /oauth/register with `client_credentials` + platform scopes and NO
/// certificate → rejected (fail-closed everywhere; there is no env fallback).
#[tokio::test]
async fn dcr_m2m_platform_scope_rejected_certless() {
    let Some((app, _pool, _state)) = spawn_server_with_state().await else {
        return;
    };
    let dcr_body = serde_json::json!({
        "client_name": format!("gate-certless-{}", uuid::Uuid::new_v4().simple()),
        "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "self_signed_tls_client_auth",
        "scope": "sentin8:sys:instances:read",
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&dcr_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "cert-less M2M registration with platform scopes must be rejected"
    );
}

/// PUT /oauth/register/{id} on an M2M-only client requesting a scope that is
/// NOT in the certificate's grant → rejected (closes the RFC 7592 escalation
/// route: register OIDC-only, then PUT platform scopes on).
#[tokio::test]
async fn dcr_m2m_update_scope_escalation_rejected() {
    let Some((app, _pool, _state)) = spawn_server_with_state().await else {
        return;
    };
    // 1. Register an OIDC-only interactive client (no gate — baseline only).
    let dcr_body = serde_json::json!({
        "client_name": format!("escalate-{}", uuid::Uuid::new_v4().simple()),
        "redirect_uris": ["https://app.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": "openid profile email",
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&dcr_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let client_id = json["client_id"].as_str().unwrap().to_string();
    let rat = json["registration_access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. PUT grant_types → client_credentials + platform scopes. The merged
    // client is now M2M-only with platform scopes → the gate must fire.
    let update_body = serde_json::json!({
        "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "self_signed_tls_client_auth",
        "scope": "openid profile email sentin8:sys:instances:read",
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/oauth/register/{client_id}"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {rat}"))
                .header("x-sentin8-client-cert-thumbprint", "ungranted-cert-thumb")
                .body(Body::from(serde_json::to_vec(&update_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "PUT escalation to platform scopes without a grant must be rejected"
    );
}

/// POST /oauth/register interactive client with platform scopes in `scope`:
/// NOT gated (interactive clients keep the RFC 7591 default — the scopes are
/// recorded but the client cannot use them without a user grant flow).
#[tokio::test]
async fn dcr_interactive_client_platform_scope_not_gated() {
    let Some((app, _pool, _state)) = spawn_server_with_state().await else {
        return;
    };
    let dcr_body = serde_json::json!({
        "client_name": format!("interactive-{}", uuid::Uuid::new_v4().simple()),
        "redirect_uris": ["https://app.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": "openid profile email sentin8:app:store:read",
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&dcr_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "interactive clients are not mTLS-gated (body: {})",
        axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_else(|e| format!("<body read failed: {e}>"))
    );
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
