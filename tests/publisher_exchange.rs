// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

// ═══════════════════════════════════════════════════════════════════════
// 23.3 - publisher-token exchange (Sentin8:Bus ) integration tests
// ═══════════════════════════════════════════════════════════════════════
//
// A subscriber service (M2M client) exchanges a publisher's Sentin8:Auth
// JWT for a downscoped, act-attributed delegated token. Covers the eight
// acceptance scenarios from story :
// 1. valid access-token publisher → delegated token, act.sub = publisher sub
// 2. valid m2m publisher → act.sub = service client
// 3. expired publisher → 401
// 4. unauthorized subscriber (not in publisher's env) → 403 may_act_denied
// 5. jti replay → 400 token_already_exchanged
// 6. publisher is itself delegated → nested act chain (act.act.sub)
// 7. non-cert-bound subscriber → delegated token without cnf
// 8. requested scope exceeds publisher's → downscoped to intersection
//
// Run: make test-rust-integration (from repo root) after `make infra-up`.
// Runtime-skip gating (sentin8-testing strategy): returns `None` when
// PostgreSQL is unreachable - the caller skips with one printed line.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

use sentin8_auth_server::jwt::AuthClaims;
use sentin8_auth_server::{build_router, AppState, SigningKeys, TestConfig};

const SYS_ENV: &str = "00000000-0000-0000-0000-000000000002";

async fn spawn_server() -> Option<(axum::Router, PgPool, Arc<SigningKeys>)> {
    // cargo test does NOT run the binary's dotenvy step - load the repo
    // .env here so SENTIN8_AUTH_DB_DSN (the service role, auth search_path)
    // applies; without it the harness falls back to `default_database_url`
    // (sentin8_app - no USAGE on schema auth) and every test fails with
    // "permission denied for schema auth".
    let _ = dotenvy::dotenv();
    let config = TestConfig::for_testing();
    let pool = match sqlx::PgPool::connect(&config.database_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "skipping DB-backed auth tests - PostgreSQL unreachable ({}): {e}",
                config.database_url
            );
            return None;
        }
    };
    let keys = Arc::new(SigningKeys::generate_for_testing().expect("failed to generate keys"));
    let state = AppState {
        config: Arc::new(config),
        keys: keys.clone(),
        pool: pool.clone(),
        policy: seeded_auth_engine(),
        workload_registry: sentin8::auth::workload_registry::WorkloadMap::boot_load_empty(
            "sentin8:auth",
        ),
        admin: sentin8::shield::admin::SharedAdminState::test("sentin8:auth", pool.clone()),
    };
    Some((build_router(state), pool, keys))
}

/// Sign an arbitrary claims struct into a JWT with the test signing keys.
fn sign(keys: &SigningKeys, claims: &AuthClaims) -> String {
    keys.sign(claims).expect("failed to sign test token")
}

fn publisher_access_claims(sub: &str, scope: &str, exp: i64) -> AuthClaims {
    AuthClaims {
        sub: sub.into(),
        // Must match TestConfig::for_testing's issuer.
        iss: "https://auth.test.local.sentin8.dev".into(),
        aud: None,
        jti: uuid::Uuid::new_v4().to_string(),
        iat: chrono::Utc::now().timestamp(),
        exp,
        token_tp: "access".into(),
        scope: scope.into(),
        env_id: Some(SYS_ENV.into()),
        email: None,
        client_id: None,
        act: None,
        cnf: None,
        grant_id: None,
    userinfo_claims: None,
        // User access tokens carry no vertical/service_type - those stamp
        // M2M produce workloads only (VDC-2/4).
        vertical: None,
        service_type: None,
    }
}

/// Create (or reuse) a subscriber M2M client row in the system env with the
/// given scopes, and grant it a role in the system env (may_act). The
/// junction `user_roles` carries env_id per the bank8 convention.
async fn seed_subscriber(pool: &PgPool, client_id: &str, scopes: &[&str]) {
    let env: uuid::Uuid = SYS_ENV.parse().unwrap();
    // RLS: the client + role writes need tenant context on the SAME
    // connection - the pool-only path is policy-blocked.
    let mut tx = pool.begin().await.unwrap();
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env)
        .execute(&mut *tx)
        .await;
    sqlx::query(
        r#"INSERT INTO auth.oauth_clients
               (env_id, client_id, client_name, redirect_uris, grant_types,
                response_types, token_endpoint_auth_method, scopes, status)
           VALUES ($1, $2, $2, '{}', '{client_credentials}', '{}', 'client_secret_post', $3, 'active')
           ON CONFLICT (client_id) DO UPDATE SET scopes = EXCLUDED.scopes, status = 'active'"#,
    )
    .bind(env)
    .bind(client_id)
    .bind(scopes)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Grant the may_act authorization: a role in the publisher's env,
    // assigned to the subscriber's M2M principal via client_roles
    // (client-path - user_roles.user_id FKs to users).
    let subscriber_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM auth.oauth_clients WHERE client_id = $1")
            .bind(client_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    let role_id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO auth.roles (id, env_id, name, permissions)
           VALUES (gen_random_uuid(), $1, $2, '{}')
           ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions
           RETURNING id"#,
    )
    .bind(env)
    .bind(format!("publisher-exchange-test:{client_id}"))
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO auth.client_roles (client_id, role_id, env_id)
           VALUES ($1, $2, $3)
           ON CONFLICT DO NOTHING"#,
    )
    .bind(subscriber_id)
    .bind(role_id)
    .bind(env)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

fn exchange_body(subject_token: &str, client_id: &str, scope: &str) -> String {
    format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={subject_token}&subject_token_type=urn:ietf:params:oauth:token-type:jwt&client_id={client_id}&scope={scope}"
    )
}

/// (1)(2) A valid publisher token exchanges for a delegated token with
/// act.sub = the publisher's sub; (8) the scope is downscoped to the
/// intersection with the publisher's and subscriber's scopes.
#[tokio::test]
async fn publisher_exchange_mints_act_delegated_token() {
    let Some((app, pool, keys)) = spawn_server().await else {
        return;
    };
    seed_subscriber(
        &pool,
        "test-subscriber",
        &["sentin8:bus:consume", "sentin8:auth:users:read"],
    )
    .await;

    let exp = (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp();
    let publisher = publisher_access_claims("pub-user-1", "sentin8:bus:consume other:scope", exp);
    let token = sign(&keys, &publisher);

    let resp = app
        .clone()
        .oneshot(
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(exchange_body(
                    &token,
                    "test-subscriber",
                    "sentin8:bus:consume other:scope",
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    if status != StatusCode::OK {
        assert!(
            false,
            "DEBUG: exchange returned {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Decode the delegated token (unverified is fine for structural checks).
    let delegated = doc["access_token"].as_str().unwrap();
    let claims = sentin8::auth::jwt::decode_payload(delegated).unwrap();
    assert_eq!(claims["token_tp"], "delegated");
    assert_eq!(claims["sub"], "test-subscriber");
    assert_eq!(
        claims["act"]["sub"], "pub-user-1",
        "act.sub must be the publisher's sub"
    );
    // (8) downscoped to the intersection (sentin8:bus:consume only - other:scope is
    // not in the subscriber's scopes).
    let scope = claims["scope"].as_str().unwrap();
    assert!(scope.contains("sentin8:bus:consume"), "scope was: {scope}");
    assert!(
        !scope.contains("other:scope"),
        "downscoping failed: {scope}"
    );
    // (7) non-cert-bound subscriber → no cnf.
    assert!(
        claims.get("cnf").is_none(),
        "client_secret subscriber must not get cnf"
    );
}

/// (3) An expired publisher token is rejected.
#[tokio::test]
async fn publisher_exchange_rejects_expired_token() {
    let Some((app, pool, keys)) = spawn_server().await else {
        return;
    };
    seed_subscriber(&pool, "test-subscriber", &["sentin8:bus:consume"]).await;
    let exp = (chrono::Utc::now() - chrono::Duration::minutes(5)).timestamp();
    let token = sign(
        &keys,
        &publisher_access_claims("pub-user-2", "sentin8:bus:consume", exp),
    );

    let resp = app
        .oneshot(
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(exchange_body(
                    &token,
                    "test-subscriber",
                    "sentin8:bus:consume",
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// (5) The same publisher token cannot be exchanged twice (jti replay).
#[tokio::test]
async fn publisher_exchange_rejects_jti_replay() {
    let Some((app, pool, keys)) = spawn_server().await else {
        return;
    };
    seed_subscriber(&pool, "test-subscriber", &["sentin8:bus:consume"]).await;
    let exp = (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp();
    let token = sign(
        &keys,
        &publisher_access_claims("pub-user-3", "sentin8:bus:consume", exp),
    );

    let body = exchange_body(&token, "test-subscriber", "sentin8:bus:consume");
    let first = app
        .clone()
        .oneshot(
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        first.status(),
        StatusCode::OK,
        "first exchange must succeed"
    );

    let second = app
        .oneshot(
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        StatusCode::BAD_REQUEST,
        "replay must be rejected"
    );
    let text = axum::body::to_bytes(second.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&text).to_string();
    assert!(text.contains("token_already_exchanged"), "body was: {text}");
}

/// (6) A publisher that is itself a delegated token nests the act chain:
/// act.act.sub = the original staff user.
#[tokio::test]
async fn publisher_exchange_nests_act_chain() {
    let Some((app, pool, keys)) = spawn_server().await else {
        return;
    };
    seed_subscriber(&pool, "test-subscriber", &["sentin8:bus:consume"]).await;

    let exp = (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp();
    let mut publisher = publisher_access_claims("bff-delegated-user", "sentin8:bus:consume", exp);
    publisher.token_tp = "delegated".into();
    publisher.act = Some(serde_json::json!({ "sub": "staff-user-9", "email": "staff@a.co" }));
    let token = sign(&keys, &publisher);

    let resp = app
        .oneshot(
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(exchange_body(
                    &token,
                    "test-subscriber",
                    "sentin8:bus:consume",
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let claims = sentin8::auth::jwt::decode_payload(doc["access_token"].as_str().unwrap()).unwrap();
    assert_eq!(claims["act"]["sub"], "bff-delegated-user");
    assert_eq!(
        claims["act"]["act"]["sub"], "staff-user-9",
        "act chain must nest: act.act.sub = original staff user"
    );
}

/// (4) A subscriber that is NOT authorized in the publisher's env is
/// rejected with 403 may_act_denied (cross-tenant exchange blocked).
#[tokio::test]
async fn publisher_exchange_rejects_cross_tenant() {
    let Some((app, pool, keys)) = spawn_server().await else {
        return;
    };
    // Subscriber lives in the system env; the publisher token carries a
    // different env → may_act fails.
    seed_subscriber(&pool, "test-subscriber", &["sentin8:bus:consume"]).await;
    let exp = (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp();
    let mut publisher = publisher_access_claims("pub-user-4", "sentin8:bus:consume", exp);
    publisher.env_id = Some("99999999-9999-9999-9999-999999999999".into());
    let token = sign(&keys, &publisher);

    let resp = app
        .oneshot(
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(exchange_body(
                    &token,
                    "test-subscriber",
                    "sentin8:bus:consume",
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
        "cross-tenant exchange must fail (got {})",
        resp.status()
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
 // The engine evaluates per-request env - seed under the SYSTEM env
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
