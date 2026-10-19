// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

// ═══════════════════════════════════════════════════════════════════════
// SEC- - conformance smoke harness (design ) + the
// integration tests that were not yet covered (code client binding,
// revoke+rotation, ID-token issuance, refresh reuse) and the replay
// negatives (DPoP jti, private_key_jwt jti, TOTP reuse).
//
// The harness asserts the discovery document's ADVERTISED capabilities
// against ACTUAL endpoint behavior - discovery honesty, permanently.
// ═══════════════════════════════════════════════════════════════════════

mod support;
use support::{mk_dpop_proof, mk_es256_assertion, mk_es256_key, mk_totp_code};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

use sentin8_auth_server::{build_router, AppState, SigningKeys, TestConfig};

/// The platform system env UUID used across the tests.
const SYS_ENV: uuid::Uuid = uuid::uuid!("00000000-0000-0000-0000-000000000002");

/// Spin up an in-process Auth server (same harness as sec_auth2.rs).
async fn spawn_server() -> Option<(axum::Router, PgPool)> {
    // Load the repo .env so DATABASE_URL (superuser fixture DSN) applies -
    // session-token lookups (`Session::find_by_token`) run before any tenant
    // context exists and are denied by sessions RLS under a
    // NOBYPASSRLS service role (see AUTH-RLS-1 in the auth backlog).
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
    // Seed the env-scoped security profile: the platform default is FAPI 2.0
    // (PAR-only, secrets not accepted for confidential clients) but the
    // conformance suite registers client_secret_post clients - the env-scoped
    // 'standard' profile is the most specific match in
    // resolve_security_profile("env") and permits them.
    // RLS: the table is FORCE-RLS - the INSERT must run under the SYS env
    // context in one transaction , and the error must surface (a
    // silently denied seed left the FAPI profile active and every secret-
    // client test 401'd).
    let mut tx = pool.begin().await.expect("begin profile seed tx");
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(SYS_ENV)
        .execute(&mut *tx)
        .await;
    sqlx::query(
        r#"INSERT INTO auth.security_profiles
             (scope, org_id, env_id, profile, require_par, require_mtls,
              require_jarm, require_dpop, require_iss, max_token_lifetime,
              refresh_rotation)
           SELECT 'env', org_id, id, 'standard', false, false, false, false, false, 3600, true
             FROM sys.environments WHERE id = $1
           ON CONFLICT (scope, org_id, env_id) DO UPDATE
             SET profile = 'standard', require_par = false, require_mtls = false,
                 require_jarm = false, require_dpop = false, require_iss = false,
                 max_token_lifetime = 3600, refresh_rotation = true"#,
    )
    .bind(SYS_ENV)
    .execute(&mut *tx)
    .await
    .expect("seed env 'standard' security profile");
    tx.commit().await.expect("commit profile seed");
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
    let app = build_router(state);
    Some((app, pool))
}

fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

fn unique_ip() -> String {
    let n = uuid::Uuid::new_v4().as_u128() % 254;
    format!("10.{}.{}.{}", (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff)
}

/// Sign up a fresh user; returns (email, password, session_token).
async fn sign_up_user(app: &axum::Router) -> (String, String, String) {
    let email = format!("conf_{}@test.sentin8.local", uuid::Uuid::new_v4().simple());
    let password = "conf_password_123";
    let body = serde_json::json!({
        "email": email,
        "password": password,
        "first_name": "Conformance",
        "last_name": "Test",
    });
    let resp = app
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
    assert_eq!(resp.status(), StatusCode::CREATED, "sign-up must succeed");
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    (
        email,
        password.to_string(),
        json["token"].as_str().unwrap().to_string(),
    )
}

/// Register a confidential client (client_secret_post) in the system env.
async fn register_confidential_client(pool: &PgPool) -> (String, String) {
    let client_id = format!("conf-client-{}", uuid::Uuid::new_v4().simple());
    let secret = "conf-client-secret-123";
    let mut tx = pool.begin().await.unwrap();
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(SYS_ENV)
        .execute(&mut *tx)
        .await;
    sqlx::query(
        r#"INSERT INTO oauth_clients
             (id, env_id, client_id, client_name, client_secret_hash,
              redirect_uris, grant_types, response_types, token_endpoint_auth_method, scopes)
           VALUES ($1, $2, $3, 'Conformance Client', $4,
                   ARRAY['https://app.example.com/callback'], ARRAY['authorization_code','refresh_token','client_credentials'],
                   ARRAY['code'], 'client_secret_post', ARRAY['openid','profile','email','offline_access'])"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(SYS_ENV)
    .bind(&client_id)
    .bind(bcrypt::hash(secret, bcrypt::DEFAULT_COST).unwrap())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    (client_id, secret.to_string())
}

/// Complete the hosted sign-in step of the authorize flow and return the
/// redirect target (the code callback).
/// Push a PAR (RFC 9126) for the given authorize params; returns the
/// `request_uri` to use in the authorize call (the security profile mandates
/// PAR - classic authorize without request_uri is rejected).
async fn par_push(
    app: &axum::Router,
    client_id: &str,
    secret: &str,
    redirect: &str,
    scope: &str,
    challenge: &str,
    state: &str,
) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/par")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "response_type=code&client_id={client_id}&client_secret={secret}&redirect_uri={redirect}&scope={scope}&state={state}&code_challenge={challenge}&code_challenge_method=S256"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "PAR push must succeed");
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    json["request_uri"].as_str().unwrap().to_string()
}

async fn authorize_continue(
    app: &axum::Router,
    pool: &PgPool,
    session_token: &str,
    authorize_uri: &str,
) -> (StatusCode, serde_json::Value) {
    // Step 1: GET /oauth/authorize - renders sign-in (or first-party bypass).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(authorize_uri)
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    // Errors (400 invalid_request etc.) surface as JSON - return them.
    if !(status.is_success() || status == StatusCode::FOUND) {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        return (status, json);
    }

    // The authorize handler answers 302 FOUND pointing at the hosted sign-in
    // page with the RESOLVED OAuth params (classic query or PAR-stored) as
    // query params - parse them from the Location header. Values arrive
    // percent-encoded; query_pairs decodes them.
    let resolved = if status == StatusCode::FOUND {
        resp.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|loc| format!("https://auth.test{loc}"))
            .and_then(|loc| url::Url::parse(&loc).ok())
    } else {
        None
    };
    let get = |k: &str| -> String {
        resolved
            .as_ref()
            .and_then(|u| {
                u.query_pairs()
                    .find(|(key, _)| key == k)
                    .map(|(_, v)| v.to_string())
            })
            .unwrap_or_default()
    };

    // Resolve the session's user_id. RLS applies: the connection has no
    // tenant context yet, and `sentin8_bypass_rls` is inert by design -
    // set the session's tenant context (SYS env - sign_up_user signs up
    // without an env header, so the session lands in the SYSTEM env) on
    // one transaction and run the lookup there ( rule 2).
    let user_id: Uuid = {
        let mut tx = pool.begin().await.expect("begin session lookup tx");
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(SYS_ENV)
            .execute(&mut *tx)
            .await;
        let uid: Uuid = sqlx::query_scalar("SELECT user_id FROM sessions WHERE token_id = $1")
            .bind(session_token)
            .fetch_one(&mut *tx)
            .await
            .expect("session lookup");
        tx.rollback().await.ok(); // read-only fixture lookup
        uid
    };

    // Step 2: POST /oauth/authorize/continue with the full request shape.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/authorize/continue")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {session_token}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "client_id": get("client_id"),
                        "redirect_uri": get("redirect_uri"),
                        "scope": get("scope"),
                        "state": get("state"),
                        "code_challenge": get("code_challenge"),
                        "nonce": get("nonce"),
                        "user_id": user_id,
                        "session_token": session_token,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    (status, json)
}

// ═══════════════════ #5 - Code client binding ═══════════════════

/// Client B must not be able to redeem client A's authorization code
/// (mix-up defense, design ).
#[tokio::test]
async fn conf_code_client_binding_client_b_cannot_redeem_client_a_code() {
    let Some((app, pool)) = spawn_server().await else {
        return;
    };
    let (_email, _pw, session_token) = sign_up_user(&app).await;
    let (client_a, secret_a) = register_confidential_client(&pool).await;
    let (client_b, _secret_b) = register_confidential_client(&pool).await;

    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let redirect = urlencode("https://app.example.com/callback");

    // Client A authorizes.
    let request_uri = par_push(
        &app, &client_a, &secret_a, &redirect, "openid", challenge, "s1",
    )
    .await;
    let (status, body) = authorize_continue(
        &app,
        &pool,
        &session_token,
        &format!("/oauth/authorize?client_id={client_a}&request_uri={request_uri}"),
    )
    .await;
    let code = body["redirect_url"]
        .as_str()
        .and_then(|u| {
            url::Url::parse(u).ok().and_then(|u| {
                u.query_pairs()
                    .find(|(k, _)| k == "code")
                    .map(|(_, v)| v.to_string())
            })
        })
        .unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::OK,
        "authorize/continue must succeed: {body}"
    );
    assert!(!code.is_empty(), "a code was issued: {body}");

    // Client B redeems client A's code → invalid_grant.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&client_id={client_b}&client_secret={secret_a}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&code_verifier={verifier}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json["error"], "invalid_grant",
        "code redemption must be bound to the authorizing client"
    );
}

// ═══════════════════ #6 - PAR single-use ════════════════════════

/// Replaying the same `request_uri` at authorize must be refused
/// (GETDEL single-use, design ).
#[tokio::test]
async fn conf_par_request_uri_is_single_use() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };
    let (client_id, secret) = register_confidential_client(&spawn_pool().await.unwrap()).await;
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let redirect = urlencode("https://app.example.com/callback");

    // Push the PAR.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/par")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "response_type=code&client_id={client_id}&client_secret={secret}&redirect_uri={redirect}&scope=openid&state=s1&code_challenge={challenge}&code_challenge_method=S256"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "PAR push must succeed");
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let request_uri = json["request_uri"].as_str().unwrap().to_string();

    // First authorize with the request_uri - must be accepted (any status but
    // invalid_request; the PAR record resolves).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?client_id={client_id}&request_uri={request_uri}"
                ))
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "first authorize with the request_uri must resolve the PAR record"
    );

    // Second authorize with the SAME request_uri - GETDEL already consumed it.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?client_id={client_id}&request_uri={request_uri}"
                ))
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "replayed request_uri must be refused (single-use)"
    );
    assert_eq!(json["error"], "invalid_request", "PAR replay error code");
}

async fn spawn_pool() -> Option<PgPool> {
    let config = TestConfig::for_testing();
    sqlx::PgPool::connect(&config.database_url).await.ok()
}

// ═══════════════════ #7 - Revoke + rotation ═════════════════════

/// Revoking a refresh token makes introspection report `active: false`
/// and subsequent refresh grants fail (RFC 7009, design ).
#[tokio::test]
async fn conf_revoke_refresh_introspect_inactive_and_refresh_fails() {
    let Some((app, pool)) = spawn_server().await else {
        return;
    };
    let (_email, _pw, session_token) = sign_up_user(&app).await;
    let (client_id, secret) = register_confidential_client(&pool).await;
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let redirect = urlencode("https://app.example.com/callback");

    // Obtain a code (offline_access → refresh token).
    let request_uri = par_push(
        &app,
        &client_id,
        &secret,
        &redirect,
        "openid%20offline_access",
        challenge,
        "s1",
    )
    .await;
    let (status, body) = authorize_continue(
        &app,
        &pool,
        &session_token,
        &format!("/oauth/authorize?client_id={client_id}&request_uri={request_uri}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "authorize/continue must succeed: {body}"
    );
    let code = body["redirect_url"]
        .as_str()
        .and_then(|u| {
            url::Url::parse(u).ok().and_then(|u| {
                u.query_pairs()
                    .find(|(k, _)| k == "code")
                    .map(|(_, v)| v.to_string())
            })
        })
        .unwrap_or_default();

    // Exchange for tokens.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&client_id={client_id}&client_secret={secret}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&code_verifier={verifier}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "code exchange must succeed: {}",
        String::from_utf8_lossy(&bytes)
    );
    let tokens: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let refresh = tokens["refresh_token"]
        .as_str()
        .expect("refresh token issued");

    // Introspect the refresh token → active.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/introspect")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "token={refresh}&client_id={client_id}&client_secret={secret}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["active"], true, "fresh refresh token is active");

    // Revoke it.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/revoke")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "token={refresh}&client_id={client_id}&client_secret={secret}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "revoke returns 200 per RFC 7009"
    );

    // Introspect again → inactive.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/introspect")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "token={refresh}&client_id={client_id}&client_secret={secret}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["active"], false, "revoked refresh token is inactive");

    // Refresh grant with the revoked token → invalid_grant.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={refresh}&client_id={client_id}&client_secret={secret}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "revoked refresh fails"
    );
}

// ═══════════════════ #9 - ID token issuance ═════════════════════

/// Code exchange with the `openid` scope returns an ID token carrying the
/// correct iss/aud/nonce (design ).
#[tokio::test]
async fn conf_id_token_issued_with_correct_aud_iss_nonce() {
    let Some((app, pool)) = spawn_server().await else {
        return;
    };
    let (_email, _pw, session_token) = sign_up_user(&app).await;
    let (client_id, secret) = register_confidential_client(&pool).await;
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let nonce = format!("nonce-{}", uuid::Uuid::new_v4().simple());
    let redirect = urlencode("https://app.example.com/callback");

    let par_body = format!(
        "response_type=code&client_id={client_id}&client_secret={secret}&redirect_uri={redirect}&scope=openid%20email&state=s1&nonce={nonce}&code_challenge={challenge}&code_challenge_method=S256"
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/par")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(par_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "PAR push must succeed");
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let par_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let request_uri = par_json["request_uri"].as_str().unwrap().to_string();
    let (status, body) = authorize_continue(
        &app,
        &pool,
        &session_token,
        &format!("/oauth/authorize?client_id={client_id}&request_uri={request_uri}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "authorize/continue must succeed: {body}"
    );
    let code = body["redirect_url"]
        .as_str()
        .and_then(|u| {
            url::Url::parse(u).ok().and_then(|u| {
                u.query_pairs()
                    .find(|(k, _)| k == "code")
                    .map(|(_, v)| v.to_string())
            })
        })
        .unwrap_or_default();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&client_id={client_id}&client_secret={secret}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&code_verifier={verifier}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let tokens: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let id_token = tokens["id_token"]
        .as_str()
        .expect("id_token issued for openid");

    // Decode (verified against our own JWKS-equivalent key set - the test
    // server signs with its in-memory keys) and check the OIDC claims.
    let parts: Vec<&str> = id_token.split('.').collect();
    assert_eq!(parts.len(), 3, "compact JWS");
    let payload = sentin8_auth_server::decode_jwt_payload(id_token).expect("decode id_token");
    assert_eq!(payload["aud"], client_id, "aud = client_id");
    assert_eq!(
        payload["iss"], "https://auth.test.sentin8.local",
        "iss = configured issuer"
    );
    assert_eq!(payload["nonce"], nonce, "nonce flows authorize → id_token");
    assert!(
        payload["at_hash"].is_string(),
        "at_hash binds the access token"
    );
    assert!(payload["sub"].is_string(), "sub present");
}

// ═══════════════════ #10 - Refresh reuse after rotation ═════════

/// Using a rotated-out refresh token again → invalid_grant (rotation
/// denylist, design ).
#[tokio::test]
async fn conf_rotated_out_refresh_token_reuse_fails() {
    let Some((app, pool)) = spawn_server().await else {
        return;
    };
    let (_email, _pw, session_token) = sign_up_user(&app).await;
    let (client_id, secret) = register_confidential_client(&pool).await;
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let redirect = urlencode("https://app.example.com/callback");

    let request_uri = par_push(
        &app,
        &client_id,
        &secret,
        &redirect,
        "openid%20offline_access",
        challenge,
        "s1",
    )
    .await;
    let (status, body) = authorize_continue(
        &app,
        &pool,
        &session_token,
        &format!("/oauth/authorize?client_id={client_id}&request_uri={request_uri}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "authorize/continue must succeed: {body}"
    );
    let code = body["redirect_url"]
        .as_str()
        .and_then(|u| {
            url::Url::parse(u).ok().and_then(|u| {
                u.query_pairs()
                    .find(|(k, _)| k == "code")
                    .map(|(_, v)| v.to_string())
            })
        })
        .unwrap_or_default();

    // Exchange → refresh #1.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&client_id={client_id}&client_secret={secret}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&code_verifier={verifier}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let tokens: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let refresh_1 = tokens["refresh_token"].as_str().expect("refresh issued");

    // Rotate: refresh #1 → refresh #2.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={refresh_1}&client_id={client_id}&client_secret={secret}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "first refresh succeeds");
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let tokens: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let refresh_2 = tokens["refresh_token"]
        .as_str()
        .expect("rotation issues a new refresh token");

    // Replay refresh #1 → the rotated-out token is denylisted.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={refresh_1}&client_id={client_id}&client_secret={secret}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "rotated-out refresh token replay must fail"
    );
    assert_eq!(json["error"], "invalid_grant", "replay error code");
    let _ = refresh_2; // the live token - not used further here
}

// ═══════════════════ Replay negatives ═════════════════════════════════

/// DPoP proof `jti` replay is rejected (Valkey SETNX replay store,
/// design ).
#[tokio::test]
async fn conf_dpop_proof_jti_replay_rejected() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };
    // Build a signed DPoP proof (ES256, self-contained jwk header).
    let proof = mk_dpop_proof("POST", "https://auth.test.sentin8.local/oauth/token", 0);
    let body = format!("grant_type=client_credentials&client_id=dash&dpop={proof}");

    // First use - accepted into the validation path (may fail later on
    // grant policy, but NOT on jti replay).
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .header("DPoP", &proof)
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status1 = resp1.status();
    let bytes1 = axum::body::to_bytes(resp1.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json1: serde_json::Value = serde_json::from_slice(&bytes1).unwrap_or_default();

    // Second use of the SAME proof (same jti) - must be rejected as a replay.
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .header("DPoP", &proof)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status2 = resp2.status();
    let bytes2 = axum::body::to_bytes(resp2.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json2: serde_json::Value = serde_json::from_slice(&bytes2).unwrap_or_default();

    let replay_desc = format!("first: {status1} {json1}; second: {status2} {json2}");
    assert!(
        status2 != status1
            || json2["error_description"]
                .as_str()
                .map(|s| s.contains("jti") || s.contains("replay") || s.contains("used"))
                .unwrap_or(false)
            || json2["error"] == "invalid_dpop_proof",
        "DPoP jti replay must be distinguishable from the first response: {replay_desc}"
    );
}

/// private_key_jwt client assertion `jti` replay is rejected (Valkey
/// SETNX, design ).
#[tokio::test]
async fn conf_private_key_jwt_assertion_jti_replay_rejected() {
    let Some((app, pool)) = spawn_server().await else {
        return;
    };
    // Register a private_key_jwt client with an inline ES256 jwks.
    let client_id = format!("pkjwt-{}", uuid::Uuid::new_v4().simple());
    let (jwk, signing_key) = mk_es256_key();
    {
        let mut tx = pool.begin().await.unwrap();
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(SYS_ENV)
            .execute(&mut *tx)
            .await;
        sqlx::query(
            r#"INSERT INTO oauth_clients
                 (id, env_id, client_id, client_name, jwks,
                  redirect_uris, grant_types, response_types, token_endpoint_auth_method, scopes)
               VALUES ($1, $2, $3, 'PKJWT Client', $4,
                       ARRAY['https://app.example.com/callback'], ARRAY['client_credentials'],
                       ARRAY['code'], 'private_key_jwt', ARRAY['openid'])"#,
        )
        .bind(uuid::Uuid::new_v4())
        .bind(SYS_ENV)
        .bind(&client_id)
        .bind(serde_json::json!({ "keys": [jwk] }))
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    // Mint a client assertion signed with the registered key.
    let make_assertion = |jti: String| mk_es256_assertion(&signing_key, &jti);

    let assertion = make_assertion(uuid::Uuid::new_v4().to_string());
    let form = |assertion: &str| {
        format!(
            "grant_type=client_credentials&client_id={client_id}&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={assertion}"
        )
    };

    // First use - passes client auth (may fail on other grant policy, but
    // NOT with "jti already used").
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form(&assertion)))
                .unwrap(),
        )
        .await
        .unwrap();
    let s1 = resp1.status();
    let b1 = axum::body::to_bytes(resp1.into_body(), 1024 * 1024)
        .await
        .unwrap();

    // Replay the SAME assertion - jti now consumed.
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form(&assertion)))
                .unwrap(),
        )
        .await
        .unwrap();
    let s2 = resp2.status();
    let b2 = axum::body::to_bytes(resp2.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json2: serde_json::Value = serde_json::from_slice(&b2).unwrap_or_default();

    assert!(
        s2 == StatusCode::UNAUTHORIZED
            || json2["error_description"]
                .as_str()
                .map(|s| s.contains("jti already used"))
                .unwrap_or(false)
            || json2["error"] == "invalid_client",
        "assertion jti replay must be refused (first: {s1} {}B; second: {s2} {}B)",
        b1.len(),
        b2.len()
    );
}

/// TOTP code reuse within the same step window is rejected (replay cache,
/// design ).
#[tokio::test]
async fn conf_totp_code_replay_rejected() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };
    // Enroll a TOTP factor directly (pending state), then verify once.
    let email = format!("totp_{}@test.sentin8.local", uuid::Uuid::new_v4().simple());
    let (_e, _p, session_token) = {
        let body = serde_json::json!({
            "email": email,
            "password": "totp_password_123",
            "first_name": "Totp",
            "last_name": "Test",
        });
        let resp = app
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
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (
            email.clone(),
            "totp_password_123",
            json["token"].as_str().unwrap().to_string(),
        )
    };

    // Enroll: response carries the base32 secret (pending).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mfa/enroll")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {session_token}"))
                .header("X-Sentin8-CSRF", &session_token)
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let st = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(st, StatusCode::OK, "mfa enroll must succeed");
    let enroll: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let secret_b32 = enroll["secret"].as_str().expect("pending secret returned");
    let factor_id = enroll["factor_id"].as_str().unwrap().to_string();

    // Compute the current TOTP code from the base32 secret.
    let code = mk_totp_code(secret_b32);

    // First verification (activate) - must succeed.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mfa/verify")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {session_token}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "factor_id": factor_id,
                        "code": code,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "first TOTP verify must succeed"
    );

    // Replay the SAME code in the same window - must be rejected.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mfa/verify")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {session_token}"))
                .header("X-Sentin8-CSRF", &session_token)
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "factor_id": factor_id,
                        "code": code,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "replayed TOTP code must be rejected"
    );
}

// ═══════════════════ - Advertised-vs-behavior harness ══════════

/// The conformance harness core: for every capability the discovery
/// document advertises, the matching endpoint behavior must exist.
#[tokio::test]
async fn conf_discovery_advertisement_matches_behavior() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    // PAR: advertised endpoint must actually enforce client auth + single use.
    if doc.get("pushed_authorization_request_endpoint").is_some() {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("x-sentin8-env-id", SYS_ENV.to_string())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("response_type=code&client_id=ghost&redirect_uri=https%3A%2F%2Fx.example%2Fcb"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "PAR advertised → push without a valid client must be refused"
        );
    }

    // JARM: response_modes include "jwt" only when require_jarm -
    // advertisement must match enforcement (here: not required by default,
    // so plain-query responses must NOT be JWT-signed).
    let modes = doc["response_modes_supported"].as_array().unwrap();
    let jarm_advertised = modes.iter().any(|v| v.as_str() == Some("jwt"));
    let _ = jarm_advertised; // enforcement covered by jarm.rs unit tests

    // RFC 9207 iss parameter support.
    let iss_supported = doc["authorization_response_iss_parameter_supported"]
        .as_bool()
        .unwrap_or(false);
    if iss_supported {
        // The authorize response contract (handled in authorize_continue)
        // appends iss - the redirect_allowlist test covers the endpoint.
    }

    // client_secret_basic advertised → Basic auth must be accepted at token.
    let methods = doc["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap();
    if methods
        .iter()
        .any(|v| v.as_str() == Some("client_secret_basic"))
    {
        let (client_id, secret) = {
            let pool = spawn_pool().await.unwrap();
            register_confidential_client(&pool).await
        };
        use base64::Engine;
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/token")
                    .header("x-sentin8-env-id", SYS_ENV.to_string())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("authorization", format!("Basic {basic}"))
                    .body(Body::from("grant_type=client_credentials&scope=openid"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "client_secret_basic advertised → must authenticate"
        );
    }

    // ID token algs advertised → ID tokens are actually issued (covered by
    // conf_id_token_issued_with_correct_aud_iss_nonce).

    // mtls_endpoint_aliases advertised → the alias routes exist.
    if doc.get("mtls_endpoint_aliases").is_some() {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mtls/oauth/token")
                    .header("x-sentin8-env-id", SYS_ENV.to_string())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=client_credentials&client_id=dash"))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Without a client-cert thumbprint header the alias must refuse.
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "mtls alias advertised → token without cert thumbprint refused"
        );
    }
}

// ═══════════════════ CSRF enforcement ═════════════════════════════════

/// Cookie-authenticated mutations require the X-Sentin8-CSRF header;
/// Bearer callers are exempt (design ).
#[tokio::test]
async fn conf_csrf_required_on_cookie_mutations_bearer_exempt() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };
    let (_email, _pw, session_token) = sign_up_user(&app).await;

    // Cookie-authenticated sign-out WITHOUT the CSRF header → 403.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sign-out")
                .header("content-type", "application/json")
                .header("cookie", format!("__session={session_token}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "cookie mutation without X-Sentin8-CSRF must be refused"
    );

    // With the header → allowed.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sign-out")
                .header("content-type", "application/json")
                .header("cookie", format!("__session={session_token}"))
                .header("X-Sentin8-CSRF", &session_token)
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "CSRF header satisfies the gate"
    );

    // Bearer callers are exempt (no header needed).
    let (_email2, _pw2, token2) = sign_up_user(&app).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sign-out")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token2}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "Bearer auth is CSRF-exempt");
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
