// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

// ═══════════════════════════════════════════════════════════════════════
// — security hardening integration tests
// ═══════════════════════════════════════════════════════════════════════

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

use sentin8_auth_server::{build_router, AppState, SigningKeys, TestConfig};

/// The platform system env UUID used across the tests.
const SYS_ENV: &str = "00000000-0000-0000-0000-000000000002";

/// Spin up an in-process Auth server (same harness as integration.rs).
///
/// Runtime-skip gating (sentin8-testing strategy): returns `None` when
/// PostgreSQL is unreachable — the caller skips with one printed line.
async fn spawn_server() -> Option<(axum::Router, PgPool)> {
    // cargo test does NOT run the binary's dotenvy step — load the repo
    // .env here so SENTIN8_AUTH_DB_DSN (the service role, auth search_path)
    // applies (same rationale as the other test harnesses).
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

    let app = build_router(state);
    Some((app, pool))
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

/// SEC- — the unauthenticated-access matrix. Every guarded route
/// must reject requests without credentials. One parameterized pass over
/// the full guarded surface catches "new module forgot the guard" forever.
#[tokio::test]
async fn sec_auth2_unauthenticated_access_matrix() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let guarded_get: &[&str] = &[
        "/v1/admin/users?target_env_id=00000000-0000-0000-0000-000000000002",
        "/v1/admin/roles?target_env_id=00000000-0000-0000-0000-000000000002",
        "/v1/admin/groups?target_env_id=00000000-0000-0000-0000-000000000002",
        "/v1/admin/sessions?target_env_id=00000000-0000-0000-0000-000000000002",
        "/v1/admin/api-keys?target_env_id=00000000-0000-0000-0000-000000000002",
        "/v1/admin/memberships?target_env_id=00000000-0000-0000-0000-000000000002",
        "/v1/admin/audit?target_env_id=00000000-0000-0000-0000-000000000002",
        "/v1/admin/enterprise-connections?target_env_id=00000000-0000-0000-0000-000000000002",
        "/v1/admin/webhooks/endpoints?target_env_id=00000000-0000-0000-0000-000000000002",
        "/v1/admin/actor-tokens?target_env_id=00000000-0000-0000-0000-000000000002",
        "/v1/admin/actor-events?target_env_id=00000000-0000-0000-0000-000000000002",
        "/v1/security-profile?scope=platform",
        "/v1/admin/oauth-clients?target_env_id=00000000-0000-0000-0000-000000000002",
    ];
    for uri in guarded_get {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(*uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET {uri} must require authentication"
        );
    }

    let users_uri = format!("/v1/admin/users?target_env_id={SYS_ENV}");
    let bc_body = r#"{"session_id":"00000000-0000-0000-0000-000000000002","user_id":"00000000-0000-0000-0000-000000000002"}"#.to_string();
    let revoke_body = r#"{"token_id":"00000000-0000-0000-0000-000000000002"}"#.to_string();
    let device_body = r#"{"user_code":"AAAA-BBBB"}"#.to_string();
    let ciba_body = r#"{"auth_req_id":"req-x","approved":true}"#.to_string();
    let introspect_body = "token=forged.token.value&client_id=dash".to_string();
    let profile_body = r#"{"scope":"platform"}"#.to_string();

    let guarded_post: &[(&str, &str, String)] = &[
        ("POST", users_uri.as_str(), "{}".to_string()),
        ("PUT", "/v1/security-profile", profile_body),
        ("POST", "/oauth/backchannel-logout", bc_body),
        ("POST", "/v1/actor-tokens/revoke", revoke_body),
        ("POST", "/device/verify", device_body),
        ("POST", "/v1/ciba/approve", ciba_body),
        ("POST", "/oauth/introspect", introspect_body),
    ];
    for (method, uri, body) in guarded_post {
        // OAuth protocol endpoints (introspect) are form-encoded; the admin
        // JSON endpoints need application/json — send the right content-type
        // so the extractor runs and the handler's auth check (not a 415
        // extractor rejection) produces the 401.
        let content_type = if uri.contains("introspect") {
            "application/x-www-form-urlencoded"
        } else {
            "application/json"
        };
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(*method)
                    .uri(*uri)
                    .header("content-type", content_type)
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri} must require authentication"
        );
    }
}

/// SEC- — forged tokens are refused on the deciding paths.
#[tokio::test]
async fn sec_auth2_forged_tokens_rejected() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    // Forged refresh token (garbage shape) — the verified decode rejects with
    // 401 (unauthorized token); 400 would also be a valid RFC 6749 shape.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=refresh_token&refresh_token=not-a-jwt&client_id=dash",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::BAD_REQUEST,
        "malformed refresh token rejected (got {})",
        resp.status()
    );

    // Forged refresh token (JWT-shaped but unsigned/forged payload).
    use base64::Engine;
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"alg":"MLDSA65","typ":"JWT","kid":"forged"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        br#"{"sub":"00000000-0000-0000-0000-000000000002","iss":"https://auth.test.sentin8.local","exp":4102444800,"token_tp":"refresh","jti":"forged-1","scope":"openid"}"#,
    );
    let forged = format!("{header}.{payload}.Zm9yZ2Vk");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={forged}&client_id=dash"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "forged (signature-invalid) refresh token must be refused"
    );

    // Forged token at userinfo.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .header("authorization", format!("Bearer {forged}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "userinfo refuses forged tokens"
    );
}

/// SEC- — introspection requires client auth and is honest about
/// inactive tokens.
#[tokio::test]
async fn sec_auth2_introspection_requires_client_auth_and_is_honest() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    // No client credentials -> 401 (RFC 7662 ).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("token=whatever"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "introspect requires client auth"
    );

    // Public client (dash) is REJECTED — RFC 7662 requires real client
    // authentication for introspection (a bare client_id is not credentials).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("token=garbage&client_id=dash"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "public client must NOT be able to introspect (RFC 7662)"
    );

    // Confidential client authenticates (secret) — a garbage token then
    // introspects honestly as inactive.
    let secret_hash = bcrypt::hash("test-secret-123", bcrypt::DEFAULT_COST).unwrap();
    let conf_client_id = format!("sec-auth2-introspect-{}", uuid::Uuid::new_v4().simple());
    let conf_db_id = uuid::Uuid::new_v4();
    {
        let mut tx = _pool.begin().await.unwrap();
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(uuid::Uuid::parse_str(SYS_ENV).unwrap())
            .execute(&mut *tx)
            .await;
        sqlx::query(
            r#"INSERT INTO oauth_clients
                 (id, env_id, client_id, client_name, client_secret_hash,
                  redirect_uris, grant_types, response_types, token_endpoint_auth_method, scopes)
               VALUES ($1, $2, $3, 'Sec Auth2 Introspect Test', $4,
                       ARRAY['https://app.example.com/callback'], ARRAY['client_credentials'],
                       ARRAY['code'], 'client_secret_post', ARRAY['openid'])"#,
        )
        .bind(conf_db_id)
        .bind(uuid::Uuid::parse_str(SYS_ENV).unwrap())
        .bind(&conf_client_id)
        .bind(&secret_hash)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "token=garbage&client_id={conf_client_id}&client_secret=test-secret-123"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "authenticated confidential client can introspect"
    );
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["active"], false, "garbage token introspects inactive");
}

/// SEC- — authorize rejects unregistered redirect URIs
/// (open-redirect defense) and enforces PKCE under the FAPI profile.
#[tokio::test]
async fn sec_auth2_authorize_redirect_allowlist_and_pkce() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    // Unregistered redirect_uri -> 400 (never a redirect).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?response_type=code&client_id=dash&redirect_uri={}&scope=openid&state=s1&code_challenge={}&code_challenge_method=S256",
                    urlencode("https://evil.example.com/callback"),
                    urlencode(challenge),
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "unregistered redirect_uri must be refused"
    );

    // Unknown client -> 400.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?response_type=code&client_id=nonexistent-client&redirect_uri={}&scope=openid&state=s1&code_challenge={}&code_challenge_method=S256",
                    urlencode("https://bff.dash.ops.sys.sentin8.local/auth/callback"),
                    urlencode(challenge),
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "unknown client refused"
    );

    // PKCE mandatory under the FAPI profile: no code_challenge -> 400.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?response_type=code&client_id=dash&redirect_uri={}&scope=openid&state=s1",
                    urlencode("https://bff.dash.ops.sys.sentin8.local/auth/callback"),
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    assert!(
        status == StatusCode::BAD_REQUEST || json["error"] == "invalid_request",
        "PKCE-less authorize must be refused under the FAPI profile (got {status}: {json})"
    );
}

/// SEC- — logout only redirects to registered post-logout URIs.
#[tokio::test]
async fn sec_auth2_logout_redirect_allowlist() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth/logout?post_logout_redirect_uri={}",
                    urlencode("https://evil.example.com/phish")
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(
        location, "/sign-in",
        "unregistered post_logout_redirect_uri falls back to /sign-in (got {location})"
    );
}

/// SEC- — PAR pushes require a known client.
#[tokio::test]
async fn sec_auth2_par_requires_known_client() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let redirect = urlencode("https://bff.dash.ops.sys.sentin8.local/auth/callback");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/par")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "response_type=code&client_id=nonexistent-client&redirect_uri={redirect}&scope=openid&state=s1&code_challenge={challenge}&code_challenge_method=S256"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "PAR with unknown client refused"
    );
}

/// SEC- — SCIM refuses forged tokens.
#[tokio::test]
async fn sec_auth2_scim_forged_token_rejected() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    use base64::Engine;
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"alg":"MLDSA65","typ":"JWT"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        br#"{"sub":"x","iss":"https://auth.test.sentin8.local","exp":4102444800,"token_tp":"m2m","scope":"sentin8:scim:write","env_id":"00000000-0000-0000-0000-000000000002"}"#,
    );
    let forged = format!("{header}.{payload}.forged");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/scim/v2/Users")
                .header("authorization", format!("Bearer {forged}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "SCIM must refuse forged (unverified) tokens"
    );
}

/// SEC- — conformance smoke: discovery advertises exactly what is
/// enforced. `client_secret_basic` is advertised, so it must WORK (the
/// extractor parses the Authorization: Basic header).
#[tokio::test]
async fn sec_auth2_conformance_discovery_shape() {
    let Some((app, _pool)) = spawn_server().await else {
        return;
    };

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Advertised auth methods must include the newly-implemented ones.
    let methods = doc["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("auth methods advertised");
    let has = |m: &str| methods.iter().any(|v| v.as_str() == Some(m));
    assert!(has("client_secret_post"), "client_secret_post advertised");
    assert!(
        has("client_secret_basic"),
        "client_secret_basic advertised and implemented (SEC-2.2.1)"
    );
    assert!(
        has("private_key_jwt"),
        "private_key_jwt advertised and implemented (SEC-2.2.1)"
    );

    // Grant types match what the dispatcher handles.
    let grants = doc["grant_types_supported"]
        .as_array()
        .expect("grants advertised");
    let has_g = |g: &str| grants.iter().any(|v| v.as_str() == Some(g));
    assert!(has_g("authorization_code"));
    assert!(has_g("refresh_token"));
    assert!(has_g("client_credentials"));

    // Response types / modes.
    assert_eq!(doc["response_types_supported"][0], "code");
    let modes = doc["response_modes_supported"].as_array().unwrap();
    assert!(modes.iter().any(|v| v.as_str() == Some("query")));

    // PKCE method.
    assert_eq!(doc["code_challenge_methods_supported"][0], "S256");

    // No phantom claims: `id_token_signing_alg_values_supported` is now real
    // (SEC- issues ID tokens).
    let algs = doc["id_token_signing_alg_values_supported"]
        .as_array()
        .expect("id_token algs advertised");
    assert!(
        !algs.is_empty(),
        "ID token signing algs advertised (ID tokens are issued)"
    );

    // The JWKS endpoint publishes at least the active key.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let keys = jwks["keys"].as_array().expect("jwks keys array");
    assert!(!keys.is_empty(), "JWKS publishes the active signing key");
    assert!(
        keys[0].get("kid").is_some(),
        "keys are kid-indexed (rotation overlap)"
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
