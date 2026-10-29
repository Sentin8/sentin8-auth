// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-License-Identifier: Apache-2.0

//! Shared harness for the in-process OIDF rig mirror (`tests/oidf_*.rs`).
//!
//! `sentin8-auth-oidf` (auth DESIGN §9a.2) is the source of truth for what
//! the OIDF certification campaigns exercise; this harness spins the SAME
//! router the fleet boots inside the test process and seeds the SAME
//! per-posture `security_profiles` rows the battery seeds - so every
//! campaign wire behavior is asserted directly, without the OIDF suite
//! runtime. Campaign rules carried into Rust (auth DESIGN §9b):
//! - **No-skip** (§9a.10): a capability the discovery document advertises
//!   must behave; a test asserts the behavior, not a skip path.
//! - **Warning-zero** (§9a.11): each assertion roots the behavior a suite
//!   WARNING would surface (honest metadata, uniform errors, no-store).
//!
//! The profile seeding uses the app service role + the SYS env context
//! (the rows are scope-`env`), mirroring `conformance.rs::spawn_server`.

#![allow(dead_code)]

use std::sync::Arc;

use sqlx::PgPool;

use sentin8_auth_server::{build_router, AppState, SigningKeys, TestConfig};

/// The platform system env UUID (the tests' tenant fixture: profile rows +
/// clients + users all live here).
pub const SYS_ENV: uuid::Uuid = uuid::uuid!("00000000-0000-0000-0000-000000000002");

/// The platform system org UUID (org-scope rows + RLS org lookups).
pub const SYS_ORG: uuid::Uuid = uuid::uuid!("00000000-0000-0000-0000-000000000001");

/// One registered redirect URI shared by the mirror clients (a
/// suite-callback-shaped https url - the rig's redirect shape).
pub const REDIRECT_URI: &str = "https://rp.example.org/cb";

/// A registered POST-LOGOUT landing shared by the logout-mirror clients
/// (the suite's `{base}/post_logout_redirect` shape).
pub const POST_LOGOUT_URI: &str = "https://rp.example.org/post_logout_redirect";

// ── Posture (profile row) seeds ─────────────────────────────────────────

/// The per-posture flag shape the battery seeds per family env
/// (auth DESIGN §9a.2 step 2). One row per posture, keyed by the
/// `profile` enum member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    /// env `standard` (the Basic/Config/Dynamic/Logout families).
    Standard,
    /// env `fapi_1_advanced` (PAR + JARM + strict PKCE + query-reject).
    Fapi1Advanced,
    /// env `fapi_2` (PAR + DPoP + JARM).
    Fapi2,
    /// env `fapi_2_message_signing` (FAPI2 + the message-signing details).
    Fapi2MessageSigning,
    /// env `fapi_ciba` (CIBA ID1: no PAR, DPoP on, strict client auth).
    FapiCiba,
    /// env `vci` (the OID4VCI issuer family).
    Vci,
    /// env `vci_haip` (the HAIP family: attestation auth + encryption).
    VciHaip,
}

impl Posture {
    /// The `security_profiles.profile` row value.
    pub fn row_name(&self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Fapi1Advanced => "fapi_1_advanced",
            Self::Fapi2 => "fapi_2",
            Self::Fapi2MessageSigning => "fapi_2_message_signing",
            Self::FapiCiba => "fapi_ciba",
            Self::Vci => "vci",
            Self::VciHaip => "vci_haip",
        }
    }

    /// The request-object mandate table (`fapi.rs required_flags`).
    pub fn fapi_profile(&self) -> Option<sentin8_auth_server::fapi::FapiProfile> {
        use sentin8_auth_server::fapi::FapiProfile;
        match self {
            Self::Standard | Self::Vci | Self::VciHaip => None,
            Self::Fapi1Advanced => Some(FapiProfile::Fapi10Advanced),
            Self::Fapi2 => Some(FapiProfile::Fapi20),
            Self::Fapi2MessageSigning => Some(FapiProfile::Fapi20MessageSigning),
            Self::FapiCiba => None,
        }
    }
}

/// Serialize the DB-mutating profile tests (they write the same
/// `security_profiles` rows - the unique index makes concurrent upserts
/// race). Same pattern as conformance_profiles.rs.
pub static DB_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Seed the SYS env's profile row for a posture (the per-env shape).
///
/// `signing_alg` = RS256 (the rig's classical posture - §9a.2 step 3).
/// `with_attestation` rides the vci_haip family's extra columns
/// (§9a.19) when the caller supplies trust-anchor material.
pub async fn seed_profile(pool: &PgPool, posture: &Posture, attestation: Option<(&str, &str)>) {
    let (allow_att, anchor_pem, att_issuer) = attestation
        .map(|(a, i)| (true, a.to_string(), i.to_string()))
        .unwrap_or((false, String::new(), String::new()));
    let mut tx = pool.begin().await.expect("profile seed tx");
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(SYS_ENV)
        .execute(&mut *tx)
        .await;
    sqlx::query(
        r#"INSERT INTO auth.security_profiles
             (scope, org_id, env_id, profile, require_par, require_mtls,
              require_jarm, require_dpop, require_iss, max_token_lifetime,
              refresh_rotation, signing_alg, allow_client_attestation,
              client_attestation_trust_anchor_pem, client_attestation_issuer)
           VALUES ('env', $1, $2, $3, $4, $5, $6, $7, true, 900, false, 'RS256',
                   $8, $9, $10)
           ON CONFLICT (scope, org_id, env_id) WHERE org_id IS NOT NULL AND env_id IS NOT NULL
           DO UPDATE SET profile = $3, require_par = $4, require_mtls = $5,
             require_jarm = $6, require_dpop = $7, require_iss = true,
             max_token_lifetime = 900, refresh_rotation = false,
             signing_alg = 'RS256', allow_client_attestation = $8,
             client_attestation_trust_anchor_pem = $9,
             client_attestation_issuer = $10"#,
    )
    .bind(SYS_ORG)
    .bind(SYS_ENV)
    .bind(posture.row_name())
    .bind(
        posture == &Posture::Fapi1Advanced
            || posture == &Posture::Fapi2
            || posture == &Posture::Fapi2MessageSigning,
    )
    .bind(false)
    .bind(matches!(
        posture,
        Posture::Fapi1Advanced | Posture::Fapi2 | Posture::Fapi2MessageSigning
    ))
    .bind(matches!(
        posture,
        Posture::Fapi2 | Posture::Fapi2MessageSigning | Posture::FapiCiba
    ))
    .bind(allow_att)
    .bind(&anchor_pem)
    .bind(&att_issuer)
    .execute(&mut *tx)
    .await
    .expect("seed security profile row");
    tx.commit().await.expect("commit profile seed");
}

/// Restore the env `standard` profile row (the tests' default posture -
/// conformance.rs's shape) so other suites are unaffected.
pub async fn restore_standard_profile(pool: &PgPool) {
    seed_profile(pool, &Posture::Standard, None).await;
    // conformance.rs's harness seeds refresh_rotation=true on this row -
    // converge the two shapes.
    sqlx::query(
        "UPDATE auth.security_profiles SET refresh_rotation = true WHERE scope='env' AND env_id=$1",
    )
    .bind(SYS_ENV)
    .execute(pool)
    .await
    .ok();
}

// ── Server + clients ────────────────────────────────────────────────────

/// Spin up an in-process Auth server with the shared harness shape.
///
/// Runtime-skip gating: returns `None` when PostgreSQL is unreachable -
/// the caller prints one `skipping` line (conformance.rs pattern).
pub async fn spawn_server() -> Option<(axum::Router, PgPool)> {
    // cargo test does NOT run the binary's dotenvy step - load the repo
    // .env so the service-role DSN (search_path=auth) applies.
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

/// The scope-mirror Shield engine (conformance.rs's seed - the enforced
/// set the enroll path provisions for sentin8:auth; fail-closed otherwise).
pub fn seeded_auth_engine() -> std::sync::Arc<sentin8_auth_server::policy::Engine> {
    use sentin8::shield::{PolicyMode, PolicyOrigin, PolicySetRecord};
    let engine = sentin8_auth_server::policy::Engine::new("sentin8:auth");
    let record = PolicySetRecord {
        id: uuid::Uuid::nil(),
        env_id: SYS_ENV,
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
        )
        .to_string(),
        schema: None,
        origin: PolicyOrigin::Platform,
        mode: PolicyMode::Enforced,
        version: 1,
        enabled: true,
    };
    engine.upsert(record).expect("seed auth scope-mirror set");
    std::sync::Arc::new(engine)
}

/// URL-encode a component (tests' urlencode).
pub fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

/// A unique per-test source IP (bot-protection rate windows are per-IP).
pub fn unique_ip() -> String {
    format!(
        "10.{}.{}.{}",
        rand::random::<u16>() % 250 + 10,
        rand::random::<u16>() % 250 + 2,
        rand::random::<u16>() % 250 + 2
    )
}

/// Sign up a user through `/v1/sign-up` (the identity plane's real path);
/// returns `(email, password, session_bearer)`.
pub async fn sign_up_user(app: &axum::Router) -> (String, String, String) {
    let email = format!(
        "oidf_{}@test.local.sentin8.dev",
        uuid::Uuid::new_v4().simple()
    );
    let password = "oidf_password_123";
    let body = serde_json::json!({
        "email": email,
        "password": password,
        "first_name": "Oidf",
        "last_name": "Mirror",
    });
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/sign-up")
                .header("content-type", "application/json")
                .header("x-forwarded-for", unique_ip())
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
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
        axum::http::StatusCode::CREATED,
        "sign-up must succeed"
    );
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    (
        email,
        password.to_string(),
        json["token"].as_str().unwrap().to_string(),
    )
}

/// The common client-registrations column shape.
pub struct RegisteredClient {
    /// The oauth_clients row id.
    pub id: uuid::Uuid,
    /// The OAuth client_id string.
    pub client_id: String,
    /// The plaintext secret (confidential-secret clients only).
    pub secret: Option<String>,
    /// The client's inline jwks (assertion/attestation clients).
    pub jwks: Option<serde_json::Value>,
}

/// Insert a client row with the FULL mirror shape + common options.
///
/// This is the mirror's DCR-equivalent (the rig seeds clients via
/// `conformance-seed.sh`; the in-process mirror seeds via the same SQL
/// shapes the DCR handler writes).
#[allow(clippy::too_many_arguments)]
pub async fn register_client(pool: &PgPool, spec: &ClientSpec) -> RegisteredClient {
    let row_id = uuid::Uuid::new_v4();
    let client_id = format!("oidf-{}", uuid::Uuid::new_v4().simple());
    // bcrypt the plaintext secret (the token endpoint's client-secret
    // verifier compares against this hash). A spec WITHOUT a secret
    // registers a hashless row (public/assertion/attestation clients).
    let secret_hash: Option<String> = match spec.secret {
        Some(pw) => Some(bcrypt::hash(pw, bcrypt::DEFAULT_COST).expect("bcrypt")),
        None => None,
    };
    let mut tx = pool.begin().await.expect("client seed tx");
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(SYS_ENV)
        .execute(&mut *tx)
        .await;
    let default_redirects = vec![REDIRECT_URI.to_string()];
    let redirects = spec.redirect_uris.as_ref().unwrap_or(&default_redirects);
    let post_logout: Vec<String> = spec.post_logout_uris.clone().unwrap_or_default();
    sqlx::query(
        r#"INSERT INTO oauth_clients
             (id, env_id, client_id, client_name, client_secret_hash,
              redirect_uris, post_logout_redirect_uris, grant_types,
              response_types, token_endpoint_auth_method, scopes, jwks,
              backchannel_logout_uri, consent_required)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)"#,
    )
    .bind(row_id)
    .bind(SYS_ENV)
    .bind(&client_id)
    .bind(spec.name)
    .bind(&secret_hash)
    .bind(redirects)
    .bind(&post_logout)
    .bind(spec.grant_types.to_vec())
    .bind(spec.response_types.to_vec())
    .bind(spec.auth_method)
    .bind(spec.scopes.to_vec())
    .bind(spec.jwks.as_ref())
    .bind(spec.backchannel_logout_uri)
    .bind(false)
    .execute(&mut *tx)
    .await
    .expect("insert oauth_clients row");
    tx.commit().await.expect("commit client seed");
    RegisteredClient {
        id: row_id,
        client_id,
        secret: spec.secret.map(str::to_string),
        jwks: spec.jwks.clone(),
    }
}

/// A client-registration fixture (the columns the mirror seeds).
pub struct ClientSpec {
    /// client_name.
    pub name: &'static str,
    /// token_endpoint_auth_method.
    pub auth_method: &'static str,
    /// grant_types array.
    pub grant_types: &'static [&'static str],
    /// response_types array.
    pub response_types: &'static [&'static str],
    /// scopes array.
    pub scopes: &'static [&'static str],
    /// client_secret (plaintext; hashed into the row).
    pub secret: Option<&'static str>,
    /// Extra redirect URIs (defaults to [`REDIRECT_URI`]).
    pub redirect_uris: Option<Vec<String>>,
    /// post-logout URIs (the logout family registers one).
    pub post_logout_uris: Option<Vec<String>>,
    /// inline jwks (assertion / attestation / JAR clients).
    pub jwks: Option<serde_json::Value>,
    /// backchannel_logout_uri (the BC-logout family).
    pub backchannel_logout_uri: Option<&'static str>,
}

impl ClientSpec {
    /// A confidential client_secret_post client.
    pub fn secret_post() -> Self {
        Self {
            name: "Mirror Secret Post",
            auth_method: "client_secret_post",
            grant_types: &["authorization_code", "refresh_token", "client_credentials"],
            response_types: &["code"],
            scopes: &[
                "openid",
                "profile",
                "email",
                "phone",
                "address",
                "offline_access",
            ],
            secret: Some("oidf-mirror-secret"),
            redirect_uris: None,
            post_logout_uris: None,
            jwks: None,
            backchannel_logout_uri: None,
        }
    }

    /// A confidential client_secret_basic client.
    pub fn secret_basic() -> Self {
        Self {
            name: "Mirror Secret Basic",
            auth_method: "client_secret_basic",
            ..Self::secret_post()
        }
    }

    /// A private_key_jwt confidential client (inline jwks).
    pub fn private_key_jwt(jwks: serde_json::Value) -> Self {
        Self {
            name: "Mirror PKJWT",
            auth_method: "private_key_jwt",
            grant_types: &["authorization_code", "refresh_token", "client_credentials"],
            response_types: &["code"],
            scopes: &[
                "openid",
                "profile",
                "email",
                "phone",
                "address",
                "offline_access",
            ],
            secret: None,
            redirect_uris: None,
            post_logout_uris: None,
            jwks: Some(jwks),
            backchannel_logout_uri: None,
        }
    }

    /// A public PKCE client (token_endpoint_auth_method=none).
    pub fn public_client() -> Self {
        Self {
            name: "Mirror Public",
            auth_method: "none",
            ..Self::secret_post()
        }
    }
}

/// Complete the hosted sign-in step for an authorize flow and return the
/// resulting HTTP response + body (the `authorize_continue` helper -
/// conformance.rs's shape).
pub async fn authorize_continue(
    app: &axum::Router,
    pool: &PgPool,
    session_token: &str,
    authorize_uri: &str,
) -> (axum::http::StatusCode, serde_json::Value, Option<String>) {
    // Step 1: GET /oauth/authorize - 302 to the hosted sign-in with the
    // RESOLVED OAuth params as query params.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri(authorize_uri)
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    if !(status.is_success() || status == axum::http::StatusCode::FOUND) {
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok().map(str::to_string));
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        return (status, json, location);
    }
    let resolved = if status == axum::http::StatusCode::FOUND {
        resp.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|loc| url::Url::parse(&format!("https://auth.test{loc}")).ok())
            .and_then(|o| o)
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
    let _continue_location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok().map(str::to_string));

    // Resolve the session's user_id (RLS: the SYS env context).
    let user_id: uuid::Uuid = {
        let mut tx = pool.begin().await.expect("begin session lookup tx");
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(SYS_ENV)
            .execute(&mut *tx)
            .await;
        let uid: uuid::Uuid =
            sqlx::query_scalar("SELECT user_id FROM sessions WHERE token_id = $1")
                .bind(session_token)
                .fetch_one(&mut *tx)
                .await
                .expect("session lookup");
        tx.rollback().await.ok();
        uid
    };

    // Step 2: POST /oauth/authorize/continue with the full request shape.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/oauth/authorize/continue")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {session_token}"))
                .body(axum::body::Body::from(
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
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok().map(str::to_string));
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    (status, json, location)
}

/// Register a client + run the FULL Basic journey (sign-up → authorize
/// continue with prompt=none → code exchange) and return the minted
/// ACCESS-token bearer + the client. The journey is the mirror's
/// in-process `oidcc-server`: everything after rides real endpoints.
///
/// Uses `offline_access` in the scope (the exchange's refresh gate) and
/// the standard `email` scope (the userinfo claims family).
pub async fn mint_user_access_token(
    app: &axum::Router,
    pool: &PgPool,
) -> (Option<String>, Option<RegisteredClient>) {
    let Some((_email, _pw, session)) = Some(sign_up_user(app).await) else {
        return (None, None);
    };
    let client = register_client(pool, &ClientSpec::secret_post()).await;
    let verifier = "m".repeat(64);
    let authorize_uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile%20email%20offline_access&state=st-mint&code_challenge={challenge}&code_challenge_method=S256&prompt=none&nonce=oidf-nonce-mint",
        client.client_id,
        urlencode(REDIRECT_URI),
        challenge = sentin8_auth_server::pkce_s256_challenge_for_tests(&verifier),
    );
    let (st, _body, location) = authorize_continue(app, pool, &session, &authorize_uri).await;
    if st != axum::http::StatusCode::FOUND {
        eprintln!("mint_user_access_token: authorize answered {st}");
        return (None, Some(client));
    }
    let loc = match location {
        Some(l) => l,
        None => {
            eprintln!("mint_user_access_token: no callback location");
            return (None, Some(client));
        }
    };
    let code = loc
        .split("code=")
        .nth(1)
        .unwrap_or("")
        .split('&')
        .next()
        .unwrap_or("")
        .to_string();
    if code.is_empty() {
        eprintln!("mint_user_access_token: no code in the callback ({loc})");
        return (None, Some(client));
    }
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!(
                    "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={verifier}",
                    urlencode(REDIRECT_URI),
                    client.client_id,
                    client.secret.as_deref().unwrap_or(""),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    if status != axum::http::StatusCode::OK {
        eprintln!("mint_user_access_token: exchange answered {status} {tok}");
        return (None, Some(client));
    }
    (
        tok["access_token"].as_str().map(str::to_string),
        Some(client),
    )
}

// Re-exports the module users need (dead-code allowed above: some helpers
// are per-file concerns).
pub use tower::ServiceExt;

// ── JWT helpers (the mirror's client-side cryptography) ────────────────

/// URL-safe base64 (no padding) - the JOSE encoding (RFC 7515 §3).
pub fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

// Engine trait import for the encode helpers.
use base64::Engine as _;

fn b64url_json(v: &serde_json::Value) -> String {
    b64url(serde_json::to_vec(v).expect("serialize json").as_slice())
}

/// Generate an ES256 P-256 keypair: `(public_jwk, signing_key)` - the
/// RFC 7517 EC JWK + the signer the mirror signs assertions/objects with.
pub fn mk_es256_key_for_tests() -> (serde_json::Value, p256::ecdsa::SigningKey) {
    let signing_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let x = encoded.x().expect("P-256 point has x");
    let y = encoded.y().expect("P-256 point has y");
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(x.as_slice()),
        "y": b64url(y.as_slice()),
    });
    (jwk, signing_key)
}

/// Mint an RFC 9449 DPoP proof signed by the GIVEN key (the mirror's
/// sender-constraint cells need a SPECIFIC key, unlike `support`'s
/// self-generating helper).
pub fn mk_dpop_proof_for_tests(
    method: &str,
    uri: &str,
    jti_salt: u64,
    key: &p256::ecdsa::SigningKey,
) -> String {
    let verifying_key = key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(encoded.x().expect("x").as_slice()),
        "y": b64url(encoded.y().expect("y").as_slice()),
    });
    let signing_input = format!(
        "{}.{}",
        b64url_json(&serde_json::json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk})),
        b64url_json(&serde_json::json!({
            "htm": method.to_uppercase(),
            "htu": uri,
            "jti": format!("{jti_salt}-{}", uuid::Uuid::new_v4()),
            "iat": chrono::Utc::now().timestamp(),
        }))
    );
    use p256::ecdsa::signature::Signer as _;
    let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64url(sig.to_bytes().as_slice()))
}

/// Mint an RFC 7523 client assertion signed by the given key with the
/// given audience and iss/sub (the mirror's assertion cells control
/// every member).
pub fn mk_assertion_for(
    key: &p256::ecdsa::SigningKey,
    iss: &str,
    sub: &str,
    aud: &serde_json::Value,
    jti: &str,
    exp_delta: i64,
) -> String {
    let claims = serde_json::json!({
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "exp": chrono::Utc::now().timestamp() + exp_delta,
        "iat": chrono::Utc::now().timestamp(),
        "jti": jti,
    });
    mk_jwt(
        &serde_json::json!({"alg": "ES256", "typ": "JWT"}),
        &claims,
        Some(key),
    )
}

/// A globally-unique jti bound to a client (the replay cache's shape).
pub fn unique_jti(client_id: &str) -> String {
    format!("{client_id}:{}", uuid::Uuid::new_v4())
}

/// Sign a compact JWS/unsigned JWT with ES256 and the given header claims.
/// `alg: "none"` produces the unsigned 2-segment form (trailing `.`).
pub fn mk_jwt(
    header: &serde_json::Value,
    claims: &serde_json::Value,
    key: Option<&p256::ecdsa::SigningKey>,
) -> String {
    let signing_input = format!("{}.{}", b64url_json(header), b64url_json(claims));
    match key {
        Some(k) => {
            use p256::ecdsa::signature::Signer;
            let sig: p256::ecdsa::Signature = k.sign(signing_input.as_bytes());
            format!("{signing_input}.{}", b64url(sig.to_bytes().as_slice()))
        }
        None => format!("{signing_input}."),
    }
}

/// The RFC 7638 JWK thumbprint (RSA + EC public JWK members,
/// lexicographic order, SHA-256, URL-safe base64 - `jar.rs`/`dpop.rs`
/// contract). Duplicates the wire helper for the mirror's client side.
pub fn jwk_thumbprint_for_tests(jwk: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    let mut members: Vec<String> = Vec::new();
    for k in ["e", "kty", "n", "crv", "x", "y"] {
        if let Some(v) = jwk.get(k) {
            members.push(format!("\"{k}\":{v}"));
        }
    }
    members.sort();
    let input = format!("{{{}}}", members.join(","));
    b64url(&Sha256::digest(input.as_bytes()))
}

/// Mint an RS-capable RSA keypair for the mirror's RSA-side
/// assertions/request objects (the suite's RSA jwks clients). Returns
/// the PUBLIC JWK + the private key (sign via [`rsa_sign_jws`]).
pub fn mk_rsa_key() -> (serde_json::Value, rsa::RsaPrivateKey) {
    let mut rng = rand::thread_rng();
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    let public = rsa::RsaPublicKey::from(&private);
    use rsa::traits::PublicKeyParts;
    let n = b64url(&public.n().to_bytes_be());
    let e = b64url(&public.e().to_bytes_be());
    let jwk = serde_json::json!({ "kty": "RSA", "n": n, "e": e });
    (jwk, private)
}

/// Sign a JWS with the RSA private key: `RS256` (PKCS#1 v1.5) or `PS256`
/// (RSASSA-PSS, salt = the SHA-256 digest size per RFC 7518 §3.5 - the
/// same `rsa::pss` primitive the server verifies with, jwks.rs).
pub fn rsa_sign_jws(private: &rsa::RsaPrivateKey, signing_input: &str, alg: &str) -> String {
    use rsa::sha2::{Digest, Sha256};
    use rsa::signature::SignatureEncoding as _;
    match alg {
        "PS256" => {
            use rsa::signature::RandomizedSigner;
            let sk = rsa::pss::SigningKey::<Sha256>::new(private.clone());
            b64url(
                &sk.sign_with_rng(&mut rand::rngs::OsRng, signing_input.as_bytes())
                    .to_bytes(),
            )
        }
        _ => {
            // RSASSA-PKCS1-v1_5 over the SHA-256 digest (RFC 7518 §3.4).
            let digest = Sha256::digest(signing_input.as_bytes());
            let sig = private
                .sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest)
                .expect("pkcs1 sign");
            b64url(&sig)
        }
    }
}
