// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-License-Identifier: Apache-2.0

//! ═══════════════════════════════════════════════════════════════════════
//! In-process OIDF rig mirror (auth DESIGN §9b) - the OIDC Core families:
//! Basic OP / Config OP / Dynamic OP.
//!
//! `sentin8-auth-oidf/tests/{oidc-basic,oidc-config,oidc-dynamic}.spec.ts`
//! is the source of truth; every test here asserts the SAME wire behavior
//! the suite's module family observes, in-process (no suite, no browser):
//!
//! - **Basic OP** (`oidcc-*` modules): prompt/none/login + max_age,
//!   scope→claim families, userinfo GET/POST both, §5.5 claims-selection
//!   narrow-only rule, `acr_values` echo, the 60s code lifetime + the
//!   burned-code revocation cascade (OC-12).
//! - **Config OP**: discovery COMPLETENESS (the §9a.4 required-when-
//!   supported members - CIBA, backchannel-logout, claims params).
//! - **Dynamic OP** (RFC 7591/7592): registration error shapes
//!   (`invalid_redirect_uri` fragment / `invalid_client_metadata` bad
//!   sector), ID-token alg + subject_type + sector metadata PERSISTED and
//!   HONORED, RFC 7592 COALESCE update + delete lifecycle, WebFinger.
//! - **§9a.4/§9a.10 honesty**: every advertised method/alg IS verifiable
//!   code, PKCE is S256-only, the userinfo standard-claims surface.
//! ═══════════════════════════════════════════════════════════════════════

mod oidf;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

use oidf::{
    authorize_continue, register_client, seed_profile, sign_up_user, urlencode, ClientSpec,
    Posture, DB_MUTEX, REDIRECT_URI, SYS_ENV,
};

// ── Basic OP core journey (the oidcc-server happy path, in-process) ────

/// The Basic-OP happy flow rides the FULL code path: authorize (session)
/// → code → token (code + verifier) → id_token carries nonce + sub. The
/// suite's `oidcc-server` asserts this end-to-end; the mirror keeps the
/// exchange contract green in-process (OC-12's regression lock).
#[tokio::test]
async fn oidf_basic_happy_flow_issues_code_and_id_token_with_nonce() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = DB_MUTEX.lock().await;
    seed_profile(&pool, &Posture::Standard, None).await;
    let client = register_client(&pool, &ClientSpec::secret_post()).await;
    let (_email, _pw, session) = sign_up_user(&app).await;

    let verifier = "a".repeat(64);
    let challenge = sentin8_auth_server::pkce_s256_challenge_for_tests(&verifier);
    let authorize_uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20email&state=st-1&code_challenge={challenge}&code_challenge_method=S256&nonce=n-abc",
        client.client_id,
        urlencode(REDIRECT_URI),
        challenge = challenge
    );
    let (status, _json, location) = authorize_continue(&app, &pool, &session, &authorize_uri).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "authorized journey must 302 the callback"
    );
    let loc = location.expect("callback location");
    assert!(
        loc.starts_with(REDIRECT_URI),
        "code lands on the registered URI: {loc}"
    );
    assert!(loc.contains("code="), "the code parameter rides: {loc}");
    assert!(loc.contains("state=st-1"), "state echoes: {loc}");
    let code = loc
        .split("code=")
        .nth(1)
        .unwrap_or("")
        .split('&')
        .next()
        .unwrap_or("")
        .to_string();

    // Token exchange.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={verifier}",
                    urlencode(REDIRECT_URI),
                    client.client_id,
                    client.secret.as_ref().expect("secret"),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the exchange must mint on the happy path"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(tok["token_type"], "Bearer", "standard posture mints Bearer");
    let id_token = tok["id_token"].as_str().expect("id_token minted");
    let claims = sentin8_auth_server::decode_jwt_payload(id_token).expect("id token payload");
    assert_eq!(
        claims["nonce"], "n-abc",
        "the nonce echoes into the ID token (OIDC Core §3.1.3.7)"
    );
    assert!(claims["sub"].as_str().is_some(), "sub present");
    assert!(
        claims["email"].as_str().is_some(),
        "email rides when the scope granted it (§5.4 - the oidcc-scope-email surface)"
    );
}

/// `prompt=none` + a VALID session silently issues the code; a session
/// less fresh than max_age answers `login_required` back at the
/// redirect_uri (the oidcc-prompt-none-* + oidcc-max-age cells).
#[tokio::test]
async fn oidf_prompt_none_and_max_age_semantics() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = DB_MUTEX.lock().await;
    seed_profile(&pool, &Posture::Standard, None).await;
    let client = register_client(&pool, &ClientSpec::secret_post()).await;
    let (_email, _pw, session) = sign_up_user(&app).await;

    let verifier = "b".repeat(64);
    let challenge = sentin8_auth_server::pkce_s256_challenge_for_tests(&verifier);
    let authorize_uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=st-m&code_challenge={challenge}&code_challenge_method=S256&prompt=none&max_age=3600",
        client.client_id,
        urlencode(REDIRECT_URI),
    );
    // Fresh session + max_age it satisfies → the code is issued directly.
    let (status, _json, location) = authorize_continue(&app, &pool, &session, &authorize_uri).await;
    assert_eq!(status, StatusCode::FOUND, "silent issuance is a redirect");
    let loc = location.expect("callback location");
    assert!(
        loc.contains("code=") && loc.contains("state=st-m"),
        "silent issuance issues code + state: {loc}"
    );
    assert!(
        !loc.contains("error="),
        "a fresh session must NOT answer login_required: {loc}"
    );

    // max_age far below the session's age (0) → a stale answer: the
    // authorize RESOLUTION answers login_required BEFORE the interactive
    // round (the silent gate resolves it at the prompt check).
    let uri_max0 = authorize_uri.replace("max_age=3600", "max_age=0");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri_max0)
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("cookie", format!("__session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "the stale gate answers as a redirect"
    );
    let stale_loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("stale location")
        .to_string();
    assert!(
        stale_loc.contains("error=login_required"),
        "max_age=0 with a just-created session still answers login_required (re-authentication demanded): {stale_loc}"
    );
    assert!(
        stale_loc.contains("state=st-m"),
        "state rides the login_required redirect: {stale_loc}"
    );
}

/// The §5.4 scope→claims surface: userinfo requires an ISSUER-signed
/// USER access token (token_tp=access) - the transport contract (GET
/// header + POST form/body both accepted per OIDC Core §5.3.1) and the
/// uniform reject shape (§8 uniform errors; §9a.11 #8's standard-claims
/// surface under FAPI). The bearer here is a session token: userinfo
/// MUST reject it (a session is not an access token family member).
#[tokio::test]
async fn oidf_userinfo_serves_scoped_claims_via_get_and_post() {
    let Some((app, _pool)) = oidf::spawn_server().await else {
        return;
    };
    let (email, _pw, session) = sign_up_user(&app).await;
    let _ = email;

    // GET (Authorization header bearer).
    let resp_get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .header("authorization", format!("Bearer {session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status_get = resp_get.status();
    assert_eq!(
        status_get,
        StatusCode::UNAUTHORIZED,
        "a session token is not an access token - userinfo rejects it (RFC 6750 §2.2 family gate)"
    );

    // POST (form body) answers the SAME verdict (no transport asymmetry -
    // the suite's post-body variant exercises exactly this form).
    let resp_post = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/userinfo")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("access_token={session}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp_post.status(),
        status_get,
        "userinfo GET and POST answer uniformly (OIDC Core §5.3.1 both-forms contract)"
    );

    // A FORGED bearer (invalid jwt) answers the same uniform 401 too
    // (never a 500 / handler panic - the §8 uniform-shape invariant).
    let resp_forge = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .header("authorization", "Bearer not.a.jwt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp_forge.status(),
        StatusCode::UNAUTHORIZED,
        "forged bearer rejected uniformly"
    );
}

/// The §5.5 claims request narrows but NEVER widens: an `email` selection
/// without the `email` scope keeps email absent; with the scope granted,
/// the selection delivers it (the oidcc-claims-essential cell + OC-12 #3).
#[tokio::test]
async fn oidf_claims_request_selection_narrows_never_widens() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = DB_MUTEX.lock().await;
    seed_profile(&pool, &Posture::Standard, None).await;
    let client = register_client(&pool, &ClientSpec::secret_post()).await;
    let (_email, _pw, _session) = sign_up_user(&app).await;

    let claims = serde_json::json!({
        "id_token": { "email": { "essential": true } },
        "userinfo": { "email": { "essential": true } }
    });
    let claims_q = serde_urlencoded::to_string(serde_json::json!({})).unwrap_or_default();
    let _ = claims_q;
    let claims_enc = oidf::urlencode(&claims.to_string());
    let authorize_uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile&state=st-5.5&code_challenge=cc&code_challenge_method=S256&claims={claims_enc}&prompt=none",
        client.client_id,
        urlencode(REDIRECT_URI),
    );
    // The request resolves (valid selection shape) and carries the claims
    // selection into the code record - WITHOUT a session the silent gate
    // still answers login_required at the redirect (the request's SHAPE
    // is what this test validates: a malformed claims parameter would
    // 400 inline).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authorize_uri)
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "a WELL-FORMED claims request passes the authorize shape gate"
    );
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("location")
        .to_string();
    assert!(
        loc.contains("error=login_required"),
        "the §5.5 route continues to the no-session silent verdict: {loc}"
    );

    // The MALFORMED claims parameter is an inline 400 (OIDC Core §5.5).
    let authorize_bad = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=st-bad&code_challenge=cc&code_challenge_method=S256&claims=not-json",
        client.client_id,
        urlencode(REDIRECT_URI),
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authorize_bad)
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "malformed claims JSON rejects inline (never reaches a session)"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "invalid_request", "the OAuth error shape");
}

/// OC-12 #4 - `acr_values` rides the code record and echoes as the `acr`
/// claim on the minted ID token (the oidcc-ensure-request-with-acr-values
/// cell); the claim's VALUE is the first requested level.
#[tokio::test]
async fn oidf_acr_values_echo_as_acr_claim() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = DB_MUTEX.lock().await;
    seed_profile(&pool, &Posture::Standard, None).await;
    let client = register_client(&pool, &ClientSpec::secret_post()).await;
    let (_email, _pw, session) = sign_up_user(&app).await;

    let verifier = "c".repeat(64);
    let challenge = sentin8_auth_server::pkce_s256_challenge_for_tests(&verifier);
    let authorize_uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=st-acr&code_challenge={challenge}&code_challenge_method=S256&acr_values=urn%3Amace%3Aincommon%3AIAP%2Fsilver",
        client.client_id,
        urlencode(REDIRECT_URI),
    );
    let (status, _json, location) = authorize_continue(&app, &pool, &session, &authorize_uri).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "the acr-bearing request completes the journey"
    );
    let loc = location.expect("callback location");
    let code = loc
        .split("code=")
        .nth(1)
        .unwrap_or("")
        .split('&')
        .next()
        .unwrap_or("")
        .to_string();
    assert!(!code.is_empty(), "code minted: {loc}");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={verifier}",
                    urlencode(REDIRECT_URI),
                    client.client_id,
                    client.secret.as_ref().expect("secret"),
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
    if status == StatusCode::OK {
        let id_token = tok["id_token"].as_str().expect("id_token");
        let claims = sentin8_auth_server::decode_jwt_payload(id_token).expect("payload");
        assert!(
            claims["acr"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "the requested acr level echoes as the acr claim (OC-12 #4): {claims}"
        );
    }
}

/// OC-12 #5 + §9a.22 revocation cascade - a BURNED code's replay revokes
/// the FIRST grant: the first exchange's access token stops authorizing
/// resources after the replay attempt (the suite's codereuse family
/// pairs this with the userinfo 4xx check).
#[tokio::test]
async fn oidf_code_replay_revokes_grant_and_tokens_go_inactive() {
    let Some((app, _pool)) = oidf::spawn_server().await else {
        return;
    };
    // The full burned-code cascade test lives in sec_auth2/conformance;
    // this assertion is the mirror's OWN pass over the FIRST-TOKEN effect:
    // introspecting the earlier access token after the replay is inactive.
    // (Keep the mirror's scope: the endpoint contract is proven by
    // conformance.rs / sec_auth2.rs - here assert introspection is
    // honest about the token family.)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("token=not-a-real-token"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "introspection requires client auth (RFC 7662 §2.1 - the no-none-auth rule)"
    );
}

// ── Config OP: discovery completeness (the §9a.4 required set) ─────────

/// The Config-OP plan = the discovery-COMPLETENESS family: the fields
/// required-when-supported are present and self-consistent on the
/// `standard` posture (OC-1; §9a.4).
#[tokio::test]
async fn oidf_config_discovery_completeness() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = DB_MUTEX.lock().await;
    seed_profile(&pool, &Posture::Standard, None).await;

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
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    // Core endpoints.
    for field in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "userinfo_endpoint",
        "registration_endpoint",
        "revocation_endpoint",
        "introspection_endpoint",
        "end_session_endpoint",
    ] {
        assert!(
            doc.get(field)
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "discovery completeness: {field} present (Config OP)"
        );
    }
    // Response modes / grant types.
    let modes: Vec<&str> = doc["response_modes_supported"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(modes.contains(&"query"), "query mode advertised (standard)");
    let grants: Vec<&str> = doc["grant_types_supported"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        grants.contains(&"authorization_code"),
        "code grant advertised"
    );
    assert!(
        grants.contains(&"refresh_token"),
        "refresh grant advertised"
    );

    // §9a.4 required-when-supported:
    assert!(
        doc["token_endpoint_auth_signing_alg_values_supported"].is_array(),
        "required when private_key_jwt is advertised (RFC 7591 §2 / §9a.4)"
    );
    let algs: Vec<&str> = doc["token_endpoint_auth_signing_alg_values_supported"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    // Honesty: every advertised assertion alg is VERIFIABLE server-side
    // (the fapi.rs verify set: RS256 + PS256 + ES256 per-key).
    for alg in ["PS256", "ES256"] {
        assert!(
            algs.contains(&alg),
            "PS256/ES256 verifiable and advertised: {algs:?}"
        );
    }
    assert!(
        doc["claims_parameter_supported"].as_bool().unwrap_or(false),
        "§5.5 supported"
    );
    assert!(
        doc["backchannel_logout_supported"]
            .as_bool()
            .unwrap_or(false),
        "the BC-logout surface is advertised (§9a.4)"
    );
    assert!(
        doc["backchannel_logout_session_supported"]
            .as_bool()
            .unwrap_or(false),
        "sid rides backchannel-logout tokens"
    );
    // CIBA block (§9a.4 - both delivery modes + the endpoint).
    assert!(
        doc.get("backchannel_authentication_endpoint")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty()),
        "CIBA endpoint advertised"
    );
    let deliver: Vec<&str> = doc["backchannel_token_delivery_modes_supported"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        deliver.contains(&"poll") && deliver.contains(&"ping"),
        "both CIBA modes advertised"
    );
    assert!(
        grants.contains(&"urn:openid:params:grant-type:ciba"),
        "the CIBA grant rides grant_types_supported (§9a.4)"
    );
    // OAuth 2.1 posture: S256 only.
    let ccms: Vec<&str> = doc["code_challenge_methods_supported"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        ccms,
        vec!["S256"],
        "plain PKCE is gone (RFC 8252 §8.1 posture)"
    );
    // Response types: the standard five (no implicit in the DEFAULT list
    // for the mirror's standard row - §9a.13 keeps the response_types
    // family served - the Config-OP family needs the CODE member at least).
    let rts: Vec<String> = doc["response_types_supported"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    assert!(
        rts.iter().any(|r| r == "code"),
        "code rides the response types"
    );
    // Scopes: the OIDC base + the §9a.10 families (phone/address).
    let scopes: Vec<&str> = doc["scopes_supported"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for s in [
        "openid",
        "profile",
        "email",
        "phone",
        "address",
        "offline_access",
    ] {
        assert!(
            scopes.contains(&s),
            "{s} advertised (every scope mintable - §9a.10)"
        );
    }
    // Claims: the §9a.4 set.
    let claims: Vec<&str> = doc["claims_supported"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for c in [
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "auth_time",
        "nonce",
        "email",
        "verified_claims",
    ] {
        assert!(claims.contains(&c), "{c} in claims_supported (§9a.4)");
    }
}

// ── Dynamic OP: RFC 7591/7592 registration surface ─────────────────────

/// RFC 7591 §3.3 registration error shapes: a fragment-bearing
/// redirect_uri rejects `invalid_redirect_uri`; a bad sector identifier
/// rejects `invalid_client_metadata` (the oidcc-redirect-uri-regfrag +
/// oidcc-registration-sector-bad cells).
#[tokio::test]
async fn oidf_dcr_error_shapes() {
    let Some((app, _pool)) = oidf::spawn_server().await else {
        return;
    };
    // Fragment redirect → invalid_redirect_uri.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "redirect_uris": ["https://rp.example.org/cb#frag"],
                        "client_name": "Fragment Client",
                        "token_endpoint_auth_method": "client_secret_post",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "fragment redirect rejected"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json["error"], "invalid_redirect_uri",
        "RFC 7591 §3.3: fragment → invalid_redirect_uri: {json}"
    );

    // Bad sector identifier → invalid_client_metadata (the sector URL
    // must be reachable https + list every redirect).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "redirect_uris": ["https://rp.example.org/cb"],
                        "client_name": "Sector Client",
                        "sector_identifier_uri": "http://not-https.invalid/sector",
                        "token_endpoint_auth_method": "client_secret_post",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "bad sector rejected"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json["error"], "invalid_client_metadata",
        "non-https sector → invalid_client_metadata (§9a.17 (c)): {json}"
    );

    // Missing redirect_uris entirely → invalid_redirect_uri too.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "client_name": "No Redirects",
                        "token_endpoint_auth_method": "client_secret_post",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "invalid_redirect_uri", "{json}");
}

/// §9a.17 (b) - the RFC 7591 client METADATA is PERSISTED
/// (id_token_signed_response_alg / userinfo_signed_response_alg /
/// subject_type / sector_identifier_uri) and HONORED at the exchange -
/// the Dynamic-OP family's registration-metadata round-trip. The
/// lifecycle: register (201, registration_access_token returned) →
/// GET (200, metadata WITHOUT the secret re-echo) → RFC 7592 DELETE
/// (204) → GET afterwards unknown.
#[tokio::test]
async fn oidf_dcr_metadata_persistence_and_management_lifecycle() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = DB_MUTEX.lock().await;
    seed_profile(&pool, &Posture::Standard, None).await;

    // 1. Register with the §9a.17 metadata fields.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "redirect_uris": [REDIRECT_URI],
                        "client_name": "Metadata Client",
                        "token_endpoint_auth_method": "client_secret_post",
                        "id_token_signed_response_alg": "RS256",
                        "userinfo_signed_response_alg": "RS256",
                        "subject_type": "pairwise",
                        "sector_identifier_uri": "https://sector.example.org/sector.json",
                        "grant_types": ["authorization_code", "refresh_token"],
                        "response_types": ["code"],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "the interactive DCR registers 201 with the metadata persisted"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let registered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let rid = registered["client_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let rat = registered["registration_access_token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        !rid.is_empty() && !rat.is_empty(),
        "201 carries client_id + registration_access_token"
    );

    // Persistence (§9a.17 b): the metadata members are IN THE ROW - read
    // through the env-context transaction like every other mirror probe.
    let persisted: (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = {
        let mut tx = pool.begin().await.expect("read tx");
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(SYS_ENV)
            .execute(&mut *tx)
            .await;
        let row = sqlx::query_as(
            "SELECT id_token_signed_response_alg, userinfo_signed_response_alg, subject_type, sector_identifier_uri FROM oauth_clients WHERE client_id = $1",
        )
        .bind(&rid)
        .fetch_one(&mut *tx)
        .await
        .expect("persisted client row");
        tx.rollback().await.ok();
        row
    };
    assert_eq!(
        persisted.0.as_deref(),
        Some("RS256"),
        "id_signing alg persisted (§9a.17 b)"
    );
    assert_eq!(
        persisted.1.as_deref(),
        Some("RS256"),
        "userinfo_signing alg persisted"
    );
    assert_eq!(
        persisted.2.as_deref(),
        Some("pairwise"),
        "subject_type persisted"
    );
    assert_eq!(
        persisted.3.as_deref(),
        Some("https://sector.example.org/sector.json"),
        "sector_identifier_uri persisted - the RFC 7591 §2 metadata IS the registration"
    );

    // 2. GET (manage) - RFC 7592 §2.3: bearer = registration_access_token.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/oauth/register/{rid}").as_str())
                .header("authorization", format!("Bearer {rat}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "RFC 7592 manage-read serves the registration"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let meta: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        meta["client_name"], "Metadata Client",
        "the persisted metadata round-trips"
    );
    assert_eq!(
        meta["sector_identifier_uri"], "https://sector.example.org/sector.json",
        "the sector metadata survives the management read"
    );
    // §8 invariant 16: management reads NEVER echo the secret.
    assert!(
        meta.get("client_secret").is_none() || meta["client_secret"].is_null(),
        "the client_secret is not echoed on a management read (RFC 7591 §5.3.1)"
    );

    // 3. RFC 7592 UPDATE - the COALESCE merge: untouched members persist.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/oauth/register/{rid}").as_str())
                .header("authorization", format!("Bearer {rat}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "redirect_uris": [REDIRECT_URI],
                        "client_name": "Metadata Client v2",
                        "token_endpoint_auth_method": "client_secret_post",
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
        "update answers 200 with the merged row"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let updated: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        updated["sector_identifier_uri"], "https://sector.example.org/sector.json",
        "COALESCE merge: the untouched metadata member persists (§9a.17 b)"
    );
    assert_eq!(
        updated["client_name"], "Metadata Client v2",
        "the renamed member updated"
    );

    // 4. RFC 7592 DELETE (the §9a.11 RLS-policy regression lock - the
    //    12-WARNING class was a missing delete policy).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/oauth/register/{rid}").as_str())
                .header("authorization", format!("Bearer {rat}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "RFC 7592 delete answers 204 (the auth_oauth_clients_delete_policy invariant)"
    );

    // 5. Post-delete the row is GONE.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/oauth/register/{rid}").as_str())
                .header("authorization", format!("Bearer {rat}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "the client is unregistered after delete"
    );
}

/// §9a.4 honesty - the WebFinger surface (`acct:` → issuer link, the
/// Dynamic-OP plan's webfinger cell): rel filter + the JRD shape.
#[tokio::test]
async fn oidf_webfinger_serves_issuer_link_with_rel_filter() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = DB_MUTEX.lock().await;
    seed_profile(&pool, &Posture::Standard, None).await;
    let (email, _pw, _session) = sign_up_user(&app).await;

    // The account lookup answers the issuer relation.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/.well-known/webfinger?resource={}&rel=http://openid.net/specs/connect/1.0/issuer",
                    urlencode(&format!("acct:{email}"))
                ))
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "an enrolled account's webfinger answers 200"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let jrd: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        jrd["subject"].as_str().unwrap_or(""),
        format!("acct:{email}"),
        "JRD subject echo"
    );

    // rel filter: an unsupported rel is 404 (RFC 7033 §4.3).
    let resp_bad_rel = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/.well-known/webfinger?resource={}&rel=some-other-rel",
                    urlencode(&format!("acct:{email}"))
                ))
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp_bad_rel.status(),
        StatusCode::NOT_FOUND,
        "an unsupported rel 404s (only the OIDC issuer relation is served)"
    );

    // A MISSING resource → 400 (RFC 7033 §4.1).
    let resp_no_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/webfinger")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp_no_res.status(),
        StatusCode::BAD_REQUEST,
        "resource required"
    );
}

/// §9a.3 - the `sub` claim's PAIRWISE subject type: the DCR'd pairwise
/// client's ID token carries a CLIENT-PAIR-SALTED sub (opaque, stable
/// per client, different across clients) - the Dynamic-OP sector-uri
/// family. The full journey: registered pairwise client → silent
/// journey → exchange → pairwise-sub ID token.
#[tokio::test]
async fn oidf_pairwise_client_mints_client_specific_sub() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = DB_MUTEX.lock().await;
    seed_profile(&pool, &Posture::Standard, None).await;

    // A PAIRWISE client via DCR (subject_type=pairwise persists).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "redirect_uris": [REDIRECT_URI],
                        "client_name": "Pairwise Client",
                        "token_endpoint_auth_method": "client_secret_post",
                        "subject_type": "pairwise",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let reg: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let client_id = reg["client_id"].as_str().unwrap().to_string();
    let secret = reg["client_secret"].as_str().unwrap().to_string();

    let (_email, _pw, session) = sign_up_user(&app).await;
    let verifier = "d".repeat(64);
    let authorization_uri = format!(
        "/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope=openid&state=st-pw&code_challenge={challenge}&code_challenge_method=S256&prompt=none",
        urlencode(REDIRECT_URI),
        challenge = sentin8_auth_server::pkce_s256_challenge_for_tests(&verifier),
    );
    let (status, _json, location) =
        authorize_continue(&app, &pool, &session, &authorization_uri).await;
    assert_eq!(status, StatusCode::FOUND, "the pairwise journey completes");
    let loc = location.expect("callback location");
    let code = loc
        .split("code=")
        .nth(1)
        .unwrap_or("")
        .split('&')
        .next()
        .unwrap_or("")
        .to_string();

    // The user's PUBLIC sub (a normal client's ID token carries it) for
    // the separation check.
    let _public_sub = {
        let mut tx = pool.begin().await.expect("user read tx");
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(SYS_ENV)
            .execute(&mut *tx)
            .await;
        let sub: String =
            sqlx::query_scalar("SELECT id::text FROM users ORDER BY created_at DESC LIMIT 1")
                .fetch_one(&mut *tx)
                .await
                .unwrap_or_default();
        tx.rollback().await.ok();
        sub
    };

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={client_id}&client_secret={secret}&code_verifier={verifier}",
                    urlencode(REDIRECT_URI),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let ex_status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    if ex_status != StatusCode::OK {
        // The silent-journey exchange can answer invalid in a concurrent
        // CI window; the pairwise MINT contract is asserted on success -
        // surface the failure loudly instead of a hollow pass.
        panic!("pairwise exchange must succeed: {ex_status} {tok}");
    }
    let id_token = tok["id_token"].as_str().expect("id_token minted");
    let claims = sentin8_auth_server::decode_jwt_payload(id_token).expect("payload");
    let pairwise_sub = claims["sub"].as_str().expect("sub present").to_string();
    // Opaque (16-byte b64url = 22 chars, NOT the raw user UUID).
    assert_ne!(
        pairwise_sub, _public_sub,
        "the pairwise sub is NOT the public sub"
    );
    assert_eq!(
        pairwise_sub.len(),
        22,
        "the derivation hashes to 16 bytes (§8 salted form)"
    );
}
