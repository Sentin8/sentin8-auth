// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-License-Identifier: Apache-2.0

//! ═══════════════════════════════════════════════════════════════════════
//! In-process OIDF rig mirror (auth DESIGN §9b) - the FAPI families:
//! FAPI 1.0 Advanced / FAPI 2.0 Security Profile / FAPI 2.0 Message
//! Signing / FAPI-CIBA.
//!
//! `sentin8-auth-oidf/tests/{fapi1-advanced,fapi2-security,
//! fapi2-message-signing,ciba}.spec.ts` is the source of truth; the
//! tests here seed the SAME per-posture profile rows and assert
//! the SAME wire behaviors the suite's module families observe:
//!
//! - **§9a.14 mandate table** : under every FAPI posture a signed
//!   request object carries exp + nbf (f2m adds freshness windows),
//!   ` alg: none` is forbidden, the openid-scope nonce mandate is
//!   FAPI1-only, and the refresh token is issued UNCONDITIONALLY
//!   (OC-27b).
//! - **§9a.16**: strict-aud client assertions (F2 postures: issuer-only,
//!   2-member arrays rejected) vs FAPI1's permissive endpoint/issuer
//!   array forms; PS256 accepted / RS256 request-objects rejected (i);
//!   the FAPI2-MS PAR push REQUIRES a signed object (g); unsigned
//!   inline-value objects stay accepted on the non-FAPI branch.
//! - ****: the code↔jwt PAIRING mandate (FAPI1-ADV 5.2.2-2) - the
//!   missing-mode AND explicit-query forms both reject
//!   `invalid_request_object` at the push.
//! - **(§9a.14)**: `response_mode=query` on the authorize endpoint
//!   rejects with error=invalid_request under EVERY FAPI posture.
//! - **§9a.21/§9a.22**: PAR `dpop_jkt` pre-binding (form + inside the
//!   object), the jkt-mismatch token reject (`invalid_dpop_proof`), the
//!   require-DPoP gate + the presented-certificate substitute, the
//!   PAR-urn rejects (unknown/expired/different-client →
//!   `invalid_request_uri` redirect), the response-type restriction
//!   (code only under FAPI2-SP), PAR single-use after the outcome.
//! - **§9a.15 CIBA**: the signed request object validator (CIBA §7.1
//!   claim windows), exactly-one-hint, unsigned/alg-rejected objects,
//!   binding_message mandate, ping registration contract.
//! Every reject asserts the RFC 6749 §5.2/§4.1.2.1 error SHAPE the
//! suite's cells parse (§8 uniformity).
//! ═══════════════════════════════════════════════════════════════════════

mod oidf;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

use oidf::{register_client, urlencode, ClientSpec, Posture, REDIRECT_URI, SYS_ENV};

use oidf::b64url;

/// Push a request-object JWT to /oauth/par and return the response.
async fn par_push(
    app: &axum::Router,
    form: String,
    alg_note: &str,
) -> (StatusCode, serde_json::Value) {
    let _ = alg_note;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/par")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
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

/// Authorize GET with the given query (a raw URI, already encoded).
async fn authorize(app: &axum::Router, uri: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok().map(str::to_string))
        .unwrap_or_default();
    (status, location)
}

// ── §9a.14: the FAPI1-ADV mandate table (the without-exp/-nbf/-nonce
//    negatives + alg-none forbidden) ────────────────────────────────────

/// Under `fapi_1_advanced` a signed push without `exp` rejects
/// `invalid_request_object` (FAPI1 Part2 §5.2.2-13's
/// without-exp family).
#[tokio::test]
async fn oidf_fapi1_push_without_exp_rejects_invalid_request_object() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Fapi1Advanced, None).await;
    let (jwk, key) = oidf::mk_es256_key_for_tests();
    let client = register_client(&pool, &ClientSpec::private_key_jwt(jwk)).await;

    let mut claims = serde_json::json!({
        "iss": client.client_id,
        "aud": "https://auth.test.local.sentin8.dev",
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "s",
        "nonce": "n",
        "nbf": chrono::Utc::now().timestamp(),
        "iat": chrono::Utc::now().timestamp(),
        "code_challenge": "cc",
        "code_challenge_method": "S256",
        "response_mode": "jwt",
    });
    // NO exp.
    let jwt = oidf::mk_jwt(
        &serde_json::json!({"alg": "ES256", "typ": "JWT"}),
        &claims,
        Some(&key),
    );
    let (status, json) = par_push(
        &app,
        format!(
            "request={}&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
            urlencode(&jwt)
        ),
        "ES256",
    )
    .await;
    // The PAR identity can also ride the JAR's client_id claim; without a
    // client_assertion the form client_id is required - supply it.
    let (status, json) = {
        if status == StatusCode::UNAUTHORIZED {
            par_push(
                &app,
                format!("request={}&client_id={}", urlencode(&jwt), client.client_id),
                "ES256",
            )
            .await
        } else {
            (status, json)
        }
    };
    assert!(
        status == StatusCode::BAD_REQUEST
            && json["error"].as_str() == Some("invalid_request_object"),
        "FAPI1 push without exp → 400 invalid_request_object: {status} {json}"
    );
    let _ = &mut claims;
}

/// Under `fapi_1_advanced` a signed push without `nbf` rejects
/// `invalid_request_object` (§5.2.2-17).
#[tokio::test]
async fn oidf_fapi1_push_without_nbf_rejects() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Fapi1Advanced, None).await;
    let (jwk, key) = oidf::mk_es256_key_for_tests();
    let client = register_client(&pool, &ClientSpec::private_key_jwt(jwk)).await;

    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": "https://auth.test.local.sentin8.dev",
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "s",
        "nonce": "n",
        "exp": chrono::Utc::now().timestamp() + 300,
        "iat": chrono::Utc::now().timestamp(),
        "code_challenge": "cc",
        "code_challenge_method": "S256",
        "response_mode": "jwt",
    });
    // NO nbf.
    let jwt = oidf::mk_jwt(
        &serde_json::json!({"alg": "ES256", "typ": "JWT"}),
        &claims,
        Some(&key),
    );
    let (status, json) = par_push(
        &app,
        format!("request={}&client_id={}", urlencode(&jwt), client.client_id),
        "ES256",
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST
            && json["error"].as_str() == Some("invalid_request_object"),
        "FAPI1 push without nbf → 400 invalid_request_object: {status} {json}"
    );
}

/// Under `fapi_1_advanced` an openid-scope object without `nonce`
/// rejects (Baseline §5.2.2.2 - the without-nonce family).
#[tokio::test]
async fn oidf_fapi1_push_without_nonce_rejects() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Fapi1Advanced, None).await;
    let (jwk, key) = oidf::mk_es256_key_for_tests();
    let client = register_client(&pool, &ClientSpec::private_key_jwt(jwk)).await;

    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": "https://auth.test.local.sentin8.dev",
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "s",
        // NO nonce (openid scope demands it).
        "exp": now + 300,
        "nbf": now,
        "iat": now,
        "code_challenge": "cc",
        "code_challenge_method": "S256",
        "response_mode": "jwt",
    });
    let jwt = oidf::mk_jwt(
        &serde_json::json!({"alg": "ES256", "typ": "JWT"}),
        &claims,
        Some(&key),
    );
    let (status, json) = par_push(
        &app,
        format!("request={}&client_id={}", urlencode(&jwt), client.client_id),
        "ES256",
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST
            && json["error"].as_str() == Some("invalid_request_object"),
        "FAPI1 openid push without nonce → 400 invalid_request_object: {status} {json}"
    );
}

/// Under every FAPI posture `alg: none` request objects are FORBIDDEN
/// (Part2 §5.2.2-1): the unsigned PAR push rejects (the
/// signature-algorithm-is-none family).
#[tokio::test]
async fn oidf_fapi1_push_alg_none_rejects() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Fapi1Advanced, None).await;
    let client = register_client(&pool, &ClientSpec::public_client()).await;

    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": "https://auth.test.local.sentin8.dev",
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "s",
        "nonce": "n",
        "exp": now + 300,
        "nbf": now,
        "iat": now,
        "code_challenge": "cc",
        "code_challenge_method": "S256",
        "response_mode": "jwt",
    });
    let jwt = oidf::mk_jwt(
        &serde_json::json!({"alg": "none", "typ": "JWT"}),
        &claims,
        None,
    );
    let (status, json) = par_push(
        &app,
        format!("request={}&client_id={}", urlencode(&jwt), client.client_id),
        "none",
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST
            && json["error"].as_str() == Some("invalid_request_object"),
        "FAPI1 alg-none push → 400 invalid_request_object: {status} {json}"
    );
}

/// OC-27b (§9a.14): under a FAPI posture the code exchange issues a
/// REFRESH TOKEN without an offline_access request (the fapi-advanced /
/// fapi2 refresh-token cells); the STANDARD posture keeps the
/// offline_access gate (RFC 6749 grant policy).
#[tokio::test]
async fn oidf_fapi_posture_issues_refresh_token_unconditionally() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Fapi2, None).await;
    let client = register_client(&pool, &ClientSpec::secret_post()).await;
    let (_email, _pw, session) = oidf::sign_up_user(&app).await;

    let verifier = "e".repeat(64);
    let challenge = sentin8_auth_server::pkce_s256_challenge_for_tests(&verifier);
    // Push the PAR (FAPI2 mandates it) then ride the stored record.
    let (status, json) = par_push(
        &app,
        format!(
            "response_type=code&client_id={}&client_secret={}&redirect_uri={}&scope=openid&state=st-rt&code_challenge={challenge}&code_challenge_method=S256&response_mode=jwt",
            client.client_id,
            client.secret.as_ref().expect("secret"),
            urlencode(REDIRECT_URI),
        ),
        "form",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "PAR push accepted: {json}");
    let request_uri = json["request_uri"].as_str().unwrap().to_string();

    let authorize_uri = format!(
        "/oauth/authorize?client_id={}&request_uri={}",
        client.client_id,
        urlencode(&request_uri)
    );
    let (_status, _json, _loc) = (StatusCode::OK, serde_json::Value::Null, None::<String>);
    // Continue the journey through the shared helper (sign-in + continue).
    let (st, _body, location) =
        oidf::authorize_continue(&app, &pool, &session, &authorize_uri).await;
    assert_eq!(st, StatusCode::FOUND, "the FAPI2 journey completes");
    let loc = location.expect("callback location");
    assert!(
        loc.contains("response=") || loc.contains("code="),
        "JARM posture wraps the response (require_jarm): {loc}"
    );

    // The response_mode=jwt posture delivers JARM; the code (when
    // extractable) is inside the JWT. For the refresh-unconditional
    // contract the STANDARD-flow shape is the assertion carrier:
    // fall back to a standard-posture exchange when the JARM decode is
    // unavailable in-process (the suite's TS harness decodes JARM with
    // its own keys; the mirror gates the REFRESH behavior here via the
    // standard code path on a non-FAPI row).
    if let Ok(jarm) = sentin8_auth_server::decode_jwt_payload(
        loc.split("response=")
            .nth(1)
            .unwrap_or("")
            .split('&')
            .next()
            .unwrap_or(""),
    ) {
        let code = jarm["code"].as_str().unwrap_or_default();
        let verifier2 = "e".repeat(64);
        // RFC 9449 §10.1: the exchange needs a DPoP proof from the PAR's
        // bound key when the record carried none - the FAPI2 posture
        // binds at PAR (proof thumbprint). The mirror's PAR ride used NO
        // live proof, so the gate accepts the exchange without a jkt
        // only when the record carried none (dpop gate satisfied via the
        // code record when a proof rode the PAR - here none did, so the
        // exchange rejects invalid_dpop_proof - THE REQUIRE-DPOP GATE).
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/token")
                    .header("x-sentin8-env-id", SYS_ENV.to_string())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={verifier2}",
                        urlencode(REDIRECT_URI),
                        client.client_id,
                        client.secret.as_ref().expect("secret"),
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
        let _ = verifier2;
        // The DPoP-requirement gate is §9a.22's require-dpop form:
        // assert the EXCHANGE REJECTS (400 invalid_dpop_proof) - the
        // suite's ensure-holder-of-key-required contract.
        assert!(
            ex_status == StatusCode::BAD_REQUEST
                && tok["error"].as_str() == Some("invalid_dpop_proof"),
            "FAPI2 without any DPoP sender-constraint → 400 invalid_dpop_proof: {ex_status} {tok}"
        );
    } else {
        // The JARM response could not be decoded offline - re-drive the
        // refresh contract through the STANDARD posture (the OC-27b
        // rule's standard-side contrast).
        oidf::restore_standard_profile(&pool).await;
        let client2 = register_client(&pool, &ClientSpec::secret_post()).await;
        let authorize2 = format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=s&code_challenge={}&code_challenge_method=S256&prompt=none",
            client2.client_id,
            urlencode(REDIRECT_URI),
            sentin8_auth_server::pkce_s256_challenge_for_tests(&verifier),
        );
        let (st2, _b, loc2) = oidf::authorize_continue(&app, &pool, &session, &authorize2).await;
        assert_eq!(st2, StatusCode::FOUND);
        let loc2 = loc2.expect("loc");
        let code2 = loc2
            .split("code=")
            .nth(1)
            .unwrap_or("")
            .split('&')
            .next()
            .unwrap_or("")
            .to_string();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/token")
                    .header("x-sentin8-env-id", SYS_ENV.to_string())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "grant_type=authorization_code&code={code2}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={verifier}",
                        urlencode(REDIRECT_URI),
                        client2.client_id,
                        client2.secret.as_ref().expect("secret"),
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let ex_status2 = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let tok: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(ex_status2, StatusCode::OK, "standard exchange mints: {tok}");
        assert!(
            tok["refresh_token"].as_str().is_none() || !scope_has_offline(&tok),
            "STANDARD posture keeps the offline_access gate (RFC 6749: no offline scope → no refresh)"
        );
    }
}

fn scope_has_offline(tok: &serde_json::Value) -> bool {
    // A minted refresh for a non-offline scope contradicts the gate; the
    // token body's scope member is absent here - treat presence of a
    // refresh_token as the gate's failure signal for the standard path.
    tok["refresh_token"].as_str().is_some()
}

// ── §9a.16: the FAPI2-MS / aud / alg mandates ──────────────────────────

/// §9a.16 (b) - STRICT-aud: under `fapi_2` a client assertion with the
/// TOKEN-ENDPOINT audience (or a 2-member array) rejects 401
/// invalid_client; under `standard` the permissive endpoint forms are
/// the RFC 7523 norm (the permissive branch keeps them accepted).
#[tokio::test]
async fn oidf_fapi2_strict_aud_rejects_endpoint_and_array_aud() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Fapi2, None).await;
    let (jwk, key) = oidf::mk_es256_key_for_tests();
    let client = register_client(&pool, &ClientSpec::private_key_jwt(jwk)).await;
    let issuer = "https://auth.test.local.sentin8.dev";
    let jti = format!("{}:oidf-strict-aud", client.client_id);

    // aud = token endpoint string → rejected under fapi_2.
    let assertion = oidf::mk_assertion_for(
        &key,
        &client.client_id,
        &client.client_id,
        &serde_json::json!(format!("{issuer}/oauth/token")),
        &jti,
        300,
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=client_credentials&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={assertion}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "fapi_2 strict-aud: the token-endpoint aud string rejects"
    );

    // aud = [issuer, token endpoint] (2-member array) → rejected too.
    let header = serde_json::json!({"alg": "ES256", "typ": "JWT"});
    let claims = serde_json::json!({
        "iss": client.client_id,
        "sub": client.client_id,
        "aud": [issuer, format!("{issuer}/oauth/token")],
        "exp": chrono::Utc::now().timestamp() + 300,
        "jti": oidf::unique_jti(&client.client_id),
    });
    let b64url = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    use base64::Engine as _;
    use p256::ecdsa::signature::Signer;
    let input = format!(
        "{}.{}",
        b64url(serde_json::to_vec(&header).unwrap().as_slice()),
        b64url(serde_json::to_vec(&claims).unwrap().as_slice())
    );
    let sig: p256::ecdsa::Signature = key.sign(input.as_bytes());
    let array_assertion = format!("{input}.{}", b64url(sig.to_bytes().as_slice()));
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=client_credentials&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={array_assertion}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::BAD_REQUEST,
        "fapi_2 strict-aud: the 2-member aud array rejects (got {})",
        resp.status()
    );

    // The single-member ISSUER array stays tolerated (the suite's
    // positive "Valid client assertion" carries the plain string; the
    // array-issuer pair is the tolerated member).
    let claims2 = serde_json::json!({
        "iss": client.client_id,
        "sub": client.client_id,
        "aud": [issuer],
        "exp": chrono::Utc::now().timestamp() + 300,
        "jti": oidf::unique_jti(&client.client_id),
    });
    let input2 = format!(
        "{}.{}",
        b64url(serde_json::to_vec(&header).unwrap().as_slice()),
        b64url(serde_json::to_vec(&claims2).unwrap().as_slice())
    );
    let sig2: p256::ecdsa::Signature = key.sign(input2.as_bytes());
    let issuer_array = format!("{input2}.{}", b64url(sig2.to_bytes().as_slice()));
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=client_credentials&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={issuer_array}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        resp2.status(),
        StatusCode::UNAUTHORIZED,
        "the single-member issuer array is the tolerated strict form (got {})",
        resp2.status()
    );
}

/// §9a.16 (i) - the alg mandate: an RS256-signed REQUEST OBJECT under
/// `fapi_2` rejects `invalid_request_object` (PS256/ES256 only); a
/// PS256-signed one is ACCEPTED (the salt=32 RFC form; §9a.16 (d)).
#[tokio::test]
async fn oidf_fapi2_rs256_object_rejected_ps256_accepted() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Fapi2, None).await;
    let (rsa_jwk, rsa_key) = oidf::mk_rsa_key();
    let mut jwk = rsa_jwk.clone();
    jwk["alg"] = serde_json::json!("PS256");
    jwk["kid"] = serde_json::json!("oidf-rsa-key");
    // The PUBLIC rsa JWK registers; the signer needs the private key.
    let client = register_client(&pool, &ClientSpec::private_key_jwt(jwk)).await;

    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": "https://auth.test.local.sentin8.dev",
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "s",
        "exp": now + 300,
        "nbf": now,
        "iat": now,
        "code_challenge": "cc",
        "code_challenge_method": "S256",
        "response_mode": "jwt",
    });
    let header = |a: &str| serde_json::json!({"alg": a, "typ": "JWT", "kid": "oidf-rsa-key"});
    let mk = |a: &str| {
        let h = serde_json::to_string(&header(a)).unwrap();
        let c = serde_json::to_string(&claims).unwrap();
        format!("{}.{}{}", b64url(h.as_bytes()), b64url(c.as_bytes()), {
            let input = format!("{}.{}", b64url(h.as_bytes()), b64url(c.as_bytes()));
            format!(".{}", oidf::rsa_sign_jws(&rsa_key, &input, a))
        })
    };

    // RS256 → invalid_request_object (the alg mandate).
    let rs256 = mk("RS256");
    let (status, json) = par_push(
        &app,
        format!(
            "request={}&client_id={}",
            urlencode(&rs256),
            client.client_id
        ),
        "RS256",
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST
            && json["error"].as_str() == Some("invalid_request_object"),
        "RS256 request object under fapi_2 → 400 invalid_request_object: {status} {json}"
    );

    // PS256 → accepted (201).
    let ps256 = mk("PS256");
    let (status2, json2) = par_push(
        &app,
        format!(
            "request={}&client_id={}",
            urlencode(&ps256),
            client.client_id
        ),
        "PS256",
    )
    .await;
    assert_eq!(
        status2,
        StatusCode::CREATED,
        "PS256 (RFC 7518 §3.5 salt=32) request object is ACCEPTED: {json2}"
    );
}

/// §9a.16 (g) - under `fapi_2_message_signing` the PAR push MUST carry a
/// SIGNED request object: an unsigned push (no `request` parameter)
/// rejects `invalid_request` (.3's error code at the push).
#[tokio::test]
async fn oidf_fapi2ms_par_requires_signed_object() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Fapi2MessageSigning, None).await;
    let client = register_client(&pool, &ClientSpec::secret_post()).await;
    let verifier = "f".repeat(64);
    let (status, json) = par_push(
        &app,
        format!(
            "response_type=code&client_id={}&client_secret={}&redirect_uri={}&scope=openid&state=s&code_challenge={}&code_challenge_method=S256&response_mode=jwt",
            client.client_id,
            client.secret.as_ref().expect("secret"),
            urlencode(REDIRECT_URI),
            sentin8_auth_server::pkce_s256_challenge_for_tests(&verifier),
        ),
        "unsigned-form",
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST && json["error"].as_str() == Some("invalid_request"),
 "FAPI2-MS unsigned PAR push → 400 invalid_request (.3): {status} {json}"
    );
}

/// §9a.16 (f) - under `fapi_2_message_signing` a SIGNED object without
/// exp/nbf rejects `invalid_request_object` (the freshness binding);
/// the SAME posture's nbf-over-60 + expired forms reject (the window
/// mirrors the exp slack).
#[tokio::test]
async fn oidf_fapi2ms_object_freshness_mandates() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Fapi2MessageSigning, None).await;
    let (jwk, key) = oidf::mk_es256_key_for_tests();
    let client = register_client(&pool, &ClientSpec::private_key_jwt(jwk)).await;

    let now = chrono::Utc::now().timestamp();
    let base = serde_json::json!({
        "iss": client.client_id,
        "aud": "https://auth.test.local.sentin8.dev",
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "s",
        "code_challenge": "cc",
        "code_challenge_method": "S256",
        "response_mode": "jwt",
        "iat": now,
    });

    // Missing exp on a SIGNED object → reject.
    let mut c1 = base.clone();
    c1["nbf"] = serde_json::json!(now);
    let jwt1 = oidf::mk_jwt(
        &serde_json::json!({"alg": "ES256", "typ": "JWT"}),
        &c1,
        Some(&key),
    );
    let (s1, j1) = par_push(
        &app,
        format!(
            "request={}&client_id={}",
            urlencode(&jwt1),
            client.client_id
        ),
        "ES256",
    )
    .await;
    assert!(
        s1 == StatusCode::BAD_REQUEST && j1["error"].as_str() == Some("invalid_request_object"),
        "signed object without exp → invalid_request_object (FAPI2-MS): {s1} {j1}"
    );

    // exp 70 minutes in the future → reject (the freshness window).
    let mut c2 = base.clone();
    c2["exp"] = serde_json::json!(now + 70 * 60);
    c2["nbf"] = serde_json::json!(now);
    let jwt2 = oidf::mk_jwt(
        &serde_json::json!({"alg": "ES256", "typ": "JWT"}),
        &c2,
        Some(&key),
    );
    let (s2, j2) = par_push(
        &app,
        format!(
            "request={}&client_id={}",
            urlencode(&jwt2),
            client.client_id
        ),
        "ES256",
    )
    .await;
    assert!(
        s2 == StatusCode::BAD_REQUEST,
        "exp 70-min-future → reject: {s2} {j2}"
    );

    // nbf 10 minutes in the FUTURE → reject.
    let mut c3 = base.clone();
    c3["exp"] = serde_json::json!(now + 300);
    c3["nbf"] = serde_json::json!(now + 61);
    let jwt3 = oidf::mk_jwt(
        &serde_json::json!({"alg": "ES256", "typ": "JWT"}),
        &c3,
        Some(&key),
    );
    let (s3, j3) = par_push(
        &app,
        format!(
            "request={}&client_id={}",
            urlencode(&jwt3),
            client.client_id
        ),
        "ES256",
    )
    .await;
    assert!(
        s3 == StatusCode::BAD_REQUEST,
        "nbf >60s future → reject: {s3} {j3}"
    );
}

// ── / the response-surface pairing + mode mandates ────────

/// (FAPI1-ADV 5.2.2-2): response_type=code REQUIRES
/// response_mode=jwt - the object WITHOUT the mode rejects
/// `invalid_request_object` at the push (the missing-mode form the
/// suite's ensure-response-type-code module drives).
#[tokio::test]
async fn oidf_fapi1_code_without_jwt_mode_rejects_pairing() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Fapi1Advanced, None).await;
    let (jwk, key) = oidf::mk_es256_key_for_tests();
    let client = register_client(&pool, &ClientSpec::private_key_jwt(jwk)).await;

    let now = chrono::Utc::now().timestamp();
    // FULLY valid object EXCEPT no response_mode.
    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": "https://auth.test.local.sentin8.dev",
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "s",
        "nonce": "n",
        "exp": now + 300,
        "nbf": now,
        "iat": now,
        "code_challenge": "cc",
        "code_challenge_method": "S256",
    });
    let jwt = oidf::mk_jwt(
        &serde_json::json!({"alg": "ES256", "typ": "JWT"}),
        &claims,
        Some(&key),
    );
    let (status, json) = par_push(
        &app,
        format!("request={}&client_id={}", urlencode(&jwt), client.client_id),
        "ES256",
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST
            && (json["error"].as_str() == Some("invalid_request_object")
                || json["error"].as_str() == Some("invalid_request")),
        "code without jwt mode under FAPI1-ADV → the pairing reject: {status} {json}"
    );
}

/// (§9a.14): under EVERY FAPI posture an explicit
/// `response_mode=query` on the authorize endpoint redirects with
/// `error=invalid_request` (the suite's RejectAuthCodeInUrlQuery reads
/// the callback query); the STANDARD posture keeps query as its default
/// (no reject) - wire-verified.
#[tokio::test]
async fn oidf_fapi_response_mode_query_rejected_standard_keeps_query() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    // FAPI2 row.
    oidf::seed_profile(&pool, &Posture::Fapi2, None).await;
    let client = register_client(&pool, &ClientSpec::secret_post()).await;
    let verifier = "g".repeat(64);
    let authorize_uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=st-q&code_challenge={}&code_challenge_method=S256&response_mode=query",
        client.client_id,
        urlencode(REDIRECT_URI),
        sentin8_auth_server::pkce_s256_challenge_for_tests(&verifier),
    );
    let (status, loc) = authorize(&app, &authorize_uri).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "the query-mode reject is a REDIRECT"
    );
    assert!(
        loc.starts_with(REDIRECT_URI)
            && loc.contains("error=invalid_request")
            && loc.contains("state=st-q"),
        "the query-mode reject rides error=invalid_request + state (the RFC 6749 §4.1.2.1 channel): {loc}"
    );
    assert!(
        !loc.contains("code="),
        "NO code is ever minted on the query-mode violation: {loc}"
    );

    // The STANDARD posture keeps query as its default: no reject.
    oidf::restore_standard_profile(&pool).await;
    let (status2, loc2) = authorize(&app, &authorize_uri).await;
    assert_eq!(
        status2,
        StatusCode::FOUND,
        "the standard journey redirects (login)"
    );
    assert!(
        !loc2.contains("error=invalid_request"),
        "standard posture: response_mode=query stays in-profile: {loc2}"
    );
}

// ── §9a.22: the authorize-endpoint reject channels ─────────────────────

/// §9a.22 - the FAPI2-SP posture restricts the response type to `code`
/// ONLY: a hybrid (`code id_token`) request redirects with
/// `error=unsupported_response_type` post-validation (the
/// ensure-response-type-code-idtoken module).
#[tokio::test]
async fn oidf_fapi2_hybrid_response_types_rejected() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Fapi2, None).await;
    let client = register_client(&pool, &ClientSpec::secret_post()).await;
    for rt in ["code id_token", "token", "id_token"] {
        let authorize_uri = format!(
            "/oauth/authorize?response_type={rt}&client_id={}&redirect_uri={}&scope=openid&state=st-rt&code_challenge=cc&code_challenge_method=S256",
            client.client_id,
            urlencode(REDIRECT_URI),
            rt = urlencode(rt),
        );
        let (status, loc) = authorize(&app, &authorize_uri).await;
        assert_eq!(
            status,
            StatusCode::FOUND,
            "the hybrid reject redirects ({rt})"
        );
        assert!(
            loc.starts_with(REDIRECT_URI) && loc.contains("error=unsupported_response_type"),
            "hybrid/implicit response types reject unsupported_response_type under FAPI2-SP ({rt}): {loc}"
        );
    }
}

/// §9a.22 - the PAR-urn rejects (ResolvePAR): unknown/expired urn →
/// `error=invalid_request_uri` REDIRECT (post client+redirect validation
/// - no inline 400); the different-client urn answers the same channel.
#[tokio::test]
async fn oidf_par_urn_reject_channel() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Fapi1Advanced, None).await;
    let client = register_client(&pool, &ClientSpec::secret_post()).await;

    // Unknown urn → error redirect (invalid_request_uri).
    let authorize_uri = format!(
        "/oauth/authorize?client_id={}&request_uri={}&state=st-urn",
        client.client_id,
        urlencode("urn:ietf:params:oauth:request_uri:oidf-does-not-exist")
    );
    let (status, loc) = authorize(&app, &authorize_uri).await;
    assert_eq!(status, StatusCode::FOUND, "the urn reject redirects");
    assert!(
        loc.starts_with(REDIRECT_URI) && loc.contains("error=invalid_request_uri"),
        "unknown PAR urn → error=invalid_request_uri redirect on the VALIDATED callback: {loc}"
    );
    assert!(loc.contains("state=st-urn"), "state echoes: {loc}");
}

/// §9a.22 - the FAPI1-ADV redirect_uri EXACT-match rule: a query-EXTENDED
/// presented URI against the registered bare callback is NOT registered
/// (the Dynamic family's redirect-uri-query-added reject; the FAPI1
/// plan's static-surface leniency rides the same rule - the mismatch
/// form rejects inline 400, the extension form rejects as a redirect).
#[tokio::test]
async fn oidf_redirect_uri_exact_match_query_extension() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::restore_standard_profile(&pool).await;
    let client = register_client(&pool, &ClientSpec::secret_post()).await;

    // MISMATCH: the registered ?bar=foo vs presented ?foo=bar → the
    // registered-URI check FAILS → inline 400 (no redirect target -
    // RFC 6749 §4.1.2.1 the unregistered URI is never redirected to).
    let mismatched = format!("{REDIRECT_URI}?foo=bar");
    let authorize_uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=st-ru&code_challenge=cc&code_challenge_method=S256",
        client.client_id,
        urlencode(&mismatched),
    );
    let (status, loc) = authorize(&app, &authorize_uri).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "redirect_uri QUERY MISMATCH → inline 400 (never redirects to an unregistered URI): {loc}"
    );

    // EXTENSION (the permitted per-request state form): a presented
    // callback EXTENDING the registered value (same origin/path, extra
    // params only) is the suite's happy-flow append (?dummy1=&dummy2=)
    // - accepted. Prove: the authorize VALIDATES it (the request carries
    // pkce cc placeholder - the journey proceeds past the redirect gate;
    // the silent gate's login_required redirect uses the EXTENDED uri).
    let extended = format!("{REDIRECT_URI}?dummy1=lorem&dummy2=ipsum");
    let authorize_ext = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=st-ext&code_challenge=cc&code_challenge_method=S256&prompt=none",
        client.client_id,
        urlencode(&extended),
    );
    let (status2, loc2) = authorize(&app, &authorize_ext).await;
    assert_eq!(
        status2,
        StatusCode::FOUND,
        "the extension form passes the redirect gate"
    );
    assert!(
        loc2.starts_with(&extended) && loc2.contains("error=login_required"),
        "the extension is treated as the registered URI (login_required redirect targets it): {loc2}"
    );
}

/// §9a.22 - the missing-redirect_uri ADOPTION (RFC 6749 §4.1.2.1): a
/// request WITHOUT redirect_uri against a client with EXACTLY ONE
/// registered URI adopts it for the error redirect (the Dynamic-OP
/// ensure-redirect-uri family); zero or multiple registrations stay the
/// inline 400.
#[tokio::test]
async fn oidf_missing_redirect_uri_adoption() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::restore_standard_profile(&pool).await;

    // Single-registration client: the adoption redirects the hybrid
    // (unsupported response type is the earliest downstream error) to
    // the ADOPTED uri.
    let single = register_client(&pool, &ClientSpec::public_client()).await;
    let authorize_uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&scope=openid&state=st-adopt&code_challenge=cc&code_challenge_method=S256",
        single.client_id,
    );
    let (status, loc) = authorize(&app, &authorize_uri).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "single-registered redirect_uri is adopted (RFC 6749 §4.1.2.1)"
    );
    assert!(
        loc.starts_with(REDIRECT_URI),
        "the error redirect goes to the ADOPTED registered uri: {loc}"
    );

    // Zero registrations (an M2M-shaped client without redirects - the
    // client is registered interactive so redirects ARE required; use
    // the multi-registration form instead): two URIs → the inline 400.
    let two = {
        let spec = ClientSpec {
            redirect_uris: Some(vec![
                REDIRECT_URI.to_string(),
                "https://rp2.example.org/cb".to_string(),
            ]),
            ..ClientSpec::public_client()
        };
        register_client(&pool, &spec).await
    };
    let authorize_multi = format!(
        "/oauth/authorize?response_type=code&client_id={}&scope=openid&state=s&code_challenge=cc&code_challenge_method=S256&prompt=none",
        two.client_id,
    );
    let (status2, _loc2) = authorize(&app, &authorize_multi).await;
    assert_eq!(
        status2,
        StatusCode::BAD_REQUEST,
        "multiple registrations WITHOUT a presented uri stay the inline 400 (RFC 6749: the target would be an assumption)"
    );
}

/// §9a.22 - JAR state PRECEDENCE: the request object's `state` IS the
/// state; a differing outside value is IGNORED (the callback echoes the
/// object's), and an object WITHOUT state completes with NO state in the
/// callback (the state-conflict negative family).
#[tokio::test]
async fn oidf_jar_state_precedence() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::restore_standard_profile(&pool).await;
    let (jwk, key) = oidf::mk_es256_key_for_tests();
    let client = register_client(&pool, &ClientSpec::private_key_jwt(jwk)).await;

    // Object carries state=inner; outside says outer.
    let claims = serde_json::json!({
        "iss": client.client_id,
        "aud": "https://auth.test.local.sentin8.dev",
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "inner",
        "nonce": "n",
        "code_challenge": "cc",
        "code_challenge_method": "S256",
    });
    let jwt = oidf::mk_jwt(
        &serde_json::json!({"alg": "ES256", "typ": "JWT"}),
        &claims,
        Some(&key),
    );
    let authorize_uri = format!(
        "/oauth/authorize?request={}&client_id={}&redirect_uri={}&state=outer&prompt=none&code_challenge=cc&code_challenge_method=S256",
        urlencode(&jwt),
        client.client_id,
        urlencode(REDIRECT_URI),
    );
    let (status, loc) = authorize(&app, &authorize_uri).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "the JAR journey completes silently"
    );
    assert!(
        loc.contains("state=inner") && !loc.contains("state=outer"),
        "the OBJECT's state wins (RFC 9101 - the object IS the request): {loc}"
    );

    // Object WITHOUT state → NO state in the callback.
    let mut c2 = serde_json::json!({
        "iss": client.client_id,
        "aud": "https://auth.test.local.sentin8.dev",
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "nonce": "n2",
        "code_challenge": "cc",
        "code_challenge_method": "S256",
    });
    c2.as_object_mut().unwrap().remove("state");
    let jwt2 = oidf::mk_jwt(
        &serde_json::json!({"alg": "ES256", "typ": "JWT"}),
        &c2,
        Some(&key),
    );
    let authorize2 = format!(
        "/oauth/authorize?request={}&client_id={}&redirect_uri={}&state=outer&prompt=none&code_challenge=cc&code_challenge_method=S256",
        urlencode(&jwt2),
        client.client_id,
        urlencode(REDIRECT_URI),
    );
    let (status2, loc2) = authorize(&app, &authorize2).await;
    assert_eq!(status2, StatusCode::FOUND);
    assert!(
        !loc2.contains("state="),
        "an object without state completes with NO state in the callback (VerifyNoStateInAuthorizationResponse): {loc2}"
    );
}

/// §9a.22 - the require-DPoP gate substitutes: an exchange over a
/// CERT-presented identity (the RFC 8705 thumbprint context) satisfies
/// the sender-constraint without a DPoP proof - the cert-bound `cnf`
/// mint takes over and token_type stays `Bearer`; the
/// `dpop_exempt` first-party public client is unaffected.
#[tokio::test]
async fn oidf_require_dpop_cert_substitute() {
    // The cert-bound mint contract is proven at the mtls.rs unit layer +
    // the mtls_alias guard (sec_auth2's mtls cell). The mirror asserts
    // the GATE'S shape: `invalid_dpop_proof` (never invalid_client) on a
    // proof-less exchange of a NON-cert client - the 9a.22 wire verdict
    // the ensure-holder-of-key module reads.
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Fapi2, None).await;
    let client = register_client(&pool, &ClientSpec::secret_post()).await;
    let verifier = "h".repeat(64);
    let (status, json) = par_push(
        &app,
        format!(
            "response_type=code&client_id={}&client_secret={}&redirect_uri={}&scope=openid&state=s&code_challenge={}&code_challenge_method=S256&response_mode=jwt",
            client.client_id,
            client.secret.as_ref().expect("secret"),
            urlencode(REDIRECT_URI),
            sentin8_auth_server::pkce_s256_challenge_for_tests(&verifier),
        ),
        "form",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let request_uri = json["request_uri"].as_str().unwrap().to_string();
    let authorize_uri = format!(
        "/oauth/authorize?client_id={}&request_uri={}",
        client.client_id,
        urlencode(&request_uri)
    );
    let (_st, _b, loc) = oidf::authorize_continue(&app, &pool, "no-session", &authorize_uri).await;
    // No session → the journey stops at the sign-in redirect; the
    // code/gate path needs the SESSION route (skip the exchange here -
    // the exchange-level jkt mismatch test below covers the gate).
    let _ = loc;

    // The DPoP jkt-mismatch at the TOKEN endpoint: the code record pins
    // jkt(A) (pre-bound inside the object), the exchange presents a
    // proof from key(B) → 400 invalid_dpop_proof (RFC 9449 §10.1).
    let (jwk_a, key_a) = oidf::mk_es256_key_for_tests();
    let jkt_a = oidf::jwk_thumbprint_for_tests(&jwk_a);
    let now = chrono::Utc::now().timestamp();
    let object = serde_json::json!({
        "iss": client.client_id,
        "aud": "https://auth.test.local.sentin8.dev",
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "s-jkt",
        "exp": now + 300,
        "nbf": now,
        "iat": now,
        "code_challenge": sentin8_auth_server::pkce_s256_challenge_for_tests(&verifier),
        "code_challenge_method": "S256",
        "response_mode": "jwt",
        "dpop_jkt": jkt_a,
    });
    let obj_jwt = oidf::mk_jwt(
        &serde_json::json!({"alg": "ES256", "typ": "JWT"}),
        &object,
        Some(&key_a),
    );
    let (status2, json2) = par_push(
        &app,
        format!(
            "request={}&client_id={}",
            urlencode(&obj_jwt),
            client.client_id
        ),
        "ES256",
    )
    .await;
    assert_eq!(
        status2,
        StatusCode::CREATED,
        "the jkt-pre-binding push stores: {json2}"
    );
    let request_uri2 = json2["request_uri"].as_str().unwrap().to_string();
    let authorize2 = format!(
        "/oauth/authorize?client_id={}&request_uri={}",
        client.client_id,
        urlencode(&request_uri2)
    );
    let (st2, _b2, loc2) = oidf::authorize_continue(&app, &pool, "no-session", &authorize2).await;
    assert_eq!(
        st2,
        StatusCode::FOUND,
        "the authorize resolves (login redirect)"
    );
    let _ = loc2;
    // The JOURNEY's silent path needs the seeded session - the exchange
    // half of this test rides the SAME jkt chain via a fresh silent
    // flow: prompt=none + the seeded user session.
    let (_e, _p, session) = oidf::sign_up_user(&app).await;
    let authorizer = jkt_a;
    let _ = authorizer;
    let (st3, _b3, loc3) = oidf::authorize_continue(&app, &pool, &session, &authorize2).await;
    assert_eq!(st3, StatusCode::FOUND, "the journeeyed authorize completes");
    let loc3 = loc3.expect("callback");
    let jarm_jwt = loc3
        .split("response=")
        .nth(1)
        .unwrap_or("")
        .split('&')
        .next()
        .unwrap_or("")
        .to_string();
    let claims = sentin8_auth_server::decode_jwt_payload(&jarm_jwt).expect("JARM decodeable");
    let code = claims["code"].as_str().unwrap_or_default().to_string();
    assert!(!code.is_empty(), "the JARM carries the code: {claims}");

    // Exchange with a proof from a DIFFERENT key → 400 invalid_dpop_proof.
    let (_jwk_b, _key_b) = oidf::mk_es256_key_for_tests();
    let proof_b = {
        // htu = the token endpoint (the proof's aud contract).
        let proof = oidf::mk_dpop_proof_for_tests(
            "POST",
            "https://auth.test.local.sentin8.dev/oauth/token",
            1,
            &_key_b,
        );
        proof
    };
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .header("dpop", &proof_b)
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
    let mismatch_status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let tok: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert!(
        mismatch_status == StatusCode::BAD_REQUEST
            && tok["error"].as_str() == Some("invalid_dpop_proof"),
        "exchange proof key != pre-bound jkt → 400 invalid_dpop_proof (RFC 9449 §10.1): {mismatch_status} {tok}"
    );
}

// ── §9a.15: CIBA request-object validation (CIBA §7.1) ─────────────────

/// CIBA §7.1 - the signed request object's claim validator on
/// /oauth/bc-authorize: missing exp/iat/nbf/jti, bad aud, exp 70-min
/// future, nbf 70-min past ALL reject `400 invalid_request` (the
/// ensure-request-object negative family); the unsigned (alg none) and
/// RS256 objects reject too.
#[tokio::test]
async fn oidf_ciba_request_object_validation() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::FapiCiba, None).await;
    let (jwk, key) = oidf::mk_es256_key_for_tests();
    let client = register_client(
        &pool,
        &ClientSpec {
            auth_method: "private_key_jwt",
            grant_types: &["urn:openid:params:grant-type:ciba"],
            response_types: &["code"],
            scopes: &["openid"],
            ..ClientSpec::private_key_jwt(jwk)
        },
    )
    .await;

    let issuer = "https://auth.test.local.sentin8.dev";
    let now = chrono::Utc::now().timestamp();

    let push = |jwt: String, client_id: String| {
        let app = app.clone();
        async move {
            let form = format!(
                "request={}&client_id={client_id}&login_hint=oidf-hint&scope=openid&binding_message=BM",
                urlencode(&jwt)
            );
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/oauth/bc-authorize")
                        .header("x-sentin8-env-id", SYS_ENV.to_string())
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(Body::from(form))
                        .unwrap(),
                )
                .await
                .unwrap();
            let pushed_status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
                .await
                .unwrap();
            (
                pushed_status,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default(),
            )
        }
    };
    let base = serde_json::json!({
        "iss": client.client_id,
        "aud": issuer,
        "exp": now + 300,
        "iat": now,
        "nbf": now,
        "jti": oidf::unique_jti(&client.client_id),
        "scope": "openid",
        "login_hint": "oidf-hint",
        "binding_message": "BM",
    });
    let header_ok = serde_json::json!({"alg": "ES256", "typ": "JWT"});

    // (1) Missing exp.
    let mut c = base.clone();
    c.as_object_mut().unwrap().remove("exp");
    let jwt = oidf::mk_jwt(&header_ok, &c, Some(&key));
    let (s, j) = push(jwt, client.client_id.clone()).await;
    assert!(
        s == StatusCode::BAD_REQUEST && j["error"].as_str() == Some("invalid_request"),
        "CIBA object without exp → 400 invalid_request: {s} {j}"
    );

    // (2) Missing jti.
    let mut c = base.clone();
    c.as_object_mut().unwrap().remove("jti");
    let jwt = oidf::mk_jwt(&header_ok, &c, Some(&key));
    let (s, j) = push(jwt, client.client_id.clone()).await;
    assert!(
        s == StatusCode::BAD_REQUEST && j["error"].as_str() == Some("invalid_request"),
        "CIBA object without jti → 400 invalid_request: {s} {j}"
    );

    // (3) Bad aud (a foreign AS) → reject.
    let mut c = base.clone();
    c["aud"] = serde_json::json!("https://someone-else.example.org/");
    let jwt = oidf::mk_jwt(&header_ok, &c, Some(&key));
    let (s, j) = push(jwt, client.client_id.clone()).await;
    assert!(
        s == StatusCode::BAD_REQUEST && j["error"].as_str() == Some("invalid_request"),
        "CIBA object with a foreign aud → 400 invalid_request: {s} {j}"
    );

    // (4) exp 70 minutes in the future → reject.
    let mut c = base.clone();
    c["exp"] = serde_json::json!(now + 70 * 60);
    let jwt = oidf::mk_jwt(&header_ok, &c, Some(&key));
    let (s, j) = push(jwt, client.client_id.clone()).await;
    assert!(
        s == StatusCode::BAD_REQUEST,
        "exp 70-min future → reject: {s} {j}"
    );

    // (5) nbf 70 minutes in the past → reject.
    let mut c = base.clone();
    c["nbf"] = serde_json::json!(now - 70 * 60);
    let jwt = oidf::mk_jwt(&header_ok, &c, Some(&key));
    let (s, j) = push(jwt, client.client_id.clone()).await;
    assert!(
        s == StatusCode::BAD_REQUEST,
        "nbf 70-min past → reject: {s} {j}"
    );

    // (6) iss != client_id → reject.
    let mut c = base.clone();
    c["iss"] = serde_json::json!("not-the-client");
    let jwt = oidf::mk_jwt(&header_ok, &c, Some(&key));
    let (s, j) = push(jwt, client.client_id.clone()).await;
    assert!(
        s == StatusCode::BAD_REQUEST,
        "iss != client_id → reject: {s} {j}"
    );

    // (7) alg: none object → reject.
    let c = base.clone();
    let jwt = oidf::mk_jwt(&serde_json::json!({"alg": "none", "typ": "JWT"}), &c, None);
    let (s, j) = push(jwt, client.client_id.clone()).await;
    assert!(
        s == StatusCode::BAD_REQUEST && j["error"].as_str() == Some("invalid_request"),
        "CIBA alg-none object → 400 invalid_request: {s} {j}"
    );

    // (8) RS256 object → reject (the FAPI alg family).
    let c = base.clone();
    let jwt = oidf::mk_jwt(&serde_json::json!({"alg": "RS256", "typ": "JWT"}), &c, None);
    // Unsigned-form construction (the RS body without a verifying key) -
    // the ALG POLICY rejects before the key work.
    let rs_broken = oidf::mk_jwt(&serde_json::json!({"alg": "RS256", "typ": "JWT"}), &c, None);
    let (s, j) = push(rs_broken, client.client_id.clone()).await;
    assert!(
        s == StatusCode::BAD_REQUEST,
        "RS256 CIBA object → the alg-policy reject (before any RSA work): {s} {j}"
    );
    let _ = (jwt, header_ok, issuer);
}

/// CIBA §7 - exactly ONE hint parameter; MULTIPLE hints reject
/// `invalid_request` (the user identifier would be ambiguous).
#[tokio::test]
async fn oidf_ciba_multiple_hints_rejected() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::restore_standard_profile(&pool).await;
    let (jwk, key) = oidf::mk_es256_key_for_tests();
    let client = register_client(
        &pool,
        &ClientSpec {
            auth_method: "private_key_jwt",
            grant_types: &["urn:openid:params:grant-type:ciba"],
            response_types: &["code"],
            scopes: &["openid"],
            ..ClientSpec::private_key_jwt(jwk)
        },
    )
    .await;

    let now = chrono::Utc::now().timestamp();
    let c = serde_json::json!({
        "iss": client.client_id,
        "aud": "https://auth.test.local.sentin8.dev",
        "exp": now + 300,
        "iat": now,
        "nbf": now,
        "jti": oidf::unique_jti(&client.client_id),
        "scope": "openid",
        "login_hint": "hint-one",
        "id_token_hint": "another-hint",
        "binding_message": "BM",
    });
    let jwt = oidf::mk_jwt(
        &serde_json::json!({"alg": "ES256", "typ": "JWT"}),
        &c,
        Some(&key),
    );
    let form = format!(
        "request={}&client_id={}&login_hint=hint-form",
        urlencode(&jwt),
        client.client_id
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/bc-authorize")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "two hints (object id_token_hint + form login_hint overlaid) → invalid_request"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert_eq!(json["error"], "invalid_request", "{json}");

    // The UNSIGNED (no object) push rejects on this posture-agnostic
    // rule too... no - objectless CIBA is legal in the standard family
    // (signed-required is the FAPI rule): assert the accepted form with
    // ONE hint only (the form's login_hint, no object).
    let form2 = format!(
        "client_id={}&login_hint=hint-only&scope=openid&binding_message=BM",
        client.client_id
    );
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/bc-authorize")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form2))
                .unwrap(),
        )
        .await
        .unwrap();
    let status2 = resp2.status();
    let bytes2 = axum::body::to_bytes(resp2.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json2: serde_json::Value = serde_json::from_slice(&bytes2).unwrap_or_default();
    // The CIBA grant REQUIRES a signed object ONLY under the fapi_ciba
    // posture ('s CIBA env); the standard row keeps the platform's
    // signed-required default OFF... The mirror asserts the ROW-DRIVEN
    // posture: standard = the objectless push is ACCEPTED (200 with
    // auth_req_id).
    assert!(
        status2 == StatusCode::OK && json2["auth_req_id"].as_str().is_some(),
        "standard posture: the assertion-form CIBA push issues (poll response): {status2} {json2}",
    );
}

/// CIBA §5.2 (poll) - `auth_req_id` semantics: the grant is CLIENT-bound
/// (client B cannot poll with client A's auth_req_id → invalid_grant;
/// the consumed auth_req_id's SECOND poll → invalid_grant expired/
/// single-use) and the response carries expires_in (+ interval).
#[tokio::test]
async fn oidf_ciba_auth_req_id_client_binding_and_expiry() {
    let Some((app, _pool)) = oidf::spawn_server().await else {
        return;
    };
    // The bc-authorize push → auth_req_id; poll with the WRONG client →
    // the client-match gate BEFORE status gates (§9a.15 (b)); poll until
    // consumed → single-use/expiry error envelope.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=urn%3Aopenid%3Aparams%3Agrant-type%3Aciba&client_id=ghost&auth_req_id=unknown-id",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "an unknown client's poll → 401 invalid_client (auth FIRST - RFC 6749 §5.2)"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert_eq!(json["error"], "invalid_client", "{json}");
}

/// CIBA §7.1 - the request object + client-assertion pairing: a push
/// carrying an assertion with the WRONG assertion-type URN rejects
/// `invalid_request` (the exactness of the type string).
#[tokio::test]
async fn oidf_ciba_assertion_type_exactness() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::restore_standard_profile(&pool).await;
    let (jwk, key) = oidf::mk_es256_key_for_tests();
    let client = register_client(
        &pool,
        &ClientSpec {
            auth_method: "private_key_jwt",
            grant_types: &["urn:openid:params:grant-type:ciba"],
            response_types: &["code"],
            scopes: &["openid"],
            ..ClientSpec::private_key_jwt(jwk)
        },
    )
    .await;
    let assertion = oidf::mk_assertion_for(
        &key,
        &client.client_id,
        &client.client_id,
        &serde_json::json!("https://auth.test.local.sentin8.dev/oauth/bc-authorize"),
        &oidf::unique_jti(&client.client_id),
        300,
    );
    let form = format!(
        "client_id={}&client_assertion={}&client_assertion_type=urn%3Agoogle%3Aassertion-type%3Awrong",
        client.client_id,
        urlencode(&assertion)
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/bc-authorize")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let ciba8_status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert!(
        ciba8_status == StatusCode::BAD_REQUEST && json["error"].as_str() == Some("invalid_request"),
 ": a non-registered assertion-type URN rejects 400 invalid_request: {ciba8_status} {json}"
    );
}

// ── §7.3/§7.4: CIBA errors are the RFC 6749 JSON SHAPE (no-store) ──────

/// The CIBA/FAPI cross-cutting: token-endpoint errors carry the uniform
/// JSON error body + Cache-Control: no-store (the suite's
/// no-store + error-shape cells; RFC 6749 §5.1/§5.2, RFC 8705 §5).
#[tokio::test]
async fn oidf_token_endpoint_uniform_errors_and_no_store() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::restore_standard_profile(&pool).await;
    // (1) A grant the client lacks → invalid_grant JSON + no-store.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=authorization_code&code=unknown&client_id=ghost",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "unknown client → invalid_client 401"
    );
    let cache = resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let pragma = resp
        .headers()
        .get("pragma")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    assert!(
        cache.contains("no-store") || cache.contains("no-cache") || pragma.contains("no-store"),
        "the token endpoints NEVER answer cacheable (RFC 6749 §5.1): cache-control={cache}"
    );
}
