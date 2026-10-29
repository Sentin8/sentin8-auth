// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-License-Identifier: Apache-2.0

//! ═══════════════════════════════════════════════════════════════════════
//! In-process OIDF rig mirror (auth DESIGN §9b) - the HAIP family
//! (oid4vci-1_0-issuer-haip): ATTESTATION-based client authentication
//! (draft-ietf-oauth-attestation-based-client-auth, the suite's
//! OAuth2-ATCA07 requirements).
//!
//! `sentin8-auth-oidf/tests/oid4vci-haip.spec.ts` is the source of truth;
//! the tests here assert the SAME wire behaviors the plan's
//! client-attestation cells observe (auth DESIGN §9a.19):
//!
//! - the AUTH WIRE: `OAuth-Client-Attestation` (typ
//!   oauth-client-attestation+jwt, x5c chain) + `...-PoP` (typ
//!   oauth-client-attestation-pop+jwt) authenticate the token endpoint;
//! - the TRUST model: the attestation's x5c chain must pin the profile's
//!   trust anchor; the PoP verifies against the ATTESTED key (the
//!   signature's key binding - a mismatched PoP key rejects);
//! - the CLAIM gates: attestation iss = the profile's expected issuer +
//!   sub = client_id + exp future; PoP aud = the issuer; a PRESENTED
//!   attestation with exp IN THE PAST rejects (the suite's
//!   FailOnClientAttestationExpInPast);
//! - REPLAY: the PoP's jti is single-use (the draft's §6.2 rule; the
//!   auth:capop replay cache);
//! - negative verdicts are ALWAYS `401 invalid_client` (§8 uniformity -
//!   the suite reads the OAuth error shape, never a 500);
//! - DISCOVERY honesty: with the profile enabling attestation the
//!   discovery document advertises `attest_jwt_client_auth` +
//!   the two ES256 signing-alg lists; WITHOUT it the methods drop (the
//!   draft's required-when-supported rule; the profile-honesty plane).
//! ═══════════════════════════════════════════════════════════════════════

mod oidf;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::Engine as _;
use p256::ecdsa::signature::Signer as _;
use tower::ServiceExt;

use oidf::{b64url, register_client, ClientSpec, Posture, SYS_ENV};

/// The attester identity the haip profile seeds (the seed's
/// `client_attestation_issuer`; the per-env form).
const ATTESTATION_ISSUER: &str = "https://vci-attester.oidf-mirror.test";

/// The client_attestation header JWT + verifier material.
struct Attester {
    /// The attester leaf's PKCS#8-derived signing key.
    pub leaf_key: p256::ecdsa::SigningKey,
    /// The leaf certificate DER (the x5c[0]).
    pub leaf_der: Vec<u8>,
    /// The leaf PEM (the profile's trust anchor seed value).
    pub leaf_pem: String,
}

/// Self-issue an attester leaf whose signing key IS the given ES256 key
/// (the draft's self-contained verify path: the x5c leaf's SPKI = the
/// JWS signing key).
fn attester_from_key(key: &p256::ecdsa::SigningKey) -> Attester {
    use p256::elliptic_curve::pkcs8::EncodePrivateKey as _;
    let secret = p256::SecretKey::from_bytes(&key.to_bytes()).expect("secret");
    let pkcs8 = secret
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("pkcs8 pem");
    let kp = rcgen::KeyPair::from_pem(pkcs8.as_str()).expect("keypair");
    let mut params = rcgen::CertificateParams::new(vec![]).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "oidf-attester.test");
    let cert = params.self_signed(&kp).expect("self-signed leaf");
    let der = cert.der().to_vec();
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(&der)
    );
    Attester {
        leaf_key: key.clone(),
        leaf_der: der,
        leaf_pem: pem,
    }
}

/// The wrapped-64 standard-base64 PEM body (the header/PEM shapes).
fn wrap64(s: &str) -> String {
    s.as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap().to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The OAuth-Client-Attestation JWT (typ oauth-client-attestation+jwt):
/// claims iss = the attester's trust-domain identifier, sub = client_id,
/// exp/iat, cnf.jwk = the PROOF key. Signed by the attester leaf key;
/// the x5c chain rides the header.
fn mk_attestation(
    attester: &Attester,
    client_id: &str,
    proof_jwk: &serde_json::Value,
    exp_delta: i64,
    expected_iss: Option<&str>,
) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut claims = serde_json::json!({
        "iss": expected_iss.unwrap_or(ATTESTATION_ISSUER),
        "sub": client_id,
        "iat": now,
        "exp": now + exp_delta,
        "cnf": { "jwk": proof_jwk },
    });
    if exp_delta <= 0 {
        claims["exp"] = serde_json::json!(now + exp_delta);
    }
    let header = serde_json::json!({
        "typ": "oauth-client-attestation+jwt",
        "alg": "ES256",
        "x5c": [base64::engine::general_purpose::STANDARD.encode(&attester.leaf_der)],
    });
    let signing_input = format!(
        "{}.{}",
        b64url(serde_json::to_vec(&header).unwrap().as_slice()),
        b64url(serde_json::to_vec(&claims).unwrap().as_slice())
    );
    let sig: p256::ecdsa::Signature = attester.leaf_key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64url(sig.to_bytes().as_slice()))
}

/// The OAuth-Client-Attestation-PoP JWT: iss = the client instance key
/// identifier, aud = the issuer, jti single-use, iat fresh. Signed by
/// the ATTESTED (proof) key.
fn mk_pop(proof_key: &p256::ecdsa::SigningKey, aud: &str, jti: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": "oidf-instance-key",
        "aud": aud,
        "iat": now,
        "exp": now + 120,
        "jti": jti,
    });
    let header = serde_json::json!({
        "typ": "oauth-client-attestation-pop+jwt",
        "alg": "ES256",
    });
    let signing_input = format!(
        "{}.{}",
        b64url(serde_json::to_vec(&header).unwrap().as_slice()),
        b64url(serde_json::to_vec(&claims).unwrap().as_slice())
    );
    let sig: p256::ecdsa::Signature = proof_key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64url(sig.to_bytes().as_slice()))
}

/// The grant form the attestation-armed cell pushes (the haip posture
/// accepts the attestation pair on the FULL authenticator: token
/// + introspect + revoke).
fn attested_token_form(client_id: &str, grant: &str) -> String {
    match grant == "cc" {
        true => format!("grant_type=client_credentials&client_id={client_id}&scope=openid"),
        false => format!("grant_type={grant}&client_id={client_id}"),
    }
}

/// POST /oauth/token with the header pair; returns (status, body).
async fn token_request(
    app: &axum::Router,
    attestation: &str,
    pop: &str,
    form: &str,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("content-type", "application/x-www-form-urlencoded")
                .header("OAuth-Client-Attestation", attestation)
                .header("OAuth-Client-Attestation-PoP", pop)
                .body(Body::from(form.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

/// The full happy path + every negative the suite's ATCA cells drive:
/// valid pair authenticates (non-401); bad signature / foreign anchor /
/// iss mismatch / no sub / exp-in-past / PoP key mismatch / PoP jti
/// replay ALL answer 401 invalid_client (§8 uniformity).
#[tokio::test]
async fn oidf_haip_attestation_auth_wire_contract() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    // Seed the haip posture with the attester's trust anchor + issuer.
    let anchor_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let anchor = attester_from_key(&anchor_key);
    oidf::seed_profile(
        &pool,
        &Posture::VciHaip,
        Some((&anchor.leaf_pem, ATTESTATION_ISSUER)),
    )
    .await;
    // Clients register with the method string (the suite's registration
    // checks carry attest_jwt_client_auth).
    let (proof_jwk, proof_key) = oidf::mk_es256_key_for_tests();
    let client = register_client(
        &pool,
        &ClientSpec {
            name: "Oidf Haip Client",
            auth_method: "attest_jwt_client_auth",
            grant_types: &[
                "urn:openid:params:grant-type:ciba",
                "authorization_code",
                "client_credentials",
            ],
            response_types: &["code"],
            scopes: &["openid", "credential:VerifiedPersonCredential"],
            ..ClientSpec::private_key_jwt(proof_jwk.clone())
        },
    )
    .await;

    // (1) The HAPPY path: valid attestation + pop → the authentication
    //     proceeds (any non-401 result; the grant's scope/policy gates
    //     may still answer, but NOT 401-invalid-client on the
    //     attestation).
    let audience = "https://auth.test.local.sentin8.dev";
    let att = mk_attestation(&anchor, &client.client_id, &proof_jwk, 3600, None);
    let pop = mk_pop(&proof_key, audience, &oidf::unique_jti("oidf-pop"));
    let (status, body) = token_request(
        &app,
        &att,
        &pop,
        &attested_token_form(&client.client_id, "cc"),
    )
    .await;
    assert!(
        status != StatusCode::UNAUTHORIZED || body["error"] != "invalid_client",
        "the VALID pair authenticates (status {status}, body {body})"
    );

    // (2) FailOnInvalidClientAttestationSignature: an attestation signed
    //     by a FOREIGN key (not the anchored leaf) → 401.
    let (jwk_stranger, key_stranger) = oidf::mk_es256_key_for_tests();
    let _ = &jwk_stranger;
    let stranger = attester_from_key(&key_stranger);
    let att_stranger = mk_attestation(&stranger, &client.client_id, &proof_jwk, 3600, None);
    let pop2 = mk_pop(&proof_key, audience, &oidf::unique_jti("oidf-pop"));
    let (s2, b2) = token_request(
        &app,
        &att_stranger,
        &pop2,
        &attested_token_form(&client.client_id, "cc"),
    )
    .await;
    assert!(
        s2 == StatusCode::UNAUTHORIZED && b2["error"].as_str() == Some("invalid_client"),
        "an unanchored attestation signature → 401 invalid_client: {s2} {b2}"
    );

    // (3) FailOnClientAttestationNoSub: sub != client_id → 401.
    let att_nosub = {
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": ATTESTATION_ISSUER,
            // sub ABSENT.
            "iat": now,
            "exp": now + 3600,
            "cnf": { "jwk": proof_jwk },
        });
        let header = serde_json::json!({
            "typ": "oauth-client-attestation+jwt",
            "alg": "ES256",
            "x5c": [base64::engine::general_purpose::STANDARD.encode(&anchor.leaf_der)],
        });
        let signing_input = format!(
            "{}.{}",
            b64url(serde_json::to_vec(&header).unwrap().as_slice()),
            b64url(serde_json::to_vec(&claims).unwrap().as_slice())
        );
        let sig: p256::ecdsa::Signature = anchor.leaf_key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64url(sig.to_bytes().as_slice()))
    };
    let (s3, b3) = token_request(
        &app,
        &att_nosub,
        &pop2,
        &attested_token_form(&client.client_id, "cc"),
    )
    .await;
    assert!(
        s3 == StatusCode::UNAUTHORIZED && b3["error"].as_str() == Some("invalid_client"),
        "an attestation WITHOUT sub → 401 invalid_client (FailOnClientAttestationNoSub): {s3} {b3}"
    );

    // (4) FailOnClientAttestationExpInPast: exp in the past → 401.
    let att_expired = mk_attestation(&anchor, &client.client_id, &proof_jwk, -600, None);
    let pop4 = mk_pop(&proof_key, audience, &oidf::unique_jti("oidf-pop"));
    let (s4, b4) = token_request(
        &app,
        &att_expired,
        &pop4,
        &attested_token_form(&client.client_id, "cc"),
    )
    .await;
    assert!(
        s4 == StatusCode::UNAUTHORIZED && b4["error"].as_str() == Some("invalid_client"),
        "an expired attestation → 401 invalid_client (FailOnClientAttestationExpInPast): {s4} {b4}"
    );

    // (5) FailOnClientAttestationPopSignature: a PoP signed by a key
    //     DIFFERENT from the attested one → 401 (the draft's binding
    //     rule - the PoP proves possession of the ATTESTED key).
    let (_jwk_other, key_other) = oidf::mk_es256_key_for_tests();
    let pop_foreign = mk_pop(&key_other, audience, &oidf::unique_jti("oidf-pop"));
    let (s5, b5) = token_request(
        &app,
        &att,
        &pop_foreign,
        &attested_token_form(&client.client_id, "cc"),
    )
    .await;
    assert!(
        s5 == StatusCode::UNAUTHORIZED && b5["error"].as_str() == Some("invalid_client"),
        "a PoP from a foreign key → 401 invalid_client (FailOnMismatchedClientAttestationPopKey): {s5} {b5}"
    );

    // (6) FailOnInvalidClientAttestationPopSignature: a pop with a BAD
    //     AUD → 401 (PopAudMismatch).
    let pop_badaud = mk_pop(
        &proof_key,
        "https://a-different-issuer.example.org",
        &oidf::unique_jti("oidf-pop"),
    );
    let (s6, b6) = token_request(
        &app,
        &att,
        &pop_badaud,
        &attested_token_form(&client.client_id, "cc"),
    )
    .await;
    assert!(
        s6 == StatusCode::UNAUTHORIZED && b6["error"].as_str() == Some("invalid_client"),
        "a PoP with a foreign aud → 401 invalid_client: {s6} {b6}"
    );

    // (7) The REPLAY rule (draft §6.2): the SAME PoP (same jti)
    //     presented twice → the SECOND is 401 (the auth:capop SETNX).
    let pop_replay = mk_pop(&proof_key, audience, &oidf::unique_jti("oidf-replay"));
    let fresh_att = mk_attestation(&anchor, &client.client_id, &proof_jwk, 3600, None);
    let (s7a, _b7a) = token_request(
        &app,
        &fresh_att,
        &pop_replay,
        &attested_token_form(&client.client_id, "cc"),
    )
    .await;
    let (s7b, b7b) = token_request(
        &app,
        &fresh_att,
        &pop_replay,
        &attested_token_form(&client.client_id, "cc"),
    )
    .await;
    assert!(
        s7b == StatusCode::UNAUTHORIZED && b7b["error"].as_str() == Some("invalid_client"),
        "the PoP jti is SINGLE-USE (first {s7a}, replay {s7b} {b7b})"
    );
}

/// §9a.19 discovery honesty: with the haip profile ENABLED (anchor +
/// issuer seeded) discovery advertises `attest_jwt_client_auth` in the
/// token/revocation/introspection method lists + the two ES256 alg
/// lists; with the feature DISABLED the members stay ABSENT
/// (required-when-supported - advertising without an anchor is a lie).
#[tokio::test]
async fn oidf_haip_discovery_attestation_advertisement() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;

    // (1) DISABLED (the standard row): no attestation members.
    oidf::seed_profile(&pool, &Posture::Standard, None).await;
    let read_discovery = |app: &axum::Router| {
        let app2 = app.clone();
        async move {
            let resp = app2
                .oneshot(
                    Request::builder()
                        .uri("/.well-known/openid-configuration")
                        .header("x-sentin8-env-id", SYS_ENV.to_string())
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default()
        }
    };
    let doc = read_discovery(&app).await;
    let methods: Vec<String> = doc["token_endpoint_auth_methods_supported"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[])
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    assert!(
        !methods.iter().any(|m| m == "attest_jwt_client_auth"),
        "the standard posture does NOT advertise attestation auth: {methods:?}"
    );
    assert!(
        doc.get("client_attestation_signing_alg_values_supported")
            .is_none(),
        "the alg lists appear ONLY with the feature enabled"
    );

    // (2) ENABLED (the haip row + the anchor): the members appear.
    let anchor_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let anchor = attester_from_key(&anchor_key);
    oidf::seed_profile(
        &pool,
        &Posture::VciHaip,
        Some((&anchor.leaf_pem, ATTESTATION_ISSUER)),
    )
    .await;
    let doc2 = read_discovery(&app).await;
    let methods2: Vec<String> = doc2["token_endpoint_auth_methods_supported"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[])
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    assert!(
        methods2.iter().any(|m| m == "attest_jwt_client_auth"),
        "the enabled posture advertises the attestation method (§9a.19): {methods2:?}"
    );
    let algs: Vec<&str> = doc2["client_attestation_signing_alg_values_supported"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[])
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        algs.first().copied(),
        Some("ES256"),
        "the attestation signing-alg list rides (the draft's metadata rule)"
    );
    let pop_algs: Vec<&str> = doc2["client_attestation_pop_signing_alg_values_supported"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[])
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        pop_algs.first().copied(),
        Some("ES256"),
        "the PoP signing-alg list rides too"
    );
    // Revocation/introspection share the authenticator (the same method
    // list shape).
    let rev: Vec<String> = doc2["revocation_endpoint_auth_methods_supported"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[])
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    assert!(
        rev.iter().any(|m| m == "attest_jwt_client_auth"),
        "the revocation endpoint's method list carries the attestation method too: {rev:?}"
    );
    let _ = wrap64;
}

/// §9a.19 + - the CLIENT attestation's iss gate: an attestation
/// whose iss != the profile's configured issuer rejects (the suite's
/// PAR push asserts the OP-side check - the 'attestation iss mismatch'
/// class the per-env seed closes).
#[tokio::test]
async fn oidf_haip_attestation_iss_mismatch_rejected() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    let anchor_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let anchor = attester_from_key(&anchor_key);
    oidf::seed_profile(
        &pool,
        &Posture::VciHaip,
        Some((&anchor.leaf_pem, ATTESTATION_ISSUER)),
    )
    .await;
    let (proof_jwk, proof_key) = oidf::mk_es256_key_for_tests();
    let client = register_client(
        &pool,
        &ClientSpec {
            auth_method: "attest_jwt_client_auth",
            grant_types: &["authorization_code", "client_credentials"],
            response_types: &["code"],
            scopes: &["openid"],
            ..ClientSpec::private_key_jwt(proof_jwk.clone())
        },
    )
    .await;

    // iss = a FOREIGN attester domain → 401 (the profile's expected iss
    // is ATTESTATION_ISSUER).
    let att = mk_attestation(
        &anchor,
        &client.client_id,
        &proof_jwk,
        3600,
        Some("https://a-foreign-attester.example.org"),
    );
    let pop = mk_pop(
        &proof_key,
        "https://auth.test.local.sentin8.dev",
        &oidf::unique_jti("oidf-iss"),
    );
    let (s, b) = token_request(
        &app,
        &att,
        &pop,
        &attested_token_form(&client.client_id, "cc"),
    )
    .await;
    assert!(
        s == StatusCode::UNAUTHORIZED && b["error"].as_str() == Some("invalid_client"),
 "a foreign attestation iss → 401 ('s mismatch class): {s} {b}"
    );
}
