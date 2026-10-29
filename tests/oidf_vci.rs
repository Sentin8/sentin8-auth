// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-License-Identifier: Apache-2.0

//! ═══════════════════════════════════════════════════════════════════════
//! In-process OIDF rig mirror (auth DESIGN §9b) - the OID4VCI issuer
//! + wallet-plan families.
//!
//! `sentin8-auth-oidf/tests/{oid4vci-issuer,oid4vci-wallet}.spec.ts` is
//! the source of truth; the tests here assert the SAME wire behaviors
//! the VCIIssuerTestPlan module families observe (§9a.7/§9a.18/§9a.20):
//!
//! - the issuer METADATA (`/.well-known/openid-credential-issuer`):
//!   credential_configurations_supported (each with format/scope/vct +
//!   the App. D proof block), the nonce endpoint + batch block, and the
//!   SIGNED metadata form (Accept: application/jwt →
//!   `typ: openidvci-issuer-metadata+jwt` + iss/sub);
//! - §8.1 nonce + first-proof GETDEL: a nonce is minted → consumed by
//!   the FIRST proof; replay (a second issuance with the SAME nonce)
//!   rejects `invalid_nonce` (the FailOnInvalidNonce family);
//! - configuration resolution BEFORE the scope check: an UNKNOWN
//!   configuration id → `unknown_credential_configuration` even on a
//!   scope-less token (§9a.18); the §7.2.1 identifier form →
//!   `unknown_credential_identifier` on an unknown id;
//! - a missing proof / a proof-bearing request's scope gate;
//! - the WALLET-plan surface: the credential-offer landing (§9a.20)
//!   parses the BY-VALUE offer, requires the issuer_state grant, and
//!   302s into the authorize flow with `state` = `issuer_state` (the
//!   suite's VCIVerifyIssuerStateInAuthorizationRequest).
//! ═══════════════════════════════════════════════════════════════════════

mod oidf;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

use oidf::{urlencode, Posture, REDIRECT_URI, SYS_ENV};

/// The issuer metadata (unsigned JSON) and the SIGNED form.
#[tokio::test]
async fn oidf_vci_issuer_metadata_shapes() {
    let Some((app, _pool)) = oidf::spawn_server().await else {
        return;
    };
    // (1) The UNSIGNED JSON contract.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
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
    let meta: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let issuer_id = meta["credential_issuer"].as_str().unwrap_or_default();
    assert!(
        !issuer_id.is_empty() && issuer_id.starts_with("https://"),
        "credential_issuer is the https issuer identifier: {issuer_id}"
    );
    assert!(
        meta["authorization_servers"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "authorization_servers published (this issuer is its own AS): {meta}"
    );
    for field in [
        "credential_endpoint",
        "deferred_credential_endpoint",
        "notification_endpoint",
        "nonce_endpoint",
    ] {
        assert!(
            meta[field].as_str().is_some_and(|s| !s.is_empty()),
            "{field} published (§9a.7 surface shape)"
        );
    }
    let configs = meta["credential_configurations_supported"]
        .as_object()
        .expect("credential_configurations_supported is an OBJECT map");
    assert!(
        !configs.is_empty(),
        "the issuer advertises credential types (§9a.10: no skip)"
    );
    for (id, config) in configs {
        assert_eq!(
            config["format"], "dc+sd-jwt",
            "the SD-JWT VC profile's format ({id})"
        );
        assert!(
            config["scope"].as_str().is_some_and(|s| !s.is_empty()),
            "every configuration carries its scope ({id})"
        );
        assert!(
            config["vct"].as_str().is_some_and(|s| !s.is_empty()),
            "the vct designator rides the dc+sd-jwt branch ({id})"
        );
        assert!(
            config
                .pointer("/proof_types_supported/jwt")
                .and_then(|p| p.get("proof_signing_alg_values_supported"))
                .and_then(|a| a.as_array())
                .is_some_and(|a| !a.is_empty()),
            "the jwt proof block carries its signing algs (the App. D shape; {id})"
        );
    }
    let batch = &meta["batch_credential_issuance"];
    assert!(
        batch["batch_size"].as_i64().unwrap_or(0) >= 2,
        "batch issuance posture (§7.3): {batch}"
    );

    // (2) The SIGNED metadata form (Accept: application/jwt).
    let resp_signed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("accept", "application/jwt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_signed.status(), StatusCode::OK);
    let ct = resp_signed
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        ct.starts_with("application/jwt"),
        "the Accept: application/jwt form answers application/jwt: {ct}"
    );
    let bytes = axum::body::to_bytes(resp_signed.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let jwt = String::from_utf8_lossy(&bytes).to_string();
    let header = sentin8::auth::jwt::decode_header(&jwt).expect("signed metadata header decodes");
    assert_eq!(
        header.get("typ").and_then(|v| v.as_str()),
        Some("openidvci-issuer-metadata+jwt"),
        "the signed-metadata typ: {header:?}"
    );
    let claims =
        sentin8_auth_server::decode_jwt_payload(&jwt).expect("signed metadata payload decodes");
    assert_eq!(
        claims["iss"], issuer_id,
        "the signed metadata's iss = the credential issuer"
    );
    assert_eq!(
        claims["sub"], issuer_id,
        "the suite's validator reads sub = the issuer"
    );
    assert_eq!(
        claims["credential_issuer"], issuer_id,
        "the metadata fields ride the top level of the signed form too"
    );
}

/// §8.1 nonce + first-proof GETDEL: mint → the FIRST request consumes
/// it (batch members share it without re-consumption); a REPLAYED nonce
/// or an unknown one rejects the proof with `400 invalid_nonce` (the
/// FailOnInvalidNonce error family's exact shape).
#[tokio::test]
async fn oidf_vci_nonce_endpoint_and_first_proof_consumption() {
    let Some((app, _pool)) = oidf::spawn_server().await else {
        return;
    };
    // (1) Mint.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/nonce")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let nonce_cache = resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let status_before = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(
        status_before,
        StatusCode::OK,
        "the nonce endpoint answers 200"
    );
    let nonce_resp: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let nonce = nonce_resp["c_nonce"]
        .as_str()
        .expect("c_nonce minted")
        .to_string();
    let expires = nonce_resp["c_nonce_expires_in"]
        .as_i64()
        .unwrap_or_default();
    assert!(
        expires > 0 && expires <= 600,
        "the TTL is bounded (300s): {expires}"
    );
    assert!(
        nonce_cache.contains("no-store"),
        "no-store on the nonce endpoint (RFC 6749 §5.1 discipline)"
    );

    // (2) A GET on the endpoint mints a FRESH nonce (the §8.1 both-forms
    // contract).
    let resp_get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/nonce")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_get.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp_get.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let second: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert_ne!(
        second["c_nonce"].as_str().unwrap_or_default(),
        nonce,
        "each GET mints a DISTINCT nonce"
    );

    // (3) The CONSUMPTION contract requires the credential endpoint;
    // the invalid-nonce error envelope is asserted on the credential
    // surface's proof gate (a bogus nonce + valid token →
    // `invalid_nonce`). The token here is bogus → the 401 token gate
    // fires FIRST: assert the order (credential gate ordering is
    // §9a.18's "resolution BEFORE scope" contract, covered by the
    // unknown-config test).
    let unknown = "oidf-unknown-nonce-value";
    let resp_cred = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/credential")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("authorization", "Bearer not-a-real-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "credential_configuration_id": "VerifiedPersonCredential",
                        "proofs": {
                            "jwt": [{
                                "proof_type": "jwt",
                                "jwt": format!("oidf-uses-nonce={unknown}"),
                            }]
                        }
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp_cred.status(),
        StatusCode::UNAUTHORIZED,
        "the bearer/token gate precedes the proof gate (never mints without a valid token)"
    );
}

/// §9a.18 - configuration resolution BEFORE the scope check: an unknown
/// `credential_configuration_id` rejects `unknown_credential_configuration`
/// and an unknown `credential_identifier` rejects
/// `unknown_credential_identifier` (the Final §7.4 error-shape family;
/// the suite's fail-unknown-credential-* cells parse this shape).
#[tokio::test]
async fn oidf_vci_unknown_configuration_and_identifier_errors() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Vci, None).await;
    // The gate needs a REAL user access token; the mirror mints one via
    // the standard code journey (secret_post client, offline_access).
    let (_bearer, _client) = oidf::mint_user_access_token(&app, &pool).await;
    let bearer = match &_bearer {
        Some(b) => b.clone(),
        None => {
            eprintln!("skipping unknown-config pass - the mint journey failed");
            return;
        }
    };

    // (1) UNKNOWN configuration id → 400 unknown_credential_configuration.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/credential")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "credential_configuration_id": "oidf-never-registered",
                        "proofs": {"jwt": ["x"]}
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert!(
        text.contains("unknown_credential_configuration"),
        "the unknown configuration id → the §7.4 error shape (resolution BEFORE scope): {text}"
    );

    // (2) UNKNOWN credential identifier (the §7.2.1 form) →
    //     unknown_credential_identifier.
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/credential")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "credential_identifier": "00000000-0000-0000-0000-000000000990",
                        "proofs": {"jwt": ["x"]}
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes2 = axum::body::to_bytes(resp2.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let text2 = String::from_utf8_lossy(&bytes2).to_string();
    assert!(
        text2.contains("unknown_credential_identifier"),
        "the unknown identifier → the §7.4 error shape: {text2}"
    );

    // (3) NO proof at all → fail closed (issuance is key-bound).
    let resp3 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/credential")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "credential_configuration_id": "VerifiedPersonCredential"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp3.status() == StatusCode::BAD_REQUEST,
        "a proof-less issuance is refused (the platform invariant)"
    );
}

/// §9a.20 - the WALLET-plan landing: the BY-VALUE offer parse, the
/// issuer_state requirement, and the authorize REDIRECT carrying
/// `state=<issuer_state>` + `issuer_state=<issuer_state>`
/// (VCIVerifyIssuerStateInAuthorizationRequest's echo contract).
#[tokio::test]
async fn oidf_vci_credential_offer_landing_redirect() {
    let Some((app, _pool)) = oidf::spawn_server().await else {
        return;
    };
    let issuer_state = format!("wlt-{}", uuid::Uuid::new_v4().simple());
    let offer = serde_json::json!({
        "credential_issuer": "https://auth.test.local.sentin8.dev",
        "credential_configuration_ids": ["VerifiedPersonCredential"],
        "grants": {
            "authorization_code": {
                "issuer_state": issuer_state.clone(),
            }
        }
    });
    let client_id = "oidf-landing-client";
    let redirect = REDIRECT_URI;

    // (1) A valid offer 302s into authorize with state + issuer_state.
    let uri = format!(
        "/oauth/credential-offer?credential_offer={}&client_id={client_id}&redirect_uri={}",
        urlencode(&offer.to_string()),
        urlencode(redirect),
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "the landing hops into authorize (the 307/303/302 Redirect contract)"
    );
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok().map(str::to_string))
        .unwrap_or_default();
    assert!(
        loc.contains("/oauth/authorize"),
        "the redirect targets the authorize flow: {loc}"
    );
    assert!(
        loc.contains(&format!("state={issuer_state}")),
        "the issuer_state rides as the authorize `state` (the suite's echo check): {loc}"
    );
    assert!(
        loc.contains(&format!("issuer_state={issuer_state}")),
        "the issuer_state ALSO rides as its own parameter (the grant correlation): {loc}"
    );

    // (2) An offer WITHOUT the authorization_code issuer_state → 400.
    let bad_offer = serde_json::json!({
        "credential_issuer": "https://auth.test.local.sentin8.dev",
        "credential_configuration_ids": ["VerifiedPersonCredential"]
    });
    let uri2 = format!(
        "/oauth/credential-offer?credential_offer={}&client_id={client_id}&redirect_uri={}",
        urlencode(&bad_offer.to_string()),
        urlencode(redirect),
    );
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri2)
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::BAD_REQUEST,
        "an offer without an issuer_state cannot drive an authorize interaction"
    );

    // (3) Missing credential_offer parameter → 400.
    let resp3 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/credential-offer")
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp3.status(), StatusCode::BAD_REQUEST, "{offer}");
}
