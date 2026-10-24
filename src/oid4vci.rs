// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! OpenID for Verifiable Credential Issuance (OID4VCI) - the standard
//! issuer surface (DESIGN.md §9a.7) over the existing SD-JWT /
//! key-binding / Status-List core.
//!
//! Endpoint set (all issuer-hosted on auth):
//! - `GET /.well-known/openid-credential-issuer` - issuer metadata
//!   (`credential_configurations_supported`, endpoint addresses).
//! - `POST /oauth/credential` - single-credential issuance request
//!   (`credential_configuration_id` + optional `proof` JWT); immediate
//!   mint or `202 {transaction_id}` for deferred.
//! - `POST /oauth/deferred_credential` - poll a transaction.
//! - `POST /oauth/notifications` - wallet events (credential received /
//!   failed) recorded against the credential row.
//!
//! Authorization: an access token from the standard grant families whose
//! scope carries the credential type (`openid credential:{type}`). The
//! platform-native `/oauth/credentials*` endpoints remain as the
//! session-authenticated alias surface (BFF); these endpoints serve the
//! spec wire shape the OID4VCI conformance suite exercises.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::handlers::AppState;

// ── Metadata ──────────────────────────────────────────────────────────

/// Credential configuration entries auth mints (SD-JWT VC profile). The
/// set is the wallet credential store's supported types.
fn supported_credential_configurations(issuer: &str) -> serde_json::Value {
    let _ = issuer;
    let single = |id: &str| {
        serde_json::json!({
            "format": "dc+sd-jwt",
            "scope": format!("credential:{id}"),
            "cryptographic_binding_methods_supported": ["jwk"],
            // The VCI validators accept recognized ASYMMETRIC JWS algs
            // only (Nimbus JWS families) - ML-DSA-65 is not in the set it
            // parses, so the metadata advertises the classical families;
            // ML-DSA tokens verify kid-routed regardless (mint/verify do
            // not read this list).
            "credential_signing_alg_values_supported": ["ES256", "RS256"],
            // Final §12.2.4/App. D - the proof key MUST arrive with a key
            // attestation (`key-attestation+jwt`, signed key material);
            // the field rides INSIDE the jwt proof-type entry.
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256", "RS256"],
                    "key_attestations_required": {
                        "key_storage": ["software", "enclave", "tpm", "secure_element"]
                    },
                }
            },
            // dc+sd-jwt profile (credential_issuer_metadata-1_0.json):
            // `vct` is the REQUIRED type designator; `credential_definition`
            // belongs to the jwt_vc_json branch and `status` is not a
            // config-level property at all (the status list rides the
            // minted credential's `status` claim) - the schema rejects
            // both here (unevaluatedProperties: false).
            "vct": id,
        })
    };
    // The OIDF WALLET-plan catalog (VCICredentialConfigurations DEFAULTS -
    // the suite builds its metadata from these per-test defaults): the
    // dc+sd-jwt families the wallet plan actually requests under the
    // sd_jwt_vc format variant. Each entry carries the catalog's scope +
    // proof shape; the keyattest entries REQUIRE the key attestation like
    // the native configs (the plan's keyattest modules drive that path).
    // The minted `vct` is the catalog's designator (urn:eudi:pid:1).
    let proof = |kinds: &[&str]| {
        let mut pt = serde_json::Map::new();
        for k in kinds {
            pt.insert(
                (*k).to_string(),
                serde_json::json!({ "proof_signing_alg_values_supported": ["ES256", "RS256"] }),
            );
        }
        serde_json::Value::Object(pt)
    };
    let wallet = |id: &str, scope: &str, proofs: &[&str], vct: &str| {
        let mut v = serde_json::json!({
            "format": "dc+sd-jwt",
            "scope": scope,
            "vct": vct,
            "cryptographic_binding_methods_supported": ["jwk"],
            "credential_signing_alg_values_supported": ["ES256", "RS256"],
            "proof_types_supported": proof(proofs),
        });
        v.as_object_mut().unwrap().insert(
            "credential_metadata".to_string(),
            serde_json::json!({
                "display": [ { "name": id, "description": "Sentin8 wallet-catalog credential" } ]
            }),
        );
        // The keyattest catalog entries REQUIRE the key attestation (the
        // module drives the attested-proof path; the plain families do
        // not carry the requirement). The schema places
        // key_attestations_required INSIDE each proof-type entry (sibling
        // of the entry's proof_signing_alg_values_supported) - a sibling
        // of the proof type itself is an unknown property.
        if id.contains("keyattest") {
            let req = serde_json::json!({
                // The metadata schema requires the attestation's proof-alg
                // list INSIDE key_attestations_required (the suite's
                // VCICredentialIssuerMetadataValidation).
                "proof_signing_alg_values_supported": ["ES256"],
            });
            let pts = v
                .as_object_mut()
                .unwrap()
                .get_mut("proof_types_supported")
                .unwrap()
                .as_object_mut()
                .unwrap();
            for (_, entry) in pts.iter_mut() {
                entry
                    .as_object_mut()
                    .unwrap()
                    .insert("key_attestations_required".to_string(), req.clone());
            }
        }
        v
    };
    serde_json::json!({
        "VerifiedPersonCredential": single("VerifiedPersonCredential"),
        "VerifiedEmployeeCredential": single("VerifiedEmployeeCredential"),
        "eu.europa.ec.eudi.pid.1": wallet(
            "eu.europa.ec.eudi.pid.1",
            "eudi.pid.1",
            &["jwt"],
            "urn:eudi:pid:1",
        ),
        "eu.europa.ec.eudi.pid.1.nobinding": wallet(
            "eu.europa.ec.eudi.pid.1.nobinding",
            "eudi.pid.1.nobinding",
            &[],
            "urn:eudi:pid:1",
        ),
        "eu.europa.ec.eudi.pid.1.attestation": wallet(
            "eu.europa.ec.eudi.pid.1.attestation",
            "eudi.pid.1.attestation",
            &["attestation"],
            "urn:eudi:pid:1",
        ),
        "eu.europa.ec.eudi.pid.1.jwt.keyattest": wallet(
            "eu.europa.ec.eudi.pid.1.jwt.keyattest",
            "eudi.pid.1.jwt.keyattest",
            &["jwt"],
            "urn:eudi:pid:1",
        ),
        "eu.europa.ec.eudi.pid.1.attestation.keyattest": wallet(
            "eu.europa.ec.eudi.pid.1.attestation.keyattest",
            "eudi.pid.1.attestation.keyattest",
            &["attestation"],
            "urn:eudi:pid:1",
        ),
        "eu.europa.ec.eudi.pid.1.jwt_and_attestation.keyattest": wallet(
            "eu.europa.ec.eudi.pid.1.jwt_and_attestation.keyattest",
            "eudi.pid.1.jwt_and_attestation.keyattest",
            &["jwt", "attestation"],
            "urn:eudi:pid:1",
        ),
    })
}

/// `GET /.well-known/openid-credential-issuer` - OID4VCI issuer metadata
/// (DESIGN §9a.7). Issuer-resolved like OIDC discovery (host context).
#[utoipa::path(
    get,
    path = "/.well-known/openid-credential-issuer",
    responses(
        (status = 200, description = "OID4VCI issuer metadata", body = CredentialIssuerMetadata),
    ),
    security(),
    tag = "wallet",
)]
pub async fn credential_issuer_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let issuer = crate::oauth::resolve_issuer(&state.config, &headers);
    // §12.2.4 (HAIP) - credential-response encryption advertisement rides
    // the profile plane: the SAME flag family that enables attestation
    // client auth (only the vci_haip posture carries cryptographic
    // guarantees beyond the plain profile).
    let profile =
        crate::oauth::resolve_security_profile(&state.pool, &headers, "env").await;
    let encryption_enabled =
        profile.allow_client_attestation && !profile.client_attestation_trust_anchor_pem.trim().is_empty();
    let metadata = CredentialIssuerMetadata {
        credential_issuer: issuer.clone(),
        authorization_servers: vec![issuer.clone()],
        credential_endpoint: format!("{issuer}/oauth/credential"),
        deferred_credential_endpoint: format!("{issuer}/oauth/deferred_credential"),
        notification_endpoint: format!("{issuer}/oauth/notifications"),
        nonce_endpoint: format!("{issuer}/oauth/nonce"),
        // Final §12.2.4 - batch issuance support (the proofs array size
        // the endpoint accepts).
        batch_credential_issuance: serde_json::json!({ "batch_size": 10 }),
        credential_response_encryption: if encryption_enabled {
            Some(serde_json::json!({
                "alg_values_supported": crate::jwe::SUPPORTED_ALGS,
                "enc_values_supported": crate::jwe::SUPPORTED_ENCS,
                "encryption_required": false,
            }))
        } else {
            None
        },
        credential_request_encryption: if encryption_enabled {
            // §12.2.4: when response encryption is declared, the
            // REQUEST direction must be declared too (the suite's
            // VCIEnsureCredentialRequestEncryptionWhen... family). The
            // schema (credential-issuer-metadata-1_0.json) allows ONLY
            // {enc_values_supported, encryption_required, jwks,
            // zip_values_supported} here - no alg list (the asymmetric
            // JWE alg rides each key's own `alg` member).
            Some(serde_json::json!({
                "enc_values_supported": crate::jwe::SUPPORTED_ENCS,
                "encryption_required": false,
                "jwks": state.keys.credential_request_encryption_jwks(),
            }))
        } else {
            None
        },
        credential_configurations_supported: supported_credential_configurations(&issuer),
    };
    let value = serde_json::to_value(&metadata).unwrap_or_else(|_| serde_json::json!({}));

    // OID4VCI Final signed-metadata form: an Accept for
    // `application/jwt` gets the metadata as a signed JWT
    // (`typ: openidvci-issuer-metadata+jwt`, kid-routed to the AS's
    // published JWKS). The unsigned JSON form stays the default answer.
    let wants_jwt = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| {
            a.split(',')
                .any(|m| m.trim().split(';').next().unwrap_or("").trim() == "application/jwt")
        })
        .unwrap_or(false);
    if wants_jwt {
        return match signed_metadata_jwt(&state.keys, &issuer, &value) {
            Ok(jwt) => (
                [(axum::http::header::CONTENT_TYPE, "application/jwt")],
                jwt,
            )
                .into_response(),
            Err(e) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                e,
            )
                .into_response(),
        };
    }
    Json(value).into_response()
}

/// Sign the issuer-metadata document as the OID4VCI signed-metadata JWT:
/// `iss` = credential_issuer, `iat`/`exp` (24h window), the metadata
/// fields at the top level, header `typ: openidvci-issuer-metadata+jwt`,
/// `kid` = the active signing key's kid (the suite resolves it from the
/// AS's published JWKS).
fn signed_metadata_jwt(
    keys: &crate::jwks::SigningKeys,
    issuer: &str,
    metadata: &serde_json::Value,
) -> Result<String, String> {
    let now = Utc::now().timestamp();
    let mut claims = metadata.clone();
    let obj = claims
        .as_object_mut()
        .ok_or_else(|| "metadata is not an object".to_string())?;
    obj.insert("iss".into(), serde_json::json!(issuer));
    // The suite's validator (OID4VCI signed-metadata): `sub` carries the
    // credential issuer identifier and must equal the configured issuer.
    obj.insert("sub".into(), serde_json::json!(issuer));
    obj.insert("iat".into(), serde_json::json!(now));
    obj.insert("exp".into(), serde_json::json!(now + 24 * 3600));
    keys.sign_value_typed_inlined_jwk(&claims, "ES256", "openidvci-issuer-metadata+jwt")
        .or_else(|_| keys.sign_value_typed_inlined_jwk(&claims, "RS256", "openidvci-issuer-metadata+jwt"))
        .or_else(|_| keys.sign_value_typed(&claims, "MLDSA65", "openidvci-issuer-metadata+jwt"))
}

/// OID4VCI issuer metadata document.
#[derive(Debug, Serialize, utoipa::ToSchema)]
/// The credentialissuermetadata type.
pub struct CredentialIssuerMetadata {
    /// The credential issuer identifier (this auth instance).
    pub credential_issuer: String,
    /// Authorization servers accepting the credential scopes - this
    /// issuer is also its own AS (the standard authorize/token surface).
    pub authorization_servers: Vec<String>,
    /// `POST /oauth/credential` - the issuance endpoint.
    pub credential_endpoint: String,
    /// `POST /oauth/deferred_credential` - deferred polling endpoint.
    pub deferred_credential_endpoint: String,
    /// `POST /oauth/notifications` - wallet event endpoint.
    pub notification_endpoint: String,
    /// Final §12.2.4 - the issuance nonce endpoint (the proof's
    /// `nonce` claim echoes a c_nonce minted here; replay/reuse of an
    /// unknown nonce rejects the proof).
    pub nonce_endpoint: String,
    /// Final §12.2.4 - the batch issuance posture (`batch_size` >= 2).
    pub batch_credential_issuance: serde_json::Value,
    /// §12.2.4 (HAIP) - the credential-response encryption metadata
    /// (alg/enc values + encryption_required); present ONLY when the
    /// resolved profile enables credential encryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<serde_json::Value>,
    /// §12.2.4 (HAIP) - the credential-REQUEST encryption metadata (the
    /// issuer's recipient key set); declared alongside the response
    /// direction (the suite requires both).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_request_encryption: Option<serde_json::Value>,
    /// One entry per credential type auth mints (SD-JWT VC profile).
    pub credential_configurations_supported: serde_json::Value,
}

// ── Issuance ──────────────────────────────────────────────────────────

/// `POST /oauth/credential` request (OID4VCI §7.2).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for credential.
pub struct CredentialRequest {
    /// The configuration id being requested (a key of
    /// `credential_configurations_supported`). Omitted in the
    /// credential-identifier form (§7.2.1), where the access token is
    /// pre-bound to the configuration via its scope.
    #[serde(default)]
    pub credential_configuration_id: Option<String>,
    /// The credential-identifier form (§7.2.1): the identifier issued in
    /// the deferred flow's `transaction_id` (or the token-scope-bound
    /// request) - the configuration resolves from the token scope.
    #[serde(default)]
    pub credential_identifier: Option<String>,
    /// Final §7.2 proofs map: `{"jwt": ["<proof-jwt>"]}` - an object
    /// keyed BY proof type carrying that type's JWT array (the suite's
    /// and wallets' wire form). Unknown keys = unsupported proof types
    /// (only `jwt` is implemented - rejected below).
    #[serde(default)]
    pub proofs: Option<std::collections::BTreeMap<String, Vec<String>>>,
    /// The Draft-11 single-proof form (`proof: {proof_type, jwt}`) -
    /// still seen from earlier wallets; accepted (one-of).
    #[serde(default)]
    pub proof: Option<Proof>,
    /// §12.2.4 (HAIP) - the wallet's credential-response encryption
    /// parameters (`{alg, enc, jwk|jwks}`): when present the response
    /// body is a compact JWE over the wallet's key.
    #[serde(default)]
    pub credential_response_encryption: Option<serde_json::Value>,
}

/// The `proof` container.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// The proof type.
pub struct Proof {
    /// Must be `jwt`.
    pub proof_type: String,
    /// The JWT text.
    pub jwt: String,
}

/// `POST /oauth/deferred_credential` request.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for deferredcredential.
pub struct DeferredCredentialRequest {
    /// The transaction id returned by a 202 issuance response.
    pub transaction_id: String,
}

/// `POST /oauth/notifications` request (OID4VCI §11.1).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for notification.
pub struct NotificationRequest {
    /// The event id (server checks event semantics, not the value).
    pub event_id: String,
    /// The event type - `credential_received` / `credential_failed`.
    pub event: String,
    /// The issuance this event refers to.
    #[serde(default)]
    pub transaction_id: Option<Uuid>,
}

/// Mint the SD-JWT credential for an approved issuance record - shared by
/// the immediate and deferred paths. The claims shape mirrors the
/// platform-native mint (SD-JWT VC: `vct`, `cnf.jwk`, status list).
/// Verify a credential request's key-binding proof (OID4VCI Final
/// §7.2, DESIGN §9a.7). Two accepted forms:
/// 1. Final self-contained proof - `typ: openid4vci-proof+jwt`, the key
///    in the `jwk` HEADER member, claims `iss` (the wallet/client id,
///    optional when attested), `aud` = the credential issuer, `iat`
///    fresh (±5min; the suite's FailOnInvalidNonce class also expects
///    the nonce echo when the metadata advertises `nonce_endpoint`).
///    The signature verifies against the header JWK.
/// 2. Draft-11 payload-cnf proof - the key bound as `cnf.jwk` in the
///    payload; verified the same way once the key is extracted.
/// Returns the wallet's public JWK to bind into the credential's `cnf`.
///
/// # Errors
/// - `400` malformed proof (missing claims / bad key / bad signature).
/// - `401` when a DPoP-scheme token's proof or `ath` binding fails.
/// The JWK of an attestation JWT header's x5c LEAF certificate (DESIGN
/// §9a.7.6): decode the base64 DER chain, take the first entry, parse its
/// SubjectPublicKeyInfo into a P-256 verifying key and re-serialize the
/// point as a Standard EC JWK (kty/crv/x/y) for signature verification.
/// Returns `Ok(None)` when the header carries no x5c chain.
///
/// # Errors
/// - base64 or DER/SPKI parse failures surface as strings (caller maps
///   them to a 400).
fn key_attestation_x5c_leaf_jwk(
    att_header: &serde_json::Value,
) -> Result<Option<serde_json::Value>, String> {
    let Some(chain) = att_header.get("x5c").and_then(|v| v.as_array()) else {
        return Ok(None);
    };
    let Some(leaf_b64) = chain.first().and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD
        .decode(leaf_b64)
        .map_err(|e| format!("x5c leaf base64 decode: {e}"))?;
    // The x5c entry is a full X.509 CERTIFICATE; extract its
    // SubjectPublicKeyInfo (tbsCertificate's trailing field) before
    // SPKI-parsing (DESIGN §9a.7.6).
    let spki = x509_leaf_spki(&der).map_err(|e| format!("x5c leaf parse: {e}"))?;
    use p256::pkcs8::DecodePublicKey;
    let vk = p256::ecdsa::VerifyingKey::from_public_key_der(&spki)
        .map_err(|e| format!("x5c leaf SPKI parse: {e}"))?;
    let point = vk.to_encoded_point(false);
    // P-256 uncompressed points are always 32-byte coordinates; the
    // Option shape comes from the generic EncodedPoint API.
    let (x_raw, y_raw) = match (point.x(), point.y()) {
        (Some(x), Some(y)) => (x, y),
        _ => return Err("x5c leaf SPKI coordinates missing".into()),
    };
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x_raw);
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y_raw);
    Ok(Some(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
    })))
}

/// Der leaf parse.
///
/// Extracts the `subjectPublicKeyInfo` DER bytes from an X.509 certificate
/// (RFC 5280) with a minimal TLV walk: Certificate ::= SEQUENCE { SEQUENCE
/// tbsCertificate, ... } and tbsCertificate = version [0]?, serialNumber,
/// signature, issuer, validity, subject, subjectPublicKeyInfo. The SPKI is
/// the 7th element when version is present, the 6th otherwise. No x509
/// crate dependency - the walk only skips standard tag/length fields.
fn x509_leaf_spki(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    fn read_tlv(buf: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
        if buf.len() < 2 {
            return Err("DER buffer too short".into());
        }
        let tag = buf[0];
        let len_byte = buf[1];
        let (hdr, len) = if len_byte & 0x80 == 0 {
            (2usize, len_byte as usize)
        } else {
            let n = (len_byte & 0x7f) as usize;
            if n == 0 || n > 4 || buf.len() < 2 + n {
                return Err("unsupported DER long-form length".into());
            }
            let mut len = 0usize;
            for b in &buf[2..2 + n] {
                len = (len << 8) | *b as usize;
            }
            (2 + n, len)
        };
        if buf.len() < hdr + len {
            return Err(format!("DER truncated: need {len}, have {}", buf.len() - hdr));
        }
        let content = &buf[hdr..hdr + len];
        let rest = &buf[hdr + len..];
        Ok((tag, content, rest))
    }

    let (tag_cert, cert_seq, _) = read_tlv(cert_der).map_err(|e| format!("outer: {e}"))?;
    if tag_cert != 0x30 {
        return Err("certificate is not a SEQUENCE".into());
    }
    let (tag_tbs, tbs, _rest) = read_tlv(cert_seq).map_err(|e| format!("tbs outer: {e}"))?;
    if tag_tbs != 0x30 {
        return Err("tbsCertificate is not a SEQUENCE".into());
    }
    // Walk tbsCertificate's elements until the SPKI: [version [0]?],
    // serialNumber, signature, issuer, validity, subject -> SPKI is the
    // 7th element when the [0] version wrapper is present, else the 6th.
    // The wrapper is the ONLY context-specific tag at this depth.
    let mut cur = tbs;
    let mut count = 0usize;
    let mut spki_index = 6usize;
    loop {
        let (tag, _content, rest) = read_tlv(cur)?;
        count += 1;
        if count == 1 && tag & 0xc0 == 0x80 {
            spki_index = 7;
        }
        if count >= spki_index {
            if tag != 0x30 {
                return Err(format!(
                    "subjectPublicKeyInfo is not a SEQUENCE (tag {tag:#x})"
                ));
            }
            // The full SPKI span (tag + length header + content) is the
            // slice of `cur` before the remaining elements start; the
            // SPKI parse below consumes complete TLVs.
            let full_len = cur.len() - rest.len();
            return Ok(cur[..full_len].to_vec());
        }
        cur = rest;
        if cur.is_empty() {
            return Err("tbsCertificate ended before subjectPublicKeyInfo".into());
        }
    }
}

/// Verify a credential request's KEY-BINDING proof only (the OTSL/
/// wallet proof; the transport-level DPoP check is the handler's -
/// once per REQUEST, not per batch member). See DESIGN  9a.7.
async fn verify_credential_proof(
    state: &AppState,
    headers: &HeaderMap,
    proof_jwt: &str,
    consume_nonce: bool,
    _access_token: &str,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let header = sentin8::auth::jwt::decode_header(proof_jwt)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("proof header decode: {e}")))?;
    // Final   7.2 - the proof's typ is `openid4vci-proof+jwt` (the
    // draft-11 wallet proofs may still carry `openid4vci-proof+jwt` too;
    // an unexpected typ is a malformed proof).
    let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
    if !typ.is_empty() && typ != "openid4vci-proof+jwt" && typ != "JWT" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported proof typ: {typ}"),
        ));
    }
    let header_jwk = header.get("jwk").cloned();
    let payload = sentin8::auth::jwt::decode_payload(proof_jwt)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("proof decode: {e}")))?;
    let now = Utc::now().timestamp();

    // Final App. D - when the credential configuration requires key
    // attestation, the proof's JWS header carries
    // `key_attestation: <key-attestation+jwt>`; the attestation binds
    // the proof key and ITSELF VERIFY (the suite's
    // FailOnInvalidKeyAttestationSignature family): the verification key
    // is either the attestation's own inlined `jwk` header member or the
    // x5c leaf certificate's SubjectPublicKeyInfo (the chain form the
    // spec's attestation format carries); with EXACTLY ONE of them the
    // JWS must verify - a tampered attestation never passes (see DESIGN
    // §9a.7.6).
    if let Some(att) = header.get("key_attestation").and_then(|v| v.as_str()) {
        let payload_att = sentin8::auth::jwt::decode_payload(att)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("key attestation decode: {e}")))?;
        let att_header = sentin8::auth::jwt::decode_header(att)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("key attestation decode: {e}")))?;
        let att_jwk = att_header.get("jwk").cloned();
        let att_x5c_leaf = key_attestation_x5c_leaf_jwk(&att_header)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("key attestation x5c: {e}")))?;
        let exp_ok = payload_att
            .get("exp")
            .and_then(|v| v.as_i64())
            .map(|e| e >= now - 60)
            .unwrap_or(true);
        if !exp_ok {
            return Err((StatusCode::BAD_REQUEST, "key attestation expired".into()));
        }
        if let Some(cnf) = payload_att.pointer("/cnf/jwk") {
            if let (Some(a), Some(p)) = (cnf.as_object(), header_jwk.as_ref().and_then(|h| h.as_object())) {
                if a != p {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "key attestation does not bind the proof key".into(),
                    ));
                }
            }
        }
        // Exactly one verification key must be resolvable and the JWS
        // must verify against it - no silent skip when the chain form is
        // used (the inline-jwk and x5c chains are mutually exclusive
        // representations of the same attestation signing key).
        let att_verify_jwk = match (att_jwk, att_x5c_leaf) {
            (Some(j), _) => j,
            (None, Some(j)) => j,
            (None, None) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "key attestation carries no verification key (jwk header or x5c chain)".into(),
                ))
            }
        };
        crate::jwks::SigningKeys::verify_with_jwk(&att_verify_jwk, att)
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("key attestation signature verification failed: {e}"),
                )
            })?;
    }

    // The draft-11 form binds the key in the payload (cnf.jwk); the
    // Final form carries it in the header. Exactly one wins.
    let key_jwk = match (&header_jwk, payload.pointer("/cnf/jwk")) {
        (Some(j), _) => j.clone(),
        (None, Some(j)) => j.clone(),
        (None, None) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "proof must carry the wallet key (header jwk or payload cnf.jwk)".into(),
            ))
        }
    };

    // Signature verification against the extracted key - the proof is a
    // signed document, not a container of self-declared truths.
    crate::jwks::SigningKeys::verify_with_jwk(&key_jwk, proof_jwt)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("proof signature verification failed: {e}")))?;

    // aud = the credential issuer; iat fresh ( 5min - the same closed
    // window shape as the client assertion).
    let aud = payload.get("aud").and_then(|v| v.as_str()).unwrap_or("");
    if !aud.is_empty() && aud != crate::oauth::resolve_issuer(&state.config, headers) {
        return Err((StatusCode::BAD_REQUEST, "proof aud mismatch".into()));
    }
    if let Some(iat) = payload.get("iat").and_then(|v| v.as_i64()) {
        if (iat - now).abs() > 300 {
            return Err((StatusCode::BAD_REQUEST, "proof iat out of range (+/-5min)".into()));
        }
    } else if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
        // An exp-carrying legacy proof: still bounded.
        if exp <= now - 300 || exp > now + 300 {
            return Err((StatusCode::BAD_REQUEST, "proof exp out of range (+/-5min)".into()));
        }
    }

    // The issuance nonce (Final §8.1): when the issuer advertises the
    // nonce endpoint, every proof MUST echo a FRESH c_nonce - an
    // unknown/replayed nonce rejects the whole request with the 400
    // `invalid_nonce` error shape (the FailOnInvalidNonce family).
    // Batch rule (Final §7.3): the ONE issuance nonce covers the
    // REQUEST - the FIRST proof consumes it (GETDEL), members 1..n only
    // carry it again (their nonce is not re-consumed; a nonce mismatch
    // across the batch is still invalid via `consume_nonce`).
    if let Some(nonce) = payload.get("nonce").and_then(|v| v.as_str()) {
        if nonce.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "invalid_nonce".into()));
        }
        if consume_nonce {
            let consumed = if let Ok(conn) = sentin8::middleware::valkey_client(
                &state.config.valkey_url,
                "sentin8:auth",
            )
            .await
            {
                use glide::AsyncCommands as _;
                let key = format!("auth:vcinonce:{nonce}");
                let got: Result<Option<String>, _> = conn.get_del(key).await;
                got.ok().flatten().is_some()
            } else {
                false
            };
            if !consumed {
                return Err((StatusCode::BAD_REQUEST, "invalid_nonce".into()));
            }
        }
    } else if consume_nonce {
        // A proof WITHOUT the nonce claim while the endpoint is
        // advertised = a malformed issuance attempt.
        return Err((StatusCode::BAD_REQUEST, "invalid_nonce".into()));
    }

    Ok(key_jwk)
}

/// The transport-level sender check for the credential request: a
/// DPoP-bound access token must arrive with ITS OWN DPoP proof
/// (htm/htu/ath bound, the key == the token's cnf.jkt). ONCE per
/// request - the batch loop reuses the verdict. (RFC 9449 §7.1.)
async fn verify_credential_dpop(
    state: &AppState,
    headers: &HeaderMap,
    access_token: &str,
) -> Result<(), (StatusCode, String)> {
    let claims = state
        .keys
        .verify(access_token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid access token".to_string()))?;
    // The revocation cascade (DESIGN §9a.22): a denylisted jti (RFC 7009)
    // or a REVOKED GRANT (the code-reuse cascade - the suite's
    // attempt-reuse-authorization-code module expects the resource surface
    // to reject after the replay revocation) hard-fails the credential
    // request the same way userinfo hard-fails.
    if crate::oauth::is_token_revoked(&state, &claims.jti).await
        || crate::oauth::is_grant_revoked(&state, claims.grant_id.as_deref().unwrap_or("")).await
    {
        return Err((StatusCode::UNAUTHORIZED, "token has been revoked".into()));
    }
    let Some(cnf) = claims
        .cnf
        .as_ref()
        .and_then(|c| c.get("jkt"))
        .and_then(|k| k.as_str())
        .map(str::to_string)
    else {
        return Ok(());
    };
    let Some(proof) = crate::dpop::extract_dpop_header(headers) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "dpop-bound token requires a DPoP proof".into(),
        ));
    };
    let htu = format!(
        "{}/oauth/credential",
        crate::oauth::resolve_issuer(&state.config, headers)
    );
    let jkt = crate::dpop::validate_and_verify_dpop(&state, &proof, "POST", &htu)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
    let decoded = crate::dpop::decode_dpop_proof_unverified(&proof)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
    let expected_ath = crate::dpop::compute_ath(access_token);
    if decoded.claims.ath.as_deref() != Some(expected_ath.as_str()) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "DPoP proof ath does not bind the access token".into(),
        ));
    }
    if jkt != cnf {
        return Err((
            StatusCode::UNAUTHORIZED,
            "DPoP proof key does not match the token's cnf.jkt".into(),
        ));
    }
    Ok(())
}

/// `GET /oauth/nonce` - issuance nonce (Final §8.1): a fresh c_nonce
/// the wallet's next proof echoes. Stored in Valkey (TTL 300s) - the
/// proof check consumes it (FailOnInvalidNonce family: a random or
/// replayed nonce must answer the 400 `invalid_nonce` error shape).
///
/// # Errors
/// - `500` nonce store unavailable.
#[utoipa::path(
    method(get, post),
    path = "/oauth/nonce",
    responses(
        (status = 200, description = "Fresh issuance nonce", body = serde_json::Value),
    ),
    security(),
    tag = "wallet",
)]
pub async fn issuance_nonce(State(state): State<AppState>) -> Response {
    let nonce = Uuid::new_v4().simple().to_string();
    if let Ok(conn) =
        sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
    {
        use glide::AsyncCommands as _;
        let _: Result<(), _> = conn
            .set_ex(
                format!("auth:vcinonce:{nonce}"),
                "1",
                300u64,
            )
            .await;
    }
    (
        [
            (
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            ),
            (
                axum::http::header::PRAGMA,
                axum::http::HeaderValue::from_static("no-cache"),
            ),
        ],
        Json(serde_json::json!({
            "c_nonce": nonce,
            "c_nonce_expires_in": 300,
        })),
    )
        .into_response()
}

async fn mint_credential(
    state: &AppState,
    headers: &HeaderMap,
    credential_id: Uuid,
    env_id: Uuid,
    user_id: Uuid,
    cred_type: &str,
    cnf_jwk: &serde_json::Value,
    shared_status: Option<Uuid>,
    status_idx: u32,
    x5c_chain: Option<&[String]>,
) -> Result<String, (StatusCode, String)> {
    let _ = env_id;
    // RFC 9901 linkability: the credential's issuance time claims are
    // ROUNDED TO THE HOUR (two issuances of the same dataset within the
    // hour carry identical iat/exp - the real inter-issuance gap stays
    // unobservable; the suite's batch-time-linkability check fails a
    // precise high-entropy time cluster).
    let now = Utc::now().timestamp();
    let hour = 3600;
    let now = now - (now.rem_euclid(hour));
    let exp = now + 90 * 24 * 3600;
    let claims = serde_json::json!({
        "iss": state.config.issuer,
        "sub": user_id.to_string(),
        "iat": now,
        "exp": exp,
        "vct": cred_type,
        "status": {
            "status_list": {
                "uri": format!(
                    "{}/oauth/credentials/status/{}",
                    crate::oauth::resolve_issuer(&state.config, headers),
                    // Batch members SHARE one status list (the herd-privacy
                    // rule the suite's batch check enforces): members 1..n
                    // point at the FIRST member's list with a distinct idx.
                    shared_status.unwrap_or(credential_id)
                ),
                "idx": status_idx,
            }
        },
        "cnf": { "jwk": cnf_jwk },
    });
    // SD-JWT VC shape (SD-JWT §4): `<jws>~< disclosures>~[<kb-jwt>]`.
    // Every claim here is REGULAR (no `_sd` digests) so the disclosures
    // list is EMPTY - the format still requires the separator (and the
    // suite's ParseCredentialAsSdJwt splits on it).
    // HAIP (ValidateSdJwtCredentialX5cCertificateChain): the credential
    // JWS header carries the x5c chain of the issuer's key; fall back to
    // the plain typed form for non-HAIP profiles.
    state
        .keys
        .sign_value_typed_x5c(&claims, "ES256", "dc+sd-jwt", x5c_chain)
        .or_else(|_| state.keys.sign_value_typed(&claims, "ES256", "dc+sd-jwt"))
        .or_else(|_| state.keys.sign_value_typed(&claims, "RS256", "dc+sd-jwt"))
        .or_else(|_| state.keys.sign_value(&claims))
        .map(|jws| format!("{jws}~"))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("credential signing: {e}")))
}

/// `POST /oauth/credential` - issuance request (OID4VCI §7.2, DESIGN
/// §9a.7). Authorized by an access token whose scope carries the
/// credential type; the proof JWT binds the wallet key.
///
/// # Errors
/// - `400` unknown configuration or malformed proof.
/// - `401` missing/invalid access token or proof verification failed.
#[utoipa::path(
    post,
    path = "/oauth/credential",
    request_body = CredentialRequest,
    responses(
        (status = 200, description = "Credential issued (sd-jwt)", body = serde_json::Value),
        (status = 202, description = "Deferred - poll transaction_id at deferred_credential_endpoint", body = serde_json::Value),
        (status = 400, description = "Unknown configuration / malformed proof"),
        (status = 401, description = "Access token or proof verification failed"),
    ),
    security(),
    tag = "wallet",
)]
/// `POST /oauth/credential` - the JSON-error wrapper: OID4VCI Final
/// 7.4 - the issuance endpoint's failures render
/// `{"error": "invalid_proof|invalid_nonce|invalid_credential_request",
///  "error_description": "..."}` (the suite's
/// VCIValidateCredentialErrorResponse reads the `error` STRING).
pub async fn credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    // The §12.2.4 request-encryption form: when the body is a JWE
    // (5 dot-separated b64url segments, not a JSON object), decrypt it
    // with the issuer's ES256 recipient key (the SAME key family the
    // metadata's `credential_request_encryption.jwks` publishes) and
    // process the inner JSON request.
    let is_json = body.trim_start().starts_with('{');
    let req = if is_json {
        match serde_json::from_str::<CredentialRequest>(&body) {
            Ok(r) => r,
            Err(e) => {
                return oid4vci_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_credential_request",
                    format!("Failed to deserialize the JSON body into the target type: {e}"),
                );
            }
        }
    } else {
        let jwe = body.trim();
        let kid = sentin8::auth::jwt::decode_header(jwe)
            .ok()
            .and_then(|h| h.get("kid").and_then(|k| k.as_str()).map(str::to_string));
        let Some(pem) = state.keys.es256_private_pem(kid.as_deref()) else {
            return oid4vci_error(
                StatusCode::BAD_REQUEST,
                "invalid_credential_request",
                "no recipient key for the encrypted credential request".into(),
            );
        };
        match crate::jwe::decrypt_credential_request(jwe, &pem) {
            Err(_e) => {
                return oid4vci_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_encryption_parameters",
                    "invalid_encryption_parameters: the encrypted credential request did not decrypt".into(),
                );
            }
            Ok(plaintext) => {
                let Ok(text) = std::str::from_utf8(&plaintext) else {
                    return oid4vci_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_credential_request",
                        "the decrypted credential request is not JSON".into(),
                    );
                };
                match serde_json::from_str::<CredentialRequest>(text) {
                    Ok(r) => r,
                    Err(e) => {
                        return oid4vci_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_credential_request",
                            format!("the decrypted credential request is malformed: {e}"),
                        );
                    }
                }
            }
        }
    };
    match credential_impl(State(state), headers, req).await {
        Ok(resp) => resp,
        Err((status, msg)) => {
            // Map the message into the Final 7.4 error code family. Key
            // attestation failures ARE proof failures (the attestation is
            // part of the proof construction); the unknown-
            // configuration marker rides a leading dot-segment because
            // the code name itself contains no other marker words.
            let code = if msg.contains("invalid_nonce") {
                "invalid_nonce"
            } else if msg.starts_with("invalid_encryption_parameters") {
                // OID4VCI §12.2.4: unsupported/unusable credential
                // encryption answers its own error code (the suite's
                // VCIValidateCredentialErrorResponse).
                "invalid_encryption_parameters"
            } else if msg.starts_with(".unknown_credential_identifier") {
                "unknown_credential_identifier"
            } else if msg.starts_with(".unknown_credential_configuration") {
                "unknown_credential_configuration"
            } else if msg.contains("proof") || msg.contains("DPoP") || msg.contains("key attestation") || msg.contains("key-attestation") {
                "invalid_proof"
            } else {
                "invalid_credential_request"
            };
            oid4vci_error(status, code, msg)
        }
    }
}

/// The Final 7.4 credential-error JSON body.
fn oid4vci_error(status: StatusCode, code: &str, desc: String) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": code,
            "error_description": desc,
        })),
    )
        .into_response()
}

async fn credential_impl(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: CredentialRequest,
) -> Result<Response, (StatusCode, String)> {
    let env_id = crate::overlays::env_from_headers(&headers);

    // Access-token gate: the bearer must be a user access token carrying
    // the credential scope (standard grant families mint it; the scope
    // is the consent record - no SQL trust here). DPoP-bound tokens ride
    // the `DPoP` scheme (RFC 9449 §7.1 - the wallet's credential request
    // presents its bound proof and the same key must have minted the
    // token's cnf.jkt); plain tokens ride `Bearer`.
    let authz = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let (scheme, bearer) = authz.split_once(' ').ok_or((
        StatusCode::UNAUTHORIZED,
        "access token required".to_string(),
    ))?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "bearer" && scheme != "dpop" {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unsupported authorization scheme (bearer/dpop)".into(),
        ));
    }
    let claims = state
        .keys
        .verify(bearer)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid access token".to_string()))?;
    // The issuer compares HOST-RESOLVED (tenant domains mint their own
    // iss - the config issuer only covers the platform plane).
    if claims.iss != crate::oauth::resolve_issuer(&state.config, &headers) {
        return Err((StatusCode::UNAUTHORIZED, "token issuer mismatch".into()));
    }
    if Utc::now().timestamp() > claims.exp {
        return Err((StatusCode::UNAUTHORIZED, "token expired".into()));
    }
    if claims.token_tp != "access" {
        return Err((StatusCode::UNAUTHORIZED, "not a user access token".into()));
    }
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "token subject is not a user".to_string()))?;
    // The credential configuration is resolved BEFORE the scope check
    // (OID4VCI Final §7.2): an unknown configuration rejects with
    // `400 unknown_credential_configuration` regardless of scopes, and a
    // known one validates the token scope against THE CONFIGURATION'S
    // advertised scope (the scope is the config's `scope` value, not the
    // raw configuration id). The §7.2.1 credential-identifier form omits
    // the id entirely - the token is pre-bound to a configuration by its
    // scope; an identifier/scoped form that matches NO configuration is
    // `400 unknown_credential_identifier`.
    let known_configs = supported_credential_configurations("");
    if let Some(identifier) = req.credential_identifier.as_ref() {
        // The §7.2.1 identifier form: the identifier MUST reference a
        // credential the issuer previously issued/granted (its
        // credentials row id, the deferred-transaction form). Anything
        // the issuer never handed out is
        // `400 unknown_credential_identifier`.
        let Ok(id) = Uuid::parse_str(identifier) else {
            return Err((
                StatusCode::BAD_REQUEST,
                ".unknown_credential_identifier".to_string(),
            ));
        };
        // RLS: the read runs in a transaction with the tenant context set
        // on the SAME connection (the bare-pool SELECT violates the row
        // policy).
        let mut rtx = state
            .pool
            .begin()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(&env_id)
            .execute(&mut *rtx)
            .await;
        let exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM credentials WHERE id = $1 AND env_id = $2 AND user_id = $3",
        )
        .bind(id)
        .bind(&env_id)
        .bind(&user_id)
        .fetch_one(&mut *rtx)
        .await
        .unwrap_or(0);
        drop(rtx);
        if exists == 0 {
            return Err((
                StatusCode::BAD_REQUEST,
                ".unknown_credential_identifier".to_string(),
            ));
        }
    }
    let config_id = if let Some(id) = req.credential_configuration_id.as_ref() {
        id.clone()
    } else {
        let token_config = claims
            .scope
            .split_whitespace()
            .filter_map(|s| s.strip_prefix("credential:"))
            .find(|s| known_configs.get(*s).is_some());
        let Some(id) = token_config else {
            return Err((
                StatusCode::BAD_REQUEST,
                ".unknown_credential_identifier".to_string(),
            ));
        };
        id.to_string()
    };
    let Some(config) = known_configs.as_object().and_then(|m| m.get(&config_id)) else {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(".unknown_credential_configuration: {config_id}"),
        ));
    };
    let config_scope = config
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let scope_ok = claims.scope.split_whitespace().any(|s| s == config_scope);
    if !scope_ok {
        return Err((
            StatusCode::FORBIDDEN,
            format!("access token lacks scope {config_scope}"),
        ));
    }

    // Proof verification (OID4VCI Final §7.2). The wallet's
    // `openid4vci-proof+jwt` carries its key in the JWS HEADER
    // (`jwk` member); the claims bind iss/aud/iat. The signature
    // verifies against the header JWK itself (the self-contained
    // proof form); aud = the credential issuer; iat fresh. The
    // draft-11 payload-cnf form stays accepted (a proof either
    // carries the key in the header or binds it in the payload).
    let proof_jwts: Vec<String> = if let Some(proofs) = req.proofs.as_ref() {
        let Some(jwts) = proofs.get("jwt") else {
            return Err((
                StatusCode::BAD_REQUEST,
                "only jwt proofs are supported (the proofs map key names the type)"
                    .into(),
            ));
        };
        if jwts.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "proofs.jwt must be non-empty".into()));
        }
        jwts.clone()
    } else if let Some(proof) = req.proof.as_ref() {
        if proof.proof_type != "jwt" {
            return Err((StatusCode::BAD_REQUEST, "only jwt proofs are supported".into()));
        }
        vec![proof.jwt.clone()]
    } else {
        // No proof - fail closed: the issuance MUST be key-bound
        // (sender-constrained credentials are the platform invariant).
        return Err((
            StatusCode::BAD_REQUEST,
            "proof is required (credential issuance is key-bound)".into(),
        ));
    };
    // Batch issuance (Final §7.3): N proofs → N credentials, EVERY proof
    // verified against its own key binding.
    let mut credentials_out: Vec<serde_json::Value> = Vec::new();
    // The minted `vct` is the CONFIG's designator when the configuration
    // carries one (the OIDF wallet-catalog EUDI entries use
    // `urn:eudi:pid:1`); otherwise the configuration id IS the vct.
    let cred_type: String = config
        .get("vct")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| config_id.to_string());
    verify_credential_dpop(&state, &headers, bearer).await?;
    let mut shared_status: Option<Uuid> = None;
    let mut used_idx: Vec<u32> = Vec::new();
    for (idx, proof_jwt) in proof_jwts.iter().enumerate() {
        let member_idx: u32 = {
            // A RANDOM distinct idx within the 16-entry list - the batch's
            // members must not walk the list in an arithmetic stride (the
            // suite's index-predictability check).
            let cap = 16u32;
            let candidate = if idx == 0 {
                rand::random::<u32>() % cap
            } else {
                loop {
                    let c = rand::random::<u32>() % cap;
                    if !used_idx.contains(&c) {
                        break c;
                    }
                }
            };
            used_idx.push(candidate);
            candidate
        };
        let cnf_jwk = verify_credential_proof(&state, &headers, proof_jwt, idx == 0, bearer).await?;

        // Record the issuance (pending until mint below flips it). RLS:
        // the write runs in ONE transaction with the tenant context set
        // on the SAME connection (the bare-pool INSERT violates the row
        // policy - caught by the suite's happy-flow cell).
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(&env_id)
            .execute(&mut *tx)
            .await;
        let id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO credentials (env_id, user_id, type, cnf_jwk, credential_data)
               VALUES ($1, $2, $3, $4, $5)
               RETURNING id"#,
        )
        .bind(&env_id)
        .bind(user_id)
        .bind(&cred_type)
        .bind(&cnf_jwk)
        .bind(serde_json::json!({
            // Batch herd privacy (RFC 9901 + the suite's batch checks):
            // the batch shares ONE status list - the FIRST minted record
            // is the group owner; members reference it with a RANDOM
            // distinct idx (an arithmetic idx stride also links the
            // batch's members - the suite's stride check).
            "requested_claims": [],
            "status_group": shared_status
                .map(|u| u.to_string())
                .unwrap_or_default(),
            "status_idx": member_idx,
        }))
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("credential record: {e}")))?;
        let _ = tx.commit().await;

        // HAIP x5c chain from the env profile (issuance leaf + chain).
        let issuance_chain = crate::wallet::pem_profile_to_x5c(
            &crate::oauth::resolve_security_profile(&state.pool, &headers, "env")
                .await,
        );
        match mint_credential(
            &state,
            &headers,
            id,
            env_id,
            user_id,
            &cred_type,
            &cnf_jwk,
            shared_status,
            member_idx,
            issuance_chain.as_deref(),
        )
        .await
        {
            Ok(credential) => {
                if shared_status.is_none() {
                    shared_status = Some(id);
                }
                // Mark active (issued) - same RLS pattern (context +
                // write on one transaction).
                let mut tx2 = state
                    .pool
                    .begin()
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                    .bind(&env_id)
                    .execute(&mut *tx2)
                    .await;
                let _ = sqlx::query("UPDATE credentials SET status = 'active' WHERE id = $1")
                    .bind(id)
                    .execute(&mut *tx2)
                    .await;
                let _ = tx2.commit().await;

                credentials_out.push(serde_json::json!({
                    // Final §7.3 response object: the format +
                    // credential pair per entry.
                    "format": "dc+sd-jwt",
                    "credential": credential,
                }));
            }
            Err(e) => return Err(e),
        }
    }

    // Final §7.4 - the response carries EVERY credential minted in one
    // entry per proof. When the wallet requested credential-response
    // encryption (§12.2.4), the credentials object rides as a COMPACT
    // JWE (ECDH-ES + A256GCM) over the wallet's key - the response body
    // is the JWE text itself (VCIEnsureCredentialResponseIsEncryptedJwe).
    // Unsupported alg/enc values answer `400 invalid_credential_request`
    // BEFORE minting (FailOnUnsupportedEncryptionAlgorithm).
    if let Some(enc_obj) = &req.credential_response_encryption {
        let enc: crate::jwe::ResponseEncryption = serde_json::from_value(enc_obj.clone())
            .map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    "invalid_credential_request: credential_response_encryption is malformed".into(),
                )
            })?;
        // Validate alg/enc BEFORE any credential mint - the §12.2.4
        // error code for an unsupported/unusable encryption request is
        // `invalid_encryption_parameters` (the suite's
        // FailOnUnsupportedEncryptionAlgorithm +
        // VCIValidateCredentialErrorResponse expect it).
        enc.validate().map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid_encryption_parameters: {e:?}"),
            )
        })?;
        let payload = serde_json::json!({ "credentials": credentials_out });
        let jwe = crate::jwe::encrypt_credential_response(
            payload.to_string().as_bytes(),
            &enc,
        )
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid_credential_request: {e:?}"),
            )
        })?;
        return Ok({
            let mut resp = jwe.into_response();
            // axum renders a bare `String` body as text/plain; the §13.3
            // credential-response CT contract is `application/jwt` - set
            // (not append) it explicitly.
            resp.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/jwt"),
            );
            resp
        });
    }
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "credentials": credentials_out })),
    )
        .into_response())
}

/// `POST /oauth/deferred_credential` - poll a deferred transaction
/// (OID4VCI §8.2, DESIGN §9a.7). Transactions mint on the same store;
/// a `pending` record answers the prescribed `error: issuance_pending`.
#[utoipa::path(
    post,
    path = "/oauth/deferred_credential",
    request_body = DeferredCredentialRequest,
    responses(
        (status = 200, description = "Credential issued (sd-jwt)", body = serde_json::Value),
        (status = 400, description = "Unknown transaction"),
    ),
    security(),
    tag = "wallet",
)]
pub async fn deferred_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeferredCredentialRequest>,
) -> Result<Response, (StatusCode, String)> {
    let env_id = crate::overlays::env_from_headers(&headers);
    let id = Uuid::parse_str(&req.transaction_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid transaction_id".into()))?;
    let row = sqlx::query(
        "SELECT user_id, type, status, cnf_jwk FROM credentials WHERE id = $1 AND env_id = $2",
    )
    .bind(id)
    .bind(env_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::BAD_REQUEST, "unknown transaction_id".into()))?;

    use sqlx::Row as _;
    let user_id: Uuid = row
        .try_get("user_id")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let cred_type: String = row
        .try_get("type")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let status: String = row
        .try_get("status")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let cnf: Option<serde_json::Value> = row.try_get("cnf_jwk").ok().flatten();
    let Some(cnf) = cnf else {
        return Err((StatusCode::BAD_REQUEST, "transaction carries no wallet key".into()));
    };

    if status == "pending" {
        return Ok((
            StatusCode::OK,
            Json(serde_json::json!({ "error": "issuance_pending" })),
        )
            .into_response());
    }
    if status == "revoked" {
        return Err((StatusCode::CONFLICT, "transaction revoked".into()));
    }
    let issuance_chain = crate::wallet::pem_profile_to_x5c(
        &crate::oauth::resolve_security_profile(&state.pool, &headers, "env").await,
    );
    let credential =
        mint_credential(&state, &headers, id, env_id, user_id, &cred_type, &cnf,
 None, 0, issuance_chain.as_deref()).await?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "credentials": [{
                "format": "dc+sd-jwt",
                "credential": credential,
            }],
        })),
    )
        .into_response())
}

/// `POST /oauth/notifications` - wallet event recording (OID4VCI §11.1).
/// The event lands in the credential row's `credential_data.notifications`
/// array; failures never cascade (best-effort acknowledgment).
#[utoipa::path(
    post,
    path = "/oauth/notifications",
    request_body = NotificationRequest,
    responses(
        (status = 200, description = "Event acknowledged"),
        (status = 400, description = "Unknown event type"),
    ),
    security(),
    tag = "wallet",
)]
pub async fn notifications(
    State(state): State<AppState>,
    Json(req): Json<NotificationRequest>,
) -> Result<Response, (StatusCode, String)> {
    match req.event.as_str() {
        "credential_received" | "credential_failed" => {}
        other => {
            return Err((StatusCode::BAD_REQUEST, format!("unsupported event: {other}")));
        }
    }
    if let Some(tx) = req.transaction_id {
        let _ = sqlx::query(
            r#"UPDATE credentials
                  SET credential_data =
                      jsonb_set(COALESCE(credential_data, '{}'::jsonb),
                                '{notifications}',
                                COALESCE(credential_data->'notifications','[]'::jsonb)
                                || $2::jsonb)
                WHERE id = $1"#,
        )
        .bind(tx)
        .bind(serde_json::json!([{ "event": req.event, "event_id": req.event_id, "at": Utc::now().timestamp() }]))
        .execute(&state.pool)
        .await;
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed P-256 leaf built the same way the issuer-built
    /// attestation chains are (SPKI EC P-256); the x5c leaf must round-trip
    /// to the same standard EC JWK the raw point encodes.
    #[test]
    fn x5c_leaf_jwk_round_trips_to_standard_ec_jwk() {
        use base64::Engine as _;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let key = p256::SecretKey::random(&mut rand::thread_rng());
        let cert_der = leaf_spki_der_for_test(&key);
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "key-attestation+jwt",
            "x5c": [base64::engine::general_purpose::STANDARD.encode(&cert_der)],
        });
        let jwk = key_attestation_x5c_leaf_jwk(&header)
            .expect("x5c leaf parses")
            .expect("x5c present");
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        // The extracted JWK coordinates match the leaf key's raw point.
        let point = key.public_key().to_encoded_point(false);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&point.as_bytes()[1..33]);
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&point.as_bytes()[33..65]);
        assert_eq!(jwk["x"], x);
        assert_eq!(jwk["y"], y);
    }

    /// Minimal CERTIFICATE-shaped DER for the walker: a tbsCertificate
    /// carrying the version wrapper + the five scalar fields + SPKI,
    /// wrapped twice (tbs, certificate). The SPKI is the real PKIX SPKI
    /// of the key, so the walker's 7th-element extraction must land on it.
    fn leaf_spki_der_for_test(key: &p256::SecretKey) -> Vec<u8> {
        use p256::pkcs8::EncodePublicKey as _;
        let spki_doc = key.public_key().to_public_key_der().expect("spki doc");
        let spki = spki_doc.as_bytes();

        let tlv = |tag: u8, content: &[u8]| -> Vec<u8> {
            let mut out = vec![tag];
            let len = content.len();
            if len < 128 {
                out.push(len as u8);
            } else if len < 256 {
                out.push(0x81);
                out.push(len as u8);
            } else {
                out.push(0x82);
                out.push((len >> 8) as u8);
                out.push(len as u8);
            }
            out.extend_from_slice(content);
            out
        };

        let version = tlv(0xa0, &[0x02, 0x01, 0x00]); // [0] INTEGER v3
        let serial = tlv(0x02, &[0x01]); // INTEGER 1
        let sig_alg = tlv(0x30, &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
        let name = tlv(0x30, &[]); // empty RDN sequence
        let validity = tlv(0x30, &[]);
        let tbs_content = [version, serial, sig_alg, name.clone(), validity, name, spki.to_vec()].concat();
        let tbs = tlv(0x30, &tbs_content);
        tlv(0x30, &tbs)
    }
}