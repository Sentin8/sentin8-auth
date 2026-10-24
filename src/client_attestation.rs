// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Attestation-based client authentication
//! (draft-ietf-oauth-attestation-based-client-auth; DESIGN §9a.19).
//!
//! The client authenticates with a two-JWT header pair on the
//! token/PAR/introspect/revoke family:
//!
//! - `OAuth-Client-Attestation` - `typ oauth-client-attestation+jwt`,
//!   an `x5c` header chain; claims `iss` (the attester's trust domain),
//!   `sub` (the client_id being authenticated), `iat`/`nbf`/`exp`,
//!   `cnf.jwk` (the client's PROOF key).
//! - `OAuth-Client-Attestation-PoP` - `typ
//!   oauth-client-attestation-pop+jwt`; claims `iss` (the client's
//!   instance key), `aud` (the issuer), `iat`, `jti` (single-use), and
//!   `challenge` when an `attestation_challenge_endpoint` is advertised
//!   (auth does not advertise one - the challenge check self-skips).
//!
//! Trust model: the attestation's signature verifies against the x5c
//! LEAF certificate's SubjectPublicKeyInfo (the draft's self-contained
//! verify path); when the resolved security profile carries
//! `client_attestation_trust_anchor_pem`, the leaf (or a chain entry)
//! must equal the anchor's SPKI. The expected `iss` comes from the same
//! profile. The PoP's signature verifies against the ATTESTED key
//! (`cnf.jwk`) - possession of exactly the key the attestation binds.

use base64::Engine as _;
use chrono::Utc;
use p256::pkcs8::DecodePublicKey;

/// The two header names the draft carries the pair on.
pub const HEADER_ATTESTATION: &str = "OAuth-Client-Attestation";
/// The PoP header name (draft: `OAuth-Client-Attstation-Pop` naming -
/// the draft's exact `OAuth-Client-Attestation-PoP` spelling).
pub const HEADER_ATTESTATION_POP: &str = "OAuth-Client-Attestation-PoP";
/// The advertised client-auth method name.
pub const AUTH_METHOD: &str = "attest_jwt_client_auth";

/// Error surface: the authenticator maps every failure to the uniform
/// `401 invalid_client` (DESIGN §8) - this enum only carries the reason
/// for the trace log.
#[derive(Debug)]
pub enum AttestationRejection {
    /// The attestation header is absent.
    MissingAttestation,
    /// The PoP header is absent.
    MissingPop,
    /// typ mismatch on either JWT.
    BadTyp,
    /// x5c chain verification failed.
    ChainVerify,
    /// The x5c leaf does not parse.
    LeafParse,
    /// attestation `iss` != the profile's expected issuer.
    IssMismatch,
    /// attestation `sub` != the authenticated client_id.
    SubMismatch,
    /// attestation exp in the past.
    Expired,
    /// attestation iat outside the ±24h window.
    TimeWindow,
    /// attestation `cnf.jwk` missing.
    CnfMissing,
    /// PoP signature invalid (or its typ is wrong).
    PopSignature,
    /// PoP `aud` != the issuer.
    PopAudMismatch,
    /// PoP `jti` missing or replayed.
    PopReplay,
    /// PoP iat outside the ±60s window.
    PopTimeWindow,
}

impl AttestationRejection {
    /// Trace-log label (never sent on the wire - the authenticator
    /// answers uniformly).
    pub fn label(&self) -> &'static str {
        match self {
            AttestationRejection::MissingAttestation => "attestation header missing",
            AttestationRejection::MissingPop => "pop header missing",
            AttestationRejection::BadTyp => "typ mismatch",
            AttestationRejection::ChainVerify => "x5c chain verification failed",
            AttestationRejection::LeafParse => "x5c leaf parse failure",
            AttestationRejection::IssMismatch => "attestation iss mismatch",
            AttestationRejection::SubMismatch => "attestation sub mismatch",
            AttestationRejection::Expired => "attestation expired",
            AttestationRejection::TimeWindow => "attestation timestamps outside the window",
            AttestationRejection::CnfMissing => "attestation cnf.jwk missing",
            AttestationRejection::PopSignature => "pop signature invalid",
            AttestationRejection::PopAudMismatch => "pop aud mismatch",
            AttestationRejection::PopReplay => "pop jti replayed",
            AttestationRejection::PopTimeWindow => "pop timestamps outside the window",
        }
    }
}

/// Extract the DER SubjectPublicKeyInfo of an X.509 certificate (RFC
/// 5280 §4.1): a minimal TLV walk - the SPKI is the 7th element of
/// tbsCertificate when the [0] version wrapper is present (context
/// class), else the 6th. The full TLV span is returned so
/// `from_public_key_der` sees tag+length+content.
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
            return Err(format!(
                "DER truncated: need {len}, have {}",
                buf.len() - hdr
            ));
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
            let full_len = cur.len() - rest.len();
            return Ok(cur[..full_len].to_vec());
        }
        cur = rest;
        if cur.is_empty() {
            return Err("tbsCertificate ended before subjectPublicKeyInfo".into());
        }
    }
}

/// The P-256 public JWK of an EC SPKI (standard x/y form).
fn ec_jwk_from_spki(spki: &[u8]) -> Result<serde_json::Value, String> {
    let vk = p256::ecdsa::VerifyingKey::from_public_key_der(spki)
        .map_err(|e| format!("SPKI parse: {e}"))?;
    let point = vk.to_encoded_point(false);
    let (x_raw, y_raw) = match (point.x(), point.y()) {
        (Some(x), Some(y)) => (x, y),
        _ => return Err("SPKI coordinates missing".into()),
    };
    Ok(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x_raw),
        "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y_raw),
    }))
}

/// PEM body → DER (strip the BEGIN/END armor, standard base64).
pub fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body.trim().as_bytes())
        .ok()
}

/// Verify an attestation JWT: typ, claims (iss/sub/iat/exp), the x5c
/// chain (optional trust-anchor pin against the profile's anchor PEM),
/// and the signature against the x5c leaf key. Returns the ATTESTED key
/// (`cnf.jwk`) for the PoP verification.
///
/// # Errors
/// `AttestationRejection` for every failure surface (mapped to uniform
/// `401 invalid_client` by the authenticator).
pub fn verify_attestation(
    attestation: &str,
    client_id: &str,
    expected_iss: &str,
    trust_anchor_pem: &str,
) -> Result<serde_json::Value, AttestationRejection> {
    let header = sentin8::auth::jwt::decode_header(attestation)
        .map_err(|_| AttestationRejection::BadTyp)?;
    let payload = sentin8::auth::jwt::decode_payload(attestation)
        .map_err(|_| AttestationRejection::BadTyp)?;
    let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
    if typ != "oauth-client-attestation+jwt" {
        return Err(AttestationRejection::BadTyp);
    }
    let iss = payload.get("iss").and_then(|v| v.as_str()).unwrap_or("");
    if expected_iss.is_empty() || iss != expected_iss {
        return Err(AttestationRejection::IssMismatch);
    }
    let sub = payload.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    if sub != client_id {
        return Err(AttestationRejection::SubMismatch);
    }
    // Freshness: exp REQUIRED and in the future; iat within ±24h (the
    // attestation is a profile document - per-request freshness rides
    // the PoP).
    let now = Utc::now().timestamp();
    let exp = payload
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or(AttestationRejection::Expired)?;
    if exp <= now {
        return Err(AttestationRejection::Expired);
    }
    if let Some(iat) = payload.get("iat").and_then(|v| v.as_i64()) {
        if (iat - now).abs() > 86_400 {
            return Err(AttestationRejection::TimeWindow);
        }
    }
    let cnf = payload
        .pointer("/cnf/jwk")
        .cloned()
        .ok_or(AttestationRejection::CnfMissing)?;

    // x5c chain → leaf key → signature verify.
    let chain = header
        .get("x5c")
        .and_then(|v| v.as_array())
        .ok_or(AttestationRejection::ChainVerify)?;
    let Some(leaf_b64) = chain.first().and_then(|v| v.as_str()) else {
        return Err(AttestationRejection::ChainVerify);
    };
    let leaf_der = base64::engine::general_purpose::STANDARD
        .decode(leaf_b64)
        .map_err(|_| AttestationRejection::LeafParse)?;
    let leaf_spki = x509_leaf_spki(&leaf_der).map_err(|_| AttestationRejection::LeafParse)?;
    let leaf_jwk = ec_jwk_from_spki(&leaf_spki).map_err(|_| AttestationRejection::LeafParse)?;
    crate::jwks::SigningKeys::verify_with_jwk(&leaf_jwk, attestation)
        .map_err(|_| AttestationRejection::ChainVerify)?;

    // Trust-anchor pin: when the profile carries an anchor PEM, one of
    // the chain's SPKIs (leaf or issuer cert) must equal the anchor's.
    if !trust_anchor_pem.trim().is_empty() {
        let anchor_der =
            pem_to_der(trust_anchor_pem).ok_or(AttestationRejection::ChainVerify)?;
        let anchor_spki =
            x509_leaf_spki(&anchor_der).map_err(|_| AttestationRejection::ChainVerify)?;
        let chain_match = chain.iter().any(|c| {
            c.as_str()
                .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
                .and_then(|der| x509_leaf_spki(&der).ok())
                .map(|spki| spki == anchor_spki)
                .unwrap_or(false)
        });
        if !chain_match {
            return Err(AttestationRejection::ChainVerify);
        }
    }
    Ok(cnf)
}

/// Verify the PoP JWT: typ, `aud` (the issuer), `jti` presence (the
/// auth service adds the single-use replay check), iat window, and the
/// signature against the ATTESTED key (`cnf.jwk`).
///
/// # Errors
/// `AttestationRejection` for every failure surface.
pub fn verify_pop(
    pop: &str,
    attested_key: &serde_json::Value,
    expected_aud: &str,
) -> Result<String, AttestationRejection> {
    let header = sentin8::auth::jwt::decode_header(pop)
        .map_err(|_| AttestationRejection::PopSignature)?;
    let payload = sentin8::auth::jwt::decode_payload(pop)
        .map_err(|_| AttestationRejection::PopSignature)?;
    let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
    if typ != "oauth-client-attestation-pop+jwt" {
        return Err(AttestationRejection::BadTyp);
    }
    let aud = payload.get("aud").and_then(|v| v.as_str()).unwrap_or("");
    if aud != expected_aud {
        return Err(AttestationRejection::PopAudMismatch);
    }
    let jti = payload
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or(AttestationRejection::PopReplay)?
        .to_string();
    // Freshness ±60s (per-request proof window; exp fallback when iat
    // is absent).
    let now = Utc::now().timestamp();
    if let Some(iat) = payload.get("iat").and_then(|v| v.as_i64()) {
        if (iat - now).abs() > 60 {
            return Err(AttestationRejection::PopTimeWindow);
        }
    } else if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
        if exp <= now.saturating_sub(60) {
            return Err(AttestationRejection::PopTimeWindow);
        }
    }
    crate::jwks::SigningKeys::verify_with_jwk(attested_key, pop)
        .map_err(|_| AttestationRejection::PopSignature)?;
    Ok(jti)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64u(b: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    }

    fn wrap64(s: &str) -> String {
        s.as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Self-issue a P-256 ES256 attester leaf with rcgen from the SAME
    /// p256 key (PKCS#8 round-trip) so the x5c leaf IS the signer.
    fn leaf_from_key(key: &p256::ecdsa::SigningKey) -> Vec<u8> {
        use p256::elliptic_curve::pkcs8::EncodePrivateKey as _;
        use rcgen::KeyPair;
        let secret = p256::SecretKey::from_bytes(&key.to_bytes()).expect("secret");
        let pkcs8 = secret
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("pkcs8 pem");
        let kp = KeyPair::from_pem(pkcs8.as_str()).expect("keypair");
        let mut params = rcgen::CertificateParams::new(vec![]).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "attester.test");
        let cert = params.self_signed(&kp).expect("self-signed");
        cert.der().to_vec()
    }

    /// An unrelated valid leaf (different key) for negative tests.
    fn other_leaf() -> Vec<u8> {
        let kp = rcgen::KeyPair::generate().expect("kp");
        let mut params = rcgen::CertificateParams::new(vec![]).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "other.test");
        params.self_signed(&kp).expect("cert").der().to_vec()
    }

    fn pem(der: &[u8]) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            wrap64(&base64::engine::general_purpose::STANDARD.encode(der))
        )
    }

    /// A REAL self-signed attester leaf + an ES-signed attestation
    /// binding a second key as cnf.jwk: the full verify path
    /// round-trips, the trust-anchor pin accepts the SAME leaf PEM, a
    /// foreign anchor is rejected, the PoP verifies against the
    /// ATTESTED key, and signatures with a foreign key are rejected.
    #[test]
    fn attestation_round_trip_anchor_pin_and_pop_binding() {
        use p256::ecdsa::signature::Signer;
        use rand::RngCore;

        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let attester = p256::ecdsa::SigningKey::from_slice(&seed).expect("attester key");
        let mut seed2 = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed2);
        let client_proof_key =
            p256::ecdsa::SigningKey::from_slice(&seed2).expect("proof key");

        let cert_der = leaf_from_key(&attester);

        let now = Utc::now().timestamp();
        let proof_point = client_proof_key.verifying_key().to_encoded_point(false);
        let proof_jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": b64u(&proof_point.as_ref()[1..33]),
            "y": b64u(&proof_point.as_ref()[33..65]),
        });
        let header = serde_json::json!({
            "typ": "oauth-client-attestation+jwt",
            "alg": "ES256",
            "x5c": [base64::engine::general_purpose::STANDARD.encode(&cert_der)],
        });
        let claims = serde_json::json!({
            "iss": "https://attester.invalid",
            "sub": "c-1",
            "iat": now,
            "exp": now + 3600,
            "cnf": {"jwk": proof_jwk},
        });
        let signing_input = format!(
            "{}.{}",
            b64u(header.to_string().as_bytes()),
            b64u(claims.to_string().as_bytes())
        );
        let sig: p256::ecdsa::Signature = attester.sign(signing_input.as_bytes());
        let attestation = format!("{}.{}", signing_input, b64u(&sig.to_bytes()));

        // Round-trip WITHOUT an anchor (empty profile anchor).
        let attested =
            verify_attestation(&attestation, "c-1", "https://attester.invalid", "")
                .expect("attestation verifies");
        assert_eq!(attested["kty"], "EC");

        // Anchor pin: the SAME leaf's PEM is accepted; a foreign anchor
        // is rejected.
        verify_attestation(
            &attestation,
            "c-1",
            "https://attester.invalid",
            &pem(&cert_der),
        )
        .expect("anchor pin accepts the leaf");
        assert!(
            verify_attestation(
                &attestation,
                "c-1",
                "https://attester.invalid",
                &pem(&other_leaf()),
            )
            .is_err()
        );

        // PoP: correct key verifies; a foreign key fails.
        let pop_header = serde_json::json!({
            "typ": "oauth-client-attestation-pop+jwt",
            "alg": "ES256",
        });
        let pop_claims = serde_json::json!({
            "iss": "k-1",
            "aud": "https://issuer.invalid",
            "iat": now,
            "jti": "j-1",
        });
        let pop_input = format!(
            "{}.{}",
            b64u(pop_header.to_string().as_bytes()),
            b64u(pop_claims.to_string().as_bytes())
        );
        let pop_sig: p256::ecdsa::Signature =
            client_proof_key.sign(pop_input.as_bytes());
        let pop = format!("{}.{}", pop_input, b64u(&pop_sig.to_bytes()));
        let jti = verify_pop(&pop, &attested, "https://issuer.invalid")
            .expect("pop verifies with the attested key");
        assert_eq!(jti, "j-1");
        let foreign = other_leaf();
        let foreign_spki = x509_leaf_spki(&foreign).expect("foreign spki");
        let foreign_jwk = ec_jwk_from_spki(&foreign_spki).expect("foreign jwk");
        assert!(verify_pop(&pop, &foreign_jwk, "https://issuer.invalid").is_err());
    }

    /// Malformed inputs fail closed: wrong typ, expired attestation,
    /// sub mismatch, missing cnf.
    #[test]
    fn attestation_negative_surfaces() {
        use p256::ecdsa::signature::Signer;
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let attester = p256::ecdsa::SigningKey::from_slice(&seed).expect("key");
        let cert_der = leaf_from_key(&attester);
        let now = Utc::now().timestamp();
        let cnf = serde_json::json!({
            "cnf": {"jwk": {"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}}
        });
        let b64u = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let sign = |hdr: serde_json::Value, claims: serde_json::Value| {
            let input = format!(
                "{}.{}",
                b64u(hdr.to_string().as_bytes()),
                b64u(claims.to_string().as_bytes())
            );
            let sig: p256::ecdsa::Signature = attester.sign(input.as_bytes());
            format!("{}.{}", input, b64u(&sig.to_bytes()))
        };
        let hdr = serde_json::json!({
            "typ": "oauth-client-attestation+jwt",
            "alg": "ES256",
            "x5c": [base64::engine::general_purpose::STANDARD.encode(&cert_der)],
        });
        // wrong typ
        let bad_typ = sign(
            serde_json::json!({"typ": "other+jwt", "alg": "ES256"}),
            serde_json::json!({}),
        );
        assert!(matches!(
            verify_attestation(&bad_typ, "c-1", "iss", ""),
            Err(AttestationRejection::BadTyp)
        ));
        // sub mismatch
        let sub = sign(hdr.clone(), serde_json::json!({
            "iss": "iss", "sub": "other-client", "iat": now,
            "exp": now + 600, "cnf": cnf["cnf"].clone()
        }));
        assert!(matches!(
            verify_attestation(&sub, "c-1", "iss", ""),
            Err(AttestationRejection::SubMismatch)
        ));
        // expired
        let expired = sign(hdr.clone(), serde_json::json!({
            "iss": "iss", "sub": "c-1", "iat": now - 7200,
            "exp": now - 3600, "cnf": cnf["cnf"].clone()
        }));
        assert!(matches!(
            verify_attestation(&expired, "c-1", "iss", ""),
            Err(AttestationRejection::Expired)
        ));
        // missing cnf
        let no_cnf = sign(
            hdr,
            serde_json::json!({"iss": "iss", "sub": "c-1", "iat": now, "exp": now + 600}),
        );
        assert!(matches!(
            verify_attestation(&no_cnf, "c-1", "iss", ""),
            Err(AttestationRejection::CnfMissing)
        ));
    }
}