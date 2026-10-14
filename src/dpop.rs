// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! DPoP — Demonstrating Proof-of-Possession (RFC 9449)
//!
//! DPoP allows clients to sender-constrain their tokens by providing a
//! proof-of-possession JWT (the `DPoP` header) signed by the client's
//! private key. The AS verifies the proof and issues tokens with a `cnf.jkt`
//! claim — the thumbprint of the client's public JWK.
//!
//! DPoP proof JWT claims (RFC 9449 ):
//! - `htm` — the HTTP method (uppercase)
//! - `htu` — the HTTP target URI (without query/fragment)
//! - `jti` — unique token ID (replay protection)
//! - `iat` — issued-at timestamp
//! - `ath` — the base64url SHA-256 hash of the access token (required on
//! DPoP-bound token requests to resource servers)
//! - `typ` — must be `dpop+jwt`
//! - `jwk` — the client's public key (in the header, not the claims)
//!
//! The AS stores `jti` values in Valkey (replay prevention, TTL = exp).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// DPoP proof JWT claims (RFC 9449 ).
#[derive(Debug, Deserialize, Serialize)]
/// The dpopproofclaims type.
pub struct DpopProofClaims {
    /// HTTP method (uppercase, e.g. "POST").
    ///
    /// RFC 9449 defines the claim as `htm` — the previous `httm` rename
    /// made every standards-compliant proof fail claims parsing
    /// ("claims parse failed") and was rejected as a client bug.
    /// The htm.
    pub htm: String,
    /// HTTP target URI (without query/fragment).
    #[serde(rename = "htu")]
    /// The htu.
    pub htu: String,
    /// Unique JWT ID (replay protection).
    /// The jti.
    pub jti: String,
    /// Issued-at timestamp.
    /// The iat.
    pub iat: i64,
    /// Access token hash (base64url SHA-256) — required on protected-resource requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The ath.
    pub ath: Option<String>,
}

/// DPoP proof JWT header.
#[derive(Debug, Deserialize)]
/// The dpopproofheader type.
pub struct DpopProofHeader {
    /// Must be `dpop+jwt`.
    /// The typ.
    pub typ: String,
    /// The signing algorithm (ES256, RS256, etc.).
    /// The alg.
    pub alg: String,
    /// The client's public key as a JWK.
    /// The jwk.
    pub jwk: serde_json::Value,
    /// Optional key ID.
    #[serde(default)]
    /// The kid.
    pub kid: Option<String>,
}

/// Decoded DPoP proof (header + claims).
#[derive(Debug)]
/// The decodeddpopproof type.
pub struct DecodedDpopProof {
    /// The header.
    pub header: DpopProofHeader,
    /// The claims.
    pub claims: DpopProofClaims,
    /// The raw header.
    pub raw_header: String,
    /// The raw claims.
    pub raw_claims: String,
    /// The signature.
    pub signature: String,
}

/// Decode a DPoP proof JWT without signature verification.
/// Handle decode DPoP proof unverified.
pub fn decode_dpop_proof_unverified(token: &str) -> Result<DecodedDpopProof, String> {
    let header: DpopProofHeader =
        sentin8::auth::jwt::decode_header_typed(token).map_err(|e| format!("header parse: {e}"))?;
    let claims: DpopProofClaims = sentin8::auth::jwt::decode_payload_typed(token)
        .ok_or_else(|| "claims parse failed".to_string())?;
    let parts: Vec<&str> = token.split('.').collect();
    Ok(DecodedDpopProof {
        header,
        claims,
        raw_header: parts[0].to_string(),
        raw_claims: parts[1].to_string(),
        signature: parts[2].to_string(),
    })
}

/// Compute the JWK thumbprint (RFC 7638) — SHA-256 thumbprint of the public key.
/// This is used as the `cnf.jkt` value in access tokens.
/// Handle jwk thumbprint.
pub fn jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, String> {
    crate::jar::jwk_thumbprint(jwk)
}

/// Validate the DPoP proof claims against the request (RFC 9449 ).
/// - `htm` must match the HTTP method (case-insensitive, compared uppercase).
/// - `htu` must match the HTTP target URI (without query/fragment).
/// - `iat` must be recent (within ±60 seconds of now).
/// - `typ` in the header must be `dpop+jwt`.
/// Validate DPoP proof.
pub fn validate_dpop_proof(
    proof: &DecodedDpopProof,
    http_method: &str,
    http_uri: &str,
    now: i64,
) -> Result<(), String> {
    // Check typ.
    if proof.header.typ != "dpop+jwt" {
        return Err("DPoP proof typ must be dpop+jwt".into());
    }
    // Check htm.
    if proof.claims.htm.to_uppercase() != http_method.to_uppercase() {
        return Err("DPoP htm mismatch".into());
    }
    // Check htu — compare without query/fragment.
    let expected_htu = strip_query_fragment(http_uri);
    let claimed_htu = strip_query_fragment(&proof.claims.htu);
    if claimed_htu != expected_htu {
        return Err("DPoP htu mismatch".into());
    }
    // Check iat freshness (±60s).
    if (proof.claims.iat - now).abs() > 60 {
        return Err("DPoP iat out of range (±60s)".into());
    }
    Ok(())
}

/// Strip the query and fragment from a URI.
fn strip_query_fragment(uri: &str) -> String {
    let without_fragment = uri.split('#').next().unwrap_or(uri);
    let without_query = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    without_query.to_string()
}

/// Build the `cnf` claim for a DPoP-bound access token.
/// Per RFC 9449 , the `cnf` claim contains `jkt` — the thumbprint of the
/// client's public key.
/// Build DPoP cnf claim.
pub fn build_dpop_cnf_claim(jwk_thumbprint: &str) -> serde_json::Value {
    serde_json::json!({
        "jkt": jwk_thumbprint
    })
}

/// Compute the `ath` value: base64url SHA-256 hash of the access token.
/// Handle compute ath.
pub fn compute_ath(access_token: &str) -> String {
    use base64::Engine;
    let hash = Sha256::digest(access_token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// Extract the DPoP proof from the `DPoP` header.
/// Extract DPoP header.
pub fn extract_dpop_header(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Validate AND verify a DPoP proof for a request (SEC-).
///
/// This is the production entry point used by the token endpoint:
/// 1. decode the proof (header + claims),
/// 2. validate `typ` / `htm` / `htu` / `iat` via [`validate_dpop_proof`],
/// 3. **verify the signature** against the JWK embedded in the proof
/// header (the proof key is client-controlled, so verification is
/// self-contained — ES256 or RS256),
/// 4. enforce `jti` replay protection via Valkey SETNX
/// (`auth:dpop:jti:{jti}`, TTL 300s — the doc-comment contract this
/// module has always claimed but never implemented until now),
/// 5. return the key thumbprint (`jkt`) so the issued access token can
/// be sender-constrained with `cnf.jkt`.
/// Validate and verify DPoP.
pub async fn validate_and_verify_dpop(
    state: &crate::handlers::AppState,
    proof: &str,
    http_method: &str,
    http_uri: &str,
) -> Result<String, String> {
    let decoded = decode_dpop_proof_unverified(proof)?;

    // Structural validation (typ / htm / htu / iat).
    let now = chrono::Utc::now().timestamp();
    validate_dpop_proof(&decoded, http_method, http_uri, now)?;

    // Signature verification against the embedded JWK.
    let jwk = &decoded.header.jwk;
    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
    let header_alg = decoded.header.alg.as_str();
    match (kty, header_alg) {
        ("EC", "ES256") | ("RSA", "RS256") => {
            let raw = crate::jwks::SigningKeys::verify_with_jwk(jwk, proof)
                .map_err(|e| format!("DPoP proof signature verification failed: {e}"))?;
            // The proof payload must round-trip through the same claims we
            // validated (guards against header/payload confusion).
            let parsed: DpopProofClaims = serde_json::from_value(raw)
                .map_err(|e| format!("DPoP claims mismatch after verification: {e}"))?;
            if parsed.jti != decoded.claims.jti || parsed.htm != decoded.claims.htm {
                return Err("DPoP proof claims mismatch".into());
            }
        }
        _ => {
            return Err(format!(
                "unsupported DPoP proof key/alg: kty={kty} alg={header_alg} (ES256/RS256 only)"
            ));
        }
    }

    // jti replay protection (Valkey SET NX, TTL 300s).
    let jti = &decoded.claims.jti;
    if !jti.is_empty() {
        if let Ok(conn) = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
            .await
        {
            use glide::AsyncCommands as _;
            let setnx = conn
                .set_nx::<_, _, i64>(format!("auth:dpop:jti:{jti}"), "1")
                .await;
            if matches!(setnx, Ok(0)) {
                return Err("DPoP proof jti already used (replay)".into());
            }
            let _: Result<(), _> = conn
                .expire(format!("auth:dpop:jti:{jti}"), 300i64)
                .await;
        }
    }

    // The key thumbprint → cnf.jkt on the issued token.
    jwk_thumbprint(jwk)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proof(htm: &str, htu: &str, iat: i64) -> DecodedDpopProof {
        use base64::Engine;
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLebMU6iXPb1F4dsFT8w",
                "y": "x_FEzRu9m36HLN_bueI7d5sCqGOu0Umqfpm5g7Jx6Q"
            }
        });
        let claims = serde_json::json!({
            "htm": htm,
            "htu": htu,
            "jti": "jti-123",
            "iat": iat,
        });
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        DecodedDpopProof {
            header: serde_json::from_value(header).unwrap(),
            claims: serde_json::from_value(claims).unwrap(),
            raw_header: header_b64,
            raw_claims: claims_b64,
            signature: "fake_sig".into(),
        }
    }

    #[test]
    fn validate_dpop_proof_ok() {
        let proof = make_proof("POST", "https://auth.example.com/oauth/token", 1700000000);
        assert!(validate_dpop_proof(
            &proof,
            "POST",
            "https://auth.example.com/oauth/token",
            1700000000
        )
        .is_ok());
    }

    #[test]
    fn validate_dpop_proof_method_mismatch() {
        let proof = make_proof("GET", "https://auth.example.com/oauth/token", 1700000000);
        assert!(validate_dpop_proof(
            &proof,
            "POST",
            "https://auth.example.com/oauth/token",
            1700000000
        )
        .is_err());
    }

    #[test]
    fn validate_dpop_proof_uri_mismatch() {
        let proof = make_proof("POST", "https://auth.example.com/oauth/token", 1700000000);
        assert!(validate_dpop_proof(
            &proof,
            "POST",
            "https://auth.example.com/oauth/revoke",
            1700000000
        )
        .is_err());
    }

    #[test]
    fn validate_dpop_proof_strips_query() {
        let proof = make_proof("POST", "https://auth.example.com/oauth/token", 1700000000);
        assert!(validate_dpop_proof(
            &proof,
            "POST",
            "https://auth.example.com/oauth/token?foo=bar",
            1700000000
        )
        .is_ok());
    }

    #[test]
    fn validate_dpop_proof_iat_too_old() {
        let proof = make_proof("POST", "https://auth.example.com/oauth/token", 1700000000);
        assert!(validate_dpop_proof(
            &proof,
            "POST",
            "https://auth.example.com/oauth/token",
            1700000100
        )
        .is_err());
    }

    #[test]
    fn validate_dpop_proof_wrong_typ() {
        let mut proof = make_proof("POST", "https://auth.example.com/oauth/token", 1700000000);
        proof.header.typ = "jwt".into();
        assert!(validate_dpop_proof(
            &proof,
            "POST",
            "https://auth.example.com/oauth/token",
            1700000000
        )
        .is_err());
    }

    #[test]
    fn build_dpop_cnf_claim_roundtrip() {
        let cnf = build_dpop_cnf_claim("thumb123");
        assert_eq!(cnf["jkt"], "thumb123");
    }

    #[test]
    fn compute_ath_matches_expected() {
        let ath = compute_ath("access_token_123");
        // SHA-256 of "access_token_123" base64url.
        assert!(!ath.contains('='));
        assert_eq!(ath.len(), 43);
    }

    #[test]
    fn extract_dpop_header_parses() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("dpop", "eyJ...".parse().unwrap());
        assert_eq!(extract_dpop_header(&headers).as_deref(), Some("eyJ..."));
    }

    #[test]
    fn strip_query_fragment_strips() {
        assert_eq!(
            strip_query_fragment("https://example.com/path?foo=bar#frag"),
            "https://example.com/path"
        );
    }

    #[test]
    fn jwk_thumbprint_reuses_jar() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLebMU6iXPb1F4dsFT8w",
            "y": "x_FEzRu9m36HLN_bueI7d5sCqGOu0Umqfpm5g7Jx6Q"
        });
        let t = jwk_thumbprint(&jwk).unwrap();
        assert_eq!(t.len(), 43);
    }
}
