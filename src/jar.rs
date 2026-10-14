// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! JWT-Secured Authorization Request (JAR) — RFC 9101 .
//!
//! JAR allows clients to pass a **signed JWT** as the `request` parameter
//! (or `request_uri` pointing to a JWT) instead of sending OAuth params
//! inline. The AS must:
//! - Accept the `request` parameter (a signed JWT containing the OAuth params).
//! - Verify the JWT signature using the client's registered keys (jwks/jwks_uri).
//! - Extract all OAuth params (response_type, redirect_uri, scope, state,
//! code_challenge, etc.) from the JWT — except `client_id` which may be inline.
//! - When `request` is used, all other inline params (except `client_id`) MUST
//! be ignored.
//!
//! FAPI 2.0 requires JAR (or PAR) for authorization requests.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Claims inside a JAR request JWT (per RFC 9101 ).
#[derive(Debug, Deserialize)]
/// The jarclaims type.
pub struct JarClaims {
    /// The iss.
    pub iss: Option<String>,
    /// The aud.
    pub aud: Option<String>,
    /// The response type.
    pub response_type: String,
    /// client identifier.
    pub client_id: String,
    /// The redirect URI.
    pub redirect_uri: String,
    #[serde(default)]
    /// The scope.
    pub scope: String,
    #[serde(default)]
    /// The state.
    pub state: String,
    #[serde(default)]
    /// The code challenge.
    pub code_challenge: Option<String>,
    #[serde(default)]
    /// The code challenge method.
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    /// The nonce.
    pub nonce: Option<String>,
    /// JAR-specific: max_age
    #[serde(default)]
    /// Maximum age.
    pub max_age: Option<i64>,
    /// Resource indicators
    #[serde(default)]
    /// The resource.
    pub resource: Option<Vec<String>>,
}

/// Decode a JAR request JWT WITHOUT signature verification.
/// This is used to extract the claims for further validation.
/// Signature verification should be done using the client's registered keys.
///
/// Uses `sentin8::auth::jwt` because `jsonwebtoken::decode` fails on non-standard
/// algorithms (e.g. `MLDSA65`).
/// Handle decode JAR unverified.
pub fn decode_jar_unverified(token: &str) -> Result<JarClaims, String> {
    sentin8::auth::jwt::decode_payload_typed(token).ok_or_else(|| "JAR decode failed".into())
}

/// Compute the SHA-256 thumbprint of a JWK (for `jkt` / `kid` lookup).
/// This is used to find the client's signing key in their JWKS.
/// Handle jwk thumbprint.
pub fn jwk_thumbprint(jwk_json: &serde_json::Value) -> Result<String, String> {
    // RFC 7638: thumbprint = SHA-256 of the lexicographic concatenation of
    // required members for the key type.
    let kty = jwk_json
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or("missing kty")?
        .to_string();
    let members: Vec<(&str, &serde_json::Value)> = match kty.as_str() {
        "RSA" => vec![
            ("e", jwk_json.get("e").ok_or("missing e")?),
            ("kty", jwk_json.get("kty").ok_or("missing kty")?),
            ("n", jwk_json.get("n").ok_or("missing n")?),
        ],
        "EC" => vec![
            ("crv", jwk_json.get("crv").ok_or("missing crv")?),
            ("kty", jwk_json.get("kty").ok_or("missing kty")?),
            ("x", jwk_json.get("x").ok_or("missing x")?),
            ("y", jwk_json.get("y").ok_or("missing y")?),
        ],
        "OKP" => vec![
            ("crv", jwk_json.get("crv").ok_or("missing crv")?),
            ("kty", jwk_json.get("kty").ok_or("missing kty")?),
            ("x", jwk_json.get("x").ok_or("missing x")?),
        ],
        _ => return Err(format!("unsupported kty: {kty}")),
    };
    // Build the canonical JSON: {"key1":"val1","key2":"val2",...}
    // sorted lexicographically.
    let mut sorted = members.clone();
    sorted.sort_by_key(|a| a.0.to_owned());
    let mut json_str = String::from("{");
    for (i, (k, v)) in sorted.iter().enumerate() {
        if i > 0 {
            json_str.push(',');
        }
        let val_str = match v {
            serde_json::Value::String(s) => format!("\"{s}\""),
            other => other.to_string(),
        };
        json_str.push_str(&format!("\"{k}\":{val_str}"));
    }
    json_str.push('}');
    let hash = Sha256::digest(json_str.as_bytes());
    use base64::Engine;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash))
}

/// Validate JAR claims per RFC 9101
/// - `iss` must equal `client_id` (when present).
/// - `aud` must equal the AS issuer (when present).
/// - `response_type` is required.
/// Validate JAR claims.
pub fn validate_jar_claims(claims: &JarClaims, issuer: &str) -> Result<(), String> {
    if claims.iss.is_some() && claims.iss.as_deref() != Some(&claims.client_id) {
        return Err("JAR iss must equal client_id".into());
    }
    if let Some(aud) = &claims.aud {
        if aud != issuer {
            return Err("JAR aud must equal the AS issuer".into());
        }
    }
    if claims.response_type.is_empty() {
        return Err("JAR response_type is required".into());
    }
    if claims.redirect_uri.is_empty() {
        return Err("JAR redirect_uri is required".into());
    }
    Ok(())
}

/// Serialize JAR claims for signing (used in tests).
#[derive(Debug, Serialize)]
/// The jarclaimsforsigning type.
pub struct JarClaimsForSigning {
    /// The iss.
    pub iss: String,
    /// The aud.
    pub aud: String,
    /// The response type.
    pub response_type: String,
    /// client identifier.
    pub client_id: String,
    /// The redirect URI.
    pub redirect_uri: String,
    /// The scope.
    pub scope: String,
    /// The state.
    pub state: String,
    /// The code challenge.
    pub code_challenge: String,
    /// The code challenge method.
    pub code_challenge_method: String,
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_jar_claims_ok() {
        let claims = JarClaims {
            iss: Some("client_123".into()),
            aud: Some("https://auth.example.com".into()),
            response_type: "code".into(),
            client_id: "client_123".into(),
            redirect_uri: "https://app.example.com/callback".into(),
            scope: "openid".into(),
            state: "state123".into(),
            code_challenge: Some("challenge".into()),
            code_challenge_method: Some("S256".into()),
            nonce: None,
            max_age: None,
            resource: None,
        };
        assert!(validate_jar_claims(&claims, "https://auth.example.com").is_ok());
    }

    #[test]
    fn validate_jar_iss_mismatch() {
        let claims = JarClaims {
            iss: Some("wrong".into()),
            aud: None,
            response_type: "code".into(),
            client_id: "client_123".into(),
            redirect_uri: "https://app.example.com/callback".into(),
            scope: "".into(),
            state: "".into(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            max_age: None,
            resource: None,
        };
        assert!(validate_jar_claims(&claims, "https://auth.example.com").is_err());
    }

    #[test]
    fn validate_jar_aud_mismatch() {
        let claims = JarClaims {
            iss: None,
            aud: Some("https://wrong.example.com".into()),
            response_type: "code".into(),
            client_id: "client_123".into(),
            redirect_uri: "https://app.example.com/callback".into(),
            scope: "".into(),
            state: "".into(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            max_age: None,
            resource: None,
        };
        assert!(validate_jar_claims(&claims, "https://auth.example.com").is_err());
    }

    #[test]
    fn validate_jar_missing_response_type() {
        let claims = JarClaims {
            iss: None,
            aud: None,
            response_type: "".into(),
            client_id: "client_123".into(),
            redirect_uri: "https://app.example.com/callback".into(),
            scope: "".into(),
            state: "".into(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            max_age: None,
            resource: None,
        };
        assert!(validate_jar_claims(&claims, "https://auth.example.com").is_err());
    }

    #[test]
    fn jwk_thumbprint_rsa() {
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPbeWKwdG9EIkhA0R4bu3IqQ",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        });
        let thumb = jwk_thumbprint(&jwk).unwrap();
        // Thumbprint should be base64url, 43 chars (SHA-256).
        assert_eq!(thumb.len(), 43);
        assert!(!thumb.contains('='));
    }

    #[test]
    fn jwk_thumbprint_ec() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLebMU6iXPb1F4dsFT8w",
            "y": "x_FEzRu9m36HLN_bueI7d5sCqGOu0Umqfpm5g7Jx6Q"
        });
        let thumb = jwk_thumbprint(&jwk).unwrap();
        assert_eq!(thumb.len(), 43);
    }

    #[test]
    fn jwk_thumbprint_missing_kty() {
        let jwk = serde_json::json!({"n": "abc", "e": "AQAB"});
        assert!(jwk_thumbprint(&jwk).is_err());
    }

    #[test]
    fn jwk_thumbprint_unsupported_kty() {
        let jwk = serde_json::json!({"kty": "oct", "k": "abc"});
        assert!(jwk_thumbprint(&jwk).is_err());
    }
}
