// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! JWT Secured Authorization Response Mode (JARM)
//!
//! JARM allows the AS to return the authorization response as a **signed
//! JWT** (either as a redirect parameter or via direct response). The
//! `response_mode=jwt` parameter is advertised in the discovery document
//! when `require_jarm` is true.
//!
//! The JARM JWT contains:
//! - `iss` - the AS issuer
//! - `aud` - the client_id
//! - `exp` - expiry (short-lived, ~60s)
//! - `iat` - issued-at
//! - `code` - the authorization code (success)
//! - `state` - the state parameter from the request
//! - `error` / `error_description` - on failure

use chrono::{Duration, Utc};
use serde::Serialize;

use crate::jwks::SigningKeys;

/// JARM response JWT claims.
#[derive(Debug, Serialize)]
/// The jarmclaims type.
pub struct JarmClaims {
    /// The iss.
    pub iss: String,
    /// The aud.
    pub aud: String,
    /// The exp.
    pub exp: i64,
    /// The iat.
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The code.
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The state.
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The error.
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The error description.
    pub error_description: Option<String>,
}

/// Build a JARM success response (authorization code).
/// Build JARM success.
pub fn build_jarm_success(
    issuer: &str,
    client_id: &str,
    code: &str,
    state: Option<&str>,
) -> JarmClaims {
    let now = Utc::now();
    JarmClaims {
        iss: issuer.to_string(),
        aud: client_id.to_string(),
        exp: (now + Duration::seconds(60)).timestamp(),
        iat: now.timestamp(),
        code: Some(code.to_string()),
        state: state.map(|s| s.to_string()),
        error: None,
        error_description: None,
    }
}

/// Build a JARM error response.
/// Build JARM error.
pub fn build_jarm_error(
    issuer: &str,
    client_id: &str,
    error: &str,
    error_description: Option<&str>,
    state: Option<&str>,
) -> JarmClaims {
    let now = Utc::now();
    JarmClaims {
        iss: issuer.to_string(),
        aud: client_id.to_string(),
        exp: (now + Duration::seconds(60)).timestamp(),
        iat: now.timestamp(),
        code: None,
        state: state.map(|s| s.to_string()),
        error: Some(error.to_string()),
        error_description: error_description.map(|s| s.to_string()),
    }
}

/// Sign the JARM JWT using the AS's signing key.
/// Sign JARM JWT.
pub fn sign_jarm_jwt(keys: &SigningKeys, claims: &JarmClaims) -> Result<String, String> {
    let value = serde_json::to_value(claims).map_err(|e| format!("serialize JARM claims: {e}"))?;
    keys.sign_value(&value)
}

/// Build the redirect URL for a JARM response.
/// The JWT is passed as the `response` query parameter.
/// Build JARM redirect URL.
pub fn build_jarm_redirect_url(redirect_uri: &str, jwt: &str) -> String {
    format!("{redirect_uri}?response={jwt}")
}

/// Check if the request uses `response_mode=jwt`.
/// Handle is JARM response mode.
pub fn is_jarm_response_mode(response_mode: Option<&str>) -> bool {
    response_mode.map(|m| m == "jwt").unwrap_or(false)
}

/// Validate the JARM response (for RP-side verification - not used by AS).
/// Validate JARM claims.
pub fn validate_jarm_claims(
    claims: &JarmClaims,
    expected_issuer: &str,
    expected_aud: &str,
    now: i64,
) -> Result<(), String> {
    if claims.iss != expected_issuer {
        return Err("JARM iss mismatch".into());
    }
    if claims.aud != expected_aud {
        return Err("JARM aud mismatch".into());
    }
    if claims.exp < now {
        return Err("JARM token expired".into());
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_jarm_success_roundtrip() {
        let claims = build_jarm_success(
            "https://auth.example.com",
            "client_123",
            "code_abc",
            Some("state_xyz"),
        );
        assert_eq!(claims.iss, "https://auth.example.com");
        assert_eq!(claims.aud, "client_123");
        assert_eq!(claims.code.as_deref(), Some("code_abc"));
        assert_eq!(claims.state.as_deref(), Some("state_xyz"));
        assert!(claims.error.is_none());
    }

    #[test]
    fn build_jarm_error_roundtrip() {
        let claims = build_jarm_error(
            "https://auth.example.com",
            "client_123",
            "access_denied",
            Some("user denied consent"),
            None,
        );
        assert!(claims.code.is_none());
        assert_eq!(claims.error.as_deref(), Some("access_denied"));
        assert_eq!(
            claims.error_description.as_deref(),
            Some("user denied consent")
        );
    }

    #[test]
    fn jarm_claims_skip_none_on_success() {
        let claims = build_jarm_success("https://auth.example.com", "client_123", "code_abc", None);
        let json = serde_json::to_value(&claims).unwrap();
        assert!(json.get("error").is_none());
        assert!(json.get("error_description").is_none());
        assert!(json.get("state").is_none());
    }

    #[test]
    fn jarm_claims_skip_none_on_error() {
        let claims = build_jarm_error(
            "https://auth.example.com",
            "client_123",
            "access_denied",
            None,
            None,
        );
        let json = serde_json::to_value(&claims).unwrap();
        assert!(json.get("code").is_none());
        assert!(json.get("state").is_none());
        assert!(json.get("error_description").is_none());
    }

    #[test]
    fn is_jarm_response_mode_classifies() {
        assert!(is_jarm_response_mode(Some("jwt")));
        assert!(!is_jarm_response_mode(Some("query")));
        assert!(!is_jarm_response_mode(Some("fragment")));
        assert!(!is_jarm_response_mode(None));
    }

    #[test]
    fn validate_jarm_claims_ok() {
        let claims = build_jarm_success("https://auth.example.com", "client_123", "code", None);
        assert!(validate_jarm_claims(
            &claims,
            "https://auth.example.com",
            "client_123",
            Utc::now().timestamp()
        )
        .is_ok());
    }

    #[test]
    fn validate_jarm_iss_mismatch() {
        let claims = build_jarm_success("https://wrong.com", "client_123", "code", None);
        assert!(validate_jarm_claims(
            &claims,
            "https://auth.example.com",
            "client_123",
            Utc::now().timestamp()
        )
        .is_err());
    }

    #[test]
    fn validate_jarm_aud_mismatch() {
        let claims = build_jarm_success("https://auth.example.com", "wrong", "code", None);
        assert!(validate_jarm_claims(
            &claims,
            "https://auth.example.com",
            "client_123",
            Utc::now().timestamp()
        )
        .is_err());
    }

    #[test]
    fn validate_jarm_expired() {
        let mut claims = build_jarm_success("https://auth.example.com", "client_123", "code", None);
        claims.exp = Utc::now().timestamp() - 100; // expired
        assert!(validate_jarm_claims(
            &claims,
            "https://auth.example.com",
            "client_123",
            Utc::now().timestamp()
        )
        .is_err());
    }

    #[test]
    fn build_jarm_redirect_url_roundtrip() {
        let url = build_jarm_redirect_url("https://app.example.com/callback", "eyJ...");
        assert_eq!(url, "https://app.example.com/callback?response=eyJ...");
    }
}
