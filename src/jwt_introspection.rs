// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! JWT Response for Token Introspection — RFC 9701 .
//!
//! When the client sends `Accept: application/token-introspection+jwt`, the
//! introspection endpoint returns a **signed JWT** (content type
//! `application/token-introspection+jwt`) containing the introspection
//! response claims, instead of plain JSON.
//!
//! The JWT is signed with the AS's signing key. Claims include:
//! - `iss` — the AS issuer
//! - `aud` — the requesting client_id
//! - `iat` — issued-at
//! - `active` — boolean
//! - plus the standard introspection response fields (scope, sub, exp, etc.)

use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use serde::Serialize;

use crate::jwks::SigningKeys;

/// Content type for JWT introspection responses (RFC 9701 ).
/// The content type JWT introspection constant.
pub const CONTENT_TYPE_JWT_INTROSPECTION: &str = "application/token-introspection+jwt";

/// Check if the client requested a JWT introspection response.
/// Handle wants JWT response.
pub fn wants_jwt_response(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains(CONTENT_TYPE_JWT_INTROSPECTION))
        .unwrap_or(false)
}

/// Introspection response claims that go inside the JWT.
#[derive(Debug, Serialize)]
/// The jwtintrospectionclaims type.
pub struct JwtIntrospectionClaims {
    /// The iss.
    pub iss: String,
    /// The aud.
    pub aud: String,
    /// The iat.
    pub iat: i64,
    /// The active.
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The scope.
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// client identifier.
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The sub.
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The exp.
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// env identifier.
    pub env_id: Option<String>,
    /// Token type hint
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The token type.
    pub token_type: Option<String>,
}

/// Build the introspection JWT claims from the introspection response.
/// Build introspection claims.
pub fn build_introspection_claims(
    issuer: &str,
    audience: &str,
    active: bool,
    scope: Option<String>,
    client_id: Option<String>,
    sub: Option<String>,
    exp: Option<i64>,
    env_id: Option<String>,
) -> JwtIntrospectionClaims {
    JwtIntrospectionClaims {
        iss: issuer.to_string(),
        aud: audience.to_string(),
        iat: Utc::now().timestamp(),
        active,
        scope,
        client_id,
        sub,
        exp,
        env_id,
        token_type: Some("Bearer".into()),
    }
}

/// Sign the introspection JWT using the AS's signing key.
/// Sign introspection JWT.
pub fn sign_introspection_jwt(
    keys: &SigningKeys,
    claims: &JwtIntrospectionClaims,
) -> Result<String, String> {
    let value =
        serde_json::to_value(claims).map_err(|e| format!("serialize introspection claims: {e}"))?;
    keys.sign_value(&value)
}

/// Build a JWT introspection response (the full HTTP response).
/// Handle JWT introspection response.
pub fn jwt_introspection_response(
    keys: &SigningKeys,
    issuer: &str,
    audience: &str,
    active: bool,
    scope: Option<String>,
    client_id: Option<String>,
    sub: Option<String>,
    exp: Option<i64>,
    env_id: Option<String>,
) -> Result<(StatusCode, [(String, String); 1], String), String> {
    let claims =
        build_introspection_claims(issuer, audience, active, scope, client_id, sub, exp, env_id);
    let jwt =
        sign_introspection_jwt(keys, &claims).map_err(|e| format!("JWT signing failed: {e}"))?;
    Ok((
        StatusCode::OK,
        [(
            "content-type".to_string(),
            CONTENT_TYPE_JWT_INTROSPECTION.to_string(),
        )],
        jwt,
    ))
}

/// Extract the requesting client_id for the `aud` claim.
/// From the Authorization header (client_secret_basic) or the `client_id`
/// form field.
/// Extract audience.
pub fn extract_audience(headers: &HeaderMap, client_id_form: Option<&str>) -> String {
    // Prefer the client_id from the form body.
    if let Some(cid) = client_id_form {
        if !cid.is_empty() {
            return cid.to_string();
        }
    }
    // Fall back to the basic auth username.
    if let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(basic) = auth.strip_prefix("Basic ") {
            if let Ok(decoded) =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, basic)
            {
                if let Ok(s) = std::str::from_utf8(&decoded) {
                    if let Some((user, _)) = s.split_once(':') {
                        return user.to_string();
                    }
                }
            }
        }
    }
    "unknown".to_string()
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wants_jwt_response_true() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            "application/token-introspection+jwt".parse().unwrap(),
        );
        assert!(wants_jwt_response(&headers));
    }

    #[test]
    fn wants_jwt_response_false() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            "application/json".parse().unwrap(),
        );
        assert!(!wants_jwt_response(&headers));
    }

    #[test]
    fn wants_jwt_response_missing() {
        let headers = HeaderMap::new();
        assert!(!wants_jwt_response(&headers));
    }

    #[test]
    fn build_introspection_claims_active() {
        let claims = build_introspection_claims(
            "https://auth.example.com",
            "client_123",
            true,
            Some("openid".into()),
            None,
            Some("user-456".into()),
            Some(1700000000),
            Some("env".into()),
        );
        assert!(claims.active);
        assert_eq!(claims.iss, "https://auth.example.com");
        assert_eq!(claims.aud, "client_123");
        assert_eq!(claims.scope.as_deref(), Some("openid"));
        assert_eq!(claims.sub.as_deref(), Some("user-456"));
    }

    #[test]
    fn build_introspection_claims_inactive() {
        let claims = build_introspection_claims(
            "https://auth.example.com",
            "client_123",
            false,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(!claims.active);
        assert!(claims.scope.is_none());
    }

    #[test]
    fn extract_audience_from_form() {
        let headers = HeaderMap::new();
        assert_eq!(
            extract_audience(&headers, Some("client_form")),
            "client_form"
        );
    }

    #[test]
    fn extract_audience_default() {
        let headers = HeaderMap::new();
        assert_eq!(extract_audience(&headers, None), "unknown");
    }

    #[test]
    fn content_type_constant() {
        assert_eq!(
            CONTENT_TYPE_JWT_INTROSPECTION,
            "application/token-introspection+jwt"
        );
    }
}
