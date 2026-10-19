// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Experimental OAuth/OIDC Extensions(P2).
//!
//! These are experimental profiles that extend the core OAuth/OIDC flows:
//! - **FAPI-CIBA Profile** : Combines CIBA with FAPI 2.0 security
//! constraints (DPoP, PAR, JARM).
//! - **Attestation-Based Client Authentication** : Clients authenticate
//! via an attestation JWT (e.g. from a hardware attestation service) instead
//! of a client_secret.
//! - **Client ID Metadata Document (CIMD)** : Clients publish their
//! metadata at a well-known URL keyed by their client_id, so the AS can
//! fetch it dynamically without DCR.

use serde::{Deserialize, Serialize};

// ── FAPI-CIBA Profile ────────────────────────────────────────

/// FAPI-CIBA profile constraints.
/// Combines CIBA with FAPI : DPoP required, JARM response, PAR for the
/// initial request (if applicable), `iss` required.
#[derive(Debug, Clone, Serialize)]
/// The fapicibaprofile type.
pub struct FapiCibaProfile {
    /// The require DPoP.
    pub require_dpop: bool,
    /// The require JARM.
    pub require_jarm: bool,
    /// The require iss.
    pub require_iss: bool,
    /// The require JWT introspection.
    pub require_jwt_introspection: bool,
}

impl Default for FapiCibaProfile {
    fn default() -> Self {
        Self {
            require_dpop: true,
            require_jarm: true,
            require_iss: true,
            require_jwt_introspection: false,
        }
    }
}

/// Validate a FAPI-CIBA request.
/// - DPoP proof must be present on the token polling request.
/// - The `bc-authorize` request must include `binding_message`.
///
/// Validate FAPI CIBA request.
pub fn validate_fapi_ciba_request(
    binding_message: Option<&str>,
    dpop_present: bool,
) -> Result<(), String> {
    if binding_message.map(|s| s.is_empty()).unwrap_or(true) {
        return Err("FAPI-CIBA requires binding_message".into());
    }
    if !dpop_present {
        return Err("FAPI-CIBA requires DPoP on the token polling request".into());
    }
    Ok(())
}

// ── Attestation-Based Client Authentication ──────────────────

/// Attestation JWT claims (experimental).
/// The client presents an attestation JWT signed by a hardware attestation
/// service (e.g. Apple App Attest, Android Play Integrity).
#[derive(Debug, Deserialize)]
/// The attestationclaims type.
pub struct AttestationClaims {
    /// The client_id being authenticated.
    /// The iss.
    pub iss: String,
    /// The AS issuer (audience).
    /// The aud.
    pub aud: String,
    /// Issued-at.
    /// The iat.
    pub iat: i64,
    /// Expiry.
    /// The exp.
    pub exp: i64,
    /// The attestation type (e.g. "apple_app_attest", "android_play_integrity").
    #[serde(rename = "att_typ")]
    /// The att typ.
    pub att_typ: String,
    /// The attestation payload (nonce, nonce_hash, etc.).
    #[serde(rename = "att_payload")]
    /// The att payload.
    pub att_payload: Option<serde_json::Value>,
    /// The client's public key (JWK) for subsequent DPoP proofs.
    #[serde(default)]
    /// The jwk.
    pub jwk: Option<serde_json::Value>,
}

/// Validate an attestation JWT (without signature verification - the
/// signature is verified against the attestation service's public key).
/// Validate attestation claims.
pub fn validate_attestation_claims(
    claims: &AttestationClaims,
    expected_aud: &str,
    now: i64,
) -> Result<(), String> {
    if claims.aud != expected_aud {
        return Err("attestation aud mismatch".into());
    }
    if claims.exp < now {
        return Err("attestation expired".into());
    }
    if claims.iat > now + 60 {
        return Err("attestation iat in the future".into());
    }
    if claims.att_typ.is_empty() {
        return Err("attestation att_typ is required".into());
    }
    Ok(())
}

/// Decode an attestation JWT without signature verification.
///
/// Uses `sentin8::auth::jwt` because `jsonwebtoken::decode` fails on non-standard
/// algorithms (e.g. `MLDSA65`).
/// Handle decode attestation unverified.
pub fn decode_attestation_unverified(token: &str) -> Result<AttestationClaims, String> {
    sentin8::auth::jwt::decode_payload_typed(token)
        .ok_or_else(|| "attestation decode failed".into())
}

// ── Client ID Metadata Document (CIMD) ───────────────────────

/// The well-known URL for a client's metadata document.
/// Per CIMD (experimental), the client publishes metadata at:
/// `https://{client_origin}/.well-known/oauth-client/{client_id}`
/// Handle cimd metadata URL.
pub fn cimd_metadata_url(client_origin: &str, client_id: &str) -> String {
    let origin = client_origin.trim_end_matches('/');
    format!("{origin}/.well-known/oauth-client/{client_id}")
}

/// CIMD metadata document - same shape as DCR but keyed by client_id.
#[derive(Debug, Clone, Deserialize, Serialize)]
/// The cimdmetadata type.
pub struct CimdMetadata {
    /// client identifier.
    pub client_id: String,
    #[serde(default)]
    /// The client name.
    pub client_name: Option<String>,
    #[serde(default)]
    /// The redirect uris.
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    /// The grant types.
    pub grant_types: Vec<String>,
    #[serde(default)]
    /// The response types.
    pub response_types: Vec<String>,
    #[serde(default)]
    /// The token endpoint auth method.
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    /// The scope.
    pub scope: Option<String>,
    #[serde(default)]
    /// The JWKS URI.
    pub jwks_uri: Option<String>,
}

/// Validate a CIMD metadata document.
/// Validate cimd metadata.
pub fn validate_cimd_metadata(meta: &CimdMetadata) -> Result<(), String> {
    if meta.client_id.is_empty() {
        return Err("client_id is required in CIMD".into());
    }
    if meta.redirect_uris.is_empty() {
        return Err("redirect_uris is required in CIMD".into());
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // FAPI-CIBA

    #[test]
    fn fapi_ciba_default() {
        let p = FapiCibaProfile::default();
        assert!(p.require_dpop);
        assert!(p.require_jarm);
        assert!(p.require_iss);
    }

    #[test]
    fn validate_fapi_ciba_ok() {
        assert!(validate_fapi_ciba_request(Some("Approve?"), true).is_ok());
    }

    #[test]
    fn validate_fapi_ciba_missing_binding_message() {
        assert!(validate_fapi_ciba_request(None, true).is_err());
        assert!(validate_fapi_ciba_request(Some(""), true).is_err());
    }

    #[test]
    fn validate_fapi_ciba_missing_dpop() {
        assert!(validate_fapi_ciba_request(Some("Approve?"), false).is_err());
    }

    // Attestation

    #[test]
    fn validate_attestation_ok() {
        let claims = AttestationClaims {
            iss: "client_123".into(),
            aud: "https://auth.example.com".into(),
            iat: 1700000000,
            exp: 1700000100,
            att_typ: "apple_app_attest".into(),
            att_payload: None,
            jwk: None,
        };
        assert!(
            validate_attestation_claims(&claims, "https://auth.example.com", 1700000050).is_ok()
        );
    }

    #[test]
    fn validate_attestation_aud_mismatch() {
        let claims = AttestationClaims {
            iss: "client_123".into(),
            aud: "https://wrong.com".into(),
            iat: 1700000000,
            exp: 1700000100,
            att_typ: "apple_app_attest".into(),
            att_payload: None,
            jwk: None,
        };
        assert!(
            validate_attestation_claims(&claims, "https://auth.example.com", 1700000050).is_err()
        );
    }

    #[test]
    fn validate_attestation_expired() {
        let claims = AttestationClaims {
            iss: "client_123".into(),
            aud: "https://auth.example.com".into(),
            iat: 1700000000,
            exp: 1700000000,
            att_typ: "android_play_integrity".into(),
            att_payload: None,
            jwk: None,
        };
        assert!(
            validate_attestation_claims(&claims, "https://auth.example.com", 1700000100).is_err()
        );
    }

    #[test]
    fn validate_attestation_missing_type() {
        let claims = AttestationClaims {
            iss: "client_123".into(),
            aud: "https://auth.example.com".into(),
            iat: 1700000000,
            exp: 1700000100,
            att_typ: "".into(),
            att_payload: None,
            jwk: None,
        };
        assert!(
            validate_attestation_claims(&claims, "https://auth.example.com", 1700000050).is_err()
        );
    }

    #[test]
    fn attestation_iat_in_future() {
        let claims = AttestationClaims {
            iss: "client_123".into(),
            aud: "https://auth.example.com".into(),
            iat: 1700001000,
            exp: 1700002000,
            att_typ: "apple_app_attest".into(),
            att_payload: None,
            jwk: None,
        };
        assert!(
            validate_attestation_claims(&claims, "https://auth.example.com", 1700000000).is_err()
        );
    }

    // CIMD

    #[test]
    fn cimd_metadata_url_shape() {
        let url = cimd_metadata_url("https://app.example.com", "client_123");
        assert_eq!(
            url,
            "https://app.example.com/.well-known/oauth-client/client_123"
        );
    }

    #[test]
    fn cimd_metadata_url_trailing_slash() {
        let url = cimd_metadata_url("https://app.example.com/", "client_123");
        assert_eq!(
            url,
            "https://app.example.com/.well-known/oauth-client/client_123"
        );
    }

    #[test]
    fn validate_cimd_metadata_ok() {
        let meta = CimdMetadata {
            client_id: "client_123".into(),
            client_name: Some("My App".into()),
            redirect_uris: vec!["https://app.example.com/callback".into()],
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            token_endpoint_auth_method: Some("none".into()),
            scope: Some("openid".into()),
            jwks_uri: None,
        };
        assert!(validate_cimd_metadata(&meta).is_ok());
    }

    #[test]
    fn validate_cimd_metadata_no_client_id() {
        let meta = CimdMetadata {
            client_id: "".into(),
            client_name: None,
            redirect_uris: vec!["https://app.example.com/callback".into()],
            grant_types: vec![],
            response_types: vec![],
            token_endpoint_auth_method: None,
            scope: None,
            jwks_uri: None,
        };
        assert!(validate_cimd_metadata(&meta).is_err());
    }

    #[test]
    fn validate_cimd_metadata_no_redirect_uris() {
        let meta = CimdMetadata {
            client_id: "client_123".into(),
            client_name: None,
            redirect_uris: vec![],
            grant_types: vec![],
            response_types: vec![],
            token_endpoint_auth_method: None,
            scope: None,
            jwks_uri: None,
        };
        assert!(validate_cimd_metadata(&meta).is_err());
    }
}
