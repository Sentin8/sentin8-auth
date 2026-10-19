// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! OIDC Relying Party Metadata Choices
//!
//! This module allows Auth (as an AS) to **fetch and validate** an RP's
//! published metadata document. RPs publish their metadata at a well-known
//! URL or provide it during client registration (DCR). The AS stores the
//! `rp_metadata_uri` and can fetch the metadata to discover the RP's
//! `client_secret`, `redirect_uris`, `jwks_uri`, etc.
//!
//! Per the spec, the RP metadata document contains the same fields as a
//! DCR registration request (client_name, redirect_uris, grant_types, etc.)
//! and is fetched via HTTPS.

use serde::{Deserialize, Serialize};

/// RP metadata document (OIDC RP Metadata Choices ).
#[derive(Debug, Clone, Deserialize, Serialize)]
/// The rpmetadata type.
pub struct RpMetadata {
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
    #[serde(default)]
    /// The JWKS.
    pub jwks: Option<serde_json::Value>,
    #[serde(default)]
    /// software identifier.
    pub software_id: Option<String>,
    #[serde(default)]
    /// The software statement.
    pub software_statement: Option<String>,
    #[serde(default)]
    /// The logo URI.
    pub logo_uri: Option<String>,
    #[serde(default)]
    /// The client URI.
    pub client_uri: Option<String>,
    #[serde(default)]
    /// The policy URI.
    pub policy_uri: Option<String>,
    #[serde(default)]
    /// The tos URI.
    pub tos_uri: Option<String>,
    #[serde(default)]
    /// The contacts.
    pub contacts: Vec<String>,
    #[serde(default)]
    /// The subject type.
    pub subject_type: Option<String>,
    #[serde(default)]
    /// The application type.
    pub application_type: Option<String>,
}

/// Fetch an RP metadata document from a URL.
/// Uses HTTPS with a 10s timeout.
/// Fetch rp metadata.
pub async fn fetch_rp_metadata(uri: &str) -> Result<RpMetadata, String> {
    if !uri.starts_with("https://") {
        return Err("rp_metadata_uri must use HTTPS".into());
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(uri).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    resp.json::<RpMetadata>()
        .await
        .map_err(|e| format!("metadata parse failed: {e}"))
}

/// Validate an RP metadata document.
/// - At least one `redirect_uris` entry must be present.
/// - All redirect URIs must be valid URLs (https or custom scheme).
///
/// Validate rp metadata.
pub fn validate_rp_metadata(meta: &RpMetadata) -> Result<(), String> {
    if meta.redirect_uris.is_empty() {
        return Err("redirect_uris is required in RP metadata".into());
    }
    for uri in &meta.redirect_uris {
        if uri.is_empty() {
            return Err("redirect_uri must not be empty".into());
        }
        // Must have a scheme.
        if !uri.contains(':') {
            return Err("redirect_uri must be an absolute URL".into());
        }
    }
    Ok(())
}

/// Build the well-known RP metadata URL for a given RP origin.
/// Per the spec, RPs publish metadata at:
/// `https://{rp-origin}/.well-known/openid-relying-party-configuration`
/// Handle well known rp metadata URL.
pub fn well_known_rp_metadata_url(rp_origin: &str) -> String {
    let origin = rp_origin.trim_end_matches('/');
    format!("{origin}/.well-known/openid-relying-party-configuration")
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rp_metadata_ok() {
        let meta = RpMetadata {
            client_name: Some("Test RP".into()),
            redirect_uris: vec!["https://app.example.com/callback".into()],
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            token_endpoint_auth_method: Some("client_secret_basic".into()),
            scope: Some("openid".into()),
            jwks_uri: None,
            jwks: None,
            software_id: None,
            software_statement: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
            subject_type: Some("public".into()),
            application_type: Some("web".into()),
        };
        assert!(validate_rp_metadata(&meta).is_ok());
    }

    #[test]
    fn validate_rp_metadata_no_redirect() {
        let meta = RpMetadata {
            client_name: None,
            redirect_uris: vec![],
            grant_types: vec![],
            response_types: vec![],
            token_endpoint_auth_method: None,
            scope: None,
            jwks_uri: None,
            jwks: None,
            software_id: None,
            software_statement: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
            subject_type: None,
            application_type: None,
        };
        assert!(validate_rp_metadata(&meta).is_err());
    }

    #[test]
    fn validate_rp_metadata_relative_uri() {
        let meta = RpMetadata {
            client_name: None,
            redirect_uris: vec!["/callback".into()],
            grant_types: vec![],
            response_types: vec![],
            token_endpoint_auth_method: None,
            scope: None,
            jwks_uri: None,
            jwks: None,
            software_id: None,
            software_statement: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
            subject_type: None,
            application_type: None,
        };
        assert!(validate_rp_metadata(&meta).is_err());
    }

    #[test]
    fn well_known_rp_metadata_url_shape() {
        let url = well_known_rp_metadata_url("https://app.example.com");
        assert_eq!(
            url,
            "https://app.example.com/.well-known/openid-relying-party-configuration"
        );
    }

    #[test]
    fn well_known_rp_metadata_url_trailing_slash() {
        let url = well_known_rp_metadata_url("https://app.example.com/");
        assert_eq!(
            url,
            "https://app.example.com/.well-known/openid-relying-party-configuration"
        );
    }

    #[test]
    fn rp_metadata_deserialize() {
        let json = serde_json::json!({
            "client_name": "My RP",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": "openid profile email",
            "application_type": "web"
        });
        let meta: RpMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(meta.client_name.as_deref(), Some("My RP"));
        assert_eq!(meta.redirect_uris.len(), 1);
        assert_eq!(meta.grant_types.len(), 2);
    }

    #[test]
    fn fetch_rp_metadata_rejects_http() {
        // This is a synchronous check - no network needed.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(fetch_rp_metadata("http://example.com/.well-known/rp"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTPS"));
    }
}
