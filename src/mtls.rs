// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Mutual TLS Client Authentication (RFC 8705)
//!
//! Two modes:
//! 1. **PKI-based** (`tls_client_auth`): the client's cert subject DN must
//! match the `tls_client_auth_subject_dn` registered metadata.
//! 2. **Self-signed** (`self_signed_tls_client_auth`): the cert thumbprint
//! (X.509 SHA-256 thumbprint, `x5t#S256`) must match the registered
//! `self_signed_tls_client_auth_thumbprint`.
//!
//! Sender-constraining: when a client authenticates via mTLS, the issued
//! access token includes a `cnf` (confirmation) claim with `x5t#S256` — the
//! thumbprint of the client cert. Resource servers must verify the same
//! cert is presented when the token is used.
//!
//! TLS's `X-Sentin8-Client-Cert-Thumbprint`
//! header. This module provides the validation + `cnf` claim builder.

use sha2::{Digest, Sha256};

/// Compute the X.509 SHA-256 thumbprint (`x5t#S256`) from a DER-encoded cert.
/// This is the base64url-encoded SHA-256 hash of the DER bytes.
pub fn cert_thumbprint_sha256(der: &[u8]) -> String {
    use base64::Engine;
    let hash = Sha256::digest(der);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// Validate that the presented cert subject DN matches the registered DN.
pub fn validate_tls_client_auth(presented_dn: &str, registered_dn: &str) -> bool {
    // RFC 8705 : exact match, case-sensitive, no normalization.
    presented_dn == registered_dn
}

/// Validate that the presented cert thumbprint matches the registered thumbprint.
pub fn validate_self_signed_tls_client_auth(
    presented_thumbprint: &str,
    registered_thumbprint: &str,
) -> bool {
    presented_thumbprint == registered_thumbprint
}

/// Build the `cnf` (confirmation) claim for a sender-constrained access token.
/// Per RFC 8705 , the `cnf` claim contains `x5t#S256` — the SHA-256
/// thumbprint of the client certificate.
pub fn build_cnf_claim(cert_thumbprint: &str) -> serde_json::Value {
    serde_json::json!({
        "x5t#S256": cert_thumbprint
    })
}

/// Check if the token endpoint auth method is mTLS-based.
pub fn is_mtls_auth_method(method: &str) -> bool {
    method == "tls_client_auth" || method == "self_signed_tls_client_auth"
}

/// Resolve the mTLS client identity from headers.
///
///TLS passes the client cert metadata via headers:
/// - `X-Sentin8-Client-Cert-Thumbprint` — the x5t#S256 thumbprint
/// - `X-Sentin8-Client-Cert-Subject-DN` — the subject DN
///
/// Returns `Some(thumbprint, subject_dn)` when present.
pub fn extract_mtls_identity(headers: &axum::http::HeaderMap) -> Option<(String, Option<String>)> {
    let thumbprint = headers
        .get("x-sentin8-client-cert-thumbprint")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())?
        .to_string();
    let subject_dn = headers
        .get("x-sentin8-client-cert-subject-dn")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    Some((thumbprint, subject_dn))
}

///Validate the mTLS client cert for the `/mtls/oauth/token`
/// endpoint. Returns `Ok(thumbprint)` if the cert is present and valid.
///
/// This is called by the mTLS token endpoint wrapper before delegating to
/// the standard token handler. The thumbprint is used to add the `cnf`
/// claim to the issued access token (sender-constraining).
pub fn validate_mtls_for_token(
    headers: &axum::http::HeaderMap,
) -> Result<String, (axum::http::StatusCode, String)> {
    let (thumbprint, _subject_dn) = extract_mtls_identity(headers).ok_or_else(|| {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            "mTLS required: X-Sentin8-Client-Cert-Thumbprint header missing".to_string(),
        )
    })?;
    if thumbprint.is_empty() {
        return Err((
            axum::http::StatusCode::UNAUTHORIZED,
            "mTLS required: empty cert thumbprint".to_string(),
        ));
    }
    // mTLS alias guards read the thumbprint (mtls_token / mtls_revoke).
    Ok(thumbprint)
}

/// Extract the workload identity from the presented client certificate's
/// subject CN — the TLS layer injects `X-Sentin8-Client-Cert-Subject`
/// (best-effort CN from the DER) after CA-verifying the cert. Acme mints
/// platform client certs as `CN=m2m-{workload}`, so the CN IS the workload
/// name (auth design gate check 2). Returns the raw CN, which for
/// platform certs is the bare workload name (e.g. `m2m-auth-post`? no —
/// `m2m-` is the Acme-side prefix; the DCR client_name equals the full CN).
pub fn extract_cert_cn(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("x-sentin8-client-cert-subject")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_thumbprint_sha256_known() {
        // SHA-256 of empty bytes = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let t = cert_thumbprint_sha256(&[]);
        assert_eq!(t, "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
    }

    #[test]
    fn cert_thumbprint_is_base64url() {
        let t = cert_thumbprint_sha256(b"hello world");
        assert!(!t.contains('='));
        assert!(!t.contains('+'));
        assert!(!t.contains('/'));
    }

    #[test]
    fn validate_tls_client_auth_exact_match() {
        assert!(validate_tls_client_auth(
            "CN=client.example.com,O=Example,C=US",
            "CN=client.example.com,O=Example,C=US"
        ));
    }

    #[test]
    fn validate_tls_client_auth_mismatch() {
        assert!(!validate_tls_client_auth(
            "CN=client.example.com,O=Example,C=US",
            "CN=different.example.com,O=Example,C=US"
        ));
    }

    #[test]
    fn validate_self_signed_thumbprint() {
        assert!(validate_self_signed_tls_client_auth("abc123", "abc123"));
        assert!(!validate_self_signed_tls_client_auth("abc123", "xyz789"));
    }

    #[test]
    fn build_cnf_claim_has_x5t() {
        let cnf = build_cnf_claim("thumb123");
        assert_eq!(cnf["x5t#S256"], "thumb123");
    }

    #[test]
    fn is_mtls_auth_method_classifies() {
        assert!(is_mtls_auth_method("tls_client_auth"));
        assert!(is_mtls_auth_method("self_signed_tls_client_auth"));
        assert!(!is_mtls_auth_method("client_secret_basic"));
        assert!(!is_mtls_auth_method("none"));
    }

    #[test]
    fn extract_mtls_identity_from_headers() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-sentin8-client-cert-thumbprint",
            "thumb123".parse().unwrap(),
        );
        headers.insert(
            "x-sentin8-client-cert-subject-dn",
            "CN=test".parse().unwrap(),
        );
        let (thumb, dn) = extract_mtls_identity(&headers).unwrap();
        assert_eq!(thumb, "thumb123");
        assert_eq!(dn.as_deref(), Some("CN=test"));
    }

    #[test]
    fn extract_mtls_identity_missing_thumbprint() {
        let headers = axum::http::HeaderMap::new();
        assert!(extract_mtls_identity(&headers).is_none());
    }

    #[test]
    fn validate_mtls_for_token_ok() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-sentin8-client-cert-thumbprint",
            "thumb123".parse().unwrap(),
        );
        let result = validate_mtls_for_token(&headers);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "thumb123");
    }

    #[test]
    fn validate_mtls_for_token_missing() {
        let headers = axum::http::HeaderMap::new();
        let result = validate_mtls_for_token(&headers);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, axum::http::StatusCode::UNAUTHORIZED);
    }
}
