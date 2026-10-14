// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Resource Indicators (RFC 8707)
//!
//! The `resource` parameter allows clients to request a specific resource
//! server (audience) for the access token. The authorization server must:
//! - Accept `resource` in the authorization request and token request.
//! - Include the resource as the `audience` in the issued access token.
//! - Reject if the `resource` is not in the client's allowed list.
//!
//! The `resource` is a URL identifying the resource server (e.g.
//! `https://api.example.com/v1`). Multiple `resource` parameters may be
//! sent; the AS picks one (or all) for the audience.

use axum::http::HeaderMap;

/// Parse the `resource` parameter (may be repeated → comma-separated or
/// multiple values in form data).
pub fn parse_resource_params(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|v| v.split_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Validate a single `resource` URI.
/// Must be an absolute URI (https or http scheme).
pub fn is_valid_resource_uri(resource: &str) -> bool {
    if resource.is_empty() {
        return false;
    }
    let colon = match resource.find(':') {
        Some(c) => c,
        None => return false,
    };
    let scheme = &resource[..colon];
    // Must be a valid scheme and start with a letter.
    if scheme.is_empty() {
        return false;
    }
    let first = scheme.chars().next().unwrap();
    first.is_ascii_alphabetic()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
}

/// Select the audience for the access token.
/// If `resources` is non-empty, the first one is the primary audience.
/// Additional resources are included in the `aud` claim.
pub fn select_audience(resources: &[String]) -> Option<String> {
    resources.first().cloned()
}

/// Resolve the tenant's resource indicator from the TLS `X-Sentin8-Resource`
/// header (set when the BFF proxies to Auth with a specific resource).
pub fn extract_resource_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-sentin8-resource")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_resource_params_single() {
        let v = parse_resource_params(&["https://api.example.com".into()]);
        assert_eq!(v, vec!["https://api.example.com"]);
    }

    #[test]
    fn parse_resource_params_multiple() {
        let v =
            parse_resource_params(&["https://api1.example.com https://api2.example.com".into()]);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], "https://api1.example.com");
        assert_eq!(v[1], "https://api2.example.com");
    }

    #[test]
    fn parse_resource_params_empty() {
        let v = parse_resource_params(&[]);
        assert!(v.is_empty());
    }

    #[test]
    fn is_valid_resource_uri_validates() {
        assert!(is_valid_resource_uri("https://api.example.com"));
        assert!(is_valid_resource_uri("http://localhost:8080"));
    }

    #[test]
    fn is_valid_resource_uri_invalid() {
        assert!(!is_valid_resource_uri(""));
        assert!(!is_valid_resource_uri("not a uri"));
        assert!(!is_valid_resource_uri("/relative/path"));
    }

    #[test]
    fn select_audience_first() {
        let a = select_audience(&[
            "https://api1.example.com".into(),
            "https://api2.example.com".into(),
        ]);
        assert_eq!(a.as_deref(), Some("https://api1.example.com"));
    }

    #[test]
    fn select_audience_empty() {
        assert!(select_audience(&[]).is_none());
    }

    #[test]
    fn extract_resource_header_parses() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-sentin8-resource",
            "https://api.example.com".parse().unwrap(),
        );
        assert_eq!(
            extract_resource_header(&headers).as_deref(),
            Some("https://api.example.com")
        );
    }

    #[test]
    fn extract_resource_header_missing() {
        let headers = HeaderMap::new();
        assert!(extract_resource_header(&headers).is_none());
    }
}
