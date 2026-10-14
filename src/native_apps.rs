// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! OAuth 2.0 for Native Apps — RFC 8252 .
//!
//! Native apps (mobile, desktop, CLI) must use PKCE and one of these
//! redirect_uri types:
//! - **Custom scheme** (e.g. `com.example.app:/oauth2redirect`)
//! - **Loopback** (`http://.1:{port}/callback` or `http://[::1]:{port}/callback`)
//!
//! Private-Use URI Scheme Redirections per RFC 8252 and the loopback
//! equivalence rule (any port is allowed for loopback redirects).

/// Parse the scheme of a URI (everything before the first ':').
fn parse_scheme(uri: &str) -> Option<String> {
    let colon = uri.find(':')?;
    let scheme = &uri[..colon];
    if scheme.is_empty() {
        return None;
    }
    let mut chars = scheme.chars();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    if chars.all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
        Some(scheme.to_ascii_lowercase())
    } else {
        None
    }
}

/// Parse host and path from an http:// URI (no URL crate needed).
fn parse_http_uri(uri: &str) -> Option<(String, String, Option<u16>)> {
    let after_scheme = uri.strip_prefix("http://")?;
    let (authority, path) = match after_scheme.find('/') {
        Some(i) => (&after_scheme[..i], &after_scheme[i..]),
        None => (after_scheme, "/"),
    };
    let (host, port) = if authority.starts_with('[') {
        // IPv6 — [::1]:port or [::1]
        if let Some(end) = authority.find(']') {
            let h = &authority[..=end];
            let p = authority[end + 1..]
                .strip_prefix(':')
                .and_then(|x| x.parse::<u16>().ok());
            (h, p)
        } else {
            return None;
        }
    } else {
        match authority.rfind(':') {
            Some(i) => (&authority[..i], authority[i + 1..].parse::<u16>().ok()),
            None => (authority, None),
        }
    };
    Some((host.to_string(), path.to_string(), port))
}

/// Validate a redirect URI for native apps (RFC 8252 ).
///
/// Native app redirect URIs must be one of:
/// 1. A custom scheme (non-`http`/`https`) — e.g. `com.example.app:/oauth2redirect`.
/// Must use the app's reverse-DNS-style scheme. NOT `http` or `https`.
/// 2. A loopback redirect — `http://.1:{port}/...` or `http://[::1]:{port}/...`.
/// Any port is accepted (loopback equivalence).
///
/// Returns `true` if the redirect_uri is valid for a native app.
pub fn is_valid_native_redirect_uri(uri: &str) -> bool {
    let Some(scheme) = parse_scheme(uri) else {
        return false;
    };
    // Custom scheme — non-http/non-https.
    if scheme != "http" && scheme != "https" {
        return true;
    }
    // Loopback redirect — must be http on.1 or [::1] or localhost.
    if scheme == "http" {
        if let Some((host, _path, _port)) = parse_http_uri(uri) {
            if host == "127.0.0.1" || host == "localhost" || host == "[::1]" {
                return true;
            }
        }
    }
    false
}

/// Check whether a redirect_uri is an exact match or a loopback variant.
/// Per RFC 8252 , the port is ignored for loopback comparisons: the
/// client registers `http://.1/callback` and uses any port at
/// runtime.
///
/// Returns `true` if the runtime redirect_uri matches the registered
/// redirect_uri under the loopback equivalence rule.
pub fn redirect_uri_matches(registered: &str, runtime: &str) -> bool {
    if registered == runtime {
        return true;
    }
    // Loopback equivalence: compare scheme + host + path, ignoring port.
    let reg = parse_http_uri(registered);
    let run = parse_http_uri(runtime);
    if let (Some((r_host, r_path, _)), Some((u_host, u_path, _))) = (reg, run) {
        if (r_host == "127.0.0.1" || r_host == "localhost" || r_host == "[::1]")
            && r_host == u_host
            && r_path == u_path
        {
            return true;
        }
    }
    false
}

/// Determine if a client is a public native client (no client_secret).
/// Public clients (application_type=native, token_endpoint_auth_method=none)
/// must use PKCE.
pub fn is_public_native_client(application_type: &str, auth_method: &str) -> bool {
    application_type == "native" && auth_method == "none"
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_scheme_valid() {
        assert!(is_valid_native_redirect_uri(
            "com.example.app:/oauth2redirect"
        ));
        assert!(is_valid_native_redirect_uri("myapp://callback"));
    }

    #[test]
    fn https_not_native() {
        assert!(!is_valid_native_redirect_uri(
            "https://example.com/callback"
        ));
    }

    #[test]
    fn loopback_ipv4_valid() {
        assert!(is_valid_native_redirect_uri(
            "http://127.0.0.1:8080/callback"
        ));
        assert!(is_valid_native_redirect_uri("http://127.0.0.1/callback"));
    }

    #[test]
    fn loopback_ipv6_valid() {
        assert!(is_valid_native_redirect_uri("http://[::1]:8080/callback"));
    }

    #[test]
    fn localhost_valid() {
        assert!(is_valid_native_redirect_uri(
            "http://localhost:8080/callback"
        ));
    }

    #[test]
    fn non_loopback_http_invalid() {
        assert!(!is_valid_native_redirect_uri("http://example.com/callback"));
        assert!(!is_valid_native_redirect_uri("http://10.0.0.1/callback"));
    }

    #[test]
    fn loopback_equivalence_ignores_port() {
        assert!(redirect_uri_matches(
            "http://127.0.0.1/callback",
            "http://127.0.0.1:8080/callback"
        ));
        assert!(redirect_uri_matches(
            "http://127.0.0.1/callback",
            "http://127.0.0.1/callback"
        ));
    }

    #[test]
    fn loopback_equivalence_path_must_match() {
        assert!(!redirect_uri_matches(
            "http://127.0.0.1/callback",
            "http://127.0.0.1:8080/different"
        ));
    }

    #[test]
    fn exact_custom_scheme_match() {
        assert!(redirect_uri_matches(
            "com.example.app:/oauth2redirect",
            "com.example.app:/oauth2redirect"
        ));
    }

    #[test]
    fn public_native_client_detection() {
        assert!(is_public_native_client("native", "none"));
        assert!(!is_public_native_client("web", "none"));
        assert!(!is_public_native_client("native", "client_secret_basic"));
    }

    #[test]
    fn parse_scheme_classifies() {
        assert_eq!(parse_scheme("http://x").as_deref(), Some("http"));
        assert_eq!(
            parse_scheme("com.example:/x").as_deref(),
            Some("com.example")
        );
        assert_eq!(parse_scheme("HTTPS://x").as_deref(), Some("https"));
        assert_eq!(parse_scheme("://x"), None);
    }
}
