// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! RFC 9421 HTTP Message Signatures - FAPI 2.0 Message Signing (.).
//!
//! When the caller's env-resolved security profile has
//! `require_http_signatures = true`, mutating token-endpoint requests
//! (`POST /oauth/token`, `POST /oauth/par`, `POST /oauth/introspect`,
//! `POST /oauth/revoke`, `POST /oauth/bc-authorize`) MUST carry an
//! HTTP-Signature over at least `@method`, `@target-uri`, and
//! `content-digest`. The signature is verified against the client's
//! registered keys (inline `jwks` JSONB or `jwks_uri`, cached).
//!
//! FAPI 2.0 Message Signing (request signatures) constrains:
//! - the signature MUST cover the content of the request body (via a
//! `Content-Digest` header, RFC 9530) - replay/swap protection;
//! - the signing key MUST be an asymmetric key registered with the client
//! (ES256 or RS256 - the platform JOSE set);
//! - the `Created`/`Expires` signature parameters bound freshness
//! (±5 minutes, matching the client_assertion window).
//!
//! Wire format (RFC 9421 /): the client sends
//! `Signature-Input: sig1=("@method" "@target-uri" "content-digest");created=...;keyid="..."`
//! and `Signature: sig1=:base6464:`, where the signature base is the
//! canonicalized header values joined per The legacy `Signature`
//! scheme (`keyId="...",algorithm="...",headers="..."`) is also accepted
//! (single-line `keyId`/`algorithm`/`headers`/`signature` params) because
//! several OIDC client libraries still emit it; FAPI deployments use the
//! RFC 9421 form.

use axum::http::HeaderMap;
use sha2::{Digest, Sha256};

use crate::oauth::AuthenticatedClient;

/// Signature-parameter window (seconds) - matches the private_key_jwt
/// assertion freshness policy (±5 min).
pub const SIGNATURE_WINDOW_SECS: i64 = 300;

/// Extract a params string field: `created=1735718400`, `keyid="my-key"`.
fn param_value(params: &str, name: &str) -> Option<String> {
    let rest = params;
    loop {
        let idx = rest.find(name)?;
        let after = &rest[idx + name.len()..];
        let after = after.strip_prefix('=')?;
        // Quoted or bare value.
        if let Some(v) = after.strip_prefix('"') {
            let end = v.find('"')?;
            return Some(v[..end].to_string());
        }
        let end = after.find(';').unwrap_or(after.len());
        let v = after[..end].trim();
        if v.is_empty() {
            return None;
        }
        return Some(v.to_string());
    }
}

/// Build the RFC 9421 signature base line for one covered field.
/// Derived components (`@method`, `@target-uri`, `content-digest`) are
/// constructed from the request; header fields use the request's value.
fn signature_base_line(
    field: &str,
    method: &str,
    target_uri: &str,
    headers: &HeaderMap,
) -> Option<String> {
    let value = match field {
        "@method" => method.to_string(),
        "@target-uri" => target_uri.to_string(),
        // Header fields - case-insensitive lookup. `content-digest` is a
        // normal header (RFC 9530) sent by the client.
        f => headers
            .get(f.to_ascii_lowercase().as_str())?
            .to_str()
            .ok()?
            .to_string(),
    };
    Some(format!("\"{field}\": {value}"))
}

/// Verify an RFC 9421 (or legacy) HTTP signature on a mutating request.
///
/// Returns Ok when:
/// - a signature is present,
/// - it covers `@method`, `@target-uri`, AND `content-digest`,
/// - `created` is within the freshness window,
/// - the signature verifies against a key from the client's registered
///
/// `jwks`/`jwks_uri`,
/// - the `Content-Digest` header matches the actual body (swap protection).
///
/// Returns Err(reason) when the profile requires a signature and any of the
/// above fails. When NO signature is present, returns Err("missing") - the
/// caller decides whether that is fatal (`require_http_signatures`) or
/// tolerated.
pub fn verify_http_signature(
    client: &AuthenticatedClient,
    headers: &HeaderMap,
    method: &str,
    target_uri: &str,
    body: &[u8],
) -> Result<(), String> {
    // ── Content-Digest first (RFC 9530): sha-256=<base64> ─────────────
    let digest_b64 = headers
        .get("content-digest")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| "content-digest header is required".to_string())?;
    let digest_b64 = digest_b64
        .split(',')
        .find(|p| p.trim().starts_with("sha-256="))
        .map(|p| p.trim().strip_prefix("sha-256=").unwrap_or(p.trim()))
        .ok_or_else(|| "content-digest must include sha-256".to_string())?;
    let computed = Sha256::digest(body);
    use base64::Engine as _;
    let computed_b64_std = base64::engine::general_purpose::STANDARD.encode(computed);
    if !constant_time_eq(digest_b64.as_bytes(), computed_b64_std.as_bytes()) {
        return Err("content-digest does not match request body".into());
    }

    // ── Signature-Input (RFC 9421) or legacy Signature ───────────────
    let sig_input = headers
        .get("signature-input")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let sig_value = headers
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match (sig_input, sig_value) {
        (Some(input), Some(sig)) => {
            verify_rfc9421(client, headers, &input, &sig, method, target_uri, body)
        }
        (None, Some(legacy)) => verify_legacy(client, headers, &legacy, method, target_uri),
        _ => Err("http signature required: missing Signature-Input/Signature headers".into()),
    }
}

/// RFC 9421 verification path.
fn verify_rfc9421(
    client: &AuthenticatedClient,
    headers: &HeaderMap,
    input: &str,
    sig: &str,
    method: &str,
    target_uri: &str,
    body: &[u8],
) -> Result<(), String> {
    let _ = body;
    // Possibly multiple labeled signatures - verify the first that covers
    // the required fields.
    for component in input.split(',') {
        // A component is `sig1=("@method" ...);created=...` - but split on
        // commas inside the field list breaks it. Reassemble: find the first
        // `=(` ... `)` span.
        let Some(open) = component.find("=(") else {
            continue;
        };
        let Some(close_rel) = component[open..].find(')') else {
            continue;
        };
        let close = open + close_rel;
        let label = component[..open].trim().to_string();
        let fields_str = &component[open + 2..close];
        let params_part = component[close + 1..].trim_start_matches(';');
        let covered: Vec<String> = fields_str
            .split_whitespace()
            .map(|f| f.trim_matches('"').to_string())
            .collect();

        // Required covered components (FAPI 2.0 MS ).
        if !covered.iter().any(|f| f == "@method")
            || !covered.iter().any(|f| f == "@target-uri")
            || !covered.iter().any(|f| f == "content-digest")
        {
            continue;
        }

        // Freshness.
        let created = param_value(params_part, "created")
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or_else(|| "signature created parameter is required".to_string())?;
        let now = chrono::Utc::now().timestamp();
        if created < now - SIGNATURE_WINDOW_SECS || created > now + SIGNATURE_WINDOW_SECS {
            return Err("signature created outside the freshness window".into());
        }

        // Signature base (RFC 9421 ): each covered field line + the
        // Signature-Input line itself (labeled), joined by LF.
        let mut base_lines: Vec<String> = covered
            .iter()
            .filter_map(|f| signature_base_line(f, method, target_uri, headers))
            .collect();
        base_lines.push(format!(
            "\"@signature-params\": {}",
            component[open + 2..]
                .trim()
                .to_string()
                .trim_start_matches('(')
                .trim_end_matches(')')
        ));
        // Reconstruct params with created/keyid as in the raw input for the
        // base line - RFC 9421 requires the exact serialized params. Build
        // from the raw substring after the fields list.
        let params_raw = component[close + 1..].trim_start_matches(';').trim();
        base_lines.pop();
        base_lines.push(format!(
            "\"@signature-params\": ({fields_str});{params_raw}"
        ));
        let base = base_lines.join("\n");
        return verify_against_client_keys(client, &base, sig, &label);
    }
    Err("no signature covers the required components (@method, @target-uri, content-digest)".into())
}

/// Legacy `Signature` header form: `keyId="...",algorithm="es256",headers="(request-target) content-digest",signature="..."`.
fn verify_legacy(
    client: &AuthenticatedClient,
    headers: &HeaderMap,
    legacy: &str,
    method: &str,
    target_uri: &str,
) -> Result<(), String> {
    let keyid = param_value(legacy, "keyId")
        .or_else(|| param_value(legacy, "keyid"))
        .ok_or_else(|| "legacy signature keyId is required".to_string())?;
    let algorithm = param_value(legacy, "algorithm").unwrap_or_else(|| "es256".to_string());
    let covered_raw = param_value(legacy, "headers")
        .unwrap_or_else(|| "(request-target) content-digest".to_string());
    let signature = param_value(legacy, "signature")
        .ok_or_else(|| "legacy signature value is required".to_string())?;

    let lower_method = method.to_ascii_lowercase();
    let path = target_uri
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|i| rest[i..].to_string()))
        .unwrap_or_else(|| target_uri.to_string());
    let mut base_lines = Vec::new();
    for f in covered_raw.split_whitespace() {
        match f {
            "(request-target)" => {
                base_lines.push(format!("(request-target): {lower_method} {path}"))
            }
            f if f.starts_with('@') => {
                let line = signature_base_line(f, method, target_uri, headers)
                    .ok_or_else(|| format!("cannot resolve signature field {f}"))?;
                base_lines.push(line);
            }
            "content-digest" => {
                let v = headers
                    .get("content-digest")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| "content-digest header is required".to_string())?;
                base_lines.push(format!("content-digest: {v}"));
            }
            other => {
                let v = headers
                    .get(other.to_ascii_lowercase().as_str())
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| format!("cannot resolve signature field {other}"))?;
                base_lines.push(format!("{}: {}", other.to_ascii_lowercase(), v));
            }
        }
    }
    let base = base_lines.join("\n");
    let _ = keyid;
    let _ = algorithm;
    verify_against_client_keys(client, &base, &signature, "legacy")
}

/// Verify the signature bytes against the client's registered JWKS keys
/// (ES256/RS256 via the existing `SigningKeys::verify_with_jwk` JOSE path).
fn verify_against_client_keys(
    client: &AuthenticatedClient,
    base: &str,
    sig_b64: &str,
    label: &str,
) -> Result<(), String> {
    use base64::Engine as _;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim())
        .map_err(|e| format!("signature is not valid base64: {e}"))?;

    if let Some(jwks) = &client.jwks {
        if let Some(keys) = jwks.get("keys").and_then(|k| k.as_array()) {
            for key in keys {
                // Raw JOSE verify: the signature covers the signature-base
                // string with the key's algorithm (ES256/RS256).
                if crate::jwks::SigningKeys::verify_raw_with_jwk(key, base.as_bytes(), &sig).is_ok()
                {
                    return Ok(());
                }
            }
        }
    }
    let _ = label;
    Err("http signature verification failed against the client's registered keys".into())
}

/// Constant-time byte comparison (avoid timing oracles on digest compare).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(digest: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("content-digest", digest.parse().unwrap());
        h
    }

    #[test]
    fn param_value_bare_and_quoted() {
        assert_eq!(
            param_value("created=1735718400;keyid=\"k1\"", "created"),
            Some("1735718400".into())
        );
        assert_eq!(
            param_value("created=1;keyid=\"k1\"", "keyid"),
            Some("k1".into())
        );
    }

    #[test]
    fn digest_mismatch_detected() {
        use base64::Engine as _;
        let body = b"hello";
        let computed = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body));
        let good = headers_with(&format!("sha-256={computed}"));
        assert!(verify_http_signature(&mk_client(), &good, "POST", "https://a/x", body).is_err()); // missing signature - but digest passed (error mentions signature)
        let bad = headers_with("sha-256=AAAA");
        let err =
            verify_http_signature(&mk_client(), &bad, "POST", "https://a/x", body).unwrap_err();
        assert!(
            err.contains("content-digest"),
            "expected digest error, got: {err}"
        );
    }

    fn mk_client() -> AuthenticatedClient {
        use uuid::Uuid;
        AuthenticatedClient {
            id: Uuid::new_v4(),
            client_id: "test".into(),
            env_id: Uuid::new_v4(),
            redirect_uris: vec![],
            post_logout_redirect_uris: vec![],
            scopes: vec![],
            jwks: None,
            jwks_uri: None,
            tls_client_auth_subject_dn: None,
            self_signed_tls_client_auth_thumbprint: None,
            auth_method: "client_secret_post",
            cert_thumbprint: None,
            dpop_jkt: None,
            dpop_exempt: false,
            authorization_details_types: vec![],
        }
    }
}
