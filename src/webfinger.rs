// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! OIDC Discovery §2.1 WebFinger (RFC 7033,
//! https://datatracker.ietf.org/doc/html/rfc7033) -
//! `GET /.well-known/webfinger`.
//!
//! The Dynamic OP conformance profile requires WebFinger: a relying party
//! discovers the issuer for a user identifier (`acct:`/email) before
//! registering. The response links the identifier to this tenant's issuer
//! with `rel = http://openid.net/specs/connect/1.0/issuer`
//! (DESIGN.md §9a).
//!
//! Tenant resolution rides the same TLS-injected hostname context as
//! every other public endpoint (the `X-Sentin8-*` headers set by
//! sentin8-tls) - the issuer in the response is host-derived, never
//! guessed from the resource parameter.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::handlers::AppState;

/// The `rel` value OIDC Discovery §2.1 mandates for the issuer link.
const OIDC_ISSUER_REL: &str = "http://openid.net/specs/connect/1.0/issuer";

/// WebFinger query parameters (RFC 7033 §4.1).
#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The webfingerquery type.
pub struct WebFingerQuery {
    /// The resource identifier - `acct:user@domain`, a bare email, or any
    /// absolute URI. Only its shape is validated; the user is NOT
    /// resolved (WebFinger must not become an account-existence oracle).
    /// The resource.
    pub resource: String,
    /// Optional `rel` filter (RFC 7033). When present, only links with a
    /// matching `rel` are returned; auth serves exactly one rel.
    /// The rel.
    pub rel: Option<String>,
}

/// RFC 7033 §4.4 JSON Resource Descriptor (JRD).
#[derive(Debug, Serialize, utoipa::ToSchema)]
/// The webfingerresponse type.
pub struct WebFingerResponse {
    /// The subject echoed back (`acct:…` form).
    /// The subject.
    pub subject: String,
    /// Links to the issuer for each requested rel.
    /// The links.
    pub links: Vec<WebFingerLink>,
}

/// One JRD link entry.
#[derive(Debug, Serialize, utoipa::ToSchema)]
/// The webfingerlink type.
pub struct WebFingerLink {
    /// The link relation type.
    /// The rel.
    pub rel: String,
    /// The target - this tenant's issuer URL.
    /// The href.
    pub href: String,
}

/// Normalize a resource parameter into the `acct:` form (RFC 7033 §3.1 +
/// OIDC Discovery §2.1): `acct:` URIs pass through; bare emails become
/// `acct:user@domain`; `mailto:` URIs become `acct:` of the same address;
/// any other URI is echoed unchanged (the caller decides what it means).
fn normalize_resource(resource: &str) -> String {
    if resource.starts_with("acct:") {
        return resource.to_string();
    }
    if let Some(rest) = resource.strip_prefix("mailto:") {
        return format!("acct:{rest}");
    }
    if resource.contains('@') && !resource.contains("://") {
        return format!("acct:{resource}");
    }
    resource.to_string()
}

/// Serve WebFinger (OIDC Discovery §2.1, DESIGN §9a).
///
/// # Errors
/// - `400` when `resource` is missing or unparsable.
/// - `404` when a `rel` filter names something other than the issuer rel.
///
/// The response never reveals whether the user exists: the same issuer
/// link is returned for any syntactically valid identifier at this
/// tenant's host.
#[utoipa::path(
    get,
    path = "/.well-known/webfinger",
    params(WebFingerQuery),
    responses(
        (status = 200, description = "JRD linking the identifier to this issuer", body = WebFingerResponse),
        (status = 400, description = "Missing or unparsable resource parameter"),
        (status = 404, description = "Unknown rel requested"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn webfinger(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<WebFingerQuery>,
) -> Result<Response, (StatusCode, String)> {
    // RFC 7033 §4.1 - the resource parameter is REQUIRED.
    let resource = q.resource.trim();
    if resource.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "resource parameter is required".into()));
    }

    // rel filter (RFC 7033 §4.3): only the OIDC issuer rel is served.
    if let Some(rel) = q.rel.as_deref() {
        if rel != OIDC_ISSUER_REL {
            return Err((
                StatusCode::NOT_FOUND,
                format!("unsupported rel: {rel}"),
            ));
        }
    }

    // Issuer resolution rides the same host context as discovery
    // (X-Sentin8-Hostname / Host header) - never derived from the
    // resource (that would let a caller steer the advertised issuer).
    let issuer = crate::oauth::resolve_issuer(&state.config, &headers);
    Ok((
        StatusCode::OK,
        [
            ("content-type", "application/jrd+json"),
            ("access-control-allow-origin", "*"),
        ],
        Json(WebFingerResponse {
            subject: normalize_resource(resource),
            links: vec![WebFingerLink {
                rel: OIDC_ISSUER_REL.to_string(),
                href: issuer,
            }],
        }),
    )
        .into_response())
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acct_resource_passes_through() {
        assert_eq!(
            normalize_resource("acct:alice@example.com"),
            "acct:alice@example.com"
        );
    }

    #[test]
    fn bare_email_becomes_acct() {
        assert_eq!(
            normalize_resource("alice@example.com"),
            "acct:alice@example.com"
        );
    }

    #[test]
    fn mailto_becomes_acct() {
        assert_eq!(
            normalize_resource("mailto:alice@example.com"),
            "acct:alice@example.com"
        );
    }

    #[test]
    fn absolute_uri_echoes_unchanged() {
        assert_eq!(
            normalize_resource("https://example.com/alice"),
            "https://example.com/alice"
        );
    }
}