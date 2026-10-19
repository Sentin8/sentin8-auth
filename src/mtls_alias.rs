// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! mTLS endpoint aliases (RFC 8705) - .
//!
//! `/mtls/oauth/*` routes are cert-bound: Sentin8:TLS (with optional client
//! auth enabled) injects `X-Sentin8-Client-Cert-Thumbprint` after verifying
//! the presented certificate against the platform CA. These wrappers reject
//! requests without that header before delegating to the standard handlers,
//! so the mTLS aliases can never be exercised anonymously while `/oauth/*`
//! keeps its normal behavior.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;

use crate::handlers::AppState;
use crate::mtls;

/// Guard for the `/mtls/oauth/*` aliases: require a client-cert thumbprint
/// header (placed by `sentin8-tls` from the verified handshake certificate).
fn require_mtls_header(headers: &HeaderMap) -> Result<(), (axum::http::StatusCode, String)> {
    mtls::validate_mtls_for_token(headers).map(|_| ())
}

/// `POST /mtls/oauth/token` - the standard token handler behind a
/// client-certificate-presence guard. Delegates to `oauth::token` so
/// behavior is identical to `POST /oauth/token` apart from the guard.
#[utoipa::path(
    post,
    path = "/mtls/oauth/token",
    params(
        ("grant_type" = String, Query, description = "Client credentials grant (certificate-bound clients)"),
        ("scope" = String, Query, description = "Requested scope"),
    ),
    responses(
        (status = 200, description = "Token issued (identical contract to /oauth/token)", body = crate::oauth::TokenResponse),
        (status = 401, description = "invalid_client - no client certificate presented / thumbprint not registered"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn mtls_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    raw_body: axum::body::Bytes,
) -> Result<axum::response::Response, crate::oauth::TokenError> {
    if let Err((status, msg)) = require_mtls_header(&headers) {
        tracing::warn!(status = %status, "mtls alias: request without client certificate rejected");
        return Err(crate::oauth::TokenError::OAuth(
            crate::oauth::OAuthTokenError::with_desc(status, "invalid_client", msg),
        ));
    }
    crate::oauth::token(State(state), headers, raw_body)
        .await
        .map(|json| json.into_response())
}

/// `POST /mtls/oauth/revoke` - the standard revocation handler behind a
/// client-certificate-presence guard.
#[utoipa::path(
    post,
    path = "/mtls/oauth/revoke",
    params(
        ("token" = String, Query, description = "The token to revoke"),
        ("client_id" = String, Query, description = "Caller client"),
    ),
    responses(
        (status = 200, description = "Revoked (RFC 7009)"),
        (status = 401, description = "invalid_client - no verified client certificate"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn mtls_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Form(req): axum::Form<crate::oauth::RevokeRequest>,
) -> Result<axum::http::StatusCode, crate::oauth::TokenError> {
    if let Err((status, msg)) = require_mtls_header(&headers) {
        return Err(crate::oauth::TokenError::OAuth(
            crate::oauth::OAuthTokenError::with_desc(status, "invalid_client", msg),
        ));
    }
    crate::oauth::revoke(State(state), headers, axum::Form(req)).await
}
