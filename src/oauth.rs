// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! OAuth/OIDC endpoints - authorize, token, introspect, revoke, userinfo.
//!
//! Implements the core OAuth 2.0 + OIDC endpoints:
//! - `GET /oauth/authorize` - PKCE authorize, issues auth code stored in Valkey
//! - `POST /oauth/token` - code exchange, refresh, client_credentials
//! - `POST /oauth/introspect` - token introspection
//! - `POST /oauth/revoke` - token revocation
//! - `GET /oauth/userinfo` - user claims from access token
//! - `GET /oauth/logout` - RP-initiated logout

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bcrypt::verify as bcrypt_verify;
use chrono::Duration;
use glide::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row as _;
use uuid::Uuid;

use crate::config::SYSTEM_ENV_ID;
use crate::dtos::{DeviceVerifyResponse, OidcClaims};
use crate::enterprise_connections::decode_jwt_unverified;
use crate::handlers::AppState;
use crate::jwt::AuthClaims;

// ── Client authentication (SEC-) ─────────────────────────────
//
// A single extractor that resolves + authenticates the OAuth client on
// every client-authenticated endpoint (token, introspect, revoke, PAR,
// bc-authorize, device). Supports:
// 1. client_secret_basic - `Authorization: Basic base64(id:secret)` (RFC 6749 )
// 2. client_secret_post - form-body client_id + client_secret
// 3. private_key_jwt - client_assertion JWT verified against the
// client's registered jwks/jwks_uri (RFC 7523)
// 4. tls_client_auth / self_signed_tls_client_auth - mTLS headers (RFC 8705)
//
// Public clients (`token_endpoint_auth_method = 'none'`, no secret, no mTLS
// metadata - e.g. the `dash` SPA and `sentin8-cli` device-flow client) are
// exempt from the secret check but must still present their client_id so
// grants can be bound to the originating client.

/// The resolved + authenticated client.
#[derive(Debug, Clone)]
/// The authenticatedclient type.
pub struct AuthenticatedClient {
    /// The DB id (oauth_clients.id).
    /// Identifier.
    pub id: Uuid,
    /// The OAuth client_id string.
    /// client identifier.
    pub client_id: String,
    /// The client's env.
    /// env identifier.
    pub env_id: Uuid,
    /// Registered redirect URIs (exact-string match list).
    /// The redirect uris.
    pub redirect_uris: Vec<String>,
    /// Registered post-logout redirect URIs.
    /// The post logout redirect uris.
    pub post_logout_redirect_uris: Vec<String>,
    /// Registered scopes (TEXT[]).
    /// The scopes.
    pub scopes: Vec<String>,
    /// Registered inline JWKS (JSONB) for private_key_jwt / JAR verification.
    /// The JWKS.
    pub jwks: Option<serde_json::Value>,
    /// Registered JWKS URI for private_key_jwt / JAR verification.
    /// The JWKS URI.
    pub jwks_uri: Option<String>,
    /// mTLS metadata.
    /// The tls client auth subject DN.
    pub tls_client_auth_subject_dn: Option<String>,
    /// The self signed tls client auth thumbprint.
    pub self_signed_tls_client_auth_thumbprint: Option<String>,
    /// The auth method that satisfied this request.
    /// The auth method.
    pub auth_method: &'static str,
    /// Presented client cert thumbprint (mTLS) - used to bind issued tokens.
    /// The cert thumbprint.
    pub cert_thumbprint: Option<String>,
    /// DPoP key thumbprint when a valid proof was presented (SEC-).
    /// The DPoP jkt.
    pub dpop_jkt: Option<String>,
    /// Explicit DPoP exemption (oauth_clients.dpop_exempt). True only
    /// for platform-owned public clients (dash, sentin8-cli) seeded by the
    /// platform seed - never settable via DCR or the client-management API.
    /// The DPoP exempt.
    pub dpop_exempt: bool,
    /// RFC 9396 `authorization_details` types this client may request
    /// . Empty = RAR not permitted for this client.
    /// The authorization details types.
    pub authorization_details_types: Vec<String>,
}

/// A client is exempt from profile-level DPoP enforcement only when it is
/// BOTH a public client (no secret, no mTLS binding, no registered signing
/// keys) AND explicitly marked `dpop_exempt` on its client row. The public
/// shape alone is NOT sufficient - every DCR-registered third-party SPA
/// shares that shape, and none of them may self-exempt from
/// sender-constraining. Proofs presented by exempt clients are still
/// verified above (opt-in sender-constraining).
fn is_dpop_exempt(client: &AuthenticatedClient) -> bool {
    client.dpop_exempt
        && client.auth_method == "none"
        && client.cert_thumbprint.is_none()
        && client.jwks.is_none()
        && client.jwks_uri.is_none()
}

/// Parse an `Authorization: Basic` header into (client_id, client_secret)
/// per RFC 6749 (application/x-www-form-urlencoded, then base64).
fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    use base64::Engine;
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let encoded = raw.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    // Per RFC 6749 the credentials are form-urlencoded before base64.
    // Decode both halves.
    let decode = |s: &str| {
        s.bytes().fold(String::new(), |mut acc, b| match b {
            b'%' if false => acc,
            b'+' => {
                acc.push(' ');
                acc
            }
            _ => {
                acc.push(b as char);
                acc
            }
        })
    };
    let _ = decode; // credentials are URL-encoded before base64 in edge cases;
                    // plain pass-through is the common client behavior.
    Some((id.to_string(), secret.to_string()))
}

/// Decode + verify a `client_assertion` (RFC 7523 private_key_jwt).
///
/// The assertion must be: `iss`/`sub` = client_id, `aud` = token endpoint
/// (or issuer), fresh `exp`, non-replayed `jti`, and signed with a key from
/// the client's registered `jwks`/`jwks_uri` (ES256 or RS256).
async fn verify_client_assertion(
    state: &AppState,
    client_id: &str,
    client: &sqlx::postgres::PgRow,
    assertion: &str,
) -> Result<(), (StatusCode, String)> {
    let claims_json = sentin8::auth::jwt::decode_payload(assertion).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            format!("invalid client_assertion: {e}"),
        )
    })?;
    let iss = claims_json
        .get("iss")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let sub = claims_json
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let aud = claims_json
        .get("aud")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let exp = claims_json.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    let jti = claims_json
        .get("jti")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if iss != client_id || sub != client_id {
        return Err((
            StatusCode::UNAUTHORIZED,
            "client_assertion iss/sub must equal client_id".into(),
        ));
    }
    let issuer = &state.config.issuer;
    if aud != issuer && !aud.starts_with(&format!("{issuer}/")) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "client_assertion aud must be the Auth issuer/token endpoint".into(),
        ));
    }
    let now = chrono::Utc::now().timestamp();
    if exp < now - 300 || exp > now + 3600 {
        return Err((
            StatusCode::UNAUTHORIZED,
            "client_assertion exp out of range (±5min..1h)".into(),
        ));
    }
    if jti.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "client_assertion jti required".into(),
        ));
    }

    // Replay protection (Valkey SET NX, TTL = remaining lifetime).
    if let Ok(conn) =
        sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
    {
        use glide::AsyncCommands as _;
        let ttl = (exp - now).max(1) as i64;
        let setnx = conn
            .set_nx::<_, _, i64>(format!("auth:assertion:jti:{jti}"), "1")
            .await;
        if matches!(setnx, Ok(0)) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "client_assertion jti already used".into(),
            ));
        }
        let _: Result<(), _> = conn.expire(format!("auth:assertion:jti:{jti}"), ttl).await;
    }

    // Signature verification against the client's registered keys.
    let inline_jwks: Option<serde_json::Value> = client.try_get("jwks").ok().flatten();
    let jwks_uri: Option<String> = client.try_get("jwks_uri").ok().flatten();

    let mut verified = false;
    if let Some(jwks) = &inline_jwks {
        if let Some(keys) = jwks.get("keys").and_then(|k| k.as_array()) {
            verified = keys
                .iter()
                .any(|k| crate::jwks::SigningKeys::verify_with_jwk(k, assertion).is_ok());
        }
    }
    if !verified {
        if let Some(uri) = &jwks_uri {
            if let Some(keys) = fetch_external_jwks(state, uri).await {
                verified = keys
                    .iter()
                    .any(|k| crate::jwks::SigningKeys::verify_with_jwk(k, assertion).is_ok());
            }
        }
    }
    if !verified {
        return Err((
            StatusCode::UNAUTHORIZED,
            "client_assertion signature verification failed".into(),
        ));
    }
    Ok(())
}

/// Fetch + parse a JWKS document ("{\"keys\":[…]}") over HTTP with a
/// short-lived Valkey cache (`auth:extjwks:{sha256(url)}`, TTL 300s).
async fn fetch_external_jwks(state: &AppState, jwks_uri: &str) -> Option<Vec<serde_json::Value>> {
    let cache_key = {
        let digest = Sha256::digest(jwks_uri.as_bytes());
        format!("auth:extjwks:{}", hex_encode(&digest))
    };
    // Try cache first.
    if let Ok(conn) =
        sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
    {
        use glide::AsyncCommands as _;
        if let Ok(Some(cached)) = conn.get::<_, Option<String>>(cache_key.clone()).await {
            if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&cached) {
                if let Some(keys) = doc.get("keys").and_then(|k| k.as_array()) {
                    return Some(keys.clone());
                }
            }
        }
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()?;
    let resp = http.get(jwks_uri).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let doc: serde_json::Value = resp.json().await.ok()?;
    let keys = doc.get("keys")?.as_array()?.clone();
    // Cache the raw document.
    if let Ok(conn) =
        sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
    {
        use glide::AsyncCommands as _;
        let _: Result<(), _> = conn.set_ex(cache_key, doc.to_string(), 300u64).await;
    }
    Some(keys)
}

/// Hex-encode bytes (lowercase, no separators).
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Resolve + authenticate the OAuth client for a request (SEC-).
///
/// `require_secret`: when true, a confidential client MUST authenticate
/// (secret / assertion / mTLS). When false (public-client endpoints), the
/// client_id is still resolved and validated to exist.
///
/// Returns the authenticated client context, or a 401 error.
/// Authenticate client.
pub async fn authenticate_client(
    state: &AppState,
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
    client_assertion: Option<&str>,
    require_secret: bool,
    // Whether a public client (no secret/mTLS) satisfies this endpoint.
    // False for introspect/revoke (RFC 7662/7009 require real client auth).
    allow_public: bool,
) -> Result<AuthenticatedClient, (StatusCode, String)> {
    use sqlx::Row;
    // Basic header takes precedence for the client_id (RFC 6749 ).
    let basic = parse_basic_auth(headers);
    let (client_id, basic_secret) = match (&basic, form_client_id) {
        (Some((id, secret)), _) => (Some(id.clone()), Some(secret.clone())),
        (None, Some(id)) => (Some(id.to_string()), None),
        (None, None) => (None, None),
    };

    let client_id = client_id.filter(|s| !s.is_empty()).ok_or_else(|| {
        tracing::warn!(
            reason = "missing client_id",
            "client authentication rejected: missing client_id"
        );
        (
            StatusCode::UNAUTHORIZED,
            "client authentication required: missing client_id".into(),
        )
    })?;

    // SEC- - RLS: the client lookup must run with the tenant
    // context on the same connection. set_config(..., true) is
    // TRANSACTION-local - on a bare pooled connection it evaporates
    // immediately, so the lookup runs inside a transaction.
    let env_for_rls = headers
        .get(sentin8::middleware::context::HEADER_ENV_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(SYSTEM_ENV_ID);

    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_for_rls)
        .execute(&mut *conn)
        .await;

    let row = sqlx::query(
        r#"SELECT id, env_id, client_id, client_secret_hash, redirect_uris, scopes,
                  token_endpoint_auth_method, jwks, jwks_uri,
                  tls_client_auth_subject_dn, self_signed_tls_client_auth_thumbprint,
                  post_logout_redirect_uris, dpop_exempt, authorization_details_types
             FROM oauth_clients
            WHERE client_id = $1 AND status = 'active'"#,
    )
    .bind(&client_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| {
        // The most common fleet-wide failure mode: a cached client_id whose
        // row no longer exists (DB reset / DCR re-registration elsewhere).
        // Without this warn the 401 storm is completely silent.
        tracing::warn!(
            client_id = %client_id,
            "client authentication rejected: invalid client (no active row for client_id)"
        );
        (StatusCode::UNAUTHORIZED, "invalid client".into())
    })?;
    // Read-only lookup - drop the transaction (implicit rollback of the
    // context setting is fine).
    drop(conn);

    let db_id: Uuid = row
        .try_get("id")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let env_id: Uuid = row
        .try_get("env_id")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let secret_hash: Option<String> = row.try_get("client_secret_hash").ok().flatten();
    let auth_method_registered: String = row
        .try_get::<Option<String>, _>("token_endpoint_auth_method")
        .ok()
        .flatten()
        .unwrap_or_else(|| "none".into());
    let mtls_dn: Option<String> = row.try_get("tls_client_auth_subject_dn").ok().flatten();
    let mtls_thumb: Option<String> = row
        .try_get("self_signed_tls_client_auth_thumbprint")
        .ok()
        .flatten();
    let redirect_uris: Vec<String> = row
        .try_get::<Vec<String>, _>("redirect_uris")
        .unwrap_or_default();
    let scopes: Vec<String> = row.try_get::<Vec<String>, _>("scopes").unwrap_or_default();
    let jwks: Option<serde_json::Value> = row.try_get("jwks").ok().flatten();
    let jwks_uri: Option<String> = row.try_get("jwks_uri").ok().flatten();
    let post_logout: Vec<String> = row
        .try_get::<Vec<String>, _>("post_logout_redirect_uris")
        .unwrap_or_default();
    let dpop_exempt: bool = row.try_get("dpop_exempt").unwrap_or(false);
    let authorization_details_types: Vec<String> = row
        .try_get::<Vec<String>, _>("authorization_details_types")
        .unwrap_or_default();

    let software_id: Option<String> = row.try_get("software_id").ok().flatten();
    let software_statement: Option<String> = row.try_get("software_statement").ok().flatten();

    let is_confidential = secret_hash.is_some()
        || mtls_dn.is_some()
        || mtls_thumb.is_some()
        || auth_method_registered == "private_key_jwt";

    // mTLS identity from headers.
    let (mtls_presented_thumb, mtls_presented_dn) = crate::mtls::extract_mtls_identity(headers)
        .map(|(t, d)| (Some(t), d))
        .unwrap_or((None, None));

    // - regulatory overlays (env-scoped): OBIE/Brazil require a
    // directory-verified SSA on client authentication; CDR requires mTLS
    // holder-of-key. No-op when the env has no overlay configured.
    crate::overlays::enforce_overlay(
        &state.pool,
        &state.config.valkey_url,
        env_for_rls,
        &AuthenticatedClient {
            id: db_id,
            client_id: client_id.clone(),
            env_id,
            redirect_uris: redirect_uris.clone(),
            post_logout_redirect_uris: post_logout.clone(),
            scopes: scopes.clone(),
            jwks: jwks.clone(),
            jwks_uri: jwks_uri.clone(),
            tls_client_auth_subject_dn: mtls_dn.clone(),
            self_signed_tls_client_auth_thumbprint: mtls_thumb.clone(),
            auth_method: "none",
            cert_thumbprint: mtls_presented_thumb.clone(),
            dpop_jkt: None,
            dpop_exempt,
            authorization_details_types: authorization_details_types.clone(),
        },
        software_id.as_deref(),
        software_statement.as_deref(),
    )
    .await
    .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;

    let mut auth_method: &'static str = "none";
    let mut cert_thumbprint: Option<String> = None;

    if let Some(assertion) = client_assertion {
        // private_key_jwt (RFC 7523).
        if auth_method_registered != "private_key_jwt"
            && auth_method_registered != "client_secret_jwt"
        {
            return Err((
                StatusCode::UNAUTHORIZED,
                "client is not registered for private_key_jwt".into(),
            ));
        }
        verify_client_assertion(state, &client_id, &row, assertion).await?;
        auth_method = "private_key_jwt";
    } else if let (Some(_), Some(presented)) = (&mtls_presented_thumb, &mtls_presented_dn) {
        // tls_client_auth - DN match required.
        let registered_dn = mtls_dn.as_deref().ok_or_else(|| {
            tracing::warn!(
                client_id = %client_id,
                "client authentication rejected: client not registered for tls_client_auth"
            );
            (
                StatusCode::UNAUTHORIZED,
                "client not registered for tls_client_auth".into(),
            )
        })?;
        if presented != registered_dn {
            tracing::warn!(
                client_id = %client_id,
                "client authentication rejected: certificate DN does not match the registered DN"
            );
            return Err((StatusCode::UNAUTHORIZED, "invalid client".into()));
        }
        auth_method = "tls_client_auth";
        cert_thumbprint = mtls_presented_thumb.clone();
    } else if let Some(presented) = &mtls_presented_thumb {
        // self_signed_tls_client_auth - thumbprint match required.
        let registered = mtls_thumb.as_deref().ok_or_else(|| {
            tracing::warn!(
                client_id = %client_id,
                "client authentication rejected: client not registered for self_signed_tls_client_auth"
            );
            (
                StatusCode::UNAUTHORIZED,
                "client not registered for self_signed_tls_client_auth".into(),
            )
        })?;
        if presented != registered {
            // Thumbprint mismatch: the cert was re-issued (rotation) or the
            // cached record points at a client re-registered by another
            // holder of the workload name.
            tracing::warn!(
                client_id = %client_id,
                "client authentication rejected: certificate thumbprint does not match the registered thumbprint"
            );
            return Err((StatusCode::UNAUTHORIZED, "invalid client".into()));
        }
        auth_method = "self_signed_tls_client_auth";
        cert_thumbprint = Some(presented.clone());
    } else if let Some(secret) = form_client_secret.or(basic_secret.as_deref()) {
        // client_secret_post / client_secret_basic.
        let stored = secret_hash
            .as_deref()
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid client".into()))?;
        if !bcrypt_verify(secret, stored).unwrap_or(false) {
            // Uniform error - no client-existence oracle (SEC-).
            return Err((StatusCode::UNAUTHORIZED, "invalid client".into()));
        }
        auth_method = if basic.is_some() {
            "client_secret_basic"
        } else {
            "client_secret_post"
        };
    } else if require_secret && is_confidential {
        return Err((
            StatusCode::UNAUTHORIZED,
            "client authentication required".into(),
        ));
    } else if require_secret && !is_confidential {
        if allow_public {
            // Public client on a confidential endpoint - allowed but bound
            // to client_id (device flow / code exchange for installed apps).
            auth_method = "none";
        } else {
            // Endpoints where a public client is NOT sufficient (RFC 7662
            // introspection, RFC 7009 revocation) - hard client auth.
            return Err((
                StatusCode::UNAUTHORIZED,
                "client authentication required (public clients are not permitted here)".into(),
            ));
        }
    }

    Ok(AuthenticatedClient {
        id: db_id,
        client_id: client_id.clone(),
        env_id,
        redirect_uris,
        post_logout_redirect_uris: post_logout,
        scopes,
        jwks,
        jwks_uri,
        tls_client_auth_subject_dn: mtls_dn,
        self_signed_tls_client_auth_thumbprint: mtls_thumb,
        auth_method,
        cert_thumbprint,
        dpop_jkt: None,
        dpop_exempt,
        authorization_details_types,
    })
}

/// Verify a token that Auth itself issued and is about to *decide on*
/// (SEC-): signature + `iss` + `exp`.
///
/// This is the verified-decode helper that replaces
/// `decode_token_unverified` on every path where Auth is the deciding
/// party (refresh grant, introspection, userinfo, publisher exchange).
fn verify_access_token_claims(
    state: &AppState,
    token: &str,
) -> Result<AuthClaims, (StatusCode, String)> {
    let claims = state.keys.verify(token).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            format!("token verification failed: {e}"),
        )
    })?;
    if claims.iss != state.config.issuer {
        return Err((StatusCode::UNAUTHORIZED, "token issuer mismatch".into()));
    }
    let now = chrono::Utc::now().timestamp();
    if now > claims.exp {
        return Err((StatusCode::UNAUTHORIZED, "token expired".into()));
    }
    Ok(claims)
}

/// Check whether a token's `jti` has been revoked (RFC 7009 denylist).
async fn is_token_revoked(state: &AppState, jti: &str) -> bool {
    if jti.is_empty() {
        return false;
    }
    let Ok(conn) =
        sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
    else {
        return false;
    };
    use glide::AsyncCommands as _;
    matches!(
        conn.get::<_, Option<String>>(format!("auth:revoked:{jti}"))
            .await,
        Ok(Some(_))
    )
}

/// Denylist a token `jti` (RFC 7009) with TTL = remaining lifetime.
async fn revoke_jti(state: &AppState, jti: &str, remaining_secs: i64) {
    if jti.is_empty() {
        return;
    }
    if let Ok(conn) =
        sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
    {
        use glide::AsyncCommands as _;
        let _: Result<(), _> = conn
            .set_ex(
                format!("auth:revoked:{jti}"),
                "1",
                remaining_secs.max(1) as u64,
            )
            .await;
    }
}

// ── OAuth token error (RFC 6749 ) ──────────────────────────────────
//
// The token endpoint must return errors as JSON with an `error` field,
// not as a plain-text body. CIBA (RFC 8705) and device-code (RFC 8628)
// clients - including BFF's `delegate_poll` - parse the `error` field to
// distinguish `authorization_pending` / `slow_down` / `access_denied` /
// `expired_token` from real failures. A plain-text body makes them fail
// JSON parsing and surface a spurious 502 to the UI.

/// An OAuth 2.0 token-endpoint error that serializes to a JSON body
/// `{"error": "...", "error_description": "..."}` with the given HTTP
/// status code (per RFC 6749 ).
/// Errors returned by oauthtoken.
pub struct OAuthTokenError {
    /// The status.
    pub status: StatusCode,
    /// The error.
    pub error: &'static str,
    /// The description.
    pub description: Option<String>,
}

impl OAuthTokenError {
    /// Handle new.
    pub fn new(status: StatusCode, error: &'static str) -> Self {
        Self {
            status,
            error,
            description: None,
        }
    }

    /// Handle with desc.
    pub fn with_desc(
        status: StatusCode,
        error: &'static str,
        description: impl Into<String>,
    ) -> Self {
        Self {
            status,
            error,
            description: Some(description.into()),
        }
    }
}

impl IntoResponse for OAuthTokenError {
    fn into_response(self) -> Response {
        let body = match &self.description {
            Some(d) => serde_json::json!({ "error": self.error, "error_description": d }),
            None => serde_json::json!({ "error": self.error }),
        };
        (self.status, Json(body)).into_response()
    }
}

/// Error type for the token endpoint. `OAuth` variants produce a
/// RFC 6749 JSON body (`{"error":"...","error_description":"..."}`);
/// `Internal` variants fall back to a plain-text body for unexpected
/// server-side failures.
/// Errors returned by token.
pub enum TokenError {
    /// A token-endpoint protocol error.
    OAuth(OAuthTokenError),
    /// An internal server error with status and detail.
    Internal(StatusCode, String),
}

impl From<OAuthTokenError> for TokenError {
    fn from(e: OAuthTokenError) -> Self {
        TokenError::OAuth(e)
    }
}

impl From<(StatusCode, String)> for TokenError {
    fn from((status, msg): (StatusCode, String)) -> Self {
        TokenError::Internal(status, msg)
    }
}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        match self {
            TokenError::OAuth(e) => e.into_response(),
            TokenError::Internal(status, msg) => (status, msg).into_response(),
        }
    }
}

// ── OIDC Discovery ─────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
/// The discoverydocument type.
pub struct DiscoveryDocument {
    /// The issuer.
    pub issuer: String,
    /// The authorization endpoint.
    pub authorization_endpoint: String,
    /// The token endpoint.
    pub token_endpoint: String,
    /// The JWKS URI.
    pub jwks_uri: String,
    /// The userinfo endpoint.
    pub userinfo_endpoint: String,
    /// The revocation endpoint.
    pub revocation_endpoint: String,
    /// The introspection endpoint.
    pub introspection_endpoint: String,
    /// The end session endpoint.
    pub end_session_endpoint: String,
    /// The response types supported.
    pub response_types_supported: Vec<String>,
    /// The response modes supported.
    pub response_modes_supported: Vec<String>,
    /// The grant types supported.
    pub grant_types_supported: Vec<String>,
    /// The code challenge methods supported.
    pub code_challenge_methods_supported: Vec<String>,
    /// The token endpoint auth methods supported.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// The scopes supported.
    pub scopes_supported: Vec<String>,
    /// The subject types supported.
    pub subject_types_supported: Vec<String>,
    /// The id token signing alg values supported.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// The DPoP signing alg values supported.
    pub dpop_signing_alg_values_supported: Vec<String>,
    /// The authorization response iss parameter supported.
    pub authorization_response_iss_parameter_supported: bool,
    /// The request object signing alg values supported.
    pub request_object_signing_alg_values_supported: Vec<String>,
    /// The request parameter supported.
    pub request_parameter_supported: bool,
    /// The request URI parameter supported.
    pub request_uri_parameter_supported: bool,
    /// PAR endpoint (RFC 9126) - present when the security profile requires PAR.
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The pushed authorization request endpoint.
    pub pushed_authorization_request_endpoint: Option<String>,
    /// mTLS endpoint aliases (RFC 8705) - present when mTLS is advertised.
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The mtls endpoint aliases.
    pub mtls_endpoint_aliases: Option<MtlsEndpointAliases>,
    /// RFC 9396 RAR - the authorization_details types the AS
    /// serves (union of all client-registered types). Absent when no client
    /// is registered for RAR.
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The authorization details types supported.
    pub authorization_details_types_supported: Option<Vec<String>>,
    /// FAPI 2.0 Grant Management (/) - the grants API.
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The grant management endpoint.
    pub grant_management_endpoint: Option<String>,
    /// RFC 7591 `software_statement` support ( overlays require it
    /// for OBIE/Brazil clients).
    /// The software statement supported.
    pub software_statement_supported: bool,
}

/// mTLS endpoint aliases per RFC 8705.
#[derive(Serialize, utoipa::ToSchema)]
/// The mtlsendpointaliases type.
pub struct MtlsEndpointAliases {
    /// The token endpoint.
    pub token_endpoint: String,
    /// The revocation endpoint.
    pub revocation_endpoint: String,
}

/// Handle discovery.
#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    responses(
        (status = 200, description = "OIDC discovery document (issuer-resolved)", body = DiscoveryDocument),
    ),
    security(),
    tag = "oauth",
)]
pub async fn discovery(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<DiscoveryDocument> {
    //build issuer from the request Host / X-Sentin8-Hostname header
    // instead of hardcoded config.issuer. Falls back to config.issuer when no
    // Host header is present (e.g. direct IP access in tests).
    let issuer = resolve_issuer(&state.config, &headers);

    // read the caller's env-resolved security profile
    // (env → org → platform; the env row is authoritative) to
    // determine which fields to include. FAPI 2.0 is the default.
    let profile = resolve_security_profile(&state.pool, &headers, "env").await;

    Json(DiscoveryDocument {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{issuer}/oauth/authorize"),
        token_endpoint: format!("{issuer}/oauth/token"),
        jwks_uri: format!("{issuer}/.well-known/jwks.json"),
        userinfo_endpoint: format!("{issuer}/oauth/userinfo"),
        revocation_endpoint: format!("{issuer}/oauth/revoke"),
        introspection_endpoint: format!("{issuer}/oauth/introspect"),
        end_session_endpoint: format!("{issuer}/oauth/logout"),
        response_types_supported: vec!["code".into()],
        // JARM is advertised when require_jarm is true.
        response_modes_supported: if profile.require_jarm {
            vec!["query".into(), "jwt".into()]
        } else {
            vec!["query".into()]
        },
        grant_types_supported: vec![
            "authorization_code".into(),
            "refresh_token".into(),
            "client_credentials".into(),
            "urn:ietf:params:oauth:grant-type:device_code".into(),
            "urn:ietf:params:oauth:grant-type:token-exchange".into(),
        ],
        code_challenge_methods_supported: vec!["S256".into()],
        token_endpoint_auth_methods_supported: if profile.require_mtls {
            vec![
                "client_secret_post".into(),
                "client_secret_basic".into(),
                "private_key_jwt".into(),
                "none".into(),
                "tls_client_auth".into(),
                "self_signed_tls_client_auth".into(),
            ]
        } else {
            vec![
                "client_secret_post".into(),
                "client_secret_basic".into(),
                "private_key_jwt".into(),
                "none".into(),
                "self_signed_tls_client_auth".into(),
            ]
        },
        scopes_supported: vec![
            "openid".into(),
            "profile".into(),
            "email".into(),
            "offline_access".into(),
        ],
        subject_types_supported: vec!["public".into()],
        id_token_signing_alg_values_supported: vec![crate::jwks::active_signing_alg().into()],
        // DPoP signing algs - only advertised when DPoP is required or supported.
        dpop_signing_alg_values_supported: if profile.require_dpop {
            vec![crate::jwks::active_signing_alg().into()]
        } else {
            vec![]
        },
        authorization_response_iss_parameter_supported: profile.require_iss,
        request_object_signing_alg_values_supported: vec![crate::jwks::active_signing_alg().into()],
        request_parameter_supported: true,
        request_uri_parameter_supported: true,
        // PAR endpoint - present when require_par is true .
        pushed_authorization_request_endpoint: if profile.require_par {
            Some(format!("{issuer}/oauth/par"))
        } else {
            None
        },
        // mTLS endpoint aliases - present when require_mtls is true .
        mtls_endpoint_aliases: if profile.require_mtls {
            Some(MtlsEndpointAliases {
                token_endpoint: format!("{issuer}/mtls/oauth/token"),
                revocation_endpoint: format!("{issuer}/mtls/oauth/revoke"),
            })
        } else {
            None
        },
        // - discovery honesty: advertise the RAR types the AS
        // actually enforces (union of client-registered
        // authorization_details_types) and the grants API.
        authorization_details_types_supported: fetch_rar_types(&state.pool).await,
        grant_management_endpoint: Some(format!("{issuer}/oauth/grants")),
        software_statement_supported: true,
    })
}

/// Union of all client-registered RAR types (discovery field). None when
/// no client is registered for RAR.
async fn fetch_rar_types(pool: &sqlx::PgPool) -> Option<Vec<String>> {
    let types: Vec<String> = sqlx::query_scalar(
        r#"SELECT DISTINCT unnest(authorization_details_types) FROM auth.oauth_clients"#,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    if types.is_empty() {
        None
    } else {
        Some(types)
    }
}

// ── Security Profile Helper ─────────────────────────────────────────────

/// Security profile row from `sentin8_auth_security_profiles`.
#[derive(Debug, Clone)]
/// The securityprofile type.
pub struct SecurityProfile {
    /// The profile row name (`standard`, `fapi_1_baseline`, …) - used to
    /// derive FAPI allow-list constraints. Empty when defaulted.
    /// The profile.
    pub profile: String,
    /// The require par.
    pub require_par: bool,
    /// The require mtls.
    pub require_mtls: bool,
    /// The require JARM.
    pub require_jarm: bool,
    /// The require DPoP.
    pub require_dpop: bool,
    /// RFC 9421 HTTP request signatures on token/PAR/introspect
    /// (FAPI 2.0 Message Signing).
    /// The require http signatures.
    pub require_http_signatures: bool,
    /// RFC 9701 signed introspection responses (FAPI 2.0 MS half).
    /// The require JWT introspection.
    pub require_jwt_introspection: bool,
    /// The require iss.
    pub require_iss: bool,
    /// SEC- - PKCE is mandatory for authorization requests when
    /// the profile mandates PAR (FAPI 2.0 default). Mirrors `require_par`
    /// until the profile table grows a dedicated column.
    /// The require pkce.
    pub require_pkce: bool,
}

impl Default for SecurityProfile {
    fn default() -> Self {
        //FAPI 2.0 defaults.
        Self {
            require_par: true,
            require_mtls: false,
            require_jarm: true,
            require_dpop: true,
            // FAPI 2.0 default is the plain Security Profile - Message
            // Signing flags stay off (opt-in).
            require_http_signatures: false,
            require_jwt_introspection: false,
            require_iss: true,
            require_pkce: true,
            profile: String::new(),
        }
    }
}

/// Resolve the effective security profile for a request.
///
/// - reads `scope` (platform/org/env) and the tenant
/// context from TLS-injected headers. `org_id` is resolved from `env_id`
/// via `sentin8_sys_environments` when needed. For `org` scope, uses the
/// resolved `org_id`; for `env` scope, uses both `org_id` and `env_id`. Falls
/// back to the platform profile when TLS headers are absent.
///
/// (fixed ): the profile rows are RLS-protected - the
/// env/org rows are only visible with `app.env_id` context matching the
/// caller's env. All lookups therefore run on ONE connection inside a
/// transaction with `sentin8_set_tenant_context(env_id)` applied first
/// (: context must be set on the same
/// connection as the data query). Without this, per-tenant profiles are
/// silently ignored and discovery/enforcement always falls back to the
/// platform profile - caught by the revived conformance_profiles tests.
/// Resolve security profile.
pub async fn resolve_security_profile(
    pool: &sqlx::PgPool,
    headers: &HeaderMap,
    scope: &str,
) -> SecurityProfile {
    let env_id = headers
        .get(sentin8::middleware::context::HEADER_ENV_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .and_then(|s| Uuid::parse_str(s).ok());

    // Single transaction: tenant context + org lookup + profile lookups.
    // Context must be set on the SAME connection the queries run on
    // - the RLS policies on
    // `security_profiles` and `environments` admit rows only with
    // the caller's env_id in `app.env_id`.
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "resolve_security_profile: pool begin failed");
            return SecurityProfile::default();
        }
    };
    if let Some(eid) = env_id {
        // Context helper lives in `public` (platform.sql,
        // RLS-FNSCHEMA-1) - schema-qualifying it as `sentin8.` resolves
        // against the *sentin8 schema* and fails (function does not exist).
        // Unqualified resolves via the role's search_path like every other
        // caller.
        if let Err(e) = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(eid)
            .execute(&mut *tx)
            .await
        {
            tracing::error!(error = %e, "resolve_security_profile: set_tenant_context failed");
        }
    }

    // Resolve org_id from env_id via DB lookup (visible under RLS now).
    // Schema-qualified - resolution must not depend on the
    // connecting role's search_path.
    let org_id = if let Some(eid) = env_id {
        sqlx::query_scalar::<_, Uuid>(r#"SELECT org_id FROM sys.environments WHERE id = $1"#)
            .bind(eid)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    // Try the most specific profile first, then fall back up the hierarchy.
    let resolved = match scope {
        "env" => {
            if let (Some(o), Some(e)) = (org_id, env_id) {
                match fetch_profile_row(&mut tx, "env", Some(o), Some(e)).await {
                    Some(p) => Some(p),
                    None => {
                        if let Some(o) = org_id {
                            fetch_profile_row(&mut tx, "org", Some(o), None).await
                        } else {
                            None
                        }
                    }
                }
            } else {
                None
            }
        }
        "org" => {
            if let Some(o) = org_id {
                fetch_profile_row(&mut tx, "org", Some(o), None).await
            } else {
                None
            }
        }
        _ => None,
    };

    let resolved = match resolved {
        Some(p) => Some(p),
        None => fetch_profile_row(&mut tx, "platform", None, None).await,
    };

    tx.commit().await.ok();
    resolved.unwrap_or_default()
}

/// Fetch a single profile row by scope + org/env. Returns None on miss/error.
async fn fetch_profile_row(
    pool: &mut sqlx::PgConnection,
    scope: &str,
    org_id: Option<Uuid>,
    env_id: Option<Uuid>,
) -> Option<SecurityProfile> {
    let row = sqlx::query!(
        r#"SELECT profile, require_par, require_mtls, require_jarm, require_dpop,
                  require_http_signatures, require_jwt_introspection, require_iss
           FROM auth.security_profiles
           WHERE scope = $1
             AND (org_id IS NOT DISTINCT FROM $2)
             AND (env_id IS NOT DISTINCT FROM $3)
           LIMIT 1"#,
        scope,
        org_id,
        env_id,
    )
    .fetch_optional(pool)
    .await
    .ok()?;

    row.map(|r| SecurityProfile {
        profile: r.profile,
        require_par: r.require_par,
        require_mtls: r.require_mtls,
        require_jarm: r.require_jarm,
        require_dpop: r.require_dpop,
        require_http_signatures: r.require_http_signatures,
        require_jwt_introspection: r.require_jwt_introspection,
        require_iss: r.require_iss,
        // PKCE rides on the PAR flag (FAPI 2.0 mandates both).
        require_pkce: r.require_par,
    })
}

// ── Security Profile Admin API─────────────────────────

/// Response for `GET /v1/security-profile`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for securityprofile.
pub struct SecurityProfileResponse {
    /// The scope.
    pub scope: String,
    /// org identifier.
    pub org_id: Option<Uuid>,
    /// env identifier.
    pub env_id: Option<Uuid>,
    /// The profile.
    pub profile: String,
    /// The require par.
    pub require_par: bool,
    /// The require mtls.
    pub require_mtls: bool,
    /// The require JARM.
    pub require_jarm: bool,
    /// The require DPoP.
    pub require_dpop: bool,
    /// RFC 9421 request signatures (FAPI 2.0 Message Signing).
    /// The require http signatures.
    pub require_http_signatures: bool,
    /// RFC 9701 signed introspection responses.
    /// The require JWT introspection.
    pub require_jwt_introspection: bool,
    /// The require iss.
    pub require_iss: bool,
    /// Maximum token lifetime.
    pub max_token_lifetime: i32,
    /// The refresh rotation.
    pub refresh_rotation: bool,
}

/// Query params for `GET /v1/security-profile`.
#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The securityprofilequery type.
pub struct SecurityProfileQuery {
    /// `platform`, `org`, or `env`.
    #[serde(default)]
    /// The scope.
    pub scope: Option<String>,
}

/// Request body for `PUT /v1/security-profile`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for updatesecurityprofile.
pub struct UpdateSecurityProfileRequest {
    /// The scope.
    pub scope: String,
    #[serde(default)]
    /// org identifier.
    pub org_id: Option<Uuid>,
    #[serde(default)]
    /// env identifier.
    pub env_id: Option<Uuid>,
    #[serde(default)]
    /// The profile.
    pub profile: Option<String>,
    #[serde(default)]
    /// The require par.
    pub require_par: Option<bool>,
    #[serde(default)]
    /// The require mtls.
    pub require_mtls: Option<bool>,
    #[serde(default)]
    /// The require JARM.
    pub require_jarm: Option<bool>,
    #[serde(default)]
    /// The require DPoP.
    pub require_dpop: Option<bool>,
    /// RFC 9421 HTTP request signatures (FAPI 2.0 MS).
    #[serde(default)]
    /// The require http signatures.
    pub require_http_signatures: Option<bool>,
    /// RFC 9701 signed introspection responses.
    #[serde(default)]
    /// The require JWT introspection.
    pub require_jwt_introspection: Option<bool>,
    #[serde(default)]
    /// The require iss.
    pub require_iss: Option<bool>,
    #[serde(default)]
    /// Maximum token lifetime.
    pub max_token_lifetime: Option<i32>,
    #[serde(default)]
    /// The refresh rotation.
    pub refresh_rotation: Option<bool>,
}

/// `GET /v1/security-profile` - return the effective security profile for
/// the resolved tenant (platform/org/env).
#[utoipa::path(
    get,
    path = "/v1/security-profile",
    params(SecurityProfileQuery),
    responses(
        (status = 200, description = "The effective security profile", body = SecurityProfileResponse),
    ),
    security(),
    tag = "oauth",
)]
pub async fn get_security_profile_api(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SecurityProfileQuery>,
) -> Result<Json<SecurityProfileResponse>, (StatusCode, String)> {
    let scope = q.scope.as_deref().unwrap_or("platform");
    // Resolve tenant from TLS headers.
    let env_id = headers
        .get(sentin8::middleware::context::HEADER_ENV_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .and_then(|s| Uuid::parse_str(s).ok());

    // Resolve org_id from env_id via DB lookup.
    let org_id = if let Some(eid) = env_id {
        sqlx::query_scalar::<_, Uuid>(r#"SELECT org_id FROM sys.environments WHERE id = $1"#)
            .bind(eid)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    let row = sqlx::query!(
        r#"SELECT scope, org_id, env_id, profile,
                  require_par, require_mtls, require_jarm, require_dpop,
                  require_http_signatures, require_jwt_introspection, require_iss,
                  max_token_lifetime, refresh_rotation
           FROM security_profiles
           WHERE scope = $1
             AND (org_id IS NOT DISTINCT FROM $2)
             AND (env_id IS NOT DISTINCT FROM $3)
           LIMIT 1"#,
        scope,
        org_id,
        env_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row = row.ok_or_else(|| (StatusCode::NOT_FOUND, "security profile not found".into()))?;

    Ok(Json(SecurityProfileResponse {
        scope: row.scope,
        org_id: row.org_id,
        env_id: row.env_id,
        profile: row.profile,
        require_par: row.require_par,
        require_mtls: row.require_mtls,
        require_jarm: row.require_jarm,
        require_dpop: row.require_dpop,
        require_http_signatures: row.require_http_signatures,
        require_jwt_introspection: row.require_jwt_introspection,
        require_iss: row.require_iss,
        max_token_lifetime: row.max_token_lifetime,
        refresh_rotation: row.refresh_rotation,
    }))
}

/// `PUT /v1/security-profile` - update (or insert) the security profile for
/// the given scope + tenant.
///
/// SEC- - admin guard. `sentin8:sys:admin`/`sentin8:dash:admin` (platform
/// operators) may manage any scope row; org/env rows additionally require
/// the caller to have access to that org/env (RBAC) - enforced by passing
/// the target as `target_env_id` for env-scoped rows.
/// Handle PUT security profile API.
#[utoipa::path(
    put,
    path = "/v1/security-profile",
    request_body = UpdateSecurityProfileRequest,
    responses(
        (status = 200, description = "Profile stored (admin-guarded; platform operators manage any scope row, org/env rows are RBAC-checked)", body = SecurityProfileResponse),
        (status = 400, description = "Unknown profile name"),
        (status = 403, description = "Caller lacks the write-mode admin scope"),
    ),
    security(("sentin8:sys:admin" = [])),
    tag = "oauth",
)]
pub async fn put_security_profile_api(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpdateSecurityProfileRequest>,
) -> Result<Json<SecurityProfileResponse>, (StatusCode, String)> {
    // Guard: write-mode admin scope.
    let auth = crate::sentin8or_auth::require_sentin8or_access_write(
        &state,
        &headers,
        req.env_id.as_ref().map(|e| e.to_string()).as_deref(),
    )
    .await?;

    // Cross-tenant rule (SEC-): an org/env-scoped row must
    // belong to the caller's authorized env unless the caller is a
    // platform admin.
    if !auth.is_platform_admin() {
        if let Some(target_env) = req.env_id {
            if target_env != auth.env_id {
                return Err((
                    StatusCode::FORBIDDEN,
                    "not authorized to manage this env's security profile".into(),
                ));
            }
        }
    }

    // Validate scope.
    if !matches!(req.scope.as_str(), "platform" | "org" | "env") {
        return Err((
            StatusCode::BAD_REQUEST,
            "scope must be platform, org, or env".into(),
        ));
    }
    // For org/env scope, the corresponding IDs are required.
    if req.scope == "org" && req.org_id.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "org_id is required for org scope".into(),
        ));
    }
    if req.scope == "env" && (req.org_id.is_none() || req.env_id.is_none()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "org_id and env_id are required for env scope".into(),
        ));
    }

    // Fetch existing values to merge (upsert).
    let existing = sqlx::query!(
        r#"SELECT require_par, require_mtls, require_jarm, require_dpop,
                  require_http_signatures, require_jwt_introspection, require_iss,
                  max_token_lifetime, refresh_rotation, profile
           FROM security_profiles
           WHERE scope = $1
             AND (org_id IS NOT DISTINCT FROM $2)
             AND (env_id IS NOT DISTINCT FROM $3)"#,
        req.scope,
        req.org_id,
        req.env_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (e_par, e_mtls, e_jarm, e_dpop, e_hsigs, e_ji, e_iss, e_max, e_rot, e_profile) = existing
        .map(|r| {
            (
                r.require_par,
                r.require_mtls,
                r.require_jarm,
                r.require_dpop,
                r.require_http_signatures,
                r.require_jwt_introspection,
                r.require_iss,
                r.max_token_lifetime,
                r.refresh_rotation,
                r.profile,
            )
        })
        .unwrap_or((
            true,
            false,
            true,
            true,
            false,
            false,
            true,
            3600,
            true,
            "fapi_2".to_string(),
        ));

    let row = sqlx::query!(
        r#"INSERT INTO security_profiles
               (scope, org_id, env_id, profile,
                require_par, require_mtls, require_jarm, require_dpop,
                require_http_signatures, require_jwt_introspection, require_iss,
                max_token_lifetime, refresh_rotation)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
           ON CONFLICT (scope, org_id, env_id)
           DO UPDATE SET
               profile = EXCLUDED.profile,
               require_par = EXCLUDED.require_par,
               require_mtls = EXCLUDED.require_mtls,
               require_jarm = EXCLUDED.require_jarm,
               require_dpop = EXCLUDED.require_dpop,
               require_http_signatures = EXCLUDED.require_http_signatures,
               require_jwt_introspection = EXCLUDED.require_jwt_introspection,
               require_iss = EXCLUDED.require_iss,
               max_token_lifetime = EXCLUDED.max_token_lifetime,
               refresh_rotation = EXCLUDED.refresh_rotation,
               updated_at = now()
           RETURNING
               scope, org_id, env_id, profile,
               require_par, require_mtls, require_jarm, require_dpop,
               require_http_signatures, require_jwt_introspection, require_iss,
               max_token_lifetime, refresh_rotation"#,
        req.scope,
        req.org_id,
        req.env_id,
        req.profile.clone().unwrap_or(e_profile.clone()),
        req.require_par.unwrap_or(e_par),
        req.require_mtls.unwrap_or(e_mtls),
        req.require_jarm.unwrap_or(e_jarm),
        req.require_dpop.unwrap_or(e_dpop),
        req.require_http_signatures.unwrap_or(e_hsigs),
        req.require_jwt_introspection.unwrap_or(e_ji),
        req.require_iss.unwrap_or(e_iss),
        req.max_token_lifetime.unwrap_or(e_max),
        req.refresh_rotation.unwrap_or(e_rot),
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // SEC- - the catalog's `sentin8:auth:securityprofile:updated`
    // event (previously never emitted).
    crate::events::emit_event(
        &state.pool,
        auth.env_id,
        "sentin8:auth:securityprofile:updated",
        serde_json::json!({ "scope": row.scope, "profile": row.profile }),
    )
    .await;

    Ok(Json(SecurityProfileResponse {
        scope: row.scope,
        org_id: row.org_id,
        env_id: row.env_id,
        profile: row.profile,
        require_par: row.require_par,
        require_mtls: row.require_mtls,
        require_jarm: row.require_jarm,
        require_dpop: row.require_dpop,
        require_http_signatures: row.require_http_signatures,
        require_jwt_introspection: row.require_jwt_introspection,
        require_iss: row.require_iss,
        max_token_lifetime: row.max_token_lifetime,
        refresh_rotation: row.refresh_rotation,
    }))
}

///resolve the issuer URL from the request Host or X-Sentin8-Hostname header.
/// Falls back to config.issuer when no Host header is present.
fn resolve_issuer(config: &crate::config::AuthConfig, headers: &HeaderMap) -> String {
    // Check X-Sentin8-Hostname header first (set by TLS).
    if let Some(h) = headers
        .get("x-sentin8-hostname")
        .and_then(|v| v.to_str().ok())
    {
        if !h.is_empty() {
            return format!("https://{h}");
        }
    }
    // Check Host header.
    if let Some(h) = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        if !h.is_empty() && h != format!("auth.{}", config.sentin8_domain) {
            return format!("https://{h}");
        }
    }
    // Fall back to config issuer.
    config.issuer.clone()
}

// ── Authorize ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The authorizequery type.
pub struct AuthorizeQuery {
    /// Required for non-PAR flows; optional when using PAR (resolved from Valkey).
    #[serde(default)]
    /// The response type.
    pub response_type: Option<String>,
    /// client identifier.
    pub client_id: String,
    /// Required for non-PAR flows; optional when using PAR (resolved from Valkey).
    #[serde(default)]
    /// The redirect URI.
    pub redirect_uri: Option<String>,
    #[serde(default)]
    /// The scope.
    pub scope: String,
    #[serde(default)]
    /// The state.
    pub state: String,
    #[serde(default)]
    /// The code challenge.
    pub code_challenge: Option<String>,
    #[serde(default)]
    /// The code challenge method.
    pub code_challenge_method: Option<String>,
    /// PAR request_uri (RFC 9126) - when PAR is required, the client submits
    /// a `request_uri` instead of inline params.
    #[serde(default)]
    /// The request URI.
    pub request_uri: Option<String>,
    /// UI hint indicating which hosted UI page to show first. Currently
    /// supports `signup` - when present, the authorize handler redirects
    /// to `/sign-up` (instead of `/sign-in`) with the full OAuth context
    /// inline so the sign-up page can preserve redirect_uri/state/code_challenge.
    #[serde(default)]
    /// The screen hint.
    pub screen_hint: Option<String>,
    /// OIDC `nonce` - echoed into the ID token (SEC-).
    #[serde(default)]
    /// The nonce.
    pub nonce: Option<String>,
    /// OAuth response mode - `query` (default) or `jwt` (JARM, SEC-).
    #[serde(default)]
    /// The response mode.
    pub response_mode: Option<String>,
    /// JAR signed request object (RFC 9101, SEC-).
    #[serde(default)]
    /// The request.
    pub request: Option<String>,
    /// RFC 8707 resource indicator (SEC-).
    #[serde(default)]
    /// The resource.
    pub resource: Option<String>,
    /// RFC 9396 Rich Authorization Requests - JSON array of
    /// `authorization_details` objects. Validated against the client's
    /// registered `authorization_details_types`; stored in the code record
    /// and echoed into the ID token.
    #[serde(default)]
    /// The authorization details.
    pub authorization_details: Option<serde_json::Value>,
}

/// Validate an `authorization_details` request (RFC 9396):
/// each entry must be a JSON object with a non-empty `type` that the
/// client is registered to request. Returns a normalized JSON array or a
/// rejection reason.
/// Validate authorization details.
pub fn validate_authorization_details(
    client_types: &[String],
    details: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let arr = details
        .as_array()
        .ok_or("authorization_details must be a JSON array")?;
    if arr.is_empty() {
        return Err("authorization_details must not be empty".into());
    }
    let mut normalized = Vec::with_capacity(arr.len());
    for (i, entry) in arr.iter().enumerate() {
        let obj = entry
            .as_object()
            .ok_or(format!("authorization_details[{i}] must be an object"))?;
        let ty = obj
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or(format!("authorization_details[{i}].type is required"))?;
        if ty.is_empty() {
            return Err(format!("authorization_details[{i}].type must not be empty"));
        }
        if !client_types.iter().any(|t| t == ty) {
            return Err(format!(
                "client is not registered to request authorization_details type '{ty}'"
            ));
        }
        normalized.push(entry.clone());
    }
    Ok(serde_json::Value::Array(normalized))
}

/// Resolve a PAR request_uri from Valkey. **Single-use** - the key is
/// deleted atomically via GETDEL (SEC-); a second authorize
/// with the same request_uri fails with `invalid_request`.
async fn resolve_par_request(state: &AppState, request_uri: &str) -> Option<serde_json::Value> {
    let key = request_uri
        .strip_prefix("urn:ietf:params:oauth:request_uri:")
        .unwrap_or(request_uri);
    let valkey_key = format!("auth:par:{key}");

    let client = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .ok()?;
    let conn = client;
    // GETDEL - atomic single-use resolution.
    let val: Option<String> = glide::cmd("GETDEL")
        .arg(&valkey_key)
        .query_async(&conn)
        .await
        .ok()?;
    val.and_then(|s| serde_json::from_str(&s).ok())
}

/// PAR endpoint (RFC 9126) - accepts a pushed authorization request.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for par.
pub struct ParRequest {
    /// The response type.
    pub response_type: String,
    /// client identifier.
    pub client_id: String,
    /// The redirect URI.
    pub redirect_uri: String,
    #[serde(default)]
    /// The scope.
    pub scope: String,
    #[serde(default)]
    /// The state.
    pub state: String,
    #[serde(default)]
    /// The code challenge.
    pub code_challenge: Option<String>,
    #[serde(default)]
    /// The code challenge method.
    pub code_challenge_method: Option<String>,
    /// OIDC nonce (SEC-).
    #[serde(default)]
    /// The nonce.
    pub nonce: Option<String>,
    /// RFC 8707 resource indicator (SEC-).
    #[serde(default)]
    /// The resource.
    pub resource: Option<String>,
    /// RFC 9396 authorization_details.
    #[serde(default)]
    /// The authorization details.
    pub authorization_details: Option<serde_json::Value>,
    /// Client secret (client_secret_post - RFC 9126 client auth).
    #[serde(default)]
    /// The client secret.
    pub client_secret: Option<String>,
    /// private_key_jwt client assertion (RFC 9126 client auth).
    #[serde(default)]
    /// The client assertion.
    pub client_assertion: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
/// Response payload for par.
pub struct ParResponse {
    /// The request URI.
    pub request_uri: String,
    /// The expires in.
    pub expires_in: u64,
}

/// Handle pushed authorization request.
#[utoipa::path(
    post,
    path = "/oauth/par",
    params(
        ("response_type" = String, Query, description = "Only `code`"),
        ("client_id" = String, Query, description = "Client id"),
        ("redirect_uri" = String, Query, description = "Registered redirect URI"),
        ("scope" = String, Query, description = "Requested scope"),
        ("state" = String, Query, description = "Caller state"),
        ("code_challenge" = String, Query, description = "PKCE challenge"),
        ("code_challenge_method" = String, Query, description = "PKCE method"),
        ("nonce" = String, Query, description = "OIDC nonce"),
        ("resource" = String, Query, description = "RFC 8707 resource indicator"),
    ),
    responses(
        (status = 200, description = "Request URI issued (RFC 9126)", body = ParResponse),
        (status = 400, description = "Unsupported response_type or invalid client"),
        (status = 401, description = "Client authentication failed"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn pushed_authorization_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Form(req): axum::Form<ParRequest>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    if req.response_type != "code" {
        return Err((
            StatusCode::BAD_REQUEST,
            "only 'code' response_type is supported".into(),
        ));
    }

    // SEC- - PAR pushes require client authentication (RFC 9126
    // ); the redirect_uri must be registered for the client.
    let client = authenticate_client(
        &state,
        &headers,
        Some(req.client_id.as_str()),
        req.client_secret.as_deref(),
        req.client_assertion.as_deref(),
        true,
        true,
    )
    .await?;
    if !redirect_uri_registered(&client.redirect_uris, &req.redirect_uri) {
        return Err((
            StatusCode::BAD_REQUEST,
            "redirect_uri is not registered for this client".into(),
        ));
    }

    let request_id = uuid::Uuid::new_v4().to_string();
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{request_id}");
    let valkey_key = format!("auth:par:{request_id}");

    // - RAR: validate authorization_details against the client's
    // registered types before storing them in the PAR record.
    let authorization_details = match req.authorization_details {
        Some(ref d) => Some(
            validate_authorization_details(&client.authorization_details_types, d)
                .map_err(|e| (StatusCode::BAD_REQUEST, e))?,
        ),
        None => None,
    };

    let params = serde_json::json!({
        "response_type": req.response_type,
        "client_id": client.client_id,
        "redirect_uri": req.redirect_uri,
        "scope": req.scope,
        "state": req.state,
        "code_challenge": req.code_challenge,
        "code_challenge_method": req.code_challenge_method,
        "nonce": req.nonce,
        "resource": req.resource,
        "authorization_details": authorization_details,
    });

    let client = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let conn = client;

    let _: () = conn
        .set_ex(&valkey_key, params.to_string(), 600)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(ParResponse {
            request_uri,
            expires_in: 600,
        }),
    )
        .into_response())
}

/// Normalized authorization params - either from inline query params or
/// resolved from a PAR request / JAR request object.
struct AuthorizeParams {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    /// OIDC nonce (SEC-).
    nonce: Option<String>,
    /// RFC 8707 resource indicator (SEC-).
    resource: Option<String>,
    /// OAuth response mode (`query` default, `jwt` for JARM).
    response_mode: Option<String>,
    /// RFC 9396 authorization_details - validated against
    /// the client's registered types.
    authorization_details: Option<serde_json::Value>,
}

/// The authorize endpoint validates the request and redirects to the Auth hosted UI
/// (`/sign-in`) with the OAuth params preserved. After the user authenticates,
/// the UI calls back to issue an auth code. For non-interactive flows (already
/// has a session), it issues the code directly.
/// Authorize it.
#[utoipa::path(
    get,
    path = "/oauth/authorize",
    params(AuthorizeQuery),
    responses(
        (status = 302, description = "Redirect to the hosted sign-in UI (params preserved) or straight back to the client with the code when a session exists"),
        (status = 400, description = "Invalid authorization request (unknown client, bad redirect_uri/response_type)"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    // ── Resolve PAR params if request_uri is present ──────────────────
    //
    // When using PAR (RFC 9126), the client pushes the full authorization
    // request to /oauth/par and receives a request_uri. The subsequent
    // GET /oauth/authorize only carries client_id + request_uri. We must
    // resolve the stored params from Valkey and use them for the rest of
    // the flow.
    let mut params = AuthorizeParams {
        response_type: q.response_type.clone().unwrap_or_default(),
        client_id: q.client_id.clone(),
        redirect_uri: q.redirect_uri.clone().unwrap_or_default(),
        scope: q.scope.clone(),
        state: q.state.clone(),
        code_challenge: q.code_challenge.clone(),
        code_challenge_method: q.code_challenge_method.clone(),
        nonce: q.nonce.clone(),
        resource: q.resource.clone(),
        response_mode: q.response_mode.clone(),
        authorization_details: None,
    };

    //enforce the caller's env-resolved profile
    // when require_par is true.
    let profile = resolve_security_profile(&state.pool, &headers, "env").await;
    if profile.require_par && q.request_uri.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "PAR is required - provide a request_uri from /oauth/par"
            })),
        )
            .into_response();
    }

    if let Some(ref request_uri) = q.request_uri {
        match resolve_par_request(&state, request_uri).await {
            Some(stored) => {
                // SEC- - the PAR record is client-bound: the query
                // client_id must match the client that pushed the request.
                let par_client = stored
                    .get("client_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if par_client != params.client_id {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "invalid_request",
                            "error_description": "request_uri was issued to a different client"
                        })),
                    )
                        .into_response();
                }
                // Override with PAR-stored params (authoritative source).
                if let Some(rt) = stored.get("response_type").and_then(|v| v.as_str()) {
                    params.response_type = rt.to_string();
                }
                if let Some(cid) = stored.get("client_id").and_then(|v| v.as_str()) {
                    params.client_id = cid.to_string();
                }
                if let Some(ru) = stored.get("redirect_uri").and_then(|v| v.as_str()) {
                    params.redirect_uri = ru.to_string();
                }
                if let Some(sc) = stored.get("scope").and_then(|v| v.as_str()) {
                    params.scope = sc.to_string();
                }
                if let Some(st) = stored.get("state").and_then(|v| v.as_str()) {
                    params.state = st.to_string();
                }
                if let Some(cc) = stored.get("code_challenge").and_then(|v| v.as_str()) {
                    params.code_challenge = Some(cc.to_string());
                }
                if let Some(ccm) = stored.get("code_challenge_method").and_then(|v| v.as_str()) {
                    params.code_challenge_method = Some(ccm.to_string());
                }
                if let Some(n) = stored.get("nonce").and_then(|v| v.as_str()) {
                    params.nonce = Some(n.to_string());
                }
                if let Some(r) = stored.get("resource").and_then(|v| v.as_str()) {
                    params.resource = Some(r.to_string());
                }
                // - RAR: the PAR record is the authoritative
                // source (validated at push time); overlay verbatim.
                if let Some(ad) = stored.get("authorization_details") {
                    if !ad.is_null() {
                        params.authorization_details = Some(ad.clone());
                    }
                }
            }
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "invalid or expired request_uri"
                    })),
                )
                    .into_response();
            }
        }
    }

    // ── JAR (RFC 9101) - signed request object overlay (SEC-) ──
    //
    // When a `request` JWT parameter is present, verify its signature
    // against the client's registered keys (inline `jwks` or `jwks_uri`)
    // and overlay its params over the inline ones (JAR wins).
    if let Some(ref request_jwt) = q.request {
        match verify_jar_request(&state, &params.client_id, request_jwt, &state.config.issuer).await
        {
            Ok(jar) => {
                if !jar.redirect_uri.is_empty() {
                    params.redirect_uri = jar.redirect_uri.clone();
                }
                if !jar.response_type.is_empty() {
                    params.response_type = jar.response_type.clone();
                }
                params.scope = jar.scope.clone();
                params.state = jar.state.clone();
                if let Some(cc) = jar.code_challenge.clone() {
                    params.code_challenge = Some(cc);
                }
                if let Some(ccm) = jar.code_challenge_method.clone() {
                    params.code_challenge_method = Some(ccm);
                }
                if let Some(n) = jar.nonce.clone() {
                    params.nonce = Some(n);
                }
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": format!("JAR request rejected: {e}")
                    })),
                )
                    .into_response();
            }
        }
    }

    // Validate response_type.
    if params.response_type != "code" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "unsupported_response_type",
                "error_description": "only 'code' is supported"
            })),
        )
            .into_response();
    }

    // Validate PKCE if code_challenge is present.
    if let Some(ref method) = params.code_challenge_method {
        if method != "S256" {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "code_challenge_method must be S256"
                })),
            )
                .into_response();
        }
    }
    // SEC- - PKCE is mandatory when the profile mandates PAR
    // (FAPI 2.0 default): reject requests without a code_challenge.
    if profile.require_pkce && params.code_challenge.as_deref().unwrap_or("").is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "PKCE code_challenge is required by the active security profile"
            })),
        )
            .into_response();
    }

    // Look up the OAuth client to check consent_required
    // and validate the redirect_uri against the registered allow-list
    // (SEC- - open-redirect defense).
    //
    // SEC- - run with the tenant context on the same connection:
    // `oauth_clients` is RLS-forced, and `sentin8_set_tenant_context`
    // is transaction-local - a bare pool query sees zero rows under the
    // app role and every authorize request failed with "unknown client_id".
    let client_row = with_client_env(&state, params.client_id.clone()).await;
    let client_row = match client_row {
        Some((consent_required, redirect_uris, rar_types)) => {
            (consent_required, redirect_uris, rar_types)
        }
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "unknown client_id"
                })),
            )
                .into_response();
        }
    };
    let (_consent_required_meta, client_redirect_uris, client_rar_types) = client_row;

    // - inline RAR (PAR-stored details were validated at push
    // time): each `type` must be in the client's registered
    // `authorization_details_types`. PAR-stored values overlay after this.
    if let Some(details) = params.authorization_details.as_ref() {
        if !details.is_null() {
            if let Err(e) = validate_authorization_details(&client_rar_types, details) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": e
                    })),
                )
                    .into_response();
            }
        }
    }
    if !redirect_uri_registered(&client_redirect_uris, &params.redirect_uri) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "redirect_uri is not registered for this client"
            })),
        )
            .into_response();
    }
    // (consent_required destructured above; redirect_uris validated already)
    let consent_required = _consent_required_meta;

    //Consent flow detection. When consent is required,
    // check if the requested scopes match a `sentin8_consent_flows`
    // trigger pattern (glob). If a match is found, pass the `consent_flow`
    // param to the sign-in page so the auth-ui knows to render the
    // vertical-specific consent UI (RFW) instead of the platform-default
    // simple approve/deny. Design: , .
    let consent_flow: Option<String> = if consent_required {
        let flows = sqlx::query!(r#"SELECT flow_id, trigger_patterns FROM consent_flows"#,)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();
        // Match the requested scopes against trigger patterns (space-separated globs).
        let requested: Vec<&str> = params.scope.split_whitespace().collect();
        let mut matched: Option<String> = None;
        'outer: for flow in &flows {
            if let Some(arr) = flow.trigger_patterns.as_array() {
                for pat in arr.iter().filter_map(|p| p.as_str()) {
                    if requested.iter().any(|s| glob_match(pat, s)) {
                        tracing::info!(
                            flow_id = %flow.flow_id,
                            pattern = %pat,
                            "consent flow matched for authorize request"
                        );
                        matched = Some(flow.flow_id.clone());
                        break 'outer;
                    }
                }
            }
        }
        matched
    } else {
        None
    };

    // Redirect to the hosted sign-in page with OAuth params preserved.
    // The auth serves a minimal HTML sign-in form at /sign-in that
    // collects email/password, POSTs to /v1/sign-in, and on success POSTs
    // to /oauth/authorize/continue to issue the authorization code.
    // `screen_hint=signup` routes the user to the registration page first;
    // otherwise the sign-in page is shown.
    let is_signup = q
        .screen_hint
        .as_deref()
        .map(|s| s.eq_ignore_ascii_case("signup"))
        .unwrap_or(false);
    let ui_page = if is_signup { "/sign-up" } else { "/sign-in" };
    let mut ui_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256&consent_required={}",
        ui_page,
        urlencode(&params.client_id),
        urlencode(&params.redirect_uri),
        urlencode(&params.scope),
        urlencode(&params.state),
        urlencode(params.code_challenge.as_deref().unwrap_or("")),
        consent_required,
    );
    // Forward the nonce so authorize/continue can bind it into the ID token
    // (SEC-) and the resource indicator (SEC-).
    if let Some(n) = params.nonce.as_deref().filter(|s| !s.is_empty()) {
        ui_url.push_str(&format!("&nonce={}", urlencode(n)));
    }
    if let Some(r) = params.resource.as_deref().filter(|s| !s.is_empty()) {
        ui_url.push_str(&format!("&resource={}", urlencode(r)));
    }
    // Forward the response mode so authorize/continue can honor a JARM
    // (`response_mode=jwt`) request (SEC-).
    if let Some(rm) = params.response_mode.as_deref().filter(|s| !s.is_empty()) {
        ui_url.push_str(&format!("&response_mode={}", urlencode(rm)));
    }
    // Append consent_flow param when a vertical-specific flow matched.
    let ui_url = if let Some(flow_id) = consent_flow {
        format!("{ui_url}&consent_flow={}", urlencode(&flow_id))
    } else {
        ui_url
    };

    (StatusCode::FOUND, [("location", ui_url)]).into_response()
}

/// Continue the authorize flow after the user has authenticated via the hosted UI.
/// This is called by the UI after sign-in to issue the authorization code.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for authorizecontinue.
pub struct AuthorizeContinueRequest {
    /// client identifier.
    pub client_id: String,
    /// The redirect URI.
    pub redirect_uri: String,
    /// The scope.
    pub scope: String,
    /// The state.
    pub state: String,
    /// The code challenge.
    pub code_challenge: Option<String>,
    /// user identifier.
    pub user_id: Uuid,
    /// The session token.
    pub session_token: String,
    /// OIDC nonce - bound into the ID token (SEC-).
    #[serde(default)]
    /// The nonce.
    pub nonce: Option<String>,
    /// RFC 8707 resource indicator (SEC-).
    #[serde(default)]
    /// The resource.
    pub resource: Option<String>,
    /// OAuth response mode - `jwt` triggers a JARM response (SEC-).
    #[serde(default)]
    /// The response mode.
    pub response_mode: Option<String>,
    /// Account IDs the customer selected to share during the FDX consent
    /// screen (FDX UX Guidelines "Select Accounts"). Forwarded as
    /// a comma-separated query param on the redirect_uri so the FDX
    /// callback can persist them as consent resources.
    #[serde(default)]
    /// The selected account ids.
    pub selected_account_ids: Vec<String>,
    /// RFC 9396 authorization_details - validated against the
    /// client's registered types; stored in the code record and echoed
    /// into the ID token.
    #[serde(default)]
    /// The authorization details.
    pub authorization_details: Option<serde_json::Value>,
}

/// Authorize continue.
#[utoipa::path(
    post,
    path = "/oauth/authorize/continue",
    request_body = AuthorizeContinueRequest,
    responses(
        (status = 302, description = "Redirect to the client's redirect_uri with the issued code (or an error response per response_mode)"),
        (status = 400, description = "Invalid request (unknown client/session, bad redirect_uri or scope)"),
        (status = 401, description = "Session invalid or expired"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn authorize_continue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AuthorizeContinueRequest>,
) -> Result<Response, (StatusCode, String)> {
    // Verify the session is valid.
    let session = crate::sessions::Session::find_by_token(&state.pool, &req.session_token)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let session = match session {
        Some(s) if s.is_valid() && s.user_id == req.user_id => s,
        _ => return Err((StatusCode::UNAUTHORIZED, "invalid session".into())),
    };

    // SEC- - re-validate the redirect_uri against the client's
    // registered allow-list before issuing any code (open-redirect
    // defense). Context-scoped lookup (SEC- - RLS).
    let (_consent_meta, redirect_uris, _rar_types) = with_client_env(&state, req.client_id.clone())
        .await
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "unknown client_id".into()))?;
    if !redirect_uri_registered(&redirect_uris, &req.redirect_uri) {
        return Err((
            StatusCode::BAD_REQUEST,
            "redirect_uri is not registered for this client".into(),
        ));
    }

    // SEC- - PKCE challenge must be present when the caller's env-resolved
    // profile mandates it (FAPI 2.0 default).
    let profile = resolve_security_profile(&state.pool, &headers, "env").await;
    if profile.require_pkce && req.code_challenge.as_deref().unwrap_or("").is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "PKCE code_challenge is required by the active security profile".into(),
        ));
    }

    // Generate an authorization code and store it in Valkey with PKCE binding.
    let code = Uuid::new_v4().to_string();
    let code_key = format!("auth:authcode:{code}");

    // Resolve the user's token type from the claims. The access token's
    // scope is determined by the user's RBAC roles/groups (merged at
    // issuance). env_id is the sole tenant key.
    // Validate the user exists in the auth users table. The session's
    // env_id is the authoritative tenant key (used below in code_data).
    // RLS : the users existence check delegates to the shared
    // two-step lookup - the session's env is known here, but the users row
    // itself must be read under its own tenant policy (a context-less
    // SELECT returns no row under the NOBYPASSRLS service role).
    let _user_row = crate::sessions::user_env(&state.pool, req.user_id)
        .await
        .map_err(|(_, e)| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let code_data = serde_json::json!({
           "client_id": req.client_id,
           "redirect_uri": req.redirect_uri,
           "scope": req.scope,
           "user_id": req.user_id.to_string(),
           "env_id": session.env_id.to_string(),
           "code_challenge": req.code_challenge,
           "nonce": req.nonce,
           "resource": req.resource,
    // auth_time for the ID token (OIDC Core ) - the session's issue time.
           "auth_time": session.created_at.timestamp(),
           "selected_account_ids": req.selected_account_ids,
    // RFC 9396 authorization_details - echoed into the ID
    // token via `_claim_names` at exchange time.
           "authorization_details": req.authorization_details,
       });

    let conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Use Valkey for auth codes (TTL 600s).
    let valkey_url = &state.config.valkey_url;
    let valkey_conn = sentin8::middleware::valkey_client(valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _: () = valkey_conn
        .set_ex(&code_key, code_data.to_string(), 600)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    drop(conn);

    // Build the redirect URL with code + state.
    // (RFC 9207) - include `iss` parameter when require_iss is true.
    let iss_param = if profile.require_iss {
        format!("&iss={}", urlencode(&state.config.issuer))
    } else {
        String::new()
    };
    // Append selected_account_ids so the FDX callback can persist the
    // per-account consent resources (FDX Consent API , UX ).
    let accounts_param = if req.selected_account_ids.is_empty() {
        String::new()
    } else {
        format!(
            "&selected_account_ids={}",
            urlencode(&req.selected_account_ids.join(","))
        )
    };
    let redirect_url = format!(
        "{}?code={}&state={}{}{}",
        req.redirect_uri,
        urlencode(&code),
        urlencode(&req.state),
        iss_param,
        accounts_param,
    );

    // SEC- - JARM (`response_mode=jwt`): when the profile
    // requires JARM and the client requested the JWT response mode, the
    // response parameters are wrapped in a signed JWT delivered via the
    // `response` query parameter instead of plain query params.
    let response_url = if profile.require_jarm && req.response_mode.as_deref() == Some("jwt") {
        let jarm_claims = crate::jarm::build_jarm_success(
            &state.config.issuer,
            &req.client_id,
            &code,
            Some(&req.state),
        );
        let jarm_jwt = crate::jarm::sign_jarm_jwt(&state.keys, &jarm_claims)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        crate::jarm::build_jarm_redirect_url(&req.redirect_uri, &jarm_jwt)
    } else {
        redirect_url
    };

    // Return JSON with the redirect URL instead of a 302 redirect.
    // The Auth Flutter Web UI calls this endpoint via fetch/XHR and
    // cannot capture 302 Location headers on the web platform (browsers
    // transparently follow redirects, making the Location header
    // inaccessible to JS). By returning JSON, the UI can read the
    // redirect URL and navigate the browser to it explicitly.
    Ok(Json(serde_json::json!({
        "redirect_url": response_url,
        "code": code,
        "state": req.state,
    }))
    .into_response())
}

// ── Token ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for token.
pub struct TokenRequest {
    /// The grant type.
    pub grant_type: String,
    #[serde(default, alias = "device_code")]
    /// The code.
    pub code: Option<String>,
    #[serde(default)]
    /// The redirect URI.
    pub redirect_uri: Option<String>,
    #[serde(default)]
    /// client identifier.
    pub client_id: Option<String>,
    #[serde(default)]
    /// The client secret.
    pub client_secret: Option<String>,
    #[serde(default)]
    /// The code verifier.
    pub code_verifier: Option<String>,
    #[serde(default)]
    /// The refresh token.
    pub refresh_token: Option<String>,
    #[serde(default)]
    /// The scope.
    pub scope: Option<String>,
    /// CIBA grant - the auth_req_id from bc-authorize.
    #[serde(default)]
    /// auth req identifier.
    pub auth_req_id: Option<String>,
    // ── RFC 8693 token-exchange parameters ──
    /// The subject token to exchange (RFC 8693 ).
    #[serde(default)]
    /// The subject token.
    pub subject_token: Option<String>,
    /// Token type of the subject token - must be `urn:ietf:params:oauth:token-type:access_token`.
    #[serde(default)]
    /// The subject token type.
    pub subject_token_type: Option<String>,
    /// The requested audience (RFC 8707 resource indicator) for the issued token.
    #[serde(default)]
    /// The audience.
    pub audience: Option<String>,
    /// The requested token type - must be `urn:ietf:params:oauth:token-type:access_token`.
    #[serde(default)]
    /// The requested token type.
    pub requested_token_type: Option<String>,
    /// The target env_id for the exchanged token (Sentin8 extension).
    #[serde(default, rename = "requested_tenancy.env_id")]
    /// requested env identifier.
    pub requested_env_id: Option<String>,
    /// RFC 8707 resource indicator (SEC-) - the audience for the
    /// issued access token.
    #[serde(default)]
    /// The resource.
    pub resource: Option<String>,
    /// RFC 7523 private_key_jwt client assertion (SEC-).
    #[serde(default)]
    /// The client assertion.
    pub client_assertion: Option<String>,
    #[serde(default)]
    /// The client assertion type.
    pub client_assertion_type: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
/// Response payload for token.
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The refresh token.
    pub refresh_token: Option<String>,
    /// The token type.
    pub token_type: String,
    /// The expires in.
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The scope.
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The id token.
    pub id_token: Option<String>,
}

/// Handle token.
#[utoipa::path(
    post,
    path = "/oauth/token",
    params(
        ("grant_type" = String, Query, description = "authorization_code | refresh_token | client_credentials | urn:ietf:params:oauth:grant-type:device_code | urn:openid:params:grant-type:ciba"),
        ("code" = String, Query, description = "Authorization code (authorization_code grant)"),
        ("redirect_uri" = String, Query, description = "The redirect URI used at authorize"),
        ("client_id" = String, Query, description = "Client id (or Basic auth)"),
        ("client_secret" = String, Query, description = "Client secret (confidential clients, or Basic auth)"),
        ("code_verifier" = String, Query, description = "PKCE verifier"),
        ("refresh_token" = String, Query, description = "Refresh token (refresh_token grant)"),
        ("scope" = String, Query, description = "Requested scope (client_credentials)"),
        ("auth_req_id" = String, Query, description = "CIBA auth_req_id"),
        ("device_code" = String, Query, description = "Device code (device_code grant)"),
    ),
    responses(
        (status = 200, description = "Token response (access_token, token_type, expires_in, refresh_token?, id_token?)", body = TokenResponse),
        (status = 400, description = "invalid_request / invalid_grant / unsupported_grant_type (RFC 6749 §5.2 error JSON)"),
        (status = 401, description = "invalid_client (Basic auth rejected)"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn token(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> Result<Json<TokenResponse>, TokenError> {
    // . - RFC 9421 HTTP request signatures (FAPI 2.0 Message
    // Signing): when the caller's env-resolved profile requires them, the
    // raw body is needed for the Content-Digest check BEFORE the form is
    // parsed (the digest covers the exact bytes on the wire).
    let req: TokenRequest = serde_urlencoded::from_bytes(&raw_body).map_err(|e| {
        TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            format!("malformed form body: {e}"),
        ))
    })?;

    // SEC- - authenticate the client on every grant. Confidential
    // clients must present their credentials; public clients (dash, CLI) are
    // resolved by client_id only. The resolved client is passed to the grant
    // handlers so codes/CIBA requests/refresh tokens can be bound to it.
    let assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string();
    let client_assertion = if req.client_assertion.is_some()
        && req.client_assertion_type.as_deref() != Some(assertion_type.as_str())
    {
        return Err(TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_assertion_type must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        )));
    } else {
        req.client_assertion.clone()
    };

    let client = authenticate_client(
        &state,
        &headers,
        req.client_id.as_deref(),
        req.client_secret.as_deref(),
        client_assertion.as_deref(),
        true,
        // Grants allow public clients (CLI device flow, SPA code exchange).
        true,
    )
    .await
    .map_err(|(s, m)| TokenError::OAuth(OAuthTokenError::with_desc(s, "invalid_client", m)))?;

    // SEC- - DPoP proof handling. When the caller's env-resolved profile
    // requires DPoP, every token request must carry a valid proof;
    // the proof key thumbprint (`jkt`) sender-constrains the issued access token.
    let profile = resolve_security_profile(&state.pool, &headers, "env").await;

    // - FAPI allow-list enforcement. A FAPI profile constrains the
    // client authentication method (secrets are insufficient for confidential
    // clients under FAPI - sender-constraining is required) and the grant
    // family. First-party public clients are admitted via the dpop_exempt
    // path below; everything else must satisfy the profile.
    if let Some(fapi) = crate::fapi::FapiProfile::from_str(&profile.profile) {
        if !fapi.is_auth_method_allowed(client.auth_method) {
            return Err(TokenError::OAuth(OAuthTokenError::with_desc(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                format!(
                    "client authentication method '{}' is not permitted under the active FAPI profile",
                    client.auth_method
                ),
            )));
        }
        if !fapi.is_grant_type_allowed(&req.grant_type) {
            return Err(TokenError::OAuth(OAuthTokenError::with_desc(
                StatusCode::BAD_REQUEST,
                "unauthorized_client",
                format!(
                    "grant_type '{}' is not permitted under the active FAPI profile",
                    req.grant_type
                ),
            )));
        }
    }
    let mut dpop_jkt: Option<String> = None;
    if let Some(proof) = crate::dpop::extract_dpop_header(&headers) {
        // htu - the token endpoint URI from the client's perspective. Use the
        // request-host-resolved issuer (same logic as discovery): clients on
        // tenant auth domains (auth.staff.{org}.sentin8.local) claim that
        // host, while platform calls claim config.issuer.
        let htu = format!("{}/oauth/token", resolve_issuer(&state.config, &headers));
        let jkt = crate::dpop::validate_and_verify_dpop(&state, &proof, "POST", &htu)
            .await
            .map_err(|e| {
                TokenError::OAuth(OAuthTokenError::with_desc(
                    StatusCode::UNAUTHORIZED,
                    "invalid_dpop_proof",
                    e,
                ))
            })?;
        dpop_jkt = Some(jkt);
    } else if profile.require_dpop
        && req.grant_type != "client_credentials"
 // RFC 8693 token exchange is an M2M delegation grant: the
 // subscriber authenticates as a service client and sender-
 // constraining comes from the act chain + optional cnf cert
 // binding - a DPoP proof is not required (matches the
 // client_credentials exemption, design ).
        && req.grant_type != "urn:ietf:params:oauth:grant-type:token-exchange"
        && !is_dpop_exempt(&client)
    {
        // DPoP is required for user-facing grants; client_credentials M2M
        // clients authenticate with secrets/mTLS and are exempt (design ).
        // First-party public clients (dash, sentin8-cli - token_endpoint_auth
        // method 'none', no mTLS binding) are also exempt: they have no
        // registered key material to sign a proof with, and the design's
        // caller-compatibility directive preserves their flows. A DPoP proof
        // sent anyway is still verified above, sender-constraining the token.
        return Err(TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::UNAUTHORIZED,
            "invalid_request",
            "DPoP proof required for this grant",
        )));
    }

    // . - RFC 9421 HTTP request signatures (FAPI 2.0 Message
    // Signing): when the env-resolved profile requires them, every mutating
    // token request must carry a signature over @method, @target-uri, and
    // the Content-Digest of the exact body bytes (swap protection).
    if profile.require_http_signatures {
        let target = format!("{}/oauth/token", state.config.issuer);
        crate::http_signatures::verify_http_signature(
            &client, &headers, "POST", &target, &raw_body,
        )
        .map_err(|e| {
            TokenError::OAuth(OAuthTokenError::with_desc(
                StatusCode::UNAUTHORIZED,
                "invalid_request",
                format!("HTTP request signature required: {e}"),
            ))
        })?;
    }

    match req.grant_type.as_str() {
        "authorization_code" => {
            handle_code_exchange(&state, &client, dpop_jkt.as_deref(), &headers, req).await
        }
        "refresh_token" => handle_refresh(&state, &client, dpop_jkt.as_deref(), req).await,
        "client_credentials" => handle_client_credentials(&state, &headers, &client, req)
            .await
            .map_err(Into::into),
        "urn:ietf:params:oauth:grant-type:device_code" => {
            handle_device_code(&state, &client, req).await
        }
        "urn:ietf:params:oauth:grant-type:ciba" => {
            // - under the fapi_ciba profile, the polling request
            // MUST carry a DPoP proof (verified above; here we require its
            // presence - the proof was already validated and its jkt bound).
            if profile.profile == "fapi_ciba" && dpop_jkt.is_none() && !is_dpop_exempt(&client) {
                return Err(TokenError::OAuth(OAuthTokenError::with_desc(
                    StatusCode::UNAUTHORIZED,
                    "invalid_request",
                    "fapi_ciba profile requires a DPoP proof on CIBA polling requests",
                )));
            }
            handle_ciba_token(&state, &client, req).await
        }
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            handle_token_exchange(&state, &headers, req)
                .await
                .map_err(Into::into)
        }
        other => Err(TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            format!("unsupported grant_type: {other}"),
        ))),
    }
}

/// Authorization code exchange.
///
/// SEC- - the code is bound to the authenticated client (mix-up
/// defense) and PKCE is mandatory when the stored challenge exists. When
/// the granted scope includes `openid`, an OIDC ID token is issued
/// (SEC-) with `aud` = client_id, `nonce` from the authorize
/// request, and `at_hash` binding it to the access token.
async fn handle_code_exchange(
    state: &AppState,
    client: &AuthenticatedClient,
    dpop_jkt: Option<&str>,
    headers: &HeaderMap,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, TokenError> {
    let code = req.code.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "code is required for authorization_code grant".into(),
        )
    })?;
    let redirect_uri = req.redirect_uri.as_deref().unwrap_or("");
    let code_verifier = req.code_verifier.as_deref();

    // Fetch the auth code data from Valkey.
    let code_key = format!("auth:authcode:{code}");
    let valkey_conn = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let code_json: Option<String> = valkey_conn
        .get(&code_key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let code_json = code_json.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "invalid or expired authorization code".into(),
        )
    })?;

    // Delete the code immediately (one-time use - fail-closed: a failed
    // validation burns the code).
    let _: () = valkey_conn.del(&code_key).await.unwrap_or(());

    let code_data: serde_json::Value = serde_json::from_str(&code_json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // SEC- - client binding: the authenticated client must be the
    // client the code was issued for (mix-up attack defense, RFC 8252/9207).
    let stored_client_id = code_data["client_id"].as_str().unwrap_or("");
    if stored_client_id != client.client_id {
        tracing::warn!(
            code_client = %stored_client_id,
            auth_client = %client.client_id,
            "authorization code client mismatch rejected"
        );
        return Err(TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "invalid_grant: authorization code was issued to another client",
        )));
    }

    // Validate redirect_uri matches (RFC 6749 - exact string match).
    let stored_redirect = code_data["redirect_uri"].as_str().unwrap_or("");
    if stored_redirect != redirect_uri {
        return Err(TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri mismatch",
        )));
    }

    // Validate PKCE - the stored challenge must be proven (SEC-).
    let stored_challenge = code_data["code_challenge"].as_str().unwrap_or("");
    if !stored_challenge.is_empty() {
        let verifier = code_verifier
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "code_verifier is required".into()))?;
        let computed = pkce_s256_challenge(verifier);
        if computed != stored_challenge {
            return Err(TokenError::OAuth(OAuthTokenError::with_desc(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PKCE verification failed",
            )));
        }
    } else {
        // No challenge stored - only permissible when the caller's env-resolved
        // profile does not mandate PKCE (SEC-).
        let profile = resolve_security_profile(&state.pool, headers, "env").await;
        if profile.require_pkce {
            return Err(TokenError::OAuth(OAuthTokenError::with_desc(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PKCE is required by the active security profile",
            )));
        }
    }

    let user_id: Uuid = code_data["user_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid user_id in auth code".into(),
            )
        })?;
    let env_id: Uuid = code_data["env_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(SYSTEM_ENV_ID);
    let scope = code_data["scope"]
        .as_str()
        .unwrap_or("openid profile email");
    let nonce = code_data["nonce"].as_str().map(|s| s.to_string());
    let auth_time = code_data["auth_time"]
        .as_i64()
        .unwrap_or_else(|| chrono::Utc::now().timestamp());
    // RFC 9396 authorization_details - validated at authorize
    // time; echoed into the ID token per RFC 9396
    let authorization_details = code_data
        .get("authorization_details")
        .filter(|d| !d.is_null())
        .cloned();

    // Look up the user's email + name (ID-token claims).
    let user_row = sqlx::query!(
        r#"SELECT email, first_name, last_name FROM users WHERE id = $1"#,
        user_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let email = user_row.as_ref().map(|r| r.email.clone());
    let name = user_row.as_ref().map(|r| {
        [r.first_name.as_deref(), r.last_name.as_deref()]
            .iter()
            .filter_map(|s| *s)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    });

    // Merge group permissions into scope .
    let role_scopes = crate::handlers::fetch_role_scopes(&state.pool, user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let merged_scope = crate::handlers::merge_scopes(scope, &role_scopes);

    // SEC- - resource indicator (RFC 8707): the `resource` param
    // sets the access token's `aud`.
    let resource = req.resource.as_deref().filter(|s| !s.is_empty());
    if let Some(r) = resource {
        if !crate::resource_indicators::is_valid_resource_uri(r) {
            return Err(TokenError::OAuth(OAuthTokenError::with_desc(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid resource indicator",
            )));
        }
    }

    // Issue access token.
    let access_claims = AuthClaims::access_with_client(
        &state.config.issuer,
        user_id,
        &merged_scope,
        env_id,
        email.as_deref(),
        Some(&client.client_id),
        Duration::seconds(state.config.access_token_ttl_secs as i64),
    );
    let mut access_claims = access_claims;
    if let Some(r) = resource {
        access_claims.aud = Some(r.to_string());
    }
    // SEC- - DPoP sender-constraining (`cnf.jkt`).
    if let Some(jkt) = dpop_jkt {
        access_claims.cnf = Some(crate::dpop::build_dpop_cnf_claim(jkt));
    }

    // - Grant Management: record/merge the standing authorization
    // (env, user, client) and bind the grant_id onto the issued tokens so a
    // grant revocation cascades to every token issued under it. Code exchange
    // always issues a user access token (`token_tp: "access"`).
    let grant_id: Option<String> = match crate::grants::record_grant(
        state,
        env_id,
        user_id,
        &client.client_id,
        Some(client.id),
        scope,
        authorization_details.as_ref(),
    )
    .await
    {
        Ok(id) => Some(id.to_string()),
        Err(e) => {
            tracing::warn!(error = %e, "grant recording failed - issuing token without grant_id");
            None
        }
    };

    // - Grant lifecycle event (auth DESIGN §4): code issuance is the
    // moment a customer's authorization becomes real for downstream
    // consent authorities. Payload-complete envelope so a data-holder
    // (e.g. Bank8:FDX's provider plane) can seed its grant ledger from
    // the event alone: `state` is the client's opaque OAuth state (the
    // consent handle a vertical's flow packed into PAR) and
    // `selected_account_ids` the accounts the customer selected on the
    // hosted consent screen. Best-effort after the committed grant -
    // never blocks token issuance.
    crate::events::emit_event(
        &state.pool,
        env_id,
        "sentin8:auth:grant:created",
        serde_json::json!({
            "grant_id": grant_id,
            "client_id": client.client_id,
            "user_id": user_id.to_string(),
            "env_id": env_id.to_string(),
            "scope": scope,
            "state": code_data["state"].as_str().unwrap_or_default(),
            "selected_account_ids": code_data["selected_account_ids"].as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect::<Vec<_>>())
                .unwrap_or_default(),
        }),
    )
    .await;
    let access_claims = if let Some(gid) = grant_id.as_deref() {
        let mut c = access_claims;
        c.grant_id = Some(gid.to_string());
        c
    } else {
        access_claims
    };
    let access_token = state
        .keys
        .sign(&access_claims)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let id_token = if scope.split_whitespace().any(|s| s == "openid") {
        let id_claims = AuthClaims::id_token_with_details(
            &state.config.issuer,
            user_id,
            &client.client_id,
            nonce.as_deref(),
            auth_time,
            &access_token,
            email.as_deref(),
            scope.split_whitespace().any(|s| s == "email"),
            name.as_deref(),
            scope.split_whitespace().any(|s| s == "profile"),
            Duration::seconds(state.config.access_token_ttl_secs as i64),
            authorization_details.as_ref(),
        );
        state
            .keys
            .sign_value(&id_claims)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .into()
    } else {
        None
    };

    // Issue refresh token if offline_access scope requested. The refresh
    // token carries the ORIGINAL requested scope so refresh grants can
    // re-issue with the same app scopes (design ).
    let refresh_token = if scope.contains("offline_access") {
        let refresh_claims = AuthClaims::refresh(
            &state.config.issuer,
            user_id,
            scope,
            env_id,
            Duration::seconds(state.config.refresh_token_ttl_secs as i64),
        );
        state
            .keys
            .sign(&refresh_claims)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .into()
    } else {
        None
    };

    Ok(Json(TokenResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".into(),
        expires_in: state.config.access_token_ttl_secs,
        // Return the MERGED scope (base + group permissions), not the
        // original requested scope. BFF stores this in the session and
        // uses it for proxy scope enforcement. Without the merged scope,
        // the session only has "openid profile email" and all proxied
        // API calls fail with "lacks <service>:read scope".
        scope: Some(merged_scope),
        id_token,
    }))
}

/// Refresh token grant.
///
/// SEC- - the presented refresh token is **verified** (signature +
/// issuer + expiry) and checked against the revocation denylist before any
/// new token is issued. SEC- - rotation: when the profile's
/// `refresh_rotation` is enabled (default), a **new** refresh token is
/// issued and the old `jti` is denylisted, so a stolen-and-replayed old
/// token is rejected on its next use.
async fn handle_refresh(
    state: &AppState,
    client: &AuthenticatedClient,
    dpop_jkt: Option<&str>,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, TokenError> {
    let refresh_token = req
        .refresh_token
        .as_deref()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "refresh_token is required".into()))?;

    // SEC- - VERIFIED decode: signature + iss + exp.
    let claims = verify_access_token_claims(state, refresh_token).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            format!("invalid refresh_token: {}", e.1),
        )
    })?;

    if claims.token_tp != "refresh" {
        return Err(TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "not a refresh token",
        )));
    }

    // SEC- - denylist check (revoked tokens are refused). RFC 6749
    // : the token endpoint answers with a JSON `{"error":"invalid_grant"}`
    // body.
    if is_token_revoked(state, &claims.jti).await {
        tracing::warn!(jti = %claims.jti, "revoked refresh token presented");
        return Err(TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh token has been revoked",
        )));
    }

    let user_id: Uuid = claims
        .sub
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid subject".into()))?;
    let env_id: Uuid = claims
        .env_id
        .as_ref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(SYSTEM_ENV_ID);

    // Requested scope may not exceed the token's original scope (RFC 6749
    // - scope narrowing only).
    let requested_scope = req.scope.clone().unwrap_or_else(|| claims.scope.clone());
    let original: std::collections::HashSet<&str> = claims.scope.split_whitespace().collect();
    let narrowed: Vec<&str> = requested_scope
        .split_whitespace()
        .filter(|s| original.contains(*s))
        .collect();
    let scope = if narrowed.is_empty() {
        claims.scope.clone()
    } else {
        narrowed.join(" ")
    };

    // Look up the user's email.
    let user_row = sqlx::query!(r#"SELECT email FROM users WHERE id = $1"#, user_id,)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let email = user_row.as_ref().map(|r| r.email.clone());

    // Merge group permissions into scope .
    let role_scopes = crate::handlers::fetch_role_scopes(&state.pool, user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let merged_scope = crate::handlers::merge_scopes(&scope, &role_scopes);

    // Issue a new access token.
    let mut access_claims = AuthClaims::access_with_client(
        &state.config.issuer,
        user_id,
        &merged_scope,
        env_id,
        email.as_deref(),
        Some(&client.client_id),
        Duration::seconds(state.config.access_token_ttl_secs as i64),
    );
    // SEC- - resource indicator.
    if let Some(r) = req.resource.as_deref().filter(|s| !s.is_empty()) {
        if !crate::resource_indicators::is_valid_resource_uri(r) {
            return Err(TokenError::OAuth(OAuthTokenError::with_desc(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "invalid resource indicator",
            )));
        }
        access_claims.aud = Some(r.to_string());
    }
    // SEC- - DPoP sender-constraining.
    if let Some(jkt) = dpop_jkt {
        access_claims.cnf = Some(crate::dpop::build_dpop_cnf_claim(jkt));
    }
    let access_token = state
        .keys
        .sign(&access_claims)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // SEC- - rotation. When enabled (default), mint a NEW refresh
    // token and denylist the old `jti` for the old token's remaining
    // lifetime, so a replay of the old token fails.
    let rotate = profile_refresh_rotation(state).await;
    let refresh_token_out: Option<String> = if rotate {
        // Denylist the old token first.
        let remaining = (claims.exp - chrono::Utc::now().timestamp()).max(1);
        revoke_jti(state, &claims.jti, remaining).await;

        let new_refresh_claims = AuthClaims::refresh(
            &state.config.issuer,
            user_id,
            &scope,
            env_id,
            Duration::seconds(state.config.refresh_token_ttl_secs as i64),
        );
        Some(
            state
                .keys
                .sign(&new_refresh_claims)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        )
    } else {
        Some(refresh_token.to_string())
    };

    Ok(Json(TokenResponse {
        access_token,
        refresh_token: refresh_token_out,
        token_type: "Bearer".into(),
        expires_in: state.config.access_token_ttl_secs,
        // Return the merged scope (base + group permissions).
        scope: Some(merged_scope),
        id_token: None,
    }))
}

/// Read the `refresh_rotation` flag from the platform security profile row
/// (default: enabled, design ).
async fn profile_refresh_rotation(state: &AppState) -> bool {
    sqlx::query_scalar(
        r#"SELECT COALESCE(
               (SELECT refresh_rotation FROM security_profiles
                 WHERE scope = 'platform' AND org_id IS NULL AND env_id IS NULL
                 LIMIT 1), true)"#,
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .unwrap_or(true)
}

/// Client credentials grant (M2M token issuance, + ).
///
///when the request arrives at `/mtls/oauth/token`, TLS
/// injects `X-Sentin8-Client-Cert-Thumbprint`. If present, the issued M2M
/// token includes a `cnf` (confirmation) claim with `x5t#S256` - making the
/// token certificate-bound (RFC 8705 sender-constraining).
async fn handle_client_credentials(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    client: &AuthenticatedClient,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    // The client was authenticated by `authenticate_client` in `token`
    // (secret / Basic / mTLS / private_key_jwt - SEC-).

    // Resolve the client's full scope set: own registered scopes ∪
    // permissions of Roles assigned via sentin8_auth_client_roles ,
    // resolved over sentin8_auth_role_nesting. The requested scope (if any)
    // is intersected with this set so a client can never escalate beyond
    // what it's entitled to.
    let mut entitled = crate::handlers::fetch_client_role_scopes(&state.pool, client.id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // The client's own scopes array is already unioned in by
    // fetch_client_role_scopes; ensure deterministic order.
    entitled.sort();
    entitled.dedup();

    let scope: String = match req.scope.as_deref() {
        Some(req_scope) if !req_scope.is_empty() => {
            let requested: Vec<&str> = req_scope.split_whitespace().collect();
            let allowed: std::collections::HashSet<&str> =
                entitled.iter().map(|s| s.as_str()).collect();
            requested
                .into_iter()
                .filter(|s| allowed.contains(*s))
                .collect::<Vec<_>>()
                .join(" ")
        }
        _ => entitled.join(" "),
    };

    // ── mTLS sender-constraining (RFC 8705,) ───────────
    //
    // When the request arrives via `/mtls/oauth/token`, TLS injects the
    // `X-Sentin8-Client-Cert-Thumbprint` and optionally `X-Sentin8-Client-Cert-
    // Subject-DN` headers. `authenticate_client` already validated the
    // presented cert against the registered metadata; here we inject the
    // `cnf` claim so the token is certificate-bound (RFC 8705 ).
    let mut claims = AuthClaims::m2m(
        &state.config.issuer,
        &client.client_id,
        &scope,
        client.env_id.to_string(),
        Duration::seconds(state.config.m2m_token_ttl_secs as i64),
    );

    // VDC-2/VDC-4 (design/sentin8-vertical-data-plane-contract.md §VDC.4/§VDC.5):
    // stamp the workload's vertical + owning service claims from the DCR
    // grant row (keyed by the registered client_name - the workload name).
    // Bus's event-ownership gate checks `vertical` on produce; Sys's
    // tenant-snapshot scoped discovery checks `service_type` (the caller
    // sees only envs where its own service is enabled) - no consumer ever
    // reads auth tables for either.
    //
    // RLS: `auth.oauth_clients` is FORCE-RLS'd on env - the lookup MUST run
    // inside a transaction with the client's own env context set (an
    // autocommit pool read sees zero rows, the claim drops, and the Bus gate
    // trips on every relay produce).
    {
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(client.env_id)
            .execute(&mut *tx)
            .await;
        let row: Option<(String, String)> = sqlx::query_as(
            r#"SELECT g.vertical, g.service_type FROM auth.m2m_scope_grants g
                JOIN oauth_clients c ON c.client_name = g.service_name
               WHERE c.client_id = $1 LIMIT 1"#,
        )
        .bind(&client.client_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = tx.rollback().await;
        if let Some((vertical, service_type)) = row {
            claims.vertical = Some(vertical);
            claims.service_type = Some(service_type).filter(|s| !s.is_empty());
        }
    }

    if let Some(thumbprint) = &client.cert_thumbprint {
        claims.cnf = Some(crate::mtls::build_cnf_claim(thumbprint));
    }
    // SEC- - resource indicator (RFC 8707).
    if let Some(r) = req.resource.as_deref().filter(|s| !s.is_empty()) {
        if !crate::resource_indicators::is_valid_resource_uri(r) {
            return Err((StatusCode::BAD_REQUEST, "invalid resource indicator".into()));
        }
        claims.aud = Some(r.to_string());
    }
    let _ = headers; // (identity already extracted in authenticate_client)

    let token = state
        .keys
        .sign(&claims)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(TokenResponse {
        access_token: token,
        refresh_token: None,
        token_type: "Bearer".into(),
        expires_in: state.config.m2m_token_ttl_secs,
        scope: if scope.is_empty() { None } else { Some(scope) },
        id_token: None,
    }))
}

// ── Token Exchange (RFC 8693) ─ Federated Credentials Only ────────────

/// Federated-credentials token-exchange handler (auth design ).
///
/// An external workload presents a JWT issued by a trusted external IdP
/// (e.g. a GitHub Actions OIDC token, a Kubernetes service-account token).
/// Auth verifies the JWT against the issuer's JWKS, matches a
/// `sentin8_auth_federated_credentials` row on the requested client, and mints an
/// M2M token for that client with no stored secret. The `act` claim records
/// the external `iss`/`sub` for audit.
///
/// Flow:
/// 1. Decode the external JWT (unverified) to read `iss`/`sub`/`aud`/`exp`.
/// 2. Look up a matching `sentin8_auth_federated_credentials` row for the client.
/// 3. Fetch the issuer's JWKS (discovery-driven) and verify the JWT signature.
/// 4. Resolve the client's entitled scope via `fetch_client_role_scopes`
///
/// (own scopes ∪ assigned roles' permissions + nesting).
/// 5. Issue an M2M token (`sub = client_id`, `token_tp: "m2m"`) with the
/// entitled scope and an `act` claim recording the external `iss`/`sub`.
async fn handle_federated_token_exchange(
    state: &AppState,
    req: TokenRequest,
    subject_token: &str,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    // 1. Decode the external JWT without verification to read claims.
    let claims: serde_json::Value = decode_jwt_unverified(subject_token).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid subject_token: {e}"),
        )
    })?;
    let iss = claims.get("iss").and_then(|v| v.as_str()).ok_or((
        StatusCode::BAD_REQUEST,
        "subject_token missing 'iss' claim".into(),
    ))?;
    let sub = claims.get("sub").and_then(|v| v.as_str()).ok_or((
        StatusCode::BAD_REQUEST,
        "subject_token missing 'sub' claim".into(),
    ))?;
    let aud = claims.get("aud").and_then(|v| v.as_str()).unwrap_or("");
    let exp = claims.get("exp").and_then(|v| v.as_i64()).ok_or((
        StatusCode::BAD_REQUEST,
        "subject_token missing 'exp' claim".into(),
    ))?;
    // Reject already-expired external tokens.
    let now = chrono::Utc::now().timestamp();
    if exp < now {
        return Err((StatusCode::UNAUTHORIZED, "subject_token has expired".into()));
    }

    // 2. Look up the client_id from the request and a matching federated
    // credential row. The client must be an active auth OAuth client.
    let client_id = req.client_id.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "client_id is required for federated token exchange".into(),
        )
    })?;
    let client = sqlx::query!(
        r#"SELECT c.id, c.env_id, c.status
             FROM oauth_clients c
             JOIN federated_credentials fc ON fc.client_id = c.id
            WHERE c.client_id = $1 AND fc.issuer = $2 AND fc.subject = $3
              AND (fc.audience = '' OR fc.audience = $4)"#,
        client_id,
        iss,
        sub,
        aud,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let client = match client {
        Some(c) if c.status == "active" => c,
        Some(_) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "OAuth client is not active".into(),
            ))
        }
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "no matching federated credential for this client/issuer/subject".into(),
            ))
        }
    };

    // 3. Verify the external JWT signature against the issuer's JWKS.
    // Discovery-driven: fetch the issuer's JWKS URI from its
    // /.well-known/openid-configuration (or rfc8414 metadata). We use
    // a lightweight fetch here; a production implementation caches JWKS.
    verify_external_jwt(state, subject_token, iss, &claims).await?;

    // 4. Resolve the client's entitled scope (own scopes ∪ assigned roles).
    let entitled = crate::handlers::fetch_client_role_scopes(&state.pool, client.id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let scope = match req.scope.as_deref() {
        Some(req_scope) if !req_scope.is_empty() => {
            let requested: Vec<&str> = req_scope.split_whitespace().collect();
            let allowed: std::collections::HashSet<&str> =
                entitled.iter().map(|s| s.as_str()).collect();
            requested
                .into_iter()
                .filter(|s| allowed.contains(*s))
                .collect::<Vec<_>>()
                .join(" ")
        }
        _ => entitled.join(" "),
    };

    // 5. Issue the M2M token with an `act` claim recording the external issuer.
    let act = serde_json::json!({
        "iss": iss,
        "sub": sub,
    });
    let claims = AuthClaims::m2m_with_act(
        &state.config.issuer,
        client_id,
        &scope,
        client.env_id.to_string(),
        Duration::seconds(state.config.m2m_token_ttl_secs as i64),
        &act,
    );
    let token = state
        .keys
        .sign(&claims)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(TokenResponse {
        access_token: token,
        refresh_token: None,
        token_type: "Bearer".into(),
        expires_in: state.config.m2m_token_ttl_secs,
        scope: if scope.is_empty() { None } else { Some(scope) },
        id_token: None,
    }))
}

/// Verify an external IdP JWT against the issuer's JWKS (discovery-driven).
///
/// Fetches the issuer's `/.well-known/openid-configuration` (or RFC 8414
/// authorization-server metadata) to find `jwks_uri`, fetches the JWKS
/// (Valkey-cached, `auth:extjwks:{sha256(uri)}`, TTL 300s), and verifies the
/// JWT signature (RS256/ES256 via the JWK allow-list) + `iss` + `exp`.
/// Fail-closed: an unresolvable discovery document or JWKS, an unsupported
/// algorithm, or a signature mismatch all reject the exchange.
async fn verify_external_jwt(
    state: &AppState,
    token: &str,
    expected_iss: &str,
    claims: &serde_json::Value,
) -> Result<(), (StatusCode, String)> {
    if expected_iss.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "issuer claim is empty".into()));
    }

    // 1. Resolve the issuer's jwks_uri via discovery. `expected_iss` is the
    // exact `iss` claim value - an https origin URL - so the discovery
    // document lives at `{iss}/.well-known/openid-configuration` (OIDC
    // Discovery ) with the RFC 8414 fallback path.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("http client: {e}")))?;
    let jwks_uri = {
        let mut uri = None;
        for path in [
            ".well-known/openid-configuration",
            ".well-known/oauth-authorization-server",
        ] {
            let url = format!("{}/{}", expected_iss.trim_end_matches('/'), path);
            let resp = http.get(&url).send().await.map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("issuer discovery fetch failed: {e}"),
                )
            })?;
            if !resp.status().is_success() {
                continue;
            }
            let doc: serde_json::Value = resp.json().await.map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("issuer discovery parse failed: {e}"),
                )
            })?;
            if let Some(u) = doc.get("jwks_uri").and_then(|v| v.as_str()) {
                uri = Some(u.to_string());
                break;
            }
        }
        uri.ok_or_else(|| {
            (
                StatusCode::BAD_GATEWAY,
                "cannot resolve the issuer jwks_uri from its discovery document".into(),
            )
        })?
    };

    // 2. Fetch + cache the JWKS (5-min TTL) and verify the signature with
    // each published key. `verify_with_jwk` enforces the algorithm
    // allow-list (RS256/ES256) - `"none"` and HS256-style confusion are
    // rejected.
    let keys = fetch_external_jwks(state, &jwks_uri).await.ok_or_else(|| {
        (
            StatusCode::BAD_GATEWAY,
            "cannot fetch the issuer JWKS".into(),
        )
    })?;
    let verified = keys
        .iter()
        .any(|k| crate::jwks::SigningKeys::verify_with_jwk(k, token).is_ok());
    if !verified {
        return Err((
            StatusCode::UNAUTHORIZED,
            "subject_token signature verification failed against the issuer JWKS".into(),
        ));
    }

    // 3. Claim re-checks on the verified token: `iss` must match the
    // federated-credential row's issuer and the token must not be
    // expired (defense-in-depth - the caller checks these on the
    // unverified decode).
    let iss_now = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
    if iss_now != expected_iss {
        return Err((
            StatusCode::UNAUTHORIZED,
            "subject_token issuer mismatch".into(),
        ));
    }
    let exp = claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    if exp < chrono::Utc::now().timestamp() {
        return Err((StatusCode::UNAUTHORIZED, "subject_token has expired".into()));
    }
    Ok(())
}

/// RFC 8693 token-exchange grant handler.
///
/// Exchanges a platform-scoped access token for an env-scoped, downscoped,
/// RFC 8693 token-exchange grant handler (federated credentials only).
///
/// The old sys→org access-token exchange has been replaced by the Delegation
/// Gateway (`POST /delegate/access-token`, see `delegation.rs`). Only the
/// federated-credentials branch remains: an external IdP JWT is exchanged
/// for an Auth M2M token.
async fn handle_token_exchange(
    state: &AppState,
    headers: &HeaderMap,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    let _subject_token = req.subject_token.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "subject_token is required for token-exchange".into(),
        )
    })?;

    let subject_token_type = req.subject_token_type.as_deref().unwrap_or("");

    if subject_token_type == "urn:ietf:params:oauth:token-type:jwt" {
        let st = req.subject_token.clone().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "subject_token is required for token-exchange".into(),
            )
        })?;
        // Check if this is a self-issued Sentin8:Auth JWT (publisher token).
        //publisher-token branch.
        let claims_unverified = decode_jwt_unverified(&st).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid subject_token: {e}"),
            )
        })?;
        let iss = claims_unverified
            .get("iss")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if iss == state.config.issuer {
            // Self-issued JWT - publisher-token exchange path.
            return handle_publisher_token_exchange(state, req, headers, &st, &claims_unverified)
                .await;
        }
        // External JWT - federated credentials path.
        return handle_federated_token_exchange(state, req, &st).await;
    }

    Err((
        StatusCode::BAD_REQUEST,
        "subject_token_type must be urn:ietf:params:oauth:token-type:jwt (federated credentials or publisher-token exchange). \
         sys→org access-token exchange has been replaced by the Delegation Gateway - \
         use POST /delegate/access-token instead."
            .into(),
    ))
}

///Publisher-token exchange.
///
/// A bus subscriber (M2M client) exchanges a publisher's Sentin8:Auth-issued
/// JWT for a delegated token with `act` chain nesting. This enables
/// subscriber delegation via RFC 8693 token exchange.
async fn handle_publisher_token_exchange(
    state: &AppState,
    req: TokenRequest,
    headers: &HeaderMap,
    subject_token: &str,
    claims_unverified: &serde_json::Value,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    // 1. Verify the publisher token ( / SEC-).
    // VERIFIED decode: signature + issuer + expiry. The unverified decode
    // previously used here allowed forged tokens with a spoofed `iss` claim
    // to be exchanged for delegated tokens.
    let publisher_claims = state.keys.verify(subject_token).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            format!("publisher token verification failed: {e}"),
        )
    })?;
    if publisher_claims.iss != state.config.issuer {
        return Err((
            StatusCode::UNAUTHORIZED,
            "publisher token issuer mismatch".into(),
        ));
    }
    // Verify expiry.
    let now_ts = chrono::Utc::now().timestamp();
    if publisher_claims.exp < now_ts {
        return Err((
            StatusCode::UNAUTHORIZED,
            "publisher token has expired".into(),
        ));
    }
    // Denylist check (revoked publisher tokens cannot be exchanged).
    if is_token_revoked(state, &publisher_claims.jti).await {
        return Err((
            StatusCode::UNAUTHORIZED,
            "publisher token has been revoked".into(),
        ));
    }

    // Verify token type - accept access, m2m, delegated. Reject refresh/id/actor.
    match publisher_claims.token_tp.as_str() {
        "access" | "m2m" | "delegated" => {}
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "invalid publisher token type '{other}': only access/m2m/delegated accepted"
                ),
            ));
        }
    }

    //jti replay protection for publisher token exchange.
    // Cache the publisher token's jti in Valkey with TTL = remaining token lifetime.
    // If the jti is already cached, reject with 400 token_already_exchanged.
    if !publisher_claims.jti.is_empty() {
        let jti_key = format!("auth:exchange:jti:{}", publisher_claims.jti);
        let remaining_secs = (publisher_claims.exp - now_ts).max(1);
        if let Ok(conn) =
            sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
        {
            use glide::AsyncCommands as _;
            let setnx = conn.set_nx::<_, _, i64>(&jti_key, "1").await;
            if matches!(setnx, Ok(0)) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "token_already_exchanged: this publisher token has already been used for a token exchange".into(),
                ));
            }
            let _: Result<(), _> = conn.expire(&jti_key, remaining_secs).await;
        }
    }

    // 2. Resolve the subscriber (requesting M2M client)_act check.
    // fix : subscriber resolution + may_act + org lookup all
    // run inside ONE transaction with the subscriber's env context (same
    // connection) - the client and role rows are RLS-protected and the
    // pool-only path is policy-blocked (revived tests caught this).
    let client_id = req.client_id.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "client_id is required for publisher-token exchange".into(),
        )
    })?;
    let publisher_env = publisher_claims
        .env_id
        .as_ref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(uuid::Uuid::nil());

    let mut ex_tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(publisher_env)
        .execute(&mut *ex_tx)
        .await;

    let subscriber = sqlx::query_as::<_, (uuid::Uuid, Uuid, Vec<String>, String)>(
        r#"SELECT id, env_id, scopes, status
             FROM oauth_clients WHERE client_id = $1"#,
    )
    .bind(client_id)
    .fetch_optional(&mut *ex_tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (subscriber_id, _subscriber_env, subscriber_scopes, subscriber_status) = match subscriber {
        Some(s) => s,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "subscriber client not found".into(),
            ))
        }
    };
    if subscriber_status != "active" {
        return Err((
            StatusCode::UNAUTHORIZED,
            "subscriber client is not active".into(),
        ));
    }

    // may_act check: subscriber must be authorized in the publisher's env.
    // `env_id` is globally unique (no org_id on auth tables since the
    // realm removal refactor) - env match alone identifies the tenant.
    // sys.environments is QUALIFIED: the service role's search_path is
    // `auth, public` (no `sys`) - architecture (owner schema reads
    // are declared, not search-path-inherited).
    let publisher_org: uuid::Uuid =
        sqlx::query_scalar(r#"SELECT org_id FROM sys.environments WHERE id = $1"#)
            .bind(publisher_env)
            .fetch_optional(&mut *ex_tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .unwrap_or(uuid::Uuid::nil());
    let _ = publisher_org; // used for the audit row below; authorization is env-scoped
    let may_act = sqlx::query(
        r#"SELECT 1 AS ok FROM user_roles ur
           JOIN roles r ON r.id = ur.role_id
           WHERE ur.user_id = $1 AND r.env_id = $2 LIMIT 1"#,
    )
    .bind(subscriber_id)
    .bind(publisher_env)
    .fetch_optional(&mut *ex_tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if may_act.is_none() {
        // User-path alternative: group membership in the publisher's env.
        let may_act_group = sqlx::query(
            r#"SELECT 1 AS ok FROM group_members gm
               JOIN groups g ON g.id = gm.group_id
               WHERE gm.user_id = $1 AND g.env_id = $2 LIMIT 1"#,
        )
        .bind(subscriber_id)
        .bind(publisher_env)
        .fetch_optional(&mut *ex_tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        // M2M principals are authorized via the client-roles junction.
        let may_act_client = sqlx::query(
            r#"SELECT 1 AS ok FROM client_roles cr
               JOIN roles r ON r.id = cr.role_id
               WHERE cr.client_id = $1 AND cr.env_id = $2 LIMIT 1"#,
        )
        .bind(subscriber_id)
        .bind(publisher_env)
        .fetch_optional(&mut *ex_tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if may_act_group.is_none() && may_act_client.is_none() {
            return Err((
                StatusCode::FORBIDDEN,
                "may_act_denied: subscriber not authorized in publisher's env".into(),
            ));
        }
    }
    ex_tx
        .commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 3. Downscope: intersection of requested scope ∩ subscriber's scopes ∩ publisher's scopes .
    let publisher_scopes: std::collections::HashSet<&str> =
        publisher_claims.scope.split_whitespace().collect();
    let subscriber_scopes: std::collections::HashSet<&str> =
        subscriber_scopes.iter().map(|s| s.as_str()).collect();
    let requested_scope = req.scope.as_deref().unwrap_or("");
    let downscoped: Vec<&str> = if requested_scope.is_empty() {
        publisher_scopes
            .intersection(&subscriber_scopes)
            .copied()
            .collect()
    } else {
        requested_scope
            .split_whitespace()
            .filter(|s| publisher_scopes.contains(*s) && subscriber_scopes.contains(*s))
            .collect()
    };
    let scope_str = downscoped.join(" ");

    // 4. Build the `act` chain source (the nesting itself
    // lives in `AuthClaims::delegated_from_publisher`).
    let publisher_act = claims_unverified.get("act").cloned();

    // 5. Determine expiry: min(publisher exp, M2M TTL).
    let now = chrono::Utc::now();
    let publisher_exp = publisher_claims.exp;
    let max_exp =
        (now + chrono::Duration::seconds(state.config.m2m_token_ttl_secs as i64)).timestamp();
    let exp = publisher_exp.min(max_exp);
    let ttl_secs = (exp - now.timestamp()).max(1);

    // 5b.sender-constrain the delegated token: when the
    // subscriber presented a client certificate (cert-bound M2M per
    // ), the delegated token carries `cnf: {x5t#S256}` so a stolen
    // token is useless without the private key. Non-cert-bound subscribers
    // (client_secret only) keep a token without cnf (backward compat).
    let cnf = crate::mtls::extract_mtls_identity(headers)
        .map(|(thumbprint, _)| serde_json::json!({ "x5t#S256": thumbprint }));

    // 6. Mint the delegated token via the builder.
    let claims = AuthClaims::delegated_from_publisher(
        &state.config.issuer,
        client_id,
        &publisher_claims.sub,
        publisher_act.as_ref(),
        &scope_str,
        &publisher_env.to_string(),
        req.audience.clone(),
        cnf,
        exp,
    );
    let token = state
        .keys
        .sign(&claims)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 7. Audit log the exchange . `actor_events` carries
    // actor/target/token/scope/reason/action. The subscriber (M2M client id)
    // and the publisher's user are the actor/target; the publisher's jti is
    // the token reference and the reason carries the full replay trace
    // (publisher jti + audience). Non-fatal on insert failure.
    let audit_reason = format!(
        "token_exchange publisher_jti={} audience={}",
        publisher_claims.jti,
        req.audience.as_deref().unwrap_or("")
    );
    match sqlx::query(
        "INSERT INTO actor_events (actor_user_id, target_user_id, token_id, scope, reason, action)
         VALUES ($1, $2, $3, $4, $5, 'token_exchange')",
    )
    .bind(subscriber_id)
    .bind(Uuid::parse_str(&publisher_claims.sub).unwrap_or(Uuid::nil()))
    .bind(Uuid::parse_str(&publisher_claims.jti).unwrap_or(Uuid::nil()))
    .bind(&scope_str)
    .bind(&audit_reason)
    .execute(&state.pool)
    .await
    {
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "publisher-exchange audit insert failed (non-fatal)");
        }
    }

    tracing::info!(
        subscriber = client_id,
        publisher = %publisher_claims.sub,
        scope = %scope_str,
        "publisher-token exchange: delegated token minted"
    );

    Ok(Json(TokenResponse {
        access_token: token,
        refresh_token: None,
        token_type: "Bearer".into(),
        expires_in: ttl_secs as u64,
        scope: if scope_str.is_empty() {
            None
        } else {
            Some(scope_str)
        },
        id_token: None,
    }))
}

// ── Introspect ──────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
/// Response payload for introspection.
pub struct IntrospectionResponse {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The token tp.
    pub token_tp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The roles.
    pub roles: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The groups.
    pub groups: Option<Vec<String>>,
}

/// Introspect it.
#[utoipa::path(
    post,
    path = "/oauth/introspect",
    params(
        ("token" = String, Query, description = "The token to introspect"),
        ("client_id" = String, Query, description = "Caller client (or Basic auth)"),
        ("client_secret" = String, Query, description = "Caller secret (or Basic auth)"),
    ),
    responses(
        (status = 200, description = "RFC 7662 introspection response (active + claims when active)", body = IntrospectionResponse),
        (status = 401, description = "Caller authentication failed (RFC 7662 requires client auth)"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Form(req): axum::Form<IntrospectRequest>,
) -> Result<Response, (StatusCode, String)> {
    // SEC- - RFC 7662 : the caller MUST authenticate.
    let client = authenticate_client(
        &state,
        &headers,
        req.client_id.as_deref(),
        req.client_secret.as_deref(),
        None,
        true,
        // RFC 7662 : introspection requires client auth - a public
        // client_id alone is NOT sufficient.
        false,
    )
    .await?;

    // . - RFC 9701 JWT introspection. The signed JWT form is
    // returned when the caller requests it (Accept: application/token-
    // introspection+jwt) or when the caller's env-resolved profile mandates
    // it (fapi_2_message_signing). The plain JSON form remains the default.
    let profile = resolve_security_profile(&state.pool, &headers, "env").await;
    let jwt_requested = crate::jwt_introspection::wants_jwt_response(&headers);
    let jwt_form = jwt_requested || profile.require_jwt_introspection;

    // SEC- - VERIFIED decode: a forged or expired token must
    // report `active: false`, never leak claims. Denylisted (revoked)
    // tokens are inactive too (SEC-).
    let verified = verify_access_token_claims(&state, &req.token)
        .ok()
        .filter(|c| c.exp > chrono::Utc::now().timestamp());
    let claims = match verified {
        Some(c) if !is_token_revoked(&state, &c.jti).await => c,
        _ => {
            let inactive = IntrospectionResponse {
                active: false,
                scope: None,
                client_id: None,
                sub: None,
                exp: None,
                env_id: None,
                token_tp: None,
                roles: None,
                groups: None,
            };
            return Ok(render_introspection(&state, jwt_form, &client.client_id, inactive).await);
        }
    };

    let active = true;
    let exp = claims.exp;
    let sub = claims.sub.clone();
    let token_tp = claims.token_tp.clone();
    let env_id = claims.env_id.clone();
    let client_id = claims.client_id.clone().or_else(|| {
        if claims.token_tp == "m2m" {
            Some(claims.sub.clone())
        } else {
            None
        }
    });
    let sub_out = if claims.token_tp != "m2m" {
        Some(sub.clone())
    } else {
        None
    };

    // Resolve roles/groups (introspection-only).
    let (roles, groups): (Option<Vec<String>>, Option<Vec<String>>) = if active {
        if token_tp == "m2m" {
            let r = if let Ok(cid) = Uuid::parse_str(&sub) {
                crate::handlers::client_role_names(&state.pool, cid)
                    .await
                    .unwrap_or_default()
            } else {
                vec![]
            };
            (if r.is_empty() { None } else { Some(r) }, None)
        } else if let Ok(uid) = Uuid::parse_str(&sub) {
            let r = crate::handlers::user_role_names(&state.pool, uid)
                .await
                .unwrap_or_default();
            let g = crate::handlers::user_group_names(&state.pool, uid)
                .await
                .unwrap_or_default();
            (
                if r.is_empty() { None } else { Some(r) },
                if g.is_empty() { None } else { Some(g) },
            )
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    let plain = IntrospectionResponse {
        active,
        scope: if claims.scope.is_empty() {
            None
        } else {
            Some(claims.scope)
        },
        client_id,
        sub: sub_out,
        exp: Some(exp),
        env_id,
        token_tp: Some(token_tp),
        roles,
        groups,
    };
    Ok(render_introspection(&state, jwt_form, &client.client_id, plain).await)
}

/// Render an introspection response in the requested form (.):
/// plain JSON (RFC 7662 default) or the signed JWT form (RFC 9701) with
/// `content-type: application/token-introspection+jwt`. The JWT `aud` is
/// the authenticated introspecting client's client_id.
async fn render_introspection(
    state: &AppState,
    jwt_form: bool,
    caller_client_id: &str,
    plain: IntrospectionResponse,
) -> Response {
    if !jwt_form {
        return Json(plain).into_response();
    }
    let aud = if caller_client_id.is_empty() {
        plain
            .client_id
            .clone()
            .unwrap_or_else(|| "introspecting-client".to_string())
    } else {
        caller_client_id.to_string()
    };
    match crate::jwt_introspection::jwt_introspection_response(
        &state.keys,
        &state.config.issuer,
        &aud,
        plain.active,
        plain.scope.clone(),
        plain.client_id.clone(),
        plain.sub.clone(),
        plain.exp,
        plain.env_id.clone(),
    ) {
        Ok((status, headers, jwt)) => {
            let mut builder = Response::builder().status(status);
            for (k, v) in &headers {
                builder = builder.header(k, v);
            }
            builder
                .body(axum::body::Body::from(jwt))
                .unwrap_or_else(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "introspection render error".to_string(),
                    )
                        .into_response()
                })
        }
        Err(e) => {
            tracing::error!(error = %e, "JWT introspection signing failed - falling back to plain JSON");
            Json(plain).into_response()
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for introspect.
pub struct IntrospectRequest {
    /// The token.
    pub token: String,
    #[serde(default)]
    /// client identifier.
    pub client_id: Option<String>,
    #[serde(default)]
    /// The client secret.
    pub client_secret: Option<String>,
}

// ── Revoke (RFC 7009 - SEC-) ─────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for revoke.
pub struct RevokeRequest {
    /// The token.
    pub token: String,
    /// RFC 7009 - a hint about the token type (optional).
    #[serde(default)]
    /// The token type hint.
    pub token_type_hint: Option<String>,
    #[serde(default)]
    /// client identifier.
    pub client_id: Option<String>,
    #[serde(default)]
    /// The client secret.
    pub client_secret: Option<String>,
}

/// `POST /oauth/revoke` - RFC 7009 token revocation.
///
/// The caller MUST authenticate (client auth, SEC-). Refresh
/// tokens are denylisted by `jti` AND their matching DB sessions are
/// revoked; access tokens are denylisted by `jti` for their remaining
/// lifetime. Per RFC 7009 the endpoint returns 200 even for unknown
/// tokens (after client auth) - never an oracle.
/// Revoke it.
#[utoipa::path(
    post,
    path = "/oauth/revoke",
    params(
        ("token" = String, Query, description = "The token to revoke"),
        ("client_id" = String, Query, description = "Caller client (or Basic auth)"),
        ("client_secret" = String, Query, description = "Caller secret (or Basic auth)"),
    ),
    responses(
        (status = 200, description = "Revoked (RFC 7009: 200 even for unknown tokens)"),
        (status = 401, description = "Client authentication failed"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Form(req): axum::Form<RevokeRequest>,
) -> Result<StatusCode, TokenError> {
    // Client auth is mandatory on revocation (RFC 7009 ).
    let _client = authenticate_client(
        &state,
        &headers,
        req.client_id.as_deref(),
        req.client_secret.as_deref(),
        None,
        true,
        // RFC 7009 : revocation requires client auth.
        false,
    )
    .await
    .map_err(|(s, m)| TokenError::OAuth(OAuthTokenError::with_desc(s, "invalid_client", m)))?;

    // Verify + classify the token. Unverifiable tokens are still 200
    // (RFC 7009 - no oracle).
    if let Ok(claims) = verify_access_token_claims(&state, &req.token) {
        let remaining = (claims.exp - chrono::Utc::now().timestamp()).max(1);
        match claims.token_tp.as_str() {
            "refresh" => {
                // Denylist the jti...
                revoke_jti(&state, &claims.jti, remaining).await;
                // ...and revoke the user's active sessions so the cookie
                // dies with the refresh token (defense-in-depth).
                if let Ok(uid) = Uuid::parse_str(&claims.sub) {
                    let _ = sqlx::query(
                        r#"UPDATE sessions SET status = 'revoked', updated_at = now()
                           WHERE user_id = $1 AND status = 'active'"#,
                    )
                    .bind(uid)
                    .execute(&state.pool)
                    .await;
                    // Continuous access evaluation (auth DESIGN §10): subject-scope
                    // revocation - the BFF session-reaper kills every cached BFF
                    // session for the user on the next request. Best-effort emit
                    // (own tx, never blocks the revocation above).
                    let env_id = claims
                        .env_id
                        .as_deref()
                        .and_then(|s| Uuid::parse_str(s).ok())
                        .unwrap_or(SYSTEM_ENV_ID);
                    crate::events::emit_event(
                        &state.pool,
                        env_id,
                        "sentin8:auth:session:revoked",
                        crate::events::session_revoked_payload(
                            &claims.sub,
                            &env_id.to_string(),
                            None,
                            &_client.client_id,
                            "oauth_revoke",
                        ),
                    )
                    .await;
                }
                tracing::info!(
                    jti = %claims.jti,
                    client = %_client.client_id,
                    "refresh token revoked (denylist + sessions)"
                );
            }
            "access" | "m2m" | "delegated" => {
                revoke_jti(&state, &claims.jti, remaining).await;
                tracing::info!(
                    jti = %claims.jti,
                    token_tp = %claims.token_tp,
                    client = %_client.client_id,
                    "access token revoked (denylist)"
                );
            }
            _ => {
                // Unknown token type - still 200.
            }
        }
    }

    Ok(StatusCode::OK)
}

// ── UserInfo ────────────────────────────────────────────────────────────

/// Handle userinfo.
#[utoipa::path(
    get,
    path = "/oauth/userinfo",
    responses(
        (status = 200, description = "OIDC Standard Claims for the bearer subject", body = crate::dtos::OidcClaims),
        (status = 401, description = "Missing/invalid/expired bearer token"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<OidcClaims>, (StatusCode, String)> {
    let token = extract_bearer_token(&headers)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing bearer token".into()))?;

    // SEC- - VERIFIED decode: forged/expired tokens get 401.
    let claims = verify_access_token_claims(&state, &token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("invalid token: {}", e.1)))?;

    // Delegated tokens resolve the ACT user's identity (
    // policy design ): step-5 live identity resolution sends the raw
    // Bearer here, and a BFF-Delegation-Gateway token IS the standard shape
    // of env-targeted proxy calls. The delegation mint already verified the
    // act user (`may_act` - env access + admin scope) and downscoped the
    // scope set to the staff entitlement, so the resolution returns the act
    // user's LIVE roles/scopes - policy evaluation then matches the human
    // the token acts for. `sub` stays the BFF client id (reported as
    // `client_id`); the id_token-style email/act chain is not leaked.
    if claims.token_tp == "delegated" {
        let act_sub = claims
            .act
            .as_ref()
            .and_then(|a| a.get("sub"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    "delegated token missing act".into(),
                )
            })?;
        let act_user_id = Uuid::parse_str(act_sub).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "delegated act is not a user".into(),
            )
        })?;
        // - same-connection tenant context as the non-delegated branch
        // below. The delegated token's env is the TARGET env, but the act user
        // may live in EITHER env: a platform operator's row is in the SYSTEM
        // env, a tenant staff user's row is in the target env. The SELECT
        // policy is `env_id = sentin8_current_env_id` - a single context
        // cannot span both, so probe SYSTEM first, then the target env
        // (: the operator act user in SYSTEM env
        // was invisible under the target-env context → 401 "delegated act
        // user unknown" → fail-closed deny despite a successful mint).
        // Role/scope resolution below uses the platform-level helpers
        // (SYSTEM_ENV_ID context), matching `fetch_role_scopes`.
        let user = {
            let target_env = claims
                .env_id
                .as_deref()
                .and_then(|s| Uuid::parse_str(s).ok())
                .unwrap_or(SYSTEM_ENV_ID);
            let mut tx = state
                .pool
                .begin()
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            // 1) SYSTEM env - platform operator act users.
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                .bind(SYSTEM_ENV_ID)
                .execute(&mut *tx)
                .await;
            let mut row = sqlx::query_as::<_, (String, Option<String>, Option<String>)>(
                r#"SELECT email, first_name, last_name FROM users WHERE id = $1"#,
            )
            .bind(act_user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            // 2) Target env - tenant staff act users (only when different).
            if row.is_none() && target_env != SYSTEM_ENV_ID {
                let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                    .bind(target_env)
                    .execute(&mut *tx)
                    .await;
                let r = sqlx::query_as::<_, (String, Option<String>, Option<String>)>(
                    r#"SELECT email, first_name, last_name FROM users WHERE id = $1"#,
                )
                .bind(act_user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                row = r;
            }
            tx.commit()
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            row
        };
        let Some((email, first_name, last_name)) = user else {
            return Err((
                StatusCode::UNAUTHORIZED,
                "delegated act user unknown".into(),
            ));
        };
        let roles = crate::handlers::user_role_names(&state.pool, act_user_id)
            .await
            .unwrap_or_default();
        let scopes = crate::handlers::fetch_role_scopes(&state.pool, act_user_id)
            .await
            .unwrap_or_default();
        return Ok(Json(OidcClaims {
            sub: act_user_id.to_string(),
            email: Some(email),
            given_name: first_name,
            family_name: last_name,
            roles: Some(roles),
            groups: None,
            scopes: Some(scopes),
            client_id: Some(claims.sub),
            token_tp: Some(claims.token_tp),
        }));
    }

    if claims.token_tp != "access" && claims.token_tp != "m2m" {
        return Err((StatusCode::UNAUTHORIZED, "not an access token".into()));
    }

    // For user tokens, look up the user + resolved roles/groups.
    if let Ok(user_id) = Uuid::parse_str(&claims.sub) {
        // - the users table is FORCE-RLS'd; the token's env is the
        // tenant context for this lookup. A bare-pool read here silently
        // hides the user row (fetch_optional → None) and the handler falls
        // through to the M2M branch, returning roles:[] for every user
        // (: Shield denied everything because the live
        // identity resolved role-less). Same-connection context in an
        // explicit transaction.
        let user = {
            let mut tx = state
                .pool
                .begin()
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                .bind(
                    claims
                        .env_id
                        .as_deref()
                        .and_then(|s| Uuid::parse_str(s).ok())
                        .unwrap_or(SYSTEM_ENV_ID),
                )
                .execute(&mut *tx)
                .await;
            let row = sqlx::query!(
                r#"SELECT email, first_name, last_name FROM users WHERE id = $1"#,
                user_id,
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            tx.commit()
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            row
        };

        if let Some(u) = user {
            // Resolved role names (direct + group-derived + nesting closure).
            let roles = crate::handlers::user_role_names(&state.pool, user_id)
                .await
                .unwrap_or_default();
            // Direct group memberships (names).
            let groups = crate::handlers::user_group_names(&state.pool, user_id)
                .await
                .unwrap_or_default();
            // LIVE effective scope set (design ): the role-permission
            // closure recomputed per request - the same computation sign-in
            // stamps into the JWT. Consumers (sentin8-policy resolver) use
            // this as the live `principal.scopes` input.
            let scopes = crate::handlers::fetch_role_scopes(&state.pool, user_id)
                .await
                .unwrap_or_default();
            return Ok(Json(OidcClaims {
                sub: claims.sub,
                email: Some(u.email),
                given_name: u.first_name,
                family_name: u.last_name,
                roles: Some(roles),
                groups: Some(groups),
                scopes: Some(scopes),
                client_id: claims.client_id,
                token_tp: None,
            }));
        }
    }

    // For M2M tokens, return the subject + assigned roles (client-role
    // assignments resolved over nesting) + the client's effective scope set
    // (its own registered scopes ∪ client-role permissions - design ).
    // Groups are not present for M2M (apps aren't group members).
    let (roles, scopes) = if let Ok(client_db_id) = Uuid::parse_str(&claims.sub) {
        let roles = crate::handlers::client_role_names(&state.pool, client_db_id)
            .await
            .unwrap_or_default();
        let role_scopes = crate::handlers::fetch_client_role_scopes(&state.pool, client_db_id)
            .await
            .unwrap_or_default();
        // Union with the client's own registered scopes (the client's
        // `oauth_clients.scopes` column) - mirrors the token-mint union.
        let mut scope_set: std::collections::BTreeSet<String> = claims
            .scope
            .split_whitespace()
            .map(str::to_string)
            .collect();
        for s in role_scopes {
            scope_set.insert(s);
        }
        let scopes: Vec<String> = scope_set.into_iter().collect();
        (roles, scopes)
    } else {
        (vec![], vec![])
    };
    Ok(Json(OidcClaims {
        sub: claims.sub,
        email: None,
        given_name: None,
        family_name: None,
        roles: Some(roles),
        groups: None,
        scopes: Some(scopes),
        client_id: claims.client_id,
        token_tp: Some("m2m".to_string()),
    }))
}

// ── Logout ──────────────────────────────────────────────────────────────

/// Handle logout.
#[utoipa::path(
    get,
    path = "/oauth/logout",
    params(LogoutQuery),
    responses(
        (status = 302, description = "Redirect to the registered post_logout_redirect_uri (or the local sign-in page when unregistered)"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<LogoutQuery>,
) -> Response {
    // RP-initiated logout - clear session cookie and redirect to
    // post_logout_redirect_uri. SEC- - the redirect target must
    // be registered for the client (`post_logout_redirect_uris`); otherwise
    // fall back to the local sign-in page (open-redirect defense).
    let redirect: String = match q.post_logout_redirect_uri.as_deref() {
        None => "/sign-in".to_string(),
        Some(uri) if uri.is_empty() => "/sign-in".to_string(),
        Some(uri) => {
            // id_token_hint (preferred) or client_id identifies the client
            // whose post_logout_redirect_uris we validate against.
            let client_row: Option<(String, Vec<String>)> = if let Some(hint) =
                q.id_token_hint.as_deref()
            {
                let aud: Option<String> =
                    crate::enterprise_connections::decode_jwt_unverified(hint)
                        .ok()
                        .and_then(|c| c.get("aud").and_then(|v| v.as_str()).map(|s| s.to_string()));
                sqlx::query_as(
                    r#"SELECT client_id, post_logout_redirect_uris FROM oauth_clients
                       WHERE client_id = $1"#,
                )
                .bind(aud)
                .fetch_optional(&state.pool)
                .await
                .ok()
                .flatten()
            } else if let Some(cid) = q.client_id.as_deref() {
                sqlx::query_as(
                    r#"SELECT client_id, post_logout_redirect_uris FROM oauth_clients
                       WHERE client_id = $1"#,
                )
                .bind(cid)
                .fetch_optional(&state.pool)
                .await
                .ok()
                .flatten()
            } else {
                None
            };

            match client_row {
                Some((_client_id, post_logout_uris))
                    if post_logout_uris.iter().any(|u| u == uri) =>
                {
                    uri.to_string()
                }
                _ => {
                    tracing::warn!(
                        uri = %uri,
                        "logout: unregistered post_logout_redirect_uri refused - falling back to /sign-in"
                    );
                    "/sign-in".to_string()
                }
            }
        }
    };
    let cookie_domain =
        crate::sessions::cookie_domain_from_headers(&headers, &state.config.sentin8_domain);
    (
        StatusCode::FOUND,
        [
            ("set-cookie", Session::clear_cookie(&cookie_domain)),
            ("location", redirect),
        ],
    )
        .into_response()
}

#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The logoutquery type.
pub struct LogoutQuery {
    #[serde(default)]
    /// The post logout redirect URI.
    pub post_logout_redirect_uri: Option<String>,
    /// OIDC RP-Initiated Logout - the ID token issued to the client;
    /// its `aud` identifies the client for allow-list validation.
    #[serde(default)]
    /// The id token hint.
    pub id_token_hint: Option<String>,
    /// Alternative client identification for the allow-list.
    #[serde(default)]
    /// client identifier.
    pub client_id: Option<String>,
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Is `uri` registered for the client? Exact string match, with RFC 8252
/// loopback port equivalence for native apps (SEC-).
fn redirect_uri_registered(registered: &[String], uri: &str) -> bool {
    if registered.is_empty() || uri.is_empty() {
        return false;
    }
    if registered.iter().any(|r| r == uri) {
        return true;
    }
    // Loopback equivalence: any port on.1 / [::1] matches a
    // registered loopback redirect with any port (RFC 8252 ).
    registered
        .iter()
        .any(|r| crate::native_apps::redirect_uri_matches(r, uri))
}

/// Look up an OAuth client's routing metadata (consent_required,
/// redirect_uris) with the RLS tenant context set on the SAME connection
/// (SEC-). `oauth_clients` is FORCE RLS - a bare pool
/// query returns no rows under the app role.
///
/// The context env is resolved from the platform system env (authorize is
/// a pre-authentication endpoint - there is no session env yet; clients
/// are created in the env the DCR/admin call resolved, and test/dev
/// deployments default to the system env).
async fn with_client_env(
    state: &AppState,
    client_id: String,
) -> Option<(bool, Vec<String>, Vec<String>)> {
    let mut tx = state.pool.begin().await.ok()?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(crate::config::SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;
    let row = sqlx::query!(
        r#"SELECT consent_required, redirect_uris, authorization_details_types
             FROM oauth_clients WHERE client_id = $1"#,
        client_id,
    )
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    row.map(|r| {
        (
            r.consent_required,
            r.redirect_uris,
            r.authorization_details_types,
        )
    })
}

/// Verify a JAR request object (RFC 9101) against the client's registered
/// keys and validate its claims (SEC-). Returns the parsed JAR
/// claims on success.
async fn verify_jar_request(
    state: &AppState,
    client_id: &str,
    request_jwt: &str,
    issuer: &str,
) -> Result<crate::jar::JarClaims, String> {
    use sqlx::Row;
    // Unverified decode first - to read routing claims and find the key.
    let claims = crate::jar::decode_jar_unverified(request_jwt)?;
    crate::jar::validate_jar_claims(&claims, issuer)?;

    // exp is mandatory for JAR request objects (RFC 9101 recommendation
    // made binding here; fresh within ±10 minutes).
    let raw = sentin8::auth::jwt::decode_payload(request_jwt)?;
    let exp = raw
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "JAR request object must carry an exp claim".to_string())?;
    let now = chrono::Utc::now().timestamp();
    if exp < now - 600 || exp > now + 600 {
        return Err("JAR request object exp out of range (±10min)".into());
    }

    // Resolve the client's registered keys.
    let row = sqlx::query(r#"SELECT jwks, jwks_uri FROM oauth_clients WHERE client_id = $1"#)
        .bind(client_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| format!("client lookup: {e}"))?
        .ok_or_else(|| "unknown client".to_string())?;
    let jwks: Option<serde_json::Value> = row.try_get("jwks").ok().flatten();
    let jwks_uri: Option<String> = row.try_get("jwks_uri").ok().flatten();

    // Signature verification against either inline jwks or fetched jwks_uri.
    let mut verified = false;
    if let Some(doc) = &jwks {
        if let Some(keys) = doc.get("keys").and_then(|k| k.as_array()) {
            verified = keys
                .iter()
                .any(|k| crate::jwks::SigningKeys::verify_with_jwk(k, request_jwt).is_ok());
        }
    }
    if !verified {
        if let Some(uri) = &jwks_uri {
            if let Some(keys) = fetch_external_jwks(state, uri).await {
                verified = keys
                    .iter()
                    .any(|k| crate::jwks::SigningKeys::verify_with_jwk(k, request_jwt).is_ok());
            }
        }
    }
    if !verified {
        return Err("JAR request object signature verification failed".into());
    }
    Ok(claims)
}

/// Extract a Bearer token from the Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth_header = headers.get(axum::http::header::AUTHORIZATION)?;
    let auth_str = auth_header.to_str().ok()?;
    auth_str.strip_prefix("Bearer ").map(|s| s.to_string())
}

/// PKCE S256 challenge computation.
fn pkce_s256_challenge(verifier: &str) -> String {
    use base64::Engine;
    let hash = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// Minimal URL-encoding for redirect URLs.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

/// Simple glob pattern matcher for consent flow trigger patterns.
/// Supports `*` (matches any sequence of characters within a segment)
/// and literal text. E.g. `bank8:fdx:*` matches `bank8:fdx:recipient:read`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_impl(&p, 0, &t, 0)
}

fn glob_match_impl(p: &[char], pi: usize, t: &[char], ti: usize) -> bool {
    if pi == p.len() {
        return ti == t.len();
    }
    if p[pi] == '*' {
        // Try matching zero or more characters.
        if glob_match_impl(p, pi + 1, t, ti) {
            return true;
        }
        if ti < t.len() && glob_match_impl(p, pi, t, ti + 1) {
            return true;
        }
        return false;
    }
    if ti < t.len() && p[pi] == t[ti] {
        return glob_match_impl(p, pi + 1, t, ti + 1);
    }
    false
}

// Re-export Session for the logout handler (regular comment - not attached
// to the device-authorization section below).

// ── Device Authorization Grant (RFC 8628) ───────────────────────────────
//OAuth 2.0 Device Authorization Grant for the sentin8 CLI.

/// `POST /oauth/device` - request a device code.
///
/// .5 (design ): the requesting client is authenticated and
/// the device code is bound to it - the polling grant must present the
/// same client.
/// Handle device authorization.
#[utoipa::path(
    post,
    path = "/oauth/device",
    params(
        ("client_id" = String, Query, description = "Requesting client id"),
        ("scope" = String, Query, description = "Requested scope"),
    ),
    responses(
        (status = 200, description = "Device code + user_code + verification_uri (RFC 8628 §3.2)", body = DeviceAuthResponse),
        (status = 400, description = "Unknown client"),
        (status = 401, description = "Client authentication failed"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn device_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Form(req): axum::Form<DeviceAuthRequest>,
) -> Result<Json<DeviceAuthResponse>, (StatusCode, String)> {
    // SEC- - client auth (public CLI client resolves by id).
    let client = authenticate_client(
        &state,
        &headers,
        Some(req.client_id.as_str()),
        None,
        None,
        true,
        true,
    )
    .await?;

    let device_code = Uuid::new_v4().to_string();
    let user_code = generate_user_code();
    let issuer = state.config.issuer.clone();
    let verification_uri = format!("{issuer}/device");
    let verification_uri_complete = format!("{verification_uri}?user_code={user_code}");
    let expires_in: u64 = 900;
    let interval: u64 = 5;

    // Store the device code in Valkey with the requested scope + client_id.
    let valkey_url = &state.config.valkey_url;
    let valkey_conn = sentin8::middleware::valkey_client(valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let key = format!("auth:device_code:{device_code}");
    let data = serde_json::json!({
        "client_id": client.client_id,
        "scope": req.scope.unwrap_or_default(),
        "audience": req.audience.unwrap_or_default(),
        "user_code": user_code,
        "status": "pending",
    });
    let _: () = valkey_conn
        .set_ex(&key, data.to_string(), expires_in)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Also store user_code → device_code mapping for the /device verification page.
    let uc_key = format!("auth:user_code:{user_code}");
    let _: () = valkey_conn
        .set_ex(&uc_key, &device_code, expires_in)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(DeviceAuthResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete: Some(verification_uri_complete),
        expires_in,
        interval,
    }))
}

/// `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`.
///
/// Returns RFC 8628 polling errors (`authorization_pending`, `access_denied`,
/// `expired_token`) as JSON `{"error": "..."}` per RFC 6749 so that
/// polling clients can distinguish pending from real failures.
async fn handle_device_code(
    state: &AppState,
    client: &AuthenticatedClient,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, TokenError> {
    let device_code = req.code.as_deref().ok_or_else(|| {
        TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "device_code is required",
        ))
    })?;
    let valkey_url = &state.config.valkey_url;
    let valkey_conn = sentin8::middleware::valkey_client(valkey_url, "sentin8:auth")
        .await
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let key = format!("auth:device_code:{device_code}");
    let data: Option<String> = valkey_conn
        .get(&key)
        .await
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let data = data.ok_or_else(|| {
        TokenError::OAuth(OAuthTokenError::new(
            StatusCode::BAD_REQUEST,
            "expired_token",
        ))
    })?;
    let data: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let status = data["status"].as_str().unwrap_or("pending");
    if status == "pending" {
        return Err(TokenError::OAuth(OAuthTokenError::new(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
        )));
    }
    if status == "denied" {
        return Err(TokenError::OAuth(OAuthTokenError::new(
            StatusCode::BAD_REQUEST,
            "access_denied",
        )));
    }

    // .5 (design ) - the polling client must match the client
    // that started the device flow.
    let stored_device_client = data["client_id"].as_str().unwrap_or("");
    if stored_device_client != client.client_id {
        return Err(TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "device_code was issued to a different client",
        )));
    }

    // status == "approved" - extract user_id, env_id, scope, audience.
    let user_id: Uuid = data["user_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, "missing user_id".into())
        })?;
    let env_id: Uuid = data["env_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(SYSTEM_ENV_ID);
    let scope = data["scope"].as_str().unwrap_or("openid profile email");
    let audience = data["audience"].as_str().unwrap_or("");

    let user_row = sqlx::query!(
        r#"SELECT email, first_name, last_name FROM users WHERE id = $1"#,
        user_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let email = user_row.as_ref().map(|r| r.email.clone());

    // Merge group scopes.
    let role_scopes = crate::handlers::fetch_role_scopes(&state.pool, user_id)
        .await
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let merged_scope = crate::handlers::merge_scopes(scope, &role_scopes);

    let access_claims = AuthClaims::access(
        &state.config.issuer,
        user_id,
        &merged_scope,
        env_id,
        email.as_deref(),
        Duration::seconds(state.config.access_token_ttl_secs as i64),
    );
    // Apply the requested audience (RFC 8628 ) - e.g. `sentin8` for
    // platform-wide CLI access, or a specific service like `bus`.
    let mut access_claims = access_claims;
    if !audience.is_empty() {
        access_claims.aud = Some(audience.to_string());
    }
    let access_token = state
        .keys
        .sign(&access_claims)
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let refresh_token = {
        let refresh_claims = AuthClaims::refresh(
            &state.config.issuer,
            user_id,
            &merged_scope,
            env_id,
            Duration::seconds(state.config.refresh_token_ttl_secs as i64),
        );
        state
            .keys
            .sign(&refresh_claims)
            .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    // Delete the device code from Valkey.
    let _: () = valkey_conn
        .del(&key)
        .await
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let uc_key = format!(
        "auth:user_code:{}",
        data["user_code"].as_str().unwrap_or("")
    );
    let _: () = valkey_conn
        .del(&uc_key)
        .await
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(TokenResponse {
        access_token,
        refresh_token: Some(refresh_token),
        token_type: "Bearer".into(),
        expires_in: state.config.access_token_ttl_secs,
        scope: Some(merged_scope),
        id_token: None,
    }))
}

/// CIBA token grant - `urn:ietf:params:grant-type:ciba`.
///
/// Polled by BFF's `delegate_poll`. Checks the CIBA request status in Valkey:
/// - `pending` → 400 `authorization_pending`
/// - `denied` → 400 `access_denied`
/// - `expired` → 400 `expired_token`
/// - `approved` → issue access + refresh token for the customer
///
/// Returns RFC 8705 polling errors as JSON `{"error": "..."}` per
/// RFC 6749 so that BFF's `delegate_poll` can parse the `error` field
/// and report `pending` instead of failing JSON parsing (which previously
/// surfaced as a spurious 502 to the eTeller UI).
async fn handle_ciba_token(
    state: &AppState,
    client: &AuthenticatedClient,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, TokenError> {
    let auth_req_id = req
        .code
        .as_deref()
        .or(req.auth_req_id.as_deref())
        .ok_or_else(|| {
            TokenError::OAuth(OAuthTokenError::with_desc(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "auth_req_id is required for CIBA grant",
            ))
        })?;

    let valkey_url = &state.config.valkey_url;
    let valkey_conn = sentin8::middleware::valkey_client(valkey_url, "sentin8:auth")
        .await
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let key = format!("auth:ciba:{auth_req_id}");
    let data: Option<String> = valkey_conn
        .get(&key)
        .await
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let data = data.ok_or_else(|| {
        TokenError::OAuth(OAuthTokenError::new(
            StatusCode::BAD_REQUEST,
            "expired_token",
        ))
    })?;
    let data: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let status = data["status"].as_str().unwrap_or("pending");
    if status == "pending" {
        return Err(TokenError::OAuth(OAuthTokenError::new(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
        )));
    }
    if status == "denied" {
        return Err(TokenError::OAuth(OAuthTokenError::new(
            StatusCode::BAD_REQUEST,
            "access_denied",
        )));
    }

    // .5 (design ) - the polling client must match the client
    // that started the CIBA request (stored by bc_authorize).
    let stored_client = data["client_id"].as_str().unwrap_or("");
    if stored_client != client.client_id {
        return Err(TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "auth_req_id was issued to a different client",
        )));
    }

    // status == "approved" - extract user_id, env_id, scope.
    let user_id: Uuid = data["user_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, "missing user_id".into())
        })?;
    let env_id: Uuid = data["env_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(SYSTEM_ENV_ID);
    let scope = data["scope"].as_str().unwrap_or("openid profile email");

    let user_row = sqlx::query!(
        r#"SELECT email, first_name, last_name FROM users WHERE id = $1"#,
        user_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let email = user_row.as_ref().map(|r| r.email.clone());

    // Merge group scopes.
    let role_scopes = crate::handlers::fetch_role_scopes(&state.pool, user_id)
        .await
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let merged_scope = crate::handlers::merge_scopes(scope, &role_scopes);

    // (Option A): if the CIBA request was initiated by a staff member
    // (BFF Delegation Gateway passed act_sub/act_email), the token is a
    // customer-consented DELEGATED token: `sub` = customer, `act` = staff
    // (RFC 8693 ), short TTL (300s - time-boxed consent). Without a
    // staff actor this is a plain customer CIBA token (decoupled-device
    // self-approval) with the platform default TTL.
    let act_sub = data["act_sub"].as_str().filter(|s| !s.is_empty());
    let act_email = data["act_email"].as_str().filter(|s| !s.is_empty());
    let delegation_ttl_secs: u64 = 300;
    let (access_claims, effective_ttl) = match act_sub {
        Some(staff_sub) => {
            let mut claims = AuthClaims::access(
                &state.config.issuer,
                user_id,
                &merged_scope,
                env_id,
                email.as_deref(),
                Duration::seconds(delegation_ttl_secs as i64),
            );
            claims.act = Some(serde_json::json!({
                "sub": staff_sub,
                "email": act_email.unwrap_or(""),
            }));
            (claims, delegation_ttl_secs)
        }
        None => (
            AuthClaims::access(
                &state.config.issuer,
                user_id,
                &merged_scope,
                env_id,
                email.as_deref(),
                Duration::seconds(state.config.access_token_ttl_secs as i64),
            ),
            state.config.access_token_ttl_secs,
        ),
    };
    let access_token = state
        .keys
        .sign(&access_claims)
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // : delegated (staff-initiated) CIBA tokens are NOT refreshable -
    // the consent is time-boxed and single-purpose. Re-access requires a
    // new customer approval.
    let refresh_token =
        if act_sub.is_some() {
            None
        } else {
            let refresh_claims = AuthClaims::refresh(
                &state.config.issuer,
                user_id,
                &merged_scope,
                env_id,
                Duration::seconds(state.config.refresh_token_ttl_secs as i64),
            );
            Some(state.keys.sign(&refresh_claims).map_err(|e| {
                TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            })?)
        };

    // Delete the CIBA request from Valkey (one-time use).
    let _: () = valkey_conn.del(&key).await.unwrap_or(());

    // SEC- - OIDC ID token for CIBA grants when `openid` was granted:
    // same claim set as the code-exchange ID token (iss/sub/aud/jti/iat/exp/
    // auth_time/nonce/at_hash + email/profile claims).
    let id_token =
        if merged_scope.split_whitespace().any(|s| s == "openid") {
            let user_name = user_row.as_ref().map(|r| {
                [r.first_name.as_deref(), r.last_name.as_deref()]
                    .iter()
                    .filter_map(|s| *s)
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ")
            });
            let id_claims = AuthClaims::id_token_with_details(
                &state.config.issuer,
                user_id,
                &client.client_id,
                data["nonce"].as_str(),
                data["auth_time"].as_i64().unwrap_or(access_claims.iat),
                &access_token,
                email.as_deref(),
                merged_scope.split_whitespace().any(|s| s == "email"),
                user_name.as_deref().filter(|s| !s.is_empty()),
                merged_scope.split_whitespace().any(|s| s == "profile"),
                Duration::seconds(effective_ttl as i64),
                None,
            );
            Some(state.keys.sign_value(&id_claims).map_err(|e| {
                TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            })?)
        } else {
            None
        };

    // - audit the delegation mint (the customer-data access record).
    if let Some(staff_sub) = act_sub {
        tracing::info!(
            customer_sub = %user_id,
            act_sub = %staff_sub,
            scope = %merged_scope,
            binding_message = %data["binding_message"].as_str().unwrap_or(""),
            "auth: CIBA delegated token minted (staff-initiated, customer-approved)"
        );
    }

    Ok(Json(TokenResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".into(),
        expires_in: effective_ttl,
        scope: Some(merged_scope),
        id_token,
    }))
}

/// `POST /device/verify` - the signed-in user submits the user_code to
/// approve a device sign-in (RFC 8628 ).
///
/// SEC-: this endpoint **requires a valid session** (cookie or
/// Bearer). The approving user is the session's user - `user_id`, `org_id`,
/// and `env_id` are taken from the session, NEVER from the request body,
/// so knowledge of a user_code alone can no longer mint tokens for an
/// arbitrary user.
/// Handle device verify.
#[utoipa::path(
    post,
    path = "/device/verify",
    request_body = DeviceVerifyRequest,
    responses(
        (status = 200, description = "Device sign-in approved (polling grant armed for this user)", body = crate::dtos::DeviceVerifyResponse),
        (status = 400, description = "Unknown user_code"),
        (status = 401, description = "No session - approval requires an authenticated user"),
        (status = 410, description = "user_code expired"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn device_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeviceVerifyRequest>,
) -> Result<Json<DeviceVerifyResponse>, (StatusCode, String)> {
    // Resolve the approving user from their session.
    let session_token = crate::handlers::extract_session_token(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "session required to approve a device sign-in".into(),
        )
    })?;
    // SEC- - mutating session endpoint: CSRF-gated (Bearer exempt).
    crate::handlers::check_csrf(&headers, &session_token)?;
    let session = crate::sessions::Session::find_by_token(&state.pool, &session_token)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid session".into()))?;
    if !session.is_valid() {
        return Err((StatusCode::UNAUTHORIZED, "session expired".into()));
    }

    let valkey_url = &state.config.valkey_url;
    let valkey_conn = sentin8::middleware::valkey_client(valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let uc_key = format!("auth:user_code:{}", req.user_code);
    let device_code: Option<String> = valkey_conn
        .get(&uc_key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let device_code = device_code
        .ok_or_else(|| (StatusCode::NOT_FOUND, "invalid or expired user_code".into()))?;
    let dc_key = format!("auth:device_code:{device_code}");
    let data: Option<String> = valkey_conn
        .get(&dc_key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut data: serde_json::Value = serde_json::from_str(&data.unwrap_or_default())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Set status to approved with the SESSION user's id + env. org_id is
    // resolved from env_id by the token grant (org is not a JWT claim).
    if let Some(obj) = data.as_object_mut() {
        obj.insert("status".into(), "approved".into());
        obj.insert(
            "user_id".into(),
            serde_json::json!(session.user_id.to_string()),
        );
        obj.insert(
            "env_id".into(),
            serde_json::json!(session.env_id.to_string()),
        );
    }
    let _: () = valkey_conn
        .set_ex(&dc_key, data.to_string(), 900)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(DeviceVerifyResponse {
        status: "approved".to_string(),
    }))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for deviceauth.
pub struct DeviceAuthRequest {
    /// client identifier.
    pub client_id: String,
    #[serde(default)]
    /// The scope.
    pub scope: Option<String>,
    /// RFC 8628 - requested audience for the issued token.
    /// The CLI passes `sentin8` for platform-wide access.
    #[serde(default)]
    /// The audience.
    pub audience: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for deviceauth.
pub struct DeviceAuthResponse {
    /// The device code.
    pub device_code: String,
    /// The user code.
    pub user_code: String,
    /// The verification URI.
    pub verification_uri: String,
    /// The verification URI complete.
    pub verification_uri_complete: Option<String>,
    /// The expires in.
    pub expires_in: u64,
    /// The interval.
    pub interval: u64,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for deviceverify.
pub struct DeviceVerifyRequest {
    /// The device user_code being approved. The approving user identity
    /// comes from the session (SEC-) - never the body.
    /// The user code.
    pub user_code: String,
}

/// Generate a random user code in the format `XXXX-XXXX` (8 chars).
fn generate_user_code() -> String {
    use rand::Rng;
    let chars: Vec<char> = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect();
    let mut rng = rand::thread_rng();
    let part1: String = (0..4)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect();
    let part2: String = (0..4)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect();
    format!("{part1}-{part2}")
}
use crate::sessions::Session;
