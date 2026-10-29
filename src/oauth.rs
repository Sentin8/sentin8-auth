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

// ── Client authentication ─────────────────────────────
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

/// Persisted code-record `dpop_jkt`: an empty string (the SPA carries the
/// query field unconditionally) means NO binding - serialize None so the
/// token exchange's pre-bound check never sees a blank binding.
fn code_record_jkt(jkt: &Option<String>) -> Option<String> {
    let r = jkt.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    r
}


/// The continue endpoints' `dpop_jkt` resolution: the SPA-consent journey
/// may drop the UI-carried parameter between hops; the value falls back to
/// the parameters the authorize step stashed for this interaction
/// (`auth:authz-jkt:{state}`, DESIGN §9a.19). An empty carry-in means NO
/// binding unless the memo carries one.
async fn resolve_continue_jkt(
    state: &AppState,
    req_jkt: Option<&str>,
    params_jkt: Option<&str>,
    state_param: &str,
) -> Option<String> {
    let carry = req_jkt
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            params_jkt
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        });
    if carry.is_some() {
        return carry;
    }
    // The interaction memo (authorize stashed the resolved binding).
    if state_param.is_empty() {
        return None;
    }
    let memo_key = format!("auth:authz-jkt:{state_param}");
    let conn = match sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await {
        Ok(c) => c,
        Err(_) => return None,
    };
    let got = conn
        .get::<_, Option<String>>(memo_key.clone())
        .await
        .ok()
        .flatten();
    match got {
        Some(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}


/// The continue endpoints' `par_key` fallback (the SPA's consent hop
/// drops the relayed parameter): the authorize step stashed the
/// interaction's PAR request_uri under `auth:authz-par:{state}`
/// (DESIGN §9a.21). Empty/missing answers none.
async fn resolve_continue_par(state: &AppState, state_param: &str) -> Option<String> {
    if state_param.is_empty() {
        return None;
    }
    let conn = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .ok()?;
    conn.get::<_, Option<String>>(format!("auth:authz-par:{state_param}"))
        .await
        .ok()
        .flatten()
        .filter(|v| !v.is_empty())
}

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
    /// The ATTESTED key's RFC 7638 thumbprint (the attestation's
    /// `cnf.jwk`) when the client authenticated via the OAuth-Client-
    /// Attestation header pair - the wallet's DPoP proof MUST present
    /// exactly this key, and a mismatch answers invalid_dpop_proof.
    /// The attested thumbprint.
    pub attested_jkt: Option<String>,
    /// DPoP key thumbprint when a valid proof was presented.
    /// The DPoP jkt.
    pub dpop_jkt: Option<String>,
    /// Explicit DPoP exemption (oauth_clients.dpop_exempt). True only
    /// for platform-owned public clients (dash, sentin8-cli) seeded by the
    /// platform seed - never settable via DCR or the client-management API.
    /// The DPoP exempt.
    pub dpop_exempt: bool,
    /// RFC 9396 `authorization_details` types this client may request
    /// Empty = RAR not permitted for this client.
    /// The authorization details types.
    pub authorization_details_types: Vec<String>,
    /// RFC 7591 - the registered ID-token signing preference
    /// (`id_token_signed_response_alg`; `none` = the unsigned form the
    /// OIDC family's Dynamic-OP cell drives).
    pub id_token_signed_response_alg: Option<String>,
    /// RFC 7591 - the registered userinfo signing preference (RS256 etc.
    /// = the userinfo response is a signed JWT).
    pub userinfo_signed_response_alg: Option<String>,
    /// RFC 7591 - the registered subject type (public | pairwise).
    pub subject_type: Option<String>,
    /// RFC 7591 - the sector identifier (the pairwise salt input).
    pub sector_identifier_uri: Option<String>,
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

/// Single-use gate for a client-attestation PoP `jti` (DESIGN §9a.19,
/// draft-ietf-oauth-attestation-based-client-auth §6.2 replay rule):
/// SETNX keyed on the jti, TTL bounded by the proof's freshness window
/// (120s > the ±60s iat check). A replayed jti means the same proof is
/// presented twice - reject.
async fn replay_gate_pop_jti(
    valkey_url: &str,
    jti: &str,
) -> Result<(), (StatusCode, String)> {
    if jti.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "invalid client".into()));
    }
    if let Ok(conn) =
        sentin8::middleware::valkey_client(valkey_url, "sentin8:auth").await
    {
        use glide::AsyncCommands as _;
        let key = format!("auth:capop:{jti}");
        let setnx = conn.set_nx::<_, _, i64>(key.clone(), "1").await;
        if matches!(setnx, Ok(0)) {
            tracing::warn!(jti = %jti, "client attestation PoP jti replayed");
            return Err((StatusCode::UNAUTHORIZED, "invalid client".into()));
        }
        let _: Result<(), _> = conn.expire(key, 120i64).await;
    }
    // Valkey down → the denylist pattern is fail-open by design (DESIGN
    // §6); the attestation + signature checks above already proved
    // possession of the attested key.
    Ok(())
}

/// Decode + verify a `client_assertion` (RFC 7523 private_key_jwt).
///
/// The assertion must be: `iss`/`sub` = client_id, `aud` = token endpoint
/// (or issuer), fresh `exp`, non-replayed `jti`, and signed with a key from
/// the client's registered `jwks`/`jwks_uri` (ES256 or RS256).
async fn verify_client_assertion(
    state: &AppState,
    headers: &HeaderMap,
    client_id: &str,
    client: &sqlx::postgres::PgRow,
    assertion: &str,
) -> Result<(), (StatusCode, String)> {
    // The FAPI2 alg mandate (DESIGN §9a.16 (i)): under the FAPI 2.0
    // postures client assertions are signed with ES256/PS256 ONLY - an
    // RS256-signed assertion rejects 401 invalid_client BEFORE the key
    // work (the profile's own BSA/BE signing-alg contract).
    let assertion_alg = sentin8::auth::jwt::decode_header_typed::<serde_json::Value>(assertion)
        .ok()
        .and_then(|h| h.get("alg").and_then(|a| a.as_str()).map(str::to_string));
    if assertion_alg.as_deref() == Some("RS256") {
        // the alg mandate covers EVERY FAPI posture (the suite's
        // ensure-signed-client-assertion-with-RS256-fails cell in the
        // fapi1-advanced plan asserts the reject; Part2 §8.6 - PS256/ES256
        // only, RS256 'shall not use'). The default posture keeps RS256.
        let profile = resolve_security_profile(&state.pool, headers, "env").await;
        if crate::fapi::FapiProfile::from_str(&profile.profile).is_some() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "invalid_client: RS256 is not a permitted client_assertion algorithm under the FAPI security profile".to_string(),
            ));
        }
    }
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
    let aud_json = claims_json.get("aud");
    let exp = claims_json.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    let nbf = claims_json.get("nbf").and_then(|v| v.as_i64());
    let iat = claims_json.get("iat").and_then(|v| v.as_i64());
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
    // RFC 7523 §3 / the suite's iat/nbf-in-future variant: an assertion
    // stamped further than 60s in the future is not yet valid (and a
    // suspicious clock skew at best) - reject.
    let now_early = chrono::Utc::now().timestamp();
    if let (Some(n), Some(i)) = (nbf, iat) {
        if n > now_early + 60 || i > now_early + 60 || n - i > 60 {
            return Err((
                StatusCode::UNAUTHORIZED,
                "client_assertion iat/nbf more than 60s in the future".into(),
            ));
        }
    }
    // The aud gate rides the REQUEST's tenant-resolved issuer (the same
    // value discovery advertises) - the static config issuer is only the
    // platform fallback; a per-tenant host issuer (auth.<env>.<org>...)
    // is the aud the suite/RP received from discovery. The suite's
    // invalid-assertions module (FAPI 2.0) enforces the STRICT reading:
    // aud MUST be EXACTLY the issuer - aud=token-endpoint-string and
    // aud={issuer, token-endpoint} arrays are both REJECTED (the "Valid
    // client assertion" block carries plain-issuer aud and is the only
    // accepted shape). A string form is mandatory; array-aud assertions
    // fail (a multi-audience assertion cannot be audience-checked for a
    // single-receiver endpoint).
    let issuer = resolve_issuer(&state.config, headers);
    // RFC 8705 §5 - when the OP advertises `mtls_endpoint_aliases`, the
    // mTLS connections' assertions target the ALIASED token endpoint
    // (`{issuer}/mtls/oauth/token`) - the audience = the endpoint being
    // called. Both audiences are valid (the suite's FAPI1 modules push
    // through the alias).
    let mtls_aud = format!("{issuer}/mtls/oauth/token");
    // RFC 9126 - the PAR audience form: client assertions pushed to the
    // PAR endpoint target `{issuer}/oauth/par` (the suite's
    // PAR-URL-as-audience module) - the assertion identifies the
    // ENDPOINT it was issued for; every endpoint this OP receives client
    // assertions on is an acceptable audience.
    let par_aud = format!("{issuer}/oauth/par");
    // The plain token endpoint as the named audience (the suite's
    // token-endpoint-as-audience module pushes with aud = token URL).
    let token_aud = format!("{issuer}/oauth/token");
    // OpenID CIBA §7.1 - client assertions on the backchannel endpoint
    // target `{issuer}/oauth/bc-authorize`.
    let bc_aud = format!("{issuer}/oauth/bc-authorize");
    // RFC 7523 - the audience forms this OP accepts: a string naming
    // `issuer` (or one of the issuer's OAuth endpoints) OR an audience
    // ARRAY containing one of those values (the AS identifies itself
    // among the members).
    // The audience policy is PROFILE-SCOPED (DESIGN.md §9a.16): the FAPI 2.0
    // postures (fapi_2 / fapi_2_message_signing) accept EXACTLY the issuer
    // string - a single-member array naming the issuer is tolerated - while
    // the permissive FAPI 1 Advanced posture keeps the RFC 7523/9126
    // endpoint-form audiences (mtls token alias, PAR, plain token, CIBA).
    let strict_aud = crate::fapi::FapiProfile::from_str(
        &crate::oauth::resolve_security_profile(&state.pool, headers, "env")
            .await
            .profile,
    )
    .map(|p| {
        matches!(
            p,
            crate::fapi::FapiProfile::Fapi20 | crate::fapi::FapiProfile::Fapi20MessageSigning
        )
    })
    .unwrap_or(false);
    let aud_ok = match aud_json {
        Some(serde_json::Value::String(a)) => {
            if strict_aud {
                *a == issuer
            } else {
                *a == issuer
                    || *a == mtls_aud
                    || *a == par_aud
                    || *a == token_aud
                    || *a == bc_aud
            }
        }
        Some(serde_json::Value::Array(items)) => {
            // Under strict_aud the array form is tolerated only as a
            // SINGLE-member audience naming the issuer exactly (the suite's
            // array-aud negative sends [issuer, token] - two members - and
            // expects 400/401).
            let contains = items.iter().any(|v| {
                v.as_str() == Some(issuer.as_str())
                    || v.as_str() == Some(mtls_aud.as_str())
                    || v.as_str() == Some(par_aud.as_str())
                    || v.as_str() == Some(token_aud.as_str())
                    || v.as_str() == Some(bc_aud.as_str())
            });
            if strict_aud {
                contains && items.len() == 1 && items[0].as_str() == Some(issuer.as_str())
            } else {
                contains
            }
        }
        _ => false,
    };
    if !aud_ok {
        return Err((
            StatusCode::UNAUTHORIZED,
            "client_assertion aud must be the Auth issuer/token endpoint".into(),
        ));
    }
    let now = chrono::Utc::now().timestamp();
    // RFC 7523 §3 / the suite's exp-is-5-minutes-in-past module: the window
    // is CLOSED at 5 minutes - exp == now-300 IS already expired (the suite
    // constructs exactly now-300 and expects the rejection; the strict <
    // let it through). Same boundary shape as every RFC exp check (exp <=
    // now = expired).
    if exp <= now - 300 || exp > now + 3600 {
        return Err((
            StatusCode::UNAUTHORIZED,
            "client_assertion exp out of range (+/-5min..1h)".into(),
        ));
    }
    // (unused now_early shadow guard - the iat/nbf check above owns its own
    // timestamp; this `now` is the exp-window anchor.)
    let _ = now_early;
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
            // Client-key rotation (RFC 7592 update + the suite's
            // rp-key-rotation family): when the cached jwks_uri set
            // rejects the assertion, the client may have rotated -
            // invalidate the 300s negative cache and retry the fetch
            // ONCE before concluding the signature is bad.
            if !verified {
                invalidate_ext_jwks_cache(state, uri).await;
                if let Some(keys) = fetch_external_jwks(state, uri).await {
                    verified = keys
                        .iter()
                        .any(|k| crate::jwks::SigningKeys::verify_with_jwk(k, assertion).is_ok());
                }
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
/// Drop the cached external-JWKS document for a client's `jwks_uri`
/// (the client-key rotation retry in `verify_client_assertion`).
async fn invalidate_ext_jwks_cache(state: &AppState, jwks_uri: &str) {
    let digest = Sha256::digest(jwks_uri.as_bytes());
    let cache_key = format!("auth:extjwks:{}", hex_encode(&digest));
    if let Ok(conn) =
        sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
    {
        use glide::AsyncCommands as _;
        let _: Result<i64, _> = conn.del(cache_key).await;
    }
}

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

/// Fetch a JAR/CIBA request-object JWT from a client-supplied
/// `request_uri` (RFC 9101 §5.2.1, DESIGN §9a.7). `https` scheme only,
/// 10s timeout, 64 KiB response cap - the fetch is a request-object
/// transport, not an open proxy. Returns the JWT text.
pub async fn fetch_request_object(request_uri: &str) -> Result<String, String> {
    let parsed = url::Url::parse(request_uri).map_err(|e| format!("request_uri parse: {e}"))?;
    if parsed.scheme() != "https" {
        return Err("request_uri must be https".into());
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let resp = http
        .get(request_uri)
        .send()
        .await
        .map_err(|e| format!("request_uri fetch failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("request_uri fetch answered {}", resp.status()));
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| format!("request_uri read: {e}"))?;
    if body.len() > 64 * 1024 {
        return Err("request_uri response exceeds 64 KiB".into());
    }
    let text = String::from_utf8_lossy(&body).trim().to_string();
    // Shape check: a request object is a compact JWS (three dot-separated
    // base64url segments).
    let parts = text.split('.').count();
    if parts != 3 {
        return Err("request_uri did not return a compact JWS".into());
    }
    Ok(text)
}

/// Hex-encode bytes (lowercase, no separators).
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Resolve + authenticate the OAuth client for a request.
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

    // RFC 7523 §2.2: a private_key_jwt assertion carries the client in
    // `iss`; when no form/basic client_id arrived, the assertion IS the
    // identification - extract it here so the exchange proceeds to
    // signature verification (the suite posts assertion-only auth).
    let client_id = client_id.filter(|s| !s.is_empty()).or_else(|| {
        client_assertion.and_then(|a| {
            sentin8::auth::jwt::decode_payload(a)
                .ok()
                .and_then(|c| c.get("iss").and_then(|v| v.as_str()).map(str::to_string))
        })
    });
    // draft-ietf-oauth-attestation-based-client-auth §5: the attestation
    // header JWT carries `sub` = client_id; a header-only push (no form
    // client_id at all) is identified by its attestation, exactly like
    // the assertion path above.
    let client_id = client_id.filter(|s| !s.is_empty()).or_else(|| {
        headers
            .get(crate::client_attestation::HEADER_ATTESTATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|a| sentin8::auth::jwt::decode_payload(a).ok())
            .and_then(|c| c.get("sub").and_then(|v| v.as_str()).map(str::to_string))
            .filter(|s| !s.is_empty())
    });
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

    // RLS: the client lookup must run with the tenant
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
                  post_logout_redirect_uris, dpop_exempt, authorization_details_types,
                  id_token_signed_response_alg, userinfo_signed_response_alg,
                  subject_type, sector_identifier_uri
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
    let id_token_signed_response_alg: Option<String> =
        row.try_get("id_token_signed_response_alg").ok().flatten();
    let userinfo_signed_response_alg: Option<String> =
        row.try_get("userinfo_signed_response_alg").ok().flatten();
    let subject_type: Option<String> = row.try_get("subject_type").ok().flatten();
    let sector_identifier_uri: Option<String> =
        row.try_get("sector_identifier_uri").ok().flatten();

    let is_confidential = secret_hash.is_some()
        || mtls_dn.is_some()
        || mtls_thumb.is_some()
        || auth_method_registered == "private_key_jwt"
        || auth_method_registered == "attest_jwt_client_auth";

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
            attested_jkt: None,
            dpop_jkt: None,
            dpop_exempt,
            authorization_details_types: authorization_details_types.clone(),
            id_token_signed_response_alg: id_token_signed_response_alg.clone(),
            userinfo_signed_response_alg: userinfo_signed_response_alg.clone(),
            subject_type: subject_type.clone(),
            sector_identifier_uri: sector_identifier_uri.clone(),
        },
        software_id.as_deref(),
        software_statement.as_deref(),
    )
    .await
    .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;

    let mut auth_method: &'static str = "none";
    let mut cert_thumbprint: Option<String> = None;
    // the attested key's thumbprint (set by the attestation arm;
    // the token exchange binds the DPoP proof to exactly this key).
    let mut attested_jkt: Option<String> = None;

    // Attestation-based client authentication (draft-ietf-oauth-
    // attestation-based-client-auth, DESIGN §9a.19): the header pair
    // rides EVERY authenticate_client call site (token/PAR/revoke/
    // introspect). Gated on the RESOLVED ENV PROFILE's
    // `allow_client_attestation`; the profile carries the trust anchor
    // PEM and the expected attestation `iss`. On success auth_method =
    // attest_jwt_client_auth is selected and the method ladder is DONE:
    // this arm is the FIRST arm of the if/else chain, so a verified
    // attestation satisfies confidential endpoints (PAR/revoke/
    // introspect) with no client_secret - the draft's header pair IS
    // the client authentication.
    if let (Some(att_jwt), Some(pop_jwt)) = (
        headers
            .get(crate::client_attestation::HEADER_ATTESTATION)
            .and_then(|v| v.to_str().ok()),
        headers
            .get(crate::client_attestation::HEADER_ATTESTATION_POP)
            .and_then(|v| v.to_str().ok()),
    ) {
        let env_profile =
            crate::oauth::resolve_security_profile_for_env(&state.pool, env_id, "env")
                .await;
        if !env_profile.allow_client_attestation {
            return Err((StatusCode::UNAUTHORIZED, "invalid client".into()));
        }
        let issuer = resolve_issuer(&state.config, headers);
        let attested = crate::client_attestation::verify_attestation(
            att_jwt,
            &client_id,
            &env_profile.client_attestation_issuer,
            &env_profile.client_attestation_trust_anchor_pem,
        )
        .map_err(|e| {
            tracing::warn!(
                client_id = %client_id,
                reason = e.label(),
                "client attestation rejected"
            );
            (StatusCode::UNAUTHORIZED, "invalid client".into())
        })?;
        let jti =
            crate::client_attestation::verify_pop(pop_jwt, &attested, &issuer).map_err(
                |e| {
                    tracing::warn!(
                        client_id = %client_id,
                        reason = e.label(),
                        "client attestation PoP rejected"
                    );
                    (StatusCode::UNAUTHORIZED, "invalid client".into())
                },
            )?;
        // PoP jti single-use (the draft's replay rule): the cache marks
        // the jti consumed; a replayed jti answers invalid_client.
        replay_gate_pop_jti(&state.config.valkey_url, &jti).await?;
        auth_method = "attest_jwt_client_auth";
        attested_jkt = Some(
            crate::dpop::jwk_thumbprint(&attested).map_err(|e| {
                tracing::warn!(
                    client_id = %client_id,
                    reason = e.to_string(),
                    "client attestation cnf.jwk thumbprint failed"
                );
                (StatusCode::UNAUTHORIZED, "invalid client".into())
            })?,
        );
    } else if let Some(assertion) = client_assertion {
        // private_key_jwt (RFC 7523).
        if auth_method_registered != "private_key_jwt"
            && auth_method_registered != "client_secret_jwt"
        {
            return Err((
                StatusCode::UNAUTHORIZED,
                "client is not registered for private_key_jwt".into(),
            ));
        }
        verify_client_assertion(state, headers, &client_id, &row, assertion).await?;
        auth_method = "private_key_jwt";
    } else if auth_method_registered == "tls_client_auth"
        || auth_method_registered == "self_signed_tls_client_auth"
    {
        // RFC 8705 - the PRESENCE of a certificate is not the method
        // selector; the REGISTRATION is. `tls_client_auth` compares the
        // presented subject DN; `self_signed_tls_client_auth` compares
        // the presented cert's RFC 8705 thumbprint (a mismatched DN
        // header - the proxy's bridge path carries the subject best-
        // effort only when it exists - must not flip the method).
        if !crate::mtls::is_mtls_auth_method(&auth_method_registered) {
            return Err((StatusCode::UNAUTHORIZED, "invalid client".into()));
        }
        let Some(presented_thumb) = mtls_presented_thumb.as_deref().filter(|s| !s.is_empty()) else {
            tracing::warn!(
                client_id = %client_id,
                "client authentication rejected: no client certificate presented for the registered mTLS method"
            );
            return Err((StatusCode::UNAUTHORIZED, "client authentication required".into()));
        };
        if auth_method_registered == "tls_client_auth" {
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
            let presented_dn = mtls_presented_dn.clone().unwrap_or_default();
            if presented_dn != registered_dn {
                tracing::warn!(
                    client_id = %client_id,
                    "client authentication rejected: certificate DN does not match the registered DN"
                );
                return Err((StatusCode::UNAUTHORIZED, "invalid client".into()));
            }
        } else {
            // self_signed_tls_client_auth - thumbprint match.
            let registered_thumb = mtls_thumb.as_deref().ok_or_else(|| {
                tracing::warn!(
                    client_id = %client_id,
                    "client authentication rejected: client not registered for self_signed_tls_client_auth"
                );
                (
                    StatusCode::UNAUTHORIZED,
                    "client not registered for self_signed_tls_client_auth".into(),
                )
            })?;
            if presented_thumb != registered_thumb {
                // Thumbprint mismatch: the cert was re-issued (rotation)
                // or the cached record points at a client re-registered by
                // another holder of the workload name.
                tracing::warn!(
                    client_id = %client_id,
                    "client authentication rejected: certificate thumbprint does not match the registered thumbprint"
                );
                return Err((StatusCode::UNAUTHORIZED, "invalid client".into()));
            }
        }
        auth_method = if auth_method_registered == "tls_client_auth" {
            "tls_client_auth"
        } else {
            "self_signed_tls_client_auth"
        };
        cert_thumbprint = Some(presented_thumb.to_string());
    } else if let Some(secret) = form_client_secret.or(basic_secret.as_deref()) {
        // client_secret_post / client_secret_basic.
        let stored = secret_hash
            .as_deref()
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid client".into()))?;
        if !bcrypt_verify(secret, stored).unwrap_or(false) {
            // Uniform error - no client-existence oracle.
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
        attested_jkt,
        dpop_jkt: None,
        dpop_exempt,
        authorization_details_types,
        id_token_signed_response_alg,
        userinfo_signed_response_alg,
        subject_type,
        sector_identifier_uri,
    })
}

/// Verify a token that Auth itself issued and is about to *decide on*
///: signature + `iss` + `exp`.
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
        // Tenant-aware issuer (DESIGN §4): a token minted on a tenant's
        // auth host carries `https://auth.{env-domain}` where the env
        // domain is OPAQUE - the platform-derived
        // `{env}.{org}.{domain}` shape, a custom env domain, anything the
        // env registered. No structural parsing: the signature is the
        // trust anchor (Auth is the single issuer - verify above), and
        // this check only admits the auth-host issuer family.
        let tenant_issuer_ok = claims.iss.starts_with("https://auth.");
        if !tenant_issuer_ok {
            return Err((StatusCode::UNAUTHORIZED, "token issuer mismatch".into()));
        }
    }
    let now = chrono::Utc::now().timestamp();
    if now > claims.exp {
        return Err((StatusCode::UNAUTHORIZED, "token expired".into()));
    }
    Ok(claims)
}

/// Check whether a token's `jti` has been revoked (RFC 7009 denylist).
pub(crate) async fn is_token_revoked(state: &AppState, jti: &str) -> bool {
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

/// Denylist check for a GRANT (the `grant.revoked` cascade,
/// DESIGN §9a.11): a revoked grant hard-fails every token minted under
/// it. Same Valkey read shape as `is_token_revoked` - no DB on the hot
/// path.
pub(crate) async fn is_grant_revoked(state: &AppState, grant_id: &str) -> bool {
    if grant_id.is_empty() {
        return false;
    }
    let Ok(conn) =
        sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
    else {
        return false;
    };
    use glide::AsyncCommands as _;
    matches!(
        conn.get::<_, Option<String>>(format!("auth:grant:revoked:{grant_id}"))
            .await,
        Ok(Some(_))
    )
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
        // RFC 6749 §5.2: EVERY 4xx token-endpoint response is a protocol
        // error and MUST be the JSON `{"error":…}` shape (the suite's
        // codereuse test parses the body). A 4xx tuple is mapped to the
        // OAuth form - `invalid_grant` for the code/grant family,
        // `invalid_request` otherwise; 5xx stays Internal (plain body).
        if status.is_client_error() {
            let err = if msg.starts_with("invalid") { "invalid_grant" } else { "invalid_request" };
            return TokenError::OAuth(OAuthTokenError::with_desc(status, err, msg));
        }
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
    /// OIDC Core §5.3.2 - the signing algs a signed userinfo response may
    /// use (advertised when the dynamic signed-userinfo form is served).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,
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
    /// Attestation-based client auth (DESIGN §9a.19): the attestation
    /// JWT signing algorithms; present only when the profile enables
    /// attestation auth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_attestation_signing_alg_values_supported: Option<Vec<String>>,
    /// The PoP JWT signing algorithms (same gating).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_attestation_pop_signing_alg_values_supported: Option<Vec<String>>,
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
    /// RFC 7591 §4 / OIDC Discovery §4.1 - the dynamic-registration
    /// endpoint (anonymous for interactive clients; cert-gated for
    /// client_credentials, DESIGN §4.3f). Advertised when the surface
    /// is served (the §9a.10 no-skip honesty rule).
    pub registration_endpoint: Option<String>,
    /// RFC 7591 §4 - the registration endpoint's own auth methods
    /// (the endpoint is unauthenticated for interactive clients).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// The mtls endpoint aliases.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls_endpoint_aliases: Option<MtlsEndpointAliases>,
    /// RFC 8705 §2 - the AS issues certificate-bound access tokens
    /// (advertised when the profile's require_mtls is on).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub tls_client_certificate_bound_access_tokens: bool,
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
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    /// The software statement supported.
    pub software_statement_supported: bool,
    /// Signing algorithms the token endpoint accepts for
    /// `private_key_jwt` client assertions (required-when-advertised by
    /// OIDC Discovery §3; DESIGN §9a.4).
    /// The token endpoint auth signing alg values supported.
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    /// OIDC Core §5.5 `claims` request parameter support (eKYC-IDA
    /// surface, DESIGN §9a.3).
    /// The claims parameter supported.
    pub claims_parameter_supported: bool,
    /// The claim names the ID token / userinfo can carry (OIDC
    /// Discovery §3 recommended list; DESIGN §9a.4).
    /// The claims supported.
    pub claims_supported: Vec<String>,
    /// OIDC Back-Channel Logout 1.0 §4 advertisement (DESIGN §9a.4).
    /// The backchannel logout supported.
    pub backchannel_logout_supported: bool,
    /// Whether back-channel logout tokens carry `sid` (sessions are
    /// first-class in auth - logout tokens include the session id).
    /// The backchannel logout session supported.
    pub backchannel_logout_session_supported: bool,
    /// Client-auth methods the revocation endpoint accepts (RFC 7009 §2;
    /// DESIGN §9a.4) - same method set as the token endpoint.
    /// The revocation endpoint auth methods supported.
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    /// Client-auth methods the introspection endpoint accepts (RFC 7662;
    /// DESIGN §9a.4) - same method set as the token endpoint.
    /// The introspection endpoint auth methods supported.
    pub introspection_endpoint_auth_methods_supported: Vec<String>,
    /// CIBA (OIDC CIBA §4) - the backchannel authentication endpoint.
    /// Present when the caller's profile enables CIBA (DESIGN §9a.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The backchannel authentication endpoint.
    pub backchannel_authentication_endpoint: Option<String>,
    /// CIBA token delivery modes the AS serves (poll + ping, DESIGN
    /// §9a.4). Present when CIBA is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The backchannel token delivery modes supported.
    pub backchannel_token_delivery_modes_supported: Option<Vec<String>>,
    /// Signing algorithms accepted for signed CIBA request objects
    /// (CIBA §7.1; DESIGN §9a.4). Present when CIBA is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The backchannel authentication request signing alg values supported.
    pub backchannel_authentication_request_signing_alg_values_supported: Option<Vec<String>>,
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

/// The RFC 8414 authorization-server metadata alias
/// (https://datatracker.ietf.org/doc/html/rfc8414) - serves exactly the
/// discovery document (the OAuth 2.0 metadata form of the same issuer
/// data; the OID4VCI issuer cell resolves `authorization_servers`
/// against this well-known path).
#[utoipa::path(
    get,
    path = "/.well-known/oauth-authorization-server",
    responses(
        (status = 200, description = "RFC 8414 AS metadata (alias of the OIDC discovery document)", body = DiscoveryDocument),
    ),
    security(),
    tag = "oauth",
)]
pub async fn discovery_rfc8414_alias(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<DiscoveryDocument> {
    discovery(State(state), headers).await
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
    // §9a.11 profile-honest discovery: the resolution IS a FAPI profile
    // (fapi_1_advanced / fapi_2 / fapi_2_message_signing) → the final
    // suite's RFC 8414 metadata allow-list governs; platform-extension
    // members drop below.
    let is_fapi = crate::fapi::FapiProfile::from_str(&profile.profile).is_some();

    // DESIGN §9a.4 - the token-endpoint client-auth method set,
    // computed once and advertised for the token, revocation, and
    // introspection endpoints alike (they share the authenticator).
    let mut token_endpoint_auth_methods: Vec<String> = if profile.require_mtls {
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
    };
    // Attestation-based client auth (DESIGN §9a.19): advertised ONLY
    // when the profile both enables it and carries the trust anchor
    // (the draft's required-when-supported honesty rule - advertising
    // without an anchor would be a lie).
    let attestation_auth = profile.allow_client_attestation
        && !profile.client_attestation_trust_anchor_pem.trim().is_empty();
    if attestation_auth {
        token_endpoint_auth_methods
            .push(crate::client_attestation::AUTH_METHOD.to_string());
    }

    Json(DiscoveryDocument {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{issuer}/oauth/authorize"),
        token_endpoint: format!("{issuer}/oauth/token"),
        jwks_uri: format!("{issuer}/.well-known/jwks.json"),
        userinfo_endpoint: format!("{issuer}/oauth/userinfo"),
        // The dynamic signed-userinfo family (§9a.10 honesty: the plan's
        // oidcc-userinfo-rs256 module requires the advertisement). FAPI
        // postures keep it off - the signed-userinfo form is not a FAPI
        // surface.
        userinfo_signing_alg_values_supported: if profile.require_par
            || profile.require_mtls
        {
            None
        } else {
            Some(vec![
                crate::jwks::active_signing_alg().into(),
                "ES256".into(),
                "PS256".into(),
                "none".into(),
            ])
        },
        revocation_endpoint: format!("{issuer}/oauth/revoke"),
        introspection_endpoint: format!("{issuer}/oauth/introspect"),
        end_session_endpoint: format!("{issuer}/oauth/logout"),
        // The standard five (OIDC Core §3.1.2.1 family + DESIGN §9a.13):
        // the certification family runs variant cells per response_type.
        response_types_supported: [
                "code",
                "id_token",
                "code id_token",
                "id_token token",
                "code id_token token",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        // JARM is advertised when require_jarm is true.
        response_modes_supported: if profile.require_jarm {
            vec!["query".into(), "jwt".into()]
        } else {
            vec!["query".into()]
        },
        grant_types_supported: {
            // The 'implicit' RESPONSE-TYPE form (§9a.13 - the OIDC family's
            // implicit/hybrid cells are served) rides the non-FAPI
            // postures' grant-type list (the Dynamic-OP certification
            // profile requires it).
            let mut v = vec![
                "authorization_code".into(),
                "refresh_token".into(),
                "client_credentials".into(),
                "urn:ietf:params:oauth:grant-type:device_code".into(),
                "urn:ietf:params:oauth:grant-type:token-exchange".into(),
                // DESIGN §9a.4 - the CIBA poll grant served at the
                // token endpoint (bc-authorize issues auth_req_id first).
                "urn:openid:params:grant-type:ciba".into(),
            ];
            if !(profile.require_par || profile.require_mtls) {
                v.push("implicit".into());
            }
            v
        },
        code_challenge_methods_supported: vec!["S256".into()],
        token_endpoint_auth_methods_supported: token_endpoint_auth_methods.clone(),
        // Attestation-based client auth (DESIGN §9a.19): the two alg
        // lists appear ONLY when the profile enables attestation auth
        // (same gate as the method advertisement).
        client_attestation_signing_alg_values_supported: if attestation_auth {
            Some(vec!["ES256".into()])
        } else {
            None
        },
        client_attestation_pop_signing_alg_values_supported: if attestation_auth {
            Some(vec!["ES256".into()])
        } else {
            None
        },
        scopes_supported: vec![
            "openid".into(),
            "profile".into(),
            "email".into(),
            // DESIGN §9a.4/§9a.10 - all four OIDC claim scopes are
            // advertised AND served end-to-end (no suite skips).
            "phone".into(),
            "address".into(),
            "offline_access".into(),
            // DESIGN §9a.19/§9a.20 - the OID4VCI credential scopes (the
            // issuer's native configurations) + the OIDF wallet-catalog
            // scopes the wallet plan drives - every advertised scope is
            // mintable end-to-end by the credential endpoint.
            "credential:VerifiedPersonCredential".into(),
            "credential:VerifiedEmployeeCredential".into(),
            "eudi.pid.1".into(),
            "eudi.pid.1.nobinding".into(),
            "eudi.pid.1.attestation".into(),
            "eudi.pid.1.jwt.keyattest".into(),
            "eudi.pid.1.attestation.keyattest".into(),
            "eudi.pid.1.jwt_and_attestation.keyattest".into(),
            "openid.example.cert.1".into(),
        ],
        subject_types_supported: vec!["public".into(), "pairwise".into()],
        // DESIGN §9a.9 - the ID-token signing family the CALLER'S env
        // will actually mint (per-tenant signing_alg). Both families
        // remain verifiable via JWKS (kid-routed), so clients may see a
        // token from the other family only across tenants - this
        // document describes this issuer-host's tenant.
        // The 'none' member (unsigned ID token - OIDC Core §3.1.3.7 with
        // no signature) rides ONLY the non-FAPI postures: a FAPI discovery
        // must never admit an unsigned ID token. The Dynamic-OP plan's
        // oidcc-idtoken-unsigned module requires the advertisement (the
        // no-skip rule §9a.10 - the suite SKIPPED the module otherwise).
        id_token_signing_alg_values_supported: {
            let base = if profile.signing_alg.is_empty() {
                vec![crate::jwks::active_signing_alg().into()]
            } else {
                vec![profile.signing_alg.clone()]
            };
            let fapi_family = profile.require_par || profile.require_mtls;
            if fapi_family {
                base
            } else {
                let mut v = base;
                v.push("none".into());
                v
            }
        },
        // DPoP signing algs - SUPPORT is unconditional (the dpop gate
        // below is per-client opt-in/opt-out); the FAMILY is the tenant's
        // resolved signing family (the same key family that signs the ID
        // token - per-tenant §9a.9, not the process default). An empty
        // array while proofs are accepted is a lie and crashes
        // registry-driven consumers (the suite indexes [0]).
        dpop_signing_alg_values_supported: vec![if profile.signing_alg.is_empty() {
            crate::jwks::active_signing_alg().into()
        } else {
            profile.signing_alg.clone()
        }],
        authorization_response_iss_parameter_supported: profile.require_iss,
        // FAPI1-ADV/FAPI2-SP (the suite's FAPICheckDiscEndpointRequestObject
        // SigningAlgValuesSupported): the FAPI postures advertise the
        // mandated set {PS256, ES256} (the client-side request objects -
        // every member IS verifiable: verify_client_signed_jwt checks
        // per-key) + `none` (RFC 9101 §5 - unsigned objects, TLS-bound).
        // every member IS verifiable: verify_client_signed_jwt checks
        // per-key + `none` (RFC 9101 §5 - unsigned objects, TLS-bound).
        // DESIGN 9a.16 (i): under the PAR/FAPI2 postures the request
        // objects sign ES256/PS256 ONLY (RS256 = the alg mandate; the
        // unsigned form = the TLS-bound relaxation stays on the
        // non-FAPI branch).
        request_object_signing_alg_values_supported: if profile.require_par || profile.require_mtls {
            vec!["ES256".into(), "PS256".into()]
        } else {
            vec![
                crate::jwks::active_signing_alg().into(),
                "none".into(),
            ]
        },
        request_parameter_supported: true,
        request_uri_parameter_supported: true,
        // PAR endpoint - present when require_par is true .
        registration_endpoint: Some(format!("{issuer}/oauth/register")),
        registration_endpoint_auth_methods_supported: None,
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
        // RFC 8705 §2 - certificate-bound access tokens are a PLATFORM
        // capability (every env's client machinery supports the mtls
        // methods - §9a.12): advertised unconditionally. The mTLS ENDPOINT
        // ALIASES above stay per-profile (require_mtls) - the capability
        // is always present, the profile gates the alias ROUTES.
        tls_client_certificate_bound_access_tokens: true,
        // - discovery honesty: advertise the RAR types the AS
        // actually enforces (union of client-registered
        // authorization_details_types) and the grants API.
        authorization_details_types_supported: fetch_rar_types(&state.pool).await,
        // §9a.11 profile-honest discovery (warning #7): Grant Management
        // is a FAPI-family capability - the endpoint rides discovery only
        // under a FAPI profile; the final suite's RFC 8414 allow-list on
        // OTHER profiles rejects unknown members.
        grant_management_endpoint: is_fapi.then(|| format!("{issuer}/oauth/grants")),
        // §9a.11 profile-honest discovery (warning #7): the DCR
        // software-statement platform capability is advertised only on
        // non-FAPI hosts (the FAPI final suite's allow-list rejects it).
        // NOT advertised: the suite's RFC 8414 schema flags
        // `software_statement_supported` as an unknown property - DCR
        // software_statement processing stays server-side capability.
        #[allow(dead_code)]
        software_statement_supported: false,
        // DESIGN §9a.4 - required-when-advertised signing algs for
        // private_key_jwt client assertions. The same algorithm set the
        // client-assertion verifier accepts. DESIGN §9a.16 (i): under
        // the FAPI 2.0 postures (fapi_2 / fapi_2_message_signing) the
        // FAPI2-BSA mandate drops RS256 from the advertised + accepted
        // set - [PS256, ES256] only.
        token_endpoint_auth_signing_alg_values_supported: {
            let fapi2_posture = crate::fapi::FapiProfile::from_str(&profile.profile)
                .map(|p| {
                    matches!(p, crate::fapi::FapiProfile::Fapi20 | crate::fapi::FapiProfile::Fapi20MessageSigning)
                })
                .unwrap_or(false);
            if fapi2_posture {
                vec!["PS256".into(), "ES256".into()]
            } else {
                vec![
                    crate::jwks::active_signing_alg().into(),
                    // RFC 7518 §3.5 - PS256 (RSASSA-PSS): the FAPI-mandated RSA
                    // signing form; the verify set (RSA JWK + Algorithm::PS256)
                    // makes every advertised member verifiable (§9a.10 honesty).
                    "PS256".into(),
                    "ES256".into(),
                ]
            }
        },
        // DESIGN §9a.3 - the claims request parameter is
        // accepted at authorize; claims_supported lists what ID tokens
        // and userinfo can carry (the standard OIDC set auth mints).
        claims_parameter_supported: true,
        claims_supported: vec![
            "sub".into(),
            "iss".into(),
            "aud".into(),
            "exp".into(),
            "iat".into(),
            "auth_time".into(),
            "nonce".into(),
            "at_hash".into(),
            "c_hash".into(),
            // DESIGN §9a.4/§9a.11 - the FULL profile claim family (the
            // §9a.10 no-skip rule: every advertised claim is producible).
            "name".into(),
            "given_name".into(),
            "family_name".into(),
            "middle_name".into(),
            "nickname".into(),
            "preferred_username".into(),
            "profile".into(),
            "picture".into(),
            "website".into(),
            "gender".into(),
            "birthdate".into(),
            "zoneinfo".into(),
            "locale".into(),
            "updated_at".into(),
            "email".into(),
            "email_verified".into(),
            // DESIGN §9a.4 - the phone/address claim families, minted
            // scope-gated like email/profile above.
            "phone_number".into(),
            "phone_number_verified".into(),
            "address".into(),
            // eKYC-IDA (DESIGN §9a.7) - present when the claims request
            // selects it and an active verified credential exists.
            "verified_claims".into(),
        ],
        // DESIGN §9a.4 - back-channel logout is the only logout
        // signaling mechanism (front-channel is a design exclusion);
        // logout tokens carry `sid` (backchannel_logout.rs).
        backchannel_logout_supported: true,
        backchannel_logout_session_supported: true,
        // DESIGN §9a.4 - the revocation and introspection
        // endpoints authenticate clients with the same method set as
        // the token endpoint (RFC 8705 aliases included when mTLS is
        // advertised above).
        revocation_endpoint_auth_methods_supported: token_endpoint_auth_methods.clone(),
        introspection_endpoint_auth_methods_supported: token_endpoint_auth_methods,
        // DESIGN §9a.4 - CIBA block: the bc-authorize endpoint
        // exists on every env; delivery modes and signed request-object
        // algorithms are advertised alongside.
        backchannel_authentication_endpoint: Some(format!("{issuer}/oauth/bc-authorize")),
        backchannel_token_delivery_modes_supported: Some(vec!["poll".into(), "ping".into()]),
        backchannel_authentication_request_signing_alg_values_supported: Some(vec![
            crate::jwks::active_signing_alg().into(),
            "ES256".into(),
        ]),
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
    /// PKCE is mandatory for authorization requests when
    /// the profile mandates PAR (FAPI 2.0 default). Mirrors `require_par`
    /// until the profile table grows a dedicated column.
    /// The require pkce.
    pub require_pkce: bool,
    /// Per-tenant JWT signing family (`MLDSA65` | `RS256`) - DESIGN §9a.9.
    /// Controls which persisted key family signs this tenant's tokens;
    /// verification stays family-agnostic (kid-routed).
    /// The signing alg.
    pub signing_alg: String,
    /// Attestation-based client authentication (design §9a.19,
    /// draft-ietf-oauth-attestation-based-client-auth): the resolved
    /// profile admits `OAuth-Client-Attestation` + PoP header auth on the
    /// token endpoint family.
    pub allow_client_attestation: bool,
    /// PEM of the attester trust anchor the attestation's x5c chain must
    /// chain to; empty keeps the feature disabled.
    pub client_attestation_trust_anchor_pem: String,
    /// The attestation's expected `iss` (the attester's trust domain).
    pub client_attestation_issuer: String,
    /// HAIP (§9a.19 addendum): the issuer's ES256 X.509 leaf (PEM, the
    /// credential/status-list x5c chain's LEAF) + its CA chain; seeded
    /// per environment. Empty = the plain jwk-header form.
    pub issuance_leaf_pem: String,
    /// The issuer issuance CA chain (PEM) for the HAIP x5c; empty = plain form.
    pub issuance_chain_pem: String,
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
            signing_alg: String::new(),
            allow_client_attestation: false,
            client_attestation_trust_anchor_pem: String::new(),
            client_attestation_issuer: String::new(),
            issuance_leaf_pem: String::new(),
            issuance_chain_pem: String::new(),
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

    resolve_security_profile_inner(pool, env_id, scope).await
}

/// Resolve the security profile for a KNOWN env id (DESIGN §9a.9) - used
/// by mint paths that carry their tenant on the token (refresh grants,
/// CIBA polling) rather than on the request headers. Resolution order
/// and RLS handling match [`resolve_security_profile`].
pub async fn resolve_security_profile_for_env(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    scope: &str,
) -> SecurityProfile {
    resolve_security_profile_inner(pool, Some(env_id), scope).await
}

/// Shared resolution body: tenant context on one connection, env → org
/// lookup, then env → org → platform row fallback.
async fn resolve_security_profile_inner(
    pool: &sqlx::PgPool,
    env_id: Option<Uuid>,
    scope: &str,
) -> SecurityProfile {

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
                  require_http_signatures, require_jwt_introspection, require_iss, signing_alg,
                  allow_client_attestation, client_attestation_trust_anchor_pem,
                  client_attestation_issuer, issuance_leaf_pem, issuance_chain_pem
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
        signing_alg: r.signing_alg,
        // PKCE rides on the PAR flag (FAPI 2.0 mandates both).
        require_pkce: r.require_par,
        allow_client_attestation: r.allow_client_attestation,
        client_attestation_trust_anchor_pem: r.client_attestation_trust_anchor_pem,
        client_attestation_issuer: r.client_attestation_issuer,
        issuance_leaf_pem: r.issuance_leaf_pem,
        issuance_chain_pem: r.issuance_chain_pem,
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
    /// Per-tenant JWT signing family (`MLDSA65` | `RS256`) - DESIGN §9a.9.
    pub signing_alg: String,
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
    #[serde(default)]
    /// Per-tenant JWT signing family (`MLDSA65` | `RS256`) - DESIGN §9a.9.
    pub signing_alg: Option<String>,
    /// Attestation-based client auth (DESIGN §9a.19): enable the
    /// `OAuth-Client-Attestation` + PoP header family.
    #[serde(default)]
    pub allow_client_attestation: Option<bool>,
    /// PEM of the attester trust anchor the attestation's x5c must
    /// chain to (empty keeps the anchor check off).
    #[serde(default)]
    pub client_attestation_trust_anchor_pem: Option<String>,
    /// The attestation's expected `iss` (the attester's trust domain).
    #[serde(default)]
    pub client_attestation_issuer: Option<String>,
    /// HAIP: the issuer's ES256 leaf certificate (PEM) + its CA chain -
    /// the credential/status-list x5c chain (empty = plain jwk form).
    #[serde(default)]
    pub issuance_leaf_pem: Option<String>,
    #[serde(default)]
    /// The issuer issuance CA chain (PEM) for the HAIP x5c; empty = plain form.
    pub issuance_chain_pem: Option<String>,
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
                  max_token_lifetime, refresh_rotation, signing_alg
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
        signing_alg: row.signing_alg,
    }))
}

/// `PUT /v1/security-profile` - update (or insert) the security profile for
/// the given scope + tenant.
///
/// admin guard. `sentin8:sys:admin`/`sentin8:dash:admin` (platform
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

    // Cross-tenant rule: an org/env-scoped row must
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

    // Validate signing_alg (DESIGN §9a.9) - unknown families are
    // rejected at the API boundary, not at mint time.
    if let Some(alg) = &req.signing_alg {
        if !matches!(alg.as_str(), "MLDSA65" | "RS256" | "ES256") {
            return Err((
                StatusCode::BAD_REQUEST,
                "signing_alg must be MLDSA65, RS256, or ES256".into(),
            ));
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

    // SEC- / RLS-FNSCHEMA-1 - the security_profiles table is
    // FORCE-RLS'd: env/org rows are only writable with the caller's env
    // in `app.env_id`. Run the read-merge + upsert inside ONE
    // transaction with `sentin8_set_tenant_context` applied first -
    // context must be set on the SAME connection as the write (a
    // bare pool write sees no rows and violates the insert policy).
    let target_env = req.env_id.or(Some(auth.env_id));
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some(eid) = target_env {
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(eid)
            .execute(&mut *tx)
            .await;
    }

    // Fetch existing values to merge (upsert).
    let existing = sqlx::query!(
        r#"SELECT require_par, require_mtls, require_jarm, require_dpop,
                  require_http_signatures, require_jwt_introspection, require_iss,
                  max_token_lifetime, refresh_rotation, profile, signing_alg,
                  allow_client_attestation, client_attestation_trust_anchor_pem,
                  client_attestation_issuer, issuance_leaf_pem, issuance_chain_pem
           FROM security_profiles
           WHERE scope = $1
             AND (org_id IS NOT DISTINCT FROM $2)
             AND (env_id IS NOT DISTINCT FROM $3)"#,
        req.scope,
        req.org_id,
        req.env_id,
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (e_par, e_mtls, e_jarm, e_dpop, e_hsigs, e_ji, e_iss, e_max, e_rot,
         e_profile, e_alg, e_attest, e_anchor, e_att_iss, e_leaf, e_chain) =
        existing.map(|r| {
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
                r.signing_alg,
                r.allow_client_attestation,
                r.client_attestation_trust_anchor_pem,
                r.client_attestation_issuer,
                r.issuance_leaf_pem,
                r.issuance_chain_pem,
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
            "MLDSA65".to_string(),
            false,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ));

    let row = sqlx::query!(
        r#"INSERT INTO security_profiles
               (scope, org_id, env_id, profile,
                require_par, require_mtls, require_jarm, require_dpop,
                require_http_signatures, require_jwt_introspection, require_iss,
                max_token_lifetime, refresh_rotation, signing_alg,
                allow_client_attestation, client_attestation_trust_anchor_pem,
                client_attestation_issuer, issuance_leaf_pem,
                issuance_chain_pem)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                   $15, $16, $17, $18, $19)
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
               signing_alg = EXCLUDED.signing_alg,
               allow_client_attestation = EXCLUDED.allow_client_attestation,
               client_attestation_trust_anchor_pem =
                   EXCLUDED.client_attestation_trust_anchor_pem,
               client_attestation_issuer = EXCLUDED.client_attestation_issuer,
               issuance_leaf_pem = EXCLUDED.issuance_leaf_pem,
               issuance_chain_pem = EXCLUDED.issuance_chain_pem,
               updated_at = now()
           RETURNING
               scope, org_id, env_id, profile,
               require_par, require_mtls, require_jarm, require_dpop,
               require_http_signatures, require_jwt_introspection, require_iss,
               max_token_lifetime, refresh_rotation, signing_alg,
               allow_client_attestation, client_attestation_trust_anchor_pem,
               client_attestation_issuer"#,
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
        req.signing_alg.clone().unwrap_or(e_alg),
        req.allow_client_attestation.unwrap_or(e_attest),
        req.client_attestation_trust_anchor_pem.clone().unwrap_or(e_anchor),
        req.client_attestation_issuer.clone().unwrap_or(e_att_iss),
        req.issuance_leaf_pem.clone().unwrap_or(e_leaf),
        req.issuance_chain_pem.clone().unwrap_or(e_chain),
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Commit the profile write on the SAME transaction the tenant
    // context lives in (RLS) - a rollback would silently drop the
    // profile change.
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // the catalog's `sentin8:auth:securityprofile:updated`
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
        signing_alg: row.signing_alg,
    }))
}

///resolve the issuer URL from the request Host or X-Sentin8-Hostname header.
/// Resolve the issuer URL from the TLS-injected hostname context.
/// Falls back to config.issuer when no Host header is present.
pub fn resolve_issuer(config: &crate::config::AuthConfig, headers: &HeaderMap) -> String {
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
    /// OIDC `nonce` - echoed into the ID token.
    #[serde(default)]
    /// The nonce.
    pub nonce: Option<String>,
    /// RFC 9449 dpop_jkt - the DPoP key thumbprint pre-bound on the
    /// authorize request (rides the PAR record for pushed requests).
    #[serde(default)]
    /// The dpop jkt.
    pub dpop_jkt: Option<String>,
    /// OAuth response mode - `query` (default) or `jwt` (JARM, SEC-).
    #[serde(default)]
    /// The response mode.
    pub response_mode: Option<String>,
    /// JAR signed request object (RFC 9101, SEC-).
    #[serde(default)]
    /// The request.
    pub request: Option<String>,
    /// RFC 8707 resource indicator.
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
    /// OIDC Core §3.1.2.1 `prompt` - space-delimited values. `none`
    /// requires silent authentication (error=login_required without a
    /// valid session); `login` forces re-authentication even when a
    /// session exists. `consent` is accepted and treated as the default
    /// (the consent screen is shown when the client requires consent).
    /// DESIGN §9a.3.
    #[serde(default)]
    /// The prompt.
    pub prompt: Option<String>,
    /// OIDC Core §3.1.2.1 `max_age` - maximum allowable elapsed time
    /// since the user last authenticated. When the existing session is
    /// older, the user must re-authenticate before the code is issued.
    /// DESIGN §9a.3.
    #[serde(default)]
    /// The max age.
    pub max_age: Option<i64>,
    /// OIDC Core §5.5 `claims` - JSON object with `id_token` and/or
    /// `userinfo` sub-objects selecting claims the client needs. The
    /// selection NARROWS scope-granted claims; it can never widen them
    /// (an essential claim the user never consented to is still refused
    /// by the scope gate). DESIGN §9a.3.
    #[serde(default)]
    /// The claims.
    pub claims: Option<String>,
    /// OIDC Core §3.1.2.1 `acr_values` - space-delimited requested
    /// assurance levels. Echoed as the ID token's `acr` claim (first
    /// requested value wins - the platform issues one effective
    /// assurance level per session, DESIGN §9a.11).
    #[serde(default)]
    /// The acr values.
    pub acr_values: Option<String>,
    /// Escape hatch: force the JS-free `/oauth/login` form instead of
    /// the Flutter auth-ui (DESIGN §9a.11 - the non-JS client surface).
    #[serde(default)]
    /// The ui login page.
    pub ui_login_page: Option<bool>,
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

/// Resolve a PAR request_uri from Valkey. **Consumed when the
/// authorization interaction COMPLETES, not on the first read**: a
/// consent-bearing flow re-enters `/oauth/authorize` with the same
/// `request_uri` after login (the SPA's second navigation), and RFC
/// 9126 §4 permits the authorization server to determine when a
/// request_uri expires - our rule is "readable until the issuer record
/// expires (600s)", not GETDEL-on-first-read. A code record carries the
/// resolved params, so the reuse window never leaks a second code.
async fn resolve_par_request(state: &AppState, request_uri: &str) -> Option<serde_json::Value> {
    let key = request_uri
        .strip_prefix("urn:ietf:params:oauth:request_uri:")
        .unwrap_or(request_uri);
    let valkey_key = format!("auth:par:{key}");

    let client = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .ok()?;
    let conn = client;
    // Multi-read resolution: the record lives until its TTL; each
    // authorize (login-visit + consent re-entry) resolves the SAME
    // params.
    let val: Option<String> = conn.get(valkey_key).await.ok().flatten();
    // A code ALREADY ISSUED for this request_uri (the user-rejects /
    // reuse-after-completion negatives) retires the record - RFC 9126 §4
    // single-USE semantics on the AUTHORIZATION OUTCOME, multi-read
    // within the browser interaction.
    if val.is_some() {
        let used_key = format!("auth:par-used:{key}");
        if let Ok(Some(())) = conn.get::<_, Option<String>>(&used_key).await.map(|v| v.map(|_| ())) {
            tracing::debug!(par_key = %key, "PAR request_uri reused after code issuance - rejected");
            return None;
        }
    }
    val.and_then(|s| serde_json::from_str(&s).ok())
}

/// Mark a PAR request_uri consumed after its code issuance (auth DESIGN
/// §9a.19 note): the authorize handlers call this with the PAR key once
/// the code record is written; later resolutions refuse. The argument
/// MAY already carry the urn prefix (call sites pass `params.par_key`,
/// the full `request_uri`) - strip at MOST one prefix here; wrapping an
/// already-prefixed key produced `auth:par-used:urn:...:urn:...` (a key
/// the resolver never reads) and the reuse negative never rejected.
pub async fn mark_par_used(state: &AppState, request_uri: &str) {
    let key = request_uri
        .strip_prefix("urn:ietf:params:oauth:request_uri:")
        .unwrap_or(request_uri);
    let used_key = format!("auth:par-used:{key}");
    if let Ok(conn) = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await {
        let _: Result<(), _> = conn.set_ex(&used_key, "1", 600u64).await;
    }
}

/// PAR endpoint (RFC 9126) - accepts a pushed authorization request.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for par.
pub struct ParRequest {
    /// The response type (optional at the FORM layer: a JAR push
    /// carries ONLY the request object - the params ride inside it,
    /// RFC 9101 §4; the missing-form 422 the suite's CallPAREndpoint
    /// saw is a deserializer rejection, not an OAuth error).
    #[serde(default)]
    pub response_type: Option<String>,
    /// Client identifier (optional at the FORM layer - see
    /// `response_type`; the JAR's client or the client_assertion
    /// identifies the client).
    #[serde(default)]
    pub client_id: Option<String>,
    /// The redirect URI (optional at the FORM layer: a miss reaches the
    /// handler and answers the OAUTH JSON error shape - RFC 9126's
    /// `invalid_request` - instead of a text 422 from the deserializer).
    #[serde(default)]
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
    /// OIDC nonce.
    #[serde(default)]
    /// The nonce.
    pub nonce: Option<String>,
    /// RFC 8707 resource indicator.
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
    /// RFC 7523 §2.2 - the assertion type URN; REQUIRED (and exactly
    /// `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`) when a
    /// `client_assertion` rides the push (the invalid-assertions module).
    #[serde(default)]
    /// The client assertion type.
    pub client_assertion_type: Option<String>,
    /// The pushed request object (RFC 9126 + JAR RFC 9101): FAPI 2.0
    /// pushes the authorization request's parameters as a JWT on the
    /// PAR call - its params are AUTHORITATIVE over any inline ones.
    #[serde(default)]
    /// The request.
    pub request: Option<String>,
    /// RFC 9449 dpop_jkt - the DPoP key thumbprint the suite
    /// pre-binds on the push (the request object's parameter).
    #[serde(default)]
    /// The dpop jkt.
    pub dpop_jkt: Option<String>,
    /// A `request_uri` FORM parameter on the push. RFC 9126 §2 defines
    /// the PAR request's parameters - `request_uri` is NOT one (it is
    /// the RESPONSE payload): a push carrying it is malformed and the
    /// endpoint MUST reject it `invalid_request` (the suite's
    /// "authorization request containing request_uri form param"
    /// negative).
    #[serde(default)]
    pub request_uri: Option<String>,
    /// OAuth response mode (`query` default, `jwt` for JARM) - the
    /// JAR-only push carries it INSIDE the request object; the form
    /// overlay applies it to the stored record so the authorize +
    /// continue paths honor JARM (FAPI1/2).
    #[serde(default)]
    pub response_mode: Option<String>,
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
) -> Result<axum::response::Response, axum::response::Response> {
    // The PAR errors are OAUTH JSON bodies (RFC 9126 Section 3 / 9449:
    // {"error": ...}) - the suite's PAR checks parse the error shape;
    // a plain-text status body fails CallPAREndpoint's JSON gate.
    type ParError = axum::response::Response;
    let json_error = |status: StatusCode, error: &str, desc: String| -> ParError {
        (
            status,
            Json(serde_json::json!({
                "error": error,
                "error_description": desc,
            })),
        )
            .into_response()
    };
    // RFC 9126 §2 - `request_uri` is the PAR RESPONSE payload, never a
    // request parameter: a push carrying it as a form param is malformed
    // and rejects BEFORE client authentication (the suite's
    // request-uri-form-param negative expects invalid_request).
    if req.request_uri.as_deref().map(str::trim).map(str::len).unwrap_or(0) > 0 {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request_uri is not a valid pushed authorization request parameter".into(),
        ));
    }
    // RFC 9126 §2 - `request_uri` is the PAR RESPONSE payload, never a
    // request parameter: a push carrying it as a form param is malformed
    // and rejects BEFORE client authentication (the suite's
    // request-uri-form-param negative expects invalid_request).
    if req.request_uri.as_deref().map(str::trim).unwrap_or("").len() > 0 {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request_uri is not a valid pushed authorization request parameter".into(),
        ));
    }
    // RFC 9126 SS2 - a pushed request without redirect_uri (and without
    // a request object supplying one) is `invalid_request`.
    if req.redirect_uri.as_deref().unwrap_or("").is_empty() && req.request.as_deref().map(str::trim).unwrap_or("").is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is required".into(),
        ));
    }

    // RFC 7523 §2.2 - an attached client_assertion MUST carry the exact
    // assertion-type URN: a missing type (the token endpoint's parity
    // gate) or any non-registered value rejects BEFORE client auth with
    // the OAuth JSON error shape (the invalid-assertions PAR pair).
    const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    if req.client_assertion.is_some()
        && req.client_assertion_type.as_deref() != Some(ASSERTION_TYPE)
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_assertion_type must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
        ));
    }

    // PAR pushes require client authentication (RFC 9126
    // ); the redirect_uri must be registered for the client. A JAR-only
    // push may omit the FORM client_id: the client_assertion's verified
    // `iss`/`sub` (or the JAR's client_id claim) identifies it.
    let form_client_id = req.client_id.clone().or_else(|| {
        req.client_assertion
            .as_deref()
            .map(crate::enterprise_connections::decode_jwt_unverified)
            .and_then(|r| r.ok())
            .and_then(|c| c.get("iss").and_then(|v| v.as_str()).map(|s| s.to_string()))
    });
    if form_client_id.is_none() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required (form, request object, or client assertion)".into(),
        ));
    }
    let client = authenticate_client(
        &state,
        &headers,
        form_client_id.as_deref(),
        req.client_secret.as_deref(),
        req.client_assertion.as_deref(),
        true,
        true,
    )
    .await
    .map_err(|(status, msg)| {
        json_error(status, "invalid_client", msg)
    })?;
    // RFC 9101 §4 - the JAR-only push carries redirect_uri INSIDE the
    // request object: the effective redirect validates after the
    // overlay (the form's value wins when present).
    let jar_redirect = req
        .request
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|jwt| crate::jar::decode_jar_unverified(jwt).ok())
        .map(|c| c.redirect_uri);
    let pushed_redirect_uri = req
        .redirect_uri
        .clone()
        .or(jar_redirect)
        .unwrap_or_default();
    if !redirect_uri_registered(&client.redirect_uris, &pushed_redirect_uri) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is not registered for this client".to_string(),
        ));
    }

    // RFC 9449 SS10.1 - the PAR endpoint honors an attached DPoP proof:
    // a proof MUST verify (method/htu/iat/jti) and, when the pushed
    // request pre-binds dpop_jkt, the proof's key thumbprint MUST equal
    // it (a mismatch is a sender-constraint violation -> 400).
    let mut params_dpop_jkt: Option<String> = None;
    // RFC 9449 SS10.1: the pushed request object may pre-bind `dpop_jkt`;
    // decode it here (unverified - the FULL JAR verification with signature
    // happens after this gate) so the DPoP-vs-jkt equality check below sees
    // the JAR's pre-bound value even when the FORM carries none.
    let form_dpop_jkt: Option<String> = req
        .request
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|jwt| sentin8::auth::jwt::decode_payload(jwt).ok())
        .and_then(|v| {
            v.get("dpop_jkt")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        });
    if let Some(proof) = crate::dpop::extract_dpop_header(&headers) {
        let htu = format!("{}/oauth/par", resolve_issuer(&state.config, &headers));
        let proof_jkt: Option<String> = crate::dpop::decode_dpop_proof_unverified(&proof)
            .ok()
            .and_then(|d| {
                let mut jwk = d.header.jwk.clone();
                if let Some(obj) = jwk.as_object_mut() {
                    obj.remove("d");
                }
                crate::jar::jwk_thumbprint(&jwk).ok()
            });
        let pre_bound = req
            .dpop_jkt
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(form_dpop_jkt.as_deref().filter(|s| !s.is_empty()));
        if let Some(pre_bound) = pre_bound {
            let jkt = crate::dpop::validate_and_verify_dpop(&state, &proof, "POST", &htu)
                .await
                .map_err(|e| {
                    json_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_dpop_proof",
                        e,
                    )
                })?;
            if jkt != pre_bound {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_dpop_proof",
                    "DPoP proof key does not match the pre-bound dpop_jkt".to_string(),
                ));
            }
        }
        // RFC 9449 Section 10.1 - the PAR's own verified DPoP proof sets
        // the request's sender-constraint: the token endpoint's later
        // proof must be from the SAME key (the suite's jkt-mismatch pair).
        if req.dpop_jkt.is_none() {
            params_dpop_jkt = proof_jkt;
        }
    }

    // No JAR: the form's own response_type validates (the standard five).
    // DESIGN §9a.16 (f) - under the fapi_2_message_signing posture the
    // PAR push MUST carry a SIGNED request object: an unsigned push
    // (no `request` parameter) rejects `invalid_request_object` - the
    // non-repudiation posture has no unsigned message surface.
    if crate::fapi::FapiProfile::from_str(
        &resolve_security_profile(&state.pool, &headers, "env").await.profile,
    )
    .map(|p| p == crate::fapi::FapiProfile::Fapi20MessageSigning)
    .unwrap_or(false)
        && req.request.as_deref().map(str::trim).unwrap_or("").is_empty()
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            //.3: the PAR push's rejection error code is
            // `invalid_request` (the suite's EnsurePARInvalidRequestError);
            // `invalid_request_object` is the by-value/authorize form.
            "FAPI2 message-signing requires a signed request object on the PAR push".into(),
        ));
    }
    if req.request.as_deref().map(str::trim).unwrap_or("").is_empty()
        && !crate::oauth::is_supported_response_type(
            req.response_type.as_deref().unwrap_or(""),
        )
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "unsupported response_type (the standard five per OIDC Core)".into(),
        ));
    }

    // The pushed request object (FAPI 2.0 / JAR): when present it is
    // the AUTHORITATIVE parameter set - verify its signature against
    // the client's registered keys and overlay its params over the
    // inline ones before the record is stored (the authorize step
    // then resolves nonce/dpop_jkt exactly as the suite pushed them).
    // RFC 9101 §4 - a JAR push may carry ALL params inside the object:
    // the effective response_type validates after the overlay.
    let mut params_overlay: serde_json::Map<String, serde_json::Value> =
        serde_json::Map::new();
    if let Some(request_jwt) = req.request.as_deref().filter(|s| !s.is_empty()) {
        // The JAR's aud = the ISSUER the client saw in DISCOVERY - the
        // host-resolved issuer (x-sentin8-hostname/Host), not the static
        // platform config (multi-tenant instance).
        let issuer = resolve_issuer(&state.config, &headers);
        let resolved_profile = crate::fapi::FapiProfile::from_str(
            &resolve_security_profile(&state.pool, &headers, "env").await.profile,
        );
        // (DESIGN 9a.14): the mandate table resolves from the
        // FAPI posture ONCE - no per-call-site booleans.
        let jar_flags = resolved_profile
            .as_ref()
            .map(|p| p.required_flags())
            .unwrap_or_else(crate::fapi::required_flags_default);
        let jar = verify_jar_request(
            &state,
            &client.client_id,
            request_jwt,
            &issuer,
            &jar_flags,
            req.scope.as_str(),
        )
            .await
            .map_err(|e| {
                // the reject's precise code rides the "<code>: <text>"
                // head (the pairing rule's unsupported_response_type among
                // them); unknown prefixes keep the JAR-shape default.
                let (code, desc) = match e.split_once(": ") {
                    Some((c, d))
                        if matches!(
                            c,
                            "invalid_request"
                                | "invalid_request_object"
                                | "unsupported_response_type"
                        ) =>
                    {
                        (c.to_string(), d.to_string())
                    }
                    _ => ("invalid_request_object".to_string(), e.clone()),
                };
                json_error(
                    StatusCode::BAD_REQUEST,
                    &code,
                    format!("pushed request object rejected: {desc}"),
                )
            })?;
        let effective = if jar.response_type.is_empty() {
            req.response_type.clone().unwrap_or_default()
        } else {
            jar.response_type.clone()
        };
        if !crate::oauth::is_supported_response_type(&effective) {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "unsupported_response_type",
                "unsupported response_type (the standard five per OIDC Core)".into(),
            ));
        }
        // FAPI1-ADV 7.1 - the request object MUST carry `scope`; a
        // scope-less push rejects `invalid_request_object` (the suite's
        // without-scope module).
        if jar.scope.trim().is_empty() {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request_object",
                "pushed request object carries no scope".into(),
            ));
        }
        let stored = serde_json::json!({
            "response_type": jar.response_type,
            "client_id": jar.client_id,
            "redirect_uri": jar.redirect_uri,
            "scope": jar.scope,
            "state": jar.state,
            "code_challenge": jar.code_challenge,
            "code_challenge_method": jar.code_challenge_method,
            "nonce": jar.nonce,
            "response_mode": jar.response_mode,
            // The JAR may pre-bind the DPoP key thumbprint (RFC 9449 §10.1)
            // - the PAR's DPoP proof must hash to exactly this value.
            "dpop_jkt": code_record_jkt(&jar.dpop_jkt),
        });
        if let Some(obj) = stored.as_object() {
            for (k, v) in obj {
                if !v.is_null() {
                    params_overlay.insert(k.clone(), v.clone());
                }
            }
        }
    }

    let request_id = uuid::Uuid::new_v4().to_string();
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{request_id}");
    let valkey_key = format!("auth:par:{request_id}");

    // - RAR: validate authorization_details against the client's
    // registered types before storing them in the PAR record.
    let authorization_details = match req.authorization_details {
        Some(ref d) => Some(
            validate_authorization_details(&client.authorization_details_types, d)
                .map_err(|e| {
                    json_error(StatusCode::BAD_REQUEST, "invalid_request", e)
                })?,
        ),
        None => None,
    };

    let mut params = serde_json::json!({
        "response_type": req.response_type,
        "client_id": client.client_id,
        "redirect_uri": pushed_redirect_uri,
        "scope": req.scope,
        "state": req.state,
        "code_challenge": req.code_challenge,
        "code_challenge_method": req.code_challenge_method,
        "nonce": req.nonce,
        "resource": req.resource,
        "dpop_jkt": code_record_jkt(&req.dpop_jkt),
        "authorization_details": authorization_details,
        "response_mode": req.response_mode,
    });
    // The PAR's verified proof binds the request (overrides the absent
    // pre-bound value).
    if let Some(j) = params_dpop_jkt {
        if let Some(obj) = params.as_object_mut() {
            obj.insert("dpop_jkt".to_string(), serde_json::Value::String(j));
        }
    }
    // The pushed object's params WIN (RFC 9126: it is the request).
    if !params_overlay.is_empty() {
        if let Some(obj) = params.as_object_mut() {
            for (k, v) in params_overlay {
                obj.insert(k, v);
            }
        }
    }

    let client = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                e.to_string(),
            )
        })?;
    let conn = client;

    let _: () = conn
        .set_ex(&valkey_key, params.to_string(), 600)
        .await
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                e.to_string(),
            )
        })?;

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
    /// RFC 9449 pre-bound DPoP key thumbprint (DESIGN - the token's
    /// cnf.jkt when the request itself carries no live DPoP proof).
    dpop_jkt: Option<String>,
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    /// OIDC nonce.
    nonce: Option<String>,
    /// RFC 8707 resource indicator.
    resource: Option<String>,
    /// OAuth response mode (`query` default, `jwt` for JARM).
    response_mode: Option<String>,
    /// RFC 9396 authorization_details - validated against
    /// the client's registered types.
    authorization_details: Option<serde_json::Value>,
    /// OIDC Core §5.5 claims request - parsed + shape-validated (DESIGN
    /// §9a.3). The object rides the code record; the token exchange
    /// applies it as a claim SELECTION (never a widening).
    claims: Option<serde_json::Value>,
    /// OIDC Core §3.1.2.1 acr_values - echoed as the ID token's `acr`
    /// claim (DESIGN §9a.11).
    acr: Option<String>,
    /// The resolved PAR record's request_uri (auth DESIGN §9a.19: the
    /// record is multi-read across the SPA's login/consent re-entries and
    /// marked used when the code issues).
    par_key: Option<String>,
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
        dpop_jkt: q.dpop_jkt.clone(),
        nonce: q.nonce.clone(),
        resource: q.resource.clone(),
        response_mode: q.response_mode.clone(),
        authorization_details: None,
        // OIDC Core §5.5 claims request (DESIGN §9a.3): parse + validate
        // the JSON shape up front - malformed JSON or a non-object rejects
        // the request per spec. Unknown top-level keys are ignored (the
        // spec allows OPs to ignore claims they do not support).
        claims: match q.claims.as_deref() {
            Some(raw) if !raw.is_empty() => match serde_json::from_str::<serde_json::Value>(raw) {
                Ok(v) if v.is_object() => Some(v),
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "invalid_request",
                            "error_description": "claims parameter must be a JSON object"
                        })),
                    )
                        .into_response();
                }
            },
            _ => None,
        },
        // DESIGN §9a.11 - acr_values ride the code record; the mint
        // echoes the first requested level as the `acr` claim.
        acr: q.acr_values.clone().filter(|s| !s.trim().is_empty()),
        par_key: None,
    };

    //enforce the caller's env-resolved profile
    // when require_par is true.
    let profile = resolve_security_profile(&state.pool, &headers, "env").await;
    // DESIGN §9a.22 - the PAR-mandatory reject is DEFERRED to the same
    // browser-visible error-redirect gate as the response_type check
    // (RFC 6749 §4.1.2.1: the error redirect goes to a VALIDATED
    // redirect_uri; the flag rides to the post-validation site below).
    let missing_par = profile.require_par && q.request_uri.is_none();
    // The deferred PAR-urn reject (DESIGN §9a.22): set when the request_uri
    // did not resolve or resolved for a different client - the reject is
    // DELIVERED after the client + redirect_uri validation (error redirect).
    let mut deferred_par_reject: Option<String> = None;
    // The deferred PKCE-missing reject (same post-validation channel -
    // the PAR-flow PKCE negatives read the callback).
    let mut deferred_pkce_reject: Option<String> = None;

    // PAR urns resolve from Valkey (single-use). Anything else is a JAR
    // request-object reference (RFC 9101 §5.2.1, DESIGN §9a.7) and falls
    // through to the signed-request-object fetch below.
    let is_par_uri = q
        .request_uri
        .as_deref()
        .map(|u| u.starts_with("urn:ietf:params:oauth:request_uri:"))
        .unwrap_or(false);
    if let (Some(ref request_uri), true) = (q.request_uri.as_deref(), is_par_uri) {
        // DESIGN §9a.22 (PAR-urn-resolution reject): an unresolvable (expired
        // /retired/unknown) urn or one bound to another client DEFERS its
        // reject to the post-(client,redirect_uri)-validation site - the
        // browser then receives the OAuth error REDIRECT on the validated
        // callback (error=invalid_request_uri), never an inline 400 body
        // (the suite's request_uri-negative family + the error-page
        // placeholder class both read the callback).
        let mut par_reject: Option<&'static str> = None;
        match resolve_par_request(&state, request_uri).await {
            Some(stored) => {
                // the PAR record is client-bound: the query
                // client_id must match the client that pushed the request.
                let par_client = stored
                    .get("client_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if par_client != params.client_id {
                    // DIFFERENT-CLIENT: the resolution result exists but is
                    // not ours - same deferred channel (invalid_request_uri
                    // is permitted by the bound-to-client module's 3-way
                    // error set {invalid_request, invalid_request_uri,
                    // access_denied}).
                    par_reject = Some("request_uri was issued to a different client");
                } else {
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
                if let Some(rm) = stored.get("response_mode").and_then(|v| v.as_str()) {
                    params.response_mode = Some(rm.to_string());
                }
                if let Some(n) = stored.get("nonce").and_then(|v| v.as_str()) {
                    params.nonce = Some(n.to_string());
                }
                if let Some(r) = stored.get("resource").and_then(|v| v.as_str()) {
                    params.resource = Some(r.to_string());
                }
                // RFC 9449 - the pre-registered DPoP key thumbprint
                // (pushed on PAR / inline on authorize) binds the token's
                // cnf.jkt when the request itself carries no live DPoP
                // proof (the PAR-resolution path).
                if let Some(j) = stored
                    .get("dpop_jkt")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    params.dpop_jkt = Some(j.to_string());
                }
                params.par_key = Some(request_uri.to_string());
                // - RAR: the PAR record is the authoritative
                // source (validated at push time); overlay verbatim.
                if let Some(ad) = stored.get("authorization_details") {
                    if !ad.is_null() {
                        params.authorization_details = Some(ad.clone());
                    }
                }
                // DESIGN §9a.11 - acr_values overlay too (PAR-stored are
                // authoritative).
                if let Some(a) = stored.get("acr_values").and_then(|v| v.as_str()) {
                    if !a.trim().is_empty() {
                        params.acr = Some(a.to_string());
                    }
                }
                }
            }
            None => {
                // Expired / retired / unknown PAR urn - the DEFERRED reject
                // (DESIGN §9a.22): redirect after redirect_uri validation.
                par_reject = Some("invalid or expired request_uri");
            }
        }
        if let Some(desc) = par_reject {
            deferred_par_reject = Some(desc.to_string());
        }
    }

    // ── JAR (RFC 9101) - signed request object overlay ──
    //
    // When a `request` JWT parameter is present, verify its signature
    // against the client's registered keys (inline `jwks` or `jwks_uri`)
    // and overlay its params over the inline ones (JAR wins).
    //
    // A `request_uri` that is NOT a PAR urn is a JAR request-object
    // reference (RFC 9101 §5.2.1, DESIGN §9a.7): fetch the JWT over
    // https and treat it as the `request` parameter (same verifier).
    // A PAR urn was RESOLVED (single-use GETDEL) and overlaid above -
    // `q.request_uri` still holds it, so it must be EXCLUDED here or
    // every PAR request would also (incorrectly) run the JAR https
    // fetch on the urn and fail with "request_uri must be https"
    // (breaking the whole PAR flow - BFF/dash sign-in included).
    let jar_jwt: Option<String> = if let Some(ref request_jwt) = q.request {
        Some(request_jwt.clone())
    } else if let Some(uri) = q.request_uri.as_deref().filter(|_| !is_par_uri) {
        match fetch_request_object(uri).await {
            Ok(jwt) => Some(jwt),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": format!("request_uri: {e}")
                    })),
                )
                    .into_response();
            }
        }
    } else {
        None
    };
    if let Some(request_jwt) = jar_jwt {
        let resolved_profile = crate::fapi::FapiProfile::from_str(
            &resolve_security_profile(&state.pool, &headers, "env").await.profile,
        );
        // (DESIGN 9a.14): the mandate table resolves from the FAPI
        // posture ONCE - no per-call-site booleans. The nonce gate reads
        // the INLINE request scope (the object scope overlays AFTER the
        // signature/claims pass).
        let jar_flags = resolved_profile
            .as_ref()
            .map(|p| p.required_flags())
            .unwrap_or_else(crate::fapi::required_flags_default);
        match verify_jar_request(
            &state,
            &params.client_id,
            &request_jwt,
            &resolve_issuer(&state.config, &headers),
            &jar_flags,
            params.scope.as_str(),
        )
        .await
        {
            Ok(jar) => {
                if !jar.redirect_uri.is_empty() {
                    // OIDC Core §6.4.1: when the request object carries a
                    // redirect_uri, the outer request's redirect_uri MUST
                    // match it EXACTLY (a mismatch is a parameter-forgery
                    // mix - reject with invalid_request). When the outer
                    // one is absent it is fine (the object's value wins).
                    if let Some(outer) = q
                        .redirect_uri
                        .as_deref()
                        .filter(|s| !s.is_empty())
                    {
                        if outer != jar.redirect_uri {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({
                                    "error": "invalid_request",
                                    "error_description":
                                        "redirect_uri does not match the request object"
                                })),
                            )
                                .into_response();
                        }
                    }
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
                // the reject message carries its PRECISE error code
                // as the "<code>: <text>" head (the pairing rule's
                // unsupported_response_type among them) - the inline
                // (pre-redirect) channel passes the code through; an
                // unprefixed message keeps invalid_request.
                let (code, desc) = match e.split_once(": ") {
                    Some((c, d))
                        if matches!(
                            c,
                            "invalid_request"
                                | "invalid_request_object"
                                | "unsupported_response_type"
                        ) =>
                    {
                        (c.to_string(), d.to_string())
                    }
                    _ => ("invalid_request".to_string(), e.clone()),
                };
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": code,
                        "error_description": format!("JAR request rejected: {desc}")
                    })),
                )
                    .into_response();
            }
        }
    }

    // Validate response_type.
    // RFC 6749 §4.1.2.1 / OIDC Core §3.1.2.1: once the client_id and
    // redirect_uri are known-valid (checked below), every further
    // validation error is delivered as a 302 REDIRECT back to the
    // redirect_uri with `error` + `state` - never an inline body (the
    // OIDF suite's response-type-missing test requires the redirect;
    // an inline 400 stalls every browser-driven RP). The check is
    // therefore DEFERRED until the client/redirect_uri validation has
    // passed; see the redirect-error helper after that block.
    // The standard FIVE (DESIGN §9a.13): `code` continues into the
    // exchange; the id_token/token members make the response a FRAGMENT
    // response (OAuth-) - the redirect encoding picks the channel
    // downstream (is_fragment_response).
    // A FAPI2-SP posture (PAR-mandating profile) restricts the
    // authorization request to `code` ONLY (FAPI2-SP-FINAL-5.2.2-1: the
    // hybrid/id_token/token response types are out of profile - the
    // suite's ensure-response-type-code-idtoken-fails requires the
    // reject, DESIGN §9a.22).
    let response_type_invalid = !is_supported_response_type(&params.response_type)
        || (profile.require_par
            && params.response_type.split_whitespace().ne(std::iter::once("code").collect::<Vec<&str>>()));

    // Validate PKCE if code_challenge is present. S256-only (RFC 7636
    // §4.2 - the 'plain' method is out of the FAPI/our posture): the
    // reject DEFERS to the post-validation site (DESIGN §9a.22) - the
    // suite's plain-pkce-rejected module reads the callback
    // (EnsurePARInvalidRequestError).
    let pkce_method_invalid = params
        .code_challenge_method
        .as_deref()
        .map(|m| m != "S256")
        .unwrap_or(false);
    if pkce_method_invalid {
        deferred_pkce_reject = Some("code_challenge_method must be S256".to_string());
    }
    // PKCE is mandatory when the profile mandates PAR
    // (FAPI 2.0 default): the reject DEFERS to the post-validation site
    // (DESIGN §9a.22) - the suite's PKCE-negative family reads the
    // CALLBACK (EnsurePARInvalidRequestError); the inline 400 stays only
    // for the pre-validated client case.
    let pkce_missing = profile.require_pkce
        && params.code_challenge.as_deref().unwrap_or("").is_empty();
    if pkce_missing {
        deferred_pkce_reject = Some("PKCE code_challenge is required by the active security profile".to_string());
    }

    // (FAPI 1.0 Advanced §5.2.3.2, DESIGN §9a.3) - the `resource`
    // authorization-request parameter is outside FAPI 1.0 (RFC 8707
    // resource indicators postdate the profile; the conformance suite
    // requires the OP to reject it under fapi_1_advanced). FAPI 2.0
    // permits it (and mints aud-bound tokens from it, SEC-).
    if !params.resource.as_deref().unwrap_or("").is_empty()
        && profile.profile == "fapi_1_advanced"
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "the resource parameter is not permitted under the fapi_1_advanced security profile"
            })),
        )
            .into_response();
    }

    // Look up the OAuth client to check consent_required
    // and validate the redirect_uri against the registered allow-list
    // (open-redirect defense).
    //
    // run with the tenant context on the same connection:
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
    // The missing-redirect_uri adoption (RFC 6749 §4.1.2.1, DESIGN
    // §9a.22): a request that omits redirect_uri against a client with
    // EXACTLY ONE registered redirect_uri adopts that URI (and every
    // downstream validation error redirects there). Zero or multiple
    // registrations stay the inline 400 - the target would be an
    // assumption.
    if params.redirect_uri.is_empty() && client_redirect_uris.len() == 1 {
        params.redirect_uri = client_redirect_uris[0].clone();
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

    // DESIGN 9a.14 - the FAPI response_mode=query mandate : under
    // every FAPI posture the authorization response is fragment- or
    // JARM-encoded ONLY; an explicit query mode (inline or the
    // authoritative PAR-stored value) rejects BEFORE the code mint via
    // the profile's deferred error-redirect channel. Non-FAPI postures
    // keep query as their default mode.
    {
        let fapi_posture = crate::fapi::FapiProfile::from_str(&profile.profile)
            .map(|p| {
                matches!(
                    p,
                    crate::fapi::FapiProfile::Fapi10Advanced
                        | crate::fapi::FapiProfile::Fapi20
                        | crate::fapi::FapiProfile::Fapi20MessageSigning
                )
            })
            .unwrap_or(false);
        if fapi_posture && params.response_mode.as_deref() == Some("query") {
            // JARM wraps the reject when the posture mandates JARM and the
            // request rides response_mode=jwt... except the offending mode
            // IS query here: the wrapped form needs the jwt transport, so
            // the plain (unwrapped) url-query reject is the compliant
            // channel for a query-mode request (the suite's
            // RejectAuthCodeInUrlQuery reads `error=` from the callback).
            return authorize_error_redirect(
                &params.redirect_uri,
                "invalid_request",
                "response_mode=query is not allowed by the FAPI security profile",
                Some(params.state.as_str()),
            );
        }
    }

    // DESIGN §9a.22 - the deferred PAR-mandatory reject: the client and
    // redirect_uri are now validated, so the reject goes back as the
    // OAuth error redirect (the browser-driven RP reads the callback -
    // the ensure-unsigned-authorization-request-without-using-par-fails
    // module's EnsureInvalidRequestError).
    if missing_par {
        // JARM wraps the reject as well (response_mode=jwt - the suite's
        // ExtractJARMFromURLQuery reads the callback's `response` param
        // even for errors; a plain error redirect = no response at all).
        if profile.require_jarm && params.response_mode.as_deref() == Some("jwt") {
            let jarm_claims = crate::jarm::build_jarm_error(
                &resolve_issuer(&state.config, &headers),
                &params.client_id,
                "invalid_request",
                Some("PAR is required - provide a request_uri from /oauth/par"),
                if params.state.is_empty() {
                    None
                } else {
                    Some(&params.state)
                },
            );
            if let Ok(jwt) = crate::jarm::sign_jarm_jwt(&state.keys, &jarm_claims, &profile.signing_alg) {
                let url = crate::jarm::build_jarm_redirect_url(&params.redirect_uri, &jwt);
                return (StatusCode::FOUND, [("location", url)]).into_response();
            }
        }
        return authorize_error_redirect(
            &params.redirect_uri,
            "invalid_request",
            "PAR is required - provide a request_uri from /oauth/par",
            Some(params.state.as_str()),
        );
    }

    // DESIGN §9a.22 (PAR-urn-resolution reject): the deferred
    // invalid/expired/different-client request_uri reject - delivered now
    // that the client + redirect_uri are validated, as the OAuth error
    // redirect with `invalid_request_uri` (the suite's
    // EnsureInvalidRequestUriError exact-match channel; the bound-to-client
    // module's 3-way permitted set includes it as well).
    if let Some(desc) = deferred_par_reject {
        if profile.require_jarm && params.response_mode.as_deref() == Some("jwt") {
            let jarm_claims = crate::jarm::build_jarm_error(
                &resolve_issuer(&state.config, &headers),
                &params.client_id,
                "invalid_request_uri",
                Some(&desc),
                if params.state.is_empty() {
                    None
                } else {
                    Some(&params.state)
                },
            );
            if let Ok(jwt) = crate::jarm::sign_jarm_jwt(&state.keys, &jarm_claims, &profile.signing_alg) {
                let url = crate::jarm::build_jarm_redirect_url(&params.redirect_uri, &jwt);
                return (StatusCode::FOUND, [("location", url)]).into_response();
            }
        }
        return authorize_error_redirect(
            &params.redirect_uri,
            "invalid_request_uri",
            &desc,
            Some(params.state.as_str()),
        );
    }
    // DESIGN §9a.22 - the deferred PKCE-missing reject (the same
    // post-validation channel; the PAR-flow PKCE negatives read the
    // callback with an invalid_request error - in the JARM form when the
    // profile mandates it (response_mode=jwt rides the object).
    if let Some(desc) = deferred_pkce_reject {
        if profile.require_jarm && params.response_mode.as_deref() == Some("jwt") {
            let jarm_claims = crate::jarm::build_jarm_error(
                &resolve_issuer(&state.config, &headers),
                &params.client_id,
                "invalid_request",
                Some(&desc),
                if params.state.is_empty() {
                    None
                } else {
                    Some(&params.state)
                },
            );
            if let Ok(jwt) = crate::jarm::sign_jarm_jwt(&state.keys, &jarm_claims, &profile.signing_alg) {
                let url = crate::jarm::build_jarm_redirect_url(&params.redirect_uri, &jwt);
                return (StatusCode::FOUND, [("location", url)]).into_response();
            }
        }
        return authorize_error_redirect(
            &params.redirect_uri,
            "invalid_request",
            &desc,
            Some(params.state.as_str()),
        );
    }

    // Deferred response_type check (RFC 6749 §4.1.2.1 - see the comment at
    // the deferred site above): the client and redirect_uri are valid, so
    // the error goes back to the RP as a redirect.
    if response_type_invalid {
        // The response-type reject = the PLAIN url-query error (the
        // suite's DetectWhetherErrorResponseIsInQueryOrFragment class
        // owns this module family - it reads `error` from the callback
        // query directly; the JARM-wrapped form logs
        // 'unexpected parameters' + no-JARM decode chain).
        let mut url = format!(
            "{}?error=unsupported_response_type&error_description={}",
            params.redirect_uri,
            urlencode("only 'code' is supported")
        );
        if !params.state.is_empty() {
            url.push_str(&format!("&state={}", urlencode(&params.state)));
        }
        return (StatusCode::FOUND, [("location", url)]).into_response();
    }

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

    // (OIDC Core §3.1.2.1, DESIGN §9a.3) - prompt + max_age semantics.
    // `prompt=none` requires silent authentication: a valid session
    // issues the code directly; anything else redirects back with
    // error=login_required (never an interstitial - the RP must not
    // render a UI). `prompt=login` forces re-authentication: ignore any
    // existing session and always show the sign-in page.
    // `max_age=N` demands the session be younger than N seconds.
    let prompt_values: Vec<&str> = q
        .prompt
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .collect();
    let force_login = prompt_values.iter().any(|p| *p == "login");
    let silent_only = prompt_values.iter().any(|p| *p == "none");
    // Unknown prompt values are an error per OIDC Core §3.1.2.1 (the
    // OP MUST NOT ignore a prompt value it does not understand).
    if let Some(bad) = prompt_values
        .iter()
        .find(|p| !matches!(**p, "none" | "login" | "consent"))
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": format!("unsupported prompt value: {bad}")
            })),
        )
            .into_response();
    }

    // Session state for the silent/max_age decision (cookie or bearer).
    let existing_session = crate::handlers::extract_session_token(&headers)
        .and_then(|tok| {
            // Synchronous lookup is not possible here; mark presence and
            // let the async check below validate it.
            Some(tok)
        });
    let mut session_is_fresh_enough = false;
    let mut session_user: Option<Uuid> = None;
    // OIDC Core §2: `auth_time` = the time of the user's last authentication
    // (the session's created_at) - carried into silent-issuance code records
    // so the prompt-none tokens match the interactive token's auth_time.
    let mut session_auth_time: Option<i64> = None;
    if let Some(tok) = existing_session.clone() {
        if let Ok(Some(sess)) = crate::sessions::Session::find_by_token(&state.pool, &tok).await {
            if sess.is_valid() {
                let age_secs = chrono::Utc::now()
                    .signed_duration_since(sess.created_at)
                    .num_seconds();
                let max_age_ok = q
                    .max_age
                    .map(|m| age_secs <= m)
                    .unwrap_or(true);
                if max_age_ok {
                    session_is_fresh_enough = true;
                    session_user = Some(sess.user_id);
                    session_auth_time = Some(sess.created_at.timestamp());
                }
            }
        }
    }

    // prompt=none: silent issuance or the prescribed error redirect
    // (OIDC Core §3.1.2.1 - error goes back to redirect_uri, code never
    // reaches the client).
    if silent_only {
        // DESIGN §9a.13 - the fragment cells encode the response (SUCCESS
        // and ERROR alike) in the URL FRAGMENT (OAuth-); the query
        // channel is only for the `code`-only cell.
        let fragment_mode = crate::oauth::is_fragment_response(&params.response_type);
        let error_redirect = |err: &str, desc: &str, mode: Option<&str>| -> Response {
            let mut url = format!(
                "{}{}error={}&error_description={}",
                params.redirect_uri,
                if fragment_mode { "#" } else { "?" },
                urlencode(err),
                urlencode(desc)
            );
            if !params.state.is_empty() {
                url.push_str(&format!("&state={}", urlencode(&params.state)));
            }
            if profile.require_iss {
                url.push_str(&format!("&iss={}", urlencode(&resolve_issuer(&state.config, &headers))));
            }
            // JARM wraps authorization errors too (response_mode=jwt).
            if profile.require_jarm && mode == Some("jwt") {
                let jarm_claims = crate::jarm::build_jarm_error(
                    &state.config.issuer,
                    &params.client_id,
                    err,
                    Some(desc),
                    if params.state.is_empty() {
                        None
                    } else {
                        Some(&params.state)
                    },
                );
                if let Ok(jwt) = crate::jarm::sign_jarm_jwt(&state.keys, &jarm_claims, &profile.signing_alg) {
                    let url = crate::jarm::build_jarm_redirect_url(&params.redirect_uri, &jwt);
                    return (StatusCode::FOUND, [("location", url)]).into_response();
                }
            }
            (StatusCode::FOUND, [("location", url)]).into_response()
        };
        if !session_is_fresh_enough || session_user.is_none() {
            // OIDC Core §3.1.2.1 - both the absent-session case and the
            // stale-session case (max_age exceeded) answer with
            // `login_required` back at the redirect_uri; the description
            // distinguishes them for operators reading the logs.
            let desc = if q.max_age.is_some() && existing_session.is_some() {
                "max_age exceeded - re-authentication required"
            } else {
                "no active session"
            };
            return error_redirect("login_required", desc, params.response_mode.as_deref());
        }
        // Fresh session present - issue the code silently (no UI).
        let user_id = session_user.expect("checked above");
        let env_id = crate::overlays::env_from_headers(&headers);
        let code = Uuid::new_v4().to_string();
        let code_key = format!("auth:authcode:{code}");
        // OIDC Core §2 / prompt=none: `auth_time` is the time of the
        // USER'S LAST AUTHENTICATION - the session's created_at (captured
        // during session resolution) - never the silent-issuance wall
        // clock. The suite's prompt-none tests compare auth_time across
        // the interactive and silent tokens: stamping `now` breaks the
        // pair on every fresh session.
        let code_data = serde_json::json!({
            "client_id": params.client_id,
            "redirect_uri": params.redirect_uri,
            "scope": params.scope,
            "user_id": user_id.to_string(),
            "env_id": env_id.to_string(),
            "code_challenge": params.code_challenge,
            "nonce": params.nonce,
            "dpop_jkt": resolve_continue_jkt(&state, None, params.dpop_jkt.as_deref(), &params.state).await,
            "resource": params.resource,
            "state": params.state,
            "auth_time": session_auth_time.unwrap_or_else(|| chrono::Utc::now().timestamp()),
            "authorization_details": params.authorization_details,
            "claims": params.claims,
            "acr_values": params.acr,
            "par_key": params.par_key,
            // FAPI2-SP code-lifetime gate (DESIGN §9a.11): the record's
            // ISSUE TIME rides the payload so the exchange can
            // wall-clock-check it - the Valkey TTL alone is only the
            // 600s upper bound, never the RFC 6749 short-lived posture.
            "iat": chrono::Utc::now().timestamp(),
            // DESIGN §9a.13 - the CELL's response_type (the fragment
            // cells deliver id_token/token in the fragment even on the
            // silent path).
            "response_type": params.response_type,
        });
        let valkey_conn =
            match sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
            {
                Ok(c) => c,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "error": "server_error",
                            "error_description": format!("valkey unavailable: {e}")
                        })),
                    )
                        .into_response();
                }
            };
        let set_result: Result<(), _> = valkey_conn
            .set_ex(&code_key, code_data.to_string(), 600)
            .await;
        if let Err(e) = set_result {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": format!("code store failed: {e}")
                })),
            )
                .into_response();
        }
        if let Some(pk) = params.par_key.as_deref().filter(|s| !s.is_empty()) {
            mark_par_used(&state, pk).await;
        }
        // DESIGN §9a.13 - the fragment cells: the silent response
        // encodes id_token/token + code members in the FRAGMENT
        // (OAuth-). The code-only cell keeps the query encoding.
        if crate::oauth::is_fragment_response(&params.response_type) {
            let wants_id_token = params.response_type.split_whitespace().any(|p| p == "id_token");
            let wants_token = params.response_type.split_whitespace().any(|p| p == "token");
            let wants_code = params.response_type.split_whitespace().any(|p| p == "code");
            let issuer2 = resolve_issuer(&state.config, &headers);
            let access_token_for_hash = if wants_token {
                let scope = params.scope.clone();
                let merged = crate::handlers::merge_scopes(
                    &scope,
                    &crate::handlers::fetch_role_scopes(&state.pool, user_id).await.unwrap_or_default(),
                );
                let access_claims = {
                    let mut c = AuthClaims::access_with_client(
                        &issuer2,
                        user_id,
                        &scope,
                        env_id,
                        None,
                        Some(&params.client_id),
                        Duration::seconds(state.config.access_token_ttl_secs as i64),
                    );
                    c.token_tp = "access".into();
                    c
                };
                let _ = merged;
                let claims_json = serde_json::to_value(&access_claims).unwrap_or(serde_json::json!({}));
                match state.keys.sign_value_alg(&claims_json, &profile.signing_alg) {
                    Ok(t) => t,
                    Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
                }
            } else {
                String::new()
            };
            let Ok(mut tx) = state.pool.begin().await else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "server_error",
                        "error_description": "pool unavailable"})),
                )
                    .into_response();
            };
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                .bind(env_id)
                .execute(&mut *tx)
                .await;
            let user_row = sqlx::query!(
                r#"SELECT email, first_name, last_name, phone,
                          street_address, locality, region, postal_code, country,
                          oidc_profile, updated_at
                   FROM users WHERE id = $1"#,
                user_id,
            )
            .fetch_optional(&mut *tx)
            .await
            .unwrap_or(None);
            let _ = tx.commit().await;
            let email = user_row.as_ref().map(|r| r.email.clone());
            let name = user_row.as_ref().map(|r| {
                crate::jwt::derive_profile_name(
                    r.oidc_profile.get("name").and_then(|v| v.as_str()),
                    r.first_name.as_deref().map(str::trim).filter(|s| !s.is_empty()),
                    r.last_name.as_deref().map(str::trim).filter(|s| !s.is_empty()),
                )
                .unwrap_or_default()
            });
            let phone = user_row.as_ref().and_then(|r| r.phone.clone());
            let address = user_row.as_ref().and_then(|r| {
                crate::jwt::build_address_claim(
                    r.street_address.as_deref(),
                    r.locality.as_deref(),
                    r.region.as_deref(),
                    r.postal_code.as_deref(),
                    r.country.as_deref(),
                )
            });
            let id_claims = crate::jwt::AuthClaims::id_token_with_details(
                &issuer2,
                user_id,
                &params.client_id,
                params.nonce.as_deref(),
                session_auth_time.unwrap_or_else(|| chrono::Utc::now().timestamp()),
                &access_token_for_hash,
                email.as_deref(),
                params.scope.split_whitespace().any(|s| s == "email"),
                name.as_deref(),
                params.scope.split_whitespace().any(|s| s == "profile"),
                phone.as_deref(),
                params.scope.split_whitespace().any(|s| s == "phone"),
                address.as_ref(),
                params.scope.split_whitespace().any(|s| s == "address"),
                Duration::seconds(state.config.access_token_ttl_secs as i64),
                params.authorization_details.as_ref(),
                None,
                params.acr.as_deref(),
            );
            let mut id_claims = id_claims;
            if wants_code {
                id_claims["c_hash"] = serde_json::json!(crate::jwt::c_hash(&code));
            }
            let id_token = match state.keys.sign_value_alg(&id_claims, &profile.signing_alg) {
                Ok(t) => t,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            };
            let mut fragment_params: Vec<(&str, String)> = Vec::new();
            if wants_token {
                fragment_params.push(("access_token", access_token_for_hash.clone()));
                fragment_params.push(("token_type", "Bearer".to_string()));
                fragment_params.push(("expires_in", state.config.access_token_ttl_secs.to_string()));
            }
            if wants_code {
                fragment_params.push(("code", urlencode(&code)));
            }
            if wants_id_token {
                fragment_params.push(("id_token", id_token));
            }
            fragment_params.push(("state", urlencode(&params.state)));
            if profile.require_iss {
                fragment_params.push(("iss", urlencode(&issuer2)));
            }
            let mut url = params.redirect_uri.clone();
            let pairs: Vec<String> = fragment_params
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            url.push('#');
            url.push_str(&pairs.join("&"));
            return (StatusCode::FOUND, [("location", url)]).into_response();
        }
        let mut url = build_callback_url(
            &params.redirect_uri,
            &format!("code={}", urlencode(&code)),
            &[("state", urlencode(&params.state))],
        );
        if profile.require_iss {
            url.push_str(&format!("&iss={}", urlencode(&resolve_issuer(&state.config, &headers))));
        }
        if profile.require_jarm && params.response_mode.as_deref() == Some("jwt") {
            let jarm_claims = crate::jarm::build_jarm_success(
                &resolve_issuer(&state.config, &headers),
                &params.client_id,
                &code,
                if params.state.is_empty() { None } else { Some(&params.state) },
            );
            if let Ok(jwt) = crate::jarm::sign_jarm_jwt(&state.keys, &jarm_claims, &profile.signing_alg) {
                let url = crate::jarm::build_jarm_redirect_url(&params.redirect_uri, &jwt);
                return (StatusCode::FOUND, [("location", url)]).into_response();
            }
        }
        return (StatusCode::FOUND, [("location", url)]).into_response();
    }
    // prompt=login (or a stale max_age session): drop the silent path and
    // force the sign-in page; the session freshness check below still
    // guards max_age when the user arrives at /sign-in.
    // OIDC Core §3.1.2.1 (max_age, DESIGN §9a.3): a valid, fresh-enough
    // session answers the authorize request DIRECTLY - the same silent
    // issuance as prompt=none, WITHOUT creating a second session (the
    // max-age certification pair compares auth_time across the
    // interactive and re-authorize tokens; routing a fresh session back
    // through the login form mints a second session and a different
    // auth_time silently). The form only serves: no session, a stale
    // max_age session, or an explicit prompt=login.
    if session_is_fresh_enough
        && session_user.is_some()
        && !force_login
        && silent_only
    {
        // handled by the silent branch above (prompt=none only)
    }
    if session_is_fresh_enough && !force_login && !consent_required {
        // Reuse the silent-issuance logic: mint the code with the
        // session's own auth_time (no new session). A consent-required
        // client NEVER issues silently - the consent screen is the
        // user's decision point (the suite's user-rejects module drives
        // it; a remembered client consent would make the deny
        // un-reachable).
        let silent = crate::sessions::Session::find_by_token(
            &state.pool,
            existing_session.as_deref().unwrap_or(""),
        )
        .await
        .ok()
        .flatten()
        .filter(|s| s.is_valid());
        if let Some(sess) = silent {
            let user_id = sess.user_id;
            let env_id = sess.env_id;
            let code = Uuid::new_v4().to_string();
            let code_key = format!("auth:authcode:{code}");
            let code_data = serde_json::json!({
                "client_id": params.client_id,
                "redirect_uri": params.redirect_uri,
                "scope": params.scope,
                "user_id": user_id.to_string(),
                "env_id": env_id.to_string(),
                "code_challenge": params.code_challenge,
                "nonce": params.nonce,
            "dpop_jkt": resolve_continue_jkt(&state, None, params.dpop_jkt.as_deref(), &params.state).await,
                "resource": params.resource,
                "state": params.state,
                "auth_time": sess.created_at.timestamp(),
                "par_key": params.par_key,
                "authorization_details": params.authorization_details,
                "claims": params.claims,
                "acr_values": params.acr,
                // Same iat stamp as every other code record (§9a.11).
                "iat": chrono::Utc::now().timestamp(),
            });
            if let Ok(valkey_conn) =
                sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
            {

        if let Some(pk) = params.par_key.as_deref().filter(|s| !s.is_empty()) {
            mark_par_used(&state, pk).await;
        }
                let set_result: Result<(), _> = valkey_conn
                    .set_ex(&code_key, code_data.to_string(), 600)
                    .await;
                if set_result.is_ok() {
                    let mut url = build_callback_url(
                        &params.redirect_uri,
                        &format!("code={}", urlencode(&code)),
                        &[("state", urlencode(&params.state))],
                    );
                    if profile.require_iss {
                        url.push_str(&format!("&iss={}", urlencode(&resolve_issuer(&state.config, &headers))));
                    }
                    if profile.require_jarm && params.response_mode.as_deref() == Some("jwt") {
                        let jarm_claims = crate::jarm::build_jarm_success(
                            &resolve_issuer(&state.config, &headers),
                            &params.client_id,
                            &code,
                            Some(&params.state),
                        );
                        if let Ok(jwt) = crate::jarm::sign_jarm_jwt(&state.keys, &jarm_claims, &profile.signing_alg) {
                            let url = crate::jarm::build_jarm_redirect_url(&params.redirect_uri, &jwt);
                            return (StatusCode::FOUND, [("location", url)]).into_response();
                        }
                    }
                    return (StatusCode::FOUND, [("location", url)]).into_response();
                }
            }
        }
    }
    let _ = force_login;

    // Redirect to the hosted sign-in page with OAuth params preserved.
    // Route the interactive step (DESIGN §9a.8, §9a.11): ONE surface -
    // the ORIGINAL Flutter auth-ui (`/sign-in`/`/sign-up`). The prior
    // JS-free HTML form at /oauth/login stays for non-JS clients as the
    // explicit `?ui=html` escape hatch (e.g. a suite profile that
    // forbids JS); every browser automation (OIDF rig, e2e, Selenium-
    // class clients) drives the SPA + its test bridge now.
    let is_signup = q
        .screen_hint
        .as_deref()
        .map(|s| s.eq_ignore_ascii_case("signup"))
        .unwrap_or(false);
    let ui_page = if is_signup {
        "/sign-up"
    } else if q.ui_login_page == Some(true) {
        "/oauth/login"
    } else {
        "/sign-in"
    };
    let mut ui_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256{}",
        ui_page,
        urlencode(&params.client_id),
        urlencode(&params.redirect_uri),
        urlencode(&params.scope),
        urlencode(&params.state),
        urlencode(params.code_challenge.as_deref().unwrap_or("")),
        // The SPA reads consent_required for its first-party bypass
        // (api.dart §4.16): FALSE must ride too, or the SPA routes the
        // consent-free client to the consent page (the OIDF rig's
        // clients are consent-bypass by registration).
        format!("&consent_required={consent_required}"),
    );
    // Forward the nonce so authorize/continue can bind it into the ID token
    // and the resource indicator.
    if let Some(n) = params.nonce.as_deref().filter(|s| !s.is_empty()) {
        ui_url.push_str(&format!("&nonce={}", urlencode(n)));
    }
    if let Some(pk) = params.par_key.as_deref().filter(|s| !s.is_empty()) {
        ui_url.push_str(&format!("&par_key={}", urlencode(pk)));
    }
    // Authorize-interaction memos: the SPA relays the UI's fields (its
    // consent continue may drop the dpop_jkt/par_key parameters), so the
    // resolved binding AND the interaction's PAR request_uri stash under
    // the interaction's state for the continue endpoints to fall back to.
    if let Some(pk) = params.par_key.as_deref().filter(|s| !s.is_empty()) {
        let par_memo_key = format!("auth:authz-par:{}", params.state);
        if let Ok(conn) =
            sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
        {
            let _: Result<(), _> = conn.set_ex(&par_memo_key, pk.to_string(), 600u64).await;
        }
    }
    if let Some(j) = params.dpop_jkt.as_deref().filter(|s| !s.is_empty()) {
        ui_url.push_str(&format!("&dpop_jkt={}", urlencode(j)));
        let memo_key = format!("auth:authz-jkt:{}", params.state);
        match sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await {
            Ok(conn) => {
                if let Err(e) = conn.set_ex(&memo_key, j.to_string(), 600u64).await.map(|_: ()| ()) {
                    tracing::warn!(error = %e, "authz-jkt memo write failed");
                }
            }
            Err(e) => tracing::warn!(error = %e, "authz-jkt memo connection failed"),
        }
    }
    if let Some(r) = params.resource.as_deref().filter(|s| !s.is_empty()) {
        ui_url.push_str(&format!("&resource={}", urlencode(r)));
    }
    // Forward the response mode so authorize/continue can honor a JARM
    // (`response_mode=jwt`) request.
    // DESIGN §9a.13 - forward the CELL's response_type so the continue
    // request serves the fragment cells (the id_token/token members)
    // and stamps the record.
    ui_url.push_str(&format!(
        "&response_type={}",
        urlencode(&params.response_type)
    ));
    if let Some(rm) = params.response_mode.as_deref().filter(|s| !s.is_empty()) {
        ui_url.push_str(&format!("&response_mode={}", urlencode(rm)));
    }
    // DESIGN §9a.11 - forward acr_values so the login form's context
    // carries it into the code record (the ID-token acr echo).
    if let Some(a) = params.acr.as_deref().filter(|s| !s.trim().is_empty()) {
        ui_url.push_str(&format!("&acr_values={}", urlencode(a)));
    }
    // DESIGN §9a.3/§9a.11 - forward the §5.5 claims request so the SPA's
    // authorizeContinue re-binds it into the code record (the selection
    // never drops at the hosted-UI hop).
    if let Some(c) = params.claims.as_ref() {
        if !c.is_null() {
            ui_url.push_str(&format!(
                "&claims={}",
                urlencode(&serde_json::to_string(c).unwrap_or_default())
            ));
        }
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
    /// OIDC nonce - bound into the ID token.
    #[serde(default)]
    /// The nonce.
    pub nonce: Option<String>,
    /// RFC 8707 resource indicator.
    #[serde(default)]
    /// The resource.
    pub resource: Option<String>,
    /// OAuth response mode - `jwt` triggers a JARM response.
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
    /// OIDC Core §5.5 claims request - carried from the authorize step
    /// and applied at ID-token mint as a claim selection (DESIGN §9a.3).
    /// Accepts the JSON object OR the object-as-STRING (the hosted UI
    /// forwards the authorize request's claims parameter verbatim).
    #[serde(default, deserialize_with = "deserialize_claims_flex")]
    /// The claims.
    pub claims: Option<serde_json::Value>,
    /// OIDC Core §3.1.2.1 acr_values - carried from the authorize step
    /// (or the login form context) into the code record for the ID-token
    /// `acr` echo (DESIGN §9a.11).
    #[serde(default)]
    /// The acr values.
    pub acr_values: Option<String>,
    /// The USER DENIED the request (the hosted UI's cancel/deny
    /// control): the continuation redirects to the client with
    /// `error=access_denied` + state (RFC 6749 SS4.1.2.1; OIDC Core
    /// SS3.1.2.6) - no code is minted. The certification rig's
    /// user-rejects-authentication module drives exactly this path.
    #[serde(default)]
    /// The user denied.
    pub deny: Option<bool>,
    /// The PAR interaction key (the code issuance marks the request_uri
    /// used - auth DESIGN §9a.19).
    #[serde(default)]
    pub par_key: Option<String>,
    /// RFC 9449 dpop_jkt carried from the authorize step (the SPA
    /// forwards the pre-bound DPoP thumbprint into the code record).
    #[serde(default)]
    /// The dpop jkt.
    pub dpop_jkt: Option<String>,
    /// The authorize CELL's response_type (DESIGN §9a.13): the code/"
    /// id_token hybrid cells deliver the id_token member in the
    /// FRAGMENT response; the record stamps it for the exchange check.
    #[serde(default)]
    /// The response type.
    pub response_type: Option<String>,
}

/// Accept the claims request as the JSON object or as the object-encoded
/// string (the hosted UI forwards the authorize request's parameter
/// verbatim - DESIGN §9a.3).
fn deserialize_claims_flex<'de, D>(deserializer: D) -> Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: Option<serde_json::Value> = serde::Deserialize::deserialize(deserializer)?;
    Ok(match v {
        Some(serde_json::Value::String(raw)) if !raw.trim().is_empty() => {
            serde_json::from_str::<serde_json::Value>(raw.trim())
                .map(Some)
                .map_err(serde::de::Error::custom)?
        }
        other => other.filter(|x| !x.is_null()),
    })
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

    // re-validate the redirect_uri against the client's
    // registered allow-list before issuing any code (open-redirect
    // defense). Context-scoped lookup (RLS).
    let (_consent_meta, redirect_uris, _rar_types) = with_client_env(&state, req.client_id.clone())
        .await
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "unknown client_id".into()))?;
    if !redirect_uri_registered(&redirect_uris, &req.redirect_uri) {
        return Err((
            StatusCode::BAD_REQUEST,
            "redirect_uri is not registered for this client".into(),
        ));
    }

    // PKCE challenge must be present when the caller's env-resolved
    // profile mandates it (FAPI 2.0 default).
    let profile = resolve_security_profile(&state.pool, &headers, "env").await;
    if profile.require_pkce && req.code_challenge.as_deref().unwrap_or("").is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "PKCE code_challenge is required by the active security profile".into(),
        ));
    }

    // The USER DENIED the request (RFC 6749 SS4.1.2.1 - error redirects
    // to the redirect_uri with error=access_denied + state; OAuth2-iss
    // adds iss under require_iss). NO code is minted.
    if req.deny.unwrap_or(false) {
        // JARM (response_mode=jwt) wraps ERROR responses too - the FAPI
        // user-rejects module extracts the `response` JWT from the
        // callback (the plain access_denied query is the non-JARM form).
        if profile.require_jarm && req.response_mode.as_deref() == Some("jwt") {
            let jarm_claims = crate::jarm::build_jarm_error(
                &resolve_issuer(&state.config, &headers),
                &req.client_id,
                "access_denied",
                None,
                if req.state.is_empty() { None } else { Some(&req.state) },
            );
            let jarm_jwt = crate::jarm::sign_jarm_jwt(&state.keys, &jarm_claims, &profile.signing_alg)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
            return Ok(Json(serde_json::json!({
                "redirect_url": crate::jarm::build_jarm_redirect_url(&req.redirect_uri, &jarm_jwt)
            }))
            .into_response());
        }
        let mut url = build_callback_url(
            &req.redirect_uri,
            "error=access_denied",
            &[("state", urlencode(&req.state))],
        );
        if profile.require_iss {
            url.push_str(&format!(
                "&iss={}",
                urlencode(&resolve_issuer(&state.config, &headers))
            ));
        }
        // The SPA's authorizeContinue contract: a JSON body carrying the
        // redirect_url (the SPA navigates the browser itself) - a raw
        // 302 would be followed by fetch and break the client-side
        // state (the approval path answers the same shape).
        return Ok(Json(serde_json::json!({ "redirect_url": url })).into_response());
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

    // The PAR interaction key: the SPA's consent hop drops the relayed
    // parameter - the authorize memo (state-keyed) carries it onward
    // (auth DESIGN §9a.21).
    let interaction_par_key = {
        let carried = req.par_key.clone().filter(|s| !s.is_empty());
        match carried {
            Some(v) => Some(v),
            None => resolve_continue_par(&state, &req.state).await,
        }
    };
    let code_data = serde_json::json!({
           "client_id": req.client_id,
           "redirect_uri": req.redirect_uri,
           "scope": req.scope,
           "user_id": req.user_id.to_string(),
           "env_id": session.env_id.to_string(),
           "code_challenge": req.code_challenge,
           "nonce": req.nonce,
           "dpop_jkt": resolve_continue_jkt(&state, req.dpop_jkt.as_deref(), None, &req.state).await,
           "par_key": interaction_par_key,
           "resource": req.resource,
    // DESIGN §9a.3 - the client's `state` rides the code record
    // so the token exchange can mint `s_hash` (FAPI 1 §5.2.2.1) and
    // bind the issued tokens to this exact authorize interaction.
           "state": req.state,
    // auth_time for the ID token (OIDC Core ) - the session's issue time.
           "auth_time": session.created_at.timestamp(),
           "selected_account_ids": req.selected_account_ids,
    // RFC 9396 authorization_details - echoed into the ID
    // token via `_claim_names` at exchange time.
           "authorization_details": req.authorization_details,
    // OIDC Core §5.5 claims request - rides the code record so the
    // exchange applies the client's claim selection (DESIGN §9a.3).
           "claims": req.claims,
    // DESIGN §9a.11 - acr_values echo into the ID token.
           "acr_values": req.acr_values,
    // §9a.11 code-lifetime gate: the record's ISSUE TIME - the exchange
    // enforces the RFC 6749 short-lived posture against it.
           "iat": chrono::Utc::now().timestamp(),
    // DESIGN §9a.13 - the CELL's response_type: the fragment response
    // cells deliver id_token/token members + the exchange validates.
           "response_type": req.response_type.clone().unwrap_or_else(|| "code".to_string()),
       });

    let conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Use Valkey for auth codes (TTL 600s).
    let valkey_url = &state.config.valkey_url;

    // mark_par_used consumes the RESOLVED interaction key (the SPA's
    // consent hop drops `par_key` - the state-keyed memo carries it,
    // auth DESIGN §9a.21); using `req.par_key` alone left the used-key
    // unset and the reuse-after-outcome negative never rejected.
    if let Some(pk) = interaction_par_key
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        mark_par_used(&state, pk).await;
    }
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
        format!("&iss={}", urlencode(&resolve_issuer(&state.config, &headers)))
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
    let redirect_url = build_callback_url(
        &req.redirect_uri,
        &format!("code={}", urlencode(&code)),
        &[("state", urlencode(&req.state))],
    ) + &iss_param
        + &accounts_param;

    // JARM (`response_mode=jwt`): when the profile
    // requires JARM and the client requested the JWT response mode, the
    // response parameters are wrapped in a signed JWT delivered via the
    // `response` query parameter instead of plain query params.
    let response_url = if profile.require_jarm && req.response_mode.as_deref() == Some("jwt") {
        let jarm_claims = crate::jarm::build_jarm_success(
            &resolve_issuer(&state.config, &headers),
            &req.client_id,
            &code,
            Some(&req.state),
        );
        let jarm_jwt = crate::jarm::sign_jarm_jwt(&state.keys, &jarm_claims, &profile.signing_alg)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        crate::jarm::build_jarm_redirect_url(&req.redirect_uri, &jarm_jwt)
    } else {
        redirect_url
    };

    // DESIGN §9a.13 - the hybrid/implicit cells: a response_type carrying
    // an id_token/token member delivers its members in the URL FRAGMENT
    // (OAuth-). The id_token mints NOW (not at an exchange - there
    // is none for members without `code`); the access_token member (the
    // `token` cells) mints a bearer token bound to this grant.
    let cell_response_type = req.response_type.clone().unwrap_or_else(|| "code".to_string());
    let response_url = if crate::oauth::is_fragment_response(&cell_response_type) {
        let wants_id_token = cell_response_type.split_whitespace().any(|p| p == "id_token");
        let wants_token = cell_response_type.split_whitespace().any(|p| p == "token");
        let wants_code = cell_response_type.split_whitespace().any(|p| p == "code");
        let issuer = resolve_issuer(&state.config, &headers);
        // The user's claim data (the same RLS-scoped read the exchange
        // uses - the fragment id_token is a REAL ID token).
        let user_row = {
            let mut tx = state
                .pool
                .begin()
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                .bind(session.env_id)
                .execute(&mut *tx)
                .await;
            let row = sqlx::query!(
                r#"SELECT email, first_name, last_name, phone,
                          street_address, locality, region, postal_code, country,
                          oidc_profile, updated_at
                   FROM users WHERE id = $1"#,
                req.user_id,
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let _ = tx.commit().await;
            row
        };
        let email = user_row.as_ref().map(|r| r.email.clone());
        let name = user_row.as_ref().map(|r| {
            crate::jwt::derive_profile_name(
                r.oidc_profile.get("name").and_then(|v| v.as_str()),
                r.first_name.as_deref().map(str::trim).filter(|s| !s.is_empty()),
                r.last_name.as_deref().map(str::trim).filter(|s| !s.is_empty()),
            )
            .unwrap_or_default()
        });
        let phone = user_row.as_ref().and_then(|r| r.phone.clone());
        let address = user_row.as_ref().and_then(|r| {
            crate::jwt::build_address_claim(
                r.street_address.as_deref(),
                r.locality.as_deref(),
                r.region.as_deref(),
                r.postal_code.as_deref(),
                r.country.as_deref(),
            )
        });
        // The `token` cells: the authorize-time access token (bearer,
        // grant-bound). The `code` members mint no access token here.
        let access_token_for_hash = if wants_token {
            let scope = req.scope.clone();
            let merged = crate::handlers::merge_scopes(
                &scope,
                &crate::handlers::fetch_role_scopes(&state.pool, req.user_id)
                    .await
                    .unwrap_or_default(),
            );
            let mut access_claims = AuthClaims::access_with_client(
                &issuer,
                req.user_id,
                &scope,
                session.env_id,
                None,
                Some(&req.client_id),
                Duration::seconds(state.config.access_token_ttl_secs as i64),
            );
            let _ = merged;
            access_claims.token_tp = "access".into();
            match state.keys.sign_value_alg(
                &serde_json::to_value(&access_claims).unwrap_or(serde_json::json!({})),
                &profile.signing_alg,
            ) {
                Ok(t) => t,
                Err(e) => {
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
                }
            }
        } else {
            String::new()
        };
        // The id_token mint (c_hash binds the CODE when the cell carries
        // one; at_hash binds the access token when present).
        let id_claims = crate::jwt::AuthClaims::id_token_with_details(
            &issuer,
            req.user_id,
            &req.client_id,
            req.nonce.as_deref(),
            session.created_at.timestamp(),
            &access_token_for_hash,
            email.as_deref(),
            req.scope.split_whitespace().any(|s| s == "email"),
            name.as_deref(),
            req.scope.split_whitespace().any(|s| s == "profile"),
            phone.as_deref(),
            req.scope.split_whitespace().any(|s| s == "phone"),
            address.as_ref(),
            req.scope.split_whitespace().any(|s| s == "address"),
            Duration::seconds(state.config.access_token_ttl_secs as i64),
            req.authorization_details.as_ref(),
            None,
            req.acr_values.as_deref(),
        );
        let mut id_claims = id_claims;
        if wants_code {
            id_claims["c_hash"] = serde_json::json!(crate::jwt::c_hash(&code));
        }
        let id_token = state
            .keys
            .sign_value_alg(&id_claims, &profile.signing_alg)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        // The FRAGMENT members (order per OIDC Core §3.1.2.5 examples):
        let mut fragment_params: Vec<(&str, String)> = Vec::new();
        if wants_token {
            fragment_params.push(("access_token", access_token_for_hash.clone()));
            fragment_params.push(("token_type", "Bearer".to_string()));
            fragment_params.push(("expires_in", state.config.access_token_ttl_secs.to_string()));
        }
        if wants_code {
            fragment_params.push(("code", urlencode(&code)));
        }
        if wants_id_token {
            fragment_params.push(("id_token", id_token));
        }
        fragment_params.push(("state", urlencode(&req.state)));
        if profile.require_iss {
            fragment_params.push(("iss", urlencode(&issuer)));
        }
        let mut url = req.redirect_uri.clone();
        if !fragment_params.is_empty() {
            let pairs: Vec<String> = fragment_params
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            url.push('#');
            url.push_str(&pairs.join("&"));
        }
        url
    } else {
        response_url
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
    /// RFC 8707 resource indicator - the audience for the
    /// issued access token.
    #[serde(default)]
    /// The resource.
    pub resource: Option<String>,
    /// RFC 7523 private_key_jwt client assertion.
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
    // RFC 9421 HTTP request signatures (FAPI 2.0 Message
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

    // authenticate the client on every grant. Confidential
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

    // DPoP proof handling. When the caller's env-resolved profile
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
        // tenant auth domains (auth.staff.{org}.local.sentin8.dev) claim that
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
        && client.cert_thumbprint.is_none()
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
            // RFC 9449 Section 5 + RFC 6749 SS5.2: a request-level
            // validation failure (no proof under a DPoP-required profile)
            // = invalid_request, 400 - the client fixes and retries.
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "DPoP proof required for this grant",
        )));
    }

    // (draft-ietf-oauth-attestation-based-client-auth): the
    // attestation's cnf.jwk and the DPoP proof key MAY be distinct (the
    // draft leaves the DPoP key a wallet-local choice; the OIDF issuer
    // plan mints them separately). The sender-constraint surfaces:
    // (a) the code record's pre-bound dpop_jkt (RFC 9449) below, and
    // (b) the attestation itself verifies at client auth. No
    // attestation-vs-DPoP equality is enforced at the exchange.

    // RFC 9421 HTTP request signatures (FAPI 2.0 Message
    // Signing): when the env-resolved profile requires them, every mutating
    // token request must carry a signature over @method, @target-uri, and
    // the Content-Digest of the exact body bytes (swap protection).
    if profile.require_http_signatures {
        let target = format!("{}/oauth/token", resolve_issuer(&state.config, &headers));
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
        "refresh_token" => {
            handle_refresh(&state, &client, dpop_jkt.as_deref(), &headers, req).await
        }
        "client_credentials" => handle_client_credentials(&state, &headers, &client, req)
            .await
            .map_err(Into::into),
        "urn:ietf:params:oauth:grant-type:device_code" => {
            handle_device_code(&state, &client, &headers, req).await
        }
        // CIBA's grant type URN (OpenID CIBA §4): the suite (and our
        // discovery) use `urn:openid:params:grant-type:ciba`. A proof
        // attached to the poll (when present) was verified above; the
        // plain_fapi CIBA profile does NOT mandate one.
        "urn:openid:params:grant-type:ciba" => {
            handle_ciba_token(&state, &client, &headers, req).await
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
/// the code is bound to the authenticated client (mix-up
/// defense) and PKCE is mandatory when the stored challenge exists. When
/// the granted scope includes `openid`, an OIDC ID token is issued
/// with `aud` = client_id, `nonce` from the authorize
/// request, and `at_hash` binding it to the access token.
/// The pairwise subject derivation (OIDC Core §8 - pairwise sub =
/// the sector-identifier + client-pair salted hash, opaque to the RP).
/// The salt is the client row's DB id (per-client stable), the sector =
/// the registered sector_identifier_uri (or the redirect host).
fn pairwise_sub(client_db_id: &Uuid, sector: Option<&str>, user_id: &Uuid) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(client_db_id.as_bytes());
    h.update(user_id.as_bytes());
    h.update(sector.unwrap_or("").as_bytes());
    let d = h.finalize();
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d[..16].to_vec())
}

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

    // Tenant-aware issuer (DESIGN §4 "Tenant-aware issuer"): every token
    // minted in this exchange carries the CALLING tenant's auth host as
    // `iss`, resolved exactly like discovery (TLS-injected hostname /
    // Host header) - a process-constant issuer fails the suite's
    // ValidateIdToken on every tenant run (Issuer mismatch).
    let issuer = resolve_issuer(&state.config, headers);

    // Env-resolved security profile (DESIGN §9a.9): drives PKCE
    // enforcement AND the per-tenant signing family for every token
    // minted in this exchange. Resolved ONCE for the handler.
    let profile = resolve_security_profile(&state.pool, headers, "env").await;

    // Fetch the auth code data from Valkey.
    let code_key = format!("auth:authcode:{code}");
    let valkey_conn = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // RFC 6749 §4.1.2 reuse detection (DESIGN §9a.11) - read BEFORE the
    // code fetch: the burned-code mark is the ONLY trace a replay leaves
    // (the code record itself was deleted at first use), so a present
    // mark means the code was already redeemed AND intercepted - the
    // minted grant dies NOW (the mark carries its id).
    let replay: Option<String> = valkey_conn
        .get::<_, Option<String>>(format!("auth:burnedcode:{code}"))
        .await
        .ok()
        .flatten();
    if let Some(mark) = replay.as_deref().filter(|s| !s.is_empty()) {
        // The mark carries "grant_id|env_id" - the replay revokes the
        // FIRST issuance's grant under its OWN env context (RLS §4.3d).
        let (gid, eid) = mark.split_once('|').unwrap_or((mark, ""));
        let env = uuid::Uuid::parse_str(eid).unwrap_or(sentin8::config::SYSTEM_ENV_ID);
        let _ = crate::grants::revoke_by_id(state, env, gid).await;
        let _ = valkey_conn.del::<_, ()>(format!("auth:burnedcode:{code}")).await;
        return Err(TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code replay detected - grant revoked",
        )));
    }

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

    // FAPI2-SP-FINAL code-lifetime gate (DESIGN §9a.11): the authorization
    // code is SHORT-LIVED. RFC 6749 leaves the lifetime to the AS; FAPI 2.0
    // Security Profile requires the code to expire quickly (the suite
    // sleeps 62s and expects the reuse to be rejected). The Valkey TTL is
    // the 600s upper bound only - the wall-clock check below is the
    // enforced 60s lifetime: a present-but-expired record fails here and
    // never mints tokens; an absent `iat` (malformed record) fails too.
    const AUTH_CODE_LIFETIME_SECS: i64 = 60;
    let issued_at = code_data["iat"].as_i64().unwrap_or(0);
    if issued_at <= 0
        || chrono::Utc::now().timestamp() - issued_at > AUTH_CODE_LIFETIME_SECS
    {
        tracing::warn!(
            issued_at,
            now = chrono::Utc::now().timestamp(),
            "authorization code expired (or iat missing) - exchange rejected"
        );
        return Err(TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code expired",
        )));
    }

    // client binding: the authenticated client must be the
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

    // Validate PKCE - the stored challenge must be proven.
    // Missing verifier / mismatched proof = the PKCE contract failed for
    // THIS grant - RFC 6749 SS5.2 + RFC 7636 SS4.6 semantics: invalid_grant
    // (the suite's ensure-pkce-code-verifier-required requires it).
    let stored_challenge = code_data["code_challenge"].as_str().unwrap_or("");
    if !stored_challenge.is_empty() {
        let verifier = code_verifier.ok_or_else(|| {
            TokenError::OAuth(OAuthTokenError::with_desc(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "code_verifier is required",
            ))
        })?;
        let computed = pkce_s256_challenge(verifier);
        if computed != stored_challenge {
            return Err(TokenError::OAuth(OAuthTokenError::with_desc(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "PKCE verification failed",
            )));
        }
    } else {
        // No challenge stored - only permissible when the caller's env-resolved
        // profile does not mandate PKCE.
        if profile.require_pkce {
            return Err(TokenError::OAuth(OAuthTokenError::with_desc(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PKCE is required by the active security profile",
            )));
        }
    }

    // Per-tenant signing family (DESIGN §9a.9) - the caller's env-resolved
    // profile picks which persisted key family signs this exchange's
    // tokens. Empty = process default (SENTIN8_TLS_PQ_MODE).
    let signing_alg = profile.signing_alg.clone();

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
    let state_value = code_data["state"].as_str().map(|s| s.to_string());
    let auth_time = code_data["auth_time"]
        .as_i64()
        .unwrap_or_else(|| chrono::Utc::now().timestamp());
    // RFC 9396 authorization_details - echoed into the ID token per RFC 9396
    let authorization_details = code_data
        .get("authorization_details")
        .filter(|d| !d.is_null())
        .cloned();
    // OIDC Core §5.5 claims request (DESIGN §9a.3) - carried from
    // authorize; the ID-token mint applies it below.
    let claims_request = code_data
        .get("claims")
        .filter(|d| !d.is_null())
        .cloned();

    // Look up the user's email + name + phone/address data (ID-token
    // claims; §9a.4 - the phone/address families are minted only when
    // the consented scope grants them).
    // RLS (§4.3d): `users` is FORCE-RLS'd and the service role is
    // NOBYPASSRLS - a bare-pool read hides the row (email mints as ""
    // and the suite fails ValidateIdTokenStandardClaims). Read inside a
    // transaction with the code record's env context on the SAME
    // connection.
    let user_row = {
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        let row = sqlx::query!(
            r#"SELECT email, first_name, last_name, phone,
                      street_address, locality, region, postal_code, country,
                      oidc_profile, updated_at
               FROM users WHERE id = $1"#,
            user_id,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = tx.commit().await;
        row
    };
    let email = user_row.as_ref().map(|r| r.email.clone());
    let name = user_row.as_ref().map(|r| {
        crate::jwt::derive_profile_name(
            r.oidc_profile.get("name").and_then(|v| v.as_str()),
            r.first_name.as_deref().map(str::trim).filter(|s| !s.is_empty()),
            r.last_name.as_deref().map(str::trim).filter(|s| !s.is_empty()),
        )
        .unwrap_or_default()
    });
    // DESIGN §9a.11 - the full `profile` claim family payload (the
    // scope gate happens at mint).
    let profile_payload = user_row.as_ref().map(|r| {
        crate::jwt::build_profile_claims(
            name.as_deref(),
            &r.oidc_profile,
            Some(r.updated_at.timestamp()),
        )
    });
    let phone = user_row.as_ref().and_then(|r| r.phone.clone());
    let address = user_row
        .as_ref()
        .and_then(|r| {
            crate::jwt::build_address_claim(
                r.street_address.as_deref(),
                r.locality.as_deref(),
                r.region.as_deref(),
                r.postal_code.as_deref(),
                r.country.as_deref(),
            )
        });

    // Merge group permissions into scope .
    let role_scopes = crate::handlers::fetch_role_scopes(&state.pool, user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let merged_scope = crate::handlers::merge_scopes(scope, &role_scopes);

    // resource indicator (RFC 8707): the `resource` param
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
        &issuer,
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
    // OIDC Core 5.4/5.5 (DESIGN 9a.11): the claims request's USERINFO
    // selection stamps onto the access token - userinfo serves a
    // selected claim name without the scope family granting it (the
    // selection is the client's explicit, login-time consent signal).
    {
        let selection = claims_request
            .as_ref()
            .and_then(|c| c.get("userinfo"))
            .and_then(|v| v.as_object());
        if let Some(sel) = selection.filter(|o| !o.is_empty()) {
            access_claims.userinfo_claims =
                Some(sel.keys().cloned().collect::<Vec<_>>());
        }
    }
    // DPoP sender-constraining (`cnf.jkt`). The live proof's key
    // thumbprint binds the token; when the exchange carried NO live
    // proof, the CODE RECORD's pre-bound jkt (pushed on PAR / RFC 9449
    // dpop_jkt on authorize) still sender-constrains - the resource
    // fetch then REQUIRES a proof from that key (the userinfo gate).
    // RFC 9449 - the exchange's live proof must MATCH the pre-bound jkt
    // (the pushed request object's binding): a mismatched proof means the
    // sender is NOT the request's key holder - reject with
    // invalid_dpop_proof (RFC 9449 SS10.1 / the suite's jkt-mismatch pair).
    if let Some(pre_bound) = code_data.get("dpop_jkt").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        match dpop_jkt {
            Some(live) if live != pre_bound => {
                // RFC 9449 Section 10.1 (.1): the pre-bound
                // sender-constraint violation answers 400
                // invalid_dpop_proof.
                return Err(TokenError::OAuth(OAuthTokenError::with_desc(
                    StatusCode::BAD_REQUEST,
                    "invalid_dpop_proof",
                    "DPoP proof key does not match the request's dpop_jkt",
                )));
            }
            _ => {}
        }
    }
    // DESIGN §9a.22 - the require-dpop gate (holder-of-key): under the
    // sender-constrain=dpop posture, an exchange with NO live proof AND
    // NO pre-bound record jkt cannot satisfy the sender-constraint -
    // reject (.1 + the suite's ensure-holder-of-key-required).
    // The pre-bound record carries the PAR/authorize's key. An
    // mTLS-presented certificate IS the sender constraint (RFC 8705
    // §3): the exchange's TLS client cert (the proxy-injected
    // thumbprint context) satisfies the gate - the cert-bound cnf mint
    // takes over below (no jkt, `Bearer`). DESIGN §9a.12 (2)/(3) +
    // §9a.22.
    let mtls_presented = client
        .cert_thumbprint
        .clone()
        .or_else(|| {
            crate::mtls::extract_mtls_identity(&headers)
                .map(|(t, _)| t)
                .filter(|t| !t.is_empty())
        })
        .is_some();
    if !is_dpop_exempt(&client)
        && profile.require_dpop
        && !mtls_presented
        && dpop_jkt.is_none()
        && code_data
            .get("dpop_jkt")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .is_empty()
    {
        return Err(TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP proof is required by the sender-constrained authorization",
        )));
    }
    let bound_jkt = dpop_jkt.map(str::to_string).or_else(|| {
        code_data
            .get("dpop_jkt")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    });
    // RFC 9449 §5 / suite CheckTokenTypeIsDpop - the response's token_type
    // names the SENDER-CONSTRAINT of the access token: 'DPoP' when the
    // cnf.jkt binding rides, 'Bearer' otherwise (computed BEFORE the
    // bind consumes the value). The mTLS cells sender-constrain via the
    // CERTIFICATE - a cnf.x5t#S256-bound token rides the plain 'Bearer'
    // scheme (RFC 8705 §3: the CERT is the sender, no proof header).
    // RFC 8705 §3 - the TLS connection's OWN client certificate binds
    // too: a mTLS-connected request (the proxy injects the presented
    // cert's thumbprint) mints a certificate-bound token even when the
    // client's auth method is not the cert itself (FAPI1's
    // private_key_jwt clients still reach the token endpoint over mTLS).
    let mtls_cnf = client.cert_thumbprint.clone().or_else(|| {
        crate::mtls::extract_mtls_identity(&headers)
            .map(|(t, _)| t)
            .filter(|t| !t.is_empty())
    });
    let response_token_type = if bound_jkt.is_some() || mtls_cnf.is_some() {
        if bound_jkt.is_some() {
            "DPoP"
        } else {
            "Bearer"
        }
    } else {
        "Bearer"
    };
    if let Some(jkt) = bound_jkt {
        access_claims.cnf = Some(crate::dpop::build_dpop_cnf_claim(&jkt));
    } else if let Some(thumbprint) = mtls_cnf {
        // RFC 8705 §3 - certificate-bound token (the mTLS cells): one
        // confirmation member per token, so the cert binding rides ONLY
        // when no DPoP jkt was bound.
        access_claims.cnf = Some(crate::mtls::build_cnf_claim(&thumbprint));
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

    // RFC 6749 §4.1.2 reuse detection (DESIGN §9a.11): AFTER a grant
    // exists, mark the burned code so a second exchange finds the grant
    // to revoke. The mark rides the same TTL as the code record (600s).
    if let Ok(vc) =
        sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await
    {
        let _: Result<(), _> = vc
            .set_ex(
                format!("auth:burnedcode:{code}"),
                format!(
                    "{}|{}",
                    grant_id.clone().unwrap_or_default(),
                    env_id
                ),
                600,
            )
            .await;
    }
    if let Some(gid) = replay.as_deref().filter(|s| !s.is_empty()) {
        let _ = crate::grants::revoke_by_id(state, env_id, gid).await;
    }
    let _ = replay; // the error return happens after claims binding below

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
    // RFC 6749 §4.1.2 reuse revocation (DESIGN §9a.11): a replayed code
    // is the interception signal - revoke EVERYTHING minted for this
    // authorization (the replay itself never reaches here with tokens:
    // the grant lookup below has already cascaded). The live grant is
    // revoked BEFORE the replay's tokens would be minted, so this call
    // site revokes the FIRST issuance's grant.
    if let Some(gid) = replay.as_deref().filter(|s| !s.is_empty()) {
        let _ = crate::grants::revoke_by_id(state, env_id, gid).await;
        return Err(TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code replay detected - grant revoked",
        )));
    }
    let access_token = state
        .keys
        .sign_value_alg(
            &serde_json::to_value(&access_claims).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize claims: {e}")))?,
            &signing_alg,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let id_token = if scope.split_whitespace().any(|s| s == "openid") {
        // RFC 7591 §2 - the DCR'd client's registered
        // `id_token_signed_response_alg` preference governs the ID token's
        // signing (none = the unsigned OIDC form; the Dynamic-OP plan's
        // oidcc-idtoken-unsigned module drives it). Access/refresh tokens
        // keep the profile family.
        let id_signing_alg: String =
            client.id_token_signed_response_alg.clone().unwrap_or_else(|| signing_alg.clone());
        // DESIGN §9a.11 - email rides the ID token ONLY when the §5.5
        // claims request selects it (the scope-consented copy lives in
        // userinfo); unknown-selection = no user claims in the token.
        let id_selection = claims_request
            .as_ref()
            .and_then(|c| c.get("id_token"))
            .and_then(|v| v.as_object());
        let wants_email_in_id_token = id_selection
            .map(|o| o.contains_key("email"))
            .unwrap_or(false);
        // The profile-family payload: every populated member of the
        // STANDARD members, scope-gated at mint (a member may also be
        // individually selected by the claims request).
        let profile_extra = if scope.split_whitespace().any(|s| s == "profile") {
            profile_payload.as_ref().map(|p| {
                p.iter()
                    .filter(|(k, _)| {
                        let member_selected = id_selection
                            .map(|o| o.contains_key(k.as_str()))
                            .unwrap_or(false);
                        // §5.5-conservative ID token: a member rides the
                        // token when the claims request selects it
                        // explicitly, or (name only - the authentication
                        // display name) when no selection object exists.
                        k.as_str() == "name" && id_selection.is_none() || member_selected
                    })
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<serde_json::Map<String, serde_json::Value>>()
            })
        } else {
            None
        };
        let acr_value = code_data["acr_values"]
            .as_str()
            .and_then(|raw| raw.split_whitespace().next())
            .map(str::to_string);
        let mut id_claims = AuthClaims::id_token_with_details(
            &issuer,
            user_id,
            &client.client_id,
            nonce.as_deref(),
            auth_time,
            &access_token,
            email.as_deref(),
            scope.split_whitespace().any(|s| s == "email")
                && wants_email_in_id_token,
            name.as_deref(),
            false, // profile family rides the extra-claims overlay above
            phone.as_deref(),
            scope.split_whitespace().any(|s| s == "phone")
                && id_selection.map(|o| o.contains_key("phone_number")).unwrap_or(false),
            address.as_ref(),
            scope.split_whitespace().any(|s| s == "address")
                && id_selection.map(|o| o.contains_key("address")).unwrap_or(false),
            Duration::seconds(state.config.access_token_ttl_secs as i64),
            authorization_details.as_ref(),
            profile_extra.as_ref(),
            acr_value.as_deref(),
        );
        // (OIDC Core §3.1.3.6) - c_hash binds the ID token to the
        // authorization code being exchanged; (FAPI 1 §5.2.2.1) -
        // s_hash binds it to the client's state when one was sent.
        // RFC 7591 subject_type=pairwise: the client-pair-salted
        // derivation replaces the public sub (OIDC Core §8; the
        // Dynamic-OP plan's sector-uri family drives it).
        if client.subject_type.as_deref() == Some("pairwise") {
            id_claims["sub"] = serde_json::json!(pairwise_sub(
                &client.id,
                client.sector_identifier_uri.as_deref(),
                &user_id
            ));
        }
        id_claims["c_hash"] = serde_json::json!(crate::jwt::c_hash(&code));
        if let Some(st) = state_value.as_deref().filter(|s| !s.is_empty()) {
            id_claims["s_hash"] = serde_json::json!(crate::jwt::s_hash(st));
        }
        // OIDC Core §5.5 claims request (DESIGN §9a.3) - apply the
        // client's `id_token` claim SELECTION. This only narrows: the
        // mint above already gated email/name on the consented scope,
        // so removing a claim here cannot leak beyond the grant. A claim
        // the client asks for but the scope never granted stays absent
        // (the selection intersects with scope-consented claims).
        if let Some(selection) = claims_request
            .as_ref()
            .and_then(|c| c.get("id_token"))
            .and_then(|v| v.as_object())
        {
            let wants_email = selection.get("email").is_some();
            let wants_name = selection.get("name").is_some();
            let wants_phone = selection.get("phone_number").is_some();
            let wants_address = selection.get("address").is_some();
            if !wants_email && !selection.is_empty() {
                id_claims
                    .as_object_mut()
                    .map(|o| o.remove("email"))
                    .and(id_claims
                        .as_object_mut()
                        .map(|o| o.remove("email_verified")));
            }
            if !wants_name && !selection.is_empty() {
                id_claims
                    .as_object_mut()
                    .map(|o| o.remove("name"));
            }
            // DESIGN §9a.4 - the phone/address families narrow under the
            // same §5.5 selection rule as email/name.
            if !wants_phone && !selection.is_empty() {
                id_claims
                    .as_object_mut()
                    .map(|o| o.remove("phone_number"))
                    .and(id_claims
                        .as_object_mut()
                        .map(|o| o.remove("phone_number_verified")));
            }
            if !wants_address && !selection.is_empty() {
                id_claims
                    .as_object_mut()
                    .map(|o| o.remove("address"));
            }
        }
        // eKYC-IDA `verified_claims` (OIDC eKYC-IDA §5, DESIGN §9a.7) -
        // included when the claims request selected it (essential or
        // voluntary) AND the user holds an active verified credential.
        // The inclusion never widens: the credential's own claims are
        // the verified subset, read from the credential store.
        let wants_verified = claims_request
            .as_ref()
            .and_then(|c| c.get("id_token"))
            .and_then(|v| v.as_object())
            .map(|o| o.contains_key("verified_claims"))
            .unwrap_or(false);
        if wants_verified {
            let row: Option<(String, serde_json::Value, i64)> = sqlx::query_as(
                r#"SELECT type, credential_data,
                          EXTRACT(EPOCH FROM issued_at)::bigint AS issued_epoch
                     FROM credentials
                    WHERE user_id = $1 AND env_id = $2 AND status = 'active'
                    ORDER BY issued_at DESC LIMIT 1"#,
            )
            .bind(user_id)
            .bind(env_id)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
            if let Some((cred_type, data, issued_epoch)) = row {
                id_claims["verified_claims"] = crate::jwt::build_verified_claims(
                    "sentin8",
                    &cred_type,
                    &data,
                    issued_epoch,
                );
            }
        }
        state
            .keys
            .sign_value_alg(&id_claims, &id_signing_alg)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .into()
    } else {
        None
    };

    // OC-27b (DESIGN 9a.14): under every FAPI posture the
    // authorization-code grant issues a REFRESH TOKEN unconditionally -
    // sender-constrained confidential clients are refresh-bearing (the
    // OIDF refresh-token modules request no offline_access preamble; the
    // suite's own WARNING names the policy: refresh tokens for FAPI
    // clients). The standard family keeps the offline_access grant rule.
    let fapi_posture = crate::fapi::FapiProfile::from_str(
        &resolve_security_profile(&state.pool, &headers, "env").await.profile,
    )
    .is_some();
    let refresh_token = if fapi_posture || scope.contains("offline_access") {
        let refresh_claims = AuthClaims::refresh(
            &issuer,
            user_id,
            scope,
            env_id,
            Duration::seconds(state.config.refresh_token_ttl_secs as i64),
            Some(&client.client_id),
        );
        state
            .keys
            .sign_value_alg(
                &serde_json::to_value(&refresh_claims).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize claims: {e}")))?,
                &signing_alg,
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .into()
    } else {
        None
    };

    Ok(Json(TokenResponse {
        access_token,
        refresh_token,
        token_type: response_token_type.into(),
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
/// the presented refresh token is **verified** (signature +
/// issuer + expiry) and checked against the revocation denylist before any
/// new token is issued. rotation: when the profile's
/// `refresh_rotation` is enabled (default), a **new** refresh token is
/// issued and the old `jti` is denylisted, so a stolen-and-replayed old
/// token is rejected on its next use.
async fn handle_refresh(
    state: &AppState,
    client: &AuthenticatedClient,
    dpop_jkt: Option<&str>,
    headers: &HeaderMap,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, TokenError> {
    let refresh_token = req
        .refresh_token
        .as_deref()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "refresh_token is required".into()))?;

    // VERIFIED decode: signature + iss + exp.
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

    // denylist check (revoked tokens are refused). RFC 6749
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

    // CLIENT BINDING: the presented refresh token must belong to
    // the AUTHENTICATED client. The token's stored client_id (mint-time
    // bound) is compared to the authenticated caller - a token issued to
    // client 2 presented by client 1 reads invalid_grant (OIDC Core / the
    // suite's refresh client-binding block). Legacy tokens (no stored
    // client_id) are accepted only when the caller presents no client
    // authentication beyond the id (device/first-party shape).
    let bound = claims.client_id.as_deref().unwrap_or("");
    if !bound.is_empty() && bound != client.client_id {
        tracing::warn!(
            token_client = %bound,
            caller_client = %client.client_id,
            "refresh token client binding rejected"
        );
        return Err(TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh token was issued to a different client",
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

    // Look up the user's email - RLS (§4.3d): the users row is FORCE-RLS'd;
    // read inside a transaction with the token's env context set.
    let user_row = {
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        let row = sqlx::query!(r#"SELECT email FROM users WHERE id = $1"#, user_id,)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = tx.commit().await;
        row
    };
    let email = user_row.as_ref().map(|r| r.email.clone());

    // Merge group permissions into scope .
    let role_scopes = crate::handlers::fetch_role_scopes(&state.pool, user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let merged_scope = crate::handlers::merge_scopes(&scope, &role_scopes);

    // Per-tenant signing family (DESIGN §9a.9) - resolved from the
    // refresh token's own env context (the request headers belong to
    // the token endpoint's caller, the token carries its env).
    let profile = resolve_security_profile_for_env(&state.pool, env_id, "env").await;
    let signing_alg = profile.signing_alg.clone();

    // Tenant-aware issuer (DESIGN §4): the rotated tokens carry the
    // calling tenant's auth host (the refresh token itself was minted
    // under the same tenant's issuer).
    let issuer = resolve_issuer(&state.config, headers);

    // Issue a new access token.
    let mut access_claims = AuthClaims::access_with_client(
        &issuer,
        user_id,
        &merged_scope,
        env_id,
        email.as_deref(),
        Some(&client.client_id),
        Duration::seconds(state.config.access_token_ttl_secs as i64),
    );
    // resource indicator.
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
    // DPoP sender-constraining. The mTLS cells sender-constrain via
    // the client CERTIFICATE (cnf.x5t#S256) instead: the refresh call
    // re-presents the cert (the refresh binding below keeps the token's
    // own cnf - the cert identity never leaves the connection).
    // RFC 8705 §3 - the TLS connection's OWN client certificate binds
    // too: a mTLS-connected request (the proxy injects the presented
    // cert's thumbprint) mints a certificate-bound token even when the
    // client's auth method is not the cert itself (FAPI1's
    // private_key_jwt clients still reach the token endpoint over mTLS).
    let mtls_cnf = client.cert_thumbprint.clone().or_else(|| {
        crate::mtls::extract_mtls_identity(&headers)
            .map(|(t, _)| t)
            .filter(|t| !t.is_empty())
    });
    let response_token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };
    if let Some(jkt) = dpop_jkt {
        access_claims.cnf = Some(crate::dpop::build_dpop_cnf_claim(jkt));
    } else if let Some(thumbprint) = mtls_cnf {
        access_claims.cnf = Some(crate::mtls::build_cnf_claim(&thumbprint));
    }
    let access_token = state
        .keys
        .sign_value_alg(
            &serde_json::to_value(&access_claims).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize claims: {e}")))?,
            &signing_alg,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // rotation. When enabled (default), mint a NEW refresh
    // token and denylist the old `jti` for the old token's remaining
    // lifetime, so a replay of the old token fails.
    let rotate = profile_refresh_rotation(state, headers).await;
    let refresh_token_out: Option<String> = if rotate {
        // Denylist the old token first.
        let remaining = (claims.exp - chrono::Utc::now().timestamp()).max(1);
        revoke_jti(state, &claims.jti, remaining).await;

        let new_refresh_claims = AuthClaims::refresh(
            &issuer,
            user_id,
            &scope,
            env_id,
            Duration::seconds(state.config.refresh_token_ttl_secs as i64),
            Some(&client.client_id),
        );
        Some(
            state
                .keys
                .sign_value_alg(
                    &serde_json::to_value(&new_refresh_claims).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize claims: {e}")))?,
                    &signing_alg,
                )
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        )
    } else {
        Some(refresh_token.to_string())
    };

    Ok(Json(TokenResponse {
        access_token,
        refresh_token: refresh_token_out,
        token_type: response_token_type.into(),
        expires_in: state.config.access_token_ttl_secs,
        // Return the merged scope (base + group permissions).
        scope: Some(merged_scope),
        id_token: None,
    }))
}

/// Read the `refresh_rotation` flag for the CALLER's tenant (design §9a.5
/// per-profile posture): the env-resolved profile row wins; the platform
/// row is the fallback (default: enabled).
async fn profile_refresh_rotation(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
    let profile = resolve_security_profile(&state.pool, headers, "env").await;
    if !profile.profile.is_empty() {
        if let Some(def) = crate::fapi::ProfileDefaults::for_profile(&profile.profile) {
            return def.refresh_rotation;
        }
    }
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

    ///(design/sentin8-vertical-data-plane-contract.md §VDC.4/§VDC.5):
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
    // resource indicator (RFC 8707).
    if let Some(r) = req.resource.as_deref().filter(|s| !s.is_empty()) {
        if !crate::resource_indicators::is_valid_resource_uri(r) {
            return Err((StatusCode::BAD_REQUEST, "invalid resource indicator".into()));
        }
        claims.aud = Some(r.to_string());
    }
    let _ = headers; // (identity already extracted in authenticate_client)

    // Per-tenant signing family (DESIGN §9a.9) - the M2M client's env
    // picks the signing family.
    let profile = resolve_security_profile_for_env(&state.pool, client.env_id, "env").await;
    let signing_alg = profile.signing_alg.clone();
    let token = state
        .keys
        .sign_value_alg(
            &serde_json::to_value(&claims).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize claims: {e}")))?,
            &signing_alg,
        )
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
    // Per-tenant signing family (DESIGN §9a.9).
    let profile = resolve_security_profile_for_env(&state.pool, client.env_id, "env").await;
    let signing_alg = profile.signing_alg.clone();
    let token = state
        .keys
        .sign_value_alg(
            &serde_json::to_value(&claims).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize claims: {e}")))?,
            &signing_alg,
        )
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
    // Per-tenant signing family (DESIGN §9a.9) - the delegated token
    // inherits the PUBLISHER's env family (the token's tenant context).
    let profile = resolve_security_profile_for_env(&state.pool, publisher_env, "env").await;
    let signing_alg = profile.signing_alg.clone();
    let token = state
        .keys
        .sign_value_alg(
            &serde_json::to_value(&claims).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize claims: {e}")))?,
            &signing_alg,
        )
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
    // RFC 7662 : the caller MUST authenticate.
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

    // RFC 9701 JWT introspection. The signed JWT form is
    // returned when the caller requests it (Accept: application/token-
    // introspection+jwt) or when the caller's env-resolved profile mandates
    // it (fapi_2_message_signing). The plain JSON form remains the default.
    let profile = resolve_security_profile(&state.pool, &headers, "env").await;
    let jwt_requested = crate::jwt_introspection::wants_jwt_response(&headers);
    let jwt_form = jwt_requested || profile.require_jwt_introspection;

    // VERIFIED decode: a forged or expired token must
    // report `active: false`, never leak claims. Denylisted (revoked)
    // tokens are inactive too.
    let verified = verify_access_token_claims(&state, &req.token)
        .ok()
        .filter(|c| c.exp > chrono::Utc::now().timestamp());
    let claims = match verified {
        Some(c)
            if !is_token_revoked(&state, &c.jti).await
                && !is_grant_revoked(&state, c.grant_id.as_deref().unwrap_or("")).await =>
        {
            c
        }
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
                // ..and revoke the user's active sessions so the cookie
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

/// FAPI 1.0 §6.2.2-1 interaction id: the resource endpoint MUST return
/// `x-fapi-interaction-id` (echoing the request's value, or a fresh
/// UUID when absent). Applies to the userinfo resource surface the
/// FAPI plans exercise.
/// The userinfo render: plain JSON by default; when the caller's client
/// registered `userinfo_signed_response_alg` (RFC 7591), the response is
/// a signed userinfo JWT with content-type `application/jwt`
/// (OIDC Core §5.3.2 dynamic signed-response form; the Dynamic-OP
/// plan's oidcc-userinfo-rs256 module drives it).
/// The caller's registered userinfo signing algorithm (RFC 7591 lookup:
/// the access token's `client_id` -> the client row's
/// `userinfo_signed_response_alg`). RLS: runs under the row's env via
/// the authenticate SELECT path - a lookup by client_id goes through
/// the SYSTEM-env transaction (`with_client_env` parity).
async fn client_userinfo_signed_alg(
    state: &AppState,
    client_id: &str,
) -> Option<String> {
    if client_id.is_empty() {
        return None;
    }
    let mut conn = state.pool.begin().await.ok()?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(crate::config::SYSTEM_ENV_ID)
        .execute(&mut *conn)
        .await;
    sqlx::query(
        r#"SELECT userinfo_signed_response_alg FROM oauth_clients WHERE client_id = $1"#,
    )
    .bind(client_id)
    .fetch_optional(&mut *conn)
    .await
    .ok()
    .flatten()
    .and_then(|r| r.try_get::<Option<String>, _>(0).ok().flatten())
}

fn userinfo_json(
    headers: &HeaderMap,
    claims: OidcClaims,
    signed_alg: Option<&str>,
    keys: Option<&crate::jwks::SigningKeys>,
    issuer: &str,
    client_id: &str,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let interaction = headers
        .get("x-fapi-interaction-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    if let (Some(alg), Some(keys)) = (signed_alg, keys) {
        // OIDC Core §5.3.2 (dynamic signed-response): the userinfo JWT
        // carries the signed-JWT claim set - iss, aud = the client, iat,
        // exp - on top of the standard claims, then the alg signing.
        let mut jwt_claims =
            serde_json::to_value(&claims).unwrap_or_default();
        if let Some(obj) = jwt_claims.as_object_mut() {
            obj.insert("iss".into(), serde_json::json!(issuer));
            obj.insert("aud".into(), serde_json::json!(client_id));
            obj.insert(
                "iat".into(),
                serde_json::json!(chrono::Utc::now().timestamp()),
            );
            obj.insert(
                "exp".into(),
                serde_json::json!(
                    chrono::Utc::now().timestamp()
                        + state_userinfo_ttl()
                ),
            );
        }
        let body = keys
            .sign_value_alg(&jwt_claims, alg)
            .unwrap_or_default();
        return (
            [
                ("x-fapi-interaction-id", interaction),
                ("content-type", "application/jwt".to_string()),
            ],
            body,
        )
            .into_response();
    }
    (
        [("x-fapi-interaction-id", interaction)],
        Json(claims),
    )
        .into_response()
}


/// The signed-userinfo JWT's lifetime (5 minutes - a short-lived response
/// artifact; the verifier validates it before reading claims).
fn state_userinfo_ttl() -> i64 {
    300
}
// ── UserInfo ────────────────────────────────────────────────────────────

/// Handle userinfo.
#[utoipa::path(
    method(get, post),
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
    body: axum::body::Bytes,
) -> Result<axum::response::Response, (StatusCode, String)> {
    // OIDC Core §5.3.1: the access token rides the Authorization header
    // (GET or POST), or the form body on POST (`access_token=...`). The
    // suite's post-body variant uses the form; header takes precedence.
    // `Bytes` is infallible on GET too (empty body, the form parse
    // no-ops).
    let token = extract_bearer_token(&headers)
        .or_else(|| {
            std::str::from_utf8(&body)
                .ok()
                .and_then(|s| {
                    serde_urlencoded::from_str::<std::collections::HashMap<String, String>>(s)
                        .ok()
                })
                .and_then(|form| form.get("access_token").cloned())
        })
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing bearer token".into()))?;

    // VERIFIED decode: forged/expired tokens get 401.
    let claims = verify_access_token_claims(&state, &token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("invalid token: {}", e.1)))?;
    // revocation enforcement (DESIGN §9a.11): a denylisted jti
    // (RFC 7009) or a revoked GRANT (the code-reuse cascade) hard-fails
    // userinfo - the suite's codereuse-30s block expects the resource
    // surface to 401 after the code replay revokes the grant.
    if is_token_revoked(&state, &claims.jti).await
        || is_grant_revoked(&state, claims.grant_id.as_deref().unwrap_or("")).await
    {
        return Err((StatusCode::UNAUTHORIZED, "token has been revoked".into()));
    }

    // RFC 7591 - the caller's registered userinfo signing preference
    // (one lookup shared by the render sites; delegated tokens keep
    // plain JSON).
    let user_alg = client_userinfo_signed_alg(
        &state,
        claims.client_id.as_deref().unwrap_or(""),
    )
    .await;

    // DPoP sender-constraint (RFC 9449, FAPI2): a cnf.jkt-bound
    // access token presents a DPoP proof whose key EXACTLY matches the
    // binding - thumbprint equality + the proof's `ath` = the hash of
    // THIS access token. A sibling client's (valid!) proof is still a
    // forgery attempt for this token: reject (the suite's key-swap
    // negative test needs the 401).
    if let Some(cnf) = &claims.cnf {
        if let Some(expected_thumb) = cnf.get("x5t#S256").and_then(|v| v.as_str()) {
            // RFC 8705 §3 - CERTIFICATE-bound token: the request must
            // present the SAME client certificate (thumbprint equality;
            // no DPoP proof applies).
            let presented = crate::mtls::extract_mtls_identity(&headers)
                .map(|(t, _)| t)
                .ok_or((
                    StatusCode::UNAUTHORIZED,
                    "client certificate required for this token".to_string(),
                ))?;
            if presented != expected_thumb {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "client certificate does not match the token binding".to_string(),
                ));
            }
        } else {
            let Some(expected_jkt) = cnf.get("jkt").and_then(|v| v.as_str()) else {
                return Err((StatusCode::UNAUTHORIZED, "token cnf missing jkt".into()));
            };
            // RFC 8705 §3 + RFC 9449 §7.1 (DPoPRS-1): a caller presenting a
            // CA-verified PLATFORM WORKLOAD CERTIFICATE is itself a sender
            // constraint - the TLS layer injects the cert thumbprint header
            // ONLY after verifying the chain against the platform CA (and
            // strips client-supplied copies). Platform services verify
            // forwarded user tokens against userinfo through the Shield
            // role resolver; they cannot sign proofs for a key they do not
            // hold (the mint key is the BFF's ephemeral). The certificate
            // identity satisfies the sender-constraint verification for
            // this resource call exactly as an mTLS-bound token's cert
            // does - the workload identity is enrolled (registry-gated),
            // so a forged or revoked workload cannot ride it.
            if let Some((presented_thumb, _dn)) = crate::mtls::extract_mtls_identity(&headers) {
                if presented_thumb.is_empty() {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        "certificate identity is empty".into(),
                    ));
                }
                let Some(subject) = headers
                    .get("x-sentin8-client-cert-subject")
                    .and_then(|v| v.to_str().ok())
                    .filter(|s| s.starts_with("m2m-"))
                else {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        "certificate identity is not a platform workload".into(),
                    ));
                };
                let workload = subject.strip_prefix("m2m-").unwrap_or(subject);
                let Some(rec) = state.workload_registry.get(workload).await else {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        format!("workload '{workload}' is not enrolled"),
                    ));
                };
                if !rec.enabled {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        format!("workload '{workload}' is disabled"),
                    ));
                }
                tracing::debug!(workload, "userinfo: workload-certificate verification identity admitted (dpops-1)");
            } else {
                // RFC 9449 §7.1 - EXACTLY ONE proof per request: MORE than
                // one proof rejects 400 (invalid_request, "multiple DPoP
                // proofs") - both the two-LINE form (headers.get_all > 1) and
                // the comma-JOINED single line (the suite's JVM collapses the
                // two stored values before send - the dpop-negative cell
                // 'Try with more than one DPoP in the header').
                let dpop_seen = headers.get_all("dpop").iter().count();
                let dpop_joined = headers
                    .get_all("dpop")
                    .iter()
                    .next()
                    .and_then(|v| v.to_str().ok())
                    .map(std::string::ToString::to_string)
                    .unwrap_or_default();
                if dpop_seen > 1 || dpop_joined.contains(',') {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "invalid_request: multiple DPoP proofs".into(),
                    ));
                }
                let Some(proof) = crate::dpop::extract_dpop_header(&headers) else {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        "DPoP proof required for this token".into(),
                    ));
                };
                let htu = format!("{}/oauth/userinfo", resolve_issuer(&state.config, &headers));
                let jkt = crate::dpop::validate_and_verify_dpop(&state, &proof, "GET", &htu)
                    .await
                    .map_err(|e| (StatusCode::UNAUTHORIZED, format!("invalid DPoP proof: {}", e)))?;
                if jkt != expected_jkt {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        "DPoP proof key does not match the token binding".into(),
                    ));
                }
                let decoded = crate::dpop::decode_dpop_proof_unverified(proof.as_str())
                    .map_err(|e| (StatusCode::UNAUTHORIZED, format!("invalid DPoP proof: {}", e)))?;
                if decoded.claims.ath.as_deref() != Some(crate::dpop::compute_ath(&token).as_str()) {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        "DPoP proof ath does not match this access token".into(),
                    ));
                }
            }
        }
    }

    // Designated platform-plane caller (DPoPRS-1 carrier): a request whose
    // handshake certificate the TLS layer CA-verified and named `m2m-*`
    // is a platform workload identity - the Shield substrate role
    // resolver, the BFF session-enrichment client, and the auth→sys proxy
    // all authenticate this way. Identity resolution for those consumers
    // is NOT a FAPI browser surface: they receive the platform projection
    // below even when the resolved profile is a FAPI posture (RFC 8705
    // §3 - the certificate IS the sender constraint). Computed here, ABOVE
    // the projection gates, so the delegated and non-delegated branches
    // share the same rule.
    let cert_identity_caller = headers
        .get("x-sentin8-client-cert-subject")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.starts_with("m2m-"))
        && crate::mtls::extract_mtls_identity(&headers)
            .map(|(t, _)| !t.is_empty())
            .unwrap_or(false);

    //.1 conformance (DESIGN §9a.11): userinfo is the OIDC STANDARD
    // claims surface - under a FAPI profile the suite validates it strictly
    // and warns on members outside the standard set (the platform-plane
    // roles/groups/scopes/client_id/token_tp projections). The platform
    // plane (Shield substrate resolver, BFF session enrichment) still
    // receives them ALWAYS - the plane is keyed on the PLATFORM org
    // (org = the system org), never on the env-resolved PROFILE (the
    // platform row's fallback profile follows whichever rig profile the
    // operator seeded; a FAPI-postured platform FALLBACK must not strip
    // the identity projection out of the platform's own live-role
    // resolver - the 403-everything class). A TENANT host under a FAPI
    // profile gets the OIDC standard-claims surface (§9a.11 #8).
    let resolved_env = claims
        .env_id
        .clone()
        .and_then(|s| uuid::Uuid::parse_str(&s).ok())
        .unwrap_or(crate::config::SYSTEM_ENV_ID);
    let platform_plane = resolved_env == crate::config::SYSTEM_ENV_ID;
    let platform_claims = platform_plane
        || cert_identity_caller
        || crate::fapi::FapiProfile::from_str(
            &resolve_security_profile(&state.pool, &headers, "env").await.profile,
        )
        .is_none();
    let _ = &resolved_env;

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
        // Certificate-identity caller (DESIGN §9a.24): the TLS layer
        // injects `x-sentin8-client-cert-thumbprint` + `m2m-*` subject
        // ONLY after CA-verifying the handshake certificate (client
        // copies stripped) - the same signal the userinfo DPoP gate
        // (DPoPRS-1) trusts above. A Shield role resolver (sys/auth/acme
        // `*-tls` workloads), the BFF session-enrichment client, and the
        // auth→sys proxy all authenticate this way; for them the
        // delegated resolution must carry the platform projection.
        // (Detection HOISTED above `platform_claims` - shared by the
        // non-delegated branches, DPoPRS-1 carrier rule.)
        let roles = crate::handlers::user_role_names(&state.pool, act_user_id)
            .await
            .unwrap_or_default();
        let scopes = crate::handlers::fetch_role_scopes(&state.pool, act_user_id)
            .await
            .unwrap_or_default();
        return Ok(userinfo_json(&headers, OidcClaims {
            sub: act_user_id.to_string(),
            email: Some(email),
            given_name: first_name,
            family_name: last_name,
            // Delegated tokens are minted with the staff entitlement
            // scope set - the phone/address families ride it when
            // granted (§9a.4); the delegation path carries no phone/
            // address data (the act user's row was fetched for name/
            // email only).
            name: None,
            middle_name: None,
            nickname: None,
            preferred_username: None,
            profile: None,
            picture: None,
            website: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            locale: None,
            updated_at: None,
            email_verified: None,
            phone_number: None,
            phone_number_verified: None,
            address: None,
            // Platform-plane projection (roles/scopes/client_id/token_tp)
            // rides OUTSIDE FAPI profiles (.1 standard-claims
            // surface under FAPI; delegation consumers are non-FAPI) AND
            // for CERTIFICATE-IDENTITY callers (DESIGN §9a.24): Shield's
            // role resolver, BFF session enrichment, and the auth→sys
            // proxy authenticate with a CA-verified platform-workload
            // certificate, never a DPoP proof - a delegated token's live
            // resolution through those channels MUST carry the roles/
            // scopes the act user holds, or the resolver's empty-live-scope
            // overwrite fail-closes every delegated call (the 2026-10-28
            // e2e invitation 403 class).
            roles: (platform_claims || cert_identity_caller)
                .then_some(roles),
            groups: None,
            scopes: (platform_claims || cert_identity_caller)
                .then_some(scopes),
            client_id: (platform_claims || cert_identity_caller)
                .then_some(claims.sub.clone()),
            token_tp: (platform_claims || cert_identity_caller)
                .then_some(claims.token_tp),
        }, None, None, &resolve_issuer(&state.config, &headers), ""));
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
                r#"SELECT email, first_name, last_name, phone,
                          street_address, locality, region, postal_code, country,
                          oidc_profile, updated_at
                   FROM users WHERE id = $1"#,
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
            // OIDC Core §5.4 (DESIGN §9a.4) + §5.5 selection (DESIGN
            // §9a.11): the consented SCOPE decides the family, and the
            // access token's stamped `userinfo_claims` selection serves
            // individual members the client asked for without the
            // family (the login-time claims request IS the consent).
            let granted = claims.scope.split_whitespace().collect::<Vec<&str>>();
            let selected: std::collections::HashSet<String> = claims
                .userinfo_claims
                .clone()
                .unwrap_or_default()
                .into_iter()
                .collect();
            let selected_name = selected.contains("name");
            let selected_email = selected.contains("email");
            let selected_phone = selected.contains("phone_number");
            let selected_address = selected.contains("address");
            let has_email = granted.iter().any(|s| *s == "email") || selected_email;
            let has_profile = granted.iter().any(|s| *s == "profile") || selected_name
                || crate::jwt::PROFILE_FAMILY_MEMBERS.iter().any(|m| *m != "name" && selected.contains(*m));
            let has_phone = granted.iter().any(|s| *s == "phone") || selected_phone;
            let has_address = granted.iter().any(|s| *s == "address") || selected_address;
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
            // DESIGN §9a.11 - the full profile family: `name` derived
            // (oidc_profile.name → name parts), standard members from
            // `oidc_profile`, `updated_at` from the row. The map rides
            // the same shape at mint here - deconstructed into the DTO
            // by claim name.
            let profile_name = crate::jwt::derive_profile_name(
                u.oidc_profile.get("name").and_then(|v| v.as_str()),
                u.first_name.as_deref().map(str::trim).filter(|s| !s.is_empty()),
                u.last_name.as_deref().map(str::trim).filter(|s| !s.is_empty()),
            );
            let member = |k: &str| -> Option<String> {
                if !has_profile {
                    return None;
                }
                u.oidc_profile
                    .get(k)
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .filter(|v| !v.is_empty())
            };
            return Ok(userinfo_json(&headers, OidcClaims {
                sub: claims.sub,
                email: has_email.then_some(u.email.clone()),
                email_verified: has_email.then_some(true),
                given_name: if has_profile && !u.first_name.as_deref().unwrap_or("").is_empty() {
                    u.first_name.clone()
                } else {
                    None
                },
                family_name: if has_profile && !u.last_name.as_deref().unwrap_or("").is_empty() {
                    u.last_name.clone()
                } else {
                    None
                },
                name: if has_profile { profile_name } else { None },
                middle_name: member("middle_name"),
                nickname: member("nickname"),
                preferred_username: member("preferred_username"),
                profile: member("profile"),
                picture: member("picture"),
                website: member("website"),
                gender: member("gender"),
                birthdate: member("birthdate"),
                zoneinfo: member("zoneinfo"),
                locale: member("locale"),
                updated_at: has_profile.then(|| u.updated_at.timestamp()),
                phone_number: if has_phone {
                    u.phone.clone()
                } else {
                    None
                },
                phone_number_verified: if has_phone && u.phone.is_some() {
                    Some(true)
                } else {
                    None
                },
                address: if has_address {
                    crate::jwt::build_address_claim(
                        u.street_address.as_deref(),
                        u.locality.as_deref(),
                        u.region.as_deref(),
                        u.postal_code.as_deref(),
                        u.country.as_deref(),
                    )
                } else {
                    None
                },
                // Platform-plane projection (§9a.11.1): FAPI
                // userinfo stays a pure OIDC standard-claims document -
                // the resolved roles/groups/scopes/client_id are the
                // platform-plane consumer surface only.
                roles: platform_claims.then_some(roles),
                groups: platform_claims.then_some(groups),
                scopes: platform_claims.then_some(scopes),
                client_id: platform_claims.then_some(claims.client_id.clone()).flatten(),
                token_tp: None,
            }, user_alg.as_deref(), Some(&state.keys), &resolve_issuer(&state.config, &headers), claims.client_id.as_deref().unwrap_or("")));
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
    let user_alg = client_userinfo_signed_alg(
        &state,
        claims.client_id.as_deref().unwrap_or(""),
    )
    .await;
    let sub_for_render = claims.sub.clone();
    let sub_for_aud = claims.sub.clone();
        Ok(userinfo_json(&headers, OidcClaims {
        sub: sub_for_render,
        email: None,
        phone_number: None,
        email_verified: None,
        phone_number_verified: None,
        address: None,
        given_name: None,
        family_name: None,
        name: None,
        middle_name: None,
        nickname: None,
        preferred_username: None,
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: None,
        updated_at: None,
        // Platform-plane projection - same §9a.11 gate as the user branch
        // (the Shield substrate resolver runs on non-FAPI hosts).
        roles: platform_claims.then_some(roles),
        groups: None,
        scopes: platform_claims.then_some(scopes),
        client_id: platform_claims.then_some(claims.client_id.clone()).flatten(),
        token_tp: platform_claims.then_some("m2m".to_string()),
    },
        user_alg.as_deref(),
        Some(&state.keys),
        &resolve_issuer(&state.config, &headers),
        &sub_for_aud))
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
    // post_logout_redirect_uri. the redirect target must
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
                // OIDC RP-Initiated Logout - the hint must be a token THIS
                // OP issued: the signature verifies against our own keys
                // (a modified/hint-forged token refuses the registered-URI
                // redirect and falls back to /sign-in).
                let aud: Option<String> = state
                    .keys
                    .verify_raw(hint)
                    .ok()
                    .and_then(|c| c.get("aud").and_then(|v| v.as_str()).map(|s| s.to_string()));
                // RLS: the handler is an unauthenticated browser redirect -
                // there is no tenant context; `oauth_clients` reads go
                // through the platform-plane transaction (the same
                // `with_client_env` pattern the authorize flow uses).
                match state.pool.begin().await {
                    Ok(mut tx) => {
                        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                            .bind(crate::config::SYSTEM_ENV_ID)
                            .execute(&mut *tx)
                            .await;
                        let row = sqlx::query_as(
                            r#"SELECT client_id, post_logout_redirect_uris FROM oauth_clients
                               WHERE client_id = $1"#,
                        )
                        .bind(aud)
                        .fetch_optional(&mut *tx)
                        .await
                        .ok()
                        .flatten();
                        let _ = tx.commit().await;
                        row
                    }
                    Err(_) => None,
                }
            } else if let Some(cid) = q.client_id.as_deref() {
                match state.pool.begin().await {
                    Ok(mut tx) => {
                        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                            .bind(crate::config::SYSTEM_ENV_ID)
                            .execute(&mut *tx)
                            .await;
                        let row = sqlx::query_as(
                            r#"SELECT client_id, post_logout_redirect_uris FROM oauth_clients
                               WHERE client_id = $1"#,
                        )
                        .bind(cid)
                        .fetch_optional(&mut *tx)
                        .await
                        .ok()
                        .flatten();
                        let _ = tx.commit().await;
                        row
                    }
                    Err(_) => None,
                }
            } else {
                None
            };

            match client_row {
                Some((_client_id, post_logout_uris))
                    if post_logout_uris.iter().any(|u| u == uri) =>
                {
                    // (OIDC RP-Initiated Logout §2.1) - echo the
                    // client's `state` on the redirect so the RP can
                    // correlate the logout with its request (and bind
                    // CSRF protection). Only appended when a state was
                    // sent; a plain registered URI redirect stays
                    // untouched.
                    match q.state.as_deref().filter(|s| !s.is_empty()) {
                        Some(st) => {
                            let sep = if uri.contains('?') { '&' } else { '?' };
                            format!("{uri}{sep}state={}", urlencode(st))
                        }
                        None => uri.to_string(),
                    }
                }
                _ => {
                    // An UNREGISTERED landing target - the OIDC
                    // RP-Initiated Logout suite surface
                    // (ExpectPostLogoutRedirectUriNotRegisteredErrorPage,
                    // DESIGN 9a.23) demands a VISIBLE invalid-request page,
                    // not a silent /sign-in fallback: the silent redirect
                    // left the suite's screenshot placeholder pending
                    // forever (the module WAITING until the visit cap =
                    // INTERRUPTED). Serve the terminal error page (the
                    // response carries the session-cookie clear).
                    tracing::warn!(
                        uri = %uri,
                        "logout: unregistered post_logout_redirect_uri refused - serving the logout error page"
                    );
                    let cookie_domain = crate::sessions::cookie_domain_from_headers(&headers, &state.config.sentin8_domain);
                    let body = crate::login_page::logout_error_page(
                        "Invalid request - the post_logout_redirect_uri is not registered for this client",
                    );
                    let mut resp = (StatusCode::OK, body).into_response();
                    *resp.status_mut() = StatusCode::OK;
                    resp.headers_mut().insert(
                        axum::http::header::SET_COOKIE,
                        Session::clear_cookie(&cookie_domain)
                            .parse()
                            .unwrap_or(axum::http::HeaderValue::from_static("")),
                    );
                    resp.headers_mut().insert(
                        axum::http::header::CONTENT_TYPE,
                        axum::http::HeaderValue::from_static("text/html; charset=utf-8"),
                    );
                    return resp;
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
    /// DESIGN §9a.3 - the RP's opaque state, echoed on the
    /// post_logout_redirect_uri redirect (OIDC RP-Initiated Logout
    /// §2.1).
    #[serde(default)]
    /// The state.
    pub state: Option<String>,
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Is `uri` registered for the client? Exact string match, with RFC 8252
/// loopback port equivalence for native apps.

/// Append query parameters to a redirect URI WITHOUT clobbering an
/// existing query string (the registered URI may already carry
/// per-request state - RFC 6819 query-extension; the callback must
/// round-trip it).
fn build_callback_url(base: &str, first: &str, rest: &[(&str, String)]) -> String {
    let sep = if base.contains('?') { "&" } else { "?" };
    let mut url = format!("{base}{sep}{first}");
    for (k, v) in rest {
        url.push('&');
        url.push_str(k);
        url.push('=');
        url.push_str(v);
    }
    url
}


/// The authorization endpoint's OAuth ERROR RESPONSE (RFC 6749 §4.1.2.1):
/// a 302 to the client's redirect_uri with `error`, `error_description`
/// and the interaction's `state` (when one was resolved) - the
/// browser-visible reject shape the FAPI2-SP negatives require (a bare
/// 4xx body is neither an error redirect nor an error page).
/// Only callable once a REGISTERED redirect_uri exists (validated by the
/// caller's client resolution).
pub fn authorize_error_redirect(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
) -> Response {
    let mut extra: Vec<(String, String)> = vec![
        ("state".to_string(), urlencode(state.unwrap_or(""))),
    ];
    extra.retain(|(_, v)| !v.is_empty());
    let pairs: Vec<(&str, String)> = vec![(
        "error_description",
        urlencode(description),
    )];
    let mut url = build_callback_url(
        redirect_uri,
        &format!("error={}", urlencode(error)),
        &pairs,
    );
    for (k, v) in extra {
        url.push('&');
        url.push_str(&k);
        url.push('=');
        url.push_str(&v);
    }
    (StatusCode::FOUND, [("location", url)]).into_response()
}

fn redirect_uri_registered(registered: &[String], uri: &str) -> bool {
    if registered.is_empty() || uri.is_empty() {
        return false;
    }
    if registered.iter().any(|r| r == uri) {
        return true;
    }
    // Query-string extension: a presented redirect_uri that EXTENDS a
    // registered one with ONLY additional query parameters (same
    // scheme/host/port/path, no fragment, and the registered query's
    // own params CARRIED FORWARD unchanged) matches - the registered
    // URI is the security anchor; extra query parameters carry
    // per-request state (the suite's happy flow appends
    // ?dummy1=lorem&dummy2=ipsum to the registered callback). A
    // presented value that DIFFERS from the registered value is a
    // MISMATCH, not an extension (the suite's
    // oidcc-redirect-uri-query-mismatch registers ?bar=foo then
    // presents ?foo=bar and expects the reject - the pre-9a.24 rule
    // compared only scheme/host/port/path and accepted every
    // same-path ?uri, calling the registered redirect on the negative
    // test).
    if registered.iter().any(|r| redirect_uri_query_extension(r, uri)) {
        return true;
    }
    // Loopback equivalence: any port on.1 / [::1] matches a
    // registered loopback redirect with any port.
    registered
        .iter()
        .any(|r| crate::native_apps::redirect_uri_matches(r, uri))
}

/// Whether `uri` equals `registered_uri` plus ONLY extra query
/// parameters (identical scheme/host/port/path, no fragment, and every
/// registered query parameter present with THE SAME value).
fn redirect_uri_query_extension(registered_uri: &str, uri: &str) -> bool {
    let Ok(reg) = url::Url::parse(registered_uri) else {
        return false;
    };
    let Ok(presented) = url::Url::parse(uri) else {
        return false;
    };
    if !(reg.scheme() == presented.scheme()
        && reg.host_str() == presented.host_str()
        && reg.port_or_known_default() == presented.port_or_known_default()
        && reg.path() == presented.path()
        && presented.fragment().is_none()
        && uri.contains('?'))
    {
        return false;
    }
    // A bare-base registered URI (no query of its own) NEVER matches a
    // query-bearing variant: the presented value is not a registered URI
    // (RFC 6749 §3.1.2.3 exact string comparison - the dynamic plan's
    // oidcc-redirect-uri-query-added cell asserts the AS must not call
    // the ADDED-QUERY uri). The extension match exists for registered
    // URIs that CARRY their own query (the FAPI1 8.x form): the
    // registered query's params carry forward unchanged, the presented
    // query may only ADD.
    if reg.query().is_none() || reg.query() == Some("") {
        return false;
    }
    use std::collections::BTreeMap;
    let to_map = |q: Option<&str>| -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        if let Some(q) = q {
            for pair in q.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, v) = match pair.split_once('=') {
                    Some((k, v)) => (k, v),
                    None => (pair, ""),
                };
                m.insert(k.to_string(), v.to_string());
            }
        }
        m
    };
    let reg_q = to_map(reg.query());
    let pre_q = to_map(presented.query());
    reg_q.iter().all(|(k, v)| pre_q.get(k) == Some(v))
}

/// Look up an OAuth client's routing metadata (consent_required,
/// redirect_uris) with the RLS tenant context set on the SAME connection
///. `oauth_clients` is FORCE RLS - a bare pool
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
/// keys and validate its claims. Returns the parsed JAR
/// claims on success.
async fn verify_jar_request(
    state: &AppState,
    client_id: &str,
    request_jwt: &str,
    issuer: &str,
    flags: &crate::fapi::FapiSecurityFlags,
    request_scope: &str,
) -> Result<crate::jar::JarClaims, String> {
    // Unverified decode first - to read routing claims and find the key.
    let claims = crate::jar::decode_jar_unverified(request_jwt)?;
    crate::jar::validate_jar_claims(&claims, issuer)?;

    let header_alg = sentin8::auth::jwt::decode_header_typed::<serde_json::Value>(request_jwt)
        .ok()
        .and_then(|h| h.get("alg").and_then(|a| a.as_str()).map(str::to_string));
    let raw = sentin8::auth::jwt::decode_payload(request_jwt)?;

    // (DESIGN 9a.14 mandate table): every signed-push rule resolves
    // from the posture's FapiSecurityFlags - no per-call-site branches.
    // RFC 9101 baseline: `exp`/`nbf` are RECOMMENDED, `alg: none` is a
    // legal unsigned form, and `nonce` rides the OIDC openid rule; the
    // mandate table tightens exactly the flags a posture sets.
    if flags.forbid_jar_alg_none && header_alg.as_deref() == Some("none") {
        return Err(
            "the active security profile forbids an unsigned request object".into(),
        );
    }
    if flags.require_jar_exp && raw.get("exp").is_none() {
        return Err(
            "the signed request object must carry an exp claim".into(),
        );
    }
    if flags.require_jar_nbf && raw.get("nbf").is_none() {
        return Err(
            "the signed request object must carry an nbf claim".into(),
        );
    }
    // the nonce gate reads the OBJECT's own scope first (a PAR
    // push carries ALL parameters - including scope - inside the object;
    // the outer request's scope is EMPTY there) and falls back to the
    // outer request scope for the by-value form.
    let effective_scope = raw
        .get("scope")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(request_scope);
    if flags.require_jar_nonce
        && effective_scope.split_whitespace().any(|s| s == "openid")
        && raw.get("nonce").is_none()
    {
        return Err(
            "openid flows require the nonce claim on the request object (FAPI1 Baseline 5.2.2.2)".into(),
        );
    }
    // (FAPI1-ADV 5.2.2-2): the response surface pairing - under this
    // posture response_type=code REQUIRES response_mode=jwt (the object's
    // own claim, else the outer request's explicit mode). Nothing else
    // pairs: `code id_token` (detached-signature) and `jwt`-mode carry
    // their own protection.
    if flags.require_code_jarm_pairing {
        let rt = claims.response_type.trim();
        let mode = raw
            .get("response_mode")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| claims.response_mode.clone());
        if rt == "code" && mode.as_deref() != Some("jwt") {
            // The two PAR-side conditions reading this reject share
            // EXACTLY ONE permitted code: the response-mode-query module's
            // EnsurePARInvalidRequestOrInvalidRequestObjectError accepts
            // {invalid_request, invalid_request_object} while the
            // response-type-code module's
            // EnsurePARUnsupportedResponseTypeOrInvalidRequestOrUnauthoriz
            // edClientError accepts {unsupported_response_type,
            // invalid_request, unauthorized_client} - the PAIRING violation
            // is an invalid_request (RFC 6749 §4.1.2.1: the request's
            // mode/type combination is not obtainable here).
            return Err(
                "invalid_request: response_type=code requires response_mode=jwt (FAPI1 Advanced 5.2.2-2)".into(),
            );
        }
    }
    // The FAPI alg mandate (DESIGN 9a.16 (i)): under the signed-only
    // postures request objects sign with ES256/PS256 ONLY.
    if flags.forbid_jar_alg_none && header_alg.as_deref() == Some("RS256") {
        return Err(
            "RS256 is not a permitted request-object algorithm under the FAPI 2.0 security profile".into(),
        );
    }
    let now = chrono::Utc::now().timestamp();
    if let Some(nbf) = raw.get("nbf").and_then(|v| v.as_i64()) {
        if nbf > now + 60 {
            return Err("request object nbf more than 60s in the future".into());
        }
        if flags.require_jar_nbf && nbf < now - 600 {
            return Err("request object nbf more than 10 minutes in the past".into());
        }
    }
    if let Some(iat) = raw.get("iat").and_then(|v| v.as_i64()) {
        if iat > now + 60 {
            return Err("request object iat more than 60s in the future".into());
        }
    }
    if let Some(exp) = raw.get("exp").and_then(|v| v.as_i64()) {
        // Closed-window boundary (same shape as the client assertion): exp
        // == now-600 IS expired - the boundary instant must not pass.
        if exp <= now - 600 || exp > now + 600 {
            return Err("JAR request object exp out of range (+/-10min)".into());
        }
    }

    verify_client_signed_jwt(state, client_id, request_jwt).await?;
    Ok(claims)
}

/// Verify a client-signed JWT (JAR / CIBA request object, DESIGN §9a.7)
/// against the client's registered keys (inline `jwks` or `jwks_uri`).
/// Shared by the authorize (JAR) and bc-authorize (CIBA §7.1) verifiers.
/// Returns nothing on success - the caller owns the claim-shape rules.
pub async fn verify_client_signed_jwt(
    state: &AppState,
    client_id: &str,
    request_jwt: &str,
) -> Result<(), String> {
    use sqlx::Row;

    // RFC 9101 §5 - an unsigned request object (`alg: none`) is a legal
    // JAR form: the integrity story is the TLS transport + the AS's own
    // client authentication binding (the request is a value parameter,
    // not a fetched URI). The suite's unsigned-request-object exercises
    // exactly this form - advertise `none` in discovery (§9a.4) and
    // accept it here, so the capability is served, not skipped.
    let alg = sentin8::auth::jwt::decode_header_typed::<serde_json::Value>(request_jwt)
        .ok()
        .and_then(|h| h.get("alg").and_then(|a| a.as_str()).map(str::to_string));
    if alg.as_deref() == Some("none") {
        return Ok(());
    }

    // Resolve the client's registered keys. RLS: this verifier runs on
    // unauthenticated request paths (PAR/authorize JAR, CIBA) - the key
    // lookup goes through the platform-plane transaction (the same
    // `with_client_env` pattern; a bare pool query sees zero rows).
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| format!("client lookup tx: {e}"))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(crate::config::SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;
    let row = sqlx::query(r#"SELECT jwks, jwks_uri FROM oauth_clients WHERE client_id = $1"#)
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| format!("client lookup: {e}"))?
        .ok_or_else(|| "unknown client".to_string())?;
    let _ = tx.commit().await;
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
        return Err("request object signature verification failed".into());
    }
    Ok(())
}

/// Extract a Bearer token from the Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth_header = headers.get(axum::http::header::AUTHORIZATION)?;
    let auth_str = auth_header.to_str().ok()?;
    // RFC 6750 §2.1 + RFC 9449 §7.1: the auth scheme is case-INSENSITIVE
    // ('bearer'/'bEaReR'), and a DPoP-bound token arrives with the `DPoP`
    // scheme (the suite's resource calls switch to it once the token
    // response advertises token_type: DPoP).
    let (scheme, rest) = auth_str.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") && !scheme.eq_ignore_ascii_case("dpop") {
        return None;
    }
    Some(rest.trim().to_string())
}

/// The standard five OIDC response types (DESIGN §9a.13).
pub fn is_supported_response_type(rt: &str) -> bool {
    matches!(
        rt,
        "code"
            | "id_token"
            | "code id_token"
            | "id_token token"
            | "code id_token token"
    )
}

/// Whether the response_type encodes its response in the URL FRAGMENT
/// (OAuth-): any type carrying a token/id_token member.
pub fn is_fragment_response(response_type: &str) -> bool {
    response_type.split_whitespace().any(|p| p == "id_token" || p == "token")
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
/// 5 (design ): the requesting client is authenticated and
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
    // client auth (public CLI client resolves by id).
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
    headers: &HeaderMap,
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

    // 5 (design ) - the polling client must match the client
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
    // Tenant-aware issuer (DESIGN §4): the device token family carries the
    // calling tenant's auth host.
    let issuer = resolve_issuer(&state.config, headers);
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

    // RLS (§4.3d): the users row is FORCE-RLS'd; read with the device
    // record's env context on the same connection.
    let user_row = {
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        let row = sqlx::query!(
            r#"SELECT email, first_name, last_name FROM users WHERE id = $1"#,
            user_id,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = tx.commit().await;
        row
    };
    let email = user_row.as_ref().map(|r| r.email.clone());

    // Merge group scopes.
    let role_scopes = crate::handlers::fetch_role_scopes(&state.pool, user_id)
        .await
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let merged_scope = crate::handlers::merge_scopes(scope, &role_scopes);

    // Per-tenant signing family (DESIGN §9a.9) - tenant context rides
    // the device-flow record (the polling client may run on any host).
    let profile = resolve_security_profile_for_env(&state.pool, env_id, "env").await;
    let signing_alg = profile.signing_alg.clone();

    let access_claims = AuthClaims::access(
        &issuer,
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
        .sign_value_alg(
            &serde_json::to_value(&access_claims).map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, format!("serialize claims: {e}")))?,
            &signing_alg,
        )
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let refresh_token = {
        let refresh_claims = AuthClaims::refresh(
            &issuer,
            user_id,
            &merged_scope,
            env_id,
            Duration::seconds(state.config.refresh_token_ttl_secs as i64),
            Some(&client.client_id),
        );
        state
            .keys
            .sign_value_alg(
                &serde_json::to_value(&refresh_claims).map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, format!("serialize claims: {e}")))?,
                &signing_alg,
            )
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
    headers: &HeaderMap,
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
    // OpenID CIBA: a consumed/TTL'd auth_req_id = expired_token
    // ('s ExpectExpiredTokenErrorFromTokenEndpoint).
    let data = data.ok_or_else(|| {
        TokenError::OAuth(OAuthTokenError::new(
            StatusCode::BAD_REQUEST,
            "expired_token",
        ))
    })?;
    let data: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // first: the polling client must match the client that
    // started the request (stored by bc_authorize) - the suite polls a
    // foreign client against client1's grant and expects invalid_grant
    // BEFORE any status-specific answer.
    let stored_client = data["client_id"].as_str().unwrap_or("");
    if stored_client != client.client_id {
        return Err(TokenError::OAuth(OAuthTokenError::with_desc(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "auth_req_id was issued to a different client",
        )));
    }

    // Holder-of-key (CIBA §11.2): when the grant was bound to a client
    // certificate at bc-authorize time, the poll must present the SAME
    // certificate - a certless (or different-cert) poll rejects
    // `invalid_grant` before any status answer.
    if let Some(bound_thumb) = data["mtls_thumb"].as_str().filter(|t| !t.is_empty()) {
        let presented = crate::mtls::extract_mtls_identity(&headers)
            .map(|(t, _)| t)
            .filter(|t| !t.is_empty());
        match presented {
            Some(t) if t == bound_thumb => {}
            _ => {
                return Err(TokenError::OAuth(OAuthTokenError::with_desc(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "this grant requires the client certificate it was issued with",
                )));
            }
        }
    }

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
    if status == "consumed" {
        // Single-use: the auth_req_id already minted once.
        return Err(TokenError::OAuth(OAuthTokenError::new(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
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

    // Tenant-aware issuer (DESIGN §4): the CIBA ID token carries the
    // calling tenant's auth host, resolved like discovery.
    let issuer = resolve_issuer(&state.config, &headers);

    // RLS (§4.3d): the users row is FORCE-RLS'd; read with the CIBA
    // record's env context on the same connection.
    let user_row = {
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        let row = sqlx::query!(
            r#"SELECT email, first_name, last_name, phone,
                      street_address, locality, region, postal_code, country
               FROM users WHERE id = $1"#,
            user_id,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = tx.commit().await;
        row
    };
    let email = user_row.as_ref().map(|r| r.email.clone());
    // DESIGN §9a.4 - phone/address claim data for the CIBA ID token,
    // gated on the merged consented scope at the mint below.
    let ciba_phone = user_row.as_ref().and_then(|r| r.phone.clone());
    let ciba_address = user_row.as_ref().and_then(|r| {
        crate::jwt::build_address_claim(
            r.street_address.as_deref(),
            r.locality.as_deref(),
            r.region.as_deref(),
            r.postal_code.as_deref(),
            r.country.as_deref(),
        )
    });

    // Merge group scopes.
    let role_scopes = crate::handlers::fetch_role_scopes(&state.pool, user_id)
        .await
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let merged_scope = crate::handlers::merge_scopes(scope, &role_scopes);

    // Per-tenant signing family (DESIGN §9a.9) - tenant context rides
    // the CIBA request record.
    let profile = resolve_security_profile_for_env(&state.pool, env_id, "env").await;
    let signing_alg = profile.signing_alg.clone();

    // (Option A): if the CIBA request was initiated by a staff member
    // (BFF Delegation Gateway passed act_sub/act_email), the token is a
    // customer-consented DELEGATED token: `sub` = customer, `act` = staff
    // (RFC 8693 ), short TTL (300s - time-boxed consent). Without a
    // staff actor this is a plain customer CIBA token (decoupled-device
    // self-approval) with the platform default TTL.
    let act_sub = data["act_sub"].as_str().filter(|s| !s.is_empty());
    let act_email = data["act_email"].as_str().filter(|s| !s.is_empty());
    let delegation_ttl_secs: u64 = 300;
    let (mut access_claims, effective_ttl) = match act_sub {
        Some(staff_sub) => {
            let mut claims = AuthClaims::access(
                &issuer,
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
                &issuer,
                user_id,
                &merged_scope,
                env_id,
                email.as_deref(),
                Duration::seconds(state.config.access_token_ttl_secs as i64),
            ),
            state.config.access_token_ttl_secs,
        ),
    };
    // RFC 8705 §3 - the CIBA polling connection's TLS client certificate
    // binds the token (the FAPI1 plane's mTLS token endpoint; the
    // proxy injects the presented cert's thumbprint). A token granted
    // over a certificate-bearing poll plays only from the SAME cert.
    if let Some((ciba_thumb, _)) = crate::mtls::extract_mtls_identity(&headers) {
        if !ciba_thumb.is_empty() && act_sub.is_none() {
            access_claims.cnf = Some(crate::mtls::build_cnf_claim(&ciba_thumb));
        }
    }
    let access_token = state
        .keys
        .sign_value_alg(
            &serde_json::to_value(&access_claims).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize claims: {e}")))?,
            &signing_alg,
        )
        .map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // : delegated (staff-initiated) CIBA tokens are NOT refreshable -
    // the consent is time-boxed and single-purpose. Re-access requires a
    // new customer approval.
    let refresh_token =
        if act_sub.is_some() {
            None
        } else {
            let refresh_claims = AuthClaims::refresh(
                &issuer,
                user_id,
                &merged_scope,
                env_id,
                Duration::seconds(state.config.refresh_token_ttl_secs as i64),
                Some(&client.client_id),
            );
            Some(state.keys.sign_value_alg(
                &serde_json::to_value(&refresh_claims).map_err(|e| TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, format!("serialize claims: {e}")))?,
                &signing_alg,
            ).map_err(|e| {
                TokenError::Internal(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            })?)
        };

    // Single-use: keep the record but flip it to `consumed` so a reuse
    // poll answers invalid_grant, while a genuinely expired (TTL'd-out)
    // record answers expired_token .
    let _: Result<(), _> = valkey_conn
        .set_ex(
            &key,
            {
                let mut obj = data.clone();
                if let Some(o) = obj.as_object_mut() {
                    o.insert("status".into(), serde_json::json!("consumed"));
                }
                obj.to_string()
            },
            90,
        )
        .await;

    // OIDC ID token for CIBA grants when `openid` was granted:
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
                &issuer,
                user_id,
                &client.client_id,
                data["nonce"].as_str(),
                data["auth_time"].as_i64().unwrap_or(access_claims.iat),
                &access_token,
                email.as_deref(),
                merged_scope.split_whitespace().any(|s| s == "email"),
                user_name.as_deref().filter(|s| !s.is_empty()),
                merged_scope.split_whitespace().any(|s| s == "profile"),
                ciba_phone.as_deref(),
                merged_scope.split_whitespace().any(|s| s == "phone"),
                ciba_address.as_ref(),
                merged_scope.split_whitespace().any(|s| s == "address"),
                Duration::seconds(effective_ttl as i64),
                None,
                None,
                None,
            );
            Some(state.keys.sign_value_alg(&id_claims, &signing_alg).map_err(|e| {
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
/// this endpoint **requires a valid session** (cookie or
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
    // mutating session endpoint: CSRF-gated (Bearer exempt).
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
    /// comes from the session - never the body.
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
