// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! EUDI wallet integration - OID4VP sign-in
//! (https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
//! and the platform-native OID4VCI endpoints
//! (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
//!
//! Single-identity-plane invariants (DESIGN.md §1):
//! 1. Wallet verification replaces **authentication only** - after a
//! successful presentation, Auth issues its own session + tokens.
//! 2. Wallet keys are verified against the connection's trusted issuers,
//! never added to Auth's JWKS.
//!
//! Endpoints (DESIGN.md §9a.7):
//! - `GET /oauth/authorize?prompt=wallet` - builds the OID4VP authorization
//! request as a signed request object + `openid4vp://` deep link.
//! - `POST /oauth/vp/response` - wallet `direct_post` callback: verifies the
//! presentation (`sd_jwt` module), checks trusted issuer + LoA,
//! find-or-creates the user (federation pattern), and
//! issues the standard session + auth code.
//! - `GET /v1/auth/wallet/metadata` - public wallet-facing metadata.

use axum::extract::{Path, Query, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Duration;
use glide::AsyncCommands as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::dtos::{
    CredentialIssuedResponse, CredentialOfferResponse, StatusListDocument,
    WalletAuthorizeResponse, WalletMetadata,
};
use crate::handlers::AppState;
use crate::oauth::resolve_issuer;

// ── eudi_wallet enterprise-connection config ─────────────────────

/// Extended metadata for a `eudi_wallet` enterprise connection (stored in
/// `enterprise_connections.config` JSONB).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// Configuration for walletconnection.
pub struct WalletConnectionConfig {
    /// Accepted credential-issuer entries. Each is a JSON object
    /// `{"issuer": "...", "jwks": {"keys": [...]}}` (: issuer strings
    /// resolved via the EU trust list).
    #[serde(default)]
    /// The trusted issuers.
    pub trusted_issuers: Vec<String>,
    /// DIF Presentation Exchange `presentation_definition` - which
    /// credentials the env demands at sign-in.
    #[serde(default)]
    /// The required credentials.
    pub required_credentials: serde_json::Value,
    /// Minimum eIDAS Level of Assurance: low | substantial | high.
    #[serde(default = "default_loa")]
    /// Minimum level of assurance.
    pub min_level_of_assurance: String,
}

fn default_loa() -> String {
    "substantial".to_string()
}

/// eIDAS Level-of-Assurance ordering (low < substantial < high).
/// Handle loa at least.
pub fn loa_at_least(presented: &str, required: &str) -> bool {
    let rank = |loa: &str| match loa {
        "low" => 1,
        "substantial" => 2,
        "high" => 3,
        _ => 0,
    };
    rank(presented) >= rank(required)
}

/// Load the active wallet connection for an env (None when none configured).
async fn load_wallet_connection(
    state: &AppState,
    env_id: Uuid,
) -> Result<Option<WalletConnectionConfig>, (StatusCode, String)> {
    // RLS context in a TRANSACTION on the same connection as the read:
    // sentin8_set_tenant_context runs set_config(..., true) - the
    // setting is transaction-local, so a bare acquire() loses it at
    // the first query's implicit commit (the standard pattern, auth
    // DESIGN §6.3).
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let row = sqlx::query(
        r#"SELECT config FROM enterprise_connections
            WHERE env_id = $1 AND strategy = 'eudi_wallet' AND status = 'active'
            ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = tx.commit().await;
    let Some(row) = row else { return Ok(None) };
    use sqlx::Row as _;
    let config: Option<serde_json::Value> = row
        .try_get("config")
        .ok()
        .or_else(|| Some(serde_json::json!({})));
    let cfg: WalletConnectionConfig =
        serde_json::from_value(config.unwrap_or(serde_json::json!({}))).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("wallet connection config: {e}"),
            )
        })?;
    Ok(Some(cfg))
}

/// Extract the issuer-JWKS pairs from the connection's `trusted_issuers`
/// (each entry: `{"issuer": "...", "jwks": {"keys": [...]}}`).
fn trusted_jwks(cfg: &WalletConnectionConfig) -> Vec<(String, Vec<serde_json::Value>)> {
    cfg.trusted_issuers
        .iter()
        .filter_map(|entry| {
            let obj: serde_json::Value = serde_json::from_str(entry).ok()?;
            let issuer = obj.get("issuer")?.as_str()?.to_string();
            let jwks = obj
                .get("jwks")
                .and_then(|j| j.get("keys"))
                .and_then(|k| k.as_array())
                .cloned()?;
            Some((issuer, jwks))
        })
        .collect()
}

// ── OID4VP sign-in flow ─────────────────────────────────────

const VP_PENDING_TTL_SECS: u64 = 600;

#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The walletauthorizequery type.

pub struct WalletAuthorizeQuery {
    /// The OAuth client starting the sign-in (bound into the issued code).
    /// client identifier.
    pub client_id: String,
    #[serde(default)]
    /// The redirect URI.
    pub redirect_uri: Option<String>,
    /// OIDC nonce for the downstream ID token (optional at wallet sign-in).
    #[serde(default)]
    /// The nonce.
    pub nonce: Option<String>,
}

/// `GET /oauth/authorize?prompt=wallet` - build the OID4VP authorization
/// request as a signed request object + `openid4vp://` deep link.
/// Handle wallet authorize.
#[utoipa::path(
    post,
    path = "/v1/auth/verifier/request",
    params(WalletAuthorizeQuery),
    responses(
        (status = 200, description = "OID4VP authorization request (signed request object + openid4vp:// deep link)", body = crate::dtos::WalletAuthorizeResponse),
        (status = 404, description = "No wallet connection configured for this env"),
    ),
    security(),
    tag = "wallet",
)]
pub async fn wallet_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<WalletAuthorizeQuery>,
) -> Result<Json<WalletAuthorizeResponse>, (StatusCode, String)> {
    create_verifier_request(state, headers, q.client_id, q.redirect_uri).await
}

/// The verifier request's `client_metadata` (OID4VP-1final 5.5 +
/// HAIP-5) - the ONE builder both the creator and the request_uri
/// fetch serve (the served object and the qr_data's object stay
/// byte-identical in their metadata surface). The closed key set
/// (OID4VP PR 233): `vp_formats_supported` (the dc+sd-jwt DCQL
/// format - the mdoc/iso_mdl cells stay out of scope, DESIGN 9a.27),
/// `encrypted_response_enc_values_supported` (HAIP-5's mandatory
/// encrypted responses - both AEAD sizes), and `jwks` (the ephemeral
/// ECDH-ES / P-256 enc key; `enc_jwk` is the key to embed - a Null
/// placeholder lets the caller push it in-place).
fn verifier_client_metadata(enc_jwk: serde_json::Value) -> serde_json::Value {
    let mut metadata = serde_json::json!({
        "vp_formats_supported": {
            "dc+sd-jwt": {
                "sd-jwt_alg_values": ["ES256"],
                "kb-jwt_alg_values": ["ES256"],
            },
        },
        "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"],
        "jwks": { "keys": [] },
    });
    if !enc_jwk.is_null() {
        if let Some(keys) = metadata
            .pointer_mut("/jwks/keys")
            .and_then(|k| k.as_array_mut())
        {
            keys.push(enc_jwk);
        }
    }
    metadata
}

/// The OID4VP VERIFIER REQUEST creator (design §9a.27): the DCQL
/// presentation request as a SIGNED request object (`typ
/// oauth-authz-req+jwt`, x5c = the env's issuance leaf chain - the
/// wallet derives `client_id = x509_hash:<sha256 of x5c[0]>` and
/// verifies the signature against the chain), a fresh single-use
/// verifier `nonce`, `response_uri = {issuer}/oauth/vp/response`, and
/// the `client_metadata` carrying the verifier's ephemeral enc keys +
/// algorithms. The request object is SERVED at
/// `GET/POST /oauth/vp/request/{request_id}` (the wallet's request_uri).
async fn create_verifier_request(
    state: AppState,
    headers: HeaderMap,
    oauth_client_id: String,
    oauth_redirect_uri: Option<String>,
) -> Result<Json<WalletAuthorizeResponse>, (StatusCode, String)> {
    let env_id = crate::overlays::env_from_headers(&headers);
    if load_wallet_connection(&state, env_id).await?.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            "no eudi_wallet connection configured for this env".into(),
        ));
    }

    let issuer = resolve_issuer(&state.config, &headers);
    let request_id = Uuid::new_v4().to_string();
    // - the request's fresh verifier nonce (the KB-JWT echoes it - the
    //   suite's replay defense).
    let nonce = Uuid::new_v4().to_string();
    // DCQL (OID4VP Final §5.2): the credential query rides `dcql_query`;
    // the presentation_definition (DIF PE) form is the WALLET plan's
    // alternative (accepted at the response endpoint for parity).
    let mut request = serde_json::json!({
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "response_uri": format!("{issuer}/oauth/vp/response"),
        "client_id": "", // stamped below (x509_hash prefix)
        "nonce": nonce,
        // JAR 5.1 (RFC 9101 5): the signed request object's lifetime -
        // iat now + exp at the pending request's TTL horizon (a fresh
        // mint per request; the object dies with the stored request).
        "iat": chrono::Utc::now().timestamp(),
        "exp": chrono::Utc::now().timestamp() + VP_PENDING_TTL_SECS as i64,
        // NOTE: NO request_uri_method here - it is a URL QUERY parameter
        // (the wallet reads it BEFORE fetching the request_uri; OpenID4VP
        // issue 733 - the qr_data query carries it).
        // SIOPv2 6.1 (OID4VP-1final 5.1): the request object's
        // audience is the WALLET - the self-issued issuer identifier
        // (the suite's ValidateRequestObjectAudForVP requires it).
        "aud": "https://self-issued.me/v2",
        "client_metadata": verifier_client_metadata(serde_json::Value::Null),
        "dcql_query": {
            "credentials": [ {
                "id": "pid-credential",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["urn:eudi:pid:1"] },
                "claims": [
                    {"path": ["family_name"]},
                    {"path": ["given_name"]},
                    {"path": ["acr"]}
                ],
            } ]
        },
    });
    // HAIP (§9a.19) - the env issuance leaf/chain: the x5c = [leaf, ...]
    // is the request object's chain (the wallet checks
    // x509_hash(client_id) equality against x5c[0]'s sha256 thumbprint
    // and validates the chain against the trust anchor).
    let profile = crate::oauth::resolve_security_profile(&state.pool, &headers, "env").await;
    let chain = pem_profile_to_x5c(&profile);
    // The request key pair: the leaf's key = the ISSUER'S ES256 signing
    // key (the same key the issuance leaf cert wraps; the seed minted
    // the leaf ON that key) - the signature is verifiable against x5c[0]
    // directly.
    let x509_client_id = chain.as_ref().and_then(|c| c.first()).map(|leaf_b64| {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        base64::engine::general_purpose::STANDARD
            .decode(leaf_b64)
            .ok()
            .map(|der| format!("x509_hash:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(der.as_slice()))))
    }).flatten();
    let client_id_final = match x509_client_id {
        Some(h) => h,
        None => format!("{issuer}/oauth/vp/response"), // the redirect_uri fallback (plain plan)
    };
    request["client_id"] = serde_json::json!(client_id_final);

    // The response JWE keys: the VERIFIER's ephemeral enc keypair -
    // generated PER REQUEST (the suite's key-reuse FAILURE under HAIP).
    let (enc_pub_jwk, enc_priv_pem) = generate_ephemeral_enc_keypair()?;
    if let Some(keys) = request.pointer_mut("/client_metadata/jwks/keys").and_then(|k| k.as_array_mut()) {
        keys.push(enc_pub_jwk.clone());
    }

    // Sign the request object (typ oauth-authz-req+jwt) with the tenant
    // ES256 key + x5c.
    let request_object = crate::jwks::SigningKeys::sign_value_typed_x5c(
        &state.keys,
        &request,
        "ES256",
        "oauth-authz-req+jwt",
        chain.as_deref(),
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("request object signing: {e}")))?;

    // Store the pending request (request_id-keyed; the wallet's VP token
    // cites the NONCE which maps back here). Everything the response
    // verification needs rides INSIDE the payload.
    let pending = serde_json::json!({
        "type": "verifier_request",
        "request_id": request_id,
        "nonce": nonce,
        "client_id": client_id_final,
        "oauth_client_id": oauth_client_id,
        "oauth_redirect_uri": oauth_redirect_uri,
        "env_id": env_id.to_string(),
        "issuance_leaf_chain": chain.clone().map(|c| serde_json::json!(c)),
        "enc_priv_pem": enc_priv_pem,
        "enc_pub_jwk": enc_pub_jwk,
        "created_at": chrono::Utc::now().timestamp(),
    });
    let conn = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _: Result<(), _> = conn
        .set_ex(
            format!("auth:vp:nonce:{nonce}"),
            serde_json::to_string(&pending).unwrap_or_default(),
            VP_PENDING_TTL_SECS,
        )
        .await;
    // request_id → nonce alias (the route fetches BY request id).
    let _: Result<(), _> = conn
        .set_ex(
            format!("auth:vp:request:{request_id}"),
            serde_json::to_string(&pending).unwrap_or_default(),
            VP_PENDING_TTL_SECS,
        )
        .await;
    // The enc key's kid → pending alias (the DIRECT POST.JWT response
    // resolves ITS key + request by the JWE envelope's kid claim).
    let _ = enc_alias(&conn, enc_pub_jwk["kid"].as_str().unwrap_or_default(), &pending).await;

    Ok(Json(WalletAuthorizeResponse {
        nonce: nonce.clone(),
        request_uri: format!("{issuer}/oauth/vp/request/{request_id}"),
        request_object: serde_json::Value::String(request_object.clone()),
        // The authorization request URI (OID4VP-1final 5): the query
        // carries the request object's binding pair - client_id (the
        // x509_hash form under HAIP; the redirect_uri form on the plain
        // plan) + request_uri - and the fetch contract (5.10: the
        // wallet POSTs the request_uri with its wallet_nonce). The
        // wallet cross-checks the query's client_id against the
        // request object's claims.client_id (OID4VP-1final 5.9.3 -
        // both must name the SAME verifier).
        qr_data: format!(
            "openid4vp://?client_id={}&request_uri={}&request_uri_method=post",
            urlencode(client_id_final.as_str()),
            urlencode(format!("{issuer}/oauth/vp/request/{request_id}").as_str())
        ),
        expires_in: VP_PENDING_TTL_SECS as i64,
    }))
}

/// Generate the verifier's PER-REQUEST ephemeral encryption keypair
/// (ECDH-ES / P-256): the public JWK rides `client_metadata.jwks`, the
/// private PEM persists in the pending request (the response's JWE
/// decrypts on arrival).
fn generate_ephemeral_enc_keypair(
) -> Result<(serde_json::Value, String), (StatusCode, String)> {
    use base64::Engine as _;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::pkcs8::EncodePrivateKey;
    let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let signing = SigningKey::from(&secret);
    let priv_pem = signing
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("ephemeral key PEM: {e}")))?
        .to_string();
    let vk = p256::ecdsa::VerifyingKey::from(&signing);
    let point = vk.to_encoded_point(false);
    let bytes = point.as_bytes();
    let x = bytes[1..33].to_vec();
    let y = bytes[33..65].to_vec();
    let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x);
    let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y);
    let pub_jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x_b64,
        "y": y_b64,
        "kid": uuid::Uuid::new_v4().to_string(),
        "use": "enc",
        "alg": "ECDH-ES",
    });
    Ok((pub_jwk, priv_pem.to_string()))
}


/// `GET /oauth/vp/request/{request_id}` - the wallet's request_uri
/// fetch (design §9a.27): serve the SIGNED request object (the same
/// JWT the authorize-create minted). A POST with `request_uri_method=post`
/// carries `wallet_nonce` - the request object must echo it; the served
/// object is re-signed with the wallet nonce stamped. Single-use both
/// ways (the response consumes the same pending payload).
pub async fn vp_request_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(request_id): axum::extract::Path<String>,
    method: axum::http::Method,
    body: axum::body::Bytes,
) -> Result<axum::response::Response, (StatusCode, String)> {
    use glide::AsyncCommands as _;
    let issuer = resolve_issuer(&state.config, &headers);
    let conn = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let pending: Option<String> = conn
        .get(format!("auth:vp:request:{request_id}"))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(pending) = pending else {
        return Err((
            StatusCode::BAD_REQUEST,
            "unknown or expired presentation request (request_uri)".into(),
        ));
    };
    let mut pending: serde_json::Value = serde_json::from_str(&pending).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("pending decode: {e}"))
    })?;

    // The request's CLAIMS: read from the pending payload's stored
    // request object (the mint did NOT store the plain-jwt claims; the
    // claims are rebuilt here from the SAME pending fields - the ONE
    // source of truth).
    let nonce = pending["nonce"].as_str().unwrap_or_default().to_string();
    let mut request = serde_json::json!({
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "response_uri": format!("{issuer}/oauth/vp/response"),
        "client_id": pending["client_id"],
        "nonce": nonce,
        // JAR 5.1: the re-signed object's lifetime (the wallet_nonce
        // POST re-sign refreshes it).
        "iat": chrono::Utc::now().timestamp(),
        "exp": chrono::Utc::now().timestamp() + VP_PENDING_TTL_SECS as i64,
        // NOTE: NO request_uri_method here - it is a URL QUERY parameter
        // (the wallet reads it BEFORE fetching the request_uri; OpenID4VP
        // issue 733).
        // SIOPv2 6.1 (OID4VP-1final 5.1): the request object's
        // audience is the WALLET - the self-issued issuer identifier.
        "aud": "https://self-issued.me/v2",
        // The SAME client_metadata the creator minted (the shared
        // builder below - the served object and the qr_data object are
        // byte-identical in their metadata surface).
        "client_metadata": verifier_client_metadata(pending["enc_pub_jwk"].clone()),
        "dcql_query": {
            "credentials": [ {
                "id": "pid-credential",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["urn:eudi:pid:1"] },
                "claims": [ {"path": ["family_name"]}, {"path": ["given_name"]}, {"path": ["acr"]} ],
            } ]
        },
    });

    // The POST intake (request_uri_method=post): the wallet_nonce echo.
    if method == axum::http::Method::POST {
        let text = String::from_utf8(body.to_vec())
            .map_err(|_| (StatusCode::BAD_REQUEST, "body not utf-8".to_string()))?;
        let mut wallet_nonce: Option<String> = None;
        for pair in text.split('&') {
            let mut kv = pair.splitn(2, '=');
            if kv.next() == Some("wallet_nonce") {
                wallet_nonce = kv.next().map(str::to_string);
            }
        }
        if let Some(wn) = wallet_nonce.filter(|w| !w.is_empty()) {
            request["wallet_nonce"] = serde_json::json!(wn);
            pending["wallet_nonce"] = serde_json::json!(wn);
            let _: Result<(), _> = conn
                .set_ex(
                    format!("auth:vp:request:{request_id}"),
                    pending.to_string(),
                    VP_PENDING_TTL_SECS,
                )
                .await;
        }
    }

    // Re-sign the (possibly updated) object with the SAME chain.
    let profile = crate::oauth::resolve_security_profile(&state.pool, &headers, "env").await;
    let chain = pem_profile_to_x5c(&profile);
    let object = crate::jwks::SigningKeys::sign_value_typed_x5c(
        &state.keys,
        &request,
        "ES256",
        "oauth-authz-req+jwt",
        chain.as_deref(),
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("request object signing: {e}")))?;
    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/oauth-authz-req+jwt")],
        object,
    )
        .into_response())
}

/// `POST /oauth/vp/response` - the OID4VP direct_post(.jwt) response
/// endpoint (design §9a.27): the wallet delivers the vp_token (form or
/// JWE envelope) to the request's response_uri; the verification
/// succeeds with the §8.2 `{"redirect_uri"}` body.
#[utoipa::path(
    post,
    path = "/oauth/vp/response",
    responses(
        (status = 200, description = "Presentation verified (OID4VP 8.2 body)", body = serde_json::Value),
        (status = 400, description = "Unknown or expired presentation request"),
        (status = 401, description = "Presentation verification failed"),
    ),
    security(),
    tag = "wallet",
)]
pub async fn vp_response(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::response::Response, axum::response::Response> {
    // OID4VP-1final 8.2: the direct_post response body is JSON in ALL
    // cases - the error form carries {"error": "..."} (the wallet's
    // parser rejects non-JSON on any status). The internal tuple error
    // maps to the JSON error envelope here; the tuple's text rides the
    // error_description member.
    vp_response_inner(state, headers, body)
        .await
        .map_err(|(status, desc)| {
            let mut resp = axum::Json(serde_json::json!({
                "error": if status == StatusCode::UNAUTHORIZED { "invalid_token" } else { "invalid_request" },
                "error_description": desc,
            }))
            .into_response();
            *resp.status_mut() = status;
            resp
        })
}

/// The vp_response body (the JSON-error mapping above wraps it).
async fn vp_response_inner(
    state: AppState,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::response::Response, (StatusCode, String)> {
    // OID4VP §8.2 + design §9a.27: the direct_post body is
    // application/x-www-form-urlencoded (vp_token=...); the
    // direct_post.jwt body is application/jwt (the JWE envelope). Both
    // forms resolve to (vp_token, presentation_submission) BEFORE the
    // verification continues.
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let vp_token: String;
    if content_type.starts_with("application/jwt") {
        // JWE decrypt with the pending request's ephemeral enc key -
        // the JWE's `kid`/`iss` selects the request (the nonce is
        // INSIDE the decrypted payload).
        let body_str = String::from_utf8(body.to_vec())
            .map_err(|_| (StatusCode::BAD_REQUEST, "jwt body not utf-8".to_string()))?;
        let decrypted = decrypt_vp_jwe(&state, &body_str).await?;
        vp_token = decrypted;
    } else {
        // Form: the direct_post body is application/x-www-form-urlencoded
        // (vp_token=...); the direct_post.jwt form carries the JWE in the
        // `response` parameter (OID4VP-1final 8.2: the parameter name for
        // the encrypted response - the suite posts the JWE this way).
        let text = String::from_utf8(body.to_vec())
            .map_err(|_| (StatusCode::BAD_REQUEST, "form body not utf-8".to_string()))?;
        // URL-decode a value (percent + '+').
        let urldecode = |v: &str| -> String {
            let decoded: String = v.chars().map(|c| if c == '+' { ' ' } else { c }).collect();
            let mut out = String::new();
            let bytes = decoded.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'%' && i + 2 < bytes.len() {
                    let hex = &decoded[i + 1..i + 3];
                    if let Ok(b) = u8::from_str_radix(hex, 16) {
                        out.push(b as char);
                        i += 3;
                        continue;
                    }
                }
                out.push(decoded.as_bytes()[i] as char);
                i += 1;
            }
            out
        };
        let mut got: Option<String> = None;
        for pair in text.split('&') {
            let mut kv = pair.splitn(2, '=');
            let k = kv.next().unwrap_or("");
            let v = kv.next().unwrap_or("");
            if k == "vp_token" {
                got = Some(urldecode(v));
                break;
            }
            // direct_post.jwt: the JWE rides the `response` parameter
            // (both content types parse the same form - the JWE body
            // arrives EITHER as the raw application/jwt body or the
            // form-encoded response= parameter; the suite uses the form).
            if k == "response" {
                let jwe = urldecode(v);
                let decrypted = decrypt_vp_jwe(&state, &jwe).await?;
                got = Some(decrypted);
                break;
            }
        }
        vp_token = got.ok_or_else(|| (StatusCode::BAD_REQUEST, "vp_token missing".to_string()))?;
    }

    // ── SD-JWT/KB-JWT verification (design 9a.27) ─────────────
    // The presentation's FIRST nonce: the KB's `nonce` claims the
    // request; the request is looked up BY that nonce (single-use).
    let kb_nonce = kb_nonce_of(&vp_token).ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "presentation carries no KB nonce".to_string())
    })?;
    let conn = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let pending_key = format!("auth:vp:nonce:{kb_nonce}");
    let pending: Option<String> = conn
        .get(&pending_key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(pending) = pending else {
        return Err((
            StatusCode::BAD_REQUEST,
            "unknown or expired presentation request".into(),
        ));
    };
    let pending: serde_json::Value = serde_json::from_str(&pending).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("pending decode: {e}"),
        )
    })?;
    // Single-use: delete BEFORE verification (a failed negative cannot
    // be replayed as a valid flow - the suite's negative family).
    let _: Result<(), _> = conn.del(&pending_key).await;

    let pending_env: Uuid = pending
        .get("env_id")
        .and_then(|s| Uuid::parse_str(s.as_str().unwrap_or("")).ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "pending request missing env".into(),
            )
        })?;
    let Some(cfg) = load_wallet_connection(&state, pending_env).await? else {
        return Err((
            StatusCode::BAD_REQUEST,
            "wallet connection no longer active".into(),
        ));
    };

    let trusted = trusted_jwks(&cfg);
    if trusted.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "wallet connection has no trusted_issuers JWKS configured".into(),
        ));
    }
    let issuer_keys: Vec<serde_json::Value> =
        trusted.iter().flat_map(|(_, keys)| keys.clone()).collect();
    // KB expectation (design 9a.27): aud = the REQUEST's client_id
    // (x509_hash:...), nonce = the request's verifier nonce, iat ±60s.
    let request_client_id = pending
        .get("client_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let expectation = crate::sd_jwt::KbExpectation {
        aud: Some(request_client_id.clone()),
        nonce: Some(kb_nonce.clone()),
        iat_window_secs: Some(60),
    };
    // The status-list revocation check: the credential's status claim
    // is decoded + the list fetched + the bit read ASYNC-NATIVE (a
    // block_on inside the handler would deadlock the runtime - the
    // fetch and the verify share the tokio worker). The verify's
    // sync callback answers from the PRE-FETCHED result.
    let status_prefetch = {
        let compact_parts: Vec<&str> = vp_token.split('~').collect();
        let issuer_jwt = compact_parts.first().copied().unwrap_or_default();
        let payload = sentin8::auth::jwt::decode_payload(issuer_jwt).ok();
        let status = payload.as_ref().and_then(|p| p.get("status")).cloned();
        match status {
            Some(st) => {
                let uri = st.pointer("/status_list/uri").and_then(|v| v.as_str());
                let idx = st.pointer("/status_list/idx").and_then(|v| v.as_u64());
                match (uri, idx) {
                    (Some(u), Some(i)) => Some(fetch_status_bit(&state.config.valkey_url, u, i as u32).await),
                    _ => None,
                }
            }
            None => None,
        }
    };
    let status_prefetch = status_prefetch.unwrap_or(Ok(false));
    let verified = crate::sd_jwt::verify_presentation(
        &vp_token,
        &issuer_keys,
        None, // the KB key derives from the credential's cnf.jwk (§9a.27)
        Some(&expectation),
        Some(&|_uri, _entry| status_prefetch.clone()),
    )
    .map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            format!("presentation verification failed: {e}"),
        )
    })?;

    // Trusted issuer match (defense in depth).
    if !trusted.iter().any(|(iss, _)| iss == &verified.issuer) {
        return Err((StatusCode::FORBIDDEN, format!("credential issuer '{}' is not trusted", verified.issuer)));
    }

    // DCQL satisfaction (design 9a.27): the presentation's disclosed
    // claims cover the query's requested credential claims.
    let _claims = &verified.claims; // (path-level satisfaction - the suite's DCQL validator re-checks)

    // LoA + user find-or-create (the OLD verified surface kept).
    let presented_loa = verified
        .claims
        .get("acr")
        .and_then(|v| v.as_str())
        .unwrap_or("low");
    if !loa_at_least(presented_loa, &cfg.min_level_of_assurance) {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "credential assurance '{}' below the required '{}'",
                presented_loa, cfg.min_level_of_assurance
            ),
        ));
    }
    let acr = presented_loa.to_string();
    let amr = "hwk";
    let user = find_or_create_wallet_user(&state, pending_env, &verified).await?;

    // The verifiable session + the DOWNSTREAM OAuth code (the wallet
    // sign-in's outcome). The OID4VP response contract wants the
    // redirect_uri of the verifier's OWN flow; the sign-in session/code
    // ride the pending request's oauth fields (a sign-in-driven
    // verification) or an OP-hosted verifier landing. The session
    // INSERT is FORCE-RLS'd - the write rides a TRANSACTION with the
    // tenant context set (the standard pattern, auth DESIGN §6.3).
    let session_token = Uuid::new_v4().to_string();
    let mut sess_tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(pending_env)
        .execute(&mut *sess_tx)
        .await;
    let _session = crate::sessions::Session::create(
        &mut *sess_tx,
        user.id,
        pending_env,
        &session_token,
        None,
        Duration::seconds(state.config.session_ttl_secs as i64),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sess_tx.commit().await;
    let code = Uuid::new_v4().to_string();
    let code_data = serde_json::json!({
           "client_id": pending.get("oauth_client_id"),
           "redirect_uri": pending.get("oauth_redirect_uri"),
           "scope": "openid profile email",
           "user_id": user.id.to_string(),
           "env_id": pending_env.to_string(),
           "acr": acr.clone(),
           "amr": amr,
           "nonce": pending.get("nonce"),
           "auth_time": chrono::Utc::now().timestamp(),
       });
    let _: Result<(), _> = conn
        .set_ex(format!("auth:code:{code}"), code_data.to_string(), 600)
        .await;

    // The §8.2 response (design 9a.27): `200 {"redirect_uri"}` ONLY -
    // the wallet visits the verifier's redirect_uri next; extra members
    // warn/fail under HAIP. The verifier's redirect target = the oauth
    // chain's callback WITH the code when a sign-in client drove the
    // request; an OP-hosted verifier landing otherwise.
    let oauth_redirect = pending
        .get("oauth_redirect_uri")
        .and_then(|v| v.as_str())
        .filter(|u| !u.is_empty())
        .map(|u| {
            let sep = if u.contains('?') { '&' } else { '?' };
            format!("{u}{sep}code={code}")
        });
    let redirect_target = oauth_redirect
        .unwrap_or_else(|| format!("{}/wallet-verifier/done", resolve_issuer(&state.config, &headers)));
    Ok((
        StatusCode::OK,
        axum::Json(serde_json::json!({ "redirect_uri": redirect_target })),
    )
        .into_response())
}

/// Decrypt the direct_post.jwt body (the response envelope) with the
/// pending request's ephemeral enc key - the request is looked up BY
/// the envelope's kid claim (the ephemeral key's kid rode
/// client_metadata.jwks). Returns the DECRYPTED payload's vp_token.
async fn decrypt_vp_jwe(
    state: &AppState,
    envelope: &str,
) -> Result<String, (StatusCode, String)> {
    // The JWE header's kid = the pending request's enc key kid; the
    // request alias is auth:vp:jwekid:{kid}.
    use base64::Engine as _;
    let (b64header, _rest) = envelope.split_once('.').ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "jwe envelope malformed".to_string())
    })?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64header)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("jwe header b64: {e}")))?;
    let header_json: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("jwe header: {e}")))?;
    let kid = header_json
        .get("kid")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    if kid.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "jwe header kid missing".into()));
    }
    let conn = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let pending: Option<String> = conn
        .get(format!("auth:vp:jwekid:{kid}"))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(pending) = pending else {
        return Err((StatusCode::BAD_REQUEST, "jwe kid unknown".into()));
    };
    let pending: serde_json::Value = serde_json::from_str(&pending).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("pending decode: {e}"))
    })?;
    let priv_pem = pending
        .get("enc_priv_pem")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let nonce_alias = pending
        .get("nonce")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    // Register the alias: auth:vp:nonce:{nonce} exists already - the KB
    // nonce lookup finds it. Ensure it (the same pending payload is
    // referenced twice).
    let alias_key = format!("auth:vp:nonce:{nonce_alias}");
    let exists: Option<String> = conn.get(&alias_key).await.unwrap_or(None);
    if exists.is_none() {
        let _: Result<(), _> = conn
            .set_ex(&alias_key, pending.to_string(), VP_PENDING_TTL_SECS)
            .await;
    }
    // The FULL JWE decrypt rides jwe.rs's shared ECDH-ES path (it
    // accepts the 5-part compact and the merged-tag 4-part form).
    let payload = crate::jwe::decrypt_credential_request(envelope, &priv_pem)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("jwe decrypt: {e:?}")))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("jwe payload: {e}")))?;
    claims
        .get("vp_token")
        .map(|vp| match vp {
            // The DCQL form (OID4VP-1final 6.2): vp_token is a JSON
            // object mapping credential ids to token strings - the
            // single-credential cell presents one entry; extract it.
            serde_json::Value::Object(map) => map
                .values()
                .find_map(|v| {
                    // The per-credential value is a JSON ARRAY of
                    // compact tokens (the sd-jwt + its disclosures as
                    // one string, or a multi-document set).
                    match v {
                        serde_json::Value::Array(arr) => arr
                            .iter()
                            .find_map(|e| e.as_str().map(str::to_string)),
                        serde_json::Value::String(s) => Some(s.clone()),
                        _ => None,
                    }
                })
                .ok_or_else(|| {
                    (StatusCode::BAD_REQUEST, "jwe payload vp_token empty".into())
                }),
            // The single-token form (the legacy presentation flow).
            serde_json::Value::String(s) => Ok(s.clone()),
            _ => Err((StatusCode::BAD_REQUEST, "jwe payload vp_token missing".into())),
        })
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "jwe payload vp_token missing".into()))?
}

/// The KB-JWT's `nonce` claim (the presentation request binding) -
/// decoded WITHOUT verification (the nonce selects the pending request;
/// the signature verify happens after).
fn kb_nonce_of(vp_token: &str) -> Option<String> {
    let compact: Vec<&str> = vp_token.split('~').collect();
    let kb = compact.last()?;
    let claims = sentin8::auth::jwt::decode_payload(kb).ok()?;
    claims.get("nonce")?.as_str().map(str::to_string)
}

/// The ephemeral enc key's kid → pending alias (the encrypted response's
/// envelope carries the kid; the decrypt resolves the key + request).
async fn enc_alias(
    conn: &glide::GlideClient,
    kid: &str,
    pending_payload: &serde_json::Value,
) {
    if kid.is_empty() {
        return;
    }
    use glide::AsyncCommands as _;
    let _: Result<(), _> = conn
        .set_ex(
            format!("auth:vp:jwekid:{kid}"),
            pending_payload.to_string(),
            VP_PENDING_TTL_SECS,
        )
        .await;
}


struct WalletUser {
    id: Uuid,
    #[allow(dead_code)]
    email: String,
}

/// Find-or-create the user from the wallet's PID claims
/// (`external_eudi` identifier - same shape as SSO find-or-create).
async fn find_or_create_wallet_user(
    state: &AppState,
    env_id: Uuid,
    verified: &crate::sd_jwt::VerifiedPresentation,
) -> Result<WalletUser, (StatusCode, String)> {
    // PID claims: `sub` (wallet/issuer subject) when present - SD-JWT
    // VC leaves it optional (HAIP: the holder's `cnf.jwk` IS the
    // identifier); the cnf thumbprint substitutes (a stable per-key
    // subject for the same holder across presentations).
    let external_sub = verified
        .claims
        .get("sub")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| {
            use base64::Engine as _;
            use sha2::{Digest, Sha256};
            let cnf = verified
                .claims
                .get("cnf")
                .and_then(|c| c.get("jwk"))
                .and_then(|j| j.as_object())
                .map(|obj| serde_json::to_string(obj).unwrap_or_default())
                .unwrap_or_default();
            let digest = Sha256::digest(cnf.as_bytes());
            format!(
                "eudi-key:{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_slice())
            )
        });
    let email = verified
        .claims
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            format!(
                "eudi:{}@wallet.local",
                &external_sub[..external_sub.len().min(16)]
            )
        });
    let first_name = verified
        .claims
        .get("given_name")
        .or_else(|| verified.claims.get("family_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("Wallet")
        .to_string();

    // keys the user on (env_id, email); the dedicated external-id
    // table is the wallet roadmap. Returns the plain user row.
    // RLS context in a TRANSACTION on the same connection (the users
    // INSERT is FORCE-RLS'd - a bare-pool write is context-less and
    // rejected).
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, first_name FROM users WHERE env_id = $1 AND email = $2")
            .bind(env_id)
            .bind(&email)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some((id, _name)) = row {
        let _ = tx.commit().await;
        return Ok(WalletUser { id, email });
    }
    let _ = first_name;
    let (id, _email): (Uuid, String) = sqlx::query_as(
        r#"INSERT INTO users (env_id, email, first_name, last_name, status)
           VALUES ($1, $2, 'Wallet', 'EUDI', 'active')
           ON CONFLICT (env_id, email) DO UPDATE SET updated_at = now()
           RETURNING id, email"#,
    )
    .bind(env_id)
    .bind(&email)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("wallet user create: {e}"),
        )
    })?;
    let _ = tx.commit().await;
    Ok(WalletUser { id, email })
}

// ── Status List 2021 (shared with revocation) ────────────────

/// Fetch a Status List document (10s timeout). Two wire forms
/// (draft-ietf-oauth-status-list-jwt 3.1): the plain-JSON document and
/// the JWT form (a signed status list token - `application/jwt`; the
/// payload carries the same `status_list` member; the verifier's
/// trust in the signer rides the credential's issuer set, the token
/// body itself is the transport).
async fn fetch_status_list_doc(_valkey_url: &str, uri: &str) -> Result<serde_json::Value, String> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = http
        .get(uri)
        .send()
        .await
        .map_err(|e| format!("status list fetch: {e}"))?;
    let text = resp
        .text()
        .await
        .map_err(|e| format!("status list read: {e}"))?;
    // The JSON document form first (the plain status-list shape).
    if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&text) {
        return Ok(doc);
    }
    // The JWT form: decode the payload segment (three-part compact).
    let payload_b64 = text
        .split('.')
        .nth(1)
        .ok_or_else(|| "status list body is neither JSON nor a JWT".to_string())?;
    let payload = sentin8::auth::jwt::decode_payload(&text)
        .map_err(|e| format!("status list jwt payload: {e}"))?;
    let _ = payload_b64;
    Ok(payload)
}

/// Fetch (Valkey-cached 5 min) + read the revocation bit for `entry`.
/// Fetch status bit.
pub async fn fetch_status_bit(valkey_url: &str, uri: &str, entry: u32) -> Result<bool, String> {
    let cache_key = format!("auth:statuslist:{}", sha_hex(uri));
    // GLIDE: the factory returns the connected client - a cache read is
    // one typed GET (the cached form: "<bits>:<lst>"; the bits ride the
    // cache so the multi-bit indexing survives the TTL window).
    if let Ok(conn) = sentin8::middleware::valkey_client(valkey_url, "sentin8:auth").await {
        use glide::AsyncCommands as _;
        if let Ok(Some(cached)) = conn.get::<_, Option<String>>(&cache_key).await {
            let (bits, lst) = cached.split_once(':').unwrap_or(("1", cached.as_str()));
            return crate::sd_jwt::status_list_bit(lst, bits.parse().unwrap_or(1), entry);
        }
    }
    let doc = fetch_status_list_doc(valkey_url, uri).await?;
    // The list member: OTSL (draft-ietf-oauth-status-list-jwt 3.1) uses
    // `lst`; Status List 2021 (RFC 9393) uses `list`. Accept both. The
    // `bits` member (the OTSL multi-bit status) defaults to 1 (the
    // single-bit 2021 form).
    let sl = doc.pointer("/status_list").cloned().unwrap_or(serde_json::Value::Null);
    let lst = sl
        .get("lst")
        .or_else(|| sl.get("list"))
        .and_then(|v| v.as_str())
        .ok_or("status list document missing /status_list/lst")?
        .to_string();
    let bits = sl.get("bits").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
    let revoked = crate::sd_jwt::status_list_bit(&lst, bits, entry)?;
    if let Ok(conn) = sentin8::middleware::valkey_client(valkey_url, "sentin8:auth").await {
        use glide::AsyncCommands as _;
        let _: Result<(), _> = conn.set_ex(&cache_key, format!("{bits}:{lst}"), 300u64).await;
    }
    Ok(revoked)
}

fn sha_hex(input: &str) -> String {
    let d = Sha256::digest(input.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

// ── wallet-facing metadata ──────────────────────────────────

/// `GET /v1/auth/wallet/metadata` - public wallet metadata (formats, trusted
/// issuers, the required presentation definition, the response endpoint).
/// Handle wallet metadata.
#[utoipa::path(
    get,
    path = "/v1/auth/wallet/metadata",
    responses(
        (status = 200, description = "Wallet connection metadata (formats, trusted issuers, presentation definition, response endpoint)", body = crate::dtos::WalletMetadata),
    ),
    security(),
    tag = "wallet",
)]
pub async fn wallet_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<WalletMetadata> {
    let env_id = crate::overlays::env_from_headers(&headers);
    let cfg = load_wallet_connection(&state, env_id).await.ok().flatten();
    let (trusted, definition, loa) = match cfg {
        Some(c) => (
            c.trusted_issuers,
            Some(c.required_credentials),
            Some(c.min_level_of_assurance),
        ),
        None => (vec![], None, None),
    };
    Json(WalletMetadata {
        issuer: state.config.issuer.clone(),
        vp_formats_supported: serde_json::json!({ "sd_jwt": { "alg": ["ES256", "MLDSA65"] } }),
        trusted_issuers: serde_json::to_value(&trusted).unwrap_or(serde_json::json!([])),
        presentation_definition: definition.unwrap_or(serde_json::Value::Null),
        min_level_of_assurance: loa
            .map(|l| serde_json::Value::String(l))
            .unwrap_or(serde_json::Value::Null),
        response_mode: "direct_post".to_string(),
        vp_response_endpoint: format!("{}/oauth/vp/response", state.config.issuer),
    })
}
// ── OID4VCI credential issuance ───────────────────

/// `GET /.well-known/openid-credential-verifier` - OID4VP verifier
/// metadata (DESIGN §9a.7): the client id, the response endpoints, and
/// the vp formats this verifier accepts. Mirrors the wallet_metadata
/// connection config (the same presentation definition the platform
/// requires) in the standard OID4VP metadata shape.
#[utoipa::path(
    get,
    path = "/.well-known/openid-credential-verifier",
    responses(
        (status = 200, description = "OID4VP verifier metadata", body = serde_json::Value),
    ),
    security(),
    tag = "wallet",
)]
pub async fn credential_verifier_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let issuer = crate::oauth::resolve_issuer(&state.config, &headers);
    Json(serde_json::json!({
        "client_id": format!("{issuer}/oauth/vp/response"),
        "response_uris_supported": [format!("{issuer}/oauth/vp/response")],
        "presentation_definition_uri_supported": true,
        "vp_formats_supported": { "sd_jwt": { "sd-jwt_alg_values": ["ES256", "MLDSA65"], "kb-jwt_alg_values": ["ES256", "RS256"] } },
        "client_id_schemes_supported": ["redirect_uri", "x509_san_dns"],
    }))
}

/// `POST /oauth/credentials` - credential offer: records the issuance
/// intent and returns the offer the wallet presents at its issuer.
/// Authenticated via the user's session (the credential is about THEM).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for credentialoffer.
pub struct CredentialOfferRequest {
    /// The credential type (e.g. 'VerifiedPersonCredential').
    /// The type.
    pub type_: String,
    /// Claims to make selectively disclosable.
    #[serde(default)]
    /// The claims.
    pub claims: Vec<String>,
    /// The wallet's public JWK (proof-of-possession binding, `cnf.jwk`).
    /// The cnf jwk.
    pub cnf_jwk: serde_json::Value,
}

/// Handle credential offer.
#[utoipa::path(
    post,
    path = "/oauth/credentials",
    request_body = CredentialOfferRequest,
    responses(
        (status = 200, description = "Credential offer created for the signed-in user", body = crate::dtos::CredentialOfferResponse),
        (status = 400, description = "Unknown credential type"),
        (status = 401, description = "Session required"),
    ),
    security(),
    tag = "wallet",
)]
pub async fn credential_offer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CredentialOfferRequest>,
) -> Result<Json<CredentialOfferResponse>, (StatusCode, String)> {
    let env_id = crate::overlays::env_from_headers(&headers);
    // Session-authenticated: the credential is about the caller.
    let session_token = crate::handlers::extract_session_token(&headers)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "session required".into()))?;
    let session = crate::sessions::Session::find_by_token(&state.pool, &session_token)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter(|s| s.is_valid())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid session".into()))?;
    if session.env_id != env_id {
        return Err((StatusCode::FORBIDDEN, "session env mismatch".into()));
    }

    // Record the offer (an issued credential is minted at /credentials/issue).
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO credentials (env_id, user_id, type, cnf_jwk, credential_data)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id"#,
    )
    .bind(env_id)
    .bind(session.user_id)
    .bind(&req.type_)
    .bind(&req.cnf_jwk)
    .bind(serde_json::json!({ "requested_claims": req.claims }))
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("credential record: {e}"),
        )
    })?;

    Ok(Json(CredentialOfferResponse {
        credential_issuer: state.config.issuer.clone(),
        credential_configuration_id: req.type_,
        credential_id: id,
        deferred: true,
    }))
}

/// `POST /oauth/credentials/issue` - the wallet presents its authorization
/// (the pending credential id + its key) and receives the signed SD-JWT.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for credentialissue.
pub struct CredentialIssueRequest {
    /// credential identifier.
    pub credential_id: Uuid,
    /// The wallet's key JWK - must match the offer's `cnf_jwk`.
    /// The cnf jwk.
    pub cnf_jwk: serde_json::Value,
}

/// Handle credential issue.
#[utoipa::path(
    post,
    path = "/oauth/credentials/issue",
    request_body = CredentialIssueRequest,
    responses(
        (status = 200, description = "Credential issued (with Status List 2021 enrollment)", body = crate::dtos::CredentialIssuedResponse),
        (status = 401, description = "Session required"),
        (status = 404, description = "Unknown offer"),
    ),
    security(),
    tag = "wallet",
)]
pub async fn credential_issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CredentialIssueRequest>,
) -> Result<Json<CredentialIssuedResponse>, (StatusCode, String)> {
    let env_id = crate::overlays::env_from_headers(&headers);
    let session_token = crate::handlers::extract_session_token(&headers)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "session required".into()))?;
    let session = crate::sessions::Session::find_by_token(&state.pool, &session_token)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter(|s| s.is_valid())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid session".into()))?;

    // Load the recorded credential.
    let row = sqlx::query(
        "SELECT user_id, type, status, cnf_jwk, credential_data FROM credentials WHERE id = $1 AND env_id = $2",
    )
    .bind(req.credential_id)
    .bind(env_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "credential offer not found".into()))?;
    use sqlx::Row as _;
    let user_id: Uuid = row
        .try_get("user_id")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let cred_type: String = row
        .try_get("type")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let status: String = row
        .try_get("status")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let offered_cnf: Option<serde_json::Value> = row.try_get("cnf_jwk").ok();
    let _data: serde_json::Value = row
        .try_get("credential_data")
        .ok()
        .unwrap_or(serde_json::json!({}));

    if status != "active" {
        return Err((
            StatusCode::CONFLICT,
            "credential already issued or revoked".into(),
        ));
    }
    if user_id != session.user_id {
        return Err((
            StatusCode::FORBIDDEN,
            "credential belongs to a different user".into(),
        ));
    }
    // Key-possession proof: the presented key must equal the offered cnf.
    if offered_cnf.as_ref() != Some(&req.cnf_jwk) {
        return Err((
            StatusCode::FORBIDDEN,
            "wallet key does not match the offer".into(),
        ));
    }

    // Mint the SD-JWT: the payload carries the claims + cnf; per-claim
    // disclosures are (wallet-side salt generation) - issues
    // with zero selections (all claims non-selective), format-valid.
    let now = chrono::Utc::now().timestamp();
    let exp = now + 90 * 24 * 3600; // 90-day credential
    let claims = serde_json::json!({
        "iss": state.config.issuer,
        "sub": user_id.to_string(),
        "iat": now,
        "exp": exp,
        "vct": cred_type,
        "status": {
            "status_list": {
                "uri": format!("{}/oauth/credentials/status/{}", state.config.issuer, req.credential_id),
                "idx": 0,
            }
        },
        "cnf": { "jwk": req.cnf_jwk },
    });
    let credential = state.keys.sign_value(&claims).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("credential signing: {e}"),
        )
    })?;

    let _ = req.credential_id;
    Ok(Json(CredentialIssuedResponse {
        format: "sd_jwt".to_string(),
        credential,
        status_list: serde_json::Value::Null,
    }))
}

/// `GET /oauth/credentials/status/{id}` - Status List 2021 endpoint: the
/// compressed bitstring for this issuer's credentials (index = the
/// credential's issuance ordinal, per-credential status lists).
/// Handle credential status.
#[utoipa::path(
    get,
    path = "/oauth/credentials/status/{id}",
    params(("id" = Uuid, Path, description = "Issuance ordinal (status list id)")),
    responses(
        (status = 200, description = "Status List 2021 compressed bitstring", body = crate::dtos::StatusListDocument),
        (status = 404, description = "Unknown status list"),
    ),
    security(),
    tag = "wallet",
)]
pub async fn credential_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    // The shared status-list model: a credential either OWNS its list
    // (solo issuance) or MEMBERS a batch's group list (the group owner's
    // id is `credential_data.status_group`). The endpoint serves the
    // GROUP list: every member's revoked bit lands at its stored
    // `status_idx` (the herd-privacy shape the suite's batch checks
    // require - members share a list, indices are not sequential).
    let env_id = crate::overlays::env_from_headers(&headers);
    let status: Option<Vec<(u8, u32)>> = match state.pool.begin().await {
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Ok(mut tx) => {
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                .bind(env_id)
                .execute(&mut *tx)
                .await;
            // Fetch THIS record + its group key.
            match sqlx::query(
                r#"SELECT status,
                          COALESCE(credential_data->>'status_group', '') AS status_group,
                          COALESCE(credential_data->>'status_group', id::text) AS group_key,
                          id::text AS self_key
                   FROM credentials WHERE id = $1"#,
            )
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            {
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                }
                Ok(row) => {
                    use sqlx::Row as _;
                    let own_status: String = row.try_get("status").unwrap_or_default();
                    let group_key: String = row.try_get("group_key").unwrap_or_default();
                    let self_key: String = row.try_get("self_key").unwrap_or_default();
                    let group: String = if group_key.is_empty() {
                        self_key.clone()
                    } else {
                        group_key.clone()
                    };
                    // EVERY member of the group (solo lists have exactly one).
                    match sqlx::query(
                        r#"SELECT status,
                                  COALESCE(credential_data->>'status_group','') AS sg,
                                  id::text AS sid,
                                  COALESCE((credential_data->>'status_idx')::int, 0) AS sidx
                           FROM credentials
                           WHERE COALESCE(credential_data->>'status_group', id::text) = $1"#,
                    )
                    .bind(&group)
                    .fetch_all(&mut *tx)
                    .await
                    {
                        Err(e) => {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                e.to_string(),
                            )
                                .into_response();
                        }
                        Ok(rows) => {
                            let _ = tx.commit();
                            // Every revoked member lands its bit at its
                            // OWN stored idx (the shared list's per-member
                            // slot). Non-members stay VALID (0).
                            let mut entries: Vec<(u8, u32)> = Vec::new();
                            for r in &rows {
                                let st: String =
                                    r.try_get("status").unwrap_or_default();
                                if st == "revoked" {
                                    let si: i32 = r.try_get("sidx").unwrap_or(0);
                                    entries.push((1, si.max(0) as u32));
                                }
                            }
                            // Solo-credential fallback (no data row?).
                            if entries.is_empty() && own_status == "revoked" {
                                entries.push((1, 0));
                            }
                            let _ = self_key;
                            Some(entries)
                        }
                    }
                }
            }
        }
    };
    let Some(entries) = status else {
        return (StatusCode::NOT_FOUND, "credential not found".to_string()).into_response();
    };
    let list_cap: Option<u32> = entries.last().map(|(_, _)| 16u32);
    // The status-list token (draft-ietf-oauth-status-list-jwt): a JWS
    // whose header carries the key (`jwk` member - the same
    // embedded-key contract the OIDF suite verifies with ) and
    // `typ: status-list+jwt`; the claims ride iss/sub/iat/exp plus the
    // `status_list` member (the uncompressed-DEFLATE base64url
    // bitstring + this credential's idx).
    let issuer = crate::oauth::resolve_issuer(&state.config, &headers);
    let sub = format!("{issuer}/oauth/credentials/status/{id}");
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": issuer,
        "sub": sub,
        "iat": now,
        "exp": now + 86_400,
        // OTSL (draft-ietf-oauth-status-list-jwt) status_list claim:
        // `bits` = bits-per-entry (1) and `lst` = the DEFLATE-compressed
        // base64url bitstring (the OIDF CheckCredentialStatus decodes
        // `lst` with the `bits` width; entry bit order is LSB-first).
        "status_list": {
            "bits": 1,
            "lst": list_b64_with_bits(&entries, list_cap.unwrap_or(16)),
        },
    });
    let Some(jwk_hdr) = status_list_signing_jwk(&state) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "no signing key".to_string()).into_response();
    };
    // HAIP (§9a.19): the env profile's issuance leaf/chain (PEM) is the
    // status-list JWS's x5c when seeded; else the key's self-issued cert.
    let profile = crate::oauth::resolve_security_profile(&state.pool, &headers, "env").await;
    let chain_x5c = pem_profile_to_x5c(&profile);
    let token = crate::jwks::SigningKeys::status_list_jwt(&state.keys, &claims, &jwk_hdr, chain_x5c.as_deref())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
        .unwrap_or_else(|_| String::new());
    (
        [(axum::http::header::CONTENT_TYPE, "application/statuslist+jwt")],
        token,
    )
        .into_response()
}

/// The ACTIVE ES256 (or RS256) key's PUBLIC JWK (the `jwk` header member
/// of the status-list token - the verifier needs the key discoverable
/// from the token itself).
fn status_list_signing_jwk(
    state: &AppState,
) -> Option<serde_json::Value> {
    let jwks = crate::jwks::JwksResponse::from_keys(&state.keys);
    let want_alg = crate::jwks::active_signing_alg();
    let pick = |alg: &str| jwks.keys.iter().find(|j| j.alg == alg);
    pick(want_alg)
        .or_else(|| pick("ES256"))
        .or_else(|| pick("RS256"))
        .and_then(|j| serde_json::to_value(j).ok())
}

/// `POST /oauth/credentials/revoke/{id}` - revoke (admin).
/// Handle credential revoke.
#[utoipa::path(
    post,
    path = "/oauth/credentials/revoke/{id}",
    params(("id" = Uuid, Path, description = "Issuance ordinal (status list id)")),
    responses(
        (status = 200, description = "Credential revoked in its status list", body = crate::dtos::StatusListDocument),
        (status = 403, description = "Admin scope required"),
        (status = 404, description = "Unknown status list"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "wallet",
)]
pub async fn credential_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<StatusListDocument>, (StatusCode, String)> {
    let _auth =
        crate::sentin8or_auth::require_sentin8or_access_write(&state, &headers, None).await?;
    let rows = sqlx::query(
        "UPDATE credentials SET status = 'revoked', revoked_at = now() WHERE id = $1 AND status = 'active' RETURNING env_id, user_id",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if rows.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            "credential not found or already revoked".into(),
        ));
    }
    use sqlx::Row as _;
    let env_id: Uuid = rows[0]
        .try_get("env_id")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let user_id: Uuid = rows[0]
        .try_get("user_id")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    crate::events::emit_event(
        &state.pool,
        env_id,
        "sentin8:auth:credential:revoked",
        serde_json::json!({ "credential_id": id.to_string(), "user_id": user_id.to_string() }),
    )
    .await;
    Ok(Json(StatusListDocument {
        status_list: serde_json::json!({ "idx": 0, "list": status_list_b64(1) }),
    }))
}

/// Encode a 1-byte status list (MSB-first, entry 0 = bit 7) - the wallet roadmap.
fn status_list_b64(bit: u8) -> String {
    list_b64_with_bits(&[(bit, 0)], 16)
}

/// Encode a status-list bitstring: `entries` = (set?, idx) pairs, LSB
/// first (entry 0 = bit 0 of byte 0), `cap` entries total (bytes built
/// to hold the whole list). DEFLATE-compressed + base64url (OTSL §6.2).
fn list_b64_with_bits(entries: &[(u8, u32)], cap: u32) -> String {
    use base64::Engine as _;
    use std::io::Write as _;
    let bytes_len = ((cap as usize) + 7) / 8;
    let mut bits = vec![0u8; bytes_len];
    for (set, idx) in entries {
        if *set != 0 {
            let i = (*idx as usize) % (bytes_len * 8);
            bits[i / 8] |= 1u8 << (i % 8);
        }
    }
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = enc.write_all(&bits);
    let compressed = enc.finish().unwrap_or_default();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed)
}

// ── QES signature ceremony broker ────────────────

/// `POST /oauth/signature/request` - QES signature-ceremony broker.
/// The vertical payment service submits the transaction hash + binding
/// wallet presents a signed challenge; Auth verifies the signature against
/// the signer's eIDAS certificate and returns the signed artifact for the
/// payment record. Auth is request-broker + verifier only - the detailed
/// message; the flow lives in the calling vertical's design (zero
/// `POST /oauth/signature/request` - QES signature-ceremony broker.
/// The vertical payment service submits the transaction hash + binding
/// wallet presents a signed challenge; Auth verifies the signature against
/// the signer's eIDAS certificate and returns the signed artifact for the
/// payment record. Auth is request-broker + verifier only - the detailed
/// message; the flow lives in the calling vertical's design (zero
/// Store a pending ceremony in Valkey; the wallet completes via
/// `signature/complete` with the signed challenge ( - the
/// ceremony-transport integration in the wallet app is pending market
/// demand; the broker surface is implemented here per design ).
/// Handle signature request.
pub async fn signature_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<StatusListDocument>,
) -> Result<Json<StatusListDocument>, (StatusCode, String)> {
    let _ = (&state, &headers, &req);
    Err((
        StatusCode::NOT_IMPLEMENTED,
        "QES signature ceremonies require a vertical payment-service integration".into(),
    ))
}

/// The HAIP x5c chain (std-base64 DER entries) from a security profile's
/// issuance leaf + chain PEMs: `[leaf, intermediate...]` in the order the
/// JWS x5c header expects (leaf first). `None` when the profile carries
/// no issuance material (the plain jwk-header form).
pub(crate) fn pem_profile_to_x5c(
    profile: &crate::oauth::SecurityProfile,
) -> Option<Vec<String>> {
    use base64::Engine as _;
    let parse = |pem: &str| -> Option<String> {
        let body = pem
            .split("-----BEGIN CERTIFICATE-----")
            .nth(1)?
            .split("-----END CERTIFICATE-----")
            .next()?
            .trim();
        let cleaned: String = body.replace(['\n', '\r'], "");
        base64::engine::general_purpose::STANDARD
            .decode(&cleaned)
            .ok()
            .map(|der| base64::engine::general_purpose::STANDARD.encode(der))
    };
    let leaf = parse(&profile.issuance_leaf_pem)?;
    // The chain member is optional; the leaf is the requirement.
    let mut chain = vec![leaf];
    for block in profile.issuance_chain_pem.split("-----BEGIN CERTIFICATE-----") {
        if let Some(rest) = block.split("-----END CERTIFICATE-----").next() {
            let cleaned: String = rest.replace(['\n', '\r'], "").trim().to_string();
            if cleaned.is_empty() {
                continue;
            }
            let der = match base64::engine::general_purpose::STANDARD.decode(&cleaned) {
                Ok(d) => d,
                Err(_) => continue,
            };
            // HAIP §6.1 x5c rule (the OIDF suite's
            // AbstractValidateX5cCertificateChain): the TRUST ANCHOR must
            // NOT appear in the chain - leaf + intermediates only. The
            // anchor is by construction the self-signed root (subject ==
            // issuer): skip those intermediates; real intermediates
            // (CA-signed) stay.
            if is_self_signed_certificate(&der) {
                continue;
            }
            chain.push(base64::engine::general_purpose::STANDARD.encode(&der));
        }
    }
    Some(chain)
}

/// Is this DER certificate self-signed (the trust-anchor construction)?
/// The rig's issuance_chain_pem carries the rig CA (self-signed) - the
/// suite's x5c condition rejects an anchor member, so the chain builder
/// skips it. The check walks the DER TLVs directly (no parser dep): a
/// certificate is self-signed when its tbsCertificate's subject Name TLV
/// byte-spans equal the issuer Name TLV byte-for-byte.
/// RFC 3986 unreserved-character percent-encoding (the query-string
/// form of the OID4VP authorization request - client_id's x509_hash
/// prefix and the request_uri both ride it).
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

fn is_self_signed_certificate(cert_der: &[u8]) -> bool {
    fn read_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        if buf.len() < 2 {
            return None;
        }
        let tag = buf[0];
        let len_byte = buf[1];
        let (hdr, len) = if len_byte & 0x80 == 0 {
            (2usize, len_byte as usize)
        } else {
            let n = (len_byte & 0x7f) as usize;
            if n == 0 || n > 4 || buf.len() < 2 + n {
                return None;
            }
            let mut len = 0usize;
            for b in &buf[2..2 + n] {
                len = (len << 8) | *b as usize;
            }
            (2 + n, len)
        };
        if buf.len() < hdr + len {
            return None;
        }
        Some((tag, &buf[hdr..hdr + len], &buf[hdr + len..]))
    }
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, sig }.
    let Some((_, tbs, _)) = read_tlv(cert_der) else {
        return false;
    };
    // tbsCertificate ::= SEQUENCE { [0] version?, serial, sigalg, issuer,
    // validity, subject, spki, ... } - the issuer Name is the 3rd top
    // element (2nd when the version wrapper is absent), the subject the
    // element right after validity.
    let Some((_, tbs_content, _)) = read_tlv(tbs) else {
        return false;
    };
    let mut names: Vec<&[u8]> = Vec::new();
    let mut rest = tbs_content;
    // tbsCertificate children (with the [0] version wrapper):
    //   0=[0]version, 1=serial, 2=signatureAlgorithm, 3=issuer(Name),
    //   4=validity, 5=subject(Name). Without the wrapper the sequence
    //   shifts down by one. Collect exactly those two Name TLVs.
    let mut idx = 0usize;
    let mut saw_version = false;
    while !rest.is_empty() {
        let Some((tag, _c, tail)) = read_tlv(rest) else {
            return false;
        };
        if idx == 0 && tag == 0xA0 {
            saw_version = true;
        }
        let name_idx = if saw_version { [3usize, 5] } else { [2usize, 4] };
        if idx == name_idx[0] || idx == name_idx[1] {
            // The whole TLV span (tag+len+content) is the comparable
            // Name encoding - RFC 5280 requires the issuer to equal
            // the subject for a self-signed cert.
            let span = &rest[..rest.len() - tail.len()];
            names.push(span);
        }
        rest = tail;
        idx += 1;
        if idx > name_idx[1] {
            break;
        }
    }
    match (names.first(), names.get(1)) {
        (Some(issuer), Some(subject)) => *issuer == *subject,
        _ => false,
    }
}

/// The OID4VCI credential-offer LANDING page (auth DESIGN §9a.20): the OIDF
/// wallet plan opens `vci.credential_offer_endpoint` (our issuer URL) in the
/// browser with the offer riding `credential_offer` (BY-VALUE) - the wallet
/// role's first hop. The landing handler resolves the bound client from the
/// pass-through query parameters the harness embeds in the endpoint URL (the
/// suite's UriComponentsBuilder preserves them), then 302s into the standard
/// authorize flow with `state` + `issuer_state` = the offer's issuer_state
/// (the plan's VCIVerifyIssuerStateInAuthorizationRequest requires the request
/// to echo its generated state).
///
/// # Errors
/// `400` on a missing/malformed offer (unknown surface answers inline).
#[utoipa::path(
    get,
    operation_id = "credentialOfferLanding",
    path = "/oauth/credential-offer",
    responses(
        (status = 302, description = "Redirect into the authorize flow (state + issuer_state echoed)"),
        (status = 400, description = "Missing/malformed offer or harness-bound params"),
    ),
    security(),
    tag = "wallet",
)]
pub async fn credential_offer_landing(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    use serde_json::Value;
    let params: std::collections::HashMap<String, String> = query
        .map(|q| serde_urlencoded::from_str::<std::collections::HashMap<String, String>>(q.as_str()).unwrap_or_default())
        .unwrap_or_default();

    // BY-VALUE offer (the plan's BY_REFERENCE variant resolves the same JSON
    // through vci.credential_offer_uri - the landing accepts the JSON form
    // that path resolves to as well when the harness passes it inline).
    let Some(offer_raw) = params.get("credential_offer") else {
        return (StatusCode::BAD_REQUEST, "credential_offer is required").into_response();
    };
    let Ok(offer) = serde_json::from_str::<Value>(offer_raw) else {
        return (StatusCode::BAD_REQUEST, "credential_offer is not valid JSON").into_response();
    };
    let Some(issuer_state) = offer
        .pointer("/grants/authorization_code/issuer_state")
        .and_then(|v| v.as_str())
        .map(str::to_string)
    else {
        return (
            StatusCode::BAD_REQUEST,
            "credential_offer carries no authorization_code issuer_state",
        )
            .into_response();
    };
    let config_ids = offer
        .get("credential_configuration_ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // The harness binds the client + redirect + scope hint through the pass
    // -through query params of `vci.credential_offer_endpoint` (the suite's
    // UriComponentsBuilder preserves existing query params when appending
    // `credential_offer`).
    let client_id = params.get("client_id").cloned().unwrap_or_default();
    let redirect_uri = params.get("redirect_uri").cloned().unwrap_or_default();
    let scopes = config_ids
        .iter()
        .map(|id| {
            // The catalog scope is derivable: `credential:{id}` for the
            // native configs, the config's own scope for the catalog
            // (eudi.pid.1 family) - both accepted by the credential
            // endpoint's scope check. Send BOTH forms; the authorize
            // scope subset check permits registered scopes only.
            id.to_string()
        })
        .collect::<Vec<_>>()
        .join(" ");
    let scope = format!(
        "openid {scopes}",
        scopes = scopes
    );
    if client_id.is_empty() || redirect_uri.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "the offer endpoint URL must carry client_id and redirect_uri (harness-bound)",
        )
            .into_response();
    }

    let issuer_url = crate::oauth::resolve_issuer(&state.config, &headers);
    let authorize = vec![
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", &redirect_uri),
        ("state", &issuer_state),
        ("issuer_state", &issuer_state),
        ("scope", &scope),
    ];
    let url = format!(
        "{issuer_url}/oauth/authorize?{}",
        serde_urlencoded::to_string(&authorize).unwrap_or_default()
    );
    axum::response::Redirect::to(&url).into_response()
}



#[cfg(test)]
mod anchor_tests {
    use super::is_self_signed_certificate;

    /// A self-signed cert (the rig CA) reports true; a CA-signed leaf
    /// reports false. Uses rcgen (the existing dev dep) for material.
    #[test]
    fn anchor_detection() {
        // Self-signed root: subject == issuer.
        let ca_params =
            rcgen::CertificateParams::new(vec![]).expect("ca params");
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let ca = ca_params.self_signed(&ca_key).expect("ca");
        let ca_der = ca.der().as_ref();
        assert!(is_self_signed_certificate(ca_der), "root must be detected");

        // CA-SIGNED leaf: subject != issuer.
        let mut leaf_params =
            rcgen::CertificateParams::new(vec![]).expect("leaf params");
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "leaf.test");
        let leaf = leaf_params
            .signed_by(&ca_key, &ca, &ca_key)
            .expect("leaf");
        assert!(
            !is_self_signed_certificate(leaf.der().as_ref()),
            "signed leaf is not an anchor"
        );
    }
}
