// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! EUDI wallet integration - OID4VP sign-in.
//!
//! Single-identity-plane invariants :
//! 1. Wallet verification replaces **authentication only** - after a
//! successful presentation, Auth issues its own session + tokens.
//! 2. Wallet keys are verified against the connection's trusted issuers,
//! never added to Auth's JWKS.
//!
//! Endpoints (EUDI.1.3 + EUDI.):
//! - `GET /oauth/authorize?prompt=wallet` - builds the OID4VP authorization
//! request as a signed request object + `openid4vp://` deep link.
//! - `POST /oauth/vp/response` - wallet `direct_post` callback: verifies the
//! presentation (EUDI.1.1 `sd_jwt` module), checks trusted issuer + LoA
//! (EUDI.), find-or-creates the user ( federation pattern), and
//! issues the standard session + auth code.
//! - `GET /v1/auth/wallet/metadata` - public wallet-facing metadata.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Duration;
use glide::AsyncCommands as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::dtos::{
    CredentialIssuedResponse, CredentialOfferResponse, StatusListDocument, VpResponse,
    WalletAuthorizeResponse, WalletMetadata,
};
use crate::handlers::AppState;

// ── EUDI. - eudi_wallet enterprise-connection config ───────────────

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
    let row = sqlx::query(
        r#"SELECT config FROM enterprise_connections
            WHERE env_id = $1 AND strategy = 'eudi_wallet' AND status = 'active'
            ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(env_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
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

// ── EUDI. - OID4VP sign-in flow ─────────────────────────────────────

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
    get,
    path = "/oauth/authorize",
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
    let env_id = crate::overlays::env_from_headers(&headers);
    let Some(cfg) = load_wallet_connection(&state, env_id).await? else {
        return Err((
            StatusCode::NOT_FOUND,
            "no eudi_wallet connection configured for this env".into(),
        ));
    };

    // Single-use verifier challenge - the wallet echoes it in the KB-JWT.
    let nonce = Uuid::new_v4().to_string();
    let issuer = state.config.issuer.clone();
    let request = serde_json::json!({
        "response_type": "vp_token",
        "client_id": format!("{issuer}/wallet-verifier"),
        "response_mode": "direct_post",
        "nonce": nonce,
        "presentation_definition": cfg.required_credentials,
        "redirect_uri": format!("{issuer}/oauth/vp/response"),
    });
    // JAR-style signed request object - the wallet verifies Auth's
    // signature against the platform JWKS (OID4VP ).
    let request_object = state.keys.sign_value(&request).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("request object signing failed: {e}"),
        )
    })?;

    // Store the pending presentation (nonce → env/client context).
    let pending = serde_json::json!({
        "nonce": nonce,
        "env_id": env_id,
        "client_id": q.client_id,
        "redirect_uri": q.redirect_uri,
        "created_at": chrono::Utc::now().timestamp(),
    });
    let client = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let conn = client;
    let _: Result<(), _> = conn
        .set_ex(
            format!("auth:vp:nonce:{nonce}"),
            serde_json::to_string(&pending).unwrap_or_default(),
            VP_PENDING_TTL_SECS,
        )
        .await;

    Ok(Json(WalletAuthorizeResponse {
        nonce: nonce.clone(),
        request_uri: format!("{issuer}/oauth/vp/request/{nonce}"),
        request_object: serde_json::Value::String(request_object.clone()),
        qr_data: format!("openid4vp://?nonce={nonce}"),
        expires_in: VP_PENDING_TTL_SECS as i64,
    }))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for vpresponse.
pub struct VpResponseRequest {
    /// The vp token.
    pub vp_token: String,
    /// The nonce from the authorization request.
    /// The nonce.
    pub nonce: String,
    #[serde(default)]
    /// The presentation submission.
    pub presentation_submission: Option<serde_json::Value>,
}

/// `POST /oauth/vp/response` - the wallet's `direct_post` callback.
/// Handle vp response.
#[utoipa::path(
    post,
    path = "/oauth/vp/response",
    request_body = VpResponseRequest,
    responses(
        (status = 200, description = "Presentation accepted (single-use pending request resolved)", body = crate::dtos::VpResponse),
        (status = 400, description = "Unknown or expired presentation request"),
        (status = 401, description = "Presentation verification failed"),
    ),
    security(),
    tag = "wallet",
)]
pub async fn vp_response(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(req): Json<VpResponseRequest>,
) -> Result<Json<VpResponse>, (StatusCode, String)> {
    // Resolve (single-use) the pending presentation request.
    let client = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let conn = client;
    let pending_key = format!("auth:vp:nonce:{}", req.nonce);
    let pending: Option<String> = conn
        .get(&pending_key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(pending) = pending else {
        return Err((StatusCode::BAD_REQUEST, "unknown or expired nonce".into()));
    };
    let pending: serde_json::Value = serde_json::from_str(&pending).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("pending decode: {e}"),
        )
    })?;
    // Single-use: delete before verification.
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

    // ── EUDI. - SD-JWT verification ────────────────────────────────
    let presentation: &str = &req.vp_token;
    // Trusted issuer keys from the connection config (EUDI trust-list
    // resolution is ; uses operator-provisioned JWKS).
    let trusted = trusted_jwks(&cfg);
    if trusted.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "wallet connection has no trusted_issuers JWKS configured".into(),
        ));
    }
    let issuer_keys: Vec<serde_json::Value> =
        trusted.iter().flat_map(|(_, keys)| keys.clone()).collect();
    let verified = crate::sd_jwt::verify_presentation(
        presentation,
        &issuer_keys,
        None, // KB check via embedded jwk + sd_hash
        Some(&|uri, entry| {
            // Status check inside a sync callback (the sd_jwt verifier is
            // sync): block briefly on the current runtime.
            tokio::runtime::Handle::try_current()
                .map(|rt| rt.block_on(fetch_status_bit(&state.config.valkey_url, uri, entry)))
                .map_err(|_| "no async runtime".to_string())?
        }),
    )
    .map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            format!("presentation verification failed: {e}"),
        )
    })?;

    // Trusted issuer match (defense in depth).
    if !trusted.iter().any(|(iss, _)| iss == &verified.issuer) {
        return Err((
            StatusCode::FORBIDDEN,
            format!("credential issuer '{}' is not trusted", verified.issuer),
        ));
    }

    // ── EUDI. - assurance mapping ──────────────────────────────────
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
    let amr = "hwk"; // wallet hardware-key proof

    // ── Find-or-create the local user ( inbound federation) ───────
    let user = find_or_create_wallet_user(&state, pending_env, &verified).await?;

    // ── Standard session + auth code (identity plane preserved) ───────
    let session_token = Uuid::new_v4().to_string();
    let _session = crate::sessions::Session::create(
        &state.pool,
        user.id,
        pending_env,
        &session_token,
        None,
        Duration::seconds(state.config.session_ttl_secs as i64),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let code = Uuid::new_v4().to_string();
    let code_data = serde_json::json!({
           "client_id": pending.get("client_id"),
           "redirect_uri": pending.get("redirect_uri"),
           "scope": "openid profile email",
           "user_id": user.id.to_string(),
           "env_id": pending_env.to_string(),
    // EUDI. - assurance claims carried into the ID token.
           "acr": acr,
           "amr": amr,
           "nonce": pending.get("nonce"),
           "auth_time": chrono::Utc::now().timestamp(),
       });
    let _: Result<(), _> = conn
        .set_ex(format!("auth:code:{code}"), code_data.to_string(), 600)
        .await;
    let _: Result<(), _> = conn.del(&pending_key).await; // double-use safety

    Ok(Json(VpResponse {
        status: "verified".to_string(),
        session_token,
        code,
        redirect_uri: pending
            .get("redirect_uri")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        acr: Some(acr),
        amr: Some(vec![amr.to_string()]),
        user_id: user.id,
    }))
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
    // PID claims: `sub` (wallet/issuer subject), email, names.
    let external_sub = verified
        .claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "credential missing sub claim".into(),
            )
        })?;
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
    // table is EUDI.2.x. Returns the plain user row.
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, first_name FROM users WHERE env_id = $1 AND email = $2")
            .bind(env_id)
            .bind(&email)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some((id, _name)) = row {
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
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("wallet user create: {e}"),
        )
    })?;
    Ok(WalletUser { id, email })
}

// ── Status List 2021 (shared with EUDI.2.1 revocation) ────────────────

/// Fetch a Status List document (10s timeout).
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
    let doc: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("status list parse: {e}"))?;
    Ok(doc)
}

/// Fetch (Valkey-cached 5 min) + read the revocation bit for `entry`.
/// Fetch status bit.
pub async fn fetch_status_bit(valkey_url: &str, uri: &str, entry: u32) -> Result<bool, String> {
    let cache_key = format!("auth:statuslist:{}", sha_hex(uri));
    // GLIDE: the factory returns the connected client - a cache read is
    // one typed GET.
    if let Ok(conn) = sentin8::middleware::valkey_client(valkey_url, "sentin8:auth").await {
        use glide::AsyncCommands as _;
        if let Ok(Some(cached)) = conn.get::<_, Option<String>>(&cache_key).await {
            return crate::sd_jwt::status_list_bit(&cached, entry);
        }
    }
    let doc = fetch_status_list_doc(valkey_url, uri).await?;
    let lst = doc
        .pointer("/status_list/list")
        .and_then(|v| v.as_str())
        .ok_or("status list document missing /status_list/list")?;
    if let Ok(conn) = sentin8::middleware::valkey_client(valkey_url, "sentin8:auth").await {
        use glide::AsyncCommands as _;
        let _: Result<(), _> = conn.set_ex(&cache_key, lst, 300u64).await;
    }
    crate::sd_jwt::status_list_bit(lst, entry)
}

fn sha_hex(input: &str) -> String {
    let d = Sha256::digest(input.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

// ── EUDI. - wallet-facing metadata ──────────────────────────────────

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
// ── EUDI. - OID4VCI credential issuance ───────────────────

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
) -> Result<Json<StatusListDocument>, (StatusCode, String)> {
    let status: Option<String> = sqlx::query_scalar("SELECT status FROM credentials WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(status) = status else {
        return Err((StatusCode::NOT_FOUND, "credential not found".into()));
    };
    // Single-credential status list: bit 0 = revoked flag.
    let bit: u8 = if status == "revoked" { 1 } else { 0 };
    Ok(Json(StatusListDocument {
        status_list: serde_json::json!({ "idx": 0, "list": status_list_b64(bit) }),
    }))
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

/// Encode a 1-byte status list (MSB-first, entry 0 = bit 7) - EUDI.2.1.
fn status_list_b64(bit: u8) -> String {
    use base64::Engine as _;
    use std::io::Write as _;
    let bits = vec![if bit != 0 { 0b1000_0000u8 } else { 0u8 }];
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = enc.write_all(&bits);
    let compressed = enc.finish().unwrap_or_default();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed)
}

// ── EUDI. - QES signature ceremony broker ────────────────

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
