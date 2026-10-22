// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Dynamic Client Registration (DCR) - RFC 7591 + OIDC DCR 1.0.
//! DCR Management Protocol - RFC 7592.
//!
//! Endpoints:
//! - `POST /oauth/register` - register a new OAuth/OIDC client (RFC 7591).
//! - `GET /oauth/register/{client_id}` - read client metadata (RFC 7592).
//! - `PUT /oauth/register/{client_id}` - update client metadata (RFC 7592).
//! - `DELETE /oauth/register/{client_id}` - delete/deactivate (RFC 7592).
//!
//! Authentication for GET/PUT/DELETE uses the `registration_access_token`
//! returned at registration time, sent as a Bearer token in the
//! `Authorization` header. The token hash is stored in
//! `sentin8_auth_oauth_clients.registration_access_token_hash`.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use bcrypt::{hash as bcrypt_hash, DEFAULT_COST};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::events::emit_event;
use crate::handlers::AppState;

// ── RFC 7591 Registration Request ─────────────────────────────────────

/// Client metadata sent by the registrant (RFC 7591 ).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for register.
pub struct RegisterRequest {
    #[serde(default)]
    /// The client name.
    pub client_name: Option<String>,
    #[serde(default)]
    /// The redirect uris.
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    /// The grant types.
    pub grant_types: Vec<String>,
    #[serde(default)]
    /// The response types.
    pub response_types: Vec<String>,
    #[serde(default)]
    /// The token endpoint auth method.
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    /// The scope.
    pub scope: Option<String>,
    #[serde(default)]
    /// software identifier.
    pub software_id: Option<String>,
    #[serde(default)]
    /// The software statement.
    pub software_statement: Option<String>,
    #[serde(default)]
    /// The logo URI.
    pub logo_uri: Option<String>,
    #[serde(default)]
    /// The client URI.
    pub client_uri: Option<String>,
    #[serde(default)]
    /// The policy URI.
    pub policy_uri: Option<String>,
    #[serde(default)]
    /// The tos URI.
    pub tos_uri: Option<String>,
    #[serde(default)]
    /// The contacts.
    pub contacts: Vec<String>,
    #[serde(default)]
    /// The subject type.
    pub subject_type: Option<String>,
    #[serde(default)]
    /// The JWKS URI.
    pub jwks_uri: Option<String>,
    #[serde(default)]
    /// The JWKS.
    pub jwks: Option<serde_json::Value>,
    #[serde(default)]
    /// The sector identifier URI.
    pub sector_identifier_uri: Option<String>,
    #[serde(default)]
    /// The application type.
    pub application_type: Option<String>,
    // ── mTLS fields (RFC 8705,) ──
    /// Subject DN for `tls_client_auth` method (RFC 8705 ).
    #[serde(default)]
    /// The tls client auth subject DN.
    pub tls_client_auth_subject_dn: Option<String>,
    /// SHA-256 thumbprint for `self_signed_tls_client_auth` method.
    #[serde(default)]
    /// The self signed tls client auth thumbprint.
    pub self_signed_tls_client_auth_thumbprint: Option<String>,
    // ── Consent bypass ──
    /// When false, this first-party client skips the consent screen.
    #[serde(default = "default_true")]
    /// The consent required.
    pub consent_required: bool,
    // ── CIBA (OIDC CIBA §4 registration parameter, DESIGN §9a.7) ──
    /// The client's ping-mode notification callback. Absent = the
    /// client uses poll delivery only.
    #[serde(default)]
    /// The backchannel client notification endpoint.
    pub backchannel_client_notification_endpoint: Option<String>,
}

/// Client metadata returned after registration (RFC 7591 ).
/// Includes `client_secret`, `client_id_issued_at`, `client_secret_expires_at`,
/// and the `registration_access_token` (RFC 7592).
#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for register.
pub struct RegisterResponse {
    /// client identifier.
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The client secret.
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// client secret expires time.
    pub client_secret_expires_at: Option<i64>,
    /// client id issued time.
    pub client_id_issued_at: i64,
    /// The registration access token.
    pub registration_access_token: String,
    /// The registration client URI.
    pub registration_client_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The client name.
    pub client_name: Option<String>,
    /// The redirect uris.
    pub redirect_uris: Vec<String>,
    /// The grant types.
    pub grant_types: Vec<String>,
    /// The response types.
    pub response_types: Vec<String>,
    /// The token endpoint auth method.
    pub token_endpoint_auth_method: String,
    /// The scope.
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// software identifier.
    pub software_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The software statement.
    pub software_statement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The logo URI.
    pub logo_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The client URI.
    pub client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The policy URI.
    pub policy_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The tos URI.
    pub tos_uri: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    /// The contacts.
    pub contacts: Vec<String>,
    /// The application type.
    pub application_type: String,
    /// The consent required.
    pub consent_required: bool,
}

// ── RFC 7592 Management ───────────────────────────────────────────────

/// Update request (RFC 7592 ) - same shape as RegisterRequest but all
/// fields are optional since the client may only update a subset.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for update.
pub struct UpdateRequest {
    #[serde(default)]
    /// The client name.
    pub client_name: Option<String>,
    #[serde(default)]
    /// The redirect uris.
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    /// The grant types.
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    /// The response types.
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    /// The token endpoint auth method.
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    /// The scope.
    pub scope: Option<String>,
    #[serde(default)]
    /// software identifier.
    pub software_id: Option<String>,
    #[serde(default)]
    /// The software statement.
    pub software_statement: Option<String>,
    #[serde(default)]
    /// The logo URI.
    pub logo_uri: Option<String>,
    #[serde(default)]
    /// The client URI.
    pub client_uri: Option<String>,
    #[serde(default)]
    /// The policy URI.
    pub policy_uri: Option<String>,
    #[serde(default)]
    /// The tos URI.
    pub tos_uri: Option<String>,
    #[serde(default)]
    /// The contacts.
    pub contacts: Option<Vec<String>>,
    #[serde(default)]
    /// The JWKS URI.
    pub jwks_uri: Option<String>,
    #[serde(default)]
    /// The JWKS.
    pub jwks: Option<serde_json::Value>,
    #[serde(default)]
    /// The sector identifier URI.
    pub sector_identifier_uri: Option<String>,
    #[serde(default)]
    /// The consent required.
    pub consent_required: Option<bool>,
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Default value for `consent_required` when omitted from DCR requests.
fn default_true() -> bool {
    true
}

/// Generate a random client_id (opaque, URL-safe).
fn generate_client_id() -> String {
    Uuid::new_v4().simple().to_string()
}

/// Generate a random client_secret (high-entropy).
fn generate_client_secret() -> String {
    let bytes: [u8; 32] = rand::random();
    hex_encode(&bytes)
}

/// Generate a random registration_access_token (RFC 7592).
fn generate_registration_access_token() -> String {
    let bytes: [u8; 32] = rand::random();
    format!("rat_{}", hex_encode(&bytes))
}

/// SHA-256 hex hash of a token.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex_encode(&hasher.finalize())
}

/// Hex-encode a byte slice (avoids adding the `hex` crate dependency).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Resolve the tenant env ID from TLS headers, defaulting to the System
/// env for platform-level registration. The auth tables no longer carry
/// `org_id` - `env_id` is the sole tenant key. The org_id needed for bus
/// event routing is resolved from `sentin8_sys_environments` at emit time
/// (or uses `SYSTEM_ORG_ID` as a fallback).
fn resolve_tenant(headers: &HeaderMap) -> Uuid {
    use crate::config::SYSTEM_ENV_ID;
    headers
        .get(sentin8::middleware::context::HEADER_ENV_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(SYSTEM_ENV_ID)
}

/// Resolve the issuer for building `registration_client_uri`.
fn resolve_issuer(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(h) = headers
        .get("x-sentin8-hostname")
        .and_then(|v| v.to_str().ok())
    {
        if !h.is_empty() {
            return format!("https://{h}");
        }
    }
    if let Some(h) = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        if !h.is_empty() {
            return format!("https://{h}");
        }
    }
    state.config.issuer.clone()
}

/// Extract a Bearer token from the Authorization header.
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").map(|t| t.to_string()))
}

/// OIDC baseline scopes - never gated by the M2M scope grants.
/// DESIGN §9a.4: all four OIDC claim scopes are baseline (advertised
/// and served; no suite skips per §9a.10).
const OIDC_BASELINE: &[&str] = &[
    "openid",
    "profile",
    "email",
    "phone",
    "address",
    "offline_access",
];

/// Extract the *platform* (non-OIDC-baseline) scopes from a space-separated
/// scope string. Empty result → no gate evaluation needed.
fn platform_scopes(scope: Option<&str>) -> Vec<String> {
    scope
        .unwrap_or("")
        .split_whitespace()
        .filter(|s| !OIDC_BASELINE.contains(s))
        .map(String::from)
        .collect()
}

/// - certificate-bound DCR scope gate (auth design
/// target-state revision).
///
/// A `client_credentials`-only registration may request platform scopes
/// only when the TLS handshake carries a client certificate that (1) chains
/// to the platform CA (guaranteed by `sentin8-tls` optional client auth -
/// the `X-Sentin8-Client-Cert-*` headers are injected ONLY for certs
/// verified against `SENTIN8_TLS_CLIENT_CA_PEM`, the Acme Root CA), and
/// (2) whose subject `CN` equals a grant row's `service_name` in
/// `auth.m2m_scope_grants` (enroll-upserted from the service's
/// `m2m_grants` self-declaration), with a superset of the requested scopes.
///
/// **No fallback** - not even in dev: a caller without a certificate has no
/// identity, and an identity-less caller gets no platform scopes.
/// Fail-closed always. The gate covers BOTH registration paths
/// (`POST /oauth/register` and the RFC 7592 `PUT`, evaluating the merged
/// scope set of M2M-only clients) so a client cannot be registered
/// OIDC-only and escalated later.
///
/// `Ok` = allowed; `Err(msg)` = `400 invalid_client_metadata`.
async fn m2m_scope_gate(
    pool: &sqlx::PgPool,
    headers: &HeaderMap,
    workload_name: &str,
    requested: &[String],
) -> Result<(), (StatusCode, String)> {
    use sqlx::Row;
    if requested.is_empty() {
        return Ok(());
    }
    // Identity resolution - certificate identity ONLY. The TLS layer
    // injects the thumbprint header after verifying the presented cert
    // against the platform CA; a caller without a cert has no identity.
    let Some((thumbprint, _subject)) = crate::mtls::extract_mtls_identity(headers) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata: mTLS client certificate required - \
             certificate-bound mTLS is the only M2M registration path"
                .into(),
        ));
    };
    // The workload's identity is the Acme-minted leaf's subject CN
    // (`CN=m2m-{workload}`); the DCR client_name must agree with it. The
    // grant row is keyed by service_name (= the CN the cert must carry).
    // The `m2m-` prefix is the reserved workload-identity namespace: only
    // Sentin8:Acme (guarded issuance) mints leaves in it, so
    // "Acme-signed + `m2m-{workload}`" is the workload identity claim.
    let cn = crate::mtls::extract_cert_cn(headers);
    let Some(cn) = cn else {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata: client certificate subject CN missing".into(),
        ));
    };
    let workload_cn = match cn.strip_prefix("m2m-") {
        Some(w) => w.to_string(),
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "invalid_client_metadata: certificate CN ({cn}) is not a \
                     platform workload identity (expected prefix `m2m-`)"
                ),
            ));
        }
    };
    if workload_cn != workload_name {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "invalid_client_metadata: certificate CN ({cn}) does not match the requested workload ({workload_name})"
            ),
        ));
    }
    // The gate table is platform-internal (no RLS) - read on the pool.
    // Keyed by service_name (= the cert CN), upserted by `vertical enroll`.
    let row = sqlx::query(
        r#"SELECT allowed_scopes FROM auth.m2m_scope_grants
             WHERE service_name = $1"#,
    )
    .bind(workload_name)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("scope grant lookup failed: {e}"),
        )
    })?;
    let Some(row) = row else {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata: workload is not granted M2M scope registration".into(),
        ));
    };
    let allowed: Vec<String> = row
        .try_get::<Option<Vec<String>>, _>("allowed_scopes")
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("scope grant decode failed: {e}"),
            )
        })?
        .unwrap_or_default();
    let missing: Vec<&str> = requested
        .iter()
        .filter(|s| !allowed.contains(s))
        .map(|s| s.as_str())
        .collect();
    if !missing.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "invalid_client_metadata: scope(s) not granted for this workload: {}",
                missing.join(" ")
            ),
        ));
    }
    // The verified thumbprint (TLS-injected, CA-checked) is returned for
    // the registration row's `self_signed_tls_client_auth_thumbprint` -
    // token requests later match against it (RFC 8705).
    let _ = thumbprint;
    Ok(())
}

/// Is this grant-type set an M2M-only (service principal) client?
/// `client_credentials` present and `authorization_code` absent - mirrors
/// the redirect-URI exemption check in `register`.
fn is_m2m_only_grants(grant_types: &[String]) -> bool {
    grant_types.iter().any(|g| g == "client_credentials")
        && !grant_types.iter().any(|g| g == "authorization_code")
}

// ── POST /oauth/register (RFC 7591) ───────────────────────────────────

/// Register it.
#[utoipa::path(
    post,
    path = "/oauth/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Client registered (registration_access_token returned)", body = RegisterResponse),
        (status = 400, description = "invalid_client_metadata / invalid_redirect_uri (RFC 7591 §3.3)"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), (StatusCode, String)> {
    // Validate redirect_uris - required for interactive clients (RFC 7591 ),
    // but M2M clients (client_credentials only) don't need redirect URIs.
    let is_m2m_only = is_m2m_only_grants(&req.grant_types);
    if req.redirect_uris.is_empty() && !is_m2m_only {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata: redirect_uris is required".into(),
        ));
    }

    // - mTLS-bound DCR for M2M scope registration (auth design
    // b): platform scopes on a `client_credentials`-only
    // client require a granted certificate thumbprint (or the explicit
    // dev fallback). Interactive clients keep the RFC 7591 default.
    let env_id = resolve_tenant(&headers);
    let client_id = generate_client_id();
    let client_name = req
        .client_name
        .unwrap_or_else(|| format!("client_{client_id}"));

    if is_m2m_only {
        m2m_scope_gate(
            &state.pool,
            &headers,
            &client_name,
            &platform_scopes(req.scope.as_deref()),
        )
        .await?;
    }

    // Determine auth method - default to client_secret_basic for confidential clients.
    let token_endpoint_auth_method = req
        .token_endpoint_auth_method
        .unwrap_or_else(|| "client_secret_basic".to_string());

    // Generate a client_secret for confidential clients.
    //
    // (design ) - `private_key_jwt` clients
    // authenticate with an RFC 7523 client_assertion signed by their
    // registered key (`jwks` metadata); no shared secret is issued. `none`
    // = public client (no key, no secret).
    let (raw_secret, secret_hash) = if token_endpoint_auth_method == "none"
        || token_endpoint_auth_method == "private_key_jwt"
    {
        (None, None)
    } else {
        let raw = generate_client_secret();
        let hash = bcrypt_hash(&raw, DEFAULT_COST)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        (Some(raw), Some(hash))
    };

    // Client secret expires at 0 = never (RFC 7591 ).
    let client_secret_expires_at: Option<i64> = if raw_secret.is_some() { Some(0) } else { None };

    let grant_types = if req.grant_types.is_empty() {
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ]
    } else {
        req.grant_types
    };
    let response_types = if req.response_types.is_empty() {
        vec!["code".to_string()]
    } else {
        req.response_types
    };
    let scopes: Vec<String> = req
        .scope
        .as_deref()
        .unwrap_or("openid profile email")
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    // Generate the registration_access_token (RFC 7592).
    let registration_access_token = generate_registration_access_token();
    let rat_hash = hash_token(&registration_access_token);

    let now = Utc::now();
    // SEC- - run the INSERT inside a transaction with the tenant
    // context on the same connection (RLS under the app role; set_config is
    // transaction-local so the pool-only path denied the write).
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
        r#"INSERT INTO oauth_clients
               (env_id, client_id, client_name,
                client_secret_hash, redirect_uris, grant_types, response_types,
                token_endpoint_auth_method, scopes,
                client_id_issued_at, client_secret_expires_at,
                software_id, software_statement,
                logo_uri, client_uri, policy_uri, tos_uri, contacts,
                jwks_uri, jwks, sector_identifier_uri, application_type,
                registration_access_token_hash, dcr_protected,
                tls_client_auth_subject_dn, self_signed_tls_client_auth_thumbprint,
                consent_required, backchannel_client_notification_endpoint)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                   $10, $11, $12, $13, $14, $15, $16, $17, $18,
                   $19, $20, $21, $22, $23, true,
                   $24, $25, $26, $27)
           RETURNING
               client_id, client_id_issued_at, client_secret_expires_at,
               client_name, redirect_uris, grant_types, response_types,
               token_endpoint_auth_method, scopes,
               software_id, software_statement,
               logo_uri, client_uri, policy_uri, tos_uri, contacts,
               application_type, consent_required"#,
        env_id,
        &client_id,
        &client_name,
        secret_hash,
        &req.redirect_uris,
        &grant_types,
        &response_types,
        &token_endpoint_auth_method,
        &scopes,
        now,
        client_secret_expires_at.map(|_| now + Duration::days(365)),
        req.software_id.as_deref(),
        req.software_statement.as_deref(),
        req.logo_uri.as_deref(),
        req.client_uri.as_deref(),
        req.policy_uri.as_deref(),
        req.tos_uri.as_deref(),
        // `contacts`/`consent_required` are NOT NULL columns; RegisterRequest
        // coalesces them (Vec / bool with serde default) so no bound NULL is
        // possible here - the RFC 7592 update path is the one that binds
        // Option values (UpdateRequest) and coalesces onto existing values.
        &req.contacts,
        req.jwks_uri.as_deref(),
        req.jwks.as_ref(),
        req.sector_identifier_uri.as_deref(),
        req.application_type.as_deref().unwrap_or("web"),
        &rat_hash,
        req.tls_client_auth_subject_dn.as_deref(),
        req.self_signed_tls_client_auth_thumbprint.as_deref(),
        req.consent_required,
        // CIBA (DESIGN §9a.7) - the ping-mode notification callback,
        // registered through DCR exactly like the suite does.
        req.backchannel_client_notification_endpoint.as_deref(),
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = tx.commit().await; // SEC-2.4.8 - persist the client

    let issuer = resolve_issuer(&state, &headers);
    let registration_client_uri = format!("{issuer}/oauth/register/{}", row.client_id);

    emit_event(
        &state.pool,
        env_id,
        "sentin8:auth:dcr:created",
        serde_json::json!({ "client_id": &row.client_id }),
    )
    .await;

    // RFC 7591 - the registration response MUST be 201 Created.
    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            client_id: row.client_id,
            client_secret: raw_secret,
            client_secret_expires_at: row.client_secret_expires_at.map(|t| t.timestamp()),
            client_id_issued_at: row.client_id_issued_at.timestamp(),
            registration_access_token,
            registration_client_uri,
            client_name: Some(row.client_name),
            redirect_uris: row.redirect_uris,
            grant_types: row.grant_types,
            response_types: row.response_types,
            token_endpoint_auth_method: row.token_endpoint_auth_method,
            scope: row.scopes.join(" "),
            software_id: row.software_id,
            software_statement: row.software_statement,
            logo_uri: row.logo_uri,
            client_uri: row.client_uri,
            policy_uri: row.policy_uri,
            tos_uri: row.tos_uri,
            contacts: row.contacts,
            application_type: row.application_type,
            consent_required: row.consent_required,
        }),
    ))
}

// ── GET /oauth/register/{client_id} (RFC 7592 ) ────────────────────

/// Fetch client.
#[utoipa::path(
    get,
    path = "/oauth/register/{client_id}",
    params(("client_id" = String, Path, description = "Client id")),
    responses(
        (status = 200, description = "Client configuration (RFC 7592 §2.2)", body = RegisterResponse),
        (status = 401, description = "Missing/invalid registration access token"),
        (status = 404, description = "Unknown client"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn get_client(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let rat = extract_bearer(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "invalid_token: registration_access_token required".into(),
        )
    })?;
    let rat_hash = hash_token(&rat);

    let row = sqlx::query!(
        r#"SELECT
               client_id, client_id_issued_at, client_secret_expires_at,
               client_name, redirect_uris, grant_types, response_types,
               token_endpoint_auth_method, scopes,
               software_id, software_statement,
               logo_uri, client_uri, policy_uri, tos_uri, contacts,
               jwks_uri, jwks, sector_identifier_uri, application_type,
               registration_access_token_hash, consent_required
           FROM oauth_clients
           WHERE client_id = $1 AND dcr_protected = true"#,
        client_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row = row.ok_or_else(|| (StatusCode::NOT_FOUND, "client not found".into()))?;

    // Validate the registration_access_token.
    if row.registration_access_token_hash != Some(rat_hash) {
        return Err((StatusCode::UNAUTHORIZED, "invalid_token".into()));
    }

    Ok(Json(serde_json::json!({
        "client_id": row.client_id,
        "client_id_issued_at": row.client_id_issued_at.timestamp(),
        "client_secret_expires_at": row.client_secret_expires_at.map(|t| t.timestamp()),
        "client_name": row.client_name,
        "redirect_uris": row.redirect_uris,
        "grant_types": row.grant_types,
        "response_types": row.response_types,
        "token_endpoint_auth_method": row.token_endpoint_auth_method,
        "scope": row.scopes.join(" "),
        "software_id": row.software_id,
        "software_statement": row.software_statement,
        "logo_uri": row.logo_uri,
        "client_uri": row.client_uri,
        "policy_uri": row.policy_uri,
        "tos_uri": row.tos_uri,
        "contacts": row.contacts,
        "jwks_uri": row.jwks_uri,
        "jwks": row.jwks,
        "sector_identifier_uri": row.sector_identifier_uri,
        "application_type": row.application_type,
        "consent_required": row.consent_required,
    })))
}

// ── PUT /oauth/register/{client_id} (RFC 7592 ) ────────────────────

/// Update client.
#[utoipa::path(
    put,
    path = "/oauth/register/{client_id}",
    params(("client_id" = String, Path, description = "Client id")),
    request_body = UpdateRequest,
    responses(
        (status = 200, description = "Client configuration updated", body = RegisterResponse),
        (status = 401, description = "Missing/invalid registration access token"),
        (status = 404, description = "Unknown client"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn update_client(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<UpdateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let rat = extract_bearer(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "invalid_token: registration_access_token required".into(),
        )
    })?;
    let rat_hash = hash_token(&rat);

    // Fetch the existing client to validate the token.
    // fix : `oauth_clients` is RLS-protected - the
    // fetch and the UPDATE must run inside ONE transaction with the
    // client's env context set (same connection). Without context
    // the SELECT is policy-blocked → `fetch_optional` returns None → the
    // handler wrongly reports 404 for a live client. Caught by the revived
    // integration tests.
    let env_id = resolve_tenant(&headers);
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;

    let existing = sqlx::query!(
        r#"SELECT registration_access_token_hash, redirect_uris, grant_types, response_types,
                  token_endpoint_auth_method, scopes, contacts, application_type,
                  client_name
           FROM oauth_clients
           WHERE client_id = $1 AND dcr_protected = true"#,
        client_id,
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let existing = existing.ok_or_else(|| (StatusCode::NOT_FOUND, "client not found".into()))?;
    if existing.registration_access_token_hash != Some(rat_hash) {
        return Err((StatusCode::UNAUTHORIZED, "invalid_token".into()));
    }

    // Merge: use the new values when provided, otherwise keep existing.
    let redirect_uris = req.redirect_uris.unwrap_or(existing.redirect_uris);
    let grant_types = req.grant_types.unwrap_or(existing.grant_types);
    let response_types = req.response_types.unwrap_or(existing.response_types);
    let token_endpoint_auth_method = req
        .token_endpoint_auth_method
        .unwrap_or(existing.token_endpoint_auth_method);
    let scopes: Vec<String> = req
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(|s| s.to_string()).collect())
        .unwrap_or(existing.scopes);
    let contacts = req.contacts.unwrap_or(existing.contacts);

    // - the RFC 7592 update path is a first-class bypass route:
    // a registrant could POST an OIDC-only client and then PUT platform
    // scopes onto it. Gate the MERGED scope set of M2M-only clients (the
    // same certificate rule as registration; the RAT holder is the
    // registrant, so its certificate is the presented identity).
    if is_m2m_only_grants(&grant_types) {
        m2m_scope_gate(
            &state.pool,
            &headers,
            existing.client_name.as_str(),
            &platform_scopes(Some(&scopes.join(" "))),
        )
        .await?;
    }

    let row = sqlx::query!(
        r#"UPDATE oauth_clients SET
               client_name = COALESCE($2, client_name),
               redirect_uris = $3,
               grant_types = $4,
               response_types = $5,
               token_endpoint_auth_method = $6,
               scopes = $7,
               logo_uri = COALESCE($8, logo_uri),
               client_uri = COALESCE($9, client_uri),
               policy_uri = COALESCE($10, policy_uri),
               tos_uri = COALESCE($11, tos_uri),
               contacts = $12,
               jwks_uri = COALESCE($13, jwks_uri),
               jwks = COALESCE($14, jwks),
               sector_identifier_uri = COALESCE($15, sector_identifier_uri),
               software_id = COALESCE($16, software_id),
               software_statement = COALESCE($17, software_statement),
               consent_required = COALESCE($18, consent_required),
               updated_at = now()
           WHERE client_id = $1
           RETURNING
               client_id, client_id_issued_at, client_secret_expires_at,
               client_name, redirect_uris, grant_types, response_types,
               token_endpoint_auth_method, scopes,
               software_id, software_statement,
               logo_uri, client_uri, policy_uri, tos_uri, contacts,
               jwks_uri, jwks, sector_identifier_uri, application_type, consent_required"#,
        client_id,
        req.client_name,
        &redirect_uris,
        &grant_types,
        &response_types,
        &token_endpoint_auth_method,
        &scopes,
        req.logo_uri.as_deref(),
        req.client_uri.as_deref(),
        req.policy_uri.as_deref(),
        req.tos_uri.as_deref(),
        &contacts,
        req.jwks_uri.as_deref(),
        req.jwks.as_ref(),
        req.sector_identifier_uri.as_deref(),
        req.software_id.as_deref(),
        req.software_statement.as_deref(),
        req.consent_required,
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row = row.ok_or_else(|| (StatusCode::NOT_FOUND, "client not found".into()))?;

    let evt_env_id = resolve_tenant(&headers);
    emit_event(
        &state.pool,
        evt_env_id,
        "sentin8:auth:dcr:updated",
        serde_json::json!({ "client_id": &row.client_id }),
    )
    .await;

    Ok(Json(serde_json::json!({
        "client_id": row.client_id,
        "client_id_issued_at": row.client_id_issued_at.timestamp(),
        "client_secret_expires_at": row.client_secret_expires_at.map(|t| t.timestamp()),
        "client_name": row.client_name,
        "redirect_uris": row.redirect_uris,
        "grant_types": row.grant_types,
        "response_types": row.response_types,
        "token_endpoint_auth_method": row.token_endpoint_auth_method,
        "scope": row.scopes.join(" "),
        "software_id": row.software_id,
        "software_statement": row.software_statement,
        "logo_uri": row.logo_uri,
        "client_uri": row.client_uri,
        "policy_uri": row.policy_uri,
        "tos_uri": row.tos_uri,
        "contacts": row.contacts,
        "jwks_uri": row.jwks_uri,
        "jwks": row.jwks,
        "sector_identifier_uri": row.sector_identifier_uri,
        "application_type": row.application_type,
        "consent_required": row.consent_required,
    })))
}

// ── DELETE /oauth/register/{client_id} (RFC 7592 ) ─────────────────

/// Delete client.
#[utoipa::path(
    delete,
    path = "/oauth/register/{client_id}",
    params(("client_id" = String, Path, description = "Client id")),
    responses(
        (status = 204, description = "Client deleted"),
        (status = 401, description = "Missing/invalid registration access token"),
        (status = 404, description = "Unknown client"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn delete_client(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, String)> {
    let rat = extract_bearer(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "invalid_token: registration_access_token required".into(),
        )
    })?;
    let rat_hash = hash_token(&rat);

    let result = sqlx::query!(
        r#"DELETE FROM oauth_clients
           WHERE client_id = $1
             AND dcr_protected = true
             AND registration_access_token_hash = $2"#,
        client_id,
        rat_hash,
    )
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "client not found or invalid token".into(),
        ));
    }

    let evt_env_id = resolve_tenant(&headers);
    emit_event(
        &state.pool,
        evt_env_id,
        "sentin8:auth:dcr:deleted",
        serde_json::json!({ "client_id": &client_id }),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_client_id_is_unique() {
        let a = generate_client_id();
        let b = generate_client_id();
        assert_ne!(a, b);
        assert!(a.len() >= 32);
    }

    #[test]
    fn generate_client_secret_is_unique() {
        let a = generate_client_secret();
        let b = generate_client_secret();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64); // 32 bytes hex
    }

    #[test]
    fn hash_token_is_sha256_hex() {
        let h = hash_token("test");
        assert_eq!(h.len(), 64); // 32 bytes hex
                                 // Known SHA-256 of "test"
        assert_eq!(
            h,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn registration_access_token_format() {
        let t = generate_registration_access_token();
        assert!(t.starts_with("rat_"));
        assert!(t.len() > 32);
    }

    #[test]
    fn extract_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer rat_abc123".parse().unwrap());
        assert_eq!(extract_bearer(&headers), Some("rat_abc123".to_string()));

        let empty_headers = HeaderMap::new();
        assert_eq!(extract_bearer(&empty_headers), None);
    }
}
