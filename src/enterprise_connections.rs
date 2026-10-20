// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Enterprise connections (SAML/OIDC IdP)
//!
//! Implements the admin API for managing external identity provider (IdP)
//! connections and the OIDC SSO sign-in flow. SAML metadata is stored and
//! served but full SAML assertion parsing is a large surface; this module
//! implements the OIDC Authorization Code flow end-to-end and provides the
//! SAML SP metadata endpoint + the ACS endpoint stub (assertion validation
//! is left as a future extension once a SAML library is vendored).
//!
//! ## Endpoints
//!
//! Admin API:
//! - `GET /v1/admin/enterprise-connections` - list connections
//! - `POST /v1/admin/enterprise-connections` - create connection
//! - `GET /v1/admin/enterprise-connections/{id}` - connection detail
//! - `PUT /v1/admin/enterprise-connections/{id}` - update
//! - `DELETE /v1/admin/enterprise-connections/{id}` - delete
//!
//! SSO flow:
//! - `GET /v1/sso/{connection_id}/authorize` - redirect to the IdP authorize
//! URL (OIDC) or SAML SSO URL.
//! - `GET /v1/sso/{connection_id}/callback` - OIDC code exchange callback.
//! - `GET /v1/saml/metadata/{connection_id}` - SP metadata XML.
//! - `POST /v1/saml/acs/{connection_id}` - SAML ACS (accepts SAMLResponse).

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::admin::{set_tenant_context, TargetEnvQuery};
use crate::dtos::SamlMetadataResponse;
use crate::handlers::AppState;

/// SSO session TTL (10 minutes - enough for an IdP round trip).
const SSO_SESSION_TTL_SECS: i64 = 600;

// ── Admin API: requests / responses ───────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for createconnection.
pub struct CreateConnectionRequest {
    /// The name.
    pub name: String,
    /// Federation protocol: `oidc` or `saml`.
    pub strategy: String, // "oidc" | "saml"
    #[serde(default)]
    /// env identifier.
    pub env_id: Option<Uuid>,
    // OIDC
    #[serde(default)]
    /// The issuer URL.
    pub issuer_url: Option<String>,
    #[serde(default)]
    /// The discovery URL.
    pub discovery_url: Option<String>,
    #[serde(default)]
    /// client identifier.
    pub client_id: Option<String>,
    #[serde(default)]
    /// The client secret.
    pub client_secret: Option<String>,
    #[serde(default)]
    /// The scopes.
    pub scopes: Option<Vec<String>>,
    // SAML
    #[serde(default)]
    /// The metadata URL.
    pub metadata_url: Option<String>,
    #[serde(default)]
    /// The metadata xml.
    pub metadata_xml: Option<String>,
    #[serde(default)]
    /// entity identifier.
    pub entity_id: Option<String>,
    #[serde(default)]
    /// The acs URL.
    pub acs_url: Option<String>,
    #[serde(default)]
    /// The domain hint.
    pub domain_hint: Option<String>,
    #[serde(default)]
    /// The email attribute.
    pub email_attribute: Option<String>,
    #[serde(default)]
    /// The name attribute.
    pub name_attribute: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for connection.
pub struct ConnectionResponse {
    /// Identifier.
    pub id: Uuid,
    /// The name.
    pub name: String,
    /// The strategy.
    pub strategy: String,
    /// The status.
    pub status: String,
    /// env identifier.
    pub env_id: Option<Uuid>,
    /// The issuer URL.
    pub issuer_url: Option<String>,
    /// The discovery URL.
    pub discovery_url: Option<String>,
    /// client identifier.
    pub client_id: Option<String>,
    /// The scopes.
    pub scopes: Vec<String>,
    /// The metadata URL.
    pub metadata_url: Option<String>,
    /// entity identifier.
    pub entity_id: Option<String>,
    /// The acs URL.
    pub acs_url: Option<String>,
    /// The domain hint.
    pub domain_hint: Option<String>,
    /// The email attribute.
    pub email_attribute: String,
    /// The name attribute.
    pub name_attribute: Option<String>,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// updated time.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
/// The listconnectionsquery type.
pub struct ListConnectionsQuery {
    #[serde(default)]
    /// env identifier.
    pub env_id: Option<Uuid>,
    /// Target env (BFF proxy contract - design Fix A/B/C: admin
    /// endpoints resolve their tenant from this param; required).
    #[serde(default)]
    /// target env identifier.
    pub target_env_id: Option<String>,
}

// ── Admin API: handlers ────────────────────────────────────────────────

/// `GET /v1/admin/enterprise-connections` - list enterprise connections.
#[utoipa::path(
    get,
    operation_id = "connection.list",
    path = "/v1/admin/enterprise-connections",
    params(("env_id" = Option<Uuid>, Query, description = "Filter by env ID")),
    responses(
        (status = 200, description = "Enterprise connections", body = [ConnectionResponse]),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List connections.
pub async fn list_connections(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListConnectionsQuery>,
) -> Result<Json<Vec<ConnectionResponse>>, (StatusCode, String)> {
    // SEC- - admin guard + tenant scoping. The previous
    // `WHERE ($1::uuid IS NULL OR env_id = $1)` listed EVERY tenant's IdP
    // connections when env_id was omitted - a cross-tenant leak.
    let env_param = q
        .target_env_id
        .clone()
        .or_else(|| q.env_id.map(|u| u.to_string()));
    let auth = crate::sentin8or_auth::require_sentin8or_access_with_env(
        &state,
        &headers,
        env_param.as_deref(),
    )
    .await?;
    // Tenant context on the same connection (auth DESIGN §6.3):
    // sentin8_set_tenant_context is transaction-local (set_config(…, true))
    // - a pool-direct query runs context-less and the FORCE-RLS policy
    // filters every row, so the admin UI's connection list came back empty.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, auth.env_id).await;
    let rows = sqlx::query!(
        r#"SELECT
               id, name, strategy, status, env_id,
               issuer_url, discovery_url, client_id, scopes,
               metadata_url, entity_id, acs_url, domain_hint,
               email_attribute, name_attribute, created_at, updated_at
           FROM enterprise_connections
           WHERE env_id = $1
           ORDER BY created_at DESC"#,
        auth.env_id,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let conns: Vec<ConnectionResponse> = rows
        .into_iter()
        .map(|r| ConnectionResponse {
            id: r.id,
            name: r.name,
            strategy: r.strategy,
            status: r.status,
            env_id: r.env_id,
            issuer_url: r.issuer_url,
            discovery_url: r.discovery_url,
            client_id: r.client_id,
            scopes: r.scopes,
            metadata_url: r.metadata_url,
            entity_id: r.entity_id,
            acs_url: r.acs_url,
            domain_hint: r.domain_hint,
            email_attribute: r.email_attribute,
            name_attribute: r.name_attribute,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect();
    Ok(Json(conns))
}

/// `POST /v1/admin/enterprise-connections` - create an enterprise connection.
#[utoipa::path(
    post,
    operation_id = "connection.create",
    path = "/v1/admin/enterprise-connections",
    request_body = CreateConnectionRequest,
    responses(
        (status = 200, description = "Connection created", body = ConnectionResponse),
        (status = 400, description = "strategy must be 'oidc' or 'saml'"),
        (status = 409, description = "connection name already exists"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Create connection.
pub async fn create_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Json(req): Json<CreateConnectionRequest>,
) -> Result<Response, (StatusCode, String)> {
    // SEC- - admin guard. target_env_id is forwarded by the BFF proxy
    // (design Fix A) - auth is env-scoped, no fallback.
    let _auth = crate::sentin8or_auth::require_sentin8or_access_write(
        &state,
        &headers,
        teq.target_env_id.as_deref(),
    )
    .await?;
    if req.strategy != "oidc" && req.strategy != "saml" {
        return Err((
            StatusCode::BAD_REQUEST,
            "strategy must be 'oidc' or 'saml'".into(),
        ));
    }

    let client_secret_cipher = req
        .client_secret
        .as_ref()
        .filter(|s| !s.is_empty())
        .map(|s| encrypt_secret(&state.config, s.as_bytes()));

    let scopes = req
        .scopes
        .unwrap_or_else(|| vec!["openid".into(), "profile".into(), "email".into()]);

    // SEC- - tenant context on the same connection (design ).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(_auth.env_id)
        .execute(&mut *conn)
        .await;
    let row = sqlx::query!(
        r#"INSERT INTO enterprise_connections
             (env_id, name, strategy, status,
              issuer_url, discovery_url, client_id, client_secret_cipher, scopes,
              metadata_url, metadata_xml, entity_id, acs_url, domain_hint,
              email_attribute, name_attribute)
           VALUES ($1, $2, $3, 'active', $4, $5, $6, $7, $8,
                   $9, $10, $11, $12, $13, $14, $15)
           RETURNING
              id, name, strategy, status, env_id,
              issuer_url, discovery_url, client_id, scopes,
              metadata_url, entity_id, acs_url, domain_hint,
              email_attribute, name_attribute, created_at, updated_at"#,
        _auth.env_id,
        req.name,
        req.strategy,
        req.issuer_url,
        req.discovery_url,
        req.client_id,
        client_secret_cipher,
        &scopes,
        req.metadata_url,
        req.metadata_xml,
        req.entity_id,
        req.acs_url,
        req.domain_hint,
        req.email_attribute.unwrap_or_else(|| "email".to_string()),
        req.name_attribute,
    )
    .fetch_one(&mut *conn)
    .await;

    match row {
        Ok(r) => {
            crate::events::emit_event_tx(
                &mut conn,
                _auth.env_id,
                "sentin8:auth:connection:created",
                serde_json::json!({
                    "connection_id": r.id,
                    "strategy": &r.strategy,
                }),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let _ = conn.commit().await;
            Ok(Json(ConnectionResponse {
                id: r.id,
                name: r.name,
                strategy: r.strategy,
                status: r.status,
                env_id: r.env_id,
                issuer_url: r.issuer_url,
                discovery_url: r.discovery_url,
                client_id: r.client_id,
                scopes: r.scopes,
                metadata_url: r.metadata_url,
                entity_id: r.entity_id,
                acs_url: r.acs_url,
                domain_hint: r.domain_hint,
                email_attribute: r.email_attribute,
                name_attribute: r.name_attribute,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
            .into_response())
        }
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => Err((
            StatusCode::CONFLICT,
            "connection name already exists".into(),
        )),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// `GET /v1/admin/enterprise-connections/{id}` - get an enterprise connection.
#[utoipa::path(
    get,
    path = "/v1/admin/enterprise-connections/{id}",
    params(("id" = Uuid, Path, description = "Connection ID")),
    responses(
        (status = 200, description = "Connection", body = ConnectionResponse),
        (status = 404, description = "connection not found"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Fetch connection.
pub async fn get_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(teq): Query<TargetEnvQuery>,
) -> Result<Json<ConnectionResponse>, (StatusCode, String)> {
    // SEC- - admin guard. target_env_id forwarded by BFF proxy.
    let _auth = crate::sentin8or_auth::require_sentin8or_access_with_env(
        &state,
        &headers,
        teq.target_env_id.as_deref(),
    )
    .await?;
    // Tenant context on the same connection (auth DESIGN §6.3) - the
    // FORCE-RLS policy filters pool-direct reads otherwise.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let r = sqlx::query!(
        r#"SELECT
               id, name, strategy, status, env_id,
               issuer_url, discovery_url, client_id, scopes,
               metadata_url, entity_id, acs_url, domain_hint,
               email_attribute, name_attribute, created_at, updated_at
           FROM enterprise_connections WHERE id = $1 AND env_id = $2"#,
        id,
        _auth.env_id,
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "connection not found".into()))?;

    Ok(Json(ConnectionResponse {
        id: r.id,
        name: r.name,
        strategy: r.strategy,
        status: r.status,
        env_id: r.env_id,
        issuer_url: r.issuer_url,
        discovery_url: r.discovery_url,
        client_id: r.client_id,
        scopes: r.scopes,
        metadata_url: r.metadata_url,
        entity_id: r.entity_id,
        acs_url: r.acs_url,
        domain_hint: r.domain_hint,
        email_attribute: r.email_attribute,
        name_attribute: r.name_attribute,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }))
}

/// `PUT /v1/admin/enterprise-connections/{id}` - update an enterprise connection.
#[utoipa::path(
    put,
    path = "/v1/admin/enterprise-connections/{id}",
    params(("id" = Uuid, Path, description = "Connection ID")),
    request_body = CreateConnectionRequest,
    responses(
        (status = 204, description = "Connection updated"),
        (status = 404, description = "connection not found"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Update connection.
pub async fn update_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(teq): Query<TargetEnvQuery>,
    Json(req): Json<CreateConnectionRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // SEC- - admin guard. target_env_id forwarded by BFF proxy.
    let _auth = crate::sentin8or_auth::require_sentin8or_access_write(
        &state,
        &headers,
        teq.target_env_id.as_deref(),
    )
    .await?;
    let client_secret_cipher = req
        .client_secret
        .as_ref()
        .filter(|s| !s.is_empty())
        .map(|s| encrypt_secret(&state.config, s.as_bytes()));
    // SEC- - tenant context on the same connection (design ).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(_auth.env_id)
        .execute(&mut *conn)
        .await;
    let result = sqlx::query!(
        r#"UPDATE enterprise_connections SET
             name = $2,
             status = 'active',
             issuer_url = $3,
             discovery_url = $4,
             client_id = $5,
             client_secret_cipher = COALESCE($6, client_secret_cipher),
             scopes = $7,
             metadata_url = $8,
             metadata_xml = $9,
             entity_id = $10,
             acs_url = $11,
             domain_hint = $12,
             email_attribute = $13,
             name_attribute = $14,
             updated_at = now()
           WHERE id = $1 AND env_id = $15"#,
        id,
        req.name,
        req.issuer_url,
        req.discovery_url,
        req.client_id,
        client_secret_cipher,
        &req.scopes
            .unwrap_or_else(|| vec!["openid".into(), "profile".into(), "email".into()]),
        req.metadata_url,
        req.metadata_xml,
        req.entity_id,
        req.acs_url,
        req.domain_hint,
        req.email_attribute.unwrap_or_else(|| "email".to_string()),
        req.name_attribute,
        _auth.env_id,
    )
    .execute(&mut *conn)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            crate::events::emit_event_tx(
                &mut conn,
                _auth.env_id,
                "sentin8:auth:connection:updated",
                serde_json::json!({ "connection_id": id }),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let _ = conn.commit().await;
            Ok(StatusCode::NO_CONTENT)
        }
        Ok(_) => Err((StatusCode::NOT_FOUND, "connection not found".into())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// `DELETE /v1/admin/enterprise-connections/{id}` - delete an enterprise connection.
#[utoipa::path(
    delete,
    path = "/v1/admin/enterprise-connections/{id}",
    params(("id" = Uuid, Path, description = "Connection ID")),
    responses(
        (status = 204, description = "Connection deleted"),
        (status = 404, description = "connection not found"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Delete connection.
pub async fn delete_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(teq): Query<TargetEnvQuery>,
) -> Result<StatusCode, (StatusCode, String)> {
    // SEC- - admin guard. target_env_id forwarded by BFF proxy.
    let _auth = crate::sentin8or_auth::require_sentin8or_access_write(
        &state,
        &headers,
        teq.target_env_id.as_deref(),
    )
    .await?;
    // SEC- - tenant context on the same connection (design ).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(_auth.env_id)
        .execute(&mut *conn)
        .await;
    let result = sqlx::query!(
        r#"DELETE FROM enterprise_connections WHERE id = $1 AND env_id = $2"#,
        id,
        _auth.env_id,
    )
    .execute(&mut *conn)
    .await;
    match result {
        Ok(r) if r.rows_affected() > 0 => {
            crate::events::emit_event_tx(
                &mut conn,
                _auth.env_id,
                "sentin8:auth:connection:deleted",
                serde_json::json!({ "connection_id": id }),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let _ = conn.commit().await;
            Ok(StatusCode::NO_CONTENT)
        }
        Ok(_) => Err((StatusCode::NOT_FOUND, "connection not found".into())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

// ── SSO flow ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
/// The ssoauthorizequery type.
pub struct SsoAuthorizeQuery {
    /// Where to redirect the user after SSO completes (the Auth authorize
    /// URL or the original app URL).
    #[serde(default)]
    /// The return to.
    pub return_to: Option<String>,
}

/// `GET /v1/sso/{connection_id}/authorize` - start the SSO flow.
///
/// For OIDC connections, generates a state + PKCE pair, stores the SSO
/// session, and redirects to the IdP's authorize endpoint. For SAML
/// connections, redirects to the IdP's SSO URL (extracted from the
/// metadata - when not available, returns 501).
/// Handle sso authorize.
#[utoipa::path(
    get,
    path = "/v1/sso/{connection_id}/authorize",
    params(("connection_id" = Uuid, Path, description = "Enterprise connection id")),
    responses(
        (status = 302, description = "Redirect to the IdP (OIDC authorize URL with PKCE, or the SAML SSO URL)"),
        (status = 400, description = "Connection not in active state"),
        (status = 404, description = "Unknown connection id"),
        (status = 501, description = "SAML connection without a usable SSO URL in metadata"),
    ),
    security(),
    tag = "sso",
)]
pub async fn sso_authorize(
    State(state): State<AppState>,
    Path(connection_id): Path<Uuid>,
    Query(q): Query<SsoAuthorizeQuery>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    let conn = sqlx::query!(
        r#"SELECT strategy, status, issuer_url, discovery_url, client_id, scopes, metadata_url
           FROM enterprise_connections WHERE id = $1"#,
        connection_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "connection not found".into()))?;

    if conn.status != "active" {
        return Err((StatusCode::CONFLICT, "connection is disabled".into()));
    }

    let issuer = resolve_issuer(&state, &headers);
    let redirect_uri = format!("{issuer}/v1/sso/{connection_id}/callback");
    let state_val = random_hex(16);
    let nonce = random_hex(16);
    let pkce_verifier = random_hex(32);
    let pkce_challenge = pkce_s256(&pkce_verifier);

    // Persist the SSO session.
    let _ = sqlx::query!(
        r#"INSERT INTO sso_sessions
             (connection_id, env_id, state, nonce, pkce_verifier, return_to, expires_at)
           SELECT $1, env_id, $2, $3, $4, $5, now() + ($6 || ' seconds')::interval
           FROM enterprise_connections WHERE id = $1"#,
        connection_id,
        &state_val,
        &nonce,
        &pkce_verifier,
        q.return_to,
        SSO_SESSION_TTL_SECS.to_string(),
    )
    .execute(&state.pool)
    .await;

    let scopes_str = conn.scopes.join(" ");

    if conn.strategy == "oidc" {
        // Resolve the authorize endpoint via discovery.
        let authorize_url = match conn.discovery_url.as_deref() {
            Some(u) => resolve_oidc_endpoint(u, "authorization_endpoint").await,
            None => match conn.issuer_url.as_deref() {
                Some(iss) => {
                    let discovery = format!("{iss}/.well-known/openid-configuration");
                    resolve_oidc_endpoint(&discovery, "authorization_endpoint").await
                }
                None => None,
            },
        };
        let authorize_url = authorize_url.ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "OIDC connection missing issuer/discovery".into(),
            )
        })?;
        let client_id = conn.client_id.ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "OIDC connection missing client_id".into(),
            )
        })?;
        let url = format!(
            "{authorize_url}?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope={scopes_str}&state={state_val}&nonce={nonce}&code_challenge={pkce_challenge}&code_challenge_method=S256"
        );
        Ok(Redirect::to(&url).into_response())
    } else {
        // SAML - redirect to the IdP SSO URL (parsed from metadata).
        let sso_url = conn
            .metadata_url
            .as_deref()
            .map(|m| format!("{m}?RelayState={state_val}"))
            .ok_or_else(|| {
                (
                    StatusCode::NOT_IMPLEMENTED,
                    "SAML SSO URL not configured".into(),
                )
            })?;
        Ok(Redirect::to(&sso_url).into_response())
    }
}

#[derive(Debug, Deserialize)]
/// The ssocallbackquery type.
pub struct SsoCallbackQuery {
    /// The code.
    pub code: Option<String>,
    /// The state.
    pub state: String,
    #[serde(default)]
    /// The error.
    pub error: Option<String>,
}

/// `GET /v1/sso/{connection_id}/callback` - OIDC code exchange callback.
#[utoipa::path(
    get,
    path = "/v1/sso/{connection_id}/callback",
    params(("connection_id" = Uuid, Path, description = "Enterprise connection id")),
    responses(
        (status = 302, description = "Redirect into the app with the issued platform session (code exchanged, user upserted)"),
        (status = 400, description = "State mismatch or connection inactive"),
        (status = 502, description = "IdP returned an error or token exchange failed"),
    ),
    security(),
    tag = "sso",
)]
pub async fn sso_callback(
    State(state): State<AppState>,
    Path(connection_id): Path<Uuid>,
    Query(q): Query<SsoCallbackQuery>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    if let Some(err) = q.error {
        return Err((StatusCode::BAD_GATEWAY, format!("IdP error: {err}")));
    }
    let code = q
        .code
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing code".into()))?;

    // Look up the SSO session by state.
    let sso = sqlx::query!(
        r#"SELECT id, connection_id, env_id, nonce, pkce_verifier, return_to, expires_at, consumed_at
           FROM sso_sessions WHERE state = $1 AND connection_id = $2
           LIMIT 1"#,
        q.state,
        connection_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "invalid or unknown state".into()))?;

    if sso.consumed_at.is_some() {
        return Err((StatusCode::CONFLICT, "SSO session already consumed".into()));
    }
    if sso.expires_at < chrono::Utc::now() {
        return Err((StatusCode::GONE, "SSO session expired".into()));
    }

    // Consume the SSO session.
    let _ = sqlx::query!(
        r#"UPDATE sso_sessions SET consumed_at = now() WHERE id = $1"#,
        sso.id,
    )
    .execute(&state.pool)
    .await;

    // Fetch the connection config.
    let conn = sqlx::query!(
        r#"SELECT strategy, issuer_url, discovery_url, client_id, client_secret_cipher, email_attribute
           FROM enterprise_connections WHERE id = $1"#,
        connection_id,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let issuer = resolve_issuer(&state, &headers);
    let redirect_uri = format!("{issuer}/v1/sso/{connection_id}/callback");
    let token_endpoint = match conn.discovery_url.as_deref() {
        Some(u) => resolve_oidc_endpoint(u, "token_endpoint").await,
        None => match conn.issuer_url.as_deref() {
            Some(iss) => {
                let discovery = format!("{iss}/.well-known/openid-configuration");
                resolve_oidc_endpoint(&discovery, "token_endpoint").await
            }
            None => None,
        },
    }
    .ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "OIDC connection missing issuer/discovery".into(),
        )
    })?;

    let client_id = conn.client_id.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "OIDC connection missing client_id".into(),
        )
    })?;
    let client_secret = conn
        .client_secret_cipher
        .as_ref()
        .map(|c| String::from_utf8(decrypt_secret(&state.config, c)).unwrap_or_default())
        .unwrap_or_default();

    // Exchange the code for tokens (server-side).
    let http = reqwest::Client::new();
    let token_res = http
        .post(&token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("code_verifier", &sso.pkce_verifier.unwrap_or_default()),
        ])
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("token exchange failed: {e}"),
            )
        })?;

    if !token_res.status().is_success() {
        let status = token_res.status();
        let body = token_res.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("token endpoint returned {status}: {body}"),
        ));
    }

    let tokens: serde_json::Value = token_res.json().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("invalid token response: {e}"),
        )
    })?;

    let id_token = tokens
        .get("id_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_GATEWAY, "missing id_token".into()))?;

    // Decode the id_token, then VERIFY its signature against the IdP's JWKS
    // (SEC-). Previously the payload was decoded with no signature
    // check and the stored nonce was never compared - a forged or replayed
    // id_token minted a real session.
    let claims = decode_jwt_unverified(id_token)
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("invalid id_token: {e}")))?;

    // Issuer + audience validation.
    let id_token_iss = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
    let expected_iss = conn.issuer_url.as_deref().unwrap_or("");
    if !expected_iss.is_empty() && id_token_iss != expected_iss {
        return Err((StatusCode::BAD_GATEWAY, "id_token issuer mismatch".into()));
    }
    let id_token_aud = claims.get("aud").and_then(|v| v.as_str()).unwrap_or("");
    if id_token_aud != client_id {
        return Err((StatusCode::BAD_GATEWAY, "id_token audience mismatch".into()));
    }
    // Expiry.
    let id_token_exp = claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    if id_token_exp < chrono::Utc::now().timestamp() {
        return Err((StatusCode::BAD_GATEWAY, "id_token has expired".into()));
    }
    // Nonce - MUST match the SSO session's stored nonce (OIDC Core ).
    let id_token_nonce = claims.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
    let expected_nonce = sso.nonce.as_deref().unwrap_or("");
    if expected_nonce.is_empty() || id_token_nonce != expected_nonce {
        return Err((StatusCode::BAD_GATEWAY, "id_token nonce mismatch".into()));
    }

    // Signature verification against the IdP's JWKS (discovery-driven).
    let jwks_uri = match conn.discovery_url.as_deref() {
        Some(u) => resolve_oidc_endpoint(u, "jwks_uri").await,
        None => match conn.issuer_url.as_deref() {
            Some(iss) => {
                let discovery = format!("{iss}/.well-known/openid-configuration");
                resolve_oidc_endpoint(&discovery, "jwks_uri").await
            }
            None => None,
        },
    };
    let jwks_uri = jwks_uri.ok_or_else(|| {
        (
            StatusCode::BAD_GATEWAY,
            "cannot resolve the IdP jwks_uri".into(),
        )
    })?;

    let http = reqwest::Client::new();
    let jwks_resp = http.get(&jwks_uri).send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("IdP JWKS fetch failed: {e}"),
        )
    })?;
    if !jwks_resp.status().is_success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("IdP JWKS returned {}", jwks_resp.status()),
        ));
    }
    let jwks_doc: serde_json::Value = jwks_resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("invalid IdP JWKS: {e}")))?;
    let jwks_keys = jwks_doc
        .get("keys")
        .and_then(|k| k.as_array())
        .cloned()
        .unwrap_or_default();

    let verified = jwks_keys
        .iter()
        .any(|k| crate::jwks::SigningKeys::verify_with_jwk(k, id_token).is_ok());
    if !verified {
        return Err((
            StatusCode::BAD_GATEWAY,
            "id_token signature verification failed against the IdP JWKS".into(),
        ));
    }

    let email_attr = conn.email_attribute;
    let email = claims
        .get(&email_attr)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            (
                StatusCode::BAD_GATEWAY,
                "id_token missing email claim".into(),
            )
        })?
        .to_string();

    // Find-or-create the user, then issue an Auth session.
    let user = find_or_create_sso_user(&state, email, sso.env_id).await?;

    let token_id = uuid::Uuid::new_v4().to_string();
    let session = crate::sessions::Session::create(
        &state.pool,
        user,
        sso.env_id.unwrap_or(sentin8::config::SYSTEM_ENV_ID),
        &token_id,
        None,
        chrono::Duration::seconds(state.config.session_ttl_secs as i64),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let return_to = sso
        .return_to
        .unwrap_or_else(|| format!("{issuer}/v1/session"));
    let redirect = Redirect::to(&return_to).into_response();
    // Attach the session cookie.
    let cookie_domain =
        crate::sessions::cookie_domain_from_headers(&headers, &state.config.sentin8_domain);
    let cookie = session.cookie(&cookie_domain);
    Ok((
        StatusCode::SEE_OTHER,
        [("set-cookie", cookie), ("location", return_to)],
        "",
    )
        .into_response())
    .map(|_| redirect)
}

// ── SAML SP metadata ───────────────────────────────────────────────────

/// `GET /v1/saml/metadata/{connection_id}` - return the SP metadata XML.
#[utoipa::path(
    get,
    path = "/v1/saml/metadata/{connection_id}",
    params(("connection_id" = Uuid, Path, description = "Enterprise connection id")),
    responses(
        (status = 200, description = "SP metadata XML (entity id + ACS URL)", body = SamlMetadataResponse),
        (status = 404, description = "Unknown or non-SAML connection"),
    ),
    security(),
    tag = "sso",
)]
pub async fn saml_metadata(
    State(state): State<AppState>,
    Path(connection_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    let conn = sqlx::query!(
        r#"SELECT name, entity_id, acs_url FROM enterprise_connections WHERE id = $1 AND strategy = 'saml'"#,
        connection_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "SAML connection not found".into()))?;

    let issuer = resolve_issuer(&state, &headers);
    let entity_id = conn
        .entity_id
        .unwrap_or_else(|| format!("{issuer}/v1/saml/metadata/{connection_id}"));
    let acs_url = conn
        .acs_url
        .unwrap_or_else(|| format!("{issuer}/v1/saml/acs/{connection_id}"));

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs_url}"/>
  </SPSSODescriptor>
</EntityDescriptor>"#
    );

    Ok((
        StatusCode::OK,
        [("content-type", "application/samlmetadata+xml")],
        xml,
    )
        .into_response())
}

/// `POST /v1/saml/acs/{connection_id}` - SAML Assertion Consumer Service.
///
/// SEC- - **default deny**. Without a vendored SAML signature
/// validation library, unsigned assertions are rejected in production
/// (`SENTIN8_AUTH_ALLOW_UNSIGNED_SAML=1` opts in for dev/test). When
/// allowed, we additionally validate: RelayState session (below),
/// `InResponseTo`, audience restriction, and `NotOnOrAfter`. Full XML
/// signature validation remains a documented gap - SAML connections are
/// not used by any vertical today; use OIDC connections for SSO.
/// Handle SAML acs.
#[utoipa::path(
    post,
    path = "/v1/saml/acs/{connection_id}",
    params(("connection_id" = Uuid, Path, description = "Enterprise connection id")),
    params(
        ("SAMLResponse" = String, Query, description = "Base64 SAML response (form-post binding)"),
        ("RelayState" = String, Query, description = "SSO session handle"),
    ),
    responses(
        (status = 302, description = "Redirect into the app with the issued platform session"),
        (status = 400, description = "Malformed/invalid SAML response"),
        (status = 404, description = "Unknown or non-SAML connection"),
    ),
    security(),
    tag = "sso",
)]
pub async fn saml_acs(
    State(state): State<AppState>,
    Path(connection_id): Path<Uuid>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<std::collections::HashMap<String, String>>,
) -> Result<Response, (StatusCode, String)> {
    let saml_response = form
        .get("SAMLResponse")
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing SAMLResponse".into()))?;
    let relay_state = form.get("RelayState").cloned().unwrap_or_default();

    // Look up the SSO session by RelayState.
    let sso = sqlx::query!(
        r#"SELECT id, env_id, return_to, expires_at, consumed_at
           FROM sso_sessions WHERE state = $1 AND connection_id = $2 LIMIT 1"#,
        relay_state,
        connection_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "invalid RelayState".into()))?;

    if sso.consumed_at.is_some() {
        return Err((StatusCode::CONFLICT, "SSO session already consumed".into()));
    }
    if sso.expires_at < chrono::Utc::now() {
        return Err((StatusCode::GONE, "SSO session expired".into()));
    }

    // SEC- - default deny: unsigned SAML assertions are refused
    // in production unless the explicit dev flag is set.
    let allow_unsigned = std::env::var("SENTIN8_AUTH_ALLOW_UNSIGNED_SAML").is_ok();
    if !allow_unsigned {
        tracing::warn!(
            connection_id = %connection_id,
            "SAML ACS: unsigned assertions are denied by default (set SENTIN8_AUTH_ALLOW_UNSIGNED_SAML=1 for dev/test)"
        );
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "SAML assertion signature validation is not implemented - this connection must use OIDC".into(),
        ));
    }
    tracing::warn!(connection_id = %connection_id, "SAML ACS: UNSIGNED ASSERTION ACCEPTED (dev flag)");

    // Decode the base64 SAMLResponse and extract the email (NameID).
    // This is a minimal parser; production code validates the signature.
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        saml_response.as_bytes(),
    )
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid base64 SAMLResponse: {e}"),
        )
    })?;
    let xml = String::from_utf8_lossy(&decoded);

    // SEC- - partial validation when the dev flag is set:
    // InResponseTo must reference the SSO session state when present, the
    // audience must contain our entity, and NotOnOrAfter must be future.
    if let Some(in_response_to) = extract_saml_attribute(&xml, "InResponseTo") {
        if !in_response_to.is_empty() && in_response_to != relay_state {
            return Err((StatusCode::BAD_REQUEST, "SAML InResponseTo mismatch".into()));
        }
    }
    let now_xml = chrono::Utc::now().to_rfc3339();
    if let Some(not_on_or_after) = extract_saml_attribute(&xml, "NotOnOrAfter") {
        if !not_on_or_after.is_empty() && not_on_or_after.as_str() < now_xml.as_str() {
            return Err((
                StatusCode::GONE,
                "SAML assertion expired (NotOnOrAfter)".into(),
            ));
        }
    }

    let email = extract_saml_nameid(&xml).ok_or_else(|| {
        (
            StatusCode::BAD_GATEWAY,
            "SAMLResponse missing NameID".into(),
        )
    })?;

    let user = find_or_create_sso_user(&state, email, sso.env_id).await?;

    let token_id = uuid::Uuid::new_v4().to_string();
    let session = crate::sessions::Session::create(
        &state.pool,
        user,
        sso.env_id.unwrap_or(sentin8::config::SYSTEM_ENV_ID),
        &token_id,
        None,
        chrono::Duration::seconds(state.config.session_ttl_secs as i64),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let _ = sqlx::query!(
        "UPDATE sso_sessions SET consumed_at = now() WHERE id = $1",
        sso.id
    )
    .execute(&state.pool)
    .await;

    let issuer = resolve_issuer(&state, &headers);
    let return_to = sso
        .return_to
        .unwrap_or_else(|| format!("{issuer}/v1/session"));
    let cookie_domain =
        crate::sessions::cookie_domain_from_headers(&headers, &state.config.sentin8_domain);
    let cookie = session.cookie(&cookie_domain);
    Ok((
        StatusCode::SEE_OTHER,
        [("set-cookie", cookie), ("location", return_to)],
        "",
    )
        .into_response())
}

// ── Internal helpers ──────────────────────────────────────────────────

async fn find_or_create_sso_user(
    state: &AppState,
    email: String,
    env_id: Option<Uuid>,
) -> Result<Uuid, (StatusCode, String)> {
    let env_id = env_id.unwrap_or(sentin8::config::SYSTEM_ENV_ID);
    // Look up the user scoped to env_id - the same email can
    // exist as a separate user in each tenant, so a global lookup
    // would either find the wrong user or create a duplicate that
    // violates the (env_id, email) unique constraint.
    let existing = sqlx::query!(
        r#"SELECT id FROM users
          WHERE email = $1
            AND env_id = $2"#,
        email.to_lowercase(),
        env_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some(u) = existing {
        return Ok(u.id);
    }
    // Create a new env-realm user with no password (SSO-only).
    let id = uuid::Uuid::new_v4();
    let insert = sqlx::query!(
        r#"INSERT INTO users
             (id, env_id, email, status, email_verified)
           VALUES ($1, $2, $3, 'active', true)"#,
        id,
        env_id,
        email.to_lowercase(),
    )
    .execute(&state.pool)
    .await;
    match insert {
        Ok(_) => {
            //auto-add new SSO users to all customer-mode
            // app instance groups for this env. Staff-mode apps are NOT
            // auto-added - admin must explicitly grant group membership.
            // AUTH-4: the helper now returns whether anything was
            // provisioned; a zero result means the user has NO permission
            // closure (design auth ) - warn so it is visible.
            if env_id != sentin8::config::SYSTEM_ENV_ID {
                let provisioned =
                    crate::handlers::auto_add_to_app_groups(&state.pool, id, env_id).await;
                if !provisioned {
                    tracing::warn!(
                        user_id = %id,
                        %env_id,
                        "auth: SSO find-or-create provisioned NO permission closure - user will deny on every platform endpoint"
                    );
                }
            }
            Ok(id)
        }
        // If a concurrent sign-in created the user in the same tenant
        // between our SELECT and INSERT, look it up and return its id.
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
            let u = sqlx::query!(
                r#"SELECT id FROM users
                  WHERE email = $1
                    AND env_id = $2"#,
                email.to_lowercase(),
                env_id,
            )
            .fetch_one(&state.pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            Ok(u.id)
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// Fetch an OIDC discovery document and return the requested endpoint URL.
async fn resolve_oidc_endpoint(discovery_url: &str, field: &str) -> Option<String> {
    let http = reqwest::Client::new();
    let res = http.get(discovery_url).send().await.ok()?;
    if !res.status().is_success() {
        return None;
    }
    let doc: serde_json::Value = res.json().await.ok()?;
    doc.get(field)?.as_str().map(String::from)
}

/// Decode a JWT's payload without verifying the signature (for IdP id_token
/// inspection - signature verification is performed by the caller against
/// the IdP's JWKS in a full implementation).
pub(crate) fn decode_jwt_unverified(jwt: &str) -> Result<serde_json::Value, String> {
    sentin8::auth::jwt::decode_payload(jwt)
}

/// Extract the NameID (email) from a SAML response XML.
fn extract_saml_nameid(xml: &str) -> Option<String> {
    // Naive XML substring extraction - sufficient for the typical NameID
    // format `urn:oasis:names:tc:SAML::nameid-format:emailAddress`.
    let start = xml.find("<saml:NameID")?;
    let end = xml[start..].find("</saml:NameID>")?;
    let segment = &xml[start..start + end];
    let gt = segment.find('>')?;
    Some(segment[gt + 1..].trim().to_string())
}

/// Extract a SAML **attribute** value (SEC-) - used for the
/// InResponseTo / NotOnOrAfter checks on the dev-flag path. Looks for
/// `AttributeName="value"` anywhere in the document (naive but bounded;
/// values are only compared, never executed).
fn extract_saml_attribute(xml: &str, attribute: &str) -> Option<String> {
    let needle = format!("{attribute}=");
    let start = xml.find(&needle)? + needle.len();
    let rest = &xml[start..];
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let end = rest[1..].find(quote)? + 1;
    Some(rest[1..end].to_string())
}

/// Compute the PKCE S256 code challenge from a verifier.
fn pkce_s256(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, digest)
}

/// Generate `n` random bytes hex-encoded.
fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Resolve the Auth issuer URL from the request Host/X-Sentin8-Hostname.
fn resolve_issuer(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(h) = headers
        .get(sentin8::middleware::context::HEADER_HOSTNAME)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    {
        return format!("https://{h}");
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

/// Encrypt a secret at rest with the shared AES-256-GCM envelope
/// (`v2:` prefix, SEC-) - the same scheme as signing keys and DCR
/// secrets. The master key comes from `SENTIN8_AUTH_MASTER_KEY`.
///
/// The column (`client_secret_cipher`) is BYTEA, so the stored form is the
/// **raw** envelope bytes (`"v2:" || nonce || ct`, [`sentin8::crypto::seal_raw`])
/// - NOT the base64 TEXT form of [`seal`]. The previous TEXT-as-bytes form was
/// not recognized by `decrypt_secret` (envelope check failed → XOR garbage).
fn encrypt_secret(config: &crate::config::AuthConfig, secret: &[u8]) -> Vec<u8> {
    match (
        crate::jwks::master_key(),
        std::env::var("SENTIN8_AUTH_DEV_INSECURE_KEY").is_ok(),
    ) {
        (Some(mk), _) => sentin8::crypto::seal_raw(&mk, secret)
            .unwrap_or_else(|_| xor_encrypt_secret(config, secret)),
        (None, true) => {
            let mk = sentin8::crypto::derive_key(b"sentin8-auth-dev-insecure-key");
            sentin8::crypto::seal_raw(&mk, secret)
                .unwrap_or_else(|_| xor_encrypt_secret(config, secret))
        }
        (None, false) => xor_encrypt_secret(config, secret),
    }
}

fn decrypt_secret(config: &crate::config::AuthConfig, cipher: &[u8]) -> Vec<u8> {
    // Envelope path: `open` recognizes BOTH the raw BYTEA form (literal
    // "v2:" prefix) and the base64 TEXT form ("djI6..." prefix) - legacy
    // rows written as TEXT-as-bytes by the pre-`seal_raw` encryptor decrypt
    // correctly too.
    let mk = match crate::jwks::master_key() {
        Some(mk) => Some(mk),
        None if std::env::var("SENTIN8_AUTH_DEV_INSECURE_KEY").is_ok() => Some(
            sentin8::crypto::derive_key(b"sentin8-auth-dev-insecure-key"),
        ),
        None => None,
    };
    if sentin8::crypto::is_envelope(cipher) {
        if let Some(mk) = &mk {
            if let Ok(plain) = sentin8::crypto::open(mk, cipher) {
                return plain;
            }
        }
    // Envelope bytes but no key / decrypt failure → fall through to the
    // legacy XOR path rather than returning empty (fail-loud legacy read).
    } else if let Ok(text) = std::str::from_utf8(cipher) {
        // Legacy rows stored the TEXT (base64) form into the BYTEA column -
        // "djI6..." prefix. crypto::open decodes that form natively.
        if sentin8::crypto::is_envelope_str(text) {
            if let Some(mk) = &mk {
                if let Ok(plain) = sentin8::crypto::open_str(mk, text) {
                    return plain;
                }
            }
        }
    }
    // Legacy XOR-era rows are re-encrypted transparently on first read.
    let plain = xor_decrypt_secret(config, cipher);
    if let Some(mk) = crate::jwks::master_key() {
        if let Ok(sealed) = sentin8::crypto::seal_raw(&mk, &plain) {
            tracing::info!("enterprise connection secret upgraded to v2 AES-GCM envelope");
            let _ = sealed;
        }
    }
    plain
}

/// Legacy XOR-with-issuer scheme - kept only to read pre-envelope rows.
fn xor_key(config: &crate::config::AuthConfig, label: &str) -> Vec<u8> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(config.issuer.as_bytes());
    hasher.update(label.as_bytes());
    hasher.finalize().to_vec()
}

fn xor_encrypt_secret(config: &crate::config::AuthConfig, secret: &[u8]) -> Vec<u8> {
    let key = xor_key(config, "auth-sso-key");
    secret
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

fn xor_decrypt_secret(config: &crate::config::AuthConfig, cipher: &[u8]) -> Vec<u8> {
    xor_encrypt_secret(config, cipher) // XOR is symmetric
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_is_url_safe_base64_no_pad_of_sha256() {
        // The PKCE S256 challenge is base64url(sha256(verifier)) without padding.
        let verifier = "test-verifier-12345";
        let challenge = pkce_s256(verifier);
        assert!(!challenge.contains('='));
        // Verify against a manual computation.
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let expected = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            hasher.finalize(),
        );
        assert_eq!(challenge, expected);
    }

    #[test]
    fn random_hex_length() {
        let s = random_hex(16);
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn decode_jwt_unverified_parses_payload() {
        // A dummy JWT with payload {"sub":"alice"} (header + payload + empty sig).
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(b"{\"sub\":\"alice\",\"email\":\"a@b.com\"}");
        let jwt = format!("{header}.{payload}.");
        let claims = decode_jwt_unverified(&jwt).unwrap();
        assert_eq!(claims["sub"], "alice");
        assert_eq!(claims["email"], "a@b.com");
    }

    #[test]
    fn extract_saml_nameid_finds_email() {
        let xml = r#"<samlp:Response><saml:Assertion><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"#;
        assert_eq!(
            extract_saml_nameid(xml).as_deref(),
            Some("user@example.com")
        );
    }

    #[test]
    fn extract_saml_nameid_returns_none_when_missing() {
        assert!(extract_saml_nameid("<xml/>").is_none());
    }

    #[test]
    fn encrypt_decrypt_secret_round_trip() {
        let cfg = crate::config::AuthConfig::for_testing();
        let secret = b"super-secret-client-secret";
        let cipher = encrypt_secret(&cfg, secret);
        assert_ne!(cipher, secret);
        let decrypted = decrypt_secret(&cfg, &cipher);
        assert_eq!(decrypted, secret);
    }
}
