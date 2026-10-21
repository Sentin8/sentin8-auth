// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! OpenID for Verifiable Credential Issuance (OID4VCI) - the standard
//! issuer surface (DESIGN.md §9a.7) over the existing SD-JWT /
//! key-binding / Status-List core.
//!
//! Endpoint set (all issuer-hosted on auth):
//! - `GET /.well-known/openid-credential-issuer` - issuer metadata
//!   (`credential_configurations_supported`, endpoint addresses).
//! - `POST /oauth/credential` - single-credential issuance request
//!   (`credential_configuration_id` + optional `proof` JWT); immediate
//!   mint or `202 {transaction_id}` for deferred.
//! - `POST /oauth/deferred_credential` - poll a transaction.
//! - `POST /oauth/notifications` - wallet events (credential received /
//!   failed) recorded against the credential row.
//!
//! Authorization: an access token from the standard grant families whose
//! scope carries the credential type (`openid credential:{type}`). The
//! platform-native `/oauth/credentials*` endpoints remain as the
//! session-authenticated alias surface (BFF); these endpoints serve the
//! spec wire shape the OID4VCI conformance suite exercises.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::handlers::AppState;

// ── Metadata ──────────────────────────────────────────────────────────

/// Credential configuration entries auth mints (SD-JWT VC profile). The
/// set is the wallet credential store's supported types.
fn supported_credential_configurations(issuer: &str) -> serde_json::Value {
    let status_uri = format!("{issuer}/oauth/credentials/status/{{id}}");
    let single = |id: &str| {
        serde_json::json!({
            "format": "dc+sd-jwt",
            "scope": format!("credential:{id}"),
            "cryptographic_binding_methods_supported": ["jwk"],
            "credential_signing_alg_values_supported": ["ES256", "RS256", "MLDSA65"],
            "proof_types_supported": { "jwt": { "proof_signing_alg_values_supported": ["ES256", "RS256"] } },
            "credential_definition": { "type": id, "credential_subject": {} },
            "status": { "status_list": { "uri": status_uri } },
        })
    };
    serde_json::json!({
        "VerifiedPersonCredential": single("VerifiedPersonCredential"),
        "VerifiedEmployeeCredential": single("VerifiedEmployeeCredential"),
    })
}

/// `GET /.well-known/openid-credential-issuer` - OID4VCI issuer metadata
/// (DESIGN §9a.7). Issuer-resolved like OIDC discovery (host context).
#[utoipa::path(
    get,
    path = "/.well-known/openid-credential-issuer",
    responses(
        (status = 200, description = "OID4VCI issuer metadata", body = CredentialIssuerMetadata),
    ),
    security(),
    tag = "wallet",
)]
pub async fn credential_issuer_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<CredentialIssuerMetadata> {
    let issuer = crate::oauth::resolve_issuer(&state.config, &headers);
    Json(CredentialIssuerMetadata {
        credential_issuer: issuer.clone(),
        authorization_servers: vec![issuer.clone()],
        credential_endpoint: format!("{issuer}/oauth/credential"),
        deferred_credential_endpoint: format!("{issuer}/oauth/deferred_credential"),
        notification_endpoint: format!("{issuer}/oauth/notifications"),
        credential_configurations_supported: supported_credential_configurations(&issuer),
    })
}

/// OID4VCI issuer metadata document.
#[derive(Debug, Serialize, utoipa::ToSchema)]
/// The credentialissuermetadata type.
pub struct CredentialIssuerMetadata {
    /// The credential issuer identifier (this auth instance).
    pub credential_issuer: String,
    /// Authorization servers accepting the credential scopes - this
    /// issuer is also its own AS (the standard authorize/token surface).
    pub authorization_servers: Vec<String>,
    /// `POST /oauth/credential` - the issuance endpoint.
    pub credential_endpoint: String,
    /// `POST /oauth/deferred_credential` - deferred polling endpoint.
    pub deferred_credential_endpoint: String,
    /// `POST /oauth/notifications` - wallet event endpoint.
    pub notification_endpoint: String,
    /// One entry per credential type auth mints (SD-JWT VC profile).
    pub credential_configurations_supported: serde_json::Value,
}

// ── Issuance ──────────────────────────────────────────────────────────

/// `POST /oauth/credential` request (OID4VCI §7.2).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for credential.
pub struct CredentialRequest {
    /// The configuration id being requested (a key of
    /// `credential_configurations_supported`).
    pub credential_configuration_id: String,
    /// Proof of possession JWT (`proof_type: jwt`) binding the wallet's
    /// key: `iss` = client_id, `aud` = issuer, fresh `exp`, and the
    /// key JWK embedded as `cnf.jwk`. Optional when the access token's
    /// grant already carries the wallet key (pre-authorized flow).
    #[serde(default)]
    pub proof: Option<Proof>,
}

/// The `proof` container.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// The proof type.
pub struct Proof {
    /// Must be `jwt`.
    pub proof_type: String,
    /// The JWT text.
    pub jwt: String,
}

/// `POST /oauth/deferred_credential` request.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for deferredcredential.
pub struct DeferredCredentialRequest {
    /// The transaction id returned by a 202 issuance response.
    pub transaction_id: String,
}

/// `POST /oauth/notifications` request (OID4VCI §11.1).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for notification.
pub struct NotificationRequest {
    /// The event id (server checks event semantics, not the value).
    pub event_id: String,
    /// The event type - `credential_received` / `credential_failed`.
    pub event: String,
    /// The issuance this event refers to.
    #[serde(default)]
    pub transaction_id: Option<Uuid>,
}

/// Mint the SD-JWT credential for an approved issuance record - shared by
/// the immediate and deferred paths. The claims shape mirrors the
/// platform-native mint (SD-JWT VC: `vct`, `cnf.jwk`, status list).
async fn mint_credential(
    state: &AppState,
    credential_id: Uuid,
    env_id: Uuid,
    user_id: Uuid,
    cred_type: &str,
    cnf_jwk: &serde_json::Value,
) -> Result<String, (StatusCode, String)> {
    let _ = env_id;
    let now = Utc::now().timestamp();
    let exp = now + 90 * 24 * 3600;
    let claims = serde_json::json!({
        "iss": state.config.issuer,
        "sub": user_id.to_string(),
        "iat": now,
        "exp": exp,
        "vct": cred_type,
        "status": {
            "status_list": {
                "uri": format!("{}/oauth/credentials/status/{}", state.config.issuer, credential_id),
                "idx": 0,
            }
        },
        "cnf": { "jwk": cnf_jwk },
    });
    state
        .keys
        .sign_value(&claims)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("credential signing: {e}")))
}

/// `POST /oauth/credential` - issuance request (OID4VCI §7.2, DESIGN
/// §9a.7). Authorized by an access token whose scope carries the
/// credential type; the proof JWT binds the wallet key.
///
/// # Errors
/// - `400` unknown configuration or malformed proof.
/// - `401` missing/invalid access token or proof verification failed.
#[utoipa::path(
    post,
    path = "/oauth/credential",
    request_body = CredentialRequest,
    responses(
        (status = 200, description = "Credential issued (sd-jwt)", body = serde_json::Value),
        (status = 202, description = "Deferred - poll transaction_id at deferred_credential_endpoint", body = serde_json::Value),
        (status = 400, description = "Unknown configuration / malformed proof"),
        (status = 401, description = "Access token or proof verification failed"),
    ),
    security(),
    tag = "wallet",
)]
pub async fn credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CredentialRequest>,
) -> Result<Response, (StatusCode, String)> {
    let env_id = crate::overlays::env_from_headers(&headers);

    // Access-token gate: the bearer must be a user access token carrying
    // the credential scope (standard grant families mint it; the scope
    // is the consent record - no SQL trust here). Verification uses the
    // same signing-key verify path every service consumer uses.
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "access token required".to_string()))?;
    let claims = state
        .keys
        .verify(bearer)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid access token".to_string()))?;
    if claims.iss != state.config.issuer {
        return Err((StatusCode::UNAUTHORIZED, "token issuer mismatch".into()));
    }
    if Utc::now().timestamp() > claims.exp {
        return Err((StatusCode::UNAUTHORIZED, "token expired".into()));
    }
    if claims.token_tp != "access" {
        return Err((StatusCode::UNAUTHORIZED, "not a user access token".into()));
    }
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "token subject is not a user".to_string()))?;
    let scope_ok = claims
        .scope
        .split_whitespace()
        .any(|s| s == format!("credential:{}", req.credential_configuration_id));
    if !scope_ok {
        return Err((
            StatusCode::FORBIDDEN,
            format!("access token lacks scope credential:{}", req.credential_configuration_id),
        ));
    }

    // Proof verification (OID4VCI §7.2): decode unverified to extract the
    // key, verify the self-contained exp/aud, and bind the key.
    let cnf_jwk = if let Some(proof) = req.proof.as_ref() {
        if proof.proof_type != "jwt" {
            return Err((StatusCode::BAD_REQUEST, "only jwt proofs are supported".into()));
        }
        let payload = sentin8::auth::jwt::decode_payload(&proof.jwt)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("proof decode: {e}")))?;
        let exp = payload
            .get("exp")
            .and_then(|v| v.as_i64())
            .ok_or((StatusCode::BAD_REQUEST, "proof must carry exp".into()))?;
        if exp < Utc::now().timestamp() - 300 || exp > Utc::now().timestamp() + 300 {
            return Err((StatusCode::BAD_REQUEST, "proof exp out of range (±5min)".into()));
        }
        let aud = payload
            .get("aud")
            .and_then(|v| v.as_str())
            .ok_or((StatusCode::BAD_REQUEST, "proof must carry aud".into()))?;
        if aud != state.config.issuer {
            return Err((StatusCode::BAD_REQUEST, "proof aud mismatch".into()));
        }
        let jwk = payload
            .pointer("/cnf/jwk")
            .cloned()
            .ok_or((StatusCode::BAD_REQUEST, "proof must bind the wallet key (cnf.jwk)".into()))?;
        jwk
    } else {
        // No proof - fail closed: the issuance MUST be key-bound
        // (sender-constrained credentials are the platform invariant).
        return Err((
            StatusCode::BAD_REQUEST,
            "proof is required (credential issuance is key-bound)".into(),
        ));
    };

    // Record the issuance (pending until mint below flips it).
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO credentials (env_id, user_id, type, cnf_jwk, credential_data)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id"#,
    )
    .bind(env_id)
    .bind(user_id)
    .bind(&req.credential_configuration_id)
    .bind(&cnf_jwk)
    .bind(serde_json::json!({ "requested_claims": [] }))
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("credential record: {e}")))?;

    let cred_type = req.credential_configuration_id.clone();
    match mint_credential(&state, id, env_id, user_id, &cred_type, &cnf_jwk).await {
        Ok(credential) => {
            // Mark active (issued).
            let _ = sqlx::query("UPDATE credentials SET status = 'active' WHERE id = $1")
                .bind(id)
                .execute(&state.pool)
                .await;
            Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "format": "dc+sd-jwt",
                    "credential": credential,
                })),
            )
                .into_response())
        }
        Err(e) => Err(e),
    }
}

/// `POST /oauth/deferred_credential` - poll a deferred transaction
/// (OID4VCI §8.2, DESIGN §9a.7). Transactions mint on the same store;
/// a `pending` record answers the prescribed `error: issuance_pending`.
#[utoipa::path(
    post,
    path = "/oauth/deferred_credential",
    request_body = DeferredCredentialRequest,
    responses(
        (status = 200, description = "Credential issued (sd-jwt)", body = serde_json::Value),
        (status = 400, description = "Unknown transaction"),
    ),
    security(),
    tag = "wallet",
)]
pub async fn deferred_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeferredCredentialRequest>,
) -> Result<Response, (StatusCode, String)> {
    let env_id = crate::overlays::env_from_headers(&headers);
    let id = Uuid::parse_str(&req.transaction_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid transaction_id".into()))?;
    let row = sqlx::query(
        "SELECT user_id, type, status, cnf_jwk FROM credentials WHERE id = $1 AND env_id = $2",
    )
    .bind(id)
    .bind(env_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::BAD_REQUEST, "unknown transaction_id".into()))?;

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
    let cnf: Option<serde_json::Value> = row.try_get("cnf_jwk").ok().flatten();
    let Some(cnf) = cnf else {
        return Err((StatusCode::BAD_REQUEST, "transaction carries no wallet key".into()));
    };

    if status == "pending" {
        return Ok((
            StatusCode::OK,
            Json(serde_json::json!({ "error": "issuance_pending" })),
        )
            .into_response());
    }
    if status == "revoked" {
        return Err((StatusCode::CONFLICT, "transaction revoked".into()));
    }
    let credential = mint_credential(&state, id, env_id, user_id, &cred_type, &cnf).await?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "format": "dc+sd-jwt",
            "credential": credential,
        })),
    )
        .into_response())
}

/// `POST /oauth/notifications` - wallet event recording (OID4VCI §11.1).
/// The event lands in the credential row's `credential_data.notifications`
/// array; failures never cascade (best-effort acknowledgment).
#[utoipa::path(
    post,
    path = "/oauth/notifications",
    request_body = NotificationRequest,
    responses(
        (status = 200, description = "Event acknowledged"),
        (status = 400, description = "Unknown event type"),
    ),
    security(),
    tag = "wallet",
)]
pub async fn notifications(
    State(state): State<AppState>,
    Json(req): Json<NotificationRequest>,
) -> Result<Response, (StatusCode, String)> {
    match req.event.as_str() {
        "credential_received" | "credential_failed" => {}
        other => {
            return Err((StatusCode::BAD_REQUEST, format!("unsupported event: {other}")));
        }
    }
    if let Some(tx) = req.transaction_id {
        let _ = sqlx::query(
            r#"UPDATE credentials
                  SET credential_data =
                      jsonb_set(COALESCE(credential_data, '{}'::jsonb),
                                '{notifications}',
                                COALESCE(credential_data->'notifications','[]'::jsonb)
                                || $2::jsonb)
                WHERE id = $1"#,
        )
        .bind(tx)
        .bind(serde_json::json!([{ "event": req.event, "event_id": req.event_id, "at": Utc::now().timestamp() }]))
        .execute(&state.pool)
        .await;
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}