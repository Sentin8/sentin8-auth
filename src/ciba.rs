// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Client Initiated Backchannel Authentication (CIBA)
//!
//! CIBA allows a client to request authentication without a browser
//! redirect. The client sends a `POST /oauth/bc-authorize` with the user's
//! identifier (login_hint, sub, etc.) and receives an `auth_req_id`. The
//! client then polls `/oauth/token` with
//! `grant_type=urn:openid:params:grant-type:ciba`.
//!
//! The AS pushes the authentication request to the user's device (via a
//! decoupled device - e.g. Auth's authenticator app). The user approves
//! or denies, and the AS stores the result keyed by `auth_req_id`.
//!
//! This module implements the core CIBA flow:
//! - `POST /oauth/bc-authorize` - issue auth_req_id (+ assisted link)
//! - Token grant handler `urn:openid:params:grant-type:ciba` - poll
//! - `POST /v1/ciba/approve` - user approves/denies from their decoupled device
//! - `GET /ciba/assisted/{auth_req_id}` - Assisted Login page metadata
//! - `POST /v1/ciba/assisted/complete` - bind customer session to auth_req_id
//!
//! ## Assisted Login
//!
//! When `delivery=assisted_link`, the `bc-authorize` response includes a
//! `verification_uri_complete` (`GET /ciba/assisted/{auth_req_id}`) and a
//! `short_code`. The staff member forwards the link to the customer (SMS /
//! email / QR). The customer opens it, signs in via the standard Auth
//! hosted UI, and the page calls `POST /v1/ciba/assisted/complete` with the
//! customer's session cookie. Auth binds the `user_id` to the `auth_req_id`
//! and marks it `approved`. BFF's standard CIBA polling then completes.
//! See.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use glide::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::dtos::{CibaApproveResponse, CibaAssistedComplete, CibaAssistedPage};
use crate::events::emit_event;
use crate::handlers::{extract_session_token, AppState};
use crate::sessions::Session;

/// CIBA authorization request (POST /oauth/bc-authorize).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for CIBA.
pub struct CibaRequest {
    /// client identifier - OPTIONAL on the wire: the FAPI-CIBA push may
    /// carry ONLY the signed request object (client identity comes from
    /// the verified assertion's iss / the object's client_id claim).
    #[serde(default)]
    pub client_id: Option<String>,
    /// SEC- - client authentication (client_secret_post). Public
    /// clients omit it.
    #[serde(default)]
    /// The client secret.
    pub client_secret: Option<String>,
    /// SEC- - private_key_jwt client assertion (RFC 7523).
    #[serde(default)]
    /// The client assertion.
    pub client_assertion: Option<String>,
    /// CIBA §7.1 - the assertion type accompanying `client_assertion`
    /// (MUST be urn:ietf:params:oauth:client-assertion-type:jwt-bearer
    /// when the assertion is present).
    #[serde(default)]
    pub client_assertion_type: Option<String>,
    /// User identifier - one of: login_hint, login_hint_token, id_token_hint, sub.
    #[serde(default)]
    /// The login hint.
    pub login_hint: Option<String>,
    #[serde(default)]
    /// The login hint token.
    pub login_hint_token: Option<String>,
    #[serde(default)]
    /// The id token hint.
    pub id_token_hint: Option<String>,
    #[serde(default)]
    /// The sub.
    pub sub: Option<String>,
    #[serde(default)]
    /// The scope.
    pub scope: Option<String>,
    #[serde(default)]
    /// The user code.
    pub user_code: Option<String>,
    /// Binding message - displayed to the user on the decoupled device.
    #[serde(default)]
    /// The binding message.
    pub binding_message: Option<String>,
    /// Expiry in seconds (requested by client; AS may override).
    #[serde(default)]
    /// The requested expiry.
    pub requested_expiry: Option<u64>,
    /// Notification mode: `ping` or `poll` (default).
    #[serde(default)]
    /// The request mode.
    pub request_mode: Option<String>,
    /// Ping callback URL (required when request_mode=ping).
    #[serde(default)]
    /// The client notification token.
    pub client_notification_token: Option<String>,
    /// Delivery mode: `decoupled_device` (default) or `assisted_link`.
    /// `assisted_link` requests a front-channel verification URL
    /// (`verification_uri_complete`) that the staff forwards to the customer.
    ///Assisted Login.
    #[serde(default)]
    /// The delivery.
    pub delivery: Option<String>,
    /// Base URL for the verification link (env-scoped Auth URL).
    /// BFF passes this so the `verification_uri` in the Post message
    /// points to the customer's own Auth (e.g. `https://auth.prod.ibank.local`),
    /// not the platform Auth (`state.config.issuer`).
    #[serde(default)]
    /// The verification URI base.
    pub verification_uri_base: Option<String>,
    /// (Option A): the initiating staff member's Auth user ID.
    /// Sent by the platform BFF (Delegation Gateway) from its authenticated
    /// staff session - NOT by the staff app's request body. Embedded in the
    /// CIBA token's `act` claim (RFC 8693 ) so every customer-data
    /// access is attributable to a human.
    #[serde(default)]
    /// The act sub.
    pub act_sub: Option<String>,
    /// - staff member's email (for audit alongside `act_sub`).
    #[serde(default)]
    /// The act email.
    pub act_email: Option<String>,
    /// CIBA §7.1 signed request object (DESIGN §9a.7) - a JWT signed
    /// by the client's registered keys carrying the CIBA parameters.
    /// When present (or fetched via `request_uri`), its parameters
    /// REPLACE the unsigned form parameters.
    #[serde(default)]
    /// The request.
    pub request: Option<String>,
    /// CIBA §7.1 - https URI hosting the signed request object (same
    /// fetch mechanics as JAR `request_uri`).
    #[serde(default)]
    /// The request URI.
    pub request_uri: Option<String>,
}

/// CIBA authorization response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for CIBA.
pub struct CibaResponse {
    /// auth req identifier.
    pub auth_req_id: String,
    /// The expires in.
    pub expires_in: u64,
    /// The interval.
    pub interval: u64,
    /// Shareable approval link - present when `delivery=assisted_link`.
    /// `GET /ciba/assisted/{auth_req_id}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The verification URI complete.
    pub verification_uri_complete: Option<String>,
    /// Short code (last 6 of auth_req_id) - present when `delivery=assisted_link`.
    /// Staff reads aloud / displays for the customer to cross-check on the sign-in page.
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The short code.
    pub short_code: Option<String>,
}

/// CIBA token request parameters (extracted from the form).
#[derive(Debug, Deserialize)]
/// Request body for cibatoken.
pub struct CibaTokenRequest {
    /// auth req identifier.
    pub auth_req_id: String,
}

/// CIBA approval request (from the user's decoupled device).
///
/// The approving user is the session's user; `user_id` /
/// `org_id` / `env_id` in the body are ignored (kept as legacy wire fields
/// for wire compatibility with the authenticator app).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for cibaapproval.
pub struct CibaApprovalRequest {
    /// auth req identifier.
    pub auth_req_id: String,
    /// The approved.
    pub approved: bool,
}

/// Default poll interval (seconds).
const DEFAULT_INTERVAL: u64 = 5;

/// Default expiry (seconds).
const DEFAULT_EXPIRY: u64 = 600;

/// `POST /oauth/bc-authorize` - issue a CIBA auth_req_id.
#[utoipa::path(
    post,
    path = "/oauth/bc-authorize",
    request_body = CibaRequest,
    responses(
        (status = 200, description = "Auth request issued (CIBA backchannel)", body = CibaResponse),
        (status = 400, description = "Unknown client or invalid delivery mode"),
        (status = 401, description = "Client authentication failed"),
    ),
    security(),
    tag = "ciba",
)]
pub async fn bc_authorize(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    payload: axum::extract::Request,
) -> Result<Json<CibaResponse>, CibaAuthzError> {
    // CIBA §7.2 - the endpoint accepts application/x-www-form-urlencoded
    // (the wire format the conformance suite and every standard CIBA
    // client uses). JSON stays supported for platform-internal callers
    // (BFF); both bodies deserialize into the same CibaRequest shape.
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let req: CibaRequest = if content_type.contains("application/x-www-form-urlencoded") {
        let bytes = axum::body::to_bytes(payload.into_body(), 1024 * 1024)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        serde_urlencoded::from_bytes(&bytes)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid form body: {e}")))?
    } else {
        // Default: JSON (the platform-internal BFF contract).
        let bytes = axum::body::to_bytes(payload.into_body(), 1024 * 1024)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid JSON body: {e}")))?
    };

    // CIBA §7.1 signed request object (DESIGN §9a.7): verify the JWT
    // against the client's registered keys and let its parameters
    // REPLACE the unsigned ones (signed wins). `request` and
    // `request_uri` are mutually exclusive per spec.
    let mut req = req;
    // CIBA §7.1: resolve the signed object (may be the ONLY identity
    // carrier) before the client_id resolution.
    let signed_raw = match (req.request.as_deref(), req.request_uri.as_deref()) {
        (Some(_), Some(_)) => {
            return Err(CibaAuthzError(
                StatusCode::BAD_REQUEST,
                "invalid_request: request and request_uri are mutually exclusive"
                    .into(),
            ));
        }
        (Some(jwt), None) => Some(jwt.to_string()),
        (None, Some(uri)) => Some(
            crate::oauth::fetch_request_object(uri)
                .await
                .map_err(|e| {
                    CibaAuthzError(
                        StatusCode::BAD_REQUEST,
                        format!("invalid_request: request_uri: {e}"),
                    )
                })?,
        ),
        (None, None) => None,
    };
    // The FAPI-CIBA push may omit the FORM client_id - identity resolves
    // from the client_assertion's (verified later) iss or the request
    // object's client_id claim (CIBA §7.1).
    let form_client_id = req
        .client_id
        .clone()
        .or_else(|| {
            req.client_assertion
                .as_deref()
                .map(sentin8::auth::jwt::decode_payload)
                .and_then(|r| r.ok())
                .and_then(|c| {
                    c.get("iss").and_then(|v| v.as_str()).map(|s| s.to_string())
                })
        })
        .or_else(|| {
            signed_raw
                .as_deref()
                .map(sentin8::auth::jwt::decode_payload)
                .and_then(|r| r.ok())
                .and_then(|c| {
                    c.get("client_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
        });
    let Some(form_client_id) = form_client_id else {
        return Err(CibaAuthzError(
            StatusCode::BAD_REQUEST,
            "invalid_request: client_id is required (form, request object, or client assertion)"
                .into(),
        ));
    };
    let signed = signed_raw;
    // FAPI-CIBA (CIBA-7.1): the signed request object is MANDATORY - a
    // push with NO `request`/`request_uri` (the suite's unsigned
    // backchannel request) rejects `invalid_request`.
    if signed.is_none() {
        return Err(CibaAuthzError(
            StatusCode::BAD_REQUEST,
            "invalid_request: a signed request object is required"
                .into(),
        ));
    }
    if let Some(jwt) = signed {
        let claims = sentin8::auth::jwt::decode_payload(&jwt).map_err(|e| {
            CibaAuthzError(
                StatusCode::BAD_REQUEST,
                format!("invalid_request: signed request decode: {e}"),
            )
        })?;
        // FAPI-CIBA request-object validation (CIBA-7.1/7.1.1): claims,
        // then the alg policy, then the signature - a defective object
        // rejects 400 `invalid_request` (CIBA-13). See
        // validate_backchannel_request_object (bottom of this module).
        if let Err(e) = validate_backchannel_request_object(
            &claims,
            &form_client_id,
            &state,
            &headers,
        ) {
            return Err(CibaAuthzError(e.0, e.1));
        }
        // CIBA-7.1.1 alg policy: `none` (unsigned) and symmetric algs are
        // not legal signing algs for a backchannel request object; RS256
        // is excluded by the FAPI profile's PS/ES-only rule (the suite's
        // RS256 negative module).
        let alg = sentin8::auth::jwt::decode_header_typed::<serde_json::Value>(&jwt)
            .ok()
            .and_then(|h| h.get("alg").and_then(|a| a.as_str()).map(str::to_string));
        match alg.as_deref() {
            Some("none") => {
                return Err(CibaAuthzError(
                    StatusCode::BAD_REQUEST,
                    "invalid_request: request object signing alg 'none' is not permitted"
                        .into(),
                ));
            }
            Some(a) if a.starts_with("HS") || a == "RS256" => {
                return Err(CibaAuthzError(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "invalid_request: request object signing alg {a} is not permitted"
                    ),
                ));
            }
            _ => {}
        }
        crate::oauth::verify_client_signed_jwt(&state, &form_client_id, &jwt)
            .await
            .map_err(|e| {
                CibaAuthzError(
                    StatusCode::BAD_REQUEST,
                    format!("invalid_request: {e}"),
                )
            })?;
        // Signed parameters REPLACE the unsigned ones (CIBA §7.1). Only
        // CIBA parameters are overlaid - client identity comes from the
        // authenticated client, never from the JWT alone.
        let overlay = |field: &str, target: &mut Option<String>| {
            if let Some(v) = claims.get(field).and_then(|v| v.as_str()) {
                *target = Some(v.to_string());
            }
        };
        overlay("scope", &mut req.scope);
        overlay("user_code", &mut req.user_code);
        overlay("binding_message", &mut req.binding_message);
        overlay("client_notification_token", &mut req.client_notification_token);
        overlay("login_hint", &mut req.login_hint);
        overlay("login_hint_token", &mut req.login_hint_token);
        overlay("id_token_hint", &mut req.id_token_hint);
        if let Some(v) = claims.get("sub").and_then(|v| v.as_str()) {
            req.sub = Some(v.to_string());
        }
        if let Some(v) = claims.get("requested_expiry").and_then(|v| v.as_i64()) {
            req.requested_expiry = Some(v.unsigned_abs() as u64);
        }
        if let Some(v) = claims.get("request_mode").and_then(|v| v.as_str()) {
            req.request_mode = Some(v.to_string());
        }
        // The request_mode may live inside the CIBA `params` object
        // (spec placement) - honor both shapes.
        if let Some(v) = claims
            .get("params")
            .and_then(|p| p.get("request_mode"))
            .and_then(|v| v.as_str())
        {
            req.request_mode = Some(v.to_string());
        }
    }

    // CIBA-8: when a client_assertion is presented, the request MUST
    // carry the exact assertion type
    // (urn:ietf:params:oauth:client-assertion-type:jwt-bearer) - absent,
    // misspelled, or different → invalid_request.
    if req.client_assertion.is_some() {
        const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
        match req.client_assertion_type.as_deref() {
            Some(t) if t == JWT_BEARER => {}
            _ => {
                return Err(CibaAuthzError(
                    StatusCode::BAD_REQUEST,
                    "invalid_request: client_assertion_type must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                        .into(),
                ));
            }
        }
    }

    // Client auth on the backchannel authorize
    // endpoint: confidential clients MUST authenticate; public clients are
    // resolved by client_id (bound to the polling client).
    let client = crate::oauth::authenticate_client(
        &state,
        &headers,
        Some(form_client_id.as_str()),
        req.client_secret.as_deref(),
        req.client_assertion.as_deref(),
        true,
        true,
    )
    .await
    .map_err(CibaAuthzError::from)?;

    // - fapi_ciba profile constraints: under the FAPI-CIBA
    // profile the binding_message is MANDATORY (the user must be able to
    // verify what they are approving on the decoupled device) and client
    // auth must be private_key_jwt or mTLS (FAPI client auth rules).
    let profile = crate::oauth::resolve_security_profile(&state.pool, &headers, "env").await;
    if let Some(fapi) = crate::fapi::FapiProfile::from_str(&profile.profile) {
        if (matches!(
            fapi,
            crate::fapi::FapiProfile::Fapi20 | crate::fapi::FapiProfile::Fapi20MessageSigning
        ) || profile.profile == "fapi_ciba")
            && (!crate::fapi::FapiProfile::from_str(&profile.profile)
                .map(|f| f.is_auth_method_allowed(client.auth_method))
                .unwrap_or(true)
                || (profile.profile == "fapi_ciba"
                    && !matches!(
                        client.auth_method,
                        "private_key_jwt" | "tls_client_auth" | "self_signed_tls_client_auth"
                    )))
        {
            return Err(CibaAuthzError(
                StatusCode::UNAUTHORIZED,
                format!(
                    "invalid_client: client authentication method '{}' is not permitted under the fapi_ciba profile",
                    client.auth_method
                ),
            ));
        }
        if profile.profile == "fapi_ciba" {
            if let Err(e) = crate::experimental::validate_fapi_ciba_request(
                req.binding_message.as_deref(),
                // DPoP presence is enforced on the token polling request
                // (handle_ciba_token) - here the binding message is the
                // request-time constraint.
                true,
            ) {
                return Err(CibaAuthzError(
                    StatusCode::BAD_REQUEST,
                    format!("invalid_request: {e}"),
                ));
            }
        }
    }

    // CIBA §7.1 - exactly ONE hint parameter per request: multiple
    // hints (the suite's multiple-hints negative) reject
    // `invalid_request` - the user identifier would be ambiguous.
    let hint_count = [
        req.login_hint.is_some(),
        req.login_hint_token.is_some(),
        req.id_token_hint.is_some(),
        req.sub.is_some(),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    if hint_count > 1 {
        return Err(CibaAuthzError(
            StatusCode::BAD_REQUEST,
            "invalid_request: exactly one of login_hint, login_hint_token, id_token_hint, or sub is required"
                .into(),
        ));
    }
    // Validate that a user identifier is present.
    let user_identifier = req
        .login_hint
        .as_ref()
        .or(req.login_hint_token.as_ref())
        .or(req.id_token_hint.as_ref())
        .or(req.sub.as_ref())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "invalid_request: one of login_hint, login_hint_token, id_token_hint, or sub is required".into(),
            )
        })?;

    // (OIDC CIBA §4.4, DESIGN §9a.3) - ping-mode delivery: the client
    // must supply a client_notification_token, and its registration must
    // carry a backchannel_client_notification_endpoint. The token is
    // stored with the request; the endpoint is resolved at approval time
    // (registration is server-side truth - a request-body URL would be
    // an SSRF surface).
    // CIBA §5.2/§7.1: ping vs poll is signaled by the CLIENT - a
    // request carrying `client_notification_token` (and no explicit
    // request_mode) is a PING request: the AS notifies the client's
    // backchannel endpoint at approval time.
    let request_mode = req
        .request_mode
        .clone()
        .or_else(|| {
            (req.client_notification_token.is_some()).then(|| "ping".to_string())
        })
        .unwrap_or_else(|| "poll".to_string());
    if request_mode == "ping" {
        if req.client_notification_token.as_deref().unwrap_or("").is_empty() {
            return Err(CibaAuthzError(
                StatusCode::BAD_REQUEST,
                "invalid_request: client_notification_token is required for ping mode".into(),
            ));
        }
        // The client row is env-RLS gated - the authorize/PAR paths
        // read it under the SYSTEM env context (`with_client_env`
        // pattern); a bare pool query sees zero rows.
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(crate::config::SYSTEM_ENV_ID)
            .execute(&mut *tx)
            .await;
        let has_endpoint = sqlx::query_scalar::<_, Option<String>>(
            r#"SELECT backchannel_client_notification_endpoint
                 FROM oauth_clients WHERE client_id = $1"#,
        )
        .bind(&form_client_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .flatten()
        .is_some();
        tx.commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if !has_endpoint {
            return Err(CibaAuthzError(
                StatusCode::BAD_REQUEST,
                "invalid_request: no backchannel_client_notification_endpoint registered - use poll".into(),
            ));
        }
    } else if request_mode != "poll" {
        return Err(CibaAuthzError(
            StatusCode::BAD_REQUEST,
            format!("invalid_request: unsupported request_mode {request_mode}"),
        ));
    }

    // Two UUIDs concatenate to a 256-bit auth_req_id - the suite's
    // EnsureRecommendedAuthenticationRequestIdEntropy expects >= 160
    // bits of entropy (CIBA §6.2).
    let auth_req_id = format!("{}-{}", Uuid::new_v4(), Uuid::new_v4());
    let expires_in = req
        .requested_expiry
        .unwrap_or(DEFAULT_EXPIRY)
        .min(DEFAULT_EXPIRY);

    // Store the CIBA request in Valkey keyed by auth_req_id.
    // : staff identity is stored as the `act` chain - used by the CIBA
    // token grant to attribute the delegated token to the initiating staff
    // member. Only the platform BFF sends these fields.
    // Holder-of-key (CIBA §11.2 / FAPI): when the client authenticated
    // with a client certificate, bind the cert thumbprint to the grant -
    // the TOKEN POLL must present the SAME certificate.
    let mut request_data = serde_json::json!({
        "auth_req_id": auth_req_id,
        "client_id": form_client_id,
        "user_identifier": user_identifier,
        "scope": req.scope,
        "binding_message": req.binding_message,
        "status": "pending",
        "created_at": Utc::now().timestamp(),
        "user_id": null,
        "org_id": null,
        "env_id": null,
        "act_sub": req.act_sub,
        "act_email": req.act_email,
        // DESIGN §9a.3 - ping-mode delivery state.
        "request_mode": request_mode,
        "client_notification_token": req.client_notification_token,
    });    if let Some((thumb, _)) = crate::mtls::extract_mtls_identity(&headers) {
        if !thumb.is_empty() {
            if let Some(o) = request_data.as_object_mut() {
                o.insert("mtls_thumb".into(), serde_json::json!(thumb));
            }
        }
    }


    let client = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let conn = client;

    let key = format!("auth:ciba:{auth_req_id}");
    let _: () = conn
        .set_ex(&key, request_data.to_string(), expires_in)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Assisted Login : generate a shareable front-channel link.
    let delivery = req.delivery.as_deref().unwrap_or("decoupled_device");
    let issuer_base = req
        .verification_uri_base
        .as_deref()
        .unwrap_or(state.config.issuer.as_str())
        .trim_end_matches('/');
    let (verification_uri_complete, short_code) = if delivery == "assisted_link" {
        let link = format!("{issuer_base}/ciba/assisted/{auth_req_id}");
        let code = auth_req_id.replace('-', "");
        let code_len = code.len();
        let start = code_len.saturating_sub(6);
        let short = code[start..].to_string();
        (Some(link), Some(short))
    } else {
        (None, None)
    };

    // Post integration (D2, RS §3): for decoupled_device delivery, look up
    // the user and queue a notification in auth's LOCAL `post_outbox` so
    // the post pusher delivers it to Sentin8:Post `POST /v1/send` (DBX
    // / DBX-POST-3). This closes the loop: the customer gets a push
    // notification asking them to approve the CIBA request, instead of
    // having to open the app manually.
    // (The old code INSERTed directly into a phantom `inbox` table - auth
    // has no inbox table and no grant - so the notification silently
    // never landed. The local post_outbox is the durable, retried path.)
    if delivery == "decoupled_device" {
        if let Some(user) = lookup_user_by_identifier(&state.pool, user_identifier).await {
            // Use the env-scoped Auth URL passed by BFF for the verification
            // link, falling back to the platform issuer. BFF knows the
            // correct env-scoped Auth URL (e.g. https://auth.prod.ibank.local)
            // because it resolved it via resolve_env_sentin8_auth_url before calling
            // bc-authorize.
            let issuer = req
                .verification_uri_base
                .as_deref()
                .unwrap_or(state.config.issuer.as_str())
                .trim_end_matches('/');
            let verification_uri = format!("{issuer}/ciba/assisted/{auth_req_id}");
            let binding_msg = req.binding_message.as_deref().unwrap_or("(none)");
            crate::events::emit_post_notification(
                &state.pool,
                user.env_id,
                "auth.ciba.request",
                "security",
                "high",
                Some(user.id),
                user.email.as_deref(),
                "Approve sign-in request",
                &format!(
                    "A teller is requesting access to your account.\n\nBinding message: {binding_msg}\n\nTo approve or deny this request, open the following link:\n{verification_uri}"
                ),
                serde_json::json!({
                    "auth_req_id": auth_req_id,
                    "verification_uri": verification_uri,
                    "binding_message": req.binding_message,
                }),
            )
            .await;
            tracing::info!(auth_req_id = %auth_req_id, user_id = %user.id, verification_uri = %verification_uri, "post: CIBA notification queued");
        }
    }

    Ok(Json(CibaResponse {
        auth_req_id,
        expires_in,
        interval: DEFAULT_INTERVAL,
        verification_uri_complete,
        short_code,
    }))
}

/// `GET /ciba/assisted/{auth_req_id}` - Assisted Login page metadata.
///
/// Returns the CIBA request details so the Flutter Auth UI can render the
/// assisted sign-in page: `binding_message`, `short_code`, requesting client,
/// and requested scopes. The UI then calls `POST /v1/ciba/assisted/complete`
/// after the customer signs in.
/// Handle CIBA assisted page.
#[utoipa::path(
    get,
    path = "/v1/ciba/assisted/{auth_req_id}",
    params(("auth_req_id" = String, Path, description = "CIBA auth request id")),
    responses(
        (status = 200, description = "Assisted sign-in page details (binding_message, short_code, client, scopes)", body = crate::dtos::CibaAssistedPage),
        (status = 404, description = "Unknown or expired auth_req_id"),
    ),
    security(),
    tag = "ciba",
)]
pub async fn ciba_assisted_page(
    State(state): State<AppState>,
    Path(auth_req_id): Path<String>,
) -> Result<Json<CibaAssistedPage>, (StatusCode, String)> {
    let key = format!("auth:ciba:{auth_req_id}");
    let client = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let conn = client;

    let data: Option<String> = conn
        .get(&key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let data = data.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "invalid or expired auth_req_id".into(),
        )
    })?;
    let data: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let status = data["status"].as_str().unwrap_or("pending");
    let code = auth_req_id.replace('-', "");
    let code_len = code.len();
    let start = code_len.saturating_sub(6);
    let short_code = code[start..].to_string();

    Ok(Json(CibaAssistedPage {
        auth_req_id,
        binding_message: data["binding_message"].clone(),
        scope: data["scope"].clone(),
        client_id: data["client_id"].clone(),
        status: status.to_string(),
        short_code,
    }))
}

/// `POST /v1/ciba/assisted/complete` - bind customer session to CIBA request.
///
/// Called by the Flutter Assisted Login page after the customer signs in.
/// Reads the customer's `__session` cookie, resolves the `user_id` /
/// `org_id` / `env_id`, and marks the CIBA request `approved`. Single-use:
/// a second call returns the existing status without re-binding.
/// Handle CIBA assisted complete.
#[utoipa::path(
    post,
    path = "/v1/ciba/assisted/{auth_req_id}/complete",
    params(("auth_req_id" = String, Path, description = "CIBA auth request id")),
    responses(
        (status = 200, description = "CIBA request bound to the signed-in customer (single-use)", body = crate::dtos::CibaAssistedComplete),
        (status = 401, description = "No customer session"),
        (status = 404, description = "Unknown auth_req_id"),
        (status = 409, description = "Already completed (status returned, no re-bind)"),
    ),
    security(),
    tag = "ciba",
)]
pub async fn ciba_assisted_complete(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(auth_req_id): Path<String>,
) -> Result<Json<CibaAssistedComplete>, (StatusCode, String)> {
    // Resolve the customer's session from the __session cookie.
    let token_id = extract_session_token(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "no session - sign in first".into(),
        )
    })?;
    // SEC- - mutating session endpoint: CSRF-gated (Bearer exempt).
    crate::handlers::check_csrf(&headers, &token_id)?;
    let session = Session::find_by_token(&state.pool, &token_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "invalid or expired session".into(),
            )
        })?;
    if !session.is_valid() {
        return Err((StatusCode::UNAUTHORIZED, "session expired".into()));
    }

    let key = format!("auth:ciba:{auth_req_id}");
    let client = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let conn = client;

    let data: Option<String> = conn
        .get(&key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let data = data.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "invalid or expired auth_req_id".into(),
        )
    })?;
    let mut data: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Idempotent: if already approved/denied, return the existing status.
    let current_status = data["status"].as_str().unwrap_or("pending");
    if current_status != "pending" {
        return Ok(Json(CibaAssistedComplete {
            status: current_status.to_string(),
            already_completed: Some(true),
        }));
    }

    // Bind the customer's identity and mark approved.
    // Resolve org_id from the session's env (the Session struct no longer
    // carries org_id; sentin8_sys_environments does).
    let org_id: Uuid = sqlx::query_scalar("SELECT org_id FROM sys.environments WHERE id = $1")
        .bind(session.env_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .unwrap_or(crate::config::SYSTEM_ORG_ID);
    if let Some(obj) = data.as_object_mut() {
        obj.insert("status".into(), serde_json::json!("approved"));
        obj.insert(
            "user_id".into(),
            serde_json::json!(session.user_id.to_string()),
        );
        obj.insert("org_id".into(), serde_json::json!(org_id.to_string()));
        obj.insert(
            "env_id".into(),
            serde_json::json!(session.env_id.to_string()),
        );
    }

    let _: () = conn
        .set_ex(&key, data.to_string(), DEFAULT_EXPIRY)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(CibaAssistedComplete {
        status: "approved".to_string(),
        already_completed: None,
    }))
}

/// `POST /v1/ciba/approve` - user approves or denies from their device.
///
/// SEC- - the approving user is the **session's** user; the
/// `user_id` field in the body is ignored. Knowledge of an `auth_req_id`
/// alone can no longer bind an arbitrary user to a CIBA request.
/// Handle CIBA approve.
#[utoipa::path(
    post,
    path = "/v1/ciba/approve",
    request_body = CibaApprovalRequest,
    responses(
        (status = 200, description = "Approval recorded (the approving user is the SESSION's user)", body = crate::dtos::CibaApproveResponse),
        (status = 400, description = "Unknown auth_req_id"),
        (status = 401, description = "No session - approval requires an authenticated user"),
    ),
    security(),
    tag = "ciba",
)]
pub async fn ciba_approve(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CibaApprovalRequest>,
) -> Result<Json<CibaApproveResponse>, (StatusCode, String)> {
    // Resolve the approving user from their session (cookie or Bearer).
    let session_token = crate::handlers::extract_session_token(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "session required to approve a CIBA request".into(),
        )
    })?;
    // SEC- - mutating session endpoint: CSRF-gated (Bearer exempt).
    crate::handlers::check_csrf(&headers, &session_token)?;
    let session = crate::sessions::Session::find_by_token(&state.pool, &session_token)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter(|s| s.is_valid())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid session".into()))?;
    let approving_user_id = session.user_id;

    let key = format!("auth:ciba:{}", req.auth_req_id);
    let client = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let conn = client;

    let data: Option<String> = conn
        .get(&key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let data = data.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "invalid or expired auth_req_id".into(),
        )
    })?;

    let mut data: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Some(obj) = data.as_object_mut() {
        let status = if req.approved { "approved" } else { "denied" };
        obj.insert("status".into(), serde_json::json!(status));
        // SEC- - the session's user is the approving user.
        obj.insert(
            "user_id".into(),
            serde_json::json!(approving_user_id.to_string()),
        );
        obj.insert(
            "org_id".into(),
            serde_json::json!(uuid::Uuid::nil().to_string()),
        );
        obj.insert(
            "env_id".into(),
            serde_json::json!(session.env_id.to_string()),
        );
    }

    let _: () = conn
        .set_ex(&key, data.to_string(), DEFAULT_EXPIRY)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    emit_event(
        &state.pool,
        session.env_id,
        "sentin8:auth:ciba:approved",
        serde_json::json!({
            "auth_req_id": req.auth_req_id,
            "user_id": approving_user_id,
        }),
    )
    .await;

    // (OIDC CIBA §4.5, DESIGN §9a.3) - ping-mode notification: when
    // the request chose ping delivery, POST the notification to the
    // client's registered backchannel_client_notification_endpoint with
    // the client_notification_token as a bearer. Best-effort: a ping
    // failure never fails the approval (the client still polls); it is
    // logged for operators.
    if data["request_mode"].as_str() == Some("ping") {
        let client_id = data["client_id"].as_str().unwrap_or_default().to_string();
        let notification_token = data["client_notification_token"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        // The client row is env-RLS gated - read it under the SYSTEM
        // env context (the `with_client_env` pattern); a bare pool
        // query sees zero rows and the ping silently never fires.
        let endpoint = if let Ok(mut tx) = state.pool.begin().await {
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                .bind(crate::config::SYSTEM_ENV_ID)
                .execute(&mut *tx)
                .await;
            let ep = sqlx::query_scalar::<_, Option<String>>(
                r#"SELECT backchannel_client_notification_endpoint
                     FROM oauth_clients WHERE client_id = $1"#,
            )
            .bind(&client_id)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten()
            .flatten();
            let _ = tx.commit().await;
            ep
        } else {
            None
        };
        {
            if let Some(url) = endpoint.filter(|u| !u.is_empty()) {
                tokio::spawn(async move {
                    let payload = serde_json::json!({
                        "auth_req_id": req.auth_req_id,
                    });
                    // CIBA-10.2: the ping response's redirect (3xx) is
                    // NOT followed - a redirect to a different URI is the
                    // client misbehaving; following one would hide it.
                    let client = reqwest::Client::builder()
                        .redirect(reqwest::redirect::Policy::none())
                        .build()
                        .unwrap_or_else(|_| reqwest::Client::new());
                    match client
                        .post(&url)
                        .bearer_auth(&notification_token)
                        .json(&payload)
                        .timeout(std::time::Duration::from_secs(10))
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status().is_success() => {
                            tracing::info!(
                                auth_req_id = %req.auth_req_id,
                                url = %url,
                                "ciba: ping notification delivered"
                            );
                        }
                        Ok(resp) => {
                            tracing::warn!(
                                auth_req_id = %req.auth_req_id,
                                url = %url,
                                status = %resp.status(),
                                "ciba: ping notification endpoint answered non-2xx"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                auth_req_id = %req.auth_req_id,
                                url = %url,
                                error = %e,
                                "ciba: ping notification delivery failed"
                            );
                        }
                    }
                });
            }
        }
    }

    let status = if req.approved { "approved" } else { "denied" };
    Ok(Json(CibaApproveResponse {
        status: status.to_string(),
    }))
}

/// Poll the CIBA auth_req_id. Returns `Ok(Some(user_id, org_id, env_id, scope))`
/// if approved, `Ok(None)` if still pending, `Err` if denied or expired.
/// Handle poll CIBA.
pub async fn poll_ciba(
    state: &AppState,
    auth_req_id: &str,
) -> Result<Option<(Uuid, Option<Uuid>, Option<Uuid>, String)>, String> {
    let key = format!("auth:ciba:{auth_req_id}");
    let client = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth")
        .await
        .map_err(|e| e.to_string())?;
    let conn = client;

    let data: Option<String> = conn.get(&key).await.map_err(|e| e.to_string())?;

    let data = data.ok_or_else(|| "invalid or expired auth_req_id".to_string())?;
    let data: serde_json::Value = serde_json::from_str(&data).map_err(|e| e.to_string())?;

    let status = data["status"].as_str().unwrap_or("pending");
    match status {
        "approved" => {
            let user_id = data["user_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or("missing user_id in approved CIBA request")?;
            let org_id = data["org_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok());
            let env_id = data["env_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok());
            let scope = data["scope"].as_str().unwrap_or("openid").to_string();
            Ok(Some((user_id, org_id, env_id, scope)))
        }
        "denied" => Err("access_denied".into()),
        _ => Ok(None), // pending
    }
}

// ── Post helper (Epic ) ─────────────────────────────────────────

struct UserLookup {
    id: uuid::Uuid,
    env_id: uuid::Uuid,
    email: Option<String>,
}

/// Look up an sentin8_auth_users row by email, sub (UUID string), or external_id.
/// Returns the user's id, env, and contact email so the post_outbox
/// notification (D2, RS §3) can address the customer. The tenant context
/// is resolved from the user's env at the insert site.
async fn lookup_user_by_identifier(pool: &sqlx::PgPool, identifier: &str) -> Option<UserLookup> {
    use sqlx::Row;
    // Try as UUID (sub claim).
    if let Ok(uid) = uuid::Uuid::parse_str(identifier) {
        if let Some(r) = sqlx::query("SELECT id, env_id, email FROM users WHERE id = $1")
            .bind(uid)
            .fetch_optional(pool)
            .await
            .ok()?
        {
            return Some(UserLookup {
                id: r.get("id"),
                env_id: r.get("env_id"),
                email: r.get("email"),
            });
        }
    }
    // Try as email.
    if let Some(r) = sqlx::query("SELECT id, env_id, email FROM users WHERE email = $1")
        .bind(identifier)
        .fetch_optional(pool)
        .await
        .ok()?
    {
        return Some(UserLookup {
            id: r.get("id"),
            env_id: r.get("env_id"),
            email: r.get("email"),
        });
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciba_request_requires_user_identifier() {
        let req = CibaRequest {
            client_id: Some("client_123".to_string()),
            client_secret: None,
            client_assertion: None,
            client_assertion_type: None,
            login_hint: None,
            login_hint_token: None,
            id_token_hint: None,
            sub: None,
            scope: None,
            user_code: None,
            binding_message: None,
            requested_expiry: None,
            request_mode: None,
            client_notification_token: None,
            delivery: None,
            act_sub: None,
            act_email: None,
            verification_uri_base: None,
            request: None,
            request_uri: None,
        };
        assert!(req.login_hint.is_none());
        assert_eq!(req.delivery.as_deref(), None);
    }

    #[test]
    fn ciba_request_with_login_hint() {
        let req = CibaRequest {
            client_id: Some("client_123".to_string()),
            client_secret: None,
            client_assertion: None,
            client_assertion_type: None,
            login_hint: Some("user@example.com".into()),
            login_hint_token: None,
            id_token_hint: None,
            sub: None,
            scope: Some("openid".into()),
            user_code: None,
            binding_message: Some("Approve login?".into()),
            requested_expiry: Some(120),
            request_mode: Some("poll".into()),
            client_notification_token: None,
            delivery: Some("assisted_link".into()),
            act_sub: None,
            act_email: None,
            verification_uri_base: None,
            request: None,
            request_uri: None,
        };
        assert_eq!(req.login_hint.as_deref(), Some("user@example.com"));
        assert_eq!(req.binding_message.as_deref(), Some("Approve login?"));
        assert_eq!(req.delivery.as_deref(), Some("assisted_link"));
    }

    #[test]
    fn ciba_response_serialization_decoupled() {
        // Decoupled-device mode: no verification_uri_complete / short_code.
        let resp = CibaResponse {
            auth_req_id: "req-123".into(),
            expires_in: 600,
            interval: 5,
            verification_uri_complete: None,
            short_code: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["auth_req_id"], "req-123");
        assert_eq!(json["expires_in"], 600);
        assert_eq!(json["interval"], 5);
        assert!(json.get("verification_uri_complete").is_none());
        assert!(json.get("short_code").is_none());
    }

    #[test]
    fn ciba_response_serialization_assisted() {
        let resp = CibaResponse {
            auth_req_id: "req-123".into(),
            expires_in: 300,
            interval: 5,
            verification_uri_complete: Some(
                "https://auth.example.com/ciba/assisted/req-123".into(),
            ),
            short_code: Some("req123".into()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["auth_req_id"], "req-123");
        assert_eq!(
            json["verification_uri_complete"],
            "https://auth.example.com/ciba/assisted/req-123"
        );
        assert_eq!(json["short_code"], "req123");
    }

    #[test]
    fn ciba_approval_request() {
        // SEC- - the approving user comes from the session; the
        // body carries only auth_req_id + approved.
        let req = CibaApprovalRequest {
            auth_req_id: "req-123".into(),
            approved: true,
        };
        assert!(req.approved);
        // The legacy body fields are ignored on the wire.
        let parsed: CibaApprovalRequest = serde_json::from_value(serde_json::json!({
            "auth_req_id": "req-123",
            "approved": false,
            "user_id": "00000000-0000-0000-0000-000000000001",
        }))
        .unwrap();
        assert!(!parsed.approved);
    }

    #[test]
    fn ciba_poll_pending_data() {
        let data = serde_json::json!({
            "status": "pending",
            "auth_req_id": "req-123",
            "client_id": "client_123",
            "scope": "openid",
        });
        assert_eq!(data["status"], "pending");
    }

    #[test]
    fn ciba_poll_approved_data() {
        let data = serde_json::json!({
            "status": "approved",
            "auth_req_id": "req-123",
            "client_id": "client_123",
            "scope": "openid",
            "user_id": Uuid::new_v4().to_string(),
        });
        assert_eq!(data["status"], "approved");
        assert!(data["user_id"].as_str().is_some());
    }

    #[test]
    fn ciba_poll_denied_data() {
        let data = serde_json::json!({
            "status": "denied",
            "auth_req_id": "req-123",
        });
        assert_eq!(data["status"], "denied");
    }

    #[test]
    fn auth_req_id_is_unique() {
        let a = Uuid::new_v4().to_string();
        let b = Uuid::new_v4().to_string();
        assert_ne!(a, b);
    }
}

/// bc-authorize rejection type - renders as an RFC 6749 §5.2 JSON body
/// (`{"error": "...", "error_description": "..."}`). The suite's
/// backchannel checkers parse the `error` field (CIBA-13); a plain-text
/// body fails their JSON gate.
///
/// The string payload follows the `"{error_code}: {description}"`
/// convention - the code prefix splits off on render.
pub struct CibaAuthzError(pub StatusCode, pub String);

impl axum::response::IntoResponse for CibaAuthzError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = (self.0, self.1);
        if status.is_client_error() {
            let (code, desc) = match msg.split_once(": ") {
                Some((c, d)) => (c.to_string(), d.to_string()),
                None => (msg.clone(), String::new()),
            };
            let body = if desc.is_empty() {
                serde_json::json!({ "error": code })
            } else {
                serde_json::json!({ "error": code, "error_description": desc })
            };
            (status, axum::Json(body)).into_response()
        } else {
            (status, msg).into_response()
        }
    }
}

impl From<(StatusCode, String)> for CibaAuthzError {
    fn from((status, msg): (StatusCode, String)) -> Self {
        if status == StatusCode::UNAUTHORIZED {
            // Client-authentication failures answer `invalid_client`
            // (CIBA-8) - authenticate_client's messages carry no OAuth
            // code prefix, so the code is supplied here.
            return Self(status, format!("invalid_client: {msg}"));
        }
        Self(status, msg)
    }
}

/// FAPI-CIBA request-object claim validation (CIBA-7.1/7.1.1 - the
/// suite's `ValidateBackchannelRequestObjectClaims` + the negative
/// Ensure* modules): the signed members REPLACE the form ones, so the
/// object's claims are authoritative. REQUIRED members: `iss` == the
/// authenticated client_id, `aud` includes the AS (issuer |
/// token_endpoint | backchannel_authentication_endpoint), `exp`
/// within (-5min, +1h), `iat` within (-1d, +5min), `nbf` within
/// (-10min, +5min), `jti` a non-empty string. Every defect answers
/// 400 `invalid_request` (CIBA-13).
fn validate_backchannel_request_object(
    claims: &serde_json::Value,
    client_id: &str,
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let issuer = crate::oauth::resolve_issuer(&state.config, headers);
    let auds = [
        issuer.clone(),
        format!("{issuer}/oauth/token"),
        format!("{issuer}/oauth/bc-authorize"),
    ];
    let bad = |desc: &str| (StatusCode::BAD_REQUEST, format!("invalid_request: {desc}"));

    // iss (CIBA-7.1.1 REQUIRED): pins the client identity.
    match claims.get("iss").and_then(|v| v.as_str()) {
        Some(iss) if iss == client_id => {}
        _ => return Err(bad("iss is missing or does not equal the client_id")),
    }

    // aud (REQUIRED): the AS must be among the audience members.
    let aud_ok = match claims.get("aud") {
        Some(serde_json::Value::String(a)) => auds.iter().any(|x| x == a),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .any(|v| v.as_str().is_some_and(|s| auds.iter().any(|x| x == s))),
        _ => false,
    };
    if !aud_ok {
        return Err(bad("aud does not identify the authorization server"));
    }

    let now = chrono::Utc::now().timestamp();

    // exp (REQUIRED): past-beyond-skew or future-beyond-1h rejects
    // (the suite's expired-exp and 70-minutes-future negatives).
    let exp = claims.get("exp").and_then(|v| v.as_i64()).ok_or_else(|| {
        bad("exp is required on a backchannel request object")
    })?;
    if exp < now - 300 {
        return Err(bad("exp is in the past"));
    }
    if exp > now + 3600 {
        return Err(bad("exp is too far in the future"));
    }

    // iat (REQUIRED): future issuance or stale-by-more-than-a-day
    // rejects.
    let iat = claims.get("iat").and_then(|v| v.as_i64()).ok_or_else(|| {
        bad("iat is required on a backchannel request object")
    })?;
    if iat > now + 300 {
        return Err(bad("iat is in the future"));
    }
    if iat < now - 86_400 {
        return Err(bad("iat is more than one day in the past"));
    }

    // nbf (REQUIRED): the 70-minutes-past and 10-minutes-future
    // negatives bound the window.
    let nbf = claims.get("nbf").and_then(|v| v.as_i64()).ok_or_else(|| {
        bad("nbf is required on a backchannel request object")
    })?;
    if nbf < now - 600 {
        return Err(bad("nbf is too far in the past"));
    }
    if nbf > now + 300 {
        return Err(bad("nbf is in the future"));
    }

    // jti (REQUIRED): a non-empty string.
    if claims
        .get("jti")
        .and_then(|v| v.as_str())
        .map(|s| !s.trim().is_empty())
        != Some(true)
    {
        return Err(bad("jti is required (non-empty string)"));
    }

    Ok((StatusCode::OK, String::new()))
}
