// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Consent RFW proxy — Sentin8:Auth proxies consent RFW requests to the
//! vertical service that owns the matching consent flow.
//!
//! See `sentin8-.md` and
//! `sentin8-sentin8-auth-technical-design.md` .
//!
//!.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use sqlx::Row;

use crate::handlers::AppState;

/// Query params for the consent UI proxy request.
#[derive(Debug, Deserialize)]
/// The consentproxyquery type.
pub struct ConsentProxyQuery {
    /// The consent flow.
    pub consent_flow: Option<String>,
    /// The scopes.
    pub scopes: Option<String>,
    /// client identifier.
    pub client_id: Option<String>,
    /// The client name.
    pub client_name: Option<String>,
    /// The redirect URI.
    pub redirect_uri: Option<String>,
    /// The state.
    pub state: Option<String>,
    /// user identifier.
    pub user_id: Option<String>,
    /// The session token.
    pub session_token: Option<String>,
}

/// Resolve a consent flow from `sentin8_consent_flows` by matching
/// `trigger_patterns` against the requested scopes. Returns the
/// `(service_type, ui_endpoint, approve_endpoint, deny_endpoint)` for
/// the matching flow, or `None` if no flow matches.
async fn resolve_consent_flow(
    pool: &sqlx::PgPool,
    scopes: &str,
) -> Option<(String, String, String, String)> {
    // Load all consent flows and match trigger_patterns against scopes.
    let rows = sqlx::query(
        r#"SELECT service_type, ui_endpoint, approve_endpoint, deny_endpoint,
                  trigger_patterns
           FROM consent_flows"#,
    )
    .fetch_all(pool)
    .await
    .ok()?;

    let scope_list: Vec<&str> = scopes.split_whitespace().collect();

    for row in rows {
        let service_type: String = row.get("service_type");
        let ui_endpoint: String = row.get("ui_endpoint");
        let approve_endpoint: String = row.get("approve_endpoint");
        let deny_endpoint: String = row.get("deny_endpoint");
        let trigger_patterns: serde_json::Value = row.get("trigger_patterns");

        if let Some(patterns) = trigger_patterns.as_array() {
            for pattern_val in patterns {
                if let Some(pattern) = pattern_val.as_str() {
                    // Glob match: "fdx:recipient:*" matches "fdx:recipient:read"
                    let matched = if pattern.ends_with('*') {
                        let prefix = &pattern[..pattern.len() - 1];
                        scope_list.iter().any(|s| s.starts_with(prefix))
                    } else {
                        scope_list.iter().any(|s| *s == pattern)
                    };
                    if matched {
                        return Some((service_type, ui_endpoint, approve_endpoint, deny_endpoint));
                    }
                }
            }
        }
    }
    None
}

/// Resolve the vertical service URL from `sentin8_vertical_services`
/// by `service_type`, using `sentin8::config::platform_domain`.
async fn resolve_vertical_service_url(pool: &sqlx::PgPool, service_type: &str) -> Option<String> {
    let row = sqlx::query(
        r#"SELECT service_type FROM vertical_services
           WHERE service_type = $1 LIMIT 1"#,
    )
    .bind(service_type)
    .fetch_optional(pool)
    .await
    .ok()??;

    let _service_type: String = row.get("service_type");
    // Derive the URL from the service type via sentin8::config.
    // The platform domain for a service like "bank8-fdx" is
    // "https://bank8-fdx.ops.sys.{domain}".
    let domain = std::env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "sentin8.local".into());
    Some(format!(
        "https://{}:{}.ops.sys.{}",
        service_type,
        std::env::var("SENTIN8_BASE_PORT").unwrap_or_default(),
        domain
    ))
}

/// Validate the session for consent-proxy requests (SEC-).
///
/// Backlog claimed the `session_token` query param was validated —
/// it never was. Any caller could drive the consent UI/approve/deny proxy.
/// `require_user_match` — when true (approve/deny mutations), the consent
/// subject `user_id` must match the session user (design ).
async fn require_consent_session(
    state: &AppState,
    q: &ConsentProxyQuery,
    require_user_match: bool,
) -> Result<crate::sessions::Session, (StatusCode, String)> {
    let token = q
        .session_token
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "session_token is required".to_string(),
            )
        })?;
    // The requesting user must match the consent subject when provided.
    let session = crate::sessions::Session::find_by_token(&state.pool, token)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter(|s| s.is_valid())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid session".to_string()))?;
    if require_user_match {
        let user_id = q
            .user_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    "user_id is required for consent mutations".to_string(),
                )
            })?;
        if session.user_id.to_string() != user_id {
            return Err((
                StatusCode::UNAUTHORIZED,
                "session does not match the consent user".into(),
            ));
        }
    }
    Ok(session)
}

/// `GET /v1/auth/consent/ui` — proxy to the vertical service's consent UI endpoint.
///
/// Looks up the consent flow from `sentin8_consent_flows`, resolves the
/// vertical service URL, and proxies the request. If no consent flow
/// matches, returns a 404 (auth-ui falls back to the platform-default
/// consent page).
/// Handle proxy consent ui.
pub async fn proxy_consent_ui(
    State(state): State<AppState>,
    Query(q): Query<ConsentProxyQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // SEC- — validate the session before proxying (read: lenient).
    let _session = require_consent_session(&state, &q, false).await?;

    let scopes = q.scopes.as_deref().unwrap_or("");
    let flow = resolve_consent_flow(&state.pool, scopes).await.ok_or((
        StatusCode::NOT_FOUND,
        "no consent flow matches requested scopes".into(),
    ))?;

    let (service_type, ui_endpoint, _, _) = flow;
    let base_url = resolve_vertical_service_url(&state.pool, &service_type)
        .await
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("vertical service '{service_type}' not found"),
        ))?;

    let url = format!("{}{}?consent_flow={}&scopes={}&client_id={}&client_name={}&redirect_uri={}&state={}&user_id={}",
        base_url,
        ui_endpoint,
        q.consent_flow.as_deref().unwrap_or(""),
        scopes,
        q.client_id.as_deref().unwrap_or(""),
        q.client_name.as_deref().unwrap_or(""),
        q.redirect_uri.as_deref().unwrap_or(""),
        q.state.as_deref().unwrap_or(""),
        q.user_id.as_deref().unwrap_or(""),
    );

    let http = reqwest::Client::new();
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("consent UI proxy: {e}")))?;

    if !resp.status().is_success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("consent UI proxy: status {}", resp.status()),
        ));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("consent UI proxy decode: {e}"),
        )
    })?;

    Ok(Json(body))
}

/// `POST /v1/auth/consent/approve` — proxy consent approval to the vertical service.
#[derive(Debug, Deserialize, serde::Serialize)]
/// Request body for consentapproveproxy.
pub struct ConsentApproveProxyRequest {
    /// The consent flow.
    pub consent_flow: Option<String>,
    /// The scopes.
    pub scopes: Option<String>,
    /// client identifier.
    pub client_id: Option<String>,
    /// The redirect URI.
    pub redirect_uri: Option<String>,
    /// The state.
    pub state: Option<String>,
    /// user identifier.
    pub user_id: Option<String>,
    /// The selected account ids.
    pub selected_account_ids: Option<Vec<String>>,
    /// SEC- — the session authorizing this approval.
    /// The session token.
    pub session_token: Option<String>,
}

/// Handle proxy consent approve.
pub async fn proxy_consent_approve(
    State(state): State<AppState>,
    Json(req): Json<ConsentApproveProxyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // SEC- — validate the session before proxying.
    let q = ConsentProxyQuery {
        consent_flow: req.consent_flow.clone(),
        scopes: req.scopes.clone(),
        client_id: req.client_id.clone(),
        client_name: None,
        redirect_uri: req.redirect_uri.clone(),
        state: req.state.clone(),
        user_id: req.user_id.clone(),
        session_token: req.session_token.clone(),
    };
    let _session = require_consent_session(&state, &q, true).await?;

    let scopes = req.scopes.as_deref().unwrap_or("");
    let flow = resolve_consent_flow(&state.pool, scopes)
        .await
        .ok_or((StatusCode::NOT_FOUND, "no consent flow matches".into()))?;

    let (service_type, _, approve_endpoint, _) = flow;
    let base_url = resolve_vertical_service_url(&state.pool, &service_type)
        .await
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("vertical service '{service_type}' not found"),
        ))?;

    let url = format!("{}{}", base_url, approve_endpoint);
    let http = reqwest::Client::new();
    let resp = http.post(&url).json(&req).send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("consent approve proxy: {e}"),
        )
    })?;

    let body: serde_json::Value = resp.json().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("consent approve proxy decode: {e}"),
        )
    })?;

    Ok(Json(body))
}

/// `POST /v1/auth/consent/deny` — proxy consent denial to the vertical service.
#[derive(Debug, Deserialize, serde::Serialize)]
/// Request body for consentdenyproxy.
pub struct ConsentDenyProxyRequest {
    /// The consent flow.
    pub consent_flow: Option<String>,
    /// The scopes.
    pub scopes: Option<String>,
    /// The redirect URI.
    pub redirect_uri: Option<String>,
    /// The state.
    pub state: Option<String>,
    /// SEC- — the session authorizing this denial.
    /// The session token.
    pub session_token: Option<String>,
}

/// Handle proxy consent deny.
pub async fn proxy_consent_deny(
    State(state): State<AppState>,
    Json(req): Json<ConsentDenyProxyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // SEC- — validate the session before proxying.
    let q = ConsentProxyQuery {
        consent_flow: req.consent_flow.clone(),
        scopes: req.scopes.clone(),
        client_id: None,
        client_name: None,
        redirect_uri: req.redirect_uri.clone(),
        state: req.state.clone(),
        user_id: None,
        session_token: req.session_token.clone(),
    };
    let _session = require_consent_session(&state, &q, true).await?;

    let scopes = req.scopes.as_deref().unwrap_or("");
    let flow = resolve_consent_flow(&state.pool, scopes)
        .await
        .ok_or((StatusCode::NOT_FOUND, "no consent flow matches".into()))?;

    let (service_type, _, _, deny_endpoint) = flow;
    let base_url = resolve_vertical_service_url(&state.pool, &service_type)
        .await
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("vertical service '{service_type}' not found"),
        ))?;

    let url = format!("{}{}", base_url, deny_endpoint);
    let http = reqwest::Client::new();
    let resp = http
        .post(&url)
        .json(&req)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("consent deny proxy: {e}")))?;

    let body: serde_json::Value = resp.json().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("consent deny proxy decode: {e}"),
        )
    })?;

    Ok(Json(body))
}
