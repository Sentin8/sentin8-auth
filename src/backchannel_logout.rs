// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! OIDC Back-Channel Logout
//! (https://openid.net/specs/openid-connect-backchannel-1_0.html).
//!
//! When a session ends (sign-out, token revocation, session expiry), Auth
//! sends a **logout token** (a special JWT) to every OAuth client that has a
//! `backchannel_logout_uri` registered. The logout token contains:
//! - `iss` - Auth issuer
//! - `aud` - the client_id
//! - `sub` - the user subject (optional per spec)
//! - `sid` - the session ID (optional per spec)
//! - `iat` - issued-at
//! - `jti` - unique token ID (for replay detection)
//! - `events: {"http://schemas.openid.net/event/backchannel-logout": {}}`
//! - NO `nonce`
//!
//! Endpoint: `POST /oauth/backchannel-logout` (internal - called by Auth on
//! session termination). Accepts `{ session_id, user_id }` and fans out
//! logout tokens to all registered clients.
//!
//! Also exposes `POST /v1/backchannel-logout/trigger` as a convenience for
//! the Auth sign-out handler to invoke.

use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::handlers::AppState;
use crate::jwks::SigningKeys;

/// Trigger request - fired when a session ends.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// The backchannellogouttrigger type.
pub struct BackchannelLogoutTrigger {
    /// session identifier.
    pub session_id: Uuid,
    /// user identifier.
    pub user_id: Uuid,
    /// Optional - restrict to a single client_id (e.g. for RP-initiated logout).
    #[serde(default)]
    /// client identifier.
    pub client_id: Option<String>,
}

/// Response describing the fan-out results.
#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for backchannellogout.
pub struct BackchannelLogoutResponse {
    /// The sent.
    pub sent: u32,
    /// The failed.
    pub failed: u32,
    /// The details.
    pub details: Vec<ClientResult>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
/// The clientresult type.
pub struct ClientResult {
    /// client identifier.
    pub client_id: String,
    /// The backchannel logout URI.
    pub backchannel_logout_uri: String,
    /// The status.
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The error.
    pub error: Option<String>,
}

/// Logout token JWT claims (per OIDC Back-Channel Logout ).
#[derive(Debug, Serialize)]
pub struct LogoutTokenClaims {
    /// The issuer identifier (this OP).
    pub iss: String,
    /// The audience (the client being logged out).
    pub aud: String,
    /// Issued-at (unix seconds).
    pub iat: i64,
    /// Unique token identifier (the RP's replay key).
    pub jti: String,
    /// The `events` member - names the backchannel-logout event URI.
    pub events: serde_json::Value,
    /// The logged-out subject (optional when only `sid` is delivered).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// The session identifier (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

/// Issue a logout token JWT signed with Auth's RSA key.
fn issue_logout_token(
    keys: &SigningKeys,
    issuer: &str,
    client_id: &str,
    user_id: Option<Uuid>,
    sid: Option<String>,
) -> Result<String, String> {
    // `sid` = the SESSION's persistent id (the id_token's sid claim -
    // design 9a.26: the fanout's sid MUST equal the id_token sid the
    // suite captured at login).
    let claims = LogoutTokenClaims {
        iss: issuer.to_string(),
        aud: client_id.to_string(),
        iat: Utc::now().timestamp(),
        jti: Uuid::new_v4().to_string(),
        events: serde_json::json!({
            "http://schemas.openid.net/event/backchannel-logout": {}
        }),
        sub: user_id.map(|u| u.to_string()),
        sid,
    };
    keys.sign_value(&serde_json::to_value(claims).map_err(|e| format!("serialize claims: {e}"))?)
}

/// Handler - `POST /oauth/backchannel-logout` / `POST /v1/backchannel-logout/trigger`.
/// Handle trigger backchannel logout.
#[utoipa::path(
    post,
    path = "/oauth/backchannel-logout",
    request_body = BackchannelLogoutTrigger,
    responses(
        (status = 200, description = "OIDC Back-Channel Logout token minted and delivered", body = BackchannelLogoutResponse),
        (status = 403, description = "Admin guard - internal trigger"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "oauth",
)]
pub async fn trigger_backchannel_logout(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<BackchannelLogoutTrigger>,
) -> Result<Json<BackchannelLogoutResponse>, (StatusCode, String)> {
    // internal trigger: admin guard (also backstopped by the
    // route-guard middleware at /oauth/backchannel-logout).
    let _auth =
        crate::sentin8or_auth::require_sentin8or_access_write(&state, &headers, None).await?;
    // Find all clients with a backchannel_logout_uri for this org/env.
    let rows = sqlx::query!(
        r#"SELECT client_id, backchannel_logout_uri
           FROM oauth_clients
           WHERE backchannel_logout_uri IS NOT NULL
             AND backchannel_logout_uri != ''
             AND status = 'active'
             AND ($1::text IS NULL OR client_id = $1)"#,
        req.client_id.as_deref(),
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let rows: Vec<BackchannelClientRow> = rows
        .into_iter()
        .map(|r| BackchannelClientRow {
            client_id: r.client_id,
            backchannel_logout_uri: r.backchannel_logout_uri.unwrap_or_default(),
        })
        .collect();

    let (sent, failed, details) =
        fanout_backchannel_logout(&state, req.user_id, Some(req.session_id.to_string()), req.client_id.as_deref(), &rows).await;
    Ok(Json(BackchannelLogoutResponse { sent, failed, details }))
}

/// One registered backchannel client (the fanout's row shape).
pub struct BackchannelClientRow {
    /// The client identifier.
    pub client_id: String,
    /// The client's backchannel logout URI.
    pub backchannel_logout_uri: String,
}

/// The fanout body (design 9a.26): mint + POST the logout token to every
/// client WITH a backchannel_logout_uri (optionally restricted to one
/// client). PUBLIC - the RP-initiated logout handler (oauth.rs logout)
/// calls the SAME fanout as its side effect (the Back-Channel OP plan's
/// module family).
pub async fn fanout_backchannel_logout(
    state: &crate::handlers::AppState,
    user_id: Uuid,
    sid: Option<String>,
    client_filter: Option<&str>,
    rows: &[BackchannelClientRow],
) -> (u32, u32, Vec<ClientResult>) {
    let issuer = state.config.issuer.clone();
    let _ = client_filter;
    let mut sent = 0u32;
    let mut failed = 0u32;
    let mut details = Vec::new();

    for row in rows {
        let uri = row.backchannel_logout_uri.clone();
        let logout_token = match issue_logout_token(
            &state.keys,
            &issuer,
            &row.client_id,
            Some(user_id),
            sid.clone(),
        ) {
            Ok(t) => t,
            Err(e) => {
                failed += 1;
                details.push(ClientResult {
                    client_id: row.client_id.clone(),
                    backchannel_logout_uri: uri,
                    status: "error".into(),
                    error: Some(format!("token signing failed: {e}")),
                });
                continue;
            }
        };

        let client_result = send_logout_token(&uri, &logout_token).await;
        match client_result {
            Ok(()) => {
                sent += 1;
                details.push(ClientResult {
                    client_id: row.client_id.clone(),
                    backchannel_logout_uri: uri,
                    status: "sent".into(),
                    error: None,
                });
            }
            Err(e) => {
                failed += 1;
                details.push(ClientResult {
                    client_id: row.client_id.clone(),
                    backchannel_logout_uri: uri,
                    status: "error".into(),
                    error: Some(e),
                });
            }
        }
    }

    (sent, failed, details)
}

/// POST the logout token to the client's backchannel_logout_uri.
/// Uses `application/x-www-form-urlencoded` with `logout_token=<JWT>`.
async fn send_logout_token(uri: &str, token: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .post(uri)
        .form(&[("logout_token", token)])
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logout_token_events_claim_present() {
        let events = serde_json::json!({
            "http://schemas.openid.net/event/backchannel-logout": {}
        });
        assert!(events
            .get("http://schemas.openid.net/event/backchannel-logout")
            .is_some());
    }

    #[test]
    fn logout_token_jti_is_unique() {
        let a = Uuid::new_v4().to_string();
        let b = Uuid::new_v4().to_string();
        assert_ne!(a, b);
    }

    #[test]
    fn logout_token_serialization() {
        let claims = LogoutTokenClaims {
            iss: "https://auth.example.com".into(),
            aud: "client_123".into(),
            iat: 1700000000,
            jti: "jti-abc".into(),
            events: serde_json::json!({"http://schemas.openid.net/event/backchannel-logout": {}}),
            sub: Some("user-456".into()),
            sid: Some("session-789".into()),
        };
        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(json["iss"], "https://auth.example.com");
        assert_eq!(json["aud"], "client_123");
        assert_eq!(json["jti"], "jti-abc");
        assert!(json["events"]["http://schemas.openid.net/event/backchannel-logout"].is_object());
        assert_eq!(json["sub"], "user-456");
        assert_eq!(json["sid"], "session-789");
        // Must NOT have a nonce field.
        assert!(json.get("nonce").is_none());
    }

    #[test]
    fn logout_token_no_sub_or_sid() {
        // Per spec, sub and sid are optional - the token can omit them.
        let claims = LogoutTokenClaims {
            iss: "https://auth.example.com".into(),
            aud: "client_123".into(),
            iat: 1700000000,
            jti: "jti-abc".into(),
            events: serde_json::json!({"http://schemas.openid.net/event/backchannel-logout": {}}),
            sub: None,
            sid: None,
        };
        let json = serde_json::to_value(&claims).unwrap();
        assert!(json.get("sub").is_none());
        assert!(json.get("sid").is_none());
    }
}
