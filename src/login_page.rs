// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Server-rendered HTML login page - the automated-client surface
//! (DESIGN.md §9a.8).
//!
//! The hosted UI at `/sign-in` is the full Flutter auth-ui (canvas SPA,
//! no DOM inputs), which DOM-driven automation (the OIDF conformance
//! suite's browser runner, Selenium-class RPs, CI clients) cannot
//! complete. This module serves a JavaScript-free HTML form with stable
//! element ids (`#username`, `#password`, `#submit`):
//!
//! - `GET /oauth/login`  - renders the form with the OAuth context in
//!   an HMAC-signed hidden field (TTL 10 min - the form cannot steer a
//!   different authorization request).
//! - `POST /oauth/login`  - verifies the context, authenticates via the
//!   SAME password path as `/v1/sign-in` (rate limits, lockout,
//!   timing-safe rejection), creates the session, and completes the
//!   authorization (code + 302 to the client's redirect_uri).
//!
//! The human flow stays on the Flutter UI.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{Duration, Utc};
use glide::AsyncCommands;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::handlers::AppState;
use crate::sessions::Session;

/// Hidden-field lifetime: the signed OAuth context is usable for 10
/// minutes (DESIGN §9a.8) - long enough for a login attempt, short
/// enough that a leaked form cannot be replayed later.
const CONTEXT_TTL_SECS: i64 = 600;

/// The query shape the authorize handler forwards: the full OAuth
/// context (it re-validated everything before redirecting here).
#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The logincontextquery type.
pub struct LoginContextQuery {
    /// The client id.
    pub client_id: String,
    /// The redirect URI.
    pub redirect_uri: String,
    /// The scope.
    pub scope: String,
    /// The state.
    pub state: String,
    /// The code challenge.
    pub code_challenge: String,
    /// The PKCE method (S256).
    pub code_challenge_method: String,
    /// The OIDC nonce.
    #[serde(default)]
    pub nonce: Option<String>,
    /// The RFC 8707 resource indicator.
    #[serde(default)]
    pub resource: Option<String>,
    /// The OAuth response mode (query default, jwt for JARM).
    #[serde(default)]
    pub response_mode: Option<String>,
}

/// The form body POSTed by the browser.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct LoginForm {
    /// The HMAC-signed OAuth context blob.
    pub ctx: String,
    /// The email/username field (`#username`).
    pub username: String,
    /// The password field (`#password`).
    pub password: String,
}

// ── Context HMAC ──────────────────────────────────────────────────────
/// Constant-time byte comparison (the context-signature check never
/// short-circuits on the first mismatching byte).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}
/// The signing key for the context blob: the platform master key when
/// configured; the same dev-insecure fallback JWKS sealing uses.
fn context_key() -> Vec<u8> {
    let k = std::env::var("SENTIN8_AUTH_MASTER_KEY").unwrap_or_default();
    if !k.is_empty() {
        return k.into_bytes();
    }
    let dev = std::env::var("SENTIN8_AUTH_DEV_INSECURE_KEY").unwrap_or_default();
    if !dev.is_empty() {
        return dev.into_bytes();
    }
    // Local dev default (matches the dev-insecure posture of a fleet
    // started without a master key - production sets the master key).
    b"sentin8-auth-dev-context-key".to_vec()
}

/// Build the signed context blob: `payload|exp|hex(hmac)`.
fn sign_context(query: &LoginContextQuery) -> String {
    let exp = (Utc::now() + Duration::seconds(CONTEXT_TTL_SECS)).timestamp();
    let payload = format!(
        "{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}",
        query.client_id,
        query.redirect_uri,
        query.scope,
        query.state,
        query.code_challenge,
        query.code_challenge_method,
        query.nonce.as_deref().unwrap_or(""),
        query.resource.as_deref().unwrap_or(""),
        query.response_mode.as_deref().unwrap_or(""),
        exp,
    );
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&context_key())
        .expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    use base64::Engine;
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{payload}|{sig}")
}

/// Verify + unpack a context blob. Returns None on any mismatch (the
/// caller re-renders the form with an error).
fn verify_context(blob: &str) -> Option<LoginContextQuery> {
    let (payload, sig) = blob.rsplit_once('|')?;
    use base64::Engine;
    let expected = {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&context_key())
            .expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    };
    if !constant_time_eq(expected.as_bytes(), sig.as_bytes()) {
        return None;
    }
    let parts: Vec<&str> = payload.split('\u{1}').collect();
    if parts.len() != 10 {
        return None;
    }
    let exp: i64 = parts[9].parse().ok()?;
    if Utc::now().timestamp() > exp {
        return None;
    }
    Some(LoginContextQuery {
        client_id: parts[0].to_string(),
        redirect_uri: parts[1].to_string(),
        scope: parts[2].to_string(),
        state: parts[3].to_string(),
        code_challenge: parts[4].to_string(),
        code_challenge_method: parts[5].to_string(),
        nonce: (!parts[6].is_empty()).then(|| parts[6].to_string()),
        resource: (!parts[7].is_empty()).then(|| parts[7].to_string()),
        response_mode: (!parts[8].is_empty()).then(|| parts[8].to_string()),
    })
}

// ── Page rendering ────────────────────────────────────────────────────

/// HTML-escape a value interpolated into the page.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Render the login page. `error` is shown in `#error_message` when
/// present (DESIGN §9a.8 - the suite's negative tests read it).
/// The element ids are the automation contract: `#username`,
/// `#password`, `#submit` - never rename them.
fn render_page(ctx: &str, error: Option<&str>) -> String {
    let error_html = error
        .map(|e| format!(r#"<p id="error_message" class="error">{}</p>"#, esc(e)))
        .unwrap_or_else(|| r#"<p id="error_message" class="error" hidden></p>"#.to_string());
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in - Sentin8</title>
<style>
body {{ font-family: Inter, system-ui, sans-serif; background: #0f1117; color: #e6e8ee;
       display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
form {{ background: #171a23; border: 1px solid #262b38; border-radius: 12px;
        padding: 2rem; width: 100%; max-width: 380px; box-sizing: border-box; }}
h1 {{ font-size: 1.25rem; margin: 0 0 1.5rem; }}
label {{ display: block; margin: 0.75rem 0 0.25rem; font-size: 0.85rem; color: #9aa3b5; }}
input {{ width: 100%; box-sizing: border-box; padding: 0.65rem 0.75rem; border-radius: 8px;
         border: 1px solid #2c3346; background: #0f1117; color: #e6e8ee; font-size: 1rem; }}
input:focus {{ outline: 1px solid #D4AF37; }}
#submit {{ margin-top: 1.5rem; background: #D4AF37; border: none; color: #14161d;
           font-weight: 600; cursor: pointer; padding: 0.7rem 1rem; border-radius: 8px; }}
#submit:hover {{ background: #e0c158; }}
.error {{ color: #ff8080; margin: 0.5rem 0 0; font-size: 0.9rem; }}
</style>
</head>
<body>
<form method="post" action="/oauth/login">
<h1>Sign in</h1>
{error_html}
<input type="hidden" name="ctx" value="{ctx}">
<label for="username">Email</label>
<input id="username" name="username" type="email" autocomplete="username" required autofocus>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<input id="submit" type="submit" value="Sign in">
</form>
</body>
</html>"#,
        ctx = esc(ctx),
        error_html = error_html,
    )
}

/// `GET /oauth/login` - render the HTML login form (DESIGN §9a.8).
/// The authorize handler redirects here with the OAuth context in the
/// query string; it is signed into the hidden field.
#[utoipa::path(
    get,
    path = "/oauth/login",
    params(LoginContextQuery),
    responses(
        (status = 200, description = "HTML login form (JS-free, automation-friendly)", body = String),
    ),
    security(),
    tag = "oauth",
)]
pub async fn login_page(
    State(_state): State<AppState>,
    Query(q): Query<LoginContextQuery>,
) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        render_page(&sign_context(&q), None),
    )
        .into_response()
}

/// `POST /oauth/login` - the form handler (DESIGN §9a.8). Verifies the
/// signed context, authenticates through the SAME password path as
/// `/v1/sign-in` (rate limit + lockout + timing-safe rejection), creates
/// the session, and completes the authorization directly (code mint +
/// 302 to the redirect_uri).
///
/// Invalid credentials re-render the page with `#error_message` (200 -
/// a login failure is not a protocol error, and the suite's DOM driver
/// must read the message).
#[utoipa::path(
    post,
    path = "/oauth/login",
    request_body = LoginForm,
    responses(
        (status = 200, description = "Re-rendered form on login failure (#error_message visible)"),
        (status = 302, description = "Signed in - redirect to the client's redirect_uri with the code"),
    ),
    security(),
    tag = "oauth",
)]
pub async fn login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<LoginForm>,
) -> Response {
    // 1. Context integrity: the form is bound to ONE authorize request.
    let Some(q) = verify_context(&form.ctx) else {
        return login_error_page(&form.ctx, "The login session expired - restart the sign-in.");
    };

    // 2. Bot protection - identical to /v1/sign-in.
    let ip = crate::bot_protection::extract_client_ip(&headers);
    if let Err((_status, msg)) = crate::bot_protection::check_signin_rate(&state, &ip, &form.username).await {
        return login_error_page(&form.ctx, &msg);
    }

    // 3. Tenant resolution + user lookup (RLS-contexted, same as
    // /v1/sign-in).
    let (org_id, env_id) = crate::handlers::resolve_tenant_from_headers(&state.pool, &headers).await;
    tracing::info!(resolved_org_id = %org_id, resolved_env_id = %env_id, "auth: html login resolved tenant context");
    let mut tx = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "login_submit: pool begin failed");
            return login_error_page(&form.ctx, "Sign-in is temporarily unavailable.");
        }
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let user = match sqlx::query!(
        r#"SELECT id, env_id, email, password_hash, status
             FROM users
            WHERE email = $1
              AND env_id = $2"#,
        form.username.to_lowercase(),
        env_id,
    )
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "login_submit: user lookup failed");
            return login_error_page(&form.ctx, "Sign-in is temporarily unavailable.");
        }
    };
    let _ = tx.commit().await;

    let user = match user {
        Some(u) => u,
        None => {
            // Timing-safe rejection - identical to /v1/sign-in.
            const DUMMY_HASH: &str = "$2b$12$LJ3m4sMV0uV1ZpT1YyV1qOELQwXG5uYyY3nZcQcQK5cC4qP5oP5uS";
            let _ = crate::handlers::bcrypt_verify(&form.password, DUMMY_HASH);
            return login_error_page(&form.ctx, "Invalid email or password.");
        }
    };
    if let Err((_status, _msg)) = crate::bot_protection::check_account_lockout(&state, user.id).await {
        return login_error_page(&form.ctx, "This account is temporarily locked.");
    }
    if user.status != "active" {
        return login_error_page(&form.ctx, "This account is not active.");
    }
    let valid = user
        .password_hash
        .as_ref()
        .map(|h| crate::handlers::bcrypt_verify(&form.password, h).unwrap_or(false))
        .unwrap_or(false);
    if !valid {
        let _ = crate::bot_protection::record_failed_signin(&state, user.id).await;
        return login_error_page(&form.ctx, "Invalid email or password.");
    }
    let _ = crate::bot_protection::reset_failed_signins(&state, user.id).await;

    // MFA: this surface cannot complete a TOTP challenge (no SPA). The
    // conformance/CI users are MFA-free by design; an MFA-enrolled user
    // is told to use the app.
    if crate::mfa::user_requires_mfa(&state.pool, user.id).await.is_some() {
        return login_error_page(&form.ctx, "This account requires multi-factor authentication - sign in via the app.");
    }

    // 4. Session creation (RLS-contexted transaction - same pattern as
    // /v1/sign-in).
    let token_id = uuid::Uuid::new_v4().to_string();
    let mut session_tx = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "login_submit: session tx begin failed");
            return login_error_page(&form.ctx, "Sign-in is temporarily unavailable.");
        }
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(user.env_id)
        .execute(&mut *session_tx)
        .await;
    let session = match Session::create(
        &mut *session_tx,
        user.id,
        user.env_id,
        &token_id,
        None,
        Duration::seconds(state.config.session_ttl_secs as i64),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "login_submit: session create failed");
            return login_error_page(&form.ctx, "Sign-in is temporarily unavailable.");
        }
    };
    if let Err(e) = session_tx.commit().await {
        tracing::error!(error = %e, "login_submit: session commit failed");
        return login_error_page(&form.ctx, "Sign-in is temporarily unavailable.");
    }

    // 5. Complete the authorization: mint the code through the SAME
    // authorize-continue path the SPA uses. First-party clients
    // (consent_required=false) receive the code directly.
    let profile = crate::oauth::resolve_security_profile(&state.pool, &headers, "env").await;
    let code = uuid::Uuid::new_v4().to_string();
    let code_key = format!("auth:authcode:{code}");
    let code_data = serde_json::json!({
        "client_id": q.client_id,
        "redirect_uri": q.redirect_uri,
        "scope": q.scope,
        "user_id": user.id.to_string(),
        "env_id": user.env_id.to_string(),
        "code_challenge": if q.code_challenge.is_empty() { None } else { Some(q.code_challenge) },
        "nonce": q.nonce,
        "resource": q.resource,
        "state": q.state,
        "auth_time": chrono::Utc::now().timestamp(),
    });
    let valkey_store = async {
        match sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:auth").await {
            Ok(c) => c
                .set_ex::<_, _, ()>(&code_key, code_data.to_string(), 600)
                .await
                .map(|_: ()| ())
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        }
    }
    .await;
    if let Err(e) = valkey_store {
        tracing::error!(error = %e, "login_submit: code store failed");
        return login_error_page(&form.ctx, "Sign-in is temporarily unavailable.");
    }

    // 6. Redirect to the client with the code (iss per RFC 9207 when the
    // profile requires it; JARM wraps when response_mode=jwt).
    let cookie_domain =
        crate::sessions::cookie_domain_from_headers(&headers, &state.config.sentin8_domain);
    let mut redirect = format!(
        "{}?code={}&state={}",
        q.redirect_uri,
        urlencode(&code),
        urlencode(&q.state),
    );
    if profile.require_iss {
        redirect.push_str(&format!("&iss={}", urlencode(&state.config.issuer)));
    }
    if profile.require_jarm && q.response_mode.as_deref() == Some("jwt") {
        let jarm_claims = crate::jarm::build_jarm_success(
            &state.config.issuer,
            &q.client_id,
            &code,
            if q.state.is_empty() { None } else { Some(&q.state) },
        );
        if let Ok(jwt) = crate::jarm::sign_jarm_jwt(&state.keys, &jarm_claims) {
            redirect = crate::jarm::build_jarm_redirect_url(&q.redirect_uri, &jwt);
        }
    }
    (
        StatusCode::FOUND,
        [
            ("set-cookie", session.cookie(&cookie_domain)),
            ("location", redirect),
        ],
    )
        .into_response()
}

/// Re-render the page with an error message (DESIGN §9a.8).
fn login_error_page(ctx: &str, msg: &str) -> Response {
    // The context blob may itself be invalid here - re-sign nothing; the
    // caller should restart the flow when the ctx is bad (the page's
    // error text says so).
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        render_page(ctx, Some(msg)),
    )
        .into_response()
}

/// Minimal URL-encoding for redirect construction.
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

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_query() -> LoginContextQuery {
        LoginContextQuery {
            client_id: "client-1".into(),
            redirect_uri: "https://app.example.com/cb".into(),
            scope: "openid".into(),
            state: "st".into(),
            code_challenge: "chal".into(),
            code_challenge_method: "S256".into(),
            nonce: Some("n".into()),
            resource: None,
            response_mode: None,
        }
    }

    #[test]
    fn context_roundtrip() {
        let q = sample_query();
        let blob = sign_context(&q);
        let back = verify_context(&blob).expect("roundtrip verifies");
        assert_eq!(back.client_id, "client-1");
        assert_eq!(back.state, "st");
        assert_eq!(back.nonce.as_deref(), Some("n"));
    }

    #[test]
    fn context_tamper_rejected() {
        let blob = sign_context(&sample_query());
        let tampered = format!("{}x", blob.trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == b'=' as char));
        assert!(verify_context(&tampered).is_none(), "signature tamper must fail");
        // Swap in a forged payload.
        let forged = blob.replace("client-1", "client-2");
        assert!(verify_context(&forged).is_none(), "payload tamper must fail");
    }

    #[test]
    fn page_carries_stable_ids() {
        let html = render_page("ctx-blob", None);
        assert!(html.contains(r#"id="username""#));
        assert!(html.contains(r#"id="password""#));
        assert!(html.contains(r#"id="submit""#));
        assert!(html.contains(r#"id="error_message""#));
        assert!(html.contains(r#"name="ctx" value="ctx-blob""#));
    }

    #[test]
    fn error_page_shows_message() {
        let html = render_page("ctx", Some("Invalid email or password."));
        assert!(html.contains("Invalid email or password."));
        assert!(html.contains(r#"id="error_message""#));
    }
}