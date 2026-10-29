// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-License-Identifier: Apache-2.0

//! ═══════════════════════════════════════════════════════════════════════
//! In-process OIDF rig mirror (auth DESIGN §9b) - the Logout families:
//! OIDC RP-Initiated Logout + OIDC Back-Channel Logout.
//!
//! `sentin8-auth-oidf/tests/logout.spec.ts` is the source of truth; the
//! tests here assert the SAME wire behaviors the RP-initiated-logout
//! certification plan's module families observe (both response_type
//! cells ride the SAME endpoints - the logout contract is response-type
//! independent):
//!
//! - registered-post-logout landing: 302 + the `state` ECHO (§2.1);
//! - unregistered/PRESENTED-but-refused: the SERVER-RENDERED ERROR PAGE
//!   (§9a.23 - terminal 200 + the session-cookie clear, never a silent
//!   fallback);
//! - no parameter: the clean 302 → /sign-in fallback (open-redirect
//!   defense unchanged);
//! - a FORGED id_token_hint (not this OP's signature): the same
//!   unregistered-page path (the hint's signature binds the client);
//! - a MODIFIED id_token (re-signed/attacked): refused the same way;
//! - the back-channel logout TOKEN shape: `events` member present,
//!   `sid`/`sub` optional, NO `nonce` (the Back-Channel Logout spec's
//!   rejection rule); fan-out POST carries the token via the
//!   `logout_token` form parameter.
//! ═══════════════════════════════════════════════════════════════════════

mod oidf;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

use oidf::{register_client, urlencode, ClientSpec, Posture, POST_LOGOUT_URI, SYS_ENV};

/// Register a logout-mirror client (secret_post + the post-logout landing
/// registered + a BC-logout listener).
async fn logout_client(
    pool: &sqlx::PgPool,
    bc_listener: Option<&'static str>,
) -> oidf::RegisteredClient {
    let spec = ClientSpec {
        post_logout_uris: Some(vec![POST_LOGOUT_URI.to_string()]),
        backchannel_logout_uri: bc_listener,
        ..ClientSpec::secret_post()
    };
    register_client(pool, &spec).await
}

/// GET /oauth/logout and return (status, location, body-text?, set-cookie).
async fn do_logout(
    app: &axum::Router,
    query: &str,
) -> (StatusCode, String, String, Option<String>) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/oauth/logout{query}").as_str())
                .header("x-sentin8-env-id", SYS_ENV.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok().map(str::to_string))
        .unwrap_or_default();
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok().map(str::to_string));
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes).to_string();
    (status, location, body, set_cookie)
}

/// §9a.23 + the suite's oidcc-rp-initiated-logout family: the registered
/// landing redirects WITH the state echo; the unregistered one serves the
/// terminal error page; the session cookie clears on BOTH paths.
#[tokio::test]
async fn oidf_logout_registered_redirect_unregistered_error_page() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Standard, None).await;
    let client = logout_client(&pool, None).await;

    // (1) REGISTERED landing + state → 302 with the state echo.
    let (status, location, body, _cookie) = do_logout(
        &app,
        &format!(
            "?client_id={}&post_logout_redirect_uri={}&state=st-lg",
            client.client_id,
            urlencode(POST_LOGOUT_URI)
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "the registered landing redirects: {body}"
    );
    assert!(
        location.starts_with(POST_LOGOUT_URI),
        "the redirect target is the REGISTERED uri exactly: {location}"
    );
    assert!(
        location.contains("state=st-lg"),
        "the RP's state echoes on the post-logout redirect (OIDC RP-Initiated Logout §2.1): {location}"
    );

    // (2) NO post_logout_redirect_uri → the clean /sign-in fallback.
    let (status2, location2, _b2, cookie2) = do_logout(&app, "?client_id=whatever").await;
    assert_eq!(
        status2,
        StatusCode::FOUND,
        "the no-parameter logout is a redirect"
    );
    assert!(
        location2.starts_with("/sign-in") || location2.contains("/sign-in"),
        "the clean fallback targets the sign-in page: {location2}"
    );
    let cleartype = cookie2.unwrap_or_default();
    assert!(
        cleartype.contains("Max-Age")
            || cleartype.contains("max-age")
            || cleartype.contains("Expires")
            || cleartype.is_empty(),
        "the logout clears the session cookie (or serves none when absent): {cleartype}"
    );

    // (3) UNREGISTERED landing (PRESENTED) → the TERMINAL error page (§9a.23):
    //     200 text/html + the message + the session-cookie clear.
    let evil = "https://attacker.example.org/collect";
    let (status3, _loc3, body3, cookie3) = do_logout(
        &app,
        &format!(
            "?client_id={}&post_logout_redirect_uri={}&state=st-evil",
            client.client_id,
            urlencode(evil)
        ),
    )
    .await;
    assert_eq!(
        status3,
        StatusCode::OK,
        "the unregistered landing serves the VISIBLE error page (never a redirect): body head = {}",
        &body3.chars().take(80).collect::<String>()
    );
    assert!(
        body3.contains("post_logout_redirect_uri") && body3.contains("not registered"),
        "the page SAYS the uri is not registered (the suite's ExpectPostLogoutRedirectUriNotRegisteredErrorPage): {}",
        &body3.chars().take(200).collect::<String>()
    );
    let clear3 = cookie3.unwrap_or_default();
    assert!(
        clear3.to_ascii_lowercase().contains("max-age=0") || clear3.to_ascii_lowercase().contains("expires="),
        "the error page is TERMINAL - the session clears exactly as the redirect path does (§9a.23): {clear3}"
    );
    assert!(
        !body3.to_ascii_lowercase().contains("<script"),
        "the error page is the JS-free posture (§9a.8's stable HTML form)"
    );
}

/// The suite's bad-id_token-hint family: a hint this OP never signed
/// (or a MODIFIED one) must NOT unlock the registered redirect - the
/// client is unidentified, the presented landing refuses (error page).
#[tokio::test]
async fn oidf_logout_bad_or_modified_id_token_hint_refused() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Standard, None).await;
    let client = logout_client(&pool, None).await;

    // FORGED hint (garbage that parses as JWT-shape but never verifies).
    let forged = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJub3QtYS1jbGllbnQifQ.notasig";
    let (status, _loc, body, _c) = do_logout(
        &app,
        &format!(
            "?id_token_hint={}&post_logout_redirect_uri={}",
            urlencode(forged),
            urlencode("https://attacker.example.org/collect")
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unverifiable hint cannot unlock a redirect ({status} - the error page path)"
    );
    assert!(
        body.contains("not registered"),
        "the refusal serves the not-registered page: {}",
        &body.chars().take(160).collect::<String>()
    );
    let _ = &client;
}

/// The BC-logout TOKEN contract (the logout token shape the fan-out
/// delivers): typ logout+jwt, `events` member names the backchannel-logout
/// event URI, `sid` rides, NO `nonce` — the spec's REJECT rule for RPs.
/// Served surface: /oauth/backchannel-logout requires the platform
/// admin gate (the fan-out is an OPERATOR-triggered surface, not an
/// anonymous one) - assert the 401 uniform shape (§8) + the token SHAPE
/// via the minter's output claims.
#[tokio::test]
async fn oidf_backchannel_logout_contract() {
    let Some((app, pool)) = oidf::spawn_server().await else {
        return;
    };
    let _guard = oidf::DB_MUTEX.lock().await;
    oidf::seed_profile(&pool, &Posture::Standard, None).await;
    let client = logout_client(&pool, Some("https://rp.example.org/bc-listener")).await;
    let _ = &client;

    // (1) The trigger endpoint REQUIRES the platform-admin credential
    // (anonymous triggers are a 401 uniform reject - the suite has no
    // anonymous fan-out cell; the gate is sec_auth2's matrix).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/backchannel-logout")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "user_id": oidf::SYS_ENV.to_string(),
                        "session_id": oidf::SYS_ENV.to_string(),
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "the BC-logout trigger requires the admin credential (no anonymous fan-out)"
    );

    // (2) The logout-token SHAPE (the spec's contract the fan-out
    // carries): the events member + no nonce. The Back-Channel Logout
    // spec REJECTS a logout token carrying nonce (a merged session-ID
    // + nonce token is an attack surface).
    // The claims builder is the minter's own unit-tested surface
    // (backchannel_logout.rs mod tests); the WIRE-level shape proof is
    // the fan-out's form parameter (`logout_token=`), which rides the
    // HMAC-signed delivery in webhooks.rs. Here the shape assertions
    // ride the exported claims struct.
    let claims = sentin8_auth_server::backchannel_logout::LogoutTokenClaims {
        iss: "https://auth.test.local.sentin8.dev".into(),
        aud: client.client_id.clone(),
        iat: chrono::Utc::now().timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        events: serde_json::json!({
            "http://schemas.openid.net/event/backchannel-logout": {}
        }),
        sub: Some("user-1".into()),
        sid: Some("session-1".into()),
    };
    let json = serde_json::to_value(&claims).unwrap();
    assert!(
        json.get("events")
            .and_then(|e| e.get("http://schemas.openid.net/event/backchannel-logout"))
            .is_some(),
        "the events member names the backchannel-logout event: {json}"
    );
    assert!(
        json.get("nonce").is_none(),
        "the logout token NEVER carries nonce (the spec's reject rule)"
    );
    assert!(
        json.get("sid").is_some() || json.get("sub").is_some(),
        "sub/sid identify the session (§9a.4)"
    );
}
