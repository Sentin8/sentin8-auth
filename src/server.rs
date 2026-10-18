// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for Auth.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use utoipa::OpenApi;

use crate::actor_tokens;
use crate::admin;
use crate::backchannel_logout;
use crate::ciba;
use crate::config::AuthConfig;
use crate::consent_proxy;
use crate::dcr;
use crate::delegation;
use crate::enterprise_connections;
use crate::handlers::{self, AppState};
use crate::jwks::{self as jwks_mod, JwksResponse, SigningKeys};
use crate::mfa;
use crate::oauth;
use crate::passkey;
use crate::scim;
use crate::tokens;
use crate::webhooks;

/// Build state.
pub async fn build_state(core: sentin8::shell::ServiceCore) -> anyhow::Result<AppState> {
    let config = AuthConfig::from_env();
    let keys = Arc::new(SigningKeys::load_or_generate(&core.pool).await?);

    // DBX ( / DBX-POST-3): the post pusher drains auth's local
    // `post_outbox` (welcome emails, reset notifications, MFA alerts) to
    // Sentin8:Post's send API — no direct post.inbox writes.
    {
        let cfg0 = sentin8::config::Sentin8Config::from_env();
        crate::events::spawn_post_pusher(
            core.pool.clone(),
            cfg0.sentin8_post_url(),
            cfg0.sentin8_auth_issuer(),
        );
    }

    // ── Sentin8:Policy (— shell-owned boot): consume the
    // engine the shell booted in step 8 — no second engine, consumer, or
    // DCR registration here.
    let policy_engine = core.admin.policy.clone();

    // auth DESIGN §4.3f: the boot-loaded workload registry map — the
    // authorization record for certificate-only platform-workload calls
    // (sys's provisioning delegation presents the `auth-sys` certificate;
    // scopes ride the map, not a token). Unavailable at boot → fail-closed
    // until the next boot (same posture as bus/flow).
    let workload_registry = match sentin8::auth::workload_registry::WorkloadMap::boot_load(
        "sentin8:auth",
    )
    .await
    {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!(error = %e, "auth: workload registry map unavailable at boot — certificate-workload calls fail-closed until next boot");
            sentin8::auth::workload_registry::WorkloadMap::boot_load_empty("sentin8:auth")
        }
    };

    let state = AppState {
        config: Arc::new(config.clone()),
        keys,
        pool: core.pool.clone(),
        workload_registry,
        admin: sentin8::shield::admin::SharedAdminState {
            service: "sentin8:auth".to_string(),
            pool: core.pool.clone(),
            policy: policy_engine.clone(),
            auth_client: std::sync::Arc::new(sentin8::auth::client::Client::new(
                sentin8::auth::client::ClientOptions {
                    base_url: config.issuer.clone(),
                    ..Default::default()
                },
            )),
        },
        policy: policy_engine,
    };

    //spawn the webhook relay worker.
    webhooks::spawn_relay(state.clone());

    // JWKS rotation (SDD §2.5, root-service rule): an internal daily
    // timer — auth links no scheduler client and makes no cross-service
    // calls. The timer rotates only when the newest key passes the
    // 30-day staleness gate.
    jwks_mod::spawn_rotation_timer(state.pool.clone());
    // Daily telemetry (SDD §2.6): internal timer publishing one metric
    // frame via the shared MemBus telemetry path.
    crate::telemetry::spawn_telemetry_timer(state.pool.clone());

    Ok(state)
}

/// Build the Axum router with all routes (NO middleware layers — the
/// platform `sentin8-shell` applies the standard stack: correlation, host
/// context, TLS context, request logging, traffic counter, CORS).
/// Used by `routes` and integration tests.
///
/// SEC- — a `route_guard` layer wraps the finished router as a
/// structural backstop: every `/v1/admin/*` path, `PUT /v1/security-profile`,
/// and `POST /oauth/backchannel-logout` requires a verified Bearer token
/// with an admin scope. Per-handler guards remain the primary (they also
/// resolve tenant context) — this middleware makes "new module forgot the
/// guard" impossible.
/// Build router.
pub fn build_router(state: AppState) -> Router {
    let ui_dir = std::env::var("SENTIN8_AUTH_UI_DIR")
        .unwrap_or_else(|_| "apps/auth-ui/build/web".to_string());
    let app = Router::new()
        // Frontend API
        .route("/v1/branding", get(handlers::branding))
        .route("/v1/session", get(handlers::get_session))
        .route("/v1/sign-in", post(handlers::sign_in))
        .route("/v1/sign-up", post(handlers::sign_up))
        .route("/v1/sign-out", post(handlers::sign_out))
        .route("/v1/health", get(handlers::health))
        // ── App passwords (per-credential scope restrictions, EUDI.) ──
        .route(
            "/v1/me/app-passwords",
            get(crate::app_passwords::list_app_passwords)
                .post(crate::app_passwords::create_app_password),
        )
        .route(
            "/v1/me/app-passwords/{id}",
            delete(crate::app_passwords::revoke_app_password),
        )
        // ── Admin UI (RFW) ─────────────────────────────────────────────────
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        // Consent accounts — fetch customer accounts for the consent
        // screen's account selection step. Proxied to the vertical service
        // that owns the matching consent flow.
        .route("/v1/auth/consent/accounts", get(handlers::consent_accounts))
        // Consent RFW proxy — proxy consent UI/approve/deny to the vertical
        // service that owns the matching consent flow .
        .route("/v1/auth/consent/ui", get(consent_proxy::proxy_consent_ui))
        .route(
            "/v1/auth/consent/approve",
            post(consent_proxy::proxy_consent_approve),
        )
        .route(
            "/v1/auth/consent/deny",
            post(consent_proxy::proxy_consent_deny),
        )
        // MFA (TOTP)
        .route("/v1/mfa/enroll", post(mfa::enroll))
        .route("/v1/mfa/verify", post(mfa::verify))
        .route("/v1/mfa/disable", post(mfa::disable))
        // Passkey (WebAuthn)
        .route("/v1/passkey/enroll/begin", post(passkey::enroll_begin))
        .route("/v1/passkey/enroll/finish", post(passkey::enroll_finish))
        .route("/v1/passkey/verify/begin", post(passkey::verify_begin))
        .route("/v1/passkey/verify/finish", post(passkey::verify_finish))
        // Password reset
        .route("/v1/password/reset", post(tokens::password_reset_request))
        .route(
            "/v1/password/reset/confirm",
            post(tokens::password_reset_confirm),
        )
        // Email verification
        .route("/v1/email/verify", post(tokens::email_verify_request))
        .route(
            "/v1/email/verify/confirm",
            post(tokens::email_verify_confirm),
        )
        // Enterprise connections (SAML/OIDC IdP)
        .route(
            "/v1/admin/enterprise-connections",
            get(enterprise_connections::list_connections)
                .post(enterprise_connections::create_connection),
        )
        .route(
            "/v1/admin/enterprise-connections/{id}",
            get(enterprise_connections::get_connection)
                .put(enterprise_connections::update_connection)
                .delete(enterprise_connections::delete_connection),
        ) // POST alias for RFW row_action_post
        .route(
            "/v1/admin/enterprise-connections/{id}/delete",
            post(crate::rfw_aliases::enterprise_connection_delete),
        )
        .route(
            "/v1/sso/{connection_id}/authorize",
            get(enterprise_connections::sso_authorize),
        )
        .route(
            "/v1/sso/{connection_id}/callback",
            get(enterprise_connections::sso_callback),
        )
        .route(
            "/v1/saml/metadata/{connection_id}",
            get(enterprise_connections::saml_metadata),
        )
        .route(
            "/v1/saml/acs/{connection_id}",
            post(enterprise_connections::saml_acs),
        )
        // Actor tokens (support / delegated admin)
        .route(
            "/v1/admin/actor-tokens",
            get(actor_tokens::list_actor_tokens).post(actor_tokens::issue_actor_token),
        )
        .route(
            "/v1/actor-tokens/revoke",
            post(actor_tokens::revoke_actor_token),
        )
        .route(
            "/v1/admin/actor-events",
            get(actor_tokens::list_actor_events),
        )
        // Webhook delivery
        .route(
            "/v1/admin/webhooks/endpoints",
            get(webhooks::list_endpoints).post(webhooks::create_endpoint),
        )
        .route(
            "/v1/admin/webhooks/endpoints/{id}",
            get(webhooks::get_endpoint).delete(webhooks::delete_endpoint),
        )
        .route("/v1/admin/webhooks/outbox", get(webhooks::list_outbox))
        .route(
            "/v1/admin/webhooks/attempts/{outbox_id}",
            get(webhooks::list_attempts),
        )
        .route(
            "/v1/admin/webhooks/attempts/{outbox_id}/replay",
            post(webhooks::replay_failed),
        )
        // Cron proxy-back target — internal JWKS key rotation (AUTH-1).
        .route("/v1/internal/keys/rotate", post(internal_keys_rotate))
        // OIDC discovery + JWKS
        .route("/.well-known/openid-configuration", get(oauth::discovery))
        .route("/.well-known/jwks.json", get(jwks_endpoint))
        // OAuth endpoints
        .route("/oauth/authorize", get(oauth::authorize))
        .route("/oauth/authorize/continue", post(oauth::authorize_continue))
        // PAR endpoint (RFC 9126)
        .route("/oauth/par", post(oauth::pushed_authorization_request))
        // Dynamic Client Registration (RFC 7591 + 7592)/
        .route("/oauth/register", post(dcr::register))
        .route(
            "/oauth/register/{client_id}",
            get(dcr::get_client)
                .put(dcr::update_client)
                .delete(dcr::delete_client),
        )
        .route("/oauth/token", post(oauth::token))
        // mTLS endpoint aliases (RFC 8705); wraps
        // them with a client-certificate-presence guard so the aliases are
        // cert-bound while /oauth/* stays open to assertion/secret clients.
        .route("/mtls/oauth/token", post(crate::mtls_alias::mtls_token))
        .route("/mtls/oauth/revoke", post(crate::mtls_alias::mtls_revoke))
        // Device Authorization Grant (RFC 8628)
        .route("/oauth/device", post(oauth::device_authorization))
        .route("/device/verify", post(oauth::device_verify))
        .route("/oauth/introspect", post(oauth::introspect))
        // FAPI 2.0 Grant Management.
        .route("/oauth/grants", post(crate::grants::create_grant))
        .route(
            "/oauth/grants/{id}",
            get(crate::grants::get_grant)
                .patch(crate::grants::patch_grant)
                .delete(crate::grants::delete_grant),
        )
        // EUDI wallet — OID4VP sign-in + metadata (EUDI.).
        .route("/oauth/vp/response", post(crate::wallet::vp_response))
        .route(
            "/v1/auth/wallet/metadata",
            get(crate::wallet::wallet_metadata),
        )
        // EUDI. — OID4VCI credential issuance.
        .route("/oauth/credentials", post(crate::wallet::credential_offer))
        .route(
            "/oauth/credentials/issue",
            post(crate::wallet::credential_issue),
        )
        .route(
            "/oauth/credentials/status/{id}",
            get(crate::wallet::credential_status),
        )
        .route(
            "/oauth/credentials/revoke/{id}",
            post(crate::wallet::credential_revoke),
        )
        .route("/oauth/revoke", post(oauth::revoke))
        .route("/oauth/userinfo", get(oauth::userinfo))
        .route("/oauth/logout", get(oauth::logout))
        // Back-Channel Logout (OIDC BCN )
        .route(
            "/oauth/backchannel-logout",
            post(backchannel_logout::trigger_backchannel_logout),
        )
        // CIBA (Client Initiated Backchannel Authentication)
        .route("/oauth/bc-authorize", post(ciba::bc_authorize))
        .route("/v1/ciba/approve", post(ciba::ciba_approve))
        // Assisted Login (CIBA + front-channel link)
        // The API metadata endpoint is at /v1/ciba/assisted/:id so the
        // browser path /ciba/assisted/:id falls through to the SPA fallback
        // and serves index.html for the Flutter AssistedLoginPage to render.
        .route(
            "/v1/ciba/assisted/{auth_req_id}",
            get(ciba::ciba_assisted_page),
        )
        .route(
            "/v1/ciba/assisted/{auth_req_id}/complete",
            post(ciba::ciba_assisted_complete),
        )
        // Admin API — Users
        .route(
            "/v1/admin/users",
            get(admin::list_users).post(admin::create_user),
        )
        .route(
            "/v1/admin/users/{id}",
            get(admin::get_user)
                .put(admin::update_user)
                .delete(admin::delete_user),
        )
        // POST alias for RFW row_action_post (renderer only supports POST)
        .route("/v1/admin/users/{id}/delete", post(crate::rfw_aliases::user_delete))
        // Admin API — Roles
        .route(
            "/v1/admin/roles",
            get(admin::list_roles).post(admin::create_role),
        )
        .route(
            "/v1/admin/roles/{id}",
            get(admin::list_role_members)
                .put(admin::update_role)
                .delete(admin::delete_role),
        )
        // POST alias for RFW form submission (renderer only supports POST)
        .route("/v1/admin/roles/{id}/update", post(crate::rfw_aliases::role_update))
        .route(
            "/v1/admin/roles/{role_id}/members",
            post(admin::add_role_member),
        )
        .route(
            "/v1/admin/roles/{role_id}/members/{user_id}",
            delete(admin::remove_role_member),
        )
        // POST alias for RFW row_action_post
        .route("/v1/admin/roles/{id}/delete", post(crate::rfw_aliases::role_delete))
        // Admin API — Groups (user-grouping)
        .route(
            "/v1/admin/groups",
            get(admin::list_groups).post(admin::create_group),
        )
        .route(
            "/v1/admin/groups/{id}",
            get(crate::rfw_aliases::group_members_alias)
                .put(crate::rfw_aliases::group_update)
                .delete(crate::rfw_aliases::group_delete),
        )
        // POST alias for RFW form submission (renderer only supports POST)
        .route("/v1/admin/groups/{id}/update", post(crate::rfw_aliases::group_update))
        .route(
            "/v1/admin/groups/{group_id}/members",
            get(admin::list_group_members).post(admin::add_group_member),
        )
        .route(
            "/v1/admin/groups/{group_id}/members/{user_id}",
            delete(admin::remove_group_member),
        )
        .route(
            "/v1/admin/groups/{group_id}/roles",
            get(admin::list_group_roles).post(admin::add_group_role),
        )
        .route(
            "/v1/admin/groups/{group_id}/roles/{role_id}",
            delete(admin::remove_group_role),
        )
        // POST alias for RFW row_action_post
        .route("/v1/admin/groups/{id}/delete", post(crate::rfw_aliases::group_delete))
        // Admin API — OAuth Clients
        .route(
            "/v1/admin/oauth-clients",
            get(admin::list_oauth_clients).post(admin::create_oauth_client),
        )
        .route(
            "/v1/admin/oauth-clients/{id}",
            get(admin::get_oauth_client)
                .put(admin::update_oauth_client)
                .delete(admin::delete_oauth_client),
        )
        // POST alias for RFW row_action_post
        .route(
            "/v1/admin/oauth-clients/{id}/delete",
            post(crate::rfw_aliases::oauth_client_delete),
        )
        // Admin API — OAuth Client Roles (app-role assignments to M2M clients)
        .route(
            "/v1/admin/oauth-clients/{id}/roles",
            get(admin::list_client_roles).post(admin::add_client_role),
        )
        .route(
            "/v1/admin/oauth-clients/{id}/roles/{role_id}",
            delete(admin::remove_client_role),
        )
        // Admin API — Federated Credentials (workload-identity trusts)
        .route(
            "/v1/admin/oauth-clients/{id}/federated-credentials",
            get(admin::list_federated_credentials).post(admin::create_federated_credential),
        )
        .route(
            "/v1/admin/oauth-clients/{id}/federated-credentials/{cred_id}",
            delete(admin::delete_federated_credential),
        )
        // Admin API — User introspection (resolved roles + groups)
        .route("/v1/admin/users/{id}/roles", get(admin::list_user_roles))
        .route("/v1/admin/users/{id}/groups", get(admin::list_user_groups))
        // Admin API — API Keys
        .route(
            "/v1/admin/api-keys",
            get(admin::list_api_keys).post(admin::create_api_key),
        )
        .route(
            "/v1/admin/api-keys/{id}/revoke",
            post(admin::revoke_api_key),
        )
        // Admin API — Sessions
        .route("/v1/admin/sessions", get(admin::list_sessions))
        .route("/v1/admin/sessions/{id}", delete(admin::terminate_session))
        // POST alias for RFW row_action_post
        .route(
            "/v1/admin/sessions/{id}/revoke",
            post(crate::rfw_aliases::session_revoke),
        )
        // Admin API — Memberships & Invitations
        .route(
            "/v1/admin/memberships",
            get(admin::list_memberships).post(admin::create_membership),
        )
        .route(
            "/v1/admin/memberships/{id}",
            delete(admin::delete_membership),
        )
        // — membership provisioning for sys (Flow proxy-back
        // steps call these with the sys M2M client; Shield-gated,
        // idempotent). The cross-service INSERTs into auth.* are retired.
        .route(
            "/v1/admin/provision/role",
            post(crate::provision::provision_role),
        )
        .route(
            "/v1/admin/provision/role_nesting",
            post(crate::provision::provision_role_nesting),
        )
        .route(
            "/v1/admin/provision/group",
            post(crate::provision::provision_group),
        )
        .route(
            "/v1/admin/provision/group_role",
            post(crate::provision::provision_group_role),
        )
        .route(
            "/v1/admin/provision/group_member",
            post(crate::provision::provision_group_member),
        )
        .route(
            "/v1/admin/provision/user_role",
            post(crate::provision::provision_user_role),
        )
        .route(
            "/v1/admin/invitations",
            get(admin::list_invitations).post(admin::create_invitation),
        )
        .route(
            "/v1/admin/invitations/{id}/revoke",
            post(admin::revoke_invitation),
        )
        // Admin API — Audit Events
        .route("/v1/admin/audit", get(admin::list_audit_events))
        // Security Profile Admin API
        .route(
            "/v1/security-profile",
            get(oauth::get_security_profile_api).put(oauth::put_security_profile_api),
        )
        // — security-profile admin surface (high-level selection
        // + detail flags; both write the env-scoped row).
        .route(
            "/v1/admin/security",
            get(crate::security_admin::get_security_selection)
                .post(crate::security_admin::put_security_selection),
        )
        .route(
            "/v1/admin/security/detail",
            post(crate::security_admin::put_security_detail),
        )
        // SCIM
        .route(
            "/scim/v2/Users",
            get(scim::list_users).post(scim::create_user),
        )
        .route(
            "/scim/v2/Users/{id}",
            get(scim::get_user)
                .put(scim::replace_user)
                .patch(scim::patch_user)
                .delete(scim::delete_user),
        )
        .route("/scim/v2/Bulk", post(scim::bulk))
        .route("/scim/v2/Groups", get(scim::list_groups))
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(scim::service_provider_config),
        )
        .route("/scim/v2/ResourceTypes", get(scim::resource_types))
        // Delegation Gateway — BFF requests cert-bound delegated tokens
        .route(
            "/delegate/access-token",
            post(delegation::delegate_access_token),
        )
        // Serves the Auth hosted UI from the built Flutter web app.
        // When ServeDir can't find a file (e.g. SPA client-side routes like
        // /sign-in, /sign-up), it falls back to serving index.html so the
        // Flutter router can handle the route.
        // ── Sentin8:Policy admin API ( — shared implementation,
        // one surface per service; the routes bind the annotated wrappers
        // in `policy_docs` (utoipa cannot path a generic handler).
        .route(
            "/v1/admin/policy-sets",
            get(crate::policy_docs::policy_list_sets),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(crate::policy_docs::policy_get_set)
                .put(crate::policy_docs::policy_put_set)
                .delete(crate::policy_docs::policy_delete_set),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(crate::policy_docs::policy_test_set),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(crate::policy_docs::policy_enforce),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(crate::policy_docs::policy_shadow),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(crate::policy_docs::policy_disable),
        )
        .route(
            "/v1/admin/relations",
            get(crate::policy_docs::policy_relations)
                .put(crate::policy_docs::policy_put_relation)
                .delete(crate::policy_docs::policy_delete_relation),
        )
        .route(
            "/v1/admin/relations/check",
            get(crate::policy_docs::policy_check_relation),
        )
        .route(
            "/v1/admin/attributes",
            get(crate::policy_docs::policy_attributes)
                .put(crate::policy_docs::policy_put_attribute)
                .delete(crate::policy_docs::policy_delete_attribute),
        )
        .fallback_service(tower_http::services::ServeDir::new(&ui_dir).fallback(
            tower_http::services::ServeFile::new(format!("{ui_dir}/index.html")),
        ));

    let app = app.with_state(state.clone());

    // ── OpenAPI spec ────────────────────────────────────────────────
    let app = app.merge(sentin8::openapi::openapi_route(
        crate::openapi::AuthOpenApi::openapi(),
    ));

    // SEC- — route guard middleware (structural backstop).
    // Every admin/platform-management path requires a verified admin
    // Bearer token OR a valid session (for the cookie-authenticated admin
    // endpoints). Per-handler guards remain the primary — they also
    // resolve tenant context and apply finer-grained scope checks. This
    // layer makes "new module forgot the guard" structurally impossible.
    app.layer(axum::middleware::from_fn_with_state(state, route_guard))
}

/// SEC- — route guard backstop.
///
/// Paths guarded here:
/// - `/v1/admin/*` (all admin CRUD + admin UI data)
/// - `/v1/security-profile` (read AND write — tenant security config)
/// - `/oauth/backchannel-logout` (internal trigger)
///
/// Everything else — sign-in/up, OAuth protocol endpoints (client auth in
/// their handlers), hosted UI, discovery/JWKS, health, SSO browser
/// endpoints — passes through untouched.
async fn route_guard(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path();

    let needs_guard = path.starts_with("/v1/admin/")
        || path == "/v1/security-profile"
        || path == "/oauth/backchannel-logout";

    if !needs_guard {
        return next.run(req).await;
    }

    let headers = req.headers().clone();

    // Path 1: verified Bearer token with an admin scope.
    let bearer_ok = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|token| crate::sentin8or_auth::verify_bearer_admin(&state, token).is_ok())
        .unwrap_or(false);

    // Path 2: valid session cookie / Bearer session token (for
    // cookie-authenticated admin endpoints such as issue_actor_token —
    // the handler still enforces its own scope checks).
    let mut session_ok = false;
    if !bearer_ok {
        if let Some(token_id) = crate::handlers::extract_session_token(&headers) {
            session_ok = matches!(
                crate::sessions::Session::find_by_token(&state.pool, &token_id).await,
                Ok(Some(ref s)) if s.is_valid()
            );
        }
    }

    // Path 3: certificate-only platform-workload identity (auth DESIGN
    // §4.3f; group DESIGN.md §3.1): an enrolled workload presents its
    // Acme client certificate in the TLS handshake — the TLS layer
    // CA-verifies and injects `X-Sentin8-Client-Cert-Subject` (strips
    // client-supplied copies). The boot-loaded registry map is the
    // authorization record: any enrolled workload with an ADMIN-scope
    // grant passes the backstop (the handler's own Shield gate still
    // decides the specific action). The token model is retired for
    // platform workloads — without this path the sys provisioning
    // delegation (the `auth-sys` certificate) 401s and org access-model
    // provisioning fails (the e2e incident).
    let mut cert_ok = false;
    if !bearer_ok && !session_ok {
        if let Some(subject) = headers
            .get("x-sentin8-client-cert-subject")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
        {
            if let Some(workload) = subject.strip_prefix("m2m-") {
                if let Some(rec) = state.workload_registry.get(workload).await {
                    // Enrolled + enabled, and the grant carries an admin-
                    // class scope (the map's coarse pre-filter; the
                    // handler's Shield gate enforces the precise action).
                    cert_ok = rec.enabled
                        && rec
                            .scopes
                            .iter()
                            .any(|s| s.ends_with(":admin:write") || s == "sentin8:sys:admin");
                }
            }
        }
    }

    if bearer_ok || session_ok || cert_ok {
        return next.run(req).await;
    }

    (
        axum::http::StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "error": "unauthorized",
            "error_description": "admin endpoints require an admin Bearer token or a valid session"
        })),
    )
        .into_response()
}

/// `POST /v1/internal/keys/rotate` — Sentin8:Cron proxy-back target for
/// automated JWKS rotation (AUTH-1, auth DESIGN §10). Generates and
/// persists a new signing key; the JWKS reader keeps every key published,
/// so tokens signed by the previous key stay verifiable for overlap.
#[utoipa::path(
    post,
    path = "/v1/internal/keys/rotate",
    request_body = serde_json::Value,
    responses((status = 200, description = "Signing key rotated")),
    tag = "auth",
)]
async fn internal_keys_rotate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Verify the cron ticker's M2M token via the service's own signing
    // keys (verify_raw returns the decoded claims) and gate with Shield —
    // M2M parity: token type never bypasses policy. The raw claims map to
    // the platform AuthContext (scope/token_tp are in the token).
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "missing bearer token".into()))?;
    let raw = state
        .keys
        .verify_raw(token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
    let a = sentin8::auth::client::AuthContext {
        workload: None,
        claims: serde_json::from_value(raw)
            .map_err(|e| (StatusCode::UNAUTHORIZED, format!("claims decode: {e}")))?,
    };
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:auth:admin:write"),
    )
    .await?;
    let _ = body;
    // 30-day staleness gate (AUTH-1): the cron schedule fires daily;
    // a new key is inserted only when the newest key for the active
    // algorithm is at least 30 days old — rotation cadence = 30 days.
    let newest_age_days: f64 = sqlx::query_scalar(
        r#"SELECT EXTRACT(EPOCH FROM (now() - MAX(created_at))) / 86400.0
           FROM signing_keys WHERE alg = $1"#,
    )
    .bind(crate::jwks::active_signing_alg())
    .fetch_one(&state.pool)
    .await
    .unwrap_or(Some(9999.0))
    .unwrap_or(9999.0);
    if newest_age_days < 30.0 {
        tracing::info!(
            newest_age_days = newest_age_days,
            "auth: key rotation skipped — newest key younger than 30 days"
        );
        return Ok(Json(serde_json::json!({
            "status": "skipped",
            "reason": "newest key younger than 30 days",
            "newest_age_days": newest_age_days,
        })));
    }
    let (key_id, alg) = crate::jwks::SigningKeys::rotate(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({
        "status": "rotated",
        "key_id": key_id,
        "alg": alg,
    })))
}

/// OIDC JSON Web Key Set — the verification keys for every ID/access
/// token this issuer mints (fetched by every service + third-party IdP).
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    responses(
        (status = 200, description = "The active signing keys (JWK Set RFC 7517)", body = JwksResponse),
    ),
    security(),
    tag = "oauth",
)]
async fn jwks_endpoint(State(state): State<AppState>) -> Json<JwksResponse> {
    Json(JwksResponse::from_keys(&state.keys))
}

/// Shared policy-admin surface accessor.
impl sentin8::shield::admin::HasPolicyAdmin for crate::handlers::AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
