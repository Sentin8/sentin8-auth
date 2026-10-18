// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Auth — library re-exports for integration tests.

#![deny(missing_docs)]

/// Actor (time-boxed, audited) tokens.
pub mod actor_tokens;
/// Admin API — users, roles, groups, clients, keys, memberships.
pub mod admin;
/// Admin UI (RFW) handlers.
pub mod admin_ui;
/// App-specific password credentials.
pub mod app_passwords;
/// OIDC Back-Channel Logout.
pub mod backchannel_logout;
/// Bot / credential-stuffing protection on public flows.
pub mod bot_protection;
/// Client-Initiated Backchannel Authentication (RFC 9436 family).
pub mod ciba;
/// Environment configuration.
pub mod config;
/// Consent proxy for delegated approval surfaces.
pub mod consent_proxy;
/// OAuth Dynamic Client Registration (RFC 7591) + management.
pub mod dcr;
/// Delegation Gateway (delegated tokens, act chain).
pub mod delegation;
/// DPoP sender-constrained tokens (RFC 9449).
pub mod dpop;
/// Enterprise (federated) identity connections.
pub mod enterprise_connections;
/// Domain event emission (outbox) for auth lifecycle changes.
pub mod events;
/// Experimental, feature-flagged flows.
pub mod experimental;
/// Financial-grade API profile support.
pub mod fapi;
/// Standing-consent grant store.
pub mod grants;
/// Shared HTTP handlers and application state.
pub mod handlers;
/// HTTP message signatures (RFC 9421).
pub mod http_signatures;
/// JWT-Secured Authorization Request (RFC 9101).
pub mod jar;
/// JWT Authorization Response Mode (JARM).
pub mod jarm;
/// JWKS document building and key rotation.
pub mod jwks;
/// JWT minting and verification primitives.
pub mod jwt;
/// JWT introspection (RFC 7662).
pub mod jwt_introspection;
/// Multi-factor authentication (TOTP, enrollment, challenge).
pub mod mfa;
/// mTLS client-certificate authentication.
pub mod mtls;
/// mTLS certificate alias mapping.
pub mod mtls_alias;
/// Native app flows (custom URL schemes, PKCE enforcement).
pub mod native_apps;
/// The OAuth 2.0/OIDC core engine.
pub mod oauth;
/// Client overlay configuration (branding, policy knobs).
pub mod overlays;
/// Passkey (WebAuthn) enrollment and verification.
pub mod passkey;
pub mod policy_docs;
pub mod rfw_aliases;
/// Shield (Sentin8:Policy) integration — shared bridge re-exports.
pub mod policy;
/// Membership provisioning API (used by peers; no table access).
pub mod provision;
/// Resource indicators (RFC 8707).
pub mod resource_indicators;
/// Relying-party metadata surfaces.
pub mod rp_metadata;
/// SCIM 2.0 user/group provisioning.
pub mod scim;
/// SD-JWT / SD-JWT VC issuance and verification.
pub mod sd_jwt;
/// Security admin surfaces (keys, clients, security settings).
pub mod security_admin;
/// Sentin8or (platform assistant) authentication flows.
pub mod sentin8or_auth;
/// Axum router assembly.
pub mod server;
/// Session store and termination.
pub mod sessions;
/// Telemetry emission via Stat.
pub mod telemetry;
/// Token issuance helpers (access/refresh/id families).
pub mod tokens;
/// Verifiable-credential wallet surfaces.
pub mod wallet;
/// Webhook registration and delivery.
pub mod webhooks;

/// Decode a JWT payload without signature verification — test helper for
/// asserting OIDC claim shapes on minted id_tokens.
pub use sentin8::auth::jwt::decode_payload as decode_jwt_payload;
/// OpenAPI spec assembly.
pub mod openapi;
/// Service self-registration declarations.
pub mod registration;

/// Test re-export: auth configuration.
pub use config::AuthConfig as TestConfig;
/// Test re-export: application state.
pub use handlers::AppState;
/// Test re-export: signing keys.
pub use jwks::SigningKeys;
/// Test re-export: router builder.
pub use server::build_router;
