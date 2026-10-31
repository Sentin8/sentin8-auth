// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-License-Identifier: Apache-2.0

//! Typed response DTOs for the OAuth/wallet/CIBA/consent/SCIM admin
//! surfaces (no free-form 200 bodies).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The merged tenant branding payload (`GET /v1/branding`).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BrandingResponse {
    /// The org display name (absent when empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_name: Option<String>,
    /// Org base + env override (env wins when non-empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    /// The icon URL override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_icon_url: Option<String>,
    /// Primary accent color.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,
    /// Secondary accent color.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accent_color: Option<String>,
    /// `dark` (default) or `light`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theme_mode: Option<String>,
    /// Type family override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub font_family: Option<String>,
    /// Custom CSS injected into the hosted UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_css: Option<String>,
    /// Sign-in page tagline override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in_text: Option<String>,
}

/// A created app password (`POST /v1/me/app-passwords`); the raw
/// secret is shown once.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AppPasswordCreated {
    /// The password row id.
    pub id: Uuid,
    /// The caller-chosen label.
    pub label: String,
    /// The scope whitelist.
    pub allowed_scopes: Vec<String>,
    /// The raw secret (shown once; only a hash is stored).
    pub secret: String,
}

/// One stored app password (no hash, no secret).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AppPasswordItem {
    /// The password row id.
    pub id: Uuid,
    /// The caller-chosen label.
    pub label: String,
    /// The scope whitelist.
    pub allowed_scopes: Vec<String>,
    /// `active`/`revoked`.
    pub status: String,
    /// Last successful use (absent when never used).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Creation instant.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// The caller's app-password list.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AppPasswordList {
    /// The stored passwords (most recent first).
    pub items: Vec<AppPasswordItem>,
}

/// The revoke/delete acknowledgement.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DeletedAck {
    /// Always `deleted`.
    pub status: String,
}

/// `GET /v1/auth/consent/accounts` payload: the customer accounts the
/// consented scopes resolve to.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ConsentAccountsResponse {
    /// The consenting customer accounts.
    pub accounts: Vec<serde_json::Value>,
}

/// The `GET /oauth/userinfo` claims document (the live identity
/// projection: subject + live roles/groups/scopes).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OidcClaims {
    /// The subject id (the BFF client id on delegated tokens: the
    /// `token_tp`/`act` chain is not leaked).
    pub sub: String,
    /// The user's email (absent when the subject is a client).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The email's verified flag (the `email` scope's second member,
    ///.4 - served with the email claim family).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Given (first) name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Family (last) name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// Full name (OIDC Core §5.1 profile member; derived from the stored
    /// name parts / `oidc_profile.name` - DESIGN §9a.11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Middle name (profile family, verbatim from `oidc_profile`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    /// Casual name (profile family, verbatim from `oidc_profile`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    /// Shorthand the end-user wishes to be known as (profile family,
    /// verbatim from `oidc_profile`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// Profile page URL (profile family, verbatim from `oidc_profile`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Avatar picture URL (profile family, verbatim from `oidc_profile`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// Web site URL (profile family, verbatim from `oidc_profile`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// Gender (profile family, verbatim from `oidc_profile`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,
    /// Birthdate (`YYYY-MM-DD`, profile family, verbatim from
    /// `oidc_profile`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,
    /// Geodata / time zone string (profile family, verbatim from
    /// `oidc_profile`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,
    /// Locale (BCP 47, profile family, verbatim from `oidc_profile`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Last profile update time (profile family, derived from the users
    /// row's `updated_at` - DESIGN §9a.11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    /// Phone number (`phone_number`, served when the token's scope
    /// includes `phone`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    /// Phone verified flag (served with the phone claim family).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    /// OIDC address claim object (served when the token's scope includes
    /// `address`): `{formatted, street_address, locality, region,
    /// postal_code, country}` with absent columns omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<serde_json::Value>,
    /// Live-resolved role names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// Live-resolved group names (user tokens only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    /// Live-resolved effective scopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// The token's client id (present on delegated/M2M subjects).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// The token type (`access`/`delegated`/`m2m`; delegated only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_tp: Option<String>,
}

/// `POST /device/verify` ack.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DeviceVerifyResponse {
    /// The recorded decision: `approved` or `denied` (RFC 8628 §3.4 -
    /// the polling grant answers tokens or `access_denied`).
    pub status: String,
}

/// SAML 2.0 SP metadata descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SamlMetadataResponse {
    /// The SP entity id.
    pub entity_id: String,
    /// The Assertion Consumer Service URL.
    pub acs_url: String,
    /// The metadata XML document.
    pub xml: String,
}

// ── Wallet / OID4VP / OID4VCI (wallet.rs) ────────────────────────────────

/// `GET /v1/auth/wallet/metadata` payload.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WalletMetadata {
    /// The wallet issuer / presentation endpoint base.
    pub issuer: String,
    /// The verifiable-presentation formats this issuer accepts.
    pub vp_formats_supported: serde_json::Value,
    /// The issuers this wallet trusts.
    pub trusted_issuers: serde_json::Value,
    /// The presentation definition the wallet must satisfy.
    pub presentation_definition: serde_json::Value,
    /// Minimum level of assurance.
    pub min_level_of_assurance: serde_json::Value,
    /// Always `direct_post`.
    pub response_mode: String,
    /// The VP response endpoint.
    pub vp_response_endpoint: String,
}

/// `POST /oauth/credentials/issue` response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CredentialOfferResponse {
    /// The credential (wallet) issuer.
    pub credential_issuer: String,
    /// The credential configuration id (type).
    pub credential_configuration_id: String,
    /// The offered credential id.
    pub credential_id: Uuid,
    /// Offer deferred by the issuer.
    pub deferred: bool,
}

/// `POST /oauth/credentials` response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CredentialIssuedResponse {
    /// The credential format.
    pub format: String,
    /// The issued credential document (SD-JWT / mdoc).
    pub credential: String,
    /// Status List envelope the credential enrolls in.
    pub status_list: serde_json::Value,
}

/// `POST /oauth/credentials/status/{id}` response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct StatusListDocument {
    /// The Status List envelope (idx + compressed bitstring).
    pub status_list: serde_json::Value,
}

/// `GET /oauth/authorize` (OID4VP flow) response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WalletAuthorizeResponse {
    /// The request nonce.
    pub nonce: String,
    /// The signed request-object URI.
    pub request_uri: String,
    /// The signed request object document.
    pub request_object: serde_json::Value,
    /// The `openid4vp://` deep link for QR rendering.
    pub qr_data: String,
    /// Pending TTL seconds.
    pub expires_in: i64,
}

/// `POST /oauth/vp/response` response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct VpResponse {
    /// Always `verified` on success.
    pub status: String,
    /// The minted session token.
    pub session_token: String,
    /// The OAuth authorization code.
    pub code: String,
    /// The pending request's redirect target.
    pub redirect_uri: serde_json::Value,
    /// Assured level of identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Auth methods used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    /// The verified user id.
    pub user_id: Uuid,
}

// ── CIBA (ciba.rs) ──────────────────────────────────────────────────────

/// `GET /v1/ciba/assisted/{auth_req_id}` payload.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CibaAssistedPage {
    /// The CIBA request id.
    pub auth_req_id: String,
    /// The human binding message.
    pub binding_message: serde_json::Value,
    /// Requested scopes.
    pub scope: serde_json::Value,
    /// The requesting client.
    pub client_id: serde_json::Value,
    /// `pending`/`approved`.
    pub status: String,
    /// The short confirmation code the customer types in.
    pub short_code: String,
}

/// `POST /v1/ciba/assisted/{auth_req_id}/complete` response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CibaAssistedComplete {
    /// The completion status.
    pub status: String,
    /// `true` when this call re-read an already-completed request
    /// (idempotent replay; absent on the first completion).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub already_completed: Option<bool>,
}

/// `POST /v1/ciba/approve` response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CibaApproveResponse {
    /// The approval status.
    pub status: String,
}

/// `POST /v1/internal/keys/rotate` response (cron proxy-back).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RotateKeysResponse {
    /// `rotated` when a new key was minted; `skipped` when the newest
    /// key is younger than the 30-day cadence.
    pub status: String,
    /// The skip reason (skipped runs only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Age of the newest key, days (skipped runs only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub newest_age_days: Option<f64>,
    /// The new key id (rotated runs only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// The new key algorithm (rotated runs only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

/// SCIM 2.0 ServiceProviderConfig.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimServiceProviderConfig {
    /// The SCIM schema URIs.
    pub schemas: Vec<String>,
    /// PATCH capability.
    pub patch: serde_json::Value,
    /// Bulk capability.
    pub bulk: serde_json::Value,
    /// Filter capability.
    pub filter: serde_json::Value,
    /// changePassword capability.
    pub change_password: serde_json::Value,
    /// sort capability.
    pub sort: serde_json::Value,
    /// etag capability.
    pub etag: serde_json::Value,
    /// Authentication schemes.
    pub authentication_schemes: Vec<serde_json::Value>,
}

/// SCIM 2.0 ListResponse (groups mirrors).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ScimListResponse {
    /// The SCIM schema URI of the list envelope.
    pub schemas: Vec<String>,
    /// Total matched.
    pub total_results: usize,
    /// The page of resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<serde_json::Value>>,
}

/// One SCIM resource-type descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ScimResourceType {
    /// The resource type id (`User`/`Group`).
    pub id: String,
    /// Human name.
    pub name: String,
    /// SCIM endpoint for the type.
    pub endpoint: String,
    /// The core schema URI.
    pub schema: String,
}

/// `GET /v1/admin/groups/{id}/members` payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct GroupMembersResponse {
    /// The group's member rows.
    pub members: Vec<crate::admin::GroupMemberResponse>,
}
