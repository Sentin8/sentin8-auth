// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! JWT claims structures for all Sentin8 token types.
//!
//! See

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Claims for all Sentin8-issued JWTs (access tokens, M2M tokens, ID tokens).
///
/// The `token_tp` field distinguishes token types: `"m2m"`, `"access"`, `"id"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthClaims {
    /// Subject - user ID (for user tokens) or client_id (for M2M tokens).
    pub sub: String,
    /// Issuer - Auth issuer URL.
    pub iss: String,
    /// Audience - the intended recipient (for ID tokens, the client_id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// JWT ID (unique per token).
    pub jti: String,
    /// Issued-at timestamp.
    pub iat: i64,
    /// Expiry timestamp.
    pub exp: i64,
    /// Token type marker: `"m2m"`, `"access"`, `"id"`.
    #[serde(rename = "token_tp")]
    pub token_tp: String,
    /// Scope string (space-separated).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    /// Environment ID (tenant binding - globally unique, sole tenant key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_id: Option<String>,
    /// Email (for user tokens).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The OAuth client_id the token was issued to (which app the user
    /// signed in through, or which M2M client is calling). See.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// FAPI 2.0 Grant Management `grant_id` - references an
    /// `grants` row; revoking the grant revokes tokens carrying it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    // OIDC Core 5.4/5.5 (DESIGN 9a.11): the USERINFO claim names the
    // client's claims request selected (essential or voluntary) -
    // stamped at exchange time so userinfo serves them without a
    // matching scope (the selection IS the consent signal).
    /// OIDC Core §5.4/§5.5 (DESIGN §9a.11): the USERINFO claim names the
    /// client's claims request selected at login - stamped onto the
    /// access token so userinfo serves them without the scope family.
    #[serde(rename = "userinfo_claims", skip_serializing_if = "Option::is_none")]
    pub userinfo_claims: Option<Vec<String>>,
    /// `act` claim (RFC 8693 ) - records the original actor for
    /// token-exchange / delegated tokens, or the external IdP `iss`/`sub`
    /// for federated-credential M2M tokens. See.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<serde_json::Value>,
    /// `cnf` claim (RFC 8705) - certificate thumbprint for cert-bound tokens.
    /// Present only for M2M tokens issued via `/mtls/oauth/token`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<serde_json::Value>,
    /// The vertical this workload belongs to (VDC-2, design/
    /// sentin8-vertical-data-plane-contract.md §VDC.4). Set on M2M tokens
    /// from the `auth.m2m_scope_grants.vertical` stamp - Bus's event-ownership
    /// gate rejects produce when the event_type's first colon segment
    /// disagrees (e.g. only `sentin8:sys` may produce `sentin8:sys:*`).
    /// Absent on user/delegated tokens (they never produce).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vertical: Option<String>,
    /// The service this M2M workload performs work FOR (VDC-4, design/
    /// sentin8-vertical-data-plane-contract.md §VDC.5) - stamped from the
    /// same enroll row as `vertical` (workload names are inconsistent, so
    /// the registry is the source of truth). Consumers use it for scoped
    /// discovery WITHOUT cross-schema reads: Sys's tenant-snapshot API
    /// answers only for envs where the caller's own service is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
}

impl AuthClaims {
    /// Build claims for an M2M (client_credentials) token.
    pub fn m2m(issuer: &str, client_id: &str, scope: &str, env_id: String, ttl: Duration) -> Self {
        let now = Utc::now();
        Self {
            sub: client_id.to_string(),
            iss: issuer.to_string(),
            aud: None,
            jti: uuid::Uuid::new_v4().to_string(),
            iat: now.timestamp(),
            exp: (now + ttl).timestamp(),
            token_tp: "m2m".into(),
            scope: scope.to_string(),
            env_id: Some(env_id),
            email: None,
            client_id: Some(client_id.to_string()),
            act: None,
            cnf: None,
            grant_id: None,
            userinfo_claims: None,
            vertical: None,
            service_type: None,
        }
    }

    /// Build claims for an M2M token issued via federated credentials
    /// (workload-identity federation). The `act` claim records the
    /// external IdP `iss`/`sub` that vouched for the workload.
    pub fn m2m_with_act(
        issuer: &str,
        client_id: &str,
        scope: &str,
        env_id: String,
        ttl: Duration,
        act: &serde_json::Value,
    ) -> Self {
        let mut claims = Self::m2m(issuer, client_id, scope, env_id, ttl);
        claims.act = Some(act.clone());
        claims
    }

    /// Build claims for a delegated access token (Delegation Gateway).
    ///
    /// Issued by Auth's `POST /delegate/access-token` endpoint when BFF
    /// (acting as Delegation Gateway) requests a cross-realm token on behalf
    /// of a staff user. The token is:
    /// - `sub` = BFF client_id (machine identity - not the staff user)
    /// - `realm` = "delegated"
    /// - `act` = `{sub, email, realm}` (the staff user who initiated)
    /// - `cnf` = cert thumbprint (cert-bound, RFC 8705 sender-constrained)
    /// - `aud` = target service (RFC 8707 resource indicator)
    /// - `org_id`/`env_id` = target tenant
    /// - `scope` = downscoped to the requested subset
    pub fn delegated(
        issuer: &str,
        client_id: &str,
        scope: &str,
        env_id: String,
        ttl: Duration,
        act: &serde_json::Value,
        cnf: Option<serde_json::Value>,
        audience: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            sub: client_id.to_string(),
            iss: issuer.to_string(),
            aud: audience,
            jti: uuid::Uuid::new_v4().to_string(),
            iat: now.timestamp(),
            exp: (now + ttl).timestamp(),
            token_tp: "delegated".into(),
            scope: scope.to_string(),
            env_id: Some(env_id),
            email: None,
            client_id: Some(client_id.to_string()),
            act: Some(act.clone()),
            cnf,
            grant_id: None,
            userinfo_claims: None,
            vertical: None,
            service_type: None,
        }
    }

    /// Build claims for a user access token.
    pub fn access(
        issuer: &str,
        user_id: uuid::Uuid,
        scope: &str,
        env_id: uuid::Uuid,
        email: Option<&str>,
        ttl: Duration,
    ) -> Self {
        Self::access_with_client(issuer, user_id, scope, env_id, email, None, ttl)
    }

    /// Build claims for a user access token, recording the OAuth client_id
    /// the user signed in through (which app). Pass `None` for
    /// non-OAuth (direct sign-in) flows.
    pub fn access_with_client(
        issuer: &str,
        user_id: uuid::Uuid,
        scope: &str,
        env_id: uuid::Uuid,
        email: Option<&str>,
        client_id: Option<&str>,
        ttl: Duration,
    ) -> Self {
        let now = Utc::now();
        Self {
            sub: user_id.to_string(),
            iss: issuer.to_string(),
            aud: None,
            jti: uuid::Uuid::new_v4().to_string(),
            iat: now.timestamp(),
            exp: (now + ttl).timestamp(),
            token_tp: "access".into(),
            scope: scope.to_string(),
            env_id: Some(env_id.to_string()),
            email: email.map(|s| s.to_string()),
            client_id: client_id.map(|s| s.to_string()),
            act: None,
            cnf: None,
            grant_id: None,
            userinfo_claims: None,
            vertical: None,
            service_type: None,
        }
    }

    /// Build claims for a refresh token.
    ///
    /// The refresh token carries the original requested scope so that a
    /// refresh grant can re-issue an access token with the same scopes
    /// (requested ∪ role). Without this, a refresh would lose app-specific
    /// scopes (e.g. `fdx:recipient:read`) that were requested at login but
    /// are not granted by any role.
    ///
    /// `client_id` binds the token to its issuing client (OIDC/SEC-):
    /// the refresh grant rejects a token presented by ANY other client
    /// (the suite's refresh-token client-binding check depends on it -
    /// a client-2 token used by client 1 MUST read invalid_grant).
    /// `client_id` is None only for legacy/platform-internal refresh
    /// paths that never present the token to the grant (none in-tree).
    pub fn refresh(
        issuer: &str,
        user_id: uuid::Uuid,
        scope: &str,
        env_id: uuid::Uuid,
        ttl: Duration,
        client_id: Option<&str>,
    ) -> Self {
        let now = Utc::now();
        Self {
            sub: user_id.to_string(),
            iss: issuer.to_string(),
            aud: None,
            jti: uuid::Uuid::new_v4().to_string(),
            iat: now.timestamp(),
            exp: (now + ttl).timestamp(),
            token_tp: "refresh".into(),
            scope: scope.to_string(),
            env_id: Some(env_id.to_string()),
            email: None,
            client_id: client_id.map(str::to_string),
            act: None,
            cnf: None,
            grant_id: None,
            userinfo_claims: None,
            vertical: None,
            service_type: None,
        }
    }

    /// Expiry as a `DateTime<Utc>`.
    pub fn expires_at(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.exp, 0).unwrap_or_else(Utc::now)
    }

    /// Build claims for an OIDC **ID token**.
    ///
    /// Per OIDC Core : `iss` = Auth issuer, `sub` = user id, `aud` = the
    /// OAuth client_id, short-lived (≤ access token TTL), with `auth_time`
    /// (the sign-in time), `nonce` (from the authorize request, when
    /// provided), and `at_hash` (left half of SHA-256 of the access token,
    /// base64url - binds the ID token to its access token).
    ///
    /// Email/profile claims are added conditionally by the caller based on
    /// the granted scopes (`email`, `profile`); phone/address follow the
    /// same gating (DESIGN §9a.4).
    pub fn id_token(
        issuer: &str,
        user_id: uuid::Uuid,
        client_id: &str,
        nonce: Option<&str>,
        auth_time: i64,
        access_token: &str,
        email: Option<&str>,
        include_email_claims: bool,
        name: Option<&str>,
        include_profile_claims: bool,
        phone: Option<&str>,
        include_phone_claims: bool,
        address: Option<&serde_json::Value>,
        include_address_claims: bool,
        ttl: Duration,
    ) -> serde_json::Value {
        Self::id_token_with_details(
            issuer,
            user_id,
            client_id,
            nonce,
            auth_time,
            access_token,
            email,
            include_email_claims,
            name,
            include_profile_claims,
            phone,
            include_phone_claims,
            address,
            include_address_claims,
            ttl,
            None,
            None,
            None,
        )
    }

    ///build a delegated token from a **publisher** token's
    /// claims (token exchange). Unlike `delegated` (freeform act), this
    /// handles act-chain **nesting**: when the publisher itself is a
    /// delegated token (BFF-issued), its act chain nests - the new act is
    /// {sub: publisher_sub, act: {sub: original_staff_sub, email}} so the
    /// full delegation chain stays auditable.
    pub fn delegated_from_publisher(
        issuer: &str,
        subscriber_client_id: &str,
        publisher_sub: &str,
        publisher_act: Option<&serde_json::Value>,
        scope: &str,
        env_id: &str,
        audience: Option<String>,
        cnf: Option<serde_json::Value>,
        exp: i64,
    ) -> Self {
        let now = chrono::Utc::now();
        let act = match publisher_act {
            Some(inner) => serde_json::json!({
                "sub": publisher_sub,
                "act": inner,
            }),
            None => serde_json::json!({
                "sub": publisher_sub,
            }),
        };
        Self {
            sub: subscriber_client_id.to_string(),
            iss: issuer.to_string(),
            aud: audience,
            jti: uuid::Uuid::new_v4().to_string(),
            iat: now.timestamp(),
            exp,
            token_tp: "delegated".into(),
            scope: scope.to_string(),
            env_id: Some(env_id.to_string()),
            email: None,
            client_id: Some(subscriber_client_id.to_string()),
            act: Some(act),
            cnf,
            grant_id: None,
            userinfo_claims: None,
            vertical: None,
            service_type: None,
        }
    }

    /// `id_token` + RFC 9396 authorization_details echo.
    ///
    /// The phone/address claim families (auth DESIGN §9a.4) follow the
    /// email/profile pattern: each is included ONLY when the consented
    /// scope granted it (`phone` → `phone_number`/`phone_number_verified`,
    /// `address` → the OIDC address JSON object via
    /// [`build_address_claim`]).
    #[allow(clippy::too_many_arguments)]
    pub fn id_token_with_details(
        issuer: &str,
        user_id: uuid::Uuid,
        client_id: &str,
        nonce: Option<&str>,
        auth_time: i64,
        access_token: &str,
        email: Option<&str>,
        include_email_claims: bool,
        name: Option<&str>,
        include_profile_claims: bool,
        phone: Option<&str>,
        include_phone_claims: bool,
        address: Option<&serde_json::Value>,
        include_address_claims: bool,
        ttl: Duration,
        authorization_details: Option<&serde_json::Value>,
        extra_claims: Option<&serde_json::Map<String, serde_json::Value>>,
        acr: Option<&str>,
    ) -> serde_json::Value {
        let now = Utc::now();
        let mut claims = serde_json::json!({
                   "iss": issuer,
                   "sub": user_id.to_string(),
                   "aud": client_id,
                   "jti": uuid::Uuid::new_v4().to_string(),
                   "iat": now.timestamp(),
                   "exp": (now + ttl).timestamp(),
                   "auth_time": auth_time,
        // at_hash - OIDC Core : base64url of the left half of
        // SHA-256(access_token ASCII bytes).
                   "at_hash": at_hash(access_token),
               });
        if let Some(n) = nonce {
            claims["nonce"] = serde_json::json!(n);
        }
        if include_email_claims {
            claims["email"] = serde_json::json!(email.unwrap_or_default());
            claims["email_verified"] = serde_json::json!(true);
        }
        if include_profile_claims {
            if let Some(n) = name {
                claims["name"] = serde_json::json!(n);
            }
        }
        if include_phone_claims {
            if let Some(p) = phone {
                claims["phone_number"] = serde_json::json!(p);
            }
            claims["phone_number_verified"] = serde_json::json!(true);
        }
        if include_address_claims {
            if let Some(a) = address {
                claims["address"] = a.clone();
            }
        }
        // DESIGN §9a.11 - the extra claim payload overlays HERE for the
        // profile family (the mint site passes the scope-gated map, so
        // the overlay never widens beyond the consented scope).
        if let Some(extra) = extra_claims {
            if let Some(o) = claims.as_object_mut() {
                for (k, v) in extra {
                    o.insert(k.clone(), v.clone());
                }
            }
        }
        // DESIGN §9a.11 - the `acr` claim echoes the authorize request's
        // first `acr_values` entry (OIDC Core §3.1.2.1).
        if let Some(a) = acr.filter(|s| !s.is_empty()) {
            claims["acr"] = serde_json::json!(a);
        }
        // RFC 9396 - the ID token carries the granted
        // authorization_details so the client can verify what it asked for.
        if let Some(details) = authorization_details {
            claims["authorization_details"] = details.clone();
        }
        claims
    }
}

/// Compute the OIDC `at_hash` claim: base64url of the left half of
/// SHA-256 of the access token's ASCII bytes (OIDC Core ).
pub fn at_hash(access_token: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(access_token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16])
}

/// Compute the OIDC `c_hash` claim (OIDC Core §3.1.3.6): base64url of
/// the left half of SHA-256 of the authorization code's ASCII bytes -
/// lets the client confirm the code it received is the one the OP
/// issued, binding the ID token to the code flow that produced it.
/// Same construction as [`at_hash`] (DESIGN §9a.3).
pub fn c_hash(code: &str) -> String {
    at_hash(code)
}

/// Compute the FAPI 1.0 Advanced `s_hash` claim: base64url of the left
/// half of SHA-256 of the `state` value's ASCII bytes (FAPI 1 §5.2.2.1 -
/// the ID token MUST contain an s_hash when state is present). Shares
/// the at_hash construction (DESIGN §9a.3).
pub fn s_hash(state: &str) -> String {
    at_hash(state)
}

/// Build the OIDC `address` claim JSON object (OIDC Core §5.2.2, auth
/// DESIGN §9a.4) from the users table's postal columns. The spec shape:
/// `{formatted, street_address, locality, region, postal_code, country}` -
/// absent columns are omitted; a fully empty address yields `None` (the
/// claim is only meaningful when the user has address data).
/// Derived `name` claim: `oidc_profile.name` first, then the
/// name parts joined (DESIGN §9a.11). Empty parts drop out; a fully
/// empty profile yields `None`.
pub fn derive_profile_name(
    profile_name: Option<&str>,
    first_name: Option<&str>,
    last_name: Option<&str>,
) -> Option<String> {
    if let Some(n) = profile_name.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(n.to_string());
    }
    let joined = [first_name, last_name]
        .iter()
        .filter_map(|s| *s)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!joined.is_empty()).then_some(joined)
}

/// The OIDC Core §5.1 standard members of the `profile` claim family
/// (the §5.5 standard-mapped set): every member the userinfo response /
/// ID token can mint. `name` and `updated_at` are derived (§9a.11);
/// the rest come from the users table's `oidc_profile` JSONB verbatim.
pub(crate) const PROFILE_FAMILY_MEMBERS: [&str; 11] = [
    "name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
];

/// Build the `profile`-scope claim payload (OAuth params as JSON):
/// every populated member, keyed by OIDC claim name. Callers gate this
/// on the consented `profile` scope and map the shape onto their mint
/// (userinfo serializes it into the response; the ID-token mint merges
/// it into the claims object). `updated_at` rides `extras` (the unix
/// epoch of the users row's updated_at, mint-site derived).
pub fn build_profile_claims(
    name: Option<&str>,
    oidc_profile: &serde_json::Value,
    updated_at_epoch: Option<i64>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    if let Some(n) = name.filter(|s| !s.is_empty()) {
        out.insert("name".into(), serde_json::Value::String(n.into()));
    }
    if let Some(obj) = oidc_profile.as_object() {
        for member in PROFILE_FAMILY_MEMBERS.iter().skip(1) {
            if let Some(v) = obj.get(*member) {
                // Only populated, non-empty members are minted - an
                // absent member stays absent (never null).
                match v {
                    serde_json::Value::String(sv) if !sv.is_empty() => {
                        out.insert((*member).into(), v.clone());
                    }
                    other @ (serde_json::Value::Bool(_)
                    | serde_json::Value::Number(_)) => {
                        out.insert((*member).into(), other.clone());
                    }
                    _ => {}
                }
            }
        }
    }
    if let Some(at) = updated_at_epoch {
        out.insert("updated_at".into(), serde_json::Value::from(at));
    }
    out
}

/// Build the OIDC `address` claim object (OIDC Core §5.1.1) from the
/// users row's postal columns: `formatted` joins the populated parts;
/// absent parts stay absent. Returns `None` when NO part is populated
/// (an empty address stays out of the token).
pub fn build_address_claim(
    street_address: Option<&str>,
    locality: Option<&str>,
    region: Option<&str>,
    postal_code: Option<&str>,
    country: Option<&str>,
) -> Option<serde_json::Value> {
    let parts: Vec<String> = [street_address, locality, region, postal_code, country]
        .iter()
        .filter_map(|s| s.map(|v| v.to_string()).filter(|v| !v.is_empty()))
        .collect();
    if parts.is_empty() {
        return None;
    }
    let mut obj = serde_json::Map::new();
    obj.insert(
        "formatted".into(),
        serde_json::Value::String(parts.join(", ")),
    );
    if let Some(v) = street_address.filter(|s| !s.is_empty()) {
        obj.insert("street_address".into(), serde_json::Value::String(v.into()));
    }
    if let Some(v) = locality.filter(|s| !s.is_empty()) {
        obj.insert("locality".into(), serde_json::Value::String(v.into()));
    }
    if let Some(v) = region.filter(|s| !s.is_empty()) {
        obj.insert("region".into(), serde_json::Value::String(v.into()));
    }
    if let Some(v) = postal_code.filter(|s| !s.is_empty()) {
        obj.insert("postal_code".into(), serde_json::Value::String(v.into()));
    }
    if let Some(v) = country.filter(|s| !s.is_empty()) {
        obj.insert("country".into(), serde_json::Value::String(v.into()));
    }
    Some(serde_json::Value::Object(obj))
}

/// Build the eKYC-IDA `verified_claims` object (OIDC eKYC-IDA §5,
/// DESIGN §9a.7) from a stored credential's data. The shape is the
/// spec's two-part structure:
/// - `verification` - the trust framework, evidence, and time
/// - `claims` - the verified subset the credential attests
/// The caller (ID-token / userinfo mint) includes it ONLY when the
/// claims request selected it (or the credential scope was consented)
/// AND an active credential of the matching type exists.
pub fn build_verified_claims(
    trust_framework: &str,
    credential_type: &str,
    credential_data: &serde_json::Value,
    verified_at: i64,
) -> serde_json::Value {
    // The verified subset: the credential's non-selective claims, minus
    // the wallet-key binding (cnf is transport, not subject data).
    let mut claims = credential_data
        .as_object()
        .cloned()
        .unwrap_or_default();
    claims.remove("cnf");
    claims.remove("requested_claims");
    claims.remove("notifications");
    serde_json::json!({
        "verification": {
            "trust_framework": trust_framework,
            "time": verified_at,
            "evidence": [
                {
                    "type": credential_type,
                    "time": verified_at,
                }
            ],
        },
        "claims": claims,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_hash_is_22_char_base64url_of_half_sha256() {
        // SHA-256 of the empty string is e3b0c4...; left half is 16 bytes
        // → 22 base64url chars, no padding.
        let h = at_hash("");
        assert_eq!(h.len(), 22);
        assert!(!h.contains('='));
        assert!(!h.contains('+'));
        assert!(!h.contains('/'));
    }

    #[test]
    fn c_hash_matches_at_hash_construction() {
        // OIDC Core §3.1.3.6: c_hash is the same left-half SHA-256
        // construction applied to the authorization code.
        assert_eq!(c_hash("some-code"), at_hash("some-code"));
        assert_eq!(c_hash("").len(), 22);
    }

    #[test]
    fn s_hash_matches_at_hash_construction() {
        // FAPI 1.0 §5.2.2.1: s_hash applies the same construction to
        // the state value.
        assert_eq!(s_hash("some-state"), at_hash("some-state"));
        assert_eq!(s_hash("").len(), 22);
    }

    #[test]
    fn id_token_claims_shape() {
        let claims = AuthClaims::id_token(
            "https://auth.test.local.sentin8.dev",
            uuid::Uuid::nil(),
            "client_123",
            Some("nonce-abc"),
            1700000000,
            "access-token-value",
            Some("user@example.com"),
            true,
            Some("Alice Smith"),
            true,
            Some("+15551234567"),
            true,
            Some(&serde_json::json!({
                "formatted": "1 Main St, Springfield, IL 62701, US",
                "street_address": "1 Main St",
                "locality": "Springfield",
                "region": "IL",
                "postal_code": "62701",
                "country": "US"
            })),
            true,
            Duration::seconds(900),
        );
        assert_eq!(claims["aud"], "client_123");
        assert_eq!(claims["nonce"], "nonce-abc");
        assert_eq!(claims["auth_time"], 1700000000);
        assert!(claims.get("at_hash").is_some());
        assert_eq!(claims["email"], "user@example.com");
        assert_eq!(claims["name"], "Alice Smith");
        assert_eq!(claims["phone_number"], "+15551234567");
        assert_eq!(claims["phone_number_verified"], true);
        assert_eq!(claims["address"]["postal_code"], "62701");
        assert_eq!(claims["address"]["country"], "US");
    }

    #[test]
    fn id_token_omits_ungranted_claims() {
        let claims = AuthClaims::id_token(
            "https://auth.test.local.sentin8.dev",
            uuid::Uuid::nil(),
            "client_123",
            None,
            1700000000,
            "at",
            None,
            false,
            None,
            false,
            None,
            false,
            None,
            false,
            Duration::seconds(900),
        );
        assert!(claims.get("email").is_none());
        assert!(claims.get("name").is_none());
        assert!(claims.get("nonce").is_none());
        assert!(claims.get("phone_number").is_none());
        assert!(claims.get("phone_number_verified").is_none());
        assert!(claims.get("address").is_none());
    }

    #[test]
    fn id_token_omits_ungranted_phone_address_even_with_data() {
        // DESIGN §9a.4: the scope gate - not data presence - decides.
        let claims = AuthClaims::id_token(
            "https://auth.test.local.sentin8.dev",
            uuid::Uuid::nil(),
            "client_123",
            None,
            1700000000,
            "at",
            None,
            false,
            None,
            false,
            Some("+15551234567"),
            false,
            Some(&serde_json::json!({"country": "US"})),
            false,
            Duration::seconds(900),
        );
        assert!(claims.get("phone_number").is_none());
        assert!(claims.get("address").is_none());
    }

    #[test]
    fn address_claim_object_shape() {
        let a = build_address_claim(
            Some("1 Main St"),
            Some("Springfield"),
            Some("IL"),
            Some("62701"),
            Some("US"),
        )
        .expect("full address builds");
        assert_eq!(a["formatted"], "1 Main St, Springfield, IL, 62701, US");
        assert_eq!(a["street_address"], "1 Main St");
        assert_eq!(a["locality"], "Springfield");
        assert_eq!(a["region"], "IL");
        assert_eq!(a["postal_code"], "62701");
        assert_eq!(a["country"], "US");
    }

    #[test]
    fn address_claim_empty_yields_none() {
        assert!(build_address_claim(None, None, None, None, None).is_none());
        assert!(build_address_claim(
            Some(""),
            Some(""),
            Some(""),
            Some(""),
            Some("")
        )
        .is_none());
    }
}
