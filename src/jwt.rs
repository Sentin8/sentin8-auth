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
    /// Subject — user ID (for user tokens) or client_id (for M2M tokens).
    pub sub: String,
    /// Issuer — Auth issuer URL.
    pub iss: String,
    /// Audience — the intended recipient (for ID tokens, the client_id).
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
    /// Environment ID (tenant binding — globally unique, sole tenant key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_id: Option<String>,
    /// Email (for user tokens).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The OAuth client_id the token was issued to (which app the user
    /// signed in through, or which M2M client is calling). See.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// FAPI 2.0 Grant Management `grant_id` — references an
    /// `grants` row; revoking the grant revokes tokens carrying it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// `act` claim (RFC 8693 ) — records the original actor for
    /// token-exchange / delegated tokens, or the external IdP `iss`/`sub`
    /// for federated-credential M2M tokens. See.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<serde_json::Value>,
    /// `cnf` claim (RFC 8705) — certificate thumbprint for cert-bound tokens.
    /// Present only for M2M tokens issued via `/mtls/oauth/token`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<serde_json::Value>,
    /// The vertical this workload belongs to (VDC-2, design/
    /// sentin8-vertical-data-plane-contract.md §VDC.4). Set on M2M tokens
    /// from the `auth.m2m_scope_grants.vertical` stamp — Bus's event-ownership
    /// gate rejects produce when the event_type's first colon segment
    /// disagrees (e.g. only `sentin8:sys` may produce `sentin8:sys:*`).
    /// Absent on user/delegated tokens (they never produce).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vertical: Option<String>,
    /// The service this M2M workload performs work FOR (VDC-4, design/
    /// sentin8-vertical-data-plane-contract.md §VDC.5) — stamped from the
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
    /// - `sub` = BFF client_id (machine identity — not the staff user)
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
    pub fn refresh(
        issuer: &str,
        user_id: uuid::Uuid,
        scope: &str,
        env_id: uuid::Uuid,
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
            token_tp: "refresh".into(),
            scope: scope.to_string(),
            env_id: Some(env_id.to_string()),
            email: None,
            client_id: None,
            act: None,
            cnf: None,
            grant_id: None,
            vertical: None,
            service_type: None,
        }
    }

    /// Expiry as a `DateTime<Utc>`.
    pub fn expires_at(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.exp, 0).unwrap_or_else(Utc::now)
    }

    /// Build claims for an OIDC **ID token** (SEC-).
    ///
    /// Per OIDC Core : `iss` = Auth issuer, `sub` = user id, `aud` = the
    /// OAuth client_id, short-lived (≤ access token TTL), with `auth_time`
    /// (the sign-in time), `nonce` (from the authorize request, when
    /// provided), and `at_hash` (left half of SHA-256 of the access token,
    /// base64url — binds the ID token to its access token).
    ///
    /// Email/profile claims are added conditionally by the caller based on
    /// the granted scopes (`email`, `profile`).
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
            ttl,
            None,
        )
    }

    ///build a delegated token from a **publisher** token's
    /// claims (token exchange). Unlike `delegated` (freeform act), this
    /// handles act-chain **nesting**: when the publisher itself is a
    /// delegated token (BFF-issued), its act chain nests — the new act is
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
            vertical: None,
            service_type: None,
        }
    }

    /// `id_token` + RFC 9396 authorization_details echo.
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
        ttl: Duration,
        authorization_details: Option<&serde_json::Value>,
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
        // at_hash — OIDC Core : base64url of the left half of
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
        // RFC 9396 — the ID token carries the granted
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
    fn id_token_claims_shape() {
        let claims = AuthClaims::id_token(
            "https://auth.test.sentin8.local",
            uuid::Uuid::nil(),
            "client_123",
            Some("nonce-abc"),
            1700000000,
            "access-token-value",
            Some("user@example.com"),
            true,
            Some("Alice Smith"),
            true,
            Duration::seconds(900),
        );
        assert_eq!(claims["aud"], "client_123");
        assert_eq!(claims["nonce"], "nonce-abc");
        assert_eq!(claims["auth_time"], 1700000000);
        assert!(claims.get("at_hash").is_some());
        assert_eq!(claims["email"], "user@example.com");
        assert_eq!(claims["name"], "Alice Smith");
    }

    #[test]
    fn id_token_omits_ungranted_claims() {
        let claims = AuthClaims::id_token(
            "https://auth.test.sentin8.local",
            uuid::Uuid::nil(),
            "client_123",
            None,
            1700000000,
            "at",
            None,
            false,
            None,
            false,
            Duration::seconds(900),
        );
        assert!(claims.get("email").is_none());
        assert!(claims.get("name").is_none());
        assert!(claims.get("nonce").is_none());
    }
}
