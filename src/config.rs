// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Auth configuration loaded from environment variables.

use std::env;

/// System Organization ID (`00000000-0000-0000-0000-000000000001`).
/// The system org id constant.
pub const SYSTEM_ORG_ID: uuid::Uuid = uuid::Uuid::from_u128(0x00000000_0000_0000_0000_000000000001);
/// System Environment ID (`00000000-0000-0000-0000-000000000002`).
/// The system env id constant.
pub const SYSTEM_ENV_ID: uuid::Uuid = uuid::Uuid::from_u128(0x00000000_0000_0000_0000_000000000002);

#[derive(Debug, Clone)]
/// Configuration for auth.
pub struct AuthConfig {
    /// The port.
    pub port: u16,
    /// The issuer.
    pub issuer: String,
    /// The JWKS URL.
    pub jwks_url: String,
    /// The database URL.
    pub database_url: String,
    /// The valkey URL.
    pub valkey_url: String,
    /// The sentin8 domain.
    pub sentin8_domain: String,
    /// Session TTL in seconds (default 86400 = 24h).
    /// The session ttl secs.
    pub session_ttl_secs: u64,
    /// Access token TTL in seconds (default 900 = 15 min, FAPI 2.0 default).
    /// The access token ttl secs.
    pub access_token_ttl_secs: u64,
    /// M2M token TTL in seconds (default 3600 = 1h).
    /// The m2m token ttl secs.
    pub m2m_token_ttl_secs: u64,
    /// Refresh token TTL in seconds (default 2592000 = 30 days).
    /// The refresh token ttl secs.
    pub refresh_token_ttl_secs: u64,
    ///Stat property ID for this service's telemetry.
    /// sentin8 stat property identifier.
    pub sentin8_stat_property_id: uuid::Uuid,
    ///Stat base URL.
    /// The sentin8 stat URL.
    pub sentin8_stat_url: String,
    ///- Bus base URL for event publication.
    /// The sentin8 bus URL.
    pub sentin8_bus_url: String,
    ///- Bus stream family for Auth events
    /// (default `"auth"`).
    /// The stream family.
    pub stream_family: String,
}

impl AuthConfig {
    /// Handle from env.
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        let sentin8_domain = cfg.domain().to_string();
        Self {
            port: env::var("SENTIN8_AUTH_PORT")
                .expect("SENTIN8_AUTH_PORT must be set by captain")
                .parse()
                .expect("SENTIN8_AUTH_PORT must be a valid u16"),
            issuer: env::var("SENTIN8_AUTH_ISSUER").unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
            jwks_url: env::var("SENTIN8_AUTH_JWKS_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            database_url: env::var("SENTIN8_AUTH_DB_DSN").unwrap_or_else(|_| {
                env::var("DATABASE_URL").unwrap_or_else(|_| {
                    sentin8::config::Sentin8Config::default_database_url().to_string()
                })
            }),
            // (group DESIGN.md §3.1): explicit env override,
            // else the plane-derived URL - the historical `/1` DB number was
            // inert (GLIDE connects at DB 0; ACLs are the isolation).
            valkey_url: env::var("SENTIN8_AUTH_VALKEY_URL")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(sentin8::config::service_valkey_url),
            sentin8_domain,
            session_ttl_secs: env::var("SENTIN8_AUTH_SESSION_TTL")
                .unwrap_or("86400".into())
                .parse()
                .unwrap_or(86400),
            access_token_ttl_secs: env::var("SENTIN8_AUTH_ACCESS_TOKEN_TTL")
                .unwrap_or("900".into())
                .parse()
                .unwrap_or(900),
            m2m_token_ttl_secs: env::var("SENTIN8_AUTH_M2M_TOKEN_TTL")
                .unwrap_or("3600".into())
                .parse()
                .unwrap_or(3600),
            refresh_token_ttl_secs: env::var("SENTIN8_AUTH_REFRESH_TOKEN_TTL")
                .unwrap_or("2592000".into())
                .parse()
                .unwrap_or(2592000),
            sentin8_stat_property_id: env::var("SENTIN8_AUTH_STAT_PROPERTY_ID")
                .ok()
                .and_then(|s| uuid::Uuid::parse_str(&s).ok())
                .unwrap_or_else(|| {
                    // Default platform auth property (seeded by the auth init SQL).
                    // This is a fixed UUID derived deterministically from the service slug.
                    uuid::Uuid::parse_str("a0000000-0000-0000-0000-000000000001").unwrap()
                }),
            sentin8_stat_url: env::var("SENTIN8_STAT_URL")
                .unwrap_or_else(|_| cfg.sentin8_stat_url()),
            sentin8_bus_url: env::var("SENTIN8_BUS_URL").unwrap_or_else(|_| cfg.sentin8_bus_url()),
            stream_family: env::var("SENTIN8_AUTH_STREAM_FAMILY").unwrap_or_else(|_| "auth".into()),
        }
    }

    /// Build a config suitable for integration tests.
    /// Handle for testing.
    pub fn for_testing() -> Self {
        let database_url = env::var("SENTIN8_AUTH_DB_DSN")
            .or_else(|_| env::var("DATABASE_URL"))
            .unwrap_or_else(|_| sentin8::config::Sentin8Config::default_database_url().to_string());
        Self {
            port: 0,
            issuer: "https://auth.test.local.sentin8.dev".to_string(),
            jwks_url: "https://auth.test.local.sentin8.dev/.well-known/jwks.json".to_string(),
            database_url,
            // override → else the plane-derived URL.
            valkey_url: env::var("SENTIN8_AUTH_VALKEY_URL")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(sentin8::config::service_valkey_url),
            sentin8_domain: "test.local.sentin8.dev".to_string(),
            session_ttl_secs: 3600,
            access_token_ttl_secs: 900,
            m2m_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 2592000,
            sentin8_stat_property_id: uuid::Uuid::parse_str("a0000000-0000-0000-0000-000000000001")
                .unwrap(),
            sentin8_stat_url: "https://stat.test.local.sentin8.dev".into(),
            sentin8_bus_url: "https://bus.test.local.sentin8.dev".into(),
            stream_family: "auth".into(),
        }
    }
}
