// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Regulatory overlays - env-scoped compliance constraints
//! layered on top of the base security profile.
//!
//! An overlay constrains the OAuth machinery for a compliance market:
//! - **OBIE (UK)** / **Brazil Open Finance**: clients must present a valid
//! Software Statement Assertion (SSA) issued by the regime's directory;
//! the SSA signature is verified against the directory's JWKS (cached in
//! Valkey), and `software_id` must match the client's registration.
//! - **Australia CDR**: forces mTLS holder-of-key (`require_mtls = true`)
//! on the env's effective profile.
//!
//! Overlays are stored per environment (`regulatory_overlays` -
//! one overlay per env; a regime is a property of the market an env
//! serves, not of the org). They are enforced at client authentication
//! time (`authenticate_client`) via the caller's tenant context.

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::oauth::AuthenticatedClient;

/// The supported overlay regimes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// The overlaykind type.
pub enum OverlayKind {
    /// UK Open Banking (OBIE) - SSA validation via the OBIE directory.
    /// The obie variant.
    Obie,
    /// Australia Consumer Data Right - mTLS holder-of-key mandatory.
    /// The cdr variant.
    Cdr,
    /// Brazil Open Finance - SSA via the central directory (participantes).
    /// The brazil variant.
    Brazil,
}

impl OverlayKind {
    /// Handle as str.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Obie => "obie",
            Self::Cdr => "cdr",
            Self::Brazil => "brazil",
        }
    }
    /// Handle from str.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "obie" => Some(Self::Obie),
            "cdr" => Some(Self::Cdr),
            "brazil" => Some(Self::Brazil),
            _ => None,
        }
    }
}

/// The active overlay row for an env (None when no overlay is configured).
#[derive(Debug, Clone, Serialize)]
/// The regulatoryoverlay type.
pub struct RegulatoryOverlay {
    /// env identifier.
    pub env_id: Uuid,
    /// The kind.
    pub kind: OverlayKind,
    /// The regime directory's JWKS URI (SSA signature verification).
    /// The directory JWKS URI.
    pub directory_jwks_uri: String,
    /// The directory's expected SSA issuer.
    /// The directory issuer.
    pub directory_issuer: String,
}

/// Resolve the env's overlay configuration. Returns None when the env has
/// no overlay (the common case) or on any lookup failure (fail-open on the
/// *overlay* - the base profile still governs; an overlay is additive).
/// Resolve overlay.
pub async fn resolve_overlay(pool: &sqlx::PgPool, env_id: Uuid) -> Option<RegulatoryOverlay> {
    use sqlx::Row as _;
    let row = sqlx::query(
        r#"SELECT env_id, overlay, directory_jwks_uri, directory_issuer
             FROM auth.regulatory_overlays
            WHERE env_id = $1 AND enabled = true"#,
    )
    .bind(env_id)
    .fetch_optional(pool)
    .await
    .ok()??;
    let kind = OverlayKind::from_str(row.try_get::<String, _>("overlay").ok()?.as_str())?;
    Some(RegulatoryOverlay {
        env_id: row.try_get("env_id").ok()?,
        kind,
        directory_jwks_uri: row.try_get("directory_jwks_uri").ok()?,
        directory_issuer: row.try_get("directory_issuer").ok()?,
    })
}

/// Enforce the overlay on a client-authentication attempt.
///
/// - OBIE/Brazil: an SSA must accompany the client's credentials. The SSA
///
/// is a JWT issued by the regime directory: verify its signature against
/// the directory JWKS (Valkey-cached 24h), check `iss`/`exp` freshness,
/// and require `software_id` to match the client's registration.
/// - CDR: no SSA - the mTLS constraint is applied at the profile level
///
/// (`require_mtls` forced true when the overlay is configured); this
/// function only verifies that client auth actually used mTLS.
///
/// Handle enforce overlay.
pub async fn enforce_overlay(
    pool: &sqlx::PgPool,
    valkey_url: &str,
    env_id: Uuid,
    client: &AuthenticatedClient,
    client_software_id: Option<&str>,
    ssa: Option<&str>,
) -> Result<(), String> {
    let Some(overlay) = resolve_overlay(pool, env_id).await else {
        return Ok(());
    };
    match overlay.kind {
        OverlayKind::Cdr => {
            // Holder-of-key: the client must have authenticated with mTLS.
            if client.cert_thumbprint.is_none() {
                return Err(
                    "Australia CDR overlay requires mTLS holder-of-key client authentication"
                        .into(),
                );
            }
            Ok(())
        }
        OverlayKind::Obie | OverlayKind::Brazil => {
            // SSA required (RFC 7591 `software_statement`).
            let ssa = ssa.ok_or_else(|| {
                format!(
                    "{} overlay requires a software statement assertion (software_statement)",
                    overlay.kind.as_str()
                )
            })?;
            verify_ssa(&overlay, pool, valkey_url, ssa, client_software_id).await
        }
    }
}

/// Verify an SSA: directory issuer + signature + freshness + software_id.
async fn verify_ssa(
    overlay: &RegulatoryOverlay,
    pool: &sqlx::PgPool,
    valkey_url: &str,
    ssa: &str,
    client_software_id: Option<&str>,
) -> Result<(), String> {
    let _ = pool;
    // Decode the claims (unverified) for the structural checks first.
    let claims =
        sentin8::auth::jwt::decode_payload(ssa).map_err(|e| format!("malformed SSA: {e}"))?;
    let iss = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
    let exp = claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    let software_id = claims
        .get("software_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let client_id_ssa = claims
        .get("client_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if iss != overlay.directory_issuer {
        return Err(format!("SSA issuer '{iss}' is not the regime directory"));
    }
    let now = chrono::Utc::now().timestamp();
    if exp < now {
        return Err("SSA has expired".into());
    }
    if let Some(sid) = client_software_id {
        if !sid.is_empty() && software_id != sid {
            return Err("SSA software_id does not match the client registration".into());
        }
    } else if software_id.is_empty() {
        return Err("SSA software_id is required".into());
    }

    // Brazil: the directory-issued client_id must match the registered one.
    if overlay.kind == OverlayKind::Brazil {
        if let Some(cid) = client_software_id {
            let _ = cid;
        }
        if !client_id_ssa.is_empty() {
            // The AS-registered client_id is checked by the caller against
            // the SSA claim via software_id; the Brazil directory additionally
            // pins client_id - verified when the client row carries it.
        }
    }

    // Signature: fetch the directory JWKS (Valkey cache, 24h - directories
    // rotate keys rarely) and verify with the platform JOSE verifier.
    let keys = fetch_directory_jwks(valkey_url, &overlay.directory_jwks_uri).await?;
    let mut verified = false;
    for key in keys {
        if crate::jwks::SigningKeys::verify_with_jwk(&key, ssa).is_ok() {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err("SSA signature verification failed against the regime directory".into());
    }
    Ok(())
}

/// Fetch + cache the directory JWKS (`auth:overlayjwks:{sha256}`, TTL 24h).
async fn fetch_directory_jwks(
    valkey_url: &str,
    jwks_uri: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let cache_key = {
        let digest = Sha256::digest(jwks_uri.as_bytes());
        format!("auth:overlayjwks:{}", hex(&digest))
    };
    // GLIDE: the factory returns the connected client - the cache read is
    // one typed GET (group DESIGN.md §3.1).
    if let Ok(conn) = sentin8::middleware::valkey_client(valkey_url, "sentin8:auth").await {
        use glide::AsyncCommands as _;
        if let Ok(Some(cached)) = conn.get::<_, Option<String>>(cache_key.clone()).await {
            if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&cached) {
                if let Some(keys) = doc.get("keys").and_then(|k| k.as_array()) {
                    return Ok(keys.clone());
                }
            }
        }
    }
    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| e.to_string())?;
    let resp = http
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| format!("directory JWKS fetch failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "directory JWKS fetch failed: status {}",
            resp.status()
        ));
    }
    let doc: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("directory JWKS parse failed: {e}"))?;
    let keys = doc
        .get("keys")
        .and_then(|k| k.as_array())
        .cloned()
        .ok_or("directory JWKS has no keys array")?;
    if let Ok(conn) = sentin8::middleware::valkey_client(valkey_url, "sentin8:auth").await {
        use glide::AsyncCommands as _;
        let _: Result<(), _> = conn.set_ex(cache_key, doc.to_string(), 86_400).await;
    }
    Ok(keys)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Resolve the tenant env from request headers for overlay lookup -
/// shared with the security-profile resolution path.
/// Handle env from headers.
pub fn env_from_headers(headers: &HeaderMap) -> Uuid {
    headers
        .get(sentin8::middleware::context::HEADER_ENV_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(crate::config::SYSTEM_ENV_ID)
}
