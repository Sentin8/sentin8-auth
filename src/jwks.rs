// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! JWKS endpoint - dual-algorithm JWT signing (ML-DSA-65 + RS256), multi-key
//! verification sets, ES256 verification, and AES-256-GCM at-rest encryption
//! of private key material (SEC- / SEC-).
//!
//! Auth loads signing keys from the database at startup (or generates and
//! persists new ones on first run) based on `SENTIN8_TLS_PQ_MODE`:
//!
//! | Mode | Signing algorithm | JWKS `alg` | Use case |
//! |-------------|-------------------|------------|-----------------------------|
//! | `exclusive` | ML-DSA-65 | `MLDSA65` | Default - post-quantum |
//! | `hybrid` | ML-DSA-65 | `MLDSA65` | PQ-preferred |
//! | `classical` | RS256 (RSA-2048) | `RS256` | Emergency rollback |
//!
//! JWT signing for ML-DSA-65 is done manually (the `jsonwebtoken` crate does
//! not support ML-DSA). RS256 signing uses `jsonwebtoken` as before.
//!
//! Verification (SEC-) accepts **ML-DSA-65, RS256, and ES256**
//! regardless of mode, resolved by `kid` across **all persisted keys** -
//! tokens issued before a rotation or mode switch remain valid until they
//! expire, and the JWKS publishes every persisted key (rotation overlap).
//!
//! Private key material is stored encrypted with AES-256-GCM (envelope
//! prefix `v2:`) using the master key from `SENTIN8_AUTH_MASTER_KEY`.

use base64::Engine;
use ml_dsa::{Generate, Keypair, Signer, Verifier};
use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

use crate::jwt::AuthClaims;

/// JWKS rotation staleness gate (SDD §2.5): the internal timer rotates the
/// signing key when the newest one is older than this. The hourly tick
/// bounds the drift from the gate to at most one tick.
const ROTATION_STALENESS: chrono::Duration = chrono::Duration::days(30);
/// Timer tick - hourly; cheap staleness check, bounded drift.
const ROTATION_TICK: std::time::Duration = std::time::Duration::from_secs(3600);

/// Spawn the internal JWKS rotation timer (SDD §2.5, root-service rule):
/// auth links no scheduler client and makes no cross-service calls. Each
/// tick reads the newest key's creation time; when it passes the 30-day
/// staleness gate, the key rotates via [`SigningKeys::rotate`]
/// (insert-overlap - previous keys stay published). A failed check or
/// rotation logs and retries on the next tick (never fatal - serving
/// continues on the existing keys).
pub fn spawn_rotation_timer(pool: sqlx::PgPool) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(ROTATION_TICK).await;
            if let Err(e) = rotation_tick(&pool).await {
                tracing::warn!(error = %e, "jwks rotation check failed - retrying next tick");
            }
        }
    });
}

/// One staleness check + conditional rotation.
async fn rotation_tick(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    let newest: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar(r#"SELECT MAX(created_at) FROM auth.signing_keys"#)
            .fetch_optional(pool)
            .await?;
    let Some(newest) = newest else {
        return Ok(()); // no keys yet - boot seeds the first key
    };
    if chrono::Utc::now() - newest < ROTATION_STALENESS {
        return Ok(()); // newest key still fresh - nothing to do
    }
    let (key_id, alg) = SigningKeys::rotate(pool).await?;
    tracing::info!(
        key_id = %key_id,
        alg = %alg,
        "jwks rotation timer rotated signing key (staleness gate elapsed)"
    );
    Ok(())
}

/// Reads `SENTIN8_TLS_PQ_MODE` (default: `exclusive`).
fn pq_mode() -> String {
    std::env::var("SENTIN8_TLS_PQ_MODE").unwrap_or_else(|_| "exclusive".to_string())
}

/// Whether ML-DSA-65 is the active signing algorithm.
fn is_pq_mode() -> bool {
    pq_mode() != "classical"
}

/// The algorithm name to advertise in JWT headers and OIDC discovery.
/// Handle active signing alg.
pub fn active_signing_alg() -> &'static str {
    if is_pq_mode() {
        "MLDSA65"
    } else {
        "RS256"
    }
}

/// Load the AES-256-GCM master key for at-rest key encryption.
///
/// Returns `None` when `SENTIN8_AUTH_MASTER_KEY` is unset - callers decide
/// fail-closed behavior (integration-test mode falls back to a deterministic
/// dev key with a loud warning).
/// Handle master key.
pub fn master_key() -> Option<sentin8::crypto::MasterKey> {
    sentin8::crypto::MasterKey::from_base64(
        &std::env::var("SENTIN8_AUTH_MASTER_KEY").unwrap_or_default(),
    )
    .ok()
    .flatten()
}

/// Whether the process runs with a deliberately insecure dev/test key.
fn dev_master_key_enabled() -> bool {
    std::env::var("SENTIN8_AUTH_DEV_INSECURE_KEY").is_ok()
}

/// The master key to use, or a deterministic dev key in test mode.
///
/// Fail-closed rule (design ): without `SENTIN8_AUTH_MASTER_KEY` the
/// service refuses to persist or read real key material - unless
/// `SENTIN8_AUTH_DEV_INSECURE_KEY` is set (CI/integration tests only).
fn require_master_key() -> Result<sentin8::crypto::MasterKey, String> {
    if let Some(k) = master_key() {
        return Ok(k);
    }
    if dev_master_key_enabled() {
        tracing::warn!(
            "SENTIN8_AUTH_MASTER_KEY is not set - using a DETERMINISTIC DEV KEY. \
             Never run production this way (set SENTIN8_AUTH_DEV_INSECURE_KEY only in tests)."
        );
        return Ok(sentin8::crypto::derive_key(
            b"sentin8-auth-dev-insecure-key",
        ));
    }
    Err(
        "SENTIN8_AUTH_MASTER_KEY is not set (base64, 32 bytes) - refusing to \
         handle signing key material. Generate one with: openssl rand -base64 32"
            .to_string(),
    )
}

/// One persisted signing key (any algorithm), used for verification.
#[derive(Clone)]
pub(crate) struct StoredKey {
    key_id: String,
    alg: String,
    /// ML-DSA-65 signing key (when alg = MLDSA65).
    ml_dsa_key: Option<ml_dsa::SigningKey<ml_dsa::MlDsa65>>,
    ml_dsa_pk_b64: Option<String>,
    /// RSA encoding key (when alg = RS256).
    rsa_encoding_key: Option<jsonwebtoken::EncodingKey>,
    rsa_n_b64: Option<String>,
    rsa_e_b64: Option<String>,
    /// PKCS#8 PEM (base64) captured at generation time for RS256 persistence.
    rsa_pem_b64: Option<String>,
}

impl StoredKey {
    /// The key id (public read for the rotate endpoint response).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The signing algorithm (public read for the rotate endpoint response).
    pub fn alg(&self) -> &str {
        &self.alg
    }

    fn to_jwk(&self) -> Jwk {
        if self.alg == "MLDSA65" {
            Jwk {
                kty: "MLWE".into(),
                kid: self.key_id.clone(),
                use_field: "sig".into(),
                alg: "MLDSA65".into(),
                x: self.ml_dsa_pk_b64.clone(),
                n: None,
                e: None,
                crv: None,
            }
        } else {
            Jwk {
                kty: "RSA".into(),
                kid: self.key_id.clone(),
                use_field: "sig".into(),
                alg: "RS256".into(),
                x: None,
                n: self.rsa_n_b64.clone(),
                e: self.rsa_e_b64.clone(),
                crv: None,
            }
        }
    }

    /// Can this key sign new tokens (has private material)?
    fn can_sign(&self) -> bool {
        self.ml_dsa_key.is_some() || self.rsa_encoding_key.is_some()
    }
}

/// Multi-key signing set - the active signing key plus all persisted keys
/// for verification and JWKS publication (SEC- rotation overlap).
///
/// Keys are persisted in `sentin8_auth_signing_keys` (encrypted with
/// AES-256-GCM) so they survive auth restarts - existing JWTs remain valid
/// because the same `key_id` and private key are reused. See
/// `load_or_generate`.
#[derive(Clone)]
/// The signingkeys type.
pub struct SigningKeys {
    /// The key used to sign new tokens.
    active: StoredKey,
    /// Every persisted key (including `active`) for verification + JWKS.
    all: Vec<StoredKey>,
}

impl SigningKeys {
    /// Generate a fresh in-memory key set for the active algorithm.
    ///
    /// Used by integration tests (no database persistence, no at-rest
    /// encryption) - production loads via [`SigningKeys::load_or_generate`].
    /// Generate for testing.
    pub fn generate_for_testing() -> anyhow::Result<Self> {
        let alg = if is_pq_mode() { "MLDSA65" } else { "RS256" };
        let active = Self::generate(alg)?;
        Ok(Self {
            all: vec![active.clone()],
            active,
        })
    }

    /// Generate a new signing key for the given algorithm.
    fn generate(alg: &str) -> anyhow::Result<StoredKey> {
        let key_id = Uuid::new_v4().to_string();

        if alg == "MLDSA65" {
            // PQ mode - generate ML-DSA-65 keypair.
            let signing_key = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::generate();
            let verifying_key = signing_key.verifying_key();
            let pk_bytes = verifying_key.encode();
            let pk_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk_bytes);
            Ok(StoredKey {
                key_id,
                alg: "MLDSA65".into(),
                ml_dsa_key: Some(signing_key),
                ml_dsa_pk_b64: Some(pk_b64),
                rsa_encoding_key: None,
                rsa_n_b64: None,
                rsa_e_b64: None,
                rsa_pem_b64: None,
            })
        } else {
            // Classical mode - generate RSA-2048 keypair.
            use rsa::pkcs8::EncodePrivateKey;
            use rsa::traits::PublicKeyParts;
            let mut rng = rand::thread_rng();
            let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048)?;
            let n = priv_key.n().to_bytes_be();
            let e = priv_key.e().to_bytes_be();
            let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&n);
            let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&e);
            let pem = priv_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?;
            let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_str().as_bytes())?;
            let pem_b64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pem.as_str().as_bytes());
            Ok(StoredKey {
                key_id,
                alg: "RS256".into(),
                ml_dsa_key: None,
                ml_dsa_pk_b64: None,
                rsa_encoding_key: Some(encoding_key),
                rsa_n_b64: Some(n_b64),
                rsa_e_b64: Some(e_b64),
                rsa_pem_b64: Some(pem_b64),
            })
        }
    }

    /// Load signing keys from the database, or generate and persist new ones.
    ///
    /// Loads **all** persisted keys (both algorithms) for verification; the
    /// newest row for the active algorithm is used for signing. This ensures
    /// keys survive auth restarts AND that tokens issued before a rotation
    /// or mode switch remain verifiable (SEC-).
    ///
    /// DBX: `signing_keys` is a platform-global table (no env_id); its RLS
    /// policies admit only the SYSTEM-env context - set it on the same
    /// connection before every statement (the pool is the auth service role,
    /// NOBYPASSRLS; without the context RLS fails closed).
    /// Load or generate.
    pub async fn load_or_generate(pool: &sqlx::PgPool) -> anyhow::Result<Self> {
        let active_alg = if is_pq_mode() { "MLDSA65" } else { "RS256" };
        // DBX: signing_keys' RLS policies admit only the SYSTEM-env context.
        // The context is TRANSACTION-LOCAL (`set_config(..., true)`), so the
        // load and any generate+persist run inside ONE explicit transaction
        // on a single connection ( rule 2) -
        // in autocommit mode the context would evaporate between statements
        // and the INSERT would fail closed under the service role.
        let mut tx = pool
            .begin()
            .await
            .map_err(|e| anyhow::anyhow!("begin transaction for signing keys: {e}"))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(sentin8::config::SYSTEM_ENV_ID)
            .execute(&mut *tx)
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, "auth: failed to set SYSTEM tenant context for signing-key load")
            });
        let rows = sqlx::query(
            r#"SELECT key_id, alg, priv_key, pub_key_b64, rsa_n_b64, rsa_e_b64
               FROM signing_keys
               ORDER BY created_at ASC"#,
        )
        .fetch_all(&mut *tx)
        .await?;

        let mk = require_master_key().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut all: Vec<StoredKey> = Vec::new();

        for row in rows {
            let key_id: String = row.try_get("key_id")?;
            let alg: String = row.try_get("alg")?;
            let stored: String = row.try_get("priv_key")?;

            // Decrypt the private key. The `priv_key` column stores the
            // `sentin8-crypto` envelope as standard-base64:
            // base64(`"v2:" || nonce || ciphertext+tag`). A wrong or missing
            // master key, or a non-envelope value, is a hard error - auth
            // cannot operate without its signing-key material.
            use base64::Engine as _;
            let priv_bytes: Vec<u8> = sentin8::crypto::open_str(&mk, &stored).map_err(|e| {
                anyhow::anyhow!(
                    "signing key {key_id} decryption failed - wrong or rotated \
                         SENTIN8_AUTH_MASTER_KEY: {e}"
                )
            })?;

            let key = if alg == "MLDSA65" {
                use pkcs8::DecodePrivateKey;
                let signing_key =
                    ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_pkcs8_der(&priv_bytes)
                        .map_err(|e| anyhow::anyhow!("decode ML-DSA private key {key_id}: {e}"))?;
                let pub_key_b64: Option<String> = row.try_get("pub_key_b64").ok();
                let pk_b64 = pub_key_b64.unwrap_or_else(|| {
                    let pk_bytes = signing_key.verifying_key().encode();
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk_bytes)
                });
                StoredKey {
                    key_id,
                    alg: "MLDSA65".into(),
                    ml_dsa_key: Some(signing_key),
                    ml_dsa_pk_b64: Some(pk_b64),
                    rsa_encoding_key: None,
                    rsa_n_b64: None,
                    rsa_e_b64: None,
                    rsa_pem_b64: None,
                }
            } else {
                // RS256 rows store the PKCS#8 PEM (sealed with the envelope).
                let pem_str = String::from_utf8(priv_bytes)
                    .map_err(|e| anyhow::anyhow!("RSA PEM not UTF-8 for {key_id}: {e}"))?;
                let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(pem_str.as_bytes())
                    .map_err(|e| anyhow::anyhow!("build RSA encoding key {key_id}: {e}"))?;
                let rsa_n_b64: Option<String> = row.try_get("rsa_n_b64").ok();
                let rsa_e_b64: Option<String> = row.try_get("rsa_e_b64").ok();
                StoredKey {
                    key_id,
                    alg: "RS256".into(),
                    ml_dsa_key: None,
                    ml_dsa_pk_b64: None,
                    rsa_encoding_key: Some(encoding_key),
                    rsa_n_b64,
                    rsa_e_b64,
                    rsa_pem_b64: None,
                }
            };
            all.push(key);
        }

        // Pick the active signing key: newest row for the active algorithm.
        let active = match all
            .iter()
            .rev()
            .find(|k| k.alg == active_alg && k.can_sign())
        {
            Some(k) => k.clone(),
            None => {
                // No persisted key for the active algorithm - generate + persist.
                let key = Self::generate(active_alg)?;
                Self::persist_one(&mut tx, &mk, &key).await?;
                tracing::info!(key_id = %key.key_id, alg = %key.alg, "generated and persisted new signing key");
                key
            }
        };

        // Commit the transaction (persisted key rows + the load snapshot).
        tx.commit()
            .await
            .map_err(|e| anyhow::anyhow!("commit signing-key transaction: {e}"))?;

        if all.is_empty() {
            all.push(active.clone());
        }

        Ok(Self { active, all })
    }

    /// Rotate: generate + persist a new key for the active algorithm.
    ///
    /// The JWKS reader serves every persisted key, so tokens signed by the
    /// previous key remain verifiable for their remaining lifetime
    /// (insert-overlap rotation - auth DESIGN §3.13). Runs generate +
    /// persist inside ONE transaction that carries the SYSTEM-env context
    /// (signing_keys RLS admits only the system env; the context is
    /// transaction-local).
    pub async fn rotate(pool: &sqlx::PgPool) -> anyhow::Result<(String, String)> {
        let active_alg = active_signing_alg();
        let mut tx = pool
            .begin()
            .await
            .map_err(|e| anyhow::anyhow!("begin transaction for key rotation: {e}"))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(sentin8::config::SYSTEM_ENV_ID)
            .execute(&mut *tx)
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, "auth: failed to set SYSTEM tenant context for key rotation")
            });
        let mk = require_master_key().map_err(|e| anyhow::anyhow!("{e}"))?;
        let key = Self::generate(active_alg)?;
        let key_id = key.key_id().to_string();
        let alg = key.alg().to_string();
        Self::persist_one(&mut tx, &mk, &key).await?;
        tx.commit()
            .await
            .map_err(|e| anyhow::anyhow!("commit key rotation transaction: {e}"))?;
        tracing::info!(key_id = %key_id, alg = %alg, "rotated signing key (new key active for signing; previous keys stay published for overlap)");
        Ok((key_id, alg))
    }

    /// Persist one signing key (encrypted at rest).
    ///
    /// DBX: signing_keys' RLS admits only the SYSTEM-env context; the caller
    /// (load_or_generate, rotation) runs this inside the SAME transaction the
    /// context was set in - transaction-local GUCs do not survive statement
    /// boundaries in autocommit mode ( rule 2).
    async fn persist_one(
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        mk: &sentin8::crypto::MasterKey,
        key: &StoredKey,
    ) -> anyhow::Result<()> {
        let (priv_sealed, pub_b64, rsa_n_b64, rsa_e_b64) = if let Some(sk) = &key.ml_dsa_key {
            use pkcs8::EncodePrivateKey;
            let der = sk
                .to_pkcs8_der()
                .map_err(|e| anyhow::anyhow!("encode ML-DSA private key: {e}"))?;
            let sealed = sentin8::crypto::seal(mk, der.as_bytes())
                .map_err(|e| anyhow::anyhow!("encrypt ML-DSA private key: {e}"))?;
            (sealed, key.ml_dsa_pk_b64.clone(), None, None)
        } else if let Some(pem_b64) = &key.rsa_pem_b64 {
            let pem_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(pem_b64)
                .map_err(|e| anyhow::anyhow!("decode RS256 PEM for persistence: {e}"))?;
            let sealed = sentin8::crypto::seal(mk, &pem_bytes)
                .map_err(|e| anyhow::anyhow!("encrypt RS256 private key: {e}"))?;
            (sealed, None, key.rsa_n_b64.clone(), key.rsa_e_b64.clone())
        } else {
            anyhow::bail!("no signing key material available to persist");
        };

        sqlx::query(
            r#"INSERT INTO signing_keys (key_id, alg, priv_key, pub_key_b64, rsa_n_b64, rsa_e_b64)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(&key.key_id)
        .bind(&key.alg)
        .bind(&priv_sealed)
        .bind(&pub_b64)
        .bind(&rsa_n_b64)
        .bind(&rsa_e_b64)
        .execute(&mut **tx)
        .await
        .map_err(|e| anyhow::anyhow!("persist signing key: {e}"))?;
        Ok(())
    }

    /// The active signing key id.
    /// Handle key id.
    pub fn key_id(&self) -> &str {
        &self.active.key_id
    }

    /// The active signing algorithm.
    /// Handle alg.
    pub fn alg(&self) -> &str {
        &self.active.alg
    }

    /// Sign a JWT with the given claims.
    /// Sign it.
    pub fn sign(&self, claims: &AuthClaims) -> Result<String, String> {
        self.sign_value(
            &serde_json::to_value(claims).map_err(|e| format!("serialize claims: {e}"))?,
        )
    }

    /// Sign a JWT from an arbitrary `serde_json::Value` claims payload.
    /// Sign value.
    pub fn sign_value(&self, claims: &serde_json::Value) -> Result<String, String> {
        if let Some(sk) = &self.active.ml_dsa_key {
            // ML-DSA-65 signing (manual JWT construction).
            let header = serde_json::json!({
                "alg": "MLDSA65",
                "typ": "JWT",
                "kid": self.active.key_id,
            });
            let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&header).map_err(|e| format!("serialize header: {e}"))?);
            let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(claims).map_err(|e| format!("serialize claims: {e}"))?);
            let signing_input = format!("{header_b64}.{payload_b64}");
            let signature = sk.sign(signing_input.as_bytes());
            let sig_b64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.encode());
            Ok(format!("{signing_input}.{sig_b64}"))
        } else if let Some(ek) = &self.active.rsa_encoding_key {
            // RS256 signing (jsonwebtoken crate).
            let header = jsonwebtoken::Header {
                alg: jsonwebtoken::Algorithm::RS256,
                typ: Some("JWT".to_string()),
                kid: Some(self.active.key_id.clone()),
                ..Default::default()
            };
            jsonwebtoken::encode(&header, claims, ek).map_err(|e| format!("RS256 sign error: {e}"))
        } else {
            Err("no signing key available".to_string())
        }
    }

    /// Verify a JWT signature and decode the claims.
    ///
    /// Accepts ML-DSA-65, RS256, and ES256 tokens, resolved by `kid` across
    /// all persisted keys (SEC-). The algorithm allow-list is
    /// explicit - `"none"`, HS256, and algorithm-confusion variants are
    /// rejected.
    /// Verify it.
    pub fn verify(&self, token: &str) -> Result<AuthClaims, String> {
        let claims = self.verify_raw(token)?;
        serde_json::from_value(claims).map_err(|e| format!("deserialize claims: {e}"))
    }

    /// Verify a JWT signature and return raw JSON claims.
    /// Verify raw.
    pub fn verify_raw(&self, token: &str) -> Result<serde_json::Value, String> {
        // Decode header to detect algorithm + kid.
        let header = sentin8::auth::jwt::decode_header(token)?;
        let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        let kid = header.get("kid").and_then(|v| v.as_str());
        let signing_input = sentin8::auth::jwt::signing_input(token)?;
        let sig_bytes = sentin8::auth::jwt::decode_signature(token)?;

        match alg {
            "MLDSA65" => {
                let key = self
                    .find_key("MLDSA65", kid)
                    .ok_or_else(|| "no ML-DSA key available for this token".to_string())?;
                let sk = key.ml_dsa_key.as_ref().ok_or("key is not an ML-DSA key")?;
                let signature = <ml_dsa::Signature<ml_dsa::MlDsa65> as std::convert::TryFrom<
                    &[u8],
                >>::try_from(&sig_bytes)
                .map_err(|e| format!("decode ML-DSA signature: {e}"))?;
                sk.verifying_key()
                    .verify(signing_input.as_bytes(), &signature)
                    .map_err(|e| format!("ML-DSA signature verification failed: {e}"))?;
                sentin8::auth::jwt::decode_payload(token)
            }
            "RS256" => {
                let key = self.find_key("RS256", kid).ok_or_else(|| {
                    "no RSA key available for this token (PQ mode without a persisted RSA key)"
                        .to_string()
                })?;
                let n_b64 = key.rsa_n_b64.as_ref().ok_or("RSA key missing modulus")?;
                let e_b64 = key.rsa_e_b64.as_ref().ok_or("RSA key missing exponent")?;
                let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(n_b64, e_b64)
                    .map_err(|e| format!("build RSA decoding key: {e}"))?;
                let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
                validation.validate_aud = false;
                validation.validate_exp = false; // callers check exp explicitly
                validation.required_spec_claims.clear();
                let data =
                    jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation)
                        .map_err(|e| format!("RS256 verification failed: {e}"))?;
                Ok(data.claims)
            }
            "ES256" => {
                // ES256 verify-only path (conformance-suite client keys sign
                // DPoP/private_key_jwt proofs with ES256). Auth does not issue
                // ES256 tokens itself; this branch verifies client-assertion
                // JWTs and DPoP proofs that carry an embedded JWK.
                use p256::ecdsa::signature::Verifier;
                use p256::ecdsa::{Signature, VerifyingKey};

                let x = header
                    .get("jwk")
                    .and_then(|j| j.get("x"))
                    .and_then(|v| v.as_str());
                let y = header
                    .get("jwk")
                    .and_then(|j| j.get("y"))
                    .and_then(|v| v.as_str());
                let (x, y) = match (x, y) {
                    (Some(x), Some(y)) => (x, y),
                    _ => return Err(
                        "ES256 verification requires an embedded jwk (Auth does not issue ES256 tokens)".to_string(),
                    ),
                };
                let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(x)
                    .map_err(|e| format!("decode ES256 x: {e}"))?;
                let y_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(y)
                    .map_err(|e| format!("decode ES256 y: {e}"))?;
                let mut sec_bytes = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
                sec_bytes.push(0x04);
                sec_bytes.extend_from_slice(&x_bytes);
                sec_bytes.extend_from_slice(&y_bytes);
                let vk = VerifyingKey::from_sec1_bytes(&sec_bytes)
                    .map_err(|e| format!("build ES256 verifying key: {e}"))?;
                let sig = Signature::from_slice(&sig_bytes)
                    .map_err(|e| format!("decode ES256 signature: {e}"))?;
                vk.verify(signing_input.as_bytes(), &sig)
                    .map_err(|e| format!("ES256 verification failed: {e}"))?;
                sentin8::auth::jwt::decode_payload(token)
            }
            _ => Err(format!("unsupported JWT algorithm: {alg}")),
        }
    }

    /// Find a verification key by algorithm (+ optional kid).
    fn find_key(&self, alg: &str, kid: Option<&str>) -> Option<&StoredKey> {
        match kid {
            Some(k) => self
                .all
                .iter()
                .find(|key| key.alg == alg && key.key_id == k),
            None => self.all.iter().rev().find(|key| key.alg == alg),
        }
    }

    /// Verify an arbitrary client-assertion/DPoP/JAR JWT against an **explicit
    /// JWK** (not our own keys). Supports ES256 and RS256 (SEC-/6).
    /// Verify a **raw** (non-JWS) payload + signature pair against a client
    /// JWK (. - RFC 9421 HTTP signatures). Unlike
    /// `verify_with_jwk`, the payload is the bare signature-base string,
    /// not a compact JWS - used by the http-signatures module where the
    /// signed artifact is the canonicalized header list, not a JWT.
    /// Verify raw with jwk.
    pub fn verify_raw_with_jwk(
        jwk: &serde_json::Value,
        payload: &[u8],
        sig: &[u8],
    ) -> Result<(), String> {
        let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
        let alg = jwk.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
        match (kty, alg) {
            ("EC", "ES256") => {
                use p256::ecdsa::signature::Verifier;
                use p256::ecdsa::{Signature, VerifyingKey};
                let x = jwk
                    .get("x")
                    .and_then(|v| v.as_str())
                    .ok_or("EC JWK missing x")?;
                let y = jwk
                    .get("y")
                    .and_then(|v| v.as_str())
                    .ok_or("EC JWK missing y")?;
                let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(x)
                    .map_err(|e| format!("decode x: {e}"))?;
                let y_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(y)
                    .map_err(|e| format!("decode y: {e}"))?;
                let mut sec = vec![0x04u8];
                sec.extend_from_slice(&x_bytes);
                sec.extend_from_slice(&y_bytes);
                let vk = VerifyingKey::from_sec1_bytes(&sec)
                    .map_err(|e| format!("build EC verifying key: {e}"))?;
                let sig = Signature::from_slice(sig)
                    .map_err(|e| format!("decode ES256 signature: {e}"))?;
                vk.verify(payload, &sig)
                    .map_err(|e| format!("ES256 verification failed: {e}"))?;
                Ok(())
            }
            ("EC", _) if crv == "P-256" => {
                // alg absent on the JWK - default ES256 for P-256 keys.
                let jwk = {
                    let mut m = jwk.clone();
                    if m.get("alg").is_none() {
                        m["alg"] = serde_json::json!("ES256");
                    }
                    m
                };
                Self::verify_raw_with_jwk(&jwk, payload, sig)
            }
            ("RSA", "RS256") => {
                use rsa::pkcs1v15::VerifyingKey;
                use rsa::signature::Verifier;
                let n = jwk
                    .get("n")
                    .and_then(|v| v.as_str())
                    .ok_or("RSA JWK missing n")?;
                let e = jwk
                    .get("e")
                    .and_then(|v| v.as_str())
                    .ok_or("RSA JWK missing e")?;
                let n_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(n)
                    .map_err(|e| format!("decode n: {e}"))?;
                let e_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(e)
                    .map_err(|e| format!("decode e: {e}"))?;
                let n = rsa::BigUint::from_bytes_be(&n_bytes);
                let e = rsa::BigUint::from_bytes_be(&e_bytes);
                let vk = VerifyingKey::<sha2::Sha256>::new(
                    rsa::RsaPublicKey::new(n, e).map_err(|e| format!("build RSA key: {e}"))?,
                );
                let sig = rsa::pkcs1v15::Signature::try_from(sig)
                    .map_err(|e| format!("decode RS256 signature: {e}"))?;
                vk.verify(payload, &sig)
                    .map_err(|e| format!("RS256 verification failed: {e}"))?;
                Ok(())
            }
            _ => Err(format!(
                "unsupported JWK type/alg for raw verification: {kty}/{alg}"
            )),
        }
    }

    /// Verify with jwk.
    pub fn verify_with_jwk(
        jwk: &serde_json::Value,
        token: &str,
    ) -> Result<serde_json::Value, String> {
        let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
        let header = sentin8::auth::jwt::decode_header(token)?;
        let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        let signing_input = sentin8::auth::jwt::signing_input(token)?;
        let sig_bytes = sentin8::auth::jwt::decode_signature(token)?;

        match (kty, alg) {
            ("EC", "ES256") => {
                use p256::ecdsa::signature::Verifier;
                use p256::ecdsa::{Signature, VerifyingKey};
                let x = jwk
                    .get("x")
                    .and_then(|v| v.as_str())
                    .ok_or("EC JWK missing x")?;
                let y = jwk
                    .get("y")
                    .and_then(|v| v.as_str())
                    .ok_or("EC JWK missing y")?;
                let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(x)
                    .map_err(|e| format!("decode x: {e}"))?;
                let y_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(y)
                    .map_err(|e| format!("decode y: {e}"))?;
                let mut sec = vec![0x04u8];
                sec.extend_from_slice(&x_bytes);
                sec.extend_from_slice(&y_bytes);
                let vk = VerifyingKey::from_sec1_bytes(&sec)
                    .map_err(|e| format!("build EC verifying key: {e}"))?;
                let sig = Signature::from_slice(&sig_bytes)
                    .map_err(|e| format!("decode ES256 signature: {e}"))?;
                vk.verify(signing_input.as_bytes(), &sig)
                    .map_err(|e| format!("ES256 verification failed: {e}"))?;
                sentin8::auth::jwt::decode_payload(token)
            }
            ("RSA", "RS256") => {
                let n = jwk
                    .get("n")
                    .and_then(|v| v.as_str())
                    .ok_or("RSA JWK missing n")?;
                let e = jwk
                    .get("e")
                    .and_then(|v| v.as_str())
                    .ok_or("RSA JWK missing e")?;
                let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| format!("build RSA decoding key: {e}"))?;
                let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
                validation.validate_aud = false;
                validation.validate_exp = false;
                validation.required_spec_claims.clear();
                let data =
                    jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation)
                        .map_err(|e| format!("RS256 verification failed: {e}"))?;
                Ok(data.claims)
            }
            _ => Err(format!(
                "unsupported JWK/alg combination: kty={kty} alg={alg}"
            )),
        }
    }
}

/// JWKS response document.
#[derive(Serialize, utoipa::ToSchema)]
/// Response payload for JWKS.
pub struct JwksResponse {
    /// The keys.
    pub keys: Vec<Jwk>,
}

/// A single JSON Web Key.
///
/// In PQ mode: `kty: "MLWE"`, `alg: "MLDSA65"`, `x` = base64url public key.
/// In classical mode: `kty: "RSA"`, `alg: "RS256"`, `n`/`e` = RSA components.
#[derive(Serialize, utoipa::ToSchema)]
/// The jwk type.
pub struct Jwk {
    /// The kty.
    pub kty: String,
    /// The kid.
    pub kid: String,
    #[serde(rename = "use")]
    /// The use field.
    pub use_field: String,
    /// The alg.
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The x.
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The n.
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The e.
    pub e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The crv.
    pub crv: Option<String>,
}

impl JwksResponse {
    /// Publish **all** persisted keys (kid-indexed) so clients can verify
    /// tokens across rotations and mode switches (SEC-).
    /// Handle from keys.
    pub fn from_keys(keys: &SigningKeys) -> Self {
        let mut jwks: Vec<Jwk> = keys.all.iter().map(|k| k.to_jwk()).collect();
        // Deduplicate by kid (the active key may appear twice in `all`).
        let mut seen = std::collections::HashSet::new();
        jwks.retain(|j| seen.insert(j.kid.clone()));
        Self { keys: jwks }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_claims() -> serde_json::Value {
        serde_json::json!({
            "sub": "user-123",
            "iss": "https://auth.test.sentin8.local",
            "jti": "jti-1",
            "iat": 1700000000i64,
            "exp": 4_102_444_800i64,
            "token_tp": "access",
            "scope": "openid",
            "env_id": "00000000-0000-0000-0000-000000000002",
        })
    }

    fn make_pq_keyset() -> SigningKeys {
        let active = SigningKeys::generate("MLDSA65").unwrap();
        SigningKeys {
            active: active.clone(),
            all: vec![active],
        }
    }

    fn make_rsa_keyset() -> SigningKeys {
        let active = SigningKeys::generate("RS256").unwrap();
        SigningKeys {
            active: active.clone(),
            all: vec![active],
        }
    }

    #[test]
    fn ml_dsa_sign_verify_round_trip() {
        let keys = make_pq_keyset();
        let token = keys.sign_value(&mk_claims()).unwrap();
        let claims = keys.verify_raw(&token).unwrap();
        assert_eq!(claims["sub"], "user-123");
    }

    #[test]
    fn rsa_sign_verify_round_trip() {
        let keys = make_rsa_keyset();
        let token = keys.sign_value(&mk_claims()).unwrap();
        let claims = keys.verify_raw(&token).unwrap();
        assert_eq!(claims["sub"], "user-123");
    }

    #[test]
    fn verify_rejects_alg_none() {
        use base64::Engine;
        let keys = make_pq_keyset();
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"sub":"attacker","exp":9999999999}"#);
        let forged = format!("{header}.{payload}.");
        assert!(keys.verify_raw(&forged).is_err());
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        use base64::Engine;
        let keys = make_pq_keyset();
        let token = keys.sign_value(&mk_claims()).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let evil =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"sub":"attacker"}"#);
        let forged = format!("{}.{}.", parts[0], evil);
        assert!(keys.verify_raw(&forged).is_err());
    }

    #[test]
    fn verify_rejects_cross_key() {
        // Sign with keyset A, verify with keyset B (different key) → fail.
        let a = make_pq_keyset();
        let b = make_pq_keyset();
        let token = a.sign_value(&mk_claims()).unwrap();
        assert!(b.verify_raw(&token).is_err());
    }

    #[test]
    fn multi_key_set_publishes_and_verifies_both() {
        // A keyset with an old PQ key + a new PQ key verifies both tokens.
        let old = SigningKeys::generate("MLDSA65").unwrap();
        let new = SigningKeys::generate("MLDSA65").unwrap();
        let keys = SigningKeys {
            active: new.clone(),
            all: vec![old.clone(), new.clone()],
        };

        let claims = mk_claims();
        let old_token = {
            let ks = SigningKeys {
                active: old.clone(),
                all: vec![old.clone()],
            };
            ks.sign_value(&claims).unwrap()
        };
        let new_token = keys.sign_value(&claims).unwrap();

        assert!(
            keys.verify_raw(&old_token).is_ok(),
            "old key must still verify"
        );
        assert!(keys.verify_raw(&new_token).is_ok());

        let doc = JwksResponse::from_keys(&keys);
        assert_eq!(
            doc.keys.len(),
            2,
            "JWKS publishes all keys for rotation overlap"
        );
    }

    #[test]
    fn jwks_publishes_active_key() {
        let keys = make_pq_keyset();
        let doc = JwksResponse::from_keys(&keys);
        assert_eq!(doc.keys.len(), 1);
        assert_eq!(doc.keys[0].alg, "MLDSA65");
        assert_eq!(doc.keys[0].kid, keys.key_id());
    }

    #[test]
    fn master_key_env_rules() {
        // Without env vars, master_key is None (fail-closed) -
        // require_master_key errors unless the dev flag is set. Both vars
        // are cleared first so an ambient dev flag (CI test runs) doesn't
        // skew the assertions.
        std::env::remove_var("SENTIN8_AUTH_MASTER_KEY");
        std::env::remove_var("SENTIN8_AUTH_DEV_INSECURE_KEY");
        assert!(master_key().is_none());
        assert!(require_master_key().is_err());

        std::env::set_var("SENTIN8_AUTH_DEV_INSECURE_KEY", "1");
        assert!(require_master_key().is_ok());
        std::env::remove_var("SENTIN8_AUTH_DEV_INSECURE_KEY");

        let b64 = base64::engine::general_purpose::STANDARD.encode([3u8; 32]);
        std::env::set_var("SENTIN8_AUTH_MASTER_KEY", &b64);
        assert!(master_key().is_some());
        std::env::remove_var("SENTIN8_AUTH_MASTER_KEY");
    }

    #[test]
    fn key_encryption_round_trip_via_crypto_crate() {
        use base64::Engine as _;
        let mk = sentin8::crypto::derive_key(b"test");
        let sealed = sentin8::crypto::seal(&mk, b"private-key-bytes").unwrap();
        // TEXT-column form: base64 of "v2:" || nonce || ct ("djI6..." prefix).
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&sealed)
            .unwrap();
        assert!(raw.starts_with(b"v2:"));
        assert_eq!(
            sentin8::crypto::open_str(&mk, &sealed).unwrap(),
            b"private-key-bytes"
        );
    }

    #[test]
    fn verify_with_jwk_es256_round_trip() {
        use base64::Engine;
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};

        let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let x_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap().as_slice());
        let y_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap().as_slice());
        let jwk = serde_json::json!({"kty":"EC","crv":"P-256","x":x_b64,"y":y_b64});

        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"ES256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"sub":"client","aud":"https://auth/token"}"#);
        let signing_input = format!("{header}.{payload}");
        let sig: Signature = sk.sign(signing_input.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let token = format!("{signing_input}.{sig_b64}");

        let claims = SigningKeys::verify_with_jwk(&jwk, &token).unwrap();
        assert_eq!(claims["sub"], "client");
    }
}
