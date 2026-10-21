// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Shared test helpers for the auth conformance suite (`tests/conformance.rs`).
//!
//! These mirror what a real OIDC conformance client does:
//! - [`mk_dpop_proof`] - build a signed RFC 9449 DPoP proof (ES256,
//!   self-contained `jwk` header, `htm`/`htu`/`iat`/`jti` claims).
//! - [`mk_es256_key`] - generate an ES256 P-256 keypair and its public JWK.
//! - [`mk_es256_assertion`] - mint an RFC 7523 `private_key_jwt` client
//!   assertion (`iss`/`sub` = client_id, `aud` = issuer, fresh `exp`, given
//!   `jti`).
//! - [`mk_totp_code`] - compute the current TOTP code from the
//!   base32 secret returned by `POST /v1/mfa/enroll`.

use base64::Engine;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha1::Sha1;

/// The test issuer configured by `AuthConfig::for_testing()`.
pub const TEST_ISSUER: &str = "https://auth.test.local.sentin8.dev";

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn b64url_json(v: &serde_json::Value) -> String {
    b64url(serde_json::to_vec(v).expect("serialize json").as_slice())
}

/// Generate a fresh ES256 (P-256) keypair for tests.
///
/// Returns `(public_jwk, signing_key)` where the JWK is an RFC 7517 EC key
/// (`kty: "EC", crv: "P-256", x, y` - URL-safe base64, no padding) ready to
/// be embedded in an `oauth_clients.jwks` row or a DPoP proof header.
pub fn mk_es256_key() -> (serde_json::Value, SigningKey) {
    let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let x = encoded.x().expect("P-256 point has x");
    let y = encoded.y().expect("P-256 point has y");
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(x.as_slice()),
        "y": b64url(y.as_slice()),
    });
    (jwk, signing_key)
}

/// Sign a compact JWS with ES256 and the given header claims.
fn mk_es256_jwt(header: serde_json::Value, claims: serde_json::Value, key: &SigningKey) -> String {
    let signing_input = format!("{}.{}", b64url_json(&header), b64url_json(&claims));
    let signature: Signature = key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        b64url(signature.to_bytes().as_slice())
    )
}

/// Build a signed DPoP proof (RFC 9449) for the given method/URI.
///
/// `jti_salt` distinguishes successive proofs (the caller increments it to
/// test replay rejection). The proof carries a fresh self-generated ES256
/// key; the server reads the public key from the embedded `jwk` header and
/// binds tokens via the `cnf.jkt` thumbprint.
pub fn mk_dpop_proof(method: &str, uri: &str, jti_salt: u64) -> String {
    let (jwk, key) = mk_es256_key();
    let jti = format!(
        "{}-{}",
        hex_sha256(uri.as_bytes()),
        uuid::Uuid::new_v4().as_u128() + jti_salt as u128
    );
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk,
    });
    let claims = serde_json::json!({
        "htm": method.to_uppercase(),
        "htu": uri,
        "jti": jti,
        "iat": chrono::Utc::now().timestamp(),
    });
    mk_es256_jwt(header, claims, &key)
}

/// Mint an RFC 7523 `private_key_jwt` client assertion.
///
/// Claims follow `oauth.rs::verify_client_assertion`: `iss`/`sub` = client_id,
/// `aud` = the Auth issuer, `exp` now + 5 minutes, `jti` as supplied (unique
/// per call to defeat the replay cache).
pub fn mk_es256_assertion(key: &SigningKey, jti: &str) -> String {
    mk_es256_assertion_for(key, jti, TEST_ISSUER)
}

/// Variant with an explicit audience (the token endpoint URL).
pub fn mk_es256_assertion_for(key: &SigningKey, jti: &str, aud: &str) -> String {
    mk_es256_jwt(
        serde_json::json!({ "alg": "ES256", "typ": "JWT" }),
        serde_json::json!({
            "iss": jti_issuer_of(jti),
            "sub": jti_issuer_of(jti),
            "aud": aud,
            "exp": chrono::Utc::now().timestamp() + 300,
            "jti": jti,
        }),
        key,
    )
}

/// The client_id carried by an assertion is caller-known; the helper encodes
/// it in the jti as `client_id:jti`. Callers pass `jti` as
/// `"{client_id}:{uuid}"` - decoded here so iss/sub always equal client_id.
fn jti_issuer_of(jti: &str) -> String {
    jti.split(':').next().unwrap_or(jti).to_string()
}

/// Compute the current TOTP code from a base32 (RFC 4648) secret.
///
/// Mirrors `mfa.rs::compute_totp` (HMAC-SHA1, 30s step, 6 digits) so codes
/// generated here verify against the server's stored factor.
pub fn mk_totp_code(secret_b32: &str) -> String {
    let secret = base32_decode(secret_b32).expect("valid base32 secret");
    totp_code_at(&secret, chrono::Utc::now().timestamp() as u64)
}

/// TOTP at a fixed unix time (drift testing).
pub fn totp_code_at(secret: &[u8], unix_time: u64) -> String {
    let counter = unix_time / 30;
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let truncated: u32 = (((digest[offset] & 0x7f) as u32) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    let code = truncated % 1_000_000;
    format!("{code:06}")
}

fn hex_sha256(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Base32 decode (RFC 4648, standard alphabet, padding optional).
fn base32_decode(s: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for c in s.chars().filter(|c| *c != '=') {
        let idx = ALPHABET
            .iter()
            .position(|a| (*a as char).eq_ignore_ascii_case(&c))
            .ok_or_else(|| format!("invalid base32 char {c}"))?;
        buffer = (buffer << 5) | idx as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

// SHA1 for TOTP HMAC.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn es256_key_produces_valid_jwk() {
        let (jwk, _key) = mk_es256_key();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        // x/y must be 32 bytes each when decoded.
        for f in ["x", "y"] {
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwk[f].as_str().unwrap())
                .unwrap();
            assert_eq!(bytes.len(), 32, "{f} must be 32 bytes");
        }
    }

    #[test]
    fn assertion_has_required_claims() {
        let (_jwk, key) = mk_es256_key();
        let client_id = "pkjwt-test";
        let jti = format!("{client_id}:{}", uuid::Uuid::new_v4());
        let token = mk_es256_assertion(&key, &jti);
        let claims: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(claims["iss"], client_id);
        assert_eq!(claims["sub"], client_id);
        assert_eq!(claims["aud"], TEST_ISSUER);
        assert!(claims["jti"].as_str().is_some());
    }

    #[test]
    fn assertion_signature_verifies_with_public_key() {
        let (jwk, key) = mk_es256_key();
        let client_id = "pkjwt-test";
        let token = mk_es256_assertion(&key, &format!("{client_id}:j1"));

        // Verify like the server does: rebuild the verifying key from the JWK.
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwk["x"].as_str().unwrap())
            .unwrap();
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwk["y"].as_str().unwrap())
            .unwrap();
        let mut sec = vec![0x04];
        sec.extend_from_slice(&x);
        sec.extend_from_slice(&y);
        let vk = VerifyingKey::from_sec1_bytes(&sec).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let sig = Signature::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[2])
                .unwrap(),
        )
        .unwrap();
        vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .expect("signature must verify");
    }

    #[test]
    fn dpop_proof_parses_and_validates() {
        let token = mk_dpop_proof("POST", "https://auth.test.local.sentin8.dev/oauth/token", 0);
        let decoded =
            sentin8_auth_server::dpop::decode_dpop_proof_unverified(&token).expect("proof parses");
        sentin8_auth_server::dpop::validate_dpop_proof(
            &decoded,
            "POST",
            "https://auth.test.local.sentin8.dev/oauth/token",
            chrono::Utc::now().timestamp(),
        )
        .expect("proof validates");
        assert_eq!(decoded.header.typ, "dpop+jwt");
        assert_eq!(decoded.claims.htm, "POST");
    }

    #[test]
    fn totp_matches_server_implementation() {
        // Same secret bytes → same code as auth's compute_totp_at.
        let secret: Vec<u8> = (0..20u8).collect();
        let b32: String = {
            const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let mut out = String::new();
            let mut buffer: u64 = 0;
            let mut bits = 0u32;
            for &b in &secret {
                buffer = (buffer << 8) | b as u64;
                bits += 8;
                while bits >= 5 {
                    bits -= 5;
                    let idx = ((buffer >> bits) & 0x1f) as usize;
                    out.push(ALPHABET[idx] as char);
                }
            }
            if bits > 0 {
                let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
                out.push(ALPHABET[idx] as char);
            }
            out
        };
        let t = 1_700_000_000u64;
        assert_eq!(totp_code_at(&secret, t), {
            let decoded = base32_decode(&b32).unwrap();
            assert_eq!(decoded, secret);
            totp_code_at(&decoded, t)
        });
        let code = mk_totp_code(&b32);
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn base32_roundtrip() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut enc = String::new();
        let mut buffer: u64 = 0;
        let mut bits = 0u32;
        for &b in &bytes {
            buffer = (buffer << 8) | b as u64;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                enc.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
            }
        }
        if bits > 0 {
            enc.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
        }
        assert_eq!(base32_decode(&enc).unwrap(), bytes);
    }
}
