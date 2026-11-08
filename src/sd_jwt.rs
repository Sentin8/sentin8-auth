// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! SD-JWT (Selective Disclosure JWT) verification.
//!
//! Format per SD-JWT (https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-14.html);
//! credential shape per SD-JWT VC (https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-05.html);
//! revocation per OAuth Status List (https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-14.html).
//! Basis for the OID4VP wallet sign-in flow (wallet.rs) and OID4VCI issuance (oid4vci.rs).
//!
//! ```text
//! <issuer-signed JWT>.<disclosure 0>~<disclosure 1>...~<optional KB-JWT>
//! ```
//!
//! The issuer-signed part is a standard compact JWS whose payload carries
//! `_sd` (sorted SHA-256 disclosure digests) and `cnf` (the wallet's key
//! binding). Each disclosure is `base64url([salt, claim_name, claim_value])`
//! and must hash (SHA-256 → base64url) to one of the `_sd` entries at its
//! position in the claim tree.
//!
//! This module verifies:
//! 1. **Issuer signature** - via a trusted-issuer JWKS (or the platform
//! JWKS when the credential is self-issued; production issuer keys come
//! from the EU trust list).
//! 2. **Disclosures** - every `_sd` digest resolves to a decoded
//! disclosure; hash mismatch → reject.
//! 3. **Key binding** - `cnf.jwk` in the issuer-signed part must equal the
//! wallet's presented key; the optional Key-Binding JWT (KB-JWT) is
//! signed with that key over `{aud, nonce, sd_hash}`.
//! 4. **Status** - Status List 2021 (`status.status_list.uri/index`):
//! compressed bitstring fetch + Valkey cache (5 min); bit set = revoked.
//!
//! Note: this module verifies the **flat top-level disclosure set** - the
//! common wallet shape (`_sd` at the root and inside simple subobjects).
//! Recursive array-element disclosures are deferred work
//! (tracked under the wallet roadmap).

use sha2::{Digest, Sha256};

/// A verified SD-JWT presentation: the issuer claims with all disclosed
/// values substituted, plus the wallet's key binding.
#[derive(Debug, Clone, serde::Serialize)]
/// The verifiedpresentation type.
pub struct VerifiedPresentation {
    /// Disclosed claims (merged over the non-selective claims).
    /// The claims.
    pub claims: serde_json::Value,
    /// The credential's issuer (`iss` claim).
    /// The issuer.
    pub issuer: String,
    /// The wallet key binding (`cnf` claim) - proven by the KB-JWT.
    /// The cnf.
    pub cnf: serde_json::Value,
}

/// Verification failure reason (safe to surface to callers).
#[derive(Debug, thiserror::Error)]
pub enum SdJwtError {
    /// The SD-JWT structure is malformed.
    #[error("malformed SD-JWT: {0}")]
    Malformed(String),
    /// Issuer signature verification failed.
    #[error("issuer signature verification failed")]
    Signature,
    /// A disclosure hash does not match the credential.
    #[error("disclosure {disclosure} hash mismatch")]
    HashMismatch {
        /// The index of the mismatching disclosure.
        disclosure: usize,
    },
    /// A duplicate disclosure was detected.
    #[error("duplicate disclosure detected")]
    DuplicateDisclosure,
    /// Wallet key binding is missing or mismatched.
    #[error("wallet key binding (cnf) missing or mismatched")]
    KeyBinding,
    /// The key-binding JWT is invalid.
    #[error("key binding JWT (KB-JWT) invalid: {0}")]
    KeyBindingJwt(String),
    /// The credential is revoked per its status list.
    #[error("credential is revoked (status list entry {entry})")]
    Revoked {
        /// The status-list entry proving revocation.
        entry: u32,
    },
    /// The status list could not be fetched.
    #[error("status list fetch failed: {0}")]
    StatusList(String),
}

/// The compact parts of an SD-JWT presentation.
struct Compact {
    issuer_jwt: String,
    disclosures: Vec<String>,
    kb_jwt: Option<String>,
}

fn b64_sha256(input: &str) -> String {
    use base64::Engine as _;
    let digest = Sha256::digest(input.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Decode one disclosure `base64url([salt, name, value])` → (name, value).
fn decode_disclosure(disclosure: &str) -> Result<(String, serde_json::Value), SdJwtError> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(disclosure.trim())
        .map_err(|e| SdJwtError::Malformed(format!("disclosure decode: {e}")))?;
    let arr: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|e| SdJwtError::Malformed(format!("disclosure json: {e}")))?;
    let arr = arr
        .as_array()
        .ok_or_else(|| SdJwtError::Malformed("disclosure is not an array".into()))?;
    if arr.len() != 3 {
        return Err(SdJwtError::Malformed(format!(
            "disclosure has {} elements, expected 3",
            arr.len()
        )));
    }
    let name = arr[1]
        .as_str()
        .ok_or_else(|| SdJwtError::Malformed("disclosure name not a string".into()))?;
    Ok((name.to_string(), arr[2].clone()))
}

/// Verify an SD-JWT presentation.
///
/// `trusted_jwks`: candidate keys for the **issuer** signature (from the
/// trusted-issuer list / DID document / Auth's own JWKS for self-issued
/// credentials). Each key is a JWK JSON object.
/// `kb_nonce`: the expected challenge inside the KB-JWT (present when the
/// verifier sent a challenge - always for OID4VP).
/// `presentation_key`: the wallet's public JWK (from `cnf.jwk` of the
/// presentation request/registration) - required when a KB-JJWT is present.
/// Verify presentation.
/// The KB-JWT's expected values (design §9a.27): the verifier passes
/// what ITS OWN authorization request pinned - `aud` (the request's
/// client_id), `nonce` (the request's fresh verifier nonce), and the
/// `kb_iat_window_secs` freshness bound (default 60s). When
/// `kb_jwt_key` is None, the KB key derives from the ISSUER JWT's own
/// `cnf.jwk` (the SD-JWT KB contract - the wallet signs with the
/// credential's bound key).
#[derive(Debug, Default, Clone)]
pub struct KbExpectation {
    /// The expected KB-JWT `aud` (the request's client_id).
    pub aud: Option<String>,
    /// The expected KB-JWT `nonce` (the request's verifier nonce).
    pub nonce: Option<String>,
    /// The KB-JWT `iat` freshness window (seconds; default 60).
    pub iat_window_secs: Option<i64>,
}

/// Verify an SD-JWT PRESENTATION (the issuer-jwt + disclosures + the
/// optional KB-JWT); the KB key derives from the explicit
/// `kb_jwt_key`, or (the default) the credential's own `cnf.jwk`
/// (design §9a.27); `expectation` pins the KB's aud/nonce/iat checks.
/// # Errors
/// [`SdJwtError`] on any signature/hash/claim failure.
pub fn verify_presentation(
    sd_jwt: &str,
    trusted_jwks: &[serde_json::Value],
    kb_jwt_key: Option<&serde_json::Value>,
    expectation: Option<&KbExpectation>,
    status_list_check: Option<&dyn Fn(&str, u32) -> Result<bool, String>>,
) -> Result<VerifiedPresentation, SdJwtError> {
    let compact = split_presentation_parts(sd_jwt)?;
    let Compact {
        issuer_jwt,
        disclosures,
        kb_jwt,
    } = compact;

    // ── 1. Issuer signature ────────────────────────────────────────────
    let header = sentin8::auth::jwt::decode_header(&issuer_jwt)
        .map_err(|e| SdJwtError::Malformed(format!("issuer jwt header: {e}")))?;
    let payload = sentin8::auth::jwt::decode_payload(&issuer_jwt)
        .map_err(|e| SdJwtError::Malformed(format!("issuer jwt payload: {e}")))?;
    let signing_input = sentin8::auth::jwt::signing_input(&issuer_jwt)
        .map_err(|e| SdJwtError::Malformed(format!("issuer jwt signing input: {e}")))?;
    let sig = sentin8::auth::jwt::decode_signature(&issuer_jwt)
        .map_err(|e| SdJwtError::Malformed(format!("issuer jwt signature: {e}")))?;

    // The header's `kid` may select the key; try every trusted key.
    let mut verified = false;
    for key in trusted_jwks {
        if let Some(kid) = header.get("kid").and_then(|k| k.as_str()) {
            if key
                .get("kid")
                .and_then(|k| k.as_str())
                .map(|k| k != kid)
                .unwrap_or(false)
            {
                continue;
            }
        }
        if crate::jwks::SigningKeys::verify_raw_with_jwk(key, signing_input.as_bytes(), &sig)
            .is_ok()
        {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err(SdJwtError::Signature);
    }

    // Structural freshness (SD-JWT : iat/nbf/exp in the issuer JWT).
    let now = chrono::Utc::now().timestamp();
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
        if exp < now {
            return Err(SdJwtError::Malformed("credential expired".into()));
        }
    }
    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64()) {
        if nbf > now + 60 {
            return Err(SdJwtError::Malformed("credential not yet valid".into()));
        }
    }

    // ── 2. Disclosures: hash-check every one against the `_sd` set ────
    let sd_digests: std::collections::HashSet<String> = payload
        .get("_sd")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    if sd_digests.is_empty() && !disclosures.is_empty() {
        return Err(SdJwtError::Malformed(
            "disclosures present but no _sd array".into(),
        ));
    }
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut disclosed: Vec<(String, serde_json::Value)> = Vec::with_capacity(disclosures.len());
    for (i, d) in disclosures.iter().enumerate() {
        // Salt+name+value raw string hashes to one of the _sd digests.
        let digest = b64_sha256(d);
        if !sd_digests.contains(&digest) {
            // Nested (array/object) disclosures are deferred (wallet
            // roadmap); today a disclosure must match a top-level `_sd` entry.
            return Err(SdJwtError::HashMismatch { disclosure: i });
        }
        if !seen.insert(digest) {
            return Err(SdJwtError::DuplicateDisclosure);
        }
        let (name, value) = decode_disclosure(d)?;
        disclosed.push((name, value));
    }

    // ── 3. Key binding ─────────────────────────────────────────────────
    let cnf = payload.get("cnf").cloned().ok_or(SdJwtError::KeyBinding)?;
    if let Some(kb) = kb_jwt {
        // SD-JWT KB-JWT: signed by the WALLET key over {iss: ..., nonce,
        // iat, aud, sd_hash} - sd_hash = SHA256 of the presentation WITHOUT
        // the KB-JWT (everything before the final '~').
        //
        // design §9a.27 - the expected key: an EXPLICIT verifier-supplied
        // key, or (the default verifier flow) the credential's OWN
        // `cnf.jwk` - the wallet signs the KB with the credential's bound
        // key; a kb_jwt signed by ANY other key cannot be the credential's
        // holder proof.
        let cnf_jwk = cnf.get("jwk").cloned().unwrap_or(serde_json::Value::Null);
        let expected_key: &serde_json::Value = match (kb_jwt_key, cnf_jwk.is_null()) {
            (Some(k), _) => k,
            (None, false) => &cnf_jwk,
            (None, true) => {
                return Err(SdJwtError::KeyBindingJwt(
                    "no presentation key registered and the credential carries no cnf.jwk".into(),
                ));
            }
        };
        // The KB-JWT's key binding (SD-JWT VC 7.2): the signature MUST
        // verify against the expected key (the credential's cnf.jwk -
        // the wallet signs the KB with the credential's bound key). An
        // EMBEDDED header jwk is OPTIONAL: when present it must match
        // the expected key (a mismatched embedded key cannot be the
        // holder proof); when absent the signature against cnf.jwk IS
        // the binding check (the suite's KB carries only alg+typ).
        let kb_header = sentin8::auth::jwt::decode_header(&kb)
            .map_err(|e| SdJwtError::KeyBindingJwt(format!("header: {e}")))?;
        let kb_jwk = kb_header
            .get("jwk")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if !kb_jwk.is_null() && !kb_jwk_matches(&kb_jwk, expected_key) {
            return Err(SdJwtError::KeyBindingJwt(
                "embedded jwk ≠ the credential's cnf.jwk".into(),
            ));
        }
        // Verify the KB-JWT signature with the expected key.
        let kb_input = sentin8::auth::jwt::signing_input(&kb)
            .map_err(|e| SdJwtError::KeyBindingJwt(format!("signing input: {e}")))?;
        let kb_sig = sentin8::auth::jwt::decode_signature(&kb)
            .map_err(|e| SdJwtError::KeyBindingJwt(format!("signature: {e}")))?;
        crate::jwks::SigningKeys::verify_raw_with_jwk(expected_key, kb_input.as_bytes(), &kb_sig)
            .map_err(|e| SdJwtError::KeyBindingJwt(format!("verify: {e}")))?;
        // sd_hash binds the exact presentation bytes before the KB-JWT.
        let kb_claims = sentin8::auth::jwt::decode_payload(&kb)
            .map_err(|e| SdJwtError::KeyBindingJwt(format!("payload: {e}")))?;
        let expected_sd_hash = expected_hash_of(sd_jwt, &kb);
        let sd_hash = kb_claims
            .get("sd_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if sd_hash != expected_sd_hash {
            return Err(SdJwtError::KeyBindingJwt("sd_hash mismatch".into()));
        }
        // - aud: the KB-JWT's audience = the VERIFIER's client_id (the
        // request's client_id) - the suite's KB-JWT-aud negative.
        // - nonce: the KB-JWT echoes the request's fresh verifier nonce -
        // the suite's replay defense.
        // - iat: the freshness window (± the verifier's bound).
        if let Some(exp) = expectation {
            if let Some(want_aud) = &exp.aud {
                let got_aud = kb_claims.get("aud").and_then(|v| match v {
                    serde_json::Value::String(s) => Some(s.clone()),
                    serde_json::Value::Array(a) => a.first().and_then(|x| x.as_str().map(str::to_string)),
                    _ => None,
                });
                if got_aud.as_deref() != Some(want_aud.as_str()) {
                    return Err(SdJwtError::KeyBindingJwt(
                        "KB-JWT aud does not match the request's client_id".into(),
                    ));
                }
            }
            if let Some(want_nonce) = &exp.nonce {
                let got_nonce = kb_claims.get("nonce").and_then(|v| v.as_str());
                if got_nonce != Some(want_nonce.as_str()) {
                    return Err(SdJwtError::KeyBindingJwt(
                        "KB-JWT nonce does not match the request's verifier nonce".into(),
                    ));
                }
            }
            let window = exp.iat_window_secs.unwrap_or(60);
            if let Some(iat) = kb_claims.get("iat").and_then(|v| v.as_i64()) {
                let now_ts = chrono::Utc::now().timestamp();
                if iat < now_ts - window {
                    return Err(SdJwtError::KeyBindingJwt(
                        "KB-JWT iat is too far in the past".into(),
                    ));
                }
                if iat > now_ts + 60 {
                    return Err(SdJwtError::KeyBindingJwt(
                        "KB-JWT iat is in the future".into(),
                    ));
                }
            }
        }
    }
    // cnf must carry the wallet's key (proof-of-possession binding).
    if cnf.get("jwk").is_none() && cnf.get("jkt").is_none() {
        return Err(SdJwtError::KeyBinding);
    }

    // ── 4. Status (Status List 2021) ───────────────────────────────────
    // The status claim's shape: {"status_list": {"uri": ..., "idx": N}}
    // - the pointer paths are RELATIVE to the status object.
    if let Some(status) = payload.get("status") {
        if let (Some(uri), Some(entry)) = (
            status
                .pointer("/status_list/uri")
                .and_then(|v| v.as_str()),
            status
                .pointer("/status_list/idx")
                .and_then(|v| v.as_u64()),
        ) {
            if let Some(check) = status_list_check {
                // The callback returns true when the bit is SET (revoked).
                if check(uri, entry as u32).map_err(SdJwtError::StatusList)? {
                    return Err(SdJwtError::Revoked {
                        entry: entry as u32,
                    });
                }
            }
        }
    }

    // Merge disclosed claims over the issuer-signed payload.
    let mut claims = payload.clone();
    if let Some(obj) = claims.as_object_mut() {
        for (name, value) in disclosed {
            obj.remove("_sd");
            obj.insert(name, value);
        }
    }

    Ok(VerifiedPresentation {
        claims,
        issuer: payload
            .get("iss")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        cnf,
    })
}

/// Extract an SD-JWT's parts (issuer JWT, disclosures, KB-JWT).
fn split_presentation_parts(sd_jwt: &str) -> Result<Compact, SdJwtError> {
    let mut parts = sd_jwt.split('~');
    let issuer_jwt = parts
        .next()
        .ok_or_else(|| SdJwtError::Malformed("empty".into()))?
        .to_string();
    let rest: Vec<&str> = parts.collect();
    // Per SD-JWT : the KB-JWT is the LAST part; a trailing '~' produces
    // a final empty segment.
    let (disclosure_parts, kb) = match rest.split_last() {
        Some((last, head)) if last.is_empty() => (head.to_vec(), None),
        Some((last, head)) => (head.to_vec(), Some(last.to_string())),
        None => (vec![], None),
    };
    Ok(Compact {
        issuer_jwt,
        disclosures: disclosure_parts
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
        kb_jwt: kb,
    })
}

fn kb_jwk_matches(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    a == b
}

fn expected_hash_of(sd_jwt: &str, kb: &str) -> String {
    // sd_hash = SHA-256 over everything up to and including the '~' that
    // precedes the KB-JWT.
    let head_len = sd_jwt.len() - kb.len() - 1;
    let head = &sd_jwt[..head_len];
    b64_sha256(&format!("{head}~"))
}

use base64::Engine as _;

/// Fetch + decode a Status List 2021 document and read the revocation bit
/// for `entry`. The bitstring is deflate-compressed, base64url-encoded.
/// Cached in Valkey (5 min) by the caller wrapper - this fn is pure.
/// Handle status list bit.
/// Read one entry from a status list (RFC 9393's single-bit form +
/// draft-ietf-oauth-status-list's multi-bit form). The entries pack
/// MSB-first: entry i occupies bits `[i*bits, (i+1)*bits)` of the
/// inflated byte stream. A NON-ZERO value = revoked (the suite's
/// TokenStatusList packs the status value - 0 valid, >0 revoked).
pub fn status_list_bit(status_list_b64: &str, bits_per_entry: u32, entry: u32) -> Result<bool, String> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(status_list_b64.trim())
        .map_err(|e| format!("status list decode: {e}"))?;
    // Two compression forms: Status List 2021 (RFC 9393 - zlib) and
    // the OTSL JWT (draft-ietf-oauth-status-list-jwt 3.1 - raw
    // DEFLATE). Try zlib first, fall back to the raw form.
    use std::io::Read as _;
    let mut out = Vec::new();
    let mut zlib = flate2::read::ZlibDecoder::new(&raw[..]);
    let mut tried = Vec::new();
    match zlib.read_to_end(&mut tried) {
        Ok(_) => out = tried,
        Err(_) => {
            let mut deflate = flate2::read::DeflateDecoder::new(&raw[..]);
            deflate
                .read_to_end(&mut out)
                .map_err(|e| format!("status list inflate: {e}"))?;
        }
    }
    let bits = bits_per_entry.max(1) as usize;
    let bit_offset = entry as usize * bits;
    if bit_offset + bits > out.len() * 8 {
        return Err(format!("status list entry {entry} out of range"));
    }
    // The OTSL bit packing (the suite's TokenStatusList.getPackedValue
    // semantics): the byte stream is a little-endian bit array - bit p
    // of the stream is bit (p & 7) FROM THE LSB of byte (p >> 3); the
    // entry's bits run LSB-first from its offset.
    let mut value: u64 = 0;
    for i in 0..bits {
        let pos = bit_offset + i;
        let byte = out[pos / 8];
        let bit = (byte >> (pos % 8)) & 1;
        value |= (bit as u64) << i;
    }
    Ok(value != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disclosure_decode_round_trip() {
        use base64::Engine as _;
        let inner = serde_json::json!(["salt-1", "given_name", "Ada"]);
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(inner.to_string());
        let (name, value) = decode_disclosure(&enc).unwrap();
        assert_eq!(name, "given_name");
        assert_eq!(value, serde_json::json!("Ada"));
    }

    #[test]
    fn status_list_bit_read() {
        use base64::Engine as _;
        use std::io::Write as _;
        // A small status list (LSB-first packing): stream bit 1 set -
        // byte 0 bit 1 (the LSB-first bit array).
        let mut bytes = vec![0u8; 4];
        bytes[0] = 0b0000_0010; // bit 1 set
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&bytes).unwrap();
        let compressed = enc.finish().unwrap();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed);
        assert!(!status_list_bit(&b64, 1, 0).unwrap());
        assert!(status_list_bit(&b64, 1, 1).unwrap());
    }

    #[test]
    fn status_list_bit_multibit_read() {
        use base64::Engine as _;
        use std::io::Write as _;
        // A 2-bit-per-entry list (LSB-first): entry 0 = 0b01, entry 1 =
        // 0b10, entry 2 = 0b00 - the bits pack across the LSB-first
        // stream: 01 10 00 -> byte 0 = 0b00_01_10 | (0b01 << 6)? Build
        // by hand: entry0 bits 0-1 = 0b01, entry1 bits 2-3 = 0b10,
        // entry2 bits 4-5 = 0b00 -> byte0 = 0b0110_0100? Compute
        // directly: bit0=1, bit1=0, bit2=0, bit3=1, bit4=0, bit5=0.
        let mut bytes = vec![0u8; 1];
        bytes[0] = 0b0000_1001; // bits 0 and 3 set
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&bytes).unwrap();
        let compressed = enc.finish().unwrap();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed);
        // entry0 = bits 0,1 = 1,0 -> value 0b01 = revoked
        assert!(status_list_bit(&b64, 2, 0).unwrap());
        // entry1 = bits 2,3 = 0,1 -> value 0b10 = revoked
        assert!(status_list_bit(&b64, 2, 1).unwrap());
        // entry2 = bits 4,5 = 0,0 -> value 0 = valid
        assert!(!status_list_bit(&b64, 2, 2).unwrap());
    }

    /// The OTSL JWT body's `lst` member (draft-ietf-oauth-status-list-jwt
    /// 3.1 - the suite's TokenStatusList emits raw DEFLATE, not zlib):
    /// the reader falls back from zlib to the raw-DEFLATE form.
    #[test]
    fn status_list_bit_raw_deflate_read() {
        use base64::Engine as _;
        use std::io::Write as _;
        // bit 1 set - byte 0 bit 1 (the LSB-first bit array).
        let mut bytes = vec![0u8; 2];
        bytes[0] = 0b0000_0010;
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&bytes).unwrap();
        let compressed = enc.finish().unwrap();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed);
        assert!(!status_list_bit(&b64, 1, 0).unwrap());
        assert!(status_list_bit(&b64, 1, 1).unwrap());
        // An out-of-range entry errors (the list is 2 bytes = 16 bits).
        assert!(status_list_bit(&b64, 1, 16).is_err());
    }
}
