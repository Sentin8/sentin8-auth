// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! OID4VCI §12.2.4 credential-response encryption (DESIGN §9a.19
//! addendum): JWE production for the credential endpoint's encrypted
//! responses.
//!
//! The wallet carries `credential_response_encryption {jwk, alg, enc}`
//! in its credential request; the issuer wraps the credentials object
//! as a compact JWE. Contract (RFC 7516 + RFC 7518):
//!
//! - key agreement `ECDH-ES` (§4.6): the wallet's P-256 `jwk` epk, the
//!   issuer's ephemeral `epk` in the JWE header, `apu`/`apv` exchange
//!   headers, ConcatKDF with `alg=A256KW..-` ASCII party descriptors —
//!   produced CEK length = 32 octets (`A256GCM`).
//! - content encryption `A256GCM` (§5.2): 96-bit IV, AAD = the ASCII
//!   JWE Protected Header, 128-bit tag.
//! - unsupported `alg`/`enc` values reject with the credential-request
//!   error shape (`400 invalid_credential_request` - the suite's
//!   FailOnUnsupportedEncryptionAlgorithm).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use p256::elliptic_curve::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use serde::Deserialize;

/// The JWE algorithms the credential response supports (design §9a.19
/// addendum): ECDH-ES (single-use ephemeral key agreement, direct CEK).
pub const SUPPORTED_ALGS: [&str; 1] = ["ECDH-ES"];
/// The content-encryption algorithms the credential response supports.
pub const SUPPORTED_ENCS: [&str; 1] = ["A256GCM"];

/// The wallet's credential-response key (an EC JWK: `kty/crv/x/y`).
#[derive(Debug, Deserialize)]
pub struct ResponseEncryption {
    /// Key agreement algorithm (JWA). OPTIONAL per the OID4VCI §12.2.4
    /// wallet form - the suite's wallet omits it and carries the alg on
    /// the recipient JWK instead (`jwk.alg: "ECDH-ES"`); the accessor
    /// falls back to that JWK claim, then to `ECDH-ES` (the only
    /// supported agreement alg).
    #[serde(default)]
    pub alg: Option<String>,
    /// Content-encryption algorithm: only `A256GCM` is supported.
    pub enc: String,
    /// The recipient key (the wallet's generated ECDH-ES P-256 public
    /// JWK - the suite's VCIGenerateCredentialEncryptionJwks).
    #[serde(rename = "jwk")]
    pub jwk: Option<serde_json::Value>,
    /// Alternative wallet form: a JWKS envelope (`{keys:[...]}`).
    #[serde(rename = "jwks")]
    pub jwks: Option<serde_json::Value>,
}

impl ResponseEncryption {
    /// The EFFECTIVE key-agreement alg: the explicit `alg` member, else
    /// the recipient JWK's `alg` claim, else `ECDH-ES`.
    pub fn effective_alg(&self) -> String {
        self.alg
            .clone()
            .or_else(|| {
                self.recipient_jwk()
                    .and_then(|k| k.get("alg"))
                    .and_then(|v| v.as_str().map(str::to_string))
            })
            .unwrap_or_else(|| "ECDH-ES".to_string())
    }
}

/// A parse/validation failure (the caller maps to `400
/// invalid_credential_request`).
#[derive(Debug)]
pub enum EncryptionError {
    /// The requested alg is not in `SUPPORTED_ALGS`.
    UnsupportedAlg(String),
    /// The requested enc is not in `SUPPORTED_ENCS`.
    UnsupportedEnc(String),
    /// The wallet's recipient key is missing/malformed.
    InvalidKey,
    /// The request's key is not on P-256 (ECDH-ES direct key
    /// agreement).
    UnsupportedCurve,
    /// typ/alg header malformed.
    BadTyp,
}

impl ResponseEncryption {
    /// Validate the requested algorithms against the advertisement.
    ///
    /// # Errors
    /// `EncryptionError` - unsupported alg/enc.
    pub fn validate(&self) -> Result<(), EncryptionError> {
        let alg = self.effective_alg();
        if !SUPPORTED_ALGS.contains(&alg.as_str()) {
            return Err(EncryptionError::UnsupportedAlg(alg));
        }
        if !SUPPORTED_ENCS.contains(&self.enc.as_str()) {
            return Err(EncryptionError::UnsupportedEnc(self.enc.clone()));
        }
        Ok(())
    }

    /// The recipient public JWK: the `jwk` member, else the first key of
    /// the `jwks` envelope.
    pub fn recipient_jwk(&self) -> Option<&serde_json::Value> {
        self.jwk
            .as_ref()
            .or_else(|| {
                self.jwks
                    .as_ref()
                    .and_then(|k| k.get("keys"))
                    .and_then(|keys| keys.as_array())
                    .and_then(|a| a.first())
            })
    }
}

/// b64url no-pad encode.
fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// b64url no-pad decode.
#[allow(dead_code)]
pub(crate) fn b64u_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("b64url decode: {e}"))
}

/// ECDH-ES direct CEK (RFC 7518 §4.6 / NIST ConcatKDF): the shared
/// secret from the ephemeral key ↔ wallet key agreement, with the JWE
/// party descriptors (`apu`/`apv` exchange headers, `alg`/`enc` ASCII
/// algorithm ID).
pub(crate) fn concat_cek(
    shared_secret: &[u8],
    enc: &str,
    apu: &[u8],
    apv: &[u8],
    cek_len: usize,
) -> Vec<u8> {
    // AlgorithmID = ASCII(enc) length-prefixed 32-bit BE - RFC 7518
    // §4.6.2: for DIRECT key agreement (ECDH-ES, no key wrap) the value
    // is the `enc` content-encryption identifier, NOT `alg`;
    // PartyUInfo / PartyVInfo likewise (§4.6.1 layout).
    let mut info = Vec::with_capacity(4 + enc.len() + 4 + apu.len() + 4 + apv.len() + 4);
    info.extend_from_slice(&(enc.len() as u32).to_be_bytes());
    info.extend_from_slice(enc.as_bytes());
    info.extend_from_slice(&(apu.len() as u32).to_be_bytes());
    info.extend_from_slice(apu);
    info.extend_from_slice(&(apv.len() as u32).to_be_bytes());
    info.extend_from_slice(apv);
    info.extend_from_slice(&(cek_len as u32 * 8u32).to_be_bytes()); // SuppPubInfo = key length in BITS
    // NIST SP 800-56A §5.8.1 single-step key derivation (RFC 7518 §4.6.1
    // "Concat KDF"): KeyData = SHA-256(Counter32BE || Z || OtherInfo)
    // iterated, Z INSIDE the hashed message - NOT HKDF (HMAC-with-salt);
    // nimbus/OpenSSL implement the plain-hash form and a mixed form is
    // invisible to a same-code roundtrip test.
    use sha2::{Digest, Sha256};
    let mut out = Vec::with_capacity(cek_len);
    let mut counter: u32 = 1;
    while out.len() < cek_len {
        let mut h = Sha256::new();
        h.update(counter.to_be_bytes());
        h.update(shared_secret);
        h.update(&info);
        out.extend_from_slice(&h.finalize_reset());
        counter += 1;
    }
    out.truncate(cek_len);
    out
}

/// A recipient EC public JWK → P-256 public key bytes (SEC1
/// uncompressed). ECDH-ES direct key agreement REQUIRES P-256 for this
/// implementation (`crv: P-256`) - other curves answer
/// `UnsupportedCurve`.
pub(crate) fn jwk_to_p256(jwk: &serde_json::Value) -> Result<p256::PublicKey, EncryptionError> {
    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
    let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
    if kty != "EC" || crv != "P-256" {
        return Err(EncryptionError::UnsupportedCurve);
    }
    let x = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or(EncryptionError::InvalidKey)?;
    let y = jwk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or(EncryptionError::InvalidKey)?;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let xb = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| EncryptionError::InvalidKey)?;
    let yb = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|_| EncryptionError::InvalidKey)?;
    let mut point = vec![0x04u8];
    point.extend_from_slice(&xb);
    point.extend_from_slice(&yb);
    p256::PublicKey::from_sec1_bytes(&point).map_err(|_| EncryptionError::InvalidKey)
}

/// Build a compact JWE (RFC 7516 §5.1) wrapping `plaintext` for the
/// wallet's `credential_response_encryption` key: ECDH-ES key
/// agreement, A256GCM content encryption. Returns the JWE compact
/// serialization (`header.ekIV.ciphertext.tag` five b64url segments).
///
/// # Errors
/// `EncryptionError` - unsupported alg/enc or a malformed recipient key
/// (the caller maps to the credential-request error shape).
///
/// # Examples
/// ```no_run
/// use sentin8_auth_server::jwe::*;
/// // (shape only - real keys are generated per-request)
/// let enc = serde_json::from_value::<ResponseEncryption>(serde_json::json!({
///     "alg": "ECDH-ES", "enc": "A256GCM",
///     "jwk": {"kty":"EC","crv":"P-256","x":"a","y":"b"},
/// })).unwrap();
/// assert!(enc.validate().is_ok());
/// ```
pub fn encrypt_credential_response(
    plaintext: &[u8],
    enc: &ResponseEncryption,
) -> Result<String, EncryptionError> {
    enc.validate()?;
    let wallet_key = enc.recipient_jwk().ok_or(EncryptionError::InvalidKey)?;
    let recipient = jwk_to_p256(wallet_key)?;

    // Ephemeral key pair (the issuer's side of the ECDH-ES agreement).
    let epk_secret =
        EphemeralSecret::<p256::NistP256>::random(&mut rand::thread_rng());
    let epk_point = epk_secret.public_key().to_encoded_point(false);
    let epk = serde_json::json!({
        "kty": "EC", "crv": "P-256",
        "x": b64u(&epk_point.as_ref()[1..33]),
        "y": b64u(&epk_point.as_ref()[33..65]),
    });
    // Party descriptors: apu/apv exchange headers (absent here → zero
    // length; the wallet's probe uses the same layout).
    let apu: Vec<u8> = Vec::new();
    let apv: Vec<u8> = Vec::new();

    let protected = serde_json::json!({
        "alg": enc.alg.as_deref().unwrap_or("ECDH-ES"),
        "enc": enc.enc,
        "epk": epk,
        "apu": b64u(&apu),
        "apv": b64u(&apv),
    });
    let protected_json = protected.to_string();
    let protected_b64 = b64u(protected_json.as_bytes());

    // ECDH-ES: shared secret = ECDH(issuer_ephemeral, wallet_public).
    let shared = epk_secret.diffie_hellman(&recipient);
    let cek = concat_cek(shared.raw_secret_bytes(), &enc.enc, &apu, &apv, 32);

    // A256GCM content encryption (RFC 7518 §5.2): IV = 96-bit random,
    // AAD = ASCII(protected header).
    let cek: [u8; 32] = cek.try_into().map_err(|_| EncryptionError::InvalidKey)?;
    let cipher = Aes256Gcm::new((&cek).into());
    let iv: [u8; 12] = rand::random();
    let payload = Payload {
        msg: plaintext,
        aad: protected_b64.as_bytes(),
    };
    let sealed = cipher
        .encrypt(Nonce::from_slice(&iv), payload)
        .map_err(|_| EncryptionError::InvalidKey)?;
    // JWE splits the trailing 16-byte tag off the ciphertext; the
    // encrypted-key segment is EMPTY for ECDH-ES direct key agreement
    // (the compact form always carries all five dot-separated parts).
    let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
    Ok(format!(
        "{}..{}.{}.{}",
        protected_b64,
        b64u(&iv),
        b64u(ciphertext),
        b64u(tag),
    ))
}

/// Decrypt an incoming ECDH-ES + A256GCM compact JWE with the
/// recipient's private key (the issuer's request-encryption side): the
/// mirror of [`encrypt_credential_response`] - parse the header's
/// `epk`, agree on the shared secret with OUR private point, and open
/// the A256GCM content (AAD = the protected header segment). Used by
/// the credential endpoint when the metadata advertises
/// `credential_request_encryption` and the wallet encrypts its request.
///
/// # Errors
/// `EncryptionError` on malformed/unsupported forms and on decrypt
/// failure (maps to `400 invalid_credential_request`).
pub fn decrypt_credential_request(
    jwe: &str,
    recipient_private_pem: &str,
) -> Result<Vec<u8>, EncryptionError> {
    let (parts, merged_tag): (Vec<&str>, bool) = {
        let all: Vec<&str> = jwe.split('.').collect();
        // RFC 7516 §7.1 compact = 5 parts (tag split out). The suite's
        // wallet also emits a 4-part variant where the GCM ciphertext
        // and tag ride ONE segment - accept both (part 3 count check
        // mirrors nimbus's EncryptedJWT/JWEObject serializers).
        if all.len() == 5 {
            (all, false)
        } else if all.len() == 4 {
            (all, true)
        } else {
            return Err(EncryptionError::InvalidKey);
        }
    };
    let header_json = b64u_decode(parts[0]).map_err(|_| EncryptionError::BadTyp)?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_json).map_err(|_| EncryptionError::BadTyp)?;
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or(EncryptionError::UnsupportedAlg(String::new()))?;
    let enc_name = header
        .get("enc")
        .and_then(|v| v.as_str())
        .ok_or(EncryptionError::UnsupportedEnc(String::new()))?;
    if !SUPPORTED_ALGS.contains(&alg) {
        return Err(EncryptionError::UnsupportedAlg(alg.to_string()));
    }
    if !SUPPORTED_ENCS.contains(&enc_name) {
        return Err(EncryptionError::UnsupportedEnc(enc_name.to_string()));
    }
    // Our private point (EC/P-256 PKCS#8 PEM).
    use p256::elliptic_curve::pkcs8::DecodePrivateKey;
    let our_sk = p256::SecretKey::from_pkcs8_pem(recipient_private_pem)
        .map_err(|_| EncryptionError::InvalidKey)?;
    // The sender's ephemeral public key.
    let epk = header
        .get("epk")
        .ok_or(EncryptionError::InvalidKey)?;
    let sender_pub = jwk_to_p256(epk)?;
    let apu = b64u_decode(header.get("apu").and_then(|v| v.as_str()).unwrap_or(""))
        .map_err(|_| EncryptionError::InvalidKey)?;
    let apv = b64u_decode(header.get("apv").and_then(|v| v.as_str()).unwrap_or(""))
        .map_err(|_| EncryptionError::InvalidKey)?;
    // ECDH(our_private, sender_ephemeral) - the SAME value both sides
    // derive; the wallet used ECDH-ES direct so no encrypted key part.
    let shared = p256::elliptic_curve::ecdh::diffie_hellman(
        &our_sk.to_nonzero_scalar(),
        sender_pub.as_affine(),
    );
    let cek = concat_cek(shared.raw_secret_bytes(), enc_name, &apu, &apv, 32);
    let cek: [u8; 32] = cek.try_into().map_err(|_| EncryptionError::InvalidKey)?;
    let iv = b64u_decode(parts[2]).map_err(|_| EncryptionError::InvalidKey)?;
    let (ct, tag) = if merged_tag {
        // 4-part form: ciphertext with the GCM tag APPENDED.
        let blob = b64u_decode(parts[3]).map_err(|_| EncryptionError::InvalidKey)?;
        if blob.len() < 16 {
            return Err(EncryptionError::InvalidKey);
        }
        let (c, t) = blob.split_at(blob.len() - 16);
        (c.to_vec(), t.to_vec())
    } else {
        (
            b64u_decode(parts[3]).map_err(|_| EncryptionError::InvalidKey)?,
            b64u_decode(parts[4]).map_err(|_| EncryptionError::InvalidKey)?,
        )
    };
    let cipher = Aes256Gcm::new((&cek).into());
    let mut sealed = ct.clone();
    sealed.extend_from_slice(&tag);
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &sealed,
                aad: parts[0].as_bytes(),
            },
        )
        .map_err(|_| EncryptionError::InvalidKey)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_key() -> (serde_json::Value, p256::SecretKey) {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let sk = p256::SecretKey::from_slice(&seed).expect("sk");
        let point = sk.public_key().to_encoded_point(false);
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": b64u(&point.as_ref()[1..33]),
            "y": b64u(&point.as_ref()[33..65]),
        });
        (jwk, sk)
    }

    /// The issuer's JWE decrypts back to the plaintext with the
    /// WALLET's key: key agreement, ConcatKDF, IV/tag layout verified
    /// by round-trip (a recipient-side mirror of RFC 7516 §5.2).
    #[test]
    fn jwe_round_trips_with_the_wallet_key() {
        let (jwk, wallet_sk) = roundtrip_key();
        let enc = serde_json::from_value::<ResponseEncryption>(serde_json::json!({
            "alg": "ECDH-ES", "enc": "A256GCM", "jwk": jwk,
        }))
        .expect("parse");
        enc.validate().expect("supported");
        let plaintext = b"{\"credentials\":[{\"format\":\"dc+sd-jwt\"}]}";
        let jwe = encrypt_credential_response(plaintext, &enc).expect("encrypt");
        let parts: Vec<&str> = jwe.split('.').collect();
        assert_eq!(parts.len(), 5);
        // Recipient side: parse header, derive the same CEK via ECDH.
        let hdr: serde_json::Value = serde_json::from_slice(
            &b64u_decode(parts[0]).expect("hdr"),
        )
        .expect("hdr json");
        assert_eq!(hdr["alg"], "ECDH-ES");
        assert_eq!(hdr["enc"], "A256GCM");
        let epk = &hdr["epk"];
        let issuer_pub = jwk_to_p256(epk).expect("issuer epk");
        let apu = b64u_decode(hdr["apu"].as_str().unwrap()).expect("apu");
        let apv = b64u_decode(hdr["apv"].as_str().unwrap()).expect("apv");
        let shared = p256::elliptic_curve::ecdh::diffie_hellman(
            &wallet_sk.to_nonzero_scalar(),
            issuer_pub.as_affine(),
        );
        let cek2 = concat_cek(shared.raw_secret_bytes(), "A256GCM", &apu, &apv, 32);
        let cek2: [u8; 32] = cek2.try_into().expect("32");
        // Compact layout (ECDH-ES): [0]=header, [1]=EMPTY encrypted key,
        // [2]=IV, [3]=ciphertext, [4]=tag.
        assert!(parts[1].is_empty(), "ECDH-ES direct = empty jwe ek part");
        let iv = b64u_decode(parts[2]).expect("iv");
        let ct = b64u_decode(parts[3]).expect("ct");
        let tag = b64u_decode(parts[4]).expect("tag");
        let mut sealed = ct.clone();
        sealed.extend_from_slice(&tag);
        let cipher = Aes256Gcm::new((&cek2).into());
        let got = cipher
            .decrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: &sealed,
                    aad: parts[0].as_bytes(),
                },
            )
            .expect("decrypt");
        assert_eq!(got, plaintext);
    }

    /// Unsupported alg/enc values reject with the negative surface.
    #[test]
    fn unsupported_algorithms_reject() {
        let (jwk, _) = roundtrip_key();
        let bad_alg = serde_json::from_value::<ResponseEncryption>(serde_json::json!({
            "alg": "RSA-OAEP", "enc": "A256GCM", "jwk": jwk,
        }))
        .expect("parse");
        assert!(matches!(
            bad_alg.validate(),
            Err(EncryptionError::UnsupportedAlg(_))
        ));
        let (jwk2, _) = roundtrip_key();
        let bad_enc = serde_json::from_value::<ResponseEncryption>(serde_json::json!({
            "alg": "ECDH-ES", "enc": "A128CBC-HS256", "jwk": jwk2,
        }))
        .expect("parse");
        assert!(matches!(
            bad_enc.validate(),
            Err(EncryptionError::UnsupportedEnc(_))
        ));
    }

    /// The REQUEST-side decrypt: a JWE produced for the issuer's EC
    /// key decrypts back (the wallet's mirror of the response path).
    #[test]
    fn request_jwe_decrypts_with_the_recipient_key() {
        use p256::elliptic_curve::pkcs8::EncodePrivateKey;
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let issuer_sk = p256::SecretKey::from_slice(&seed).expect("issuer key");
        let pkcs8 = issuer_sk
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("pkcs8");
        // Wallet-side encrypt to the issuer's PUBLIC key.
        let point = issuer_sk.public_key().to_encoded_point(false);
        let issuer_jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": b64u(&point.as_ref()[1..33]),
            "y": b64u(&point.as_ref()[33..65]),
        });
        let enc = serde_json::from_value::<ResponseEncryption>(serde_json::json!({
            "alg": "ECDH-ES", "enc": "A256GCM", "jwk": issuer_jwk,
        }))
        .expect("parse");
        let plaintext = b"{\"credential_configuration_id\":\"VerifiedPersonCredential\"}";
        let jwe =
            encrypt_credential_response(plaintext, &enc).expect("encrypt");
        // Issuer-side decrypt with the SAME private PEM.
        let got =
            decrypt_credential_request(&jwe, pkcs8.as_str()).expect("decrypt");
        assert_eq!(got, plaintext);
        // A wrong key fails closed.
        let (other_jwk, _) = roundtrip_key();
        let _ = other_jwk;
        let seed2 = [2u8; 32];
        let other_sk = p256::SecretKey::from_slice(&seed2).unwrap();
        let other_pem = other_sk
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();
        assert!(decrypt_credential_request(&jwe, other_pem.as_str()).is_err());
    }
}

