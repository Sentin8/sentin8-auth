// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-License-Identifier: Apache-2.0

//! The x5c leaf helpers for the leaf-matched signer (HAIP-X5C-1): the
//! leaf certificate's EC public point in the `ec_pk_b64` comparison
//! form, shared by the credential and status-list mints.

use base64::Engine;

/// The std-base64 DER leaf's uncompressed P-256 point, URL-safe
/// base64 (the `ec_pk_b64` member's form - 65 bytes `04 || x || y`).
///
/// # Errors
/// A descriptive string when the point is absent.
pub fn leaf_ec_point_b64(cert_std_b64: &str) -> Result<String, String> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(cert_std_b64)
        .map_err(|e| format!("x5c leaf decode: {e}"))?;
    for i in 0..der.len().saturating_sub(65) {
        // The SPKI BIT STRING window (03 42 00 04 <point>) - real
        // certificates carry the uncompressed point inside the SPKI.
        if (der[i] == 0x03 || der[i] == 0x04) && der[i + 1] == 0x42 && der[i + 2] == 0x00 {
            let point = &der[i + 3..i + 68];
            if point.first() == Some(&0x04) && point.len() == 65 {
                return Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point));
            }
        }
    }
    Err("the x5c leaf carries no uncompressed P-256 public point".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_non_cert() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"not-a-cert");
        assert!(leaf_ec_point_b64(&b64).is_err());
    }
}
