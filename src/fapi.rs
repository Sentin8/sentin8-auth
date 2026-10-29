// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! FAPI Security Profiles
//!
//! This module codifies the three FAPI profiles and their required security
//! flags. The actual enforcement is done by the `SecurityProfile` in
//! `oauth.rs` (already implemented), which reads the flags
//! from `sentin8_auth_security_profiles` and applies them on the authorize, token,
//! and introspection endpoints.
//!
//! Profiles:
//! - **FAPI 1.0 Advanced** : PAR + JAR required, mTLS or DPoP,
//! JARM optional, `iss` required.
//! - **FAPI 2.0** : PAR required, DPoP required, JARM required,
//! `iss` required, mTLS optional.
//! - **FAPI 2.0 Message Signing** : FAPI 2.0 + signed introspection
//! responses (RFC 9701) + signed authorization responses (JARM) with
//! external key proof.

use serde::{Deserialize, Serialize};

/// The FAPI security profile name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// The fapiprofile type.
pub enum FapiProfile {
    /// FAPI 1.0 Advanced (Read/Write API Security Profile).
    /// The fapi10advanced variant.
    Fapi10Advanced,
    /// FAPI 2.0 Security Profile.
    /// The fapi20 variant.
    Fapi20,
    /// FAPI 2.0 Message Signing Profile.
    /// The fapi20messagesigning variant.
    Fapi20MessageSigning,
}

impl FapiProfile {
    /// Handle as str.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fapi10Advanced => "fapi_1_advanced",
            Self::Fapi20 => "fapi_2",
            Self::Fapi20MessageSigning => "fapi_2_message_signing",
        }
    }

    /// Parse a FAPI profile from the `security_profiles.profile` value
    /// (or a legacy alias). `standard` and `fapi_1_baseline` return None -
    /// they are not FAPI profiles and carry no FAPI allow-list constraints
    /// (the flag columns alone govern them).
    /// Handle from str.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "fapi_1_advanced" | "fapi_1_0_advanced" | "fapi1_advanced" => {
                Some(Self::Fapi10Advanced)
            }
            "fapi_2" | "fapi_2_0" | "fapi2" => Some(Self::Fapi20),
            "fapi_2_message_signing" | "fapi_2_0_message_signing" | "fapi2_message_signing" => {
                Some(Self::Fapi20MessageSigning)
            }
            _ => None,
        }
    }
}

/// The required security flags for a FAPI profile.

/// the RELAXED flag set for the non-FAPI postures (standard, vci,
/// vci_haip - RFC 9101's plain form): exp/nbf optional, the unsigned
/// object form allowed. `FapiProfile::from_str(..).map(required_flags)`
/// unwraps to a FAPI posture; non-FAPI postures use this default.
pub fn required_flags_default() -> FapiSecurityFlags {
    FapiSecurityFlags {
        require_par: false,
        require_mtls: false,
        require_dpop: false,
        require_jarm: false,
        require_iss: false,
        require_jar: false,
        require_jwt_introspection: false,
        require_jar_exp: false,
        require_jar_nbf: false,
        require_jar_nonce: false,
        forbid_jar_alg_none: false,
        require_code_jarm_pairing: false,
    }
}
#[derive(Debug, Clone, Serialize)]
/// The fapisecurityflags type.
pub struct FapiSecurityFlags {
    /// The require par.
    pub require_par: bool,
    /// The require mtls.
    pub require_mtls: bool,
    /// The require DPoP.
    pub require_dpop: bool,
    /// The require JARM.
    pub require_jarm: bool,
    /// The require iss.
    pub require_iss: bool,
    /// The require JAR.
    pub require_jar: bool,
    /// The require JWT introspection.
    pub require_jwt_introspection: bool,
    /// (DESIGN 9a.14 mandate table): a SIGNED push MUST carry `exp`
    /// (FAPI1-ADV Part2 §5.2.2-13 / the f2m freshness binding).
    pub require_jar_exp: bool,
    /// a SIGNED push MUST carry `nbf` (Part2 §5.2.2-17).
    pub require_jar_nbf: bool,
    /// the object scope carrying `openid` makes `nonce` mandatory
    /// (Baseline §5.2.2.2 - nonce required for ALL openid flows).
    pub require_jar_nonce: bool,
    /// an UNSIGNED (alg=none) request object rejects (the
    /// signed-only postures: Part2 §5.2.2-1).
    pub forbid_jar_alg_none: bool,
    /// (FAPI1-ADV 5.2.2-2): response_type=code REQUIRES
    /// response_mode=jwt (the object's own claim, else the outer
    /// request's explicit mode) - the code||jwt pairing rule.
    pub require_code_jarm_pairing: bool,
}

impl FapiProfile {
    /// Get the required security flags for this profile.
    /// Handle required flags.
    pub fn required_flags(&self) -> FapiSecurityFlags {
        match self {
            // FAPI 1.0 Advanced: PAR + JAR, mTLS or DPoP (sender-constraining),
            // JARM optional, iss required.
            Self::Fapi10Advanced => FapiSecurityFlags {
                require_par: true,
                require_mtls: false, // mTLS OR DPoP - not both required
                require_dpop: false, // sender-constraining via either
                require_jarm: false,
                require_iss: true,
                require_jar: true,
                require_jwt_introspection: false,
                // Part2 §5.2.2-1/13/17 + Baseline §5.2.2.2 - the
                // signed push carries exp+nbf, nonce rides openid scope,
                // and the object is signed (alg none forbidden).
                require_jar_exp: true,
                require_jar_nbf: true,
                require_jar_nonce: true,
                forbid_jar_alg_none: true,
                // 5.2.2-2 - `code` rides response_mode=jwt ONLY
                // (JARM or the detached-signature hybrid; our plan runs
                // JARM).
                require_code_jarm_pairing: true,
            },
            // FAPI : PAR required, DPoP required, JARM required, iss required.
            Self::Fapi20 => FapiSecurityFlags {
                require_par: true,
                require_mtls: false,
                require_dpop: true,
                require_jarm: true,
                require_iss: true,
                require_jar: false, // PAR covers request object in FAPI 2.0
                require_jwt_introspection: false,
                // the DPoP posture pins signed pushes (exp+nbf).
                // NONCE: NOT required under FAPI 2.0 - the suite's
                // FAPI2SPFinalEnsureAuthorizationRequestWithoutNonceSuccess
                // runs SUCCESS ('nonce is an optional parameter for
                // response_type=code'); the Baseline 5.2.2.2 nonce mandate
                // is FAPI1-only.
                require_jar_exp: true,
                require_jar_nbf: true,
                require_jar_nonce: false,
                forbid_jar_alg_none: true,
                // require_jarm covers the pairing strictly more -
                // every Fapi20 response IS jwt; the flag stays false.
                require_code_jarm_pairing: false,
            },
            // FAPI 2.0 Message Signing: FAPI 2.0 + signed introspection (RFC 9701).
            Self::Fapi20MessageSigning => FapiSecurityFlags {
                require_par: true,
                require_mtls: false,
                require_dpop: true,
                require_jarm: true,
                require_iss: true,
                require_jar: false,
                require_jwt_introspection: true,
                // identical push mandates to Fapi20 (the f2m
                // posture ADDS signed introspection; the object rules are
                // the same posture family) - including the NO-nonce rule
                // (FAPI 2.0 keeps nonce optional for code flow).
                require_jar_exp: true,
                require_jar_nbf: true,
                require_jar_nonce: false,
                forbid_jar_alg_none: true,
                require_code_jarm_pairing: false,
            },
        }
    }

    /// Get the default grant types allowed for this profile.
    ///
    /// Authorization-code family (code + refresh) plus the **decoupled
    /// approval grants**: device_code (RFC 8628, the sentin8-cli flow) and
    /// CIBA. Both are user-facing grants whose approval is session-bound
    /// and client-bound, so they satisfy FAPI's intent - the
    /// profile constrains *authentication strength and token binding*, not
    /// the UX channel. client_credentials (M2M, sender-constrained via
    /// mTLS independently) is admitted by `is_grant_type_allowed`.
    /// Handle allowed grant types.
    pub fn allowed_grant_types(&self) -> Vec<&'static str> {
        match self {
            Self::Fapi10Advanced | Self::Fapi20 | Self::Fapi20MessageSigning => vec![
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
                "urn:ietf:params:oauth:grant-type:ciba",
                // RFC 8693 token exchange - the platform's delegation grant
                // (Sentin8:Bus ): a subscriber exchanges a publisher
                // token for a downscoped delegated token. Sender-constraining
                // comes from the act chain + optional cnf cert binding.
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ],
        }
    }

    /// Get the default response types allowed for this profile.
    /// FAPI profiles only support `code` (hybrid flow removed in FAPI ).
    /// Handle allowed response types.
    pub fn allowed_response_types(&self) -> Vec<&'static str> {
        vec!["code"]
    }

    /// Get the required PKCE code challenge method.
    /// Handle required code challenge method.
    pub fn required_code_challenge_method(&self) -> &'static str {
        "S256"
    }

    /// Check if a token endpoint auth method is allowed for this profile.
    ///
    /// - consulted by the token endpoint after client auth: a
    /// confidential client that authenticated with a weaker method than its
    /// FAPI profile permits (e.g. client_secret_post under fapi_2) is
    /// rejected. First-party public clients (`none` + `dpop_exempt`) are
    /// admitted by the profile table itself - FAPI 2.0 allows public
    /// clients with PKCE + DPoP-optional per the exemption decision matrix.
    /// Handle is auth method allowed.
    pub fn is_auth_method_allowed(&self, method: &str) -> bool {
        match self {
            // FAPI 1.0 Advanced: mTLS (tls_client_auth or self_signed) or
            // private_key_jwt - NOT client_secret_post/basic.
            Self::Fapi10Advanced => {
                method == "tls_client_auth"
                    || method == "self_signed_tls_client_auth"
                    || method == "private_key_jwt"
            }
            // FAPI : public clients use DPoP/PKCE; confidential clients
            // use mTLS or private_key_jwt. Secrets are not sufficient for
            // confidentiality under FAPI 2.0 (sender-constraining is the
            // defense - a shared secret is not sender-specific).
            // Attestation-based client auth composes with FAPI 2.0
            // (draft-ietf-oauth-attestation-based-client-auth §6.3 - the
            // attested key IS sender-constraining by construction).
            Self::Fapi20 | Self::Fapi20MessageSigning => {
                method == "none"
                    || method == "tls_client_auth"
                    || method == "self_signed_tls_client_auth"
                    || method == "private_key_jwt"
                    || method == crate::client_attestation::AUTH_METHOD
            }
        }
    }

    /// Check if a grant type is allowed for this profile.
    /// FAPI profiles restrict user-facing grants to the authorization-code
    /// family; client_credentials (M2M) is outside the FAPI profile's scope
    /// (it is sender-constrained by mTLS independently ).
    /// Handle is grant type allowed.
    pub fn is_grant_type_allowed(&self, grant_type: &str) -> bool {
        self.allowed_grant_types().contains(&grant_type) || grant_type == "client_credentials"
    }
}

/// Detail-flag defaults for a profile ( reset-on-change source).
/// Derived from the flag matrix in `sentin8-.md`
/// Returns None for unknown profile names.
#[derive(Debug, Clone, Serialize)]
/// The profiledefaults type.
pub struct ProfileDefaults {
    /// The require par.
    pub require_par: bool,
    /// The require mtls.
    pub require_mtls: bool,
    /// The require JARM.
    pub require_jarm: bool,
    /// The require DPoP.
    pub require_dpop: bool,
    /// The require http signatures.
    pub require_http_signatures: bool,
    /// The require JWT introspection.
    pub require_jwt_introspection: bool,
    /// The require iss.
    pub require_iss: bool,
    /// Maximum token lifetime.
    pub max_token_lifetime: i32,
    /// The refresh rotation.
    pub refresh_rotation: bool,
}

impl ProfileDefaults {
    /// The per-profile flag matrix. Unknown names → None (the
    /// caller rejects the selection).
    /// Handle for profile.
    pub fn for_profile(profile: &str) -> Option<Self> {
        Some(match profile {
            "standard" => Self {
                require_par: false,
                require_mtls: false,
                require_jarm: false,
                require_dpop: false,
                require_http_signatures: false,
                require_jwt_introspection: false,
                require_iss: true,
                max_token_lifetime: 3600,
                refresh_rotation: true,
            },
            "fapi_1_baseline" => Self {
                require_par: false,
                require_mtls: false,
                require_jarm: true,
                require_dpop: false,
                require_http_signatures: false,
                require_jwt_introspection: false,
                require_iss: true,
                max_token_lifetime: 1800,
                refresh_rotation: true,
            },
            "fapi_1_advanced" => Self {
                require_par: true,
                require_mtls: true,
                require_jarm: true,
                require_dpop: false,
                require_http_signatures: false,
                require_jwt_introspection: false,
                require_iss: true,
                max_token_lifetime: 900,
                refresh_rotation: true,
            },
            "fapi_2" => Self {
                require_par: true,
                require_mtls: false,
                require_jarm: true,
                require_dpop: true,
                require_http_signatures: false,
                require_jwt_introspection: false,
                require_iss: true,
                max_token_lifetime: 900,
                // FAPI 2.0 Security Profile (final) 5.3.2.1-9 + Note 1:
                // refresh token rotation is PROHIBITED (sender-constrained
                // confidential tokens make rotation a pure failure mode -
                // a lost new token bricks the grant; the lost-token retry
                // exception the spec allows is an extraordinary procedure,
                // not a standing posture).
                refresh_rotation: false,
            },
            "fapi_2_message_signing" => Self {
                require_par: true,
                require_mtls: false,
                require_jarm: true,
                require_dpop: true,
                // The FINAL message-signing plan's "request signing" is the
                // SIGNED REQUEST OBJECT (JAR signed_non_repudiation variant),
                // NOT RFC 9421 HTTP message signatures on the token endpoint:
                // the suite's happy flow sends a PLAIN token POST and expects
                // 200 (the signature negatives exercise the JAR alg family).
                require_http_signatures: false,
                require_jwt_introspection: false,
                require_iss: true,
                max_token_lifetime: 900,

                // Same 5.3.2.1-9 prohibition (message signing is FAPI 2.0).
                refresh_rotation: false,
            },
            "fapi_ciba" => Self {
                require_par: false,
                require_mtls: false,
                require_jarm: false,
                require_dpop: true,
                require_http_signatures: false,
                require_jwt_introspection: false,
                require_iss: true,
                max_token_lifetime: 900,
                refresh_rotation: true,
            },
            _ => return None,
        })
    }

    /// Apply the selected extensions' effects on the defaults (
    /// extensions): Message-Signing halves are additive to any profile.
    /// Handle with extensions.
    pub fn with_extensions(mut self, extensions: &[String]) -> Self {
        if extensions.iter().any(|e| e == "http_signatures") {
            self.require_http_signatures = true;
        }
        if extensions.iter().any(|e| e == "jwt_introspection") {
            self.require_jwt_introspection = true;
        }
        self
    }

    /// Apply the overlay's constraints ( overlays): CDR forces mTLS
    /// holder-of-key; OBIE/Brazil's SSA check is transport-independent
    /// (enforced at client auth, not via flags).
    /// Handle with overlay.
    pub fn with_overlay(mut self, overlay: &str) -> Self {
        if overlay == "cdr" {
            self.require_mtls = true;
        }
        self
    }
}

/// Determine if the FAPI 1.0 Advanced sender-constraining is satisfied.
/// Per FAPI 1.0 Advanced , either mTLS or DPoP must be used.
/// Handle fapi10 sender constraining satisfied.
pub fn fapi10_sender_constraining_satisfied(use_mtls: bool, use_dpop: bool) -> bool {
    use_mtls || use_dpop
}

/// Validate a FAPI 2.0 request - DPoP must be present.
/// Handle fapi20 validate DPoP required.
pub fn fapi20_validate_dpop_required(dpop_present: bool) -> Result<(), String> {
    if !dpop_present {
        return Err("FAPI 2.0 requires DPoP".into());
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fapi_profile_from_str() {
        assert_eq!(
            FapiProfile::from_str("fapi_1_0_advanced"),
            Some(FapiProfile::Fapi10Advanced)
        );
        assert_eq!(FapiProfile::from_str("fapi_2_0"), Some(FapiProfile::Fapi20));
        assert_eq!(
            FapiProfile::from_str("fapi_2_0_message_signing"),
            Some(FapiProfile::Fapi20MessageSigning)
        );
        assert_eq!(FapiProfile::from_str("unknown"), None);
    }

    #[test]
    fn fapi10_advanced_flags() {
        let flags = FapiProfile::Fapi10Advanced.required_flags();
        assert!(flags.require_par);
        assert!(flags.require_jar);
        assert!(flags.require_iss);
        assert!(!flags.require_dpop); // mTLS OR DPoP
        assert!(!flags.require_jarm);
    }

    #[test]
    fn fapi20_flags() {
        let flags = FapiProfile::Fapi20.required_flags();
        assert!(flags.require_par);
        assert!(flags.require_dpop);
        assert!(flags.require_jarm);
        assert!(flags.require_iss);
        assert!(!flags.require_jwt_introspection);
    }

    #[test]
    fn fapi20_message_signing_flags() {
        let flags = FapiProfile::Fapi20MessageSigning.required_flags();
        assert!(flags.require_par);
        assert!(flags.require_dpop);
        assert!(flags.require_jarm);
        assert!(flags.require_iss);
        assert!(flags.require_jwt_introspection);
    }

    #[test]
    fn fapi10_auth_methods() {
        let profile = FapiProfile::Fapi10Advanced;
        assert!(profile.is_auth_method_allowed("tls_client_auth"));
        assert!(profile.is_auth_method_allowed("private_key_jwt"));
        assert!(!profile.is_auth_method_allowed("client_secret_post"));
        assert!(!profile.is_auth_method_allowed("client_secret_basic"));
    }

    #[test]
    fn fapi20_auth_methods() {
        let profile = FapiProfile::Fapi20;
        assert!(profile.is_auth_method_allowed("none"));
        assert!(profile.is_auth_method_allowed("tls_client_auth"));
        assert!(!profile.is_auth_method_allowed("client_secret_post"));
    }

    #[test]
    fn fapi10_sender_constraining() {
        assert!(fapi10_sender_constraining_satisfied(true, false));
        assert!(fapi10_sender_constraining_satisfied(false, true));
        assert!(!fapi10_sender_constraining_satisfied(false, false));
    }

    #[test]
    fn fapi20_dpop_required() {
        assert!(fapi20_validate_dpop_required(true).is_ok());
        assert!(fapi20_validate_dpop_required(false).is_err());
    }

    #[test]
    fn allowed_grant_types_respect_profile() {
        let grants = FapiProfile::Fapi20.allowed_grant_types();
        assert!(grants.contains(&"authorization_code"));
        assert!(grants.contains(&"refresh_token"));
        // implicit grant NOT allowed in FAPI 2.0
        assert!(!grants.contains(&"implicit"));
    }

    #[test]
    fn required_code_challenge_method_matches_profile() {
        assert_eq!(FapiProfile::Fapi20.required_code_challenge_method(), "S256");
    }
}
