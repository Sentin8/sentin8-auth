// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Passkey (WebAuthn) enrollment and verification
//!
//! Implements server-side WebAuthn (CTAP2 / WebAuthn Level 3) for passkey
//! enrollment and sign-in. The flow is:
//!
//! 1. `POST /v1/passkey/enroll/begin` - returns a challenge (`PublicKeyCredentialCreationOptions`)
//! containing a random nonce. The challenge is stored in
//! `sentin8_auth_mfa_challenges` (challenge_kind='enroll') with a 5-minute TTL.
//! 2. The client (Auth hosted UI) calls `navigator.credentials.create({...})`
//! and submits the result to `POST /v1/passkey/enroll/finish`.
//! 3. The server validates the attestation, extracts the credential public
//! key (P-256 ES256), stores it in `sentin8_auth_mfa_factors` (factor_kind='webauthn'),
//! and marks the factor active.
//! 4. For sign-in: `POST /v1/passkey/verify/begin` returns a
//! `PublicKeyCredentialRequestOptions` challenge; the client calls
//! `navigator.credentials.get({...})` and submits the assertion to
//! `POST /v1/passkey/verify/finish`, which validates the signature against
//! the stored public key and activates the pending session.
//!
//! This implementation supports the **P-256 / ES256** algorithm (the only
//! algorithm required by WebAuthn Level 3). Attestation format `none` and
//! `packed` are accepted; `fido-u2f`, `tpm`, `android-key`, `android-safetynet`,
//! `apple`, and `apple-appattest` attestation formats are not validated
//! (attestation is treated as `none` - trust on first use, per the passkey
//! model). RP ID is derived from the request `Host`/`X-Sentin8-Hostname`.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::Signature;
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::handlers::AppState;
use crate::sessions::Session;

/// Challenge TTL for WebAuthn ceremonies (seconds).
const WEBAUTHN_CHALLENGE_TTL_SECS: i64 = 300;
/// Supported COSE algorithm: ES256 (ECDSA w/ P-256 + SHA-256).
/// The cose alg es256 constant.
pub const COSE_ALG_ES256: i64 = -7;

// ── Requests / Responses ───────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for enrollbegin.
pub struct EnrollBeginRequest {
    #[serde(default)]
    /// user identifier.
    pub user_id: Option<Uuid>,
    /// Authenticator attachment preference: "platform" | "cross-platform".
    #[serde(default)]
    /// The authenticator attachment.
    pub authenticator_attachment: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for enrollbegin.
pub struct EnrollBeginResponse {
    /// Base64url-encoded challenge.
    /// The challenge.
    pub challenge: String,
    /// rp identifier.
    pub rp_id: String,
    /// The rp name.
    pub rp_name: String,
    /// user identifier.
    pub user_id: String,
    /// The user name.
    pub user_name: String,
    /// The user display name.
    pub user_display_name: String,
    /// challenge identifier.
    pub challenge_id: Uuid,
    /// The pub key cred params.
    pub pub_key_cred_params: Vec<PublicKeyCredentialParam>,
    /// The timeout.
    pub timeout: u64,
    /// The attestation.
    pub attestation: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
/// The publickeycredentialparam type.
pub struct PublicKeyCredentialParam {
    /// Credential type (`public-key`).
    pub r#type: String,
    /// The alg.
    pub alg: i64,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for enrollfinish.
pub struct EnrollFinishRequest {
    /// challenge identifier.
    pub challenge_id: Uuid,
    /// Base64url-encoded credential id.
    /// credential identifier.
    pub credential_id: String,
    /// Base64url-encoded attestation object (CBOR-encoded).
    /// The attestation object.
    pub attestation_object: String,
    /// Base64url-encoded client data JSON.
    /// The client data JSON.
    pub client_data_json: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for enrollfinish.
pub struct EnrollFinishResponse {
    /// factor identifier.
    pub factor_id: Uuid,
    /// The status.
    pub status: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for verifybegin.
pub struct VerifyBeginRequest {
    /// Pending session token id returned by `POST /v1/sign-in` when MFA is
    /// required.
    /// pending token identifier.
    pub pending_token_id: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for verifybegin.
pub struct VerifyBeginResponse {
    /// The challenge.
    pub challenge: String,
    /// rp identifier.
    pub rp_id: String,
    /// challenge identifier.
    pub challenge_id: Uuid,
    /// The timeout.
    pub timeout: u64,
    /// The user verification.
    pub user_verification: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for verifyfinish.
pub struct VerifyFinishRequest {
    /// challenge identifier.
    pub challenge_id: Uuid,
    /// credential identifier.
    pub credential_id: String,
    /// Base64url-encoded authenticator data.
    /// The authenticator data.
    pub authenticator_data: String,
    /// Base64url-encoded client data JSON.
    /// The client data JSON.
    pub client_data_json: String,
    /// Base64url-encoded signature (DER-encoded ECDSA signature).
    /// The signature.
    pub signature: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for verifyfinish.
pub struct VerifyFinishResponse {
    /// The status.
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The session cookie.
    pub session_cookie: Option<String>,
}

// ── Handlers ───────────────────────────────────────────────────────────

/// `POST /v1/passkey/enroll/begin` - start passkey enrollment.
#[utoipa::path(
    post,
    path = "/v1/passkey/enroll/begin",
    request_body = EnrollBeginRequest,
    responses(
        (status = 200, description = "WebAuthn creation options for the enrollment ceremony", body = EnrollBeginResponse),
        (status = 401, description = "Not authenticated (bearer or session)"),
    ),
    security(),
    tag = "passkey",
)]
pub async fn enroll_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EnrollBeginRequest>,
) -> Result<Response, (StatusCode, String)> {
    let user_id =
        crate::mfa::user_requires_passkey_enroll_target(&state.pool, &headers, req.user_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let user = sqlx::query!(
        r#"SELECT email, first_name, last_name, env_id
           FROM users WHERE id = $1"#,
        user_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "user not found".into()))?;

    // SEC- - tenant context on the same connection (design ).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(user.env_id)
        .execute(&mut *conn)
        .await;

    let rp_id = derive_rp_id(&state, &headers);
    let challenge = random_bytes_32();
    let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge);

    let challenge_id = Uuid::new_v4();
    sqlx::query!(
        r#"INSERT INTO mfa_challenges
             (id, user_id, factor_id, challenge_kind, pending_token_id, expires_at)
           VALUES ($1, $2, $3, 'enroll', NULL, now() + ($4 || ' seconds')::interval)"#,
        challenge_id,
        user_id,
        // factor_id is NULL until the ceremony finishes; use a scout.
        Uuid::nil(),
        WEBAUTHN_CHALLENGE_TTL_SECS.to_string(),
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Store the challenge bytes for later comparison.
    sqlx::query!(
        r#"INSERT INTO webauthn_challenges (id, challenge, user_id)
           VALUES ($1, $2, $3)"#,
        challenge_id,
        &challenge,
        user_id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = conn.commit().await;

    let display_name = match (&user.first_name, &user.last_name) {
        (Some(f), Some(l)) => format!("{f} {l}"),
        _ => user.email.clone(),
    };

    Ok(Json(EnrollBeginResponse {
        challenge: challenge_b64,
        rp_id,
        rp_name: "Sentin8".into(),
        user_id: user_id.to_string(),
        user_name: user.email,
        user_display_name: display_name,
        challenge_id,
        pub_key_cred_params: vec![PublicKeyCredentialParam {
            r#type: "public-key".into(),
            alg: COSE_ALG_ES256,
        }],
        timeout: WEBAUTHN_CHALLENGE_TTL_SECS as u64 * 1000,
        attestation: "none".into(),
    })
    .into_response())
}

/// `POST /v1/passkey/enroll/finish` - validate attestation, store public key.
#[utoipa::path(
    post,
    path = "/v1/passkey/enroll/finish",
    request_body = EnrollFinishRequest,
    responses(
        (status = 200, description = "Passkey stored and factor activated", body = EnrollFinishResponse),
        (status = 400, description = "Invalid attestation or client data"),
        (status = 404, description = "Challenge not found"),
        (status = 409, description = "Challenge already consumed"),
        (status = 410, description = "Challenge expired"),
    ),
    security(),
    tag = "passkey",
)]
pub async fn enroll_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EnrollFinishRequest>,
) -> Result<Response, (StatusCode, String)> {
    // Fetch the challenge.
    let challenge_row = sqlx::query!(
        r#"SELECT challenge, user_id, expires_at, consumed_at
           FROM webauthn_challenges
           WHERE id = $1"#,
        req.challenge_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "challenge not found".into()))?;

    if challenge_row.consumed_at.is_some() {
        return Err((StatusCode::CONFLICT, "challenge already consumed".into()));
    }
    if challenge_row.expires_at < chrono::Utc::now() {
        return Err((StatusCode::GONE, "challenge expired".into()));
    }
    let user_id = challenge_row.user_id;
    let expected_challenge = &challenge_row.challenge;

    // Decode client data.
    let client_data = decode_client_data(&req.client_data_json)?;
    if client_data.r#type != "webauthn.create" {
        return Err((
            StatusCode::BAD_REQUEST,
            "clientDataJSON type must be webauthn.create".into(),
        ));
    }

    // Decode the attestation object (CBOR).
    let att_obj = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.attestation_object)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid attestationObject base64: {e}"),
            )
        })?;
    let (_auth_data_bytes, public_key_cose) =
        parse_attestation_object(&att_obj).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // Verify the challenge in clientDataJSON matches.
    let client_challenge = client_data.challenge.as_bytes();
    if client_challenge != expected_challenge {
        return Err((StatusCode::UNAUTHORIZED, "challenge mismatch".into()));
    }

    // SEC- - ceremony completeness: verify the client origin
    // against the allow-list and the rpIdHash against the expected RP ID.
    verify_origin(&state, &headers, &client_data.origin)?;
    let rp_id = derive_rp_id(&state, &headers);
    verify_rp_id_hash(&_auth_data_bytes, &rp_id)?;

    // Parse the credential public key (COSE / ES256) and convert to a
    // verifying key for storage. We store the SEC1 (X.962) encoded public
    // point so verification during sign-in is straightforward.
    let public_key_sec1 = cose_pubkey_to_sec1(&public_key_cose).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid COSE public key: {e}"),
        )
    })?;

    // RLS : the users row is FORCE-RLS - resolve the env via the
    // shared two-step lookup instead of a context-less SELECT.
    let user_env_id = crate::sessions::user_env(&state.pool, user_id)
        .await
        .map_err(|(_, e)| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // SEC- - tenant context on the same connection (design ).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(user_env_id)
        .execute(&mut *conn)
        .await;

    let factor_id = Uuid::new_v4();
    let credential_id_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.credential_id)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid credentialId: {e}"),
            )
        })?;

    sqlx::query!(
        r#"INSERT INTO mfa_factors
             (id, user_id, env_id, factor_kind, name,
              public_key, credential_id, status, is_default)
           VALUES ($1, $2, $3, 'webauthn', 'passkey', $4, $5, 'active', true)"#,
        factor_id,
        user_id,
        user_env_id,
        &public_key_sec1,
        &credential_id_bytes,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    sqlx::query!(
        r#"UPDATE users SET mfa_enabled = true, updated_at = now() WHERE id = $1"#,
        user_id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Consume both challenges.
    sqlx::query!(
        "DELETE FROM webauthn_challenges WHERE id = $1",
        req.challenge_id
    )
    .execute(&mut *conn)
    .await
    .ok();
    sqlx::query!(
        "UPDATE mfa_challenges SET consumed_at = now() WHERE id = $1",
        req.challenge_id
    )
    .execute(&mut *conn)
    .await
    .ok();

    crate::events::emit_event_tx(
        &mut conn,
        user_env_id,
        "sentin8:auth:passkey:enrolled",
        serde_json::json!({
            "user_id": user_id,
            "credential_id": &req.credential_id,
        }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = conn.commit().await;

    Ok(Json(EnrollFinishResponse {
        factor_id,
        status: "active".into(),
    })
    .into_response())
}

/// `POST /v1/passkey/verify/begin` - start passkey sign-in.
#[utoipa::path(
    post,
    path = "/v1/passkey/verify/begin",
    request_body = VerifyBeginRequest,
    responses(
        (status = 200, description = "WebAuthn assertion options for the sign-in ceremony", body = VerifyBeginResponse),
        (status = 404, description = "Pending session not found or no active passkey factor"),
    ),
    security(),
    tag = "passkey",
)]
pub async fn verify_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<VerifyBeginRequest>,
) -> Result<Response, (StatusCode, String)> {
    let pending = Session::find_by_token(&state.pool, &req.pending_token_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "pending session not found".into()))?;

    // Look up an active webauthn factor for the user.
    let factor = sqlx::query!(
        r#"SELECT id FROM mfa_factors
           WHERE user_id = $1 AND factor_kind = 'webauthn' AND status = 'active'
           LIMIT 1"#,
        pending.user_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "no active passkey factor".into()))?;

    let challenge = random_bytes_32();
    let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge);
    let challenge_id = Uuid::new_v4();

    sqlx::query!(
        r#"INSERT INTO mfa_challenges
             (id, user_id, factor_id, challenge_kind, pending_token_id, expires_at)
           VALUES ($1, $2, $3, 'verify', $4, now() + ($5 || ' seconds')::interval)"#,
        challenge_id,
        pending.user_id,
        factor.id,
        req.pending_token_id,
        WEBAUTHN_CHALLENGE_TTL_SECS.to_string(),
    )
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    sqlx::query!(
        r#"INSERT INTO webauthn_challenges (id, challenge, user_id)
           VALUES ($1, $2, $3)"#,
        challenge_id,
        &challenge,
        pending.user_id,
    )
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(VerifyBeginResponse {
        challenge: challenge_b64,
        rp_id: derive_rp_id(&state, &headers),
        challenge_id,
        timeout: WEBAUTHN_CHALLENGE_TTL_SECS as u64 * 1000,
        user_verification: "preferred".into(),
    })
    .into_response())
}

/// `POST /v1/passkey/verify/finish` - validate assertion, activate session.
#[utoipa::path(
    post,
    path = "/v1/passkey/verify/finish",
    request_body = VerifyFinishRequest,
    responses(
        (status = 200, description = "Assertion verified: the pending sign-in session is activated", body = VerifyFinishResponse),
        (status = 400, description = "Invalid assertion or client data"),
        (status = 401, description = "Signature verification failed"),
        (status = 404, description = "Challenge not found"),
        (status = 409, description = "Challenge already consumed"),
        (status = 410, description = "Challenge expired"),
    ),
    security(),
    tag = "passkey",
)]
pub async fn verify_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<VerifyFinishRequest>,
) -> Result<Response, (StatusCode, String)> {
    // Fetch the challenge bytes from the webauthn challenges table.
    let wa = sqlx::query!(
        r#"SELECT challenge, user_id, expires_at, consumed_at
           FROM webauthn_challenges WHERE id = $1"#,
        req.challenge_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "challenge not found".into()))?;

    if wa.consumed_at.is_some() {
        return Err((StatusCode::CONFLICT, "challenge already consumed".into()));
    }
    if wa.expires_at < chrono::Utc::now() {
        return Err((StatusCode::GONE, "challenge expired".into()));
    }

    // Fetch the MFA challenge (factor_id + pending_token_id).
    let mfa = sqlx::query!(
        r#"SELECT factor_id, pending_token_id FROM mfa_challenges WHERE id = $1"#,
        req.challenge_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "mfa challenge not found".into()))?;

    let factor = sqlx::query!(
        r#"SELECT public_key, credential_id FROM mfa_factors WHERE id = $1"#,
        mfa.factor_id,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Parse the verifying key.
    let public_key_sec1 = factor.public_key.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing public key".into(),
        )
    })?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_sec1).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("invalid stored public key: {e}"),
        )
    })?;

    // Decode client data.
    let client_data = decode_client_data(&req.client_data_json)?;
    if client_data.r#type != "webauthn.get" {
        return Err((
            StatusCode::BAD_REQUEST,
            "clientDataJSON type must be webauthn.get".into(),
        ));
    }
    if client_data.challenge.as_bytes() != wa.challenge.as_slice() {
        return Err((StatusCode::UNAUTHORIZED, "challenge mismatch".into()));
    }

    // SEC- - ceremony completeness: verify the client origin
    // against the allow-list and the rpIdHash against the expected RP ID.
    verify_origin(&state, &headers, &client_data.origin)?;
    let rp_id = derive_rp_id(&state, &headers);

    // Parse authenticator data (RP ID hash + flags + counter).
    let auth_data = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.authenticator_data)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid authenticatorData: {e}"),
            )
        })?;
    if auth_data.len() < 37 {
        return Err((
            StatusCode::BAD_REQUEST,
            "authenticatorData too short".into(),
        ));
    }
    verify_rp_id_hash(&auth_data, &rp_id)?;

    // Verify the signature over (authenticatorData || sha256(clientDataJSON)).
    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.signature)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid signature: {e}")))?;
    let signature = Signature::from_der(&signature_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid DER signature: {e}"),
        )
    })?;

    let mut message = auth_data.clone();
    let client_data_hash = sha256(&client_data.raw_bytes);
    message.extend_from_slice(&client_data_hash);
    verifying_key.verify(&message, &signature).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "signature verification failed".into(),
        )
    })?;

    // SEC- - sign counter clone detection. If the authenticator
    // reports a counter, it must strictly increase; a non-increasing
    // counter means the credential private key has been cloned (or the
    // assertion is replayed). The new counter is persisted for the next
    // assertion.
    let new_count = extract_sign_count(&auth_data)?;
    if new_count > 0 {
        let updated = sqlx::query!(
            r#"UPDATE mfa_factors SET counter = $1
               WHERE id = $2 AND (counter IS NULL OR counter < $1)"#,
            new_count as i64,
            mfa.factor_id,
        )
        .execute(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if updated.rows_affected() == 0 {
            tracing::warn!(
                factor_id = %mfa.factor_id,
                counter = new_count,
                "webauthn sign counter did not increase - possible cloned credential"
            );
            return Err((
                StatusCode::UNAUTHORIZED,
                "sign counter did not increase - credential may be cloned".into(),
            ));
        }
    }

    // Consume challenges.
    sqlx::query!(
        "DELETE FROM webauthn_challenges WHERE id = $1",
        req.challenge_id
    )
    .execute(&state.pool)
    .await
    .ok();
    sqlx::query!(
        "UPDATE mfa_challenges SET consumed_at = now() WHERE id = $1",
        req.challenge_id
    )
    .execute(&state.pool)
    .await
    .ok();

    // Activate the pending session.
    let pending_token_id = mfa.pending_token_id.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing pending_token_id".into(),
        )
    })?;
    let session = Session::find_by_token(&state.pool, &pending_token_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "pending session not found".into()))?;

    Ok(Json(VerifyFinishResponse {
        status: "active".into(),
        session_cookie: Some(session.cookie(&crate::sessions::cookie_domain_from_headers(
            &headers,
            &state.config.sentin8_domain,
        ))),
    })
    .into_response())
}

// ── Internal helpers ───────────────────────────────────────────────────

/// SEC- - allowed WebAuthn origins.
///
/// Derived from `SENTIN8_AUTH_ALLOWED_ORIGINS` (comma-separated) plus the
/// request's own hostname (the auth-ui is served from the auth host itself)
/// plus `https://auth.ops.sys.{domain}`. The browser's `clientData.origin`
/// must match one of these - otherwise a phishing page could relay a
/// ceremony for its own origin.
fn allowed_origins(state: &AppState, headers: &HeaderMap) -> Vec<String> {
    let mut origins = vec![format!(
        "https://auth.ops.sys.{}",
        state.config.sentin8_domain
    )];
    let rp_id = derive_rp_id(state, headers);
    origins.push(format!("https://{rp_id}"));
    for extra in std::env::var("SENTIN8_AUTH_ALLOWED_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        origins.push(extra.to_string());
    }
    origins
}

/// SEC- - verify `clientData.origin` against the allow-list.
fn verify_origin(
    state: &AppState,
    headers: &HeaderMap,
    origin: &str,
) -> Result<(), (StatusCode, String)> {
    if origin.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "clientDataJSON missing origin".into(),
        ));
    }
    if !allowed_origins(state, headers).iter().any(|o| o == origin) {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("origin '{origin}' is not an allowed WebAuthn origin"),
        ));
    }
    Ok(())
}

/// SEC- - verify the rpIdHash (authenticatorData bytes 0..32)
/// equals SHA-256 of the expected RP ID.
fn verify_rp_id_hash(auth_data: &[u8], rp_id: &str) -> Result<(), (StatusCode, String)> {
    if auth_data.len() < 37 {
        return Err((
            StatusCode::BAD_REQUEST,
            "authenticatorData too short".into(),
        ));
    }
    let expected = sha256(rp_id.as_bytes());
    if &auth_data[..32] != expected.as_slice() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "rpIdHash mismatch - credential was created for a different RP ID".into(),
        ));
    }
    Ok(())
}

/// SEC- - extract the sign counter (authenticatorData bytes 33..37).
fn extract_sign_count(auth_data: &[u8]) -> Result<u32, (StatusCode, String)> {
    if auth_data.len() < 37 {
        return Err((
            StatusCode::BAD_REQUEST,
            "authenticatorData too short".into(),
        ));
    }
    Ok(u32::from_be_bytes([
        auth_data[33],
        auth_data[34],
        auth_data[35],
        auth_data[36],
    ]))
}

/// Derive the RP ID from the request Host / X-Sentin8-Hostname header.
/// Falls back to the configured sentin8_domain.
fn derive_rp_id(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(h) = headers
        .get(sentin8::middleware::context::HEADER_HOSTNAME)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    {
        return h.to_string();
    }
    if let Some(h) = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        if !h.is_empty() {
            return h.to_string();
        }
    }
    state.config.sentin8_domain.clone()
}

fn random_bytes_32() -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

#[derive(Debug, Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    r#type: String,
    challenge: String,
    /// SEC- - the origin is now VERIFIED against the allow-list
    /// (previously parsed and ignored).
    origin: String,
    #[serde(default)]
    #[allow(dead_code)]
    cross_origin: bool,
}

struct ParsedClientData {
    r#type: String,
    challenge: String,
    /// SEC- - the origin is verified against the allow-list by
    /// the finish handlers.
    origin: String,
    raw_bytes: Vec<u8>,
}

fn decode_client_data(b64url: &str) -> Result<ParsedClientData, (StatusCode, String)> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64url)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid clientDataJSON base64: {e}"),
            )
        })?;
    let cd: ClientData = serde_json::from_slice(&raw).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid clientDataJSON: {e}"),
        )
    })?;
    Ok(ParsedClientData {
        r#type: cd.r#type,
        challenge: cd.challenge,
        origin: cd.origin,
        raw_bytes: raw,
    })
}

/// Parse a CBOR-encoded attestation object, returning (authData bytes, COSE public key map).
fn parse_attestation_object(att: &[u8]) -> Result<(Vec<u8>, ciborium::Value), String> {
    let value: ciborium::Value = ciborium::de::from_reader(att)
        .map_err(|e| format!("invalid attestationObject CBOR: {e}"))?;
    let map = match value {
        ciborium::Value::Map(m) => m,
        _ => return Err("attestationObject is not a CBOR map".into()),
    };

    let mut auth_data: Option<Vec<u8>> = None;
    for (k, v) in map.iter() {
        let key = match k {
            ciborium::Value::Text(s) => s.as_str(),
            _ => continue,
        };
        if key == "authData" {
            if let ciborium::Value::Bytes(b) = v {
                auth_data = Some(b.clone());
            }
        }
    }
    let auth_data = auth_data.ok_or_else(|| "missing authData".to_string())?;

    // authData layout: rpIdHash(32) | flags(1) | signCount(4) | [attestedCredentialData].
    // attestedCredentialData: aaguid(16) | credIdLen(2, BE) | credId(credIdLen) | COSE pub key.
    if auth_data.len() < 37 {
        return Err("authData too short".into());
    }
    let flags = auth_data[32];
    let has_attested = (flags & 0x40) != 0; // AT flag
    if !has_attested {
        return Err("authData missing attested credential data".into());
    }
    let mut idx = 37;
    idx += 16; // aaguid
    if auth_data.len() < idx + 2 {
        return Err("authData truncated at credId length".into());
    }
    let cred_id_len = ((auth_data[idx] as usize) << 8) | (auth_data[idx + 1] as usize);
    idx += 2 + cred_id_len;
    if auth_data.len() <= idx {
        return Err("authData missing COSE public key".into());
    }
    // The remainder is the COSE-encoded public key.
    let cose_bytes = &auth_data[idx..];
    let cose: ciborium::Value = ciborium::de::from_reader(cose_bytes)
        .map_err(|e| format!("invalid COSE public key CBOR: {e}"))?;

    Ok((auth_data, cose))
}

/// Read a ciborium integer value as `i64`. Returns None for non-integers.
fn ciborium_int(v: &ciborium::Value) -> Option<i64> {
    match v {
        ciborium::Value::Integer(i) => {
            // ciborium::value::Integer has try_into for i128 → i64.
            let i128_val: i128 = (*i).into();
            Some(i128_val as i64)
        }
        _ => None,
    }
}

/// Convert a COSE P-256 EC2 public key (map with kty=2, crv=1, x, y) to SEC1
/// uncompressed point encoding (0x04 || x || y).
fn cose_pubkey_to_sec1(cose: &ciborium::Value) -> Result<Vec<u8>, String> {
    let map = match cose {
        ciborium::Value::Map(m) => m,
        _ => return Err("COSE pub key is not a map".into()),
    };
    let mut kty: Option<i64> = None;
    let mut crv: Option<i64> = None;
    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;
    for (k, v) in map.iter() {
        let key = match ciborium_int(k) {
            Some(i) => i,
            None => continue,
        };
        match key {
            1 => kty = ciborium_int(v),
            -1 => crv = ciborium_int(v),
            -2 => {
                if let ciborium::Value::Bytes(b) = v {
                    x = Some(b.clone());
                }
            }
            -3 => {
                if let ciborium::Value::Bytes(b) = v {
                    y = Some(b.clone());
                }
            }
            _ => {}
        }
    }
    if kty != Some(2) {
        return Err("COSE kty must be 2 (EC2)".into());
    }
    if crv != Some(1) {
        return Err("COSE crv must be 1 (P-256)".into());
    }
    let x = x.ok_or_else(|| "missing COSE x".to_string())?;
    let y = y.ok_or_else(|| "missing COSE y".to_string())?;
    let mut sec1 = vec![0x04u8];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    Ok(sec1)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_unique() {
        let a = random_bytes_32();
        let b = random_bytes_32();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
    }

    #[test]
    fn sha256_known_vector() {
        let h = sha256(b"abc");
        assert_eq!(h.len(), 32);
        // First byte of SHA-256("abc") = 0xba
        assert_eq!(h[0], 0xba);
    }

    #[test]
    fn cose_p256_to_sec1_round_trip() {
        // Build a minimal COSE EC2 P-256 key with random x/y.
        let x = vec![0u8; 32];
        let y = vec![1u8; 32];
        let mut map: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
        map.push((
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer(2.into()),
        ));
        map.push((
            ciborium::Value::Integer((-1).into()),
            ciborium::Value::Integer(1.into()),
        ));
        map.push((
            ciborium::Value::Integer((-2).into()),
            ciborium::Value::Bytes(x.clone()),
        ));
        map.push((
            ciborium::Value::Integer((-3).into()),
            ciborium::Value::Bytes(y.clone()),
        ));
        let cose = ciborium::Value::Map(map);
        let sec1 = cose_pubkey_to_sec1(&cose).unwrap();
        assert_eq!(sec1.len(), 65);
        assert_eq!(sec1[0], 0x04);
        assert_eq!(&sec1[1..33], &x[..]);
        assert_eq!(&sec1[33..65], &y[..]);
    }

    #[test]
    fn cose_rejects_non_ec2() {
        let mut map: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
        map.push((
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer(3.into()),
        )); // kty=OKP
        let cose = ciborium::Value::Map(map);
        assert!(cose_pubkey_to_sec1(&cose).is_err());
    }

    #[test]
    fn ciborium_int_parses() {
        assert_eq!(ciborium_int(&ciborium::Value::Integer(2.into())), Some(2));
        assert_eq!(
            ciborium_int(&ciborium::Value::Integer((-7).into())),
            Some(-7)
        );
        assert_eq!(ciborium_int(&ciborium::Value::Text("x".into())), None);
    }
}
