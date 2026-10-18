// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Security-profile admin surface — the two-page UX:
//!
//! - **High-level page** (`/sentin8-auth/security`): select the Profile,
//! Extensions, and Overlay. Submitting this page is the ONLY way to
//! change the high-level selection, and it **resets the detail flags**
//! to the selected profile's defaults ( matrix, adjusted by the
//! chosen extensions/overlay).
//! - **Detail page** (`/sentin8-auth/security/detail`): edit the
//! individual `require_*` flags and token lifetime. Changing detail
//! flags never changes the high-level selection.
//!
//! Both write the env-scoped `security_profiles` row (the effective
//! profile is env → org → platform; the env row is authoritative —
//! design scope model).

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::admin::TargetEnvQuery;
use crate::handlers::AppState;
use crate::sentin8or_auth::require_sentin8or_access_with_env;

/// The high-level selection (form body of the security page).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for securityselection.
pub struct SecuritySelectionRequest {
    /// The profile.
    pub profile: String,
    /// Enabled protocol extensions ( extensions) — additive.
    #[serde(default)]
    /// The extensions.
    pub extensions: Vec<String>,
    /// Regulatory overlay ( overlays) — none | obie | cdr | brazil.
    #[serde(default)]
    /// The overlay.
    pub overlay: Option<String>,
}

/// The detail-flags write (form body of the detail page).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for securitydetail.
pub struct SecurityDetailRequest {
    /// The require par.
    pub require_par: Option<bool>,
    /// The require mtls.
    pub require_mtls: Option<bool>,
    /// The require JARM.
    pub require_jarm: Option<bool>,
    /// The require DPoP.
    pub require_dpop: Option<bool>,
    /// The require http signatures.
    pub require_http_signatures: Option<bool>,
    /// The require JWT introspection.
    pub require_jwt_introspection: Option<bool>,
    /// The require iss.
    pub require_iss: Option<bool>,
    /// Maximum token lifetime.
    pub max_token_lifetime: Option<i32>,
    /// The refresh rotation.
    pub refresh_rotation: Option<bool>,
}

/// The rendered high-level selection (page prefill / CLI verify shape).
#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for securityselection.
pub struct SecuritySelectionResponse {
    /// env identifier.
    pub env_id: Uuid,
    /// The profile.
    pub profile: String,
    /// The extensions.
    pub extensions: Vec<String>,
    /// The overlay.
    pub overlay: Option<String>,
    /// True when the env row exists (false → platform default inherited).
    /// The env row exists.
    pub env_row_exists: bool,
}

/// Read the env's current effective selection + detail flags.
/// Read current.
pub async fn read_current(
    pool: &sqlx::PgPool,
    env_id: Uuid,
) -> Result<SecuritySelectionResponse, (StatusCode, String)> {
    let row = sqlx::query(
        r#"SELECT scope, profile, require_par, require_mtls, require_jarm, require_dpop,
                  require_http_signatures, require_jwt_introspection, require_iss,
                  max_token_lifetime, refresh_rotation
             FROM auth.security_profiles
            WHERE env_id = $1"#,
    )
    .bind(env_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Detail defaults when the env row is absent: the platform row still
    // governs enforcement, so read it for display.
    let (env_row_exists, profile, flags) = match row {
        Some(r) => {
            use sqlx::Row as _;
            let profile: String = r.try_get("profile").unwrap_or_default();
            let flags = DetailFlags {
                require_par: r.try_get("require_par").unwrap_or(false),
                require_mtls: r.try_get("require_mtls").unwrap_or(false),
                require_jarm: r.try_get("require_jarm").unwrap_or(false),
                require_dpop: r.try_get("require_dpop").unwrap_or(false),
                require_http_signatures: r.try_get("require_http_signatures").unwrap_or(false),
                require_jwt_introspection: r.try_get("require_jwt_introspection").unwrap_or(false),
                require_iss: r.try_get("require_iss").unwrap_or(true),
                max_token_lifetime: r.try_get("max_token_lifetime").unwrap_or(900),
                refresh_rotation: r.try_get("refresh_rotation").unwrap_or(true),
            };
            (true, profile, flags)
        }
        None => {
            // No env row — show the platform default profile with its defaults.
            let platform_profile: String = sqlx::query_scalar(
                "SELECT profile FROM auth.security_profiles WHERE scope='platform' LIMIT 1",
            )
            .fetch_optional(pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .unwrap_or_else(|| "fapi_2".into());
            let d = crate::fapi::ProfileDefaults::for_profile(&platform_profile)
                .unwrap_or_else(|| crate::fapi::ProfileDefaults::for_profile("fapi_2").unwrap());
            (
                false,
                platform_profile,
                DetailFlags {
                    require_par: d.require_par,
                    require_mtls: d.require_mtls,
                    require_jarm: d.require_jarm,
                    require_dpop: d.require_dpop,
                    require_http_signatures: d.require_http_signatures,
                    require_jwt_introspection: d.require_jwt_introspection,
                    require_iss: d.require_iss,
                    max_token_lifetime: d.max_token_lifetime,
                    refresh_rotation: d.refresh_rotation,
                },
            )
        }
    };

    // Derive the extensions display from the detail flags (extensions are
    // additive flags — the high-level view just shows which are on).
    let mut extensions = Vec::new();
    if flags.require_http_signatures {
        extensions.push("http_signatures".to_string());
    }
    if flags.require_jwt_introspection {
        extensions.push("jwt_introspection".to_string());
    }

    // Overlay from the env-scoped overlay table.
    let overlay: Option<String> = sqlx::query_scalar(
        "SELECT overlay FROM auth.regulatory_overlays WHERE env_id = $1 AND enabled = true",
    )
    .bind(env_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(SecuritySelectionResponse {
        env_id,
        profile,
        extensions,
        overlay,
        env_row_exists,
    })
}

#[derive(Debug, Clone)]
/// The detailflags type.
pub struct DetailFlags {
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

/// Read the env row's detail flags (None when the env row is absent).
/// Simpler than `read_current` when only the flags are needed (RFW prefill).
/// Read detail flags.
pub async fn read_detail_flags(
    pool: &sqlx::PgPool,
    env_id: Uuid,
) -> Result<Option<DetailFlags>, (StatusCode, String)> {
    let row = sqlx::query(
        r#"SELECT require_par, require_mtls, require_jarm, require_dpop,
                  require_http_signatures, require_jwt_introspection, require_iss,
                  max_token_lifetime, refresh_rotation
             FROM auth.security_profiles WHERE env_id = $1"#,
    )
    .bind(env_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    use sqlx::Row as _;
    Ok(row.and_then(|r| {
        Some(DetailFlags {
            require_par: r.try_get("require_par").ok()?,
            require_mtls: r.try_get("require_mtls").ok()?,
            require_jarm: r.try_get("require_jarm").ok()?,
            require_dpop: r.try_get("require_dpop").ok()?,
            require_http_signatures: r.try_get("require_http_signatures").ok()?,
            require_jwt_introspection: r.try_get("require_jwt_introspection").ok()?,
            require_iss: r.try_get("require_iss").ok()?,
            max_token_lifetime: r.try_get("max_token_lifetime").ok()?,
            refresh_rotation: r.try_get("refresh_rotation").ok()?,
        })
    }))
}

/// `GET /v1/admin/security` — read the current high-level selection
/// (prefill for the security page + CLI verify).
#[utoipa::path(
    get,
    path = "/v1/admin/security",
    params(crate::admin::TargetEnvQuery),
    responses(
        (status = 200, description = "The env's security selection", body = SecuritySelectionResponse),
        (status = 403, description = "Caller lacks the auth admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
pub async fn get_security_selection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<SecuritySelectionResponse>, (StatusCode, String)> {
    let auth =
        require_sentin8or_access_with_env(&state, &headers, q.target_env_id.as_deref()).await?;
    let resp = read_current(&state.pool, auth.env_id).await?;
    Ok(Json(resp))
}

/// `POST /v1/admin/security` — the high-level submit. Selecting a new
/// profile / extensions / overlay **resets the detail flags** to the
/// profile's defaults (adjusted for the chosen extensions/overlay),
/// then upserts the env row. The overlay row is written alongside.
#[utoipa::path(
    post,
    path = "/v1/admin/security",
    params(crate::admin::TargetEnvQuery),
    request_body = SecuritySelectionRequest,
    responses(
        (status = 200, description = "Selection stored (detail flags reset to the profile defaults)", body = SecuritySelectionResponse),
        (status = 400, description = "Unknown profile or extension"),
        (status = 403, description = "Caller lacks the auth admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
pub async fn put_security_selection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(req): Json<SecuritySelectionRequest>,
) -> Result<Json<SecuritySelectionResponse>, (StatusCode, String)> {
    let auth =
        require_sentin8or_access_with_env(&state, &headers, q.target_env_id.as_deref()).await?;

    // Validate the profile name against the CHECK constraint values.
    let defaults = crate::fapi::ProfileDefaults::for_profile(&req.profile).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("unknown profile '{}'", req.profile),
        )
    })?;

    // Reset-on-change: the detail flags become the profile defaults,
    // adjusted for the selected extensions and overlay.
    let d = defaults
        .with_extensions(&req.extensions)
        .with_overlay(req.overlay.as_deref().unwrap_or("none"));

    // Resolve the env's org for the profile row.
    let org_id: Uuid = sqlx::query_scalar("SELECT org_id FROM sys.environments WHERE id = $1")
        .bind(auth.env_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "unknown env".into()))?;

    // Upsert the env-scoped profile row with the reset flags.
    sqlx::query(
        r#"INSERT INTO auth.security_profiles
               (scope, org_id, env_id, profile,
                require_par, require_mtls, require_jarm, require_dpop,
                require_http_signatures, require_jwt_introspection, require_iss,
                max_token_lifetime, refresh_rotation)
           VALUES ('env', $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
           ON CONFLICT (scope, org_id, env_id) DO UPDATE SET
               profile = EXCLUDED.profile,
               require_par = EXCLUDED.require_par,
               require_mtls = EXCLUDED.require_mtls,
               require_jarm = EXCLUDED.require_jarm,
               require_dpop = EXCLUDED.require_dpop,
               require_http_signatures = EXCLUDED.require_http_signatures,
               require_jwt_introspection = EXCLUDED.require_jwt_introspection,
               require_iss = EXCLUDED.require_iss,
               max_token_lifetime = EXCLUDED.max_token_lifetime,
               refresh_rotation = EXCLUDED.refresh_rotation,
               updated_at = now()"#,
    )
    .bind(org_id)
    .bind(auth.env_id)
    .bind(&req.profile)
    .bind(d.require_par)
    .bind(d.require_mtls)
    .bind(d.require_jarm)
    .bind(d.require_dpop)
    .bind(d.require_http_signatures)
    .bind(d.require_jwt_introspection)
    .bind(d.require_iss)
    .bind(d.max_token_lifetime)
    .bind(d.refresh_rotation)
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Write the overlay row (none → disable any existing overlay).
    match req.overlay.as_deref() {
        None | Some("none") | Some("") => {
            let _ = sqlx::query(
                "UPDATE auth.regulatory_overlays SET enabled = false WHERE env_id = $1",
            )
            .bind(auth.env_id)
            .execute(&state.pool)
            .await;
        }
        Some(kind) => {
            if crate::overlays::OverlayKind::from_str(kind).is_none() {
                return Err((StatusCode::BAD_REQUEST, format!("unknown overlay '{kind}'")));
            }
            // Directory coordinates are required for SSA regimes — the form
            // supplies them via the detail page for OBIE/Brazil. Defaults
            // here point at the well-known directory endpoints.
            let (jwks_uri, issuer) = match kind {
                "obie" => (
                    "https://directory.openbanking.org.uk/.well-known/organisations/jwks".to_string(),
                    "https://directory.openbanking.org.uk".to_string(),
                ),
                "brazil" => (
                    "https://auth.openfinancebrasil.org.br/realms/openfinance/protocol/openid-connect/certs".to_string(),
                    "https://auth.openfinancebrasil.org.br/realms/openfinance".to_string(),
                ),
                _ => (String::new(), String::new()),
            };
            sqlx::query(
                r#"INSERT INTO auth.regulatory_overlays
                       (env_id, overlay, directory_jwks_uri, directory_issuer, enabled)
                   VALUES ($1, $2, $3, $4, true)
                   ON CONFLICT (env_id) DO UPDATE SET
                       overlay = EXCLUDED.overlay,
                       directory_jwks_uri = EXCLUDED.directory_jwks_uri,
                       directory_issuer = EXCLUDED.directory_issuer,
                       enabled = true,
                       updated_at = now()"#,
            )
            .bind(auth.env_id)
            .bind(kind)
            .bind(jwks_uri)
            .bind(issuer)
            .execute(&state.pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }

    crate::events::emit_event(
        &state.pool,
        auth.env_id,
        "sentin8:auth:securityprofile:updated",
        serde_json::json!({ "scope": "env", "profile": req.profile, "overlay": req.overlay }),
    )
    .await;

    let resp = read_current(&state.pool, auth.env_id).await?;
    Ok(Json(resp))
}

/// `POST /v1/admin/security/detail` — the detail-page submit: write the
/// individual `require_*` flags onto the env row **without** touching the
/// high-level selection. Only the provided fields change (partial update).
#[utoipa::path(
    post,
    path = "/v1/admin/security/detail",
    params(crate::admin::TargetEnvQuery),
    request_body = SecurityDetailRequest,
    responses(
        (status = 200, description = "Detail flags stored (partial update)", body = SecuritySelectionResponse),
        (status = 403, description = "Caller lacks the auth admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
pub async fn put_security_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(req): Json<SecurityDetailRequest>,
) -> Result<Json<SecuritySelectionResponse>, (StatusCode, String)> {
    let auth =
        require_sentin8or_access_with_env(&state, &headers, q.target_env_id.as_deref()).await?;

    let org_id: Uuid = sqlx::query_scalar("SELECT org_id FROM sys.environments WHERE id = $1")
        .bind(auth.env_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "unknown env".into()))?;

    // Ensure the env row exists (seed from the current defaults if absent)
    // so the partial update has a row to land on.
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth.security_profiles WHERE env_id = $1)")
            .bind(auth.env_id)
            .fetch_one(&state.pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if !exists {
        let current = read_current(&state.pool, auth.env_id).await?;
        let d = crate::fapi::ProfileDefaults::for_profile(&current.profile).ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "current profile unknown".into(),
            )
        })?;
        sqlx::query(
            r#"INSERT INTO auth.security_profiles
                   (scope, org_id, env_id, profile, require_par, require_mtls, require_jarm,
                    require_dpop, require_http_signatures, require_jwt_introspection, require_iss,
                    max_token_lifetime, refresh_rotation)
               VALUES ('env', $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
               ON CONFLICT (scope, org_id, env_id) DO NOTHING"#,
        )
        .bind(org_id)
        .bind(auth.env_id)
        .bind(&current.profile)
        .bind(d.require_par)
        .bind(d.require_mtls)
        .bind(d.require_jarm)
        .bind(d.require_dpop)
        .bind(d.require_http_signatures)
        .bind(d.require_jwt_introspection)
        .bind(d.require_iss)
        .bind(d.max_token_lifetime)
        .bind(d.refresh_rotation)
        .execute(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    // Partial update of only the provided flags — the high-level selection
    // (profile name) is never modified here.
    sqlx::query(
        r#"UPDATE auth.security_profiles SET
               require_par = COALESCE($1, require_par),
               require_mtls = COALESCE($2, require_mtls),
               require_jarm = COALESCE($3, require_jarm),
               require_dpop = COALESCE($4, require_dpop),
               require_http_signatures = COALESCE($5, require_http_signatures),
               require_jwt_introspection = COALESCE($6, require_jwt_introspection),
               require_iss = COALESCE($7, require_iss),
               max_token_lifetime = COALESCE($8, max_token_lifetime),
               refresh_rotation = COALESCE($9, refresh_rotation),
               updated_at = now()
             WHERE env_id = $10"#,
    )
    .bind(req.require_par)
    .bind(req.require_mtls)
    .bind(req.require_jarm)
    .bind(req.require_dpop)
    .bind(req.require_http_signatures)
    .bind(req.require_jwt_introspection)
    .bind(req.require_iss)
    .bind(req.max_token_lifetime)
    .bind(req.refresh_rotation)
    .bind(auth.env_id)
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    crate::events::emit_event(
        &state.pool,
        auth.env_id,
        "sentin8:auth:securityprofile:updated",
        serde_json::json!({ "scope": "env", "detail_flags": true }),
    )
    .await;

    let resp = read_current(&state.pool, auth.env_id).await?;
    Ok(Json(resp))
}
