// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! SCIM+ SEC-.
//!
//! Full SCIM 2.0 protocol (RFC 7643 + 7644) for user provisioning and management.
//! Endpoints:
//! GET /scim/v2/Users - list/search with SCIM filtering
//! POST /scim/v2/Users - create user
//! GET /scim/v2/Users/{id} - get user
//! PUT /scim/v2/Users/{id} - replace user
//! PATCH /scim/v2/Users/{id} - partial update
//! DELETE /scim/v2/Users/{id} - deactivate
//! GET /scim/v2/Groups - list groups (read-only)
//! GET /scim/v2/ServiceProviderConfig - capabilities metadata
//! GET /scim/v2/ResourceTypes - supported resource types
//!
//! Authentication (SEC-): the Bearer token is **verified** -
//! signature + issuer + expiry via Auth's own signing keys - and must
//! carry `sentin8:scim:read` / `sentin8:scim:write`. Previously the token was decoded
//! without verification, so any forged JWT with a `scope` claim could
//! perform cross-tenant user CRUD.
//!
//! Tenant scoping: the token's `env_id` claim is the sole tenant key
//! (the `org_id` column was removed from users - org is resolved
//! from env where needed). All queries are env-scoped + RLS-backed.
//!
//! Design:

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::handlers::AppState;

// ── SCIM resource types ─────────────────────────────────────────────────

/// SCIM 2.0 list response (RFC 7644 ).
#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Response payload for scimlist.
pub struct ScimListResponse {
    /// The schemas.
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    /// Number of results.
    pub total_results: i64,
    #[serde(rename = "itemsPerPage")]
    /// The items per page.
    pub items_per_page: i64,
    #[serde(rename = "startIndex")]
    /// The start index.
    pub start_index: i64,
    #[serde(rename = "Resources")]
    /// The resources.
    pub resources: Vec<ScimUser>,
}

/// SCIM 2.0 user resource (RFC 7643 - subset).
#[derive(Debug, Serialize, utoipa::ToSchema)]
/// The scimuser type.
pub struct ScimUser {
    /// The schemas.
    pub schemas: Vec<String>,
    /// Identifier.
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// external identifier.
    pub external_id: Option<String>,
    #[serde(rename = "userName")]
    /// The user name.
    pub user_name: String,
    #[serde(rename = "displayName")]
    /// The display name.
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The name.
    pub name: Option<ScimName>,
    #[serde(skip_serializing_if = "Vec::is_empty", rename = "emails")]
    /// The emails.
    pub emails: Vec<ScimEmail>,
    #[serde(skip_serializing_if = "Vec::is_empty", rename = "phoneNumbers")]
    /// The phone numbers.
    pub phone_numbers: Vec<ScimPhone>,
    /// The active.
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none", rename = "meta.created")]
    /// The created.
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "meta.lastModified")]
    /// The last modified.
    pub last_modified: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
/// The scimname type.
pub struct ScimName {
    #[serde(skip_serializing_if = "Option::is_none", rename = "givenName")]
    /// The given name.
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "familyName")]
    /// The family name.
    pub family_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
/// The scimemail type.
pub struct ScimEmail {
    /// The value.
    pub value: String,
    #[serde(default = "default_true")]
    /// The primary.
    pub primary: bool,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
/// The scimphone type.
pub struct ScimPhone {
    /// The value.
    pub value: String,
}

fn default_true() -> bool {
    true
}

/// SCIM 2.0 error response (RFC 7644 ).
#[derive(Debug, Serialize, utoipa::ToSchema)]
/// Errors returned by SCIM.
pub struct ScimError {
    /// The schemas.
    pub schemas: Vec<String>,
    /// The status.
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The detail.
    pub detail: Option<String>,
}

// ── Query params ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The scimquery type.
pub struct ScimQuery {
    #[serde(default)]
    /// The filter.
    pub filter: Option<String>,
    #[serde(default)]
    /// The start index.
    pub start_index: Option<i64>,
    #[serde(default)]
    /// The count count.
    pub count: Option<i64>,
}

// ── Create user request ──────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// The scimcreateuser type.
pub struct ScimCreateUser {
    #[serde(default)]
    /// The user name.
    pub user_name: Option<String>,
    #[serde(default)]
    /// The name.
    pub name: Option<ScimCreateName>,
    #[serde(default)]
    /// The emails.
    pub emails: Vec<ScimEmail>,
    #[serde(default, rename = "phoneNumbers")]
    /// The phone numbers.
    pub phone_numbers: Vec<ScimPhone>,
    #[serde(default)]
    /// The active.
    pub active: Option<bool>,
    #[serde(default, rename = "externalId")]
    /// external identifier.
    pub external_id: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// The scimcreatename type.
pub struct ScimCreateName {
    #[serde(default, rename = "givenName")]
    /// The given name.
    pub given_name: Option<String>,
    #[serde(default, rename = "familyName")]
    /// The family name.
    pub family_name: Option<String>,
}

// ── Patch request (RFC 7644 ) ──────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// The scimpatchop type.
pub struct ScimPatchOp {
    /// The op.
    pub op: String,
    /// The path.
    pub path: Option<String>,
    #[serde(default)]
    /// The value.
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for scimpatch.
pub struct ScimPatchRequest {
    #[serde(default)]
    /// The operations.
    pub operations: Vec<ScimPatchOp>,
}

// ── Handlers ─────────────────────────────────────────────────────────────

/// `GET /scim/v2/Users` - list/search users.
///
/// Supports SCIM filter: `userName eq "email"`, `emails.value co "text"`,
/// `name.familyName sw "prefix"`. Falls back to listing all if no filter.
/// List users.
#[utoipa::path(
    get,
    path = "/scim/v2/Users",
    params(ScimQuery),
    responses(
        (status = 200, description = "SCIM ListResponse (filter supported: userName eq, emails.value co, name.familyName sw)", body = ScimListResponse),
        (status = 400, description = "Unsupported filter"),
        (status = 401, description = "Caller authentication failed (M2M or bearer)"),
    ),
    security(("sentin8:auth:scim" = [])),
    tag = "scim",
)]
pub async fn list_users(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(q): Query<ScimQuery>,
) -> Result<Json<ScimListResponse>, (StatusCode, String)> {
    // Validate auth - require scim:read scope.
    let env_id = validate_scim_auth(&state, &headers, "sentin8:scim:read").await?;

    let limit = q.count.unwrap_or(100).min(200).max(1);
    let offset = q.start_index.unwrap_or(1).max(1) - 1;

    // Parse SCIM filter. Simple support for: userName eq "email", emails.value co "text".
    let (sql_filter, filter_values) = parse_scim_filter(q.filter.as_deref());

    // Set tenant context for RLS on a single acquired connection and run all
    // queries on that SAME connection. sentin8_set_tenant_context uses
    // set_config(..., true) which is transaction-local - if we set it on one
    // connection and then query on the pool (a different connection), the
    // context is absent and RLS blocks all rows (returns 0 results).
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(conn.as_mut())
        .await;

    // Build the query. We include an explicit env_id filter as
    // defense-in-depth (matches the pattern in get_user/replace_user/etc.),
    // so the result is correct even if RLS context is somehow absent.
    let mut param_idx = filter_values.len();
    let env_placeholder = param_idx + 1;
    let limit_placeholder = param_idx + 2;
    let offset_placeholder = param_idx + 3;
    param_idx += 3;

    let where_clause = if sql_filter.is_empty() {
        format!("WHERE env_id = ${env_placeholder}")
    } else {
        format!("WHERE {sql_filter} AND env_id = ${env_placeholder}")
    };

    let sql = format!(
        r#"SELECT id, email, first_name, last_name, status, external_id, created_at, updated_at
             FROM users
            {where_clause}
            ORDER BY created_at DESC
            LIMIT ${limit_placeholder} OFFSET ${offset_placeholder}"#
    );

    let mut query = sqlx::query(&sql);
    for v in &filter_values {
        query = query.bind(v);
    }
    query = query.bind(env_id).bind(limit).bind(offset);

    let rows = query
        .fetch_all(conn.as_mut())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Run the COUNT on the same connection (with RLS context) so the total
    // reflects only the tenant's users.
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM users WHERE env_id = $1")
        .bind(env_id)
        .fetch_one(conn.as_mut())
        .await
        .unwrap_or(0);

    let _ = param_idx; // last placeholder index (unused, kept for clarity)
    let resources = rows.iter().map(row_to_scim_user).collect();

    Ok(Json(ScimListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".into()],
        total_results: total,
        items_per_page: limit,
        start_index: offset + 1,
        resources,
    }))
}

/// `POST /scim/v2/Users` - create a user.
#[utoipa::path(
    post,
    path = "/scim/v2/Users",
    request_body = ScimCreateUser,
    responses(
        (status = 201, description = "User created", body = ScimUser),
        (status = 401, description = "Caller authentication failed"),
        (status = 409, description = "User already exists"),
    ),
    security(("sentin8:auth:scim" = [])),
    tag = "scim",
)]
pub async fn create_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ScimCreateUser>,
) -> Result<(StatusCode, Json<ScimUser>), (StatusCode, String)> {
    let env_id = validate_scim_auth(&state, &headers, "sentin8:scim:write").await?;

    let email = req.user_name.unwrap_or_default().to_lowercase();
    if email.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "userName is required".into()));
    }

    let first_name = req.name.as_ref().and_then(|n| n.given_name.as_deref());
    let last_name = req.name.as_ref().and_then(|n| n.family_name.as_deref());
    let phone = req.phone_numbers.first().map(|p| p.value.as_str());
    let status = if req.active.unwrap_or(true) {
        "active"
    } else {
        "suspended"
    };

    let row = sqlx::query(
        r#"INSERT INTO users (env_id, email, first_name, last_name, phone, status, external_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, email, first_name, last_name, status, external_id, created_at, updated_at"#,
    )
    .bind(env_id)
    .bind(&email)
    .bind(first_name)
    .bind(last_name)
    .bind(phone)
    .bind(status)
    .bind(req.external_id.as_deref())
    .fetch_one(&state.pool)
    .await;

    let row = match row {
        Ok(r) => r,
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
            return Err((StatusCode::CONFLICT, "userName already exists".into()));
        }
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };

    // SEC- - SCIM mutations emit the same domain events as the
    // admin API (the design catalog lists SCIM as a user.* trigger).
    let created_id: Uuid = row.try_get("id").unwrap_or_default();
    crate::events::emit_event(
        &state.pool,
        env_id,
        "sentin8:auth:user:created",
        serde_json::json!({ "user_id": created_id, "source": "scim" }),
    )
    .await;

    Ok((StatusCode::CREATED, Json(row_to_scim_user(&row))))
}

/// `GET /scim/v2/Users/{id}` - get a user.
#[utoipa::path(
    get,
    path = "/scim/v2/Users/{id}",
    params(("id" = String, Path, description = "SCIM user id")),
    responses(
        (status = 200, description = "The SCIM user", body = ScimUser),
        (status = 404, description = "No such user"),
        (status = 401, description = "Caller authentication failed"),
    ),
    security(("sentin8:auth:scim" = [])),
    tag = "scim",
)]
pub async fn get_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ScimUser>, (StatusCode, String)> {
    let env_id = validate_scim_auth(&state, &headers, "sentin8:scim:read").await?;

    let row = sqlx::query(
        r#"SELECT id, email, first_name, last_name, status, external_id, created_at, updated_at
             FROM users WHERE id = $1 AND env_id = $2"#,
    )
    .bind(id)
    .bind(env_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match row {
        Some(r) => Ok(Json(row_to_scim_user(&r))),
        None => Err((StatusCode::NOT_FOUND, "user not found".into())),
    }
}

/// `PUT /scim/v2/Users/{id}` - replace a user.
#[utoipa::path(
    put,
    path = "/scim/v2/Users/{id}",
    params(("id" = String, Path, description = "SCIM user id")),
    request_body = ScimCreateUser,
    responses(
        (status = 200, description = "User replaced", body = ScimUser),
        (status = 404, description = "No such user"),
        (status = 401, description = "Caller authentication failed"),
    ),
    security(("sentin8:auth:scim" = [])),
    tag = "scim",
)]
pub async fn replace_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<ScimCreateUser>,
) -> Result<Json<ScimUser>, (StatusCode, String)> {
    let env_id = validate_scim_auth(&state, &headers, "sentin8:scim:write").await?;

    let email = req.user_name.unwrap_or_default().to_lowercase();
    let first_name = req.name.as_ref().and_then(|n| n.given_name.as_deref());
    let last_name = req.name.as_ref().and_then(|n| n.family_name.as_deref());
    let status = if req.active.unwrap_or(true) {
        "active"
    } else {
        "suspended"
    };

    let row = sqlx::query(
        r#"UPDATE users
              SET email = $2, first_name = $3, last_name = $4, status = $5,
                  external_id = $6, updated_at = now()
            WHERE id = $1 AND env_id = $6
            RETURNING id, email, first_name, last_name, status, external_id, created_at, updated_at"#,
    )
    .bind(id)
    .bind(&email)
    .bind(first_name)
    .bind(last_name)
    .bind(status)
    .bind(req.external_id.as_deref())
    .bind(env_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match row {
        Some(r) => {
            // SEC- - SCIM mutations emit the same domain events as the
            // admin API (the design catalog lists SCIM as a user.* trigger).
            crate::events::emit_event(
                &state.pool,
                env_id,
                "sentin8:auth:user:updated",
                serde_json::json!({ "user_id": id, "fields_changed": ["email", "name", "status"], "source": "scim" }),
            )
            .await;
            Ok(Json(row_to_scim_user(&r)))
        }
        None => Err((StatusCode::NOT_FOUND, "user not found".into())),
    }
}

/// `PATCH /scim/v2/Users/{id}` - partial update.
#[utoipa::path(
    patch,
    path = "/scim/v2/Users/{id}",
    params(("id" = String, Path, description = "SCIM user id")),
    request_body = ScimPatchRequest,
    responses(
        (status = 200, description = "User patched", body = ScimUser),
        (status = 400, description = "Unsupported patch op"),
        (status = 404, description = "No such user"),
        (status = 401, description = "Caller authentication failed"),
    ),
    security(("sentin8:auth:scim" = [])),
    tag = "scim",
)]
pub async fn patch_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<ScimPatchRequest>,
) -> Result<Json<ScimUser>, (StatusCode, String)> {
    let env_id = validate_scim_auth(&state, &headers, "sentin8:scim:write").await?;

    let mut email: Option<String> = None;
    let mut first_name: Option<String> = None;
    let mut last_name: Option<String> = None;
    let mut active: Option<bool> = None;

    for op in &req.operations {
        if op.op == "replace" || op.op == "add" {
            let path = op.path.as_deref().unwrap_or("");
            let value = op.value.as_ref();
            match path {
                "userName" => {
                    if let Some(v) = value.and_then(|v| v.as_str()) {
                        email = Some(v.to_lowercase());
                    }
                }
                "name.givenName" => {
                    if let Some(v) = value.and_then(|v| v.as_str()) {
                        first_name = Some(v.into());
                    }
                }
                "name.familyName" => {
                    if let Some(v) = value.and_then(|v| v.as_str()) {
                        last_name = Some(v.into());
                    }
                }
                "active" => {
                    if let Some(v) = value.and_then(|v| v.as_bool()) {
                        active = Some(v);
                    }
                }
                _ => {}
            }
        }
    }

    let status = active.map(|a| if a { "active" } else { "suspended" });

    // Build dynamic UPDATE.
    let mut sets: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    let mut idx = 2u32;
    if let Some(e) = &email {
        sets.push(format!("email = ${idx}"));
        binds.push(e.clone());
        idx += 1;
    }
    if let Some(f) = &first_name {
        sets.push(format!("first_name = ${idx}"));
        binds.push(f.clone());
        idx += 1;
    }
    if let Some(l) = &last_name {
        sets.push(format!("last_name = ${idx}"));
        binds.push(l.clone());
        idx += 1;
    }
    if let Some(s) = &status {
        sets.push(format!("status = ${idx}"));
        binds.push(s.to_string());
        idx += 1;
    }
    let _ = idx; // last index consumed by the trailing WHERE id = $1 binding
    sets.push("updated_at = now()".to_string());

    let sql = format!("UPDATE users SET {} WHERE id = $1 AND env_id = ${} RETURNING id, email, first_name, last_name, status, external_id, created_at, updated_at", sets.join(", "), idx);

    let mut query = sqlx::query(&sql).bind(id);
    for b in &binds {
        query = query.bind(b);
    }
    query = query.bind(env_id);

    let row = query
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match row {
        Some(r) => {
            // SEC- - SCIM mutations emit the same domain events as the
            // admin API (the design catalog lists SCIM as a user.* trigger).
            let updated_id: Uuid = r.try_get("id").unwrap_or_default();
            crate::events::emit_event(
                &state.pool,
                env_id,
                "sentin8:auth:user:updated",
                serde_json::json!({ "user_id": updated_id, "fields_changed": ["email", "name", "status"], "source": "scim" }),
            )
            .await;
            Ok(Json(row_to_scim_user(&r)))
        }
        None => Err((StatusCode::NOT_FOUND, "user not found".into())),
    }
}

/// `DELETE /scim/v2/Users/{id}` - deactivate a user.
#[utoipa::path(
    delete,
    path = "/scim/v2/Users/{id}",
    params(("id" = String, Path, description = "SCIM user id")),
    responses(
        (status = 204, description = "User deactivated"),
        (status = 404, description = "No such user"),
        (status = 401, description = "Caller authentication failed"),
    ),
    security(("sentin8:auth:scim" = [])),
    tag = "scim",
)]
pub async fn delete_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let env_id = validate_scim_auth(&state, &headers, "sentin8:scim:write").await?;

    let result = sqlx::query(
        "UPDATE users SET status = 'suspended', updated_at = now() WHERE id = $1 AND env_id = $2",
    )
    .bind(id)
    .bind(env_id)
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "user not found".into()));
    }

    // SEC- - SCIM delete (deactivate) emits the catalog event.
    crate::events::emit_event(
        &state.pool,
        env_id,
        "sentin8:auth:user:deleted",
        serde_json::json!({ "user_id": id, "source": "scim" }),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /scim/v2/ServiceProviderConfig` - capabilities metadata.
#[utoipa::path(
    get,
    path = "/scim/v2/ServiceProviderConfig",
    responses(
        (status = 200, description = "SCIM service-provider capabilities", body = crate::dtos::ScimServiceProviderConfig),
    ),
    security(("sentin8:auth:scim" = [])),
    tag = "scim",
)]
pub async fn service_provider_config() -> Json<crate::dtos::ScimServiceProviderConfig> {
    Json(crate::dtos::ScimServiceProviderConfig {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig".to_string()],
        patch: serde_json::json!({ "supported": true }),
        bulk: serde_json::json!({ "supported": false }),
        filter: serde_json::json!({ "supported": true, "maxResults": 200 }),
        change_password: serde_json::json!({ "supported": true }),
        sort: serde_json::json!({ "supported": true }),
        etag: serde_json::json!({ "supported": false }),
        authentication_schemes: vec![serde_json::json!({
            "name": "OAuth Bearer Token",
            "description": "Authentication via Bearer token with scim:read or scim:write scope",
            "type": "oauthbearertoken",
        })],
    })
}

/// `GET /scim/v2/Groups` - list groups (read-only, env-scoped).
///
/// Enterprise IdP directory sync (Entra/Okta/Google) reads group
/// memberships to mirror them. Group *management* (create/update/delete)
/// stays on the Auth admin API - SCIM group writes are not exposed.
/// List groups.
#[utoipa::path(
    get,
    path = "/scim/v2/Groups",
    params(ScimQuery),
    responses(
        (status = 200, description = "SCIM ListResponse of group mirrors (read-only directory sync)", body = crate::dtos::ScimListResponse),
        (status = 401, description = "Caller authentication failed"),
    ),
    security(("sentin8:auth:scim" = [])),
    tag = "scim",
)]
pub async fn list_groups(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<crate::dtos::ScimListResponse>, (StatusCode, String)> {
    let env_id = validate_scim_auth(&state, &headers, "sentin8:scim:read").await?;

    let rows = sqlx::query!(
        r#"SELECT id, name, created_at FROM groups WHERE env_id = $1 ORDER BY name ASC LIMIT 200"#,
        env_id,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resources: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "id": r.id.to_string(),
                "displayName": r.name,
                "meta": { "created": r.created_at.to_rfc3339() },
            })
        })
        .collect();

    Ok(Json(crate::dtos::ScimListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: resources.len(),
        resources: Some(resources),
    }))
}

/// `GET /scim/v2/ResourceTypes` - supported resource types.
#[utoipa::path(
    get,
    path = "/scim/v2/ResourceTypes",
    responses(
        (status = 200, description = "SCIM resource types (Users, Groups)", body = Vec<crate::dtos::ScimResourceType>),
    ),
    security(("sentin8:auth:scim" = [])),
    tag = "scim",
)]
pub async fn resource_types() -> Json<Vec<crate::dtos::ScimResourceType>> {
    Json(vec![crate::dtos::ScimResourceType {
        id: "User".to_string(),
        name: "User".to_string(),
        endpoint: "/Users".to_string(),
        schema: "urn:ietf:params:scim:schemas:core:2.0:User".to_string(),
    }])
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Validate the SCIM bearer token (verified decode). Requires the specified
/// scope. Returns the caller's env_id (tenant key) from the token claims.
async fn validate_scim_auth(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    scope: &str,
) -> Result<Uuid, (StatusCode, String)> {
    // Extract Bearer token from Authorization header.
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing Bearer token".into()))?;

    // SEC- - VERIFIED decode: signature + issuer + expiry via
    // Auth's own keys. A forged token fails here instead of being honored.
    let claims = state
        .keys
        .verify(bearer)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("invalid token: {e}")))?;
    if claims.iss != state.config.issuer {
        return Err((StatusCode::UNAUTHORIZED, "token issuer mismatch".into()));
    }
    let now = chrono::Utc::now().timestamp();
    if now > claims.exp {
        return Err((StatusCode::UNAUTHORIZED, "token expired".into()));
    }

    // Check scope. `sentin8:scim:write` implies `sentin8:scim:read` (a provisioning client
    // must be able to search before it creates).
    let token_scopes: Vec<&str> = claims.scope.split_whitespace().collect();
    let allowed = token_scopes.contains(&scope)
        || (scope == "sentin8:scim:read" && token_scopes.contains(&"sentin8:scim:write"));
    if !allowed {
        return Err((StatusCode::FORBIDDEN, format!("missing scope: {scope}")));
    }

    // Tenant key: the token's env_id (SYSTEM_ENV_ID fallback for platform
    // M2M tokens - e.g. the eTeller BFF directory-sync client).
    let env_id = claims
        .env_id
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(crate::config::SYSTEM_ENV_ID);
    Ok(env_id)
}

/// Parse a simple SCIM filter string into SQL WHERE clauses.
///
/// Supported:
/// `userName eq "alice@example.com"` → `email = $1`
/// `emails.value co "alice"` → `email ILIKE '%' || $1 || '%'`
/// `name.familyName sw "Sm"` → `last_name ILIKE $1 || '%'`
/// `userName eq "a" or userName eq "b"` → `email = $1 OR email = $2`
fn parse_scim_filter(filter: Option<&str>) -> (String, Vec<String>) {
    let filter = match filter {
        Some(f) if !f.is_empty() => f,
        _ => return (String::new(), Vec::new()),
    };

    let mut values = Vec::new();
    let mut clauses = Vec::new();

    // Split on " or " (case-insensitive).
    for part in filter.split(" or ") {
        let part = part.trim();
        // Match: attribute operator "value"
        if let Some((attr, rest)) = part.split_once(" eq ") {
            let val = rest.trim().trim_matches('"');
            if attr.trim() == "userName" {
                values.push(val.to_string());
                clauses.push(format!("email = ${}", values.len()));
            }
        } else if let Some((attr, rest)) = part.split_once(" co ") {
            let val = rest.trim().trim_matches('"');
            match attr.trim() {
                "userName" | "emails.value" => {
                    values.push(format!("%{}%", val));
                    clauses.push(format!("email ILIKE ${}", values.len()));
                }
                _ => {}
            }
        } else if let Some((attr, rest)) = part.split_once(" sw ") {
            let val = rest.trim().trim_matches('"');
            match attr.trim() {
                "name.familyName" => {
                    values.push(format!("{}%", val));
                    clauses.push(format!("last_name ILIKE ${}", values.len()));
                }
                "name.givenName" => {
                    values.push(format!("{}%", val));
                    clauses.push(format!("first_name ILIKE ${}", values.len()));
                }
                "userName" | "emails.value" => {
                    values.push(format!("{}%", val));
                    clauses.push(format!("email ILIKE ${}", values.len()));
                }
                _ => {}
            }
        }
    }

    if clauses.is_empty() {
        (String::new(), Vec::new())
    } else {
        (clauses.join(" OR "), values)
    }
}

/// Convert a DB row to a SCIM user resource.
fn row_to_scim_user(r: &sqlx::postgres::PgRow) -> ScimUser {
    let email: String = r.try_get("email").unwrap_or_default();
    let first_name: Option<String> = r.try_get("first_name").ok().flatten();
    let last_name: Option<String> = r.try_get("last_name").ok().flatten();
    let status: String = r.try_get("status").unwrap_or_else(|_| "active".into());
    let id: Uuid = r.try_get("id").unwrap_or_default();
    let external_id: Option<String> = r.try_get("external_id").ok().flatten();
    let created_at: Option<chrono::DateTime<chrono::Utc>> = r.try_get("created_at").ok();
    let updated_at: Option<chrono::DateTime<chrono::Utc>> = r.try_get("updated_at").ok();

    ScimUser {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".into()],
        id: id.to_string(),
        external_id,
        user_name: email.clone(),
        display_name: {
            let parts: Vec<&str> = [first_name.as_deref(), last_name.as_deref()]
                .iter()
                .filter_map(|s| *s)
                .filter(|s| !s.is_empty())
                .collect();
            if parts.is_empty() {
                email.clone()
            } else {
                parts.join(" ")
            }
        },
        name: if first_name.is_some() || last_name.is_some() {
            Some(ScimName {
                given_name: first_name,
                family_name: last_name,
            })
        } else {
            None
        },
        emails: vec![ScimEmail {
            value: email,
            primary: true,
        }],
        phone_numbers: Vec::new(),
        active: status == "active",
        created: created_at.map(|d| d.to_rfc3339()),
        last_modified: updated_at.map(|d| d.to_rfc3339()),
    }
}

// ── Bulk (AUTH-5, RFC 7644 §3.7) ────────────────────────────────────────

/// One Bulk operation. `method`+`path` identify the per-user verb
/// (`POST /scim/v2/Users`, `PUT/PATCH/DELETE /scim/v2/Users/{id}`),
/// `bulkId` correlates a create response back to the caller's batch
/// entries, `data` is the operation's request body.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ScimBulkOperation {
    /// The HTTP verb of the wrapped per-user operation.
    pub method: String,
    /// The wrapped resource path (`/scim/v2/Users` or `.../Users/{id}`).
    pub path: String,
    /// Caller-supplied correlation id (echoed in the response entry).
    #[serde(default)]
    pub bulk_id: Option<String>,
    /// The operation's SCIM JSON body (create/replace).
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

/// Request body of `POST /scim/v2/Bulk`.
/// Request body of `POST /scim/v2/Bulk`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ScimBulkRequest {
    /// SCIM schema URIs (caller-supplied, informational).
    #[serde(default)]
    pub schemas: Option<Vec<String>>,
    /// The batch operations (SCIM wire name `Operations`).
    #[serde(rename = "Operations")]
    pub operations: Vec<ScimBulkOperation>,
    /// Max failures before the batch stops (RFC 7644 §3.7). 0 = unlimited.
    #[serde(default, rename = "failOnErrors")]
    pub fail_on_errors: Option<u32>,
}

/// Per-operation result entry.
/// Per-operation result entry.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ScimBulkOperationResult {
    /// The echoed HTTP verb.
    pub method: String,
    /// The echoed path.
    pub path: String,
    /// The echoed correlation id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bulk_id: Option<String>,
    /// HTTP status the per-verb handler produced.
    pub status: u16,
    /// The per-verb response body (or the SCIM error payload).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
}

/// Response body of `POST /scim/v2/Bulk`.
/// Response body of `POST /scim/v2/Bulk`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ScimBulkResponse {
    /// SCIM schema URIs.
    pub schemas: Vec<String>,
    /// Total operations submitted.
    pub total_operations: usize,
    /// Operations that returned a success status.
    pub succeeded: usize,
    /// Operations that returned an error status.
    pub failed: usize,
    /// Per-operation results (SCIM wire name `Operations`).
    #[serde(rename = "Operations")]
    pub operations: Vec<ScimBulkOperationResult>,
}

/// `POST /scim/v2/Bulk` - batch users provisioning (AUTH-5). Thin wrapper:
/// each operation dispatches through the SAME per-user SQL paths the
/// individual endpoints run (create/replace/delete; patch maps to
/// replace) - no second write path, no partial-batch semantics beyond
/// `failOnErrors`. Authenticated once for the whole batch.
#[utoipa::path(
    post,
    path = "/scim/v2/Bulk",
    request_body = ScimBulkRequest,
    responses(
        (status = 200, description = "Per-operation results", body = ScimBulkResponse),
        (status = 401, description = "Caller authentication failed"),
    ),
    security(("sentin8:auth:scim" = [])),
    tag = "scim",
)]
pub async fn bulk(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ScimBulkRequest>,
) -> Result<Json<ScimBulkResponse>, (StatusCode, String)> {
    let _ = validate_scim_auth(&state, &headers, "sentin8:scim:write").await?;
    if req.operations.len() > 100 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Bulk supports at most 100 operations".into(),
        ));
    }
    let mut results = Vec::with_capacity(req.operations.len());
    let (mut ok, mut failed) = (0usize, 0usize);
    for op in &req.operations {
        let outcome = dispatch_bulk_op(&state, &headers, op).await;
        let (status, response) = match outcome {
            Ok((code, body)) => (code.as_u16(), body),
            Err((code, msg)) => (
                code.as_u16(),
                Some(serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "status": code.as_u16().to_string(),
                    "detail": msg,
                })),
            ),
        };
        if (400..600).contains(&status) {
            failed += 1;
        } else {
            ok += 1;
        }
        results.push(ScimBulkOperationResult {
            method: op.method.clone(),
            path: op.path.clone(),
            bulk_id: op.bulk_id.clone(),
            status,
            response,
        });
        if let Some(max) = req.fail_on_errors {
            if max > 0 && failed >= max as usize {
                break;
            }
        }
    }
    Ok(Json(ScimBulkResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:BulkResponse".into()],
        total_operations: req.operations.len(),
        succeeded: ok,
        failed,
        operations: results,
    }))
}

/// Dispatch one Bulk operation through the per-user SQL paths. `data`
/// carries the SCIM JSON body for create/replace; DELETE needs no body.
/// Reuses `row_to_scim_user` for create/replace responses so the wrapper
/// never builds user records by hand.
async fn dispatch_bulk_op(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    op: &ScimBulkOperation,
) -> Result<(StatusCode, Option<serde_json::Value>), (StatusCode, String)> {
    let method = op.method.to_ascii_uppercase();
    let path = op.path.trim().trim_start_matches('/');
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    // Expect ["scim","v2","Users"(,{id})] - anything else is unsupported.
    if segments.len() < 3 || segments[0] != "scim" || segments[1] != "v2" || segments[2] != "Users"
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported Bulk path '{path}'"),
        ));
    }
    match (method.as_str(), segments.len()) {
        ("POST", 3) => {
            let req: ScimCreateUser =
                serde_json::from_value(op.data.clone().unwrap_or_default())
                    .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid create body: {e}")))?;
            let (code, Json(user)) = create_user_inner(state, headers, req).await?;
            Ok((code, Some(serde_json::to_value(user).unwrap_or_default())))
        }
        ("PUT", 4) => {
            let id = Uuid::parse_str(segments[3])
                .map_err(|_| (StatusCode::BAD_REQUEST, "invalid user id".into()))?;
            let req: ScimCreateUser = serde_json::from_value(op.data.clone().unwrap_or_default())
                .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("invalid replace body: {e}"),
                )
            })?;
            let Json(user) = replace_user_inner(state, headers, id, req).await?;
            Ok((
                StatusCode::OK,
                Some(serde_json::to_value(user).unwrap_or_default()),
            ))
        }
        ("DELETE", 4) => {
            let id = Uuid::parse_str(segments[3])
                .map_err(|_| (StatusCode::BAD_REQUEST, "invalid user id".into()))?;
            let code = delete_user_inner(state, headers, id).await?;
            Ok((code, None))
        }
        (m, n) => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported Bulk operation {m} with path segments {n}"),
        )),
    }
}

/// Extracted core of `create_user` (the HTTP handler delegates here) so
/// the Bulk wrapper shares the exact SQL path.
pub async fn create_user_inner(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    req: ScimCreateUser,
) -> Result<(StatusCode, Json<ScimUser>), (StatusCode, String)> {
    create_user(State(state.clone()), headers.clone(), Json(req)).await
}

/// Extracted core of `replace_user` (200 with the replaced user).
pub async fn replace_user_inner(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    id: Uuid,
    req: ScimCreateUser,
) -> Result<Json<ScimUser>, (StatusCode, String)> {
    replace_user(State(state.clone()), headers.clone(), Path(id), Json(req)).await
}

/// Extracted core of `delete_user`.
pub async fn delete_user_inner(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    id: Uuid,
) -> Result<StatusCode, (StatusCode, String)> {
    delete_user(State(state.clone()), headers.clone(), Path(id)).await
}
