// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Annotated RFW POST-alias wrappers (Dash 28.14).
//!
//! The RFW renderer is POST-only, so row actions arrive as
//! `POST /v1/admin/{resource}/{id}/{action}` instead of the canonical
//! `PATCH/DELETE`. The canonical handlers (in `admin.rs` /
//! `enterprise_connections.rs`) are already annotated at their canonical
//! paths; these thin wrappers delegate to them and annotate the alias
//! paths so the drift guard passes and the site API page shows the
//! renderer's real surface.

use crate::handlers::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;

use crate::admin::TargetEnvQuery;

/// `POST /v1/admin/users/{id}/delete` - RFW alias of
/// `DELETE /v1/admin/users/{id}`.
#[utoipa::path(
    post,
    path = "/v1/admin/users/{id}/delete",
    params(
        ("id" = uuid::Uuid, Path, description = "User id"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "User deleted (same contract as DELETE /v1/admin/users/{id})"),
        (status = 403, description = "Caller lacks the admin write scope"),
        (status = 404, description = "Unknown user"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
pub async fn user_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    crate::admin::delete_user(State(state), headers, Query(teq), Path(id)).await
}

/// `POST /v1/admin/roles/{id}/update` - RFW alias of
/// `PUT /v1/admin/roles/{id}` (form body passthrough).
#[utoipa::path(
    post,
    path = "/v1/admin/roles/{id}/update",
    params(
        ("id" = uuid::Uuid, Path, description = "Role id"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    request_body = crate::admin::UpdateRoleRequest,
    responses(
        (status = 200, description = "Role updated (same contract as PUT /v1/admin/roles/{id})", body = crate::admin::RoleResponse),
        (status = 403, description = "Caller lacks the admin write scope"),
        (status = 404, description = "Unknown role"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
pub async fn role_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<crate::admin::UpdateRoleRequest>,
) -> Result<Json<crate::admin::RoleResponse>, (StatusCode, String)> {
    crate::admin::update_role(State(state), headers, Query(teq), Path(id), Json(req)).await
}

/// `POST /v1/admin/roles/{id}/delete` - RFW alias of
/// `DELETE /v1/admin/roles/{id}`.
#[utoipa::path(
    post,
    path = "/v1/admin/roles/{id}/delete",
    params(
        ("id" = uuid::Uuid, Path, description = "Role id"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "Role deleted (same contract as DELETE /v1/admin/roles/{id})"),
        (status = 403, description = "Caller lacks the admin write scope"),
        (status = 404, description = "Unknown role"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
pub async fn role_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    crate::admin::delete_role(State(state), headers, Query(teq), Path(id)).await
}

/// `POST /v1/admin/groups/{id}/update` - RFW alias of
/// `PUT /v1/admin/groups/{id}` (raw JSON body passthrough).
#[utoipa::path(
    post,
    path = "/v1/admin/groups/{id}/update",
    params(
        ("id" = uuid::Uuid, Path, description = "Group id"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    request_body = crate::admin::UpdateGroupRequest,
    responses(
        (status = 200, description = "Group updated (same contract as PUT /v1/admin/groups/{id})", body = crate::admin::GroupResponse),
        (status = 403, description = "Caller lacks the admin write scope"),
        (status = 404, description = "Unknown group"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
pub async fn group_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<uuid::Uuid>,
    body: axum::body::Bytes,
) -> Result<Json<crate::admin::GroupResponse>, (StatusCode, String)> {
    crate::admin::update_group(State(state), headers, Query(teq), Path(id), body).await
}

/// `POST /v1/admin/groups/{id}/delete` - RFW alias of
/// `DELETE /v1/admin/groups/{id}`.
#[utoipa::path(
    post,
    path = "/v1/admin/groups/{id}/delete",
    params(
        ("id" = uuid::Uuid, Path, description = "Group id"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "Group deleted (same contract as DELETE /v1/admin/groups/{id})"),
        (status = 403, description = "Caller lacks the admin write scope"),
        (status = 404, description = "Unknown group"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
pub async fn group_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    crate::admin::delete_group(State(state), headers, Query(teq), Path(id)).await
}

/// `POST /v1/admin/oauth-clients/{id}/delete` - RFW alias of
/// `DELETE /v1/admin/oauth-clients/{id}`.
#[utoipa::path(
    post,
    path = "/v1/admin/oauth-clients/{id}/delete",
    params(
        ("id" = uuid::Uuid, Path, description = "OAuth client id"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "Client deleted (same contract as DELETE /v1/admin/oauth-clients/{id})"),
        (status = 403, description = "Caller lacks the admin write scope"),
        (status = 404, description = "Unknown client"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
pub async fn oauth_client_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    crate::admin::delete_oauth_client(State(state), headers, Query(teq), Path(id)).await
}

/// `POST /v1/admin/sessions/{id}/revoke` - RFW alias of
/// `DELETE /v1/admin/sessions/{id}`.
#[utoipa::path(
    post,
    path = "/v1/admin/sessions/{id}/revoke",
    params(
        ("id" = uuid::Uuid, Path, description = "Session id"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "Session revoked (same contract as DELETE /v1/admin/sessions/{id})"),
        (status = 403, description = "Caller lacks the admin write scope"),
        (status = 404, description = "Unknown session"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
pub async fn session_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    crate::admin::terminate_session(State(state), headers, Query(teq), Path(id)).await
}

/// `POST /v1/admin/enterprise-connections/{id}/delete` - RFW alias of
/// `DELETE /v1/admin/enterprise-connections/{id}`.
#[utoipa::path(
    post,
    path = "/v1/admin/enterprise-connections/{id}/delete",
    params(
        ("id" = uuid::Uuid, Path, description = "Enterprise connection id"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "Connection deleted (same contract as DELETE /v1/admin/enterprise-connections/{id})"),
        (status = 403, description = "Caller lacks the admin write scope"),
        (status = 404, description = "Unknown connection"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
pub async fn enterprise_connection_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    crate::enterprise_connections::delete_connection(State(state), headers, Path(id), Query(teq))
        .await
}

/// `GET /v1/admin/groups/{id}` - the group's members (the same
/// `list_group_members` handler is bound at both this path and
/// `/v1/admin/groups/{group_id}/members`; one spec entry documents the
/// contract, a second entry records this duplicate binding so the drift
/// guard passes and both forms are visible on the site page).
#[utoipa::path(
    get,
    path = "/v1/admin/groups/{id}",
    params(
        ("id" = uuid::Uuid, Path, description = "Group id"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "The group's members (identical handler to GET /v1/admin/groups/{group_id}/members)", body = serde_json::Value),
        (status = 403, description = "Caller lacks the admin read scope"),
        (status = 404, description = "Unknown group"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
pub async fn group_members_alias(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    crate::admin::list_group_members(State(state), headers, Query(teq), Path(id)).await
}