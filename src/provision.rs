// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Membership provisioning API for Sentin8:Sys (auth design
//! "Sys integration" / ).
//!
//! The internal admin surface sys's Flow proxy-back steps call for org/env
//! access provisioning: idempotent upserts of the per-tenant RBAC rows
//! (`groups` / `group_members` / `group_roles` / `role_nesting` / `roles`
//! / `user_roles`). Sys previously INSERTed these tables directly - a
//! cross-service table access retired by (
//! ): the owner (auth) exposes the provisioning verbs, sys
//! calls them with its M2M `sentin8:sys:memberships:admin`-gated client.
//!
//! All three endpoints are:
//! - **Idempotent** - `ON CONFLICT DO NOTHING/UPDATE`, safe under Flow's
//! at-least-once retry semantics (the proxy-back steps re-run on retry).
//! - **Shield-gated** - the scope mirror decides on LIVE effective scopes;
//! `sentin8:sys:memberships:admin` (the sys provisioning workload's
//! scope) and the broader `sentin8:auth:admin:write` both pass.
//! - **M2M-friendly** - the standard token gate (steps 1-4) runs before
//! Shield; tenant context rides the token's `env_id` (RLS).

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::handlers::AppState;

/// Verify the caller + gate on the Shield scope mirror (step 5). The sys
/// provisioning workload's M2M token carries `sentin8:sys:memberships:admin`;
/// operator tokens carry `sentin8:auth:admin:write` - both pass. Returns
/// the resolved tenant env (RLS context).
async fn authorize_provisioning(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, (StatusCode, String)> {
    let ctx = crate::sentin8or_auth::require_sentin8or_access_mode(
        state,
        headers,
        headers
            .get("x-sentin8-target-env-id")
            .and_then(|v| v.to_str().ok()),
        crate::sentin8or_auth::AccessMode::Write,
    )
    .await?;
    Ok(ctx.env_id)
}

/// `POST /v1/admin/provision/role` - upsert a role (idempotent).
#[derive(Debug, Deserialize, ToSchema)]
/// Request body for provisionrole.
pub struct ProvisionRoleRequest {
    /// env identifier.
    pub env_id: Uuid,
    /// The name.
    pub name: String,
    #[serde(default)]
    /// The permissions.
    pub permissions: Vec<String>,
}

#[utoipa::path(
    post,
    operation_id = "provision.role",
    path = "/v1/admin/provision/role",
    request_body = ProvisionRoleRequest,
    responses(
        (status = 200, description = "Role upserted (id returned)"),
        (status = 403, description = "Missing provisioning scope"),
    ),
    security(("sentin8:auth:admin:write" = [])),
    tag = "auth",
)]
/// Handle provision role.
pub async fn provision_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ProvisionRoleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _env = authorize_provisioning(&state, &headers).await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    crate::admin::set_tenant_context(&mut conn, req.env_id).await;
    let id = Uuid::new_v4();
    let row: Option<Uuid> = sqlx::query_scalar(
        r#"INSERT INTO roles (id, env_id, name, permissions)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (env_id, name) DO UPDATE SET
             permissions = EXCLUDED.permissions, updated_at = now()
           RETURNING id"#,
    )
    .bind(id)
    .bind(req.env_id)
    .bind(&req.name)
    .bind(&req.permissions)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = conn.commit().await;
    Ok(Json(serde_json::json!({
        "role_id": row.unwrap_or(id),
    })))
}

/// `POST /v1/admin/provision/role_nesting` - nest child under parent (idempotent).
#[derive(Debug, Deserialize, ToSchema)]
/// Request body for provisionrolenesting.
pub struct ProvisionRoleNestingRequest {
    /// env identifier.
    pub env_id: Uuid,
    /// The parent name.
    pub parent_name: String,
    /// The child name.
    pub child_name: String,
}

#[utoipa::path(
    post,
    operation_id = "provision.role_nesting",
    path = "/v1/admin/provision/role_nesting",
    request_body = ProvisionRoleNestingRequest,
    responses(
        (status = 204, description = "Nesting ensured"),
        (status = 403, description = "Missing provisioning scope"),
    ),
    security(("sentin8:auth:admin:write" = [])),
    tag = "auth",
)]
/// Handle provision role nesting.
pub async fn provision_role_nesting(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ProvisionRoleNestingRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _env = authorize_provisioning(&state, &headers).await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    crate::admin::set_tenant_context(&mut conn, req.env_id).await;
    sqlx::query(
        r#"INSERT INTO role_nesting (parent_role_id, child_role_id)
           SELECT p.id, c.id
           FROM roles p, roles c
           WHERE p.name = $2 AND p.env_id = $1
             AND c.name = $3 AND c.env_id = $1
           ON CONFLICT DO NOTHING"#,
    )
    .bind(req.env_id)
    .bind(&req.parent_name)
    .bind(&req.child_name)
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = conn.commit().await;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/admin/provision/group` - upsert a group (idempotent).
#[derive(Debug, Deserialize, ToSchema)]
/// Request body for provisiongroup.
pub struct ProvisionGroupRequest {
    /// env identifier.
    pub env_id: Uuid,
    /// The name.
    pub name: String,
}

#[utoipa::path(
    post,
    operation_id = "provision.group",
    path = "/v1/admin/provision/group",
    request_body = ProvisionGroupRequest,
    responses(
        (status = 200, description = "Group upserted (id returned)"),
        (status = 403, description = "Missing provisioning scope"),
    ),
    security(("sentin8:auth:admin:write" = [])),
    tag = "auth",
)]
/// Handle provision group.
pub async fn provision_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ProvisionGroupRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _env = authorize_provisioning(&state, &headers).await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    crate::admin::set_tenant_context(&mut conn, req.env_id).await;
    let id = Uuid::new_v4();
    let row: Option<Uuid> = sqlx::query_scalar(
        r#"INSERT INTO groups (id, env_id, name)
           VALUES ($1, $2, $3)
           ON CONFLICT (env_id, name) DO UPDATE SET updated_at = now()
           RETURNING id"#,
    )
    .bind(id)
    .bind(req.env_id)
    .bind(&req.name)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = conn.commit().await;
    Ok(Json(serde_json::json!({ "group_id": row.unwrap_or(id) })))
}

/// `POST /v1/admin/provision/group_role` - assign a role to a group (idempotent).
#[derive(Debug, Deserialize, ToSchema)]
/// Request body for provisiongrouprole.
pub struct ProvisionGroupRoleRequest {
    /// env identifier.
    pub env_id: Uuid,
    /// The group name.
    pub group_name: String,
    /// The role name.
    pub role_name: String,
}

#[utoipa::path(
    post,
    operation_id = "provision.group_role",
    path = "/v1/admin/provision/group_role",
    request_body = ProvisionGroupRoleRequest,
    responses(
        (status = 204, description = "Assignment ensured"),
        (status = 403, description = "Missing provisioning scope"),
    ),
    security(("sentin8:auth:admin:write" = [])),
    tag = "auth",
)]
/// Handle provision group role.
pub async fn provision_group_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ProvisionGroupRoleRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _env = authorize_provisioning(&state, &headers).await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    crate::admin::set_tenant_context(&mut conn, req.env_id).await;
    sqlx::query(
        r#"INSERT INTO group_roles (group_id, role_id, env_id)
           SELECT g.id, r.id, g.env_id
           FROM groups g, roles r
           WHERE g.name = $1 AND g.env_id = $3
             AND r.name = $2 AND r.env_id = $3
           ON CONFLICT DO NOTHING"#,
    )
    .bind(&req.group_name)
    .bind(&req.role_name)
    .bind(req.env_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = conn.commit().await;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/admin/provision/group_member` - add a user to a group
/// (idempotent; returns the post-state membership count - 0 when the group
/// is absent, which the caller treats as an error, fail-closed).
#[derive(Debug, Deserialize, ToSchema)]
/// Request body for provisiongroupmember.
pub struct ProvisionGroupMemberRequest {
    /// env identifier.
    pub env_id: Uuid,
    /// The group name.
    pub group_name: String,
    /// user identifier.
    pub user_id: Uuid,
}

#[utoipa::path(
    post,
    operation_id = "provision.group_member",
    path = "/v1/admin/provision/group_member",
    request_body = ProvisionGroupMemberRequest,
    responses(
        (status = 200, description = "Membership ensured (count returned)"),
        (status = 403, description = "Missing provisioning scope"),
    ),
    security(("sentin8:auth:admin:write" = [])),
    tag = "auth",
)]
/// Handle provision group member.
pub async fn provision_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ProvisionGroupMemberRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _env = authorize_provisioning(&state, &headers).await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    crate::admin::set_tenant_context(&mut conn, req.env_id).await;
    sqlx::query(
        r#"INSERT INTO group_members (group_id, user_id, env_id)
           SELECT g.id, $2, g.env_id
           FROM groups g
           WHERE g.name = $1 AND g.env_id = $3
           ON CONFLICT DO NOTHING"#,
    )
    .bind(&req.group_name)
    .bind(req.user_id)
    .bind(req.env_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Post-state count (Flow retry semantics - see sys's add_group_member).
    let existing: i64 = sqlx::query_scalar(
        r#"SELECT count(*) FROM group_members m
           JOIN groups g ON g.id = m.group_id
           WHERE g.name = $1 AND g.env_id = $2 AND m.user_id = $3"#,
    )
    .bind(&req.group_name)
    .bind(req.env_id)
    .bind(req.user_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Identity-cache invalidation (auth DESIGN §7.1): the provisioning just
    // granted access - SYSTEM-env `policy` row on the caller's transaction;
    // the tenant env to sweep rides the payload (the tenant-plane context
    // is restored first by the helper).
    if existing > 0 {
        crate::events::emit_identity_invalidation_tx(
            &mut conn,
            req.env_id,
            req.user_id,
            "sentin8:auth:membership:created",
        )
        .await;
    }
    let _ = conn.commit().await;
    Ok(Json(serde_json::json!({ "count": existing.max(0) })))
}

/// `POST /v1/admin/provision/user_role` - assign a role to a user (idempotent).
#[derive(Debug, Deserialize, ToSchema)]
/// Request body for provisionuserrole.
pub struct ProvisionUserRoleRequest {
    /// env identifier.
    pub env_id: Uuid,
    /// user identifier.
    pub user_id: Uuid,
    /// The role name.
    pub role_name: String,
}

#[utoipa::path(
    post,
    operation_id = "provision.user_role",
    path = "/v1/admin/provision/user_role",
    request_body = ProvisionUserRoleRequest,
    responses(
        (status = 204, description = "Assignment ensured"),
        (status = 403, description = "Missing provisioning scope"),
    ),
    security(("sentin8:auth:admin:write" = [])),
    tag = "auth",
)]
/// Handle provision user role.
pub async fn provision_user_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ProvisionUserRoleRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _env = authorize_provisioning(&state, &headers).await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    crate::admin::set_tenant_context(&mut conn, req.env_id).await;
    sqlx::query(
        r#"INSERT INTO user_roles (user_id, role_id, env_id)
           SELECT $2, r.id, r.env_id FROM roles r
           WHERE r.name = $3 AND r.env_id = $1
           ON CONFLICT DO NOTHING"#,
    )
    .bind(req.env_id)
    .bind(req.user_id)
    .bind(&req.role_name)
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = conn.commit().await;
    Ok(StatusCode::NO_CONTENT)
}
