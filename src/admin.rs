// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Admin API handlers - users, roles, OAuth clients, API keys, sessions,
//! memberships, invitations, and audit events.
//!
//!.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bcrypt::{hash as bcrypt_hash, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::handlers::fetch_role_scopes;
use crate::handlers::AppState;
use crate::sentin8or_auth::{require_sentin8or_access_with_env, require_sentin8or_access_write};

/// Optional `target_env_id` query parameter for cross-env admin access.
/// When present, the auth context is resolved for the target env instead
/// of the caller's own env (subject to RBAC validation).
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
/// The targetenvquery type.
pub struct TargetEnvQuery {
    #[serde(default)]
    /// target env identifier.
    pub target_env_id: Option<String>,
}

/// Set RLS tenant context on a connection. Required before querying
/// sentin8_auth_* tables when connecting as sentin8_app (NOBYPASSRLS).
pub(crate) async fn set_tenant_context(conn: &mut sqlx::PgConnection, env_id: Uuid) {
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(conn)
        .await;
}

// ── Pagination ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
/// The paginationquery type.
pub struct PaginationQuery {
    #[serde(default = "default_page")]
    /// The page.
    pub page: i64,
    #[serde(default = "default_page_size")]
    /// The page size.
    pub page_size: i64,
}

fn default_page() -> i64 {
    1
}
fn default_page_size() -> i64 {
    50
}

impl PaginationQuery {
    fn limit(&self) -> i64 {
        self.page_size.min(200)
    }
    fn offset(&self) -> i64 {
        (self.page - 1).max(0) * self.page_size
    }
}

/// Query params for `GET /v1/admin/users` - extends [PaginationQuery].
#[derive(Debug, Deserialize, ToSchema)]
/// The listusersquery type.
pub struct ListUsersQuery {
    #[serde(flatten)]
    /// The pagination.
    pub pagination: PaginationQuery,
}

impl ListUsersQuery {
    fn limit(&self) -> i64 {
        self.pagination.limit()
    }
    fn offset(&self) -> i64 {
        self.pagination.offset()
    }
}

// ── Users CRUD ──────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for createuser.
pub struct CreateUserRequest {
    /// The email.
    pub email: String,
    #[serde(default)]
    /// The password.
    pub password: Option<String>,
    #[serde(default)]
    /// The first name.
    pub first_name: Option<String>,
    #[serde(default)]
    /// The last name.
    pub last_name: Option<String>,
    #[serde(default)]
    /// env identifier.
    pub env_id: Option<Uuid>,
    #[serde(default)]
    /// The status.
    pub status: Option<String>,
    #[serde(default)]
    /// The group ids.
    pub group_ids: Vec<String>,
}

#[derive(Serialize, ToSchema)]
/// Response payload for user.
pub struct UserResponse {
    /// Identifier.
    pub id: Uuid,
    /// env identifier.
    pub env_id: Uuid,
    /// The email.
    pub email: String,
    /// The first name.
    pub first_name: Option<String>,
    /// The last name.
    pub last_name: Option<String>,
    /// The status.
    pub status: String,
    /// The email verified.
    pub email_verified: bool,
    /// The MFA enabled.
    pub mfa_enabled: bool,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// updated time.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, ToSchema)]
/// Response payload for userlist.
pub struct UserListResponse {
    /// The users.
    pub users: Vec<UserResponse>,
    /// The total count.
    pub total: i64,
    /// The page.
    pub page: i64,
    /// The page size.
    pub page_size: i64,
}

/// `GET /v1/admin/users` - list users (paginated).
#[utoipa::path(
    get,
    operation_id = "user.list",
    path = "/v1/admin/users",
    params(
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Paginated user list", body = UserListResponse),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List users.
pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Query(q): Query<ListUsersQuery>,
) -> Result<Json<UserListResponse>, (StatusCode, String)> {
    let auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire: sentin8_set_tenant_context
    // uses set_config(..., true) which is TRANSACTION-local - outside a
    // transaction it evaporates and RLS denies every write. All queries for
    // this request run inside this transaction on the same connection.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, auth.env_id).await;
    let limit = q.limit();
    let offset = q.offset();

    // Filter by auth context's env.
    use sqlx::Row as _;
    let rows: Vec<sqlx::postgres::PgRow> = {
        sqlx::query(
            r#"SELECT id, env_id, email,
                      first_name, last_name, status, email_verified, mfa_enabled,
                      created_at, updated_at
               FROM users
               WHERE env_id = $1
               ORDER BY created_at DESC
               LIMIT $2 OFFSET $3"#,
        )
        .bind(auth.env_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *conn)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total: i64 = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*)::BIGINT FROM users
           WHERE env_id = $1"#,
    )
    .bind(auth.env_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let users = rows
        .into_iter()
        .map(|r| {
            let env_id: Uuid = r.get("env_id");
            UserResponse {
                id: r.get("id"),
                env_id,
                email: r.get("email"),
                first_name: r.get("first_name"),
                last_name: r.get("last_name"),
                status: r.get("status"),
                email_verified: r.get("email_verified"),
                mfa_enabled: r.get("mfa_enabled"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
            }
        })
        .collect();

    Ok(Json(UserListResponse {
        users,
        total,
        page: q.pagination.page,
        page_size: q.pagination.page_size,
    }))
}

/// `POST /v1/admin/users` - create a new user.
#[utoipa::path(
    post,
    operation_id = "user.create",
    path = "/v1/admin/users",
    params(("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin")),
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created", body = UserResponse),
        (status = 400, description = "email is required"),
        (status = 409, description = "email already exists"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Create user.
pub async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Response, (StatusCode, String)> {
    let auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire: sentin8_set_tenant_context
    // uses set_config(..., true) which is TRANSACTION-local - outside a
    // transaction it evaporates and RLS denies every write. All queries for
    // this request run inside this transaction on the same connection.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, auth.env_id).await;
    if req.email.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "email is required".into()));
    }

    // Use the auth context's env_id if not explicitly provided.
    // SEC- - a request-supplied env_id must match the caller's
    // authorized env unless the caller is a platform admin; an org admin
    // could otherwise create users in any env.
    let env_id = match req.env_id {
        Some(e) if e != auth.env_id && !auth.is_platform_admin() => {
            return Err((
                StatusCode::FORBIDDEN,
                "env_id must match the caller's authorized env".into(),
            ));
        }
        Some(e) => e,
        None => auth.env_id,
    };

    let password_hash = match req.password {
        Some(ref pw) if !pw.is_empty() => Some(
            bcrypt_hash(pw, DEFAULT_COST)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        ),
        _ => None,
    };
    let status = req.status.unwrap_or_else(|| "active".into());

    let row = sqlx::query!(
        r#"INSERT INTO users
               (env_id, email, password_hash,
                first_name, last_name, status)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING
               id, env_id, email,
               first_name, last_name, status, email_verified, mfa_enabled,
               created_at, updated_at"#,
        env_id,
        req.email.to_lowercase(),
        password_hash,
        req.first_name,
        req.last_name,
        status,
    )
    .fetch_one(&mut *conn)
    .await;

    let row = match row {
        Ok(r) => r,
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
            return Err((StatusCode::CONFLICT, "email already exists".into()));
        }
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };

    //- emit user.created event to Bus outbox.
    crate::events::emit_event_tx(
        &mut conn,
        row.env_id,
        "sentin8:auth:user:created",
        serde_json::json!({
            "user_id": row.id,
            "email": row.email.clone(),
        }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    //send welcome notification via Sentin8:Post.
    crate::events::emit_post_notification(
        &state.pool,
        row.env_id,
        "sentin8:auth:user:welcome",
        "system",
        "normal",
        Some(row.id),
        Some(&row.email),
        "Welcome to Sentin8",
        &format!("Your account has been created. Email: {}", row.email),
        serde_json::json!({"user_id": row.id, "event": "welcome"}),
    )
    .await;

    // Add the user to the selected groups (if any were specified in the form).
    if !req.group_ids.is_empty() {
        for gid in &req.group_ids {
            let _ = sqlx::query(
                "INSERT INTO group_members (group_id, user_id, env_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            )
            .bind(gid)
            .bind(row.id)
            .bind(row.env_id)
            .execute(&state.pool)
            .await;
        }
        tracing::info!(user_id = %row.id, groups = ?req.group_ids, "auth: added user to groups at creation time");
    }

    let resp = UserResponse {
        id: row.id,
        env_id: row.env_id,
        email: row.email,
        first_name: row.first_name,
        last_name: row.last_name,
        status: row.status,
        email_verified: row.email_verified,
        mfa_enabled: row.mfa_enabled,
        created_at: row.created_at,
        updated_at: row.updated_at,
    };

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

/// `GET /v1/admin/users/{id}` - get a user by ID.
#[utoipa::path(
    get,
    operation_id = "user.get",
    path = "/v1/admin/users/{id}",
    params(
        ("id" = Uuid, Path, description = "User ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 200, description = "User", body = UserResponse),
        (status = 404, description = "user not found"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Fetch user.
pub async fn get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let row = sqlx::query!(
        r#"SELECT
               id, env_id, email,
               first_name, last_name, status, email_verified, mfa_enabled,
               created_at, updated_at
           FROM users WHERE id = $1"#,
        id,
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match row {
        Some(r) => Ok(Json(UserResponse {
            id: r.id,
            env_id: r.env_id,
            email: r.email,
            first_name: r.first_name,
            last_name: r.last_name,
            status: r.status,
            email_verified: r.email_verified,
            mfa_enabled: r.mfa_enabled,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })),
        None => Err((StatusCode::NOT_FOUND, "user not found".into())),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for updateuser.
pub struct UpdateUserRequest {
    #[serde(default)]
    /// The first name.
    pub first_name: Option<String>,
    #[serde(default)]
    /// The last name.
    pub last_name: Option<String>,
    #[serde(default)]
    /// The status.
    pub status: Option<String>,
    #[serde(default)]
    /// The email verified.
    pub email_verified: Option<bool>,
    #[serde(default)]
    /// The MFA enabled.
    pub mfa_enabled: Option<bool>,
}

/// `PUT /v1/admin/users/{id}` - update a user.
#[utoipa::path(
    put,
    operation_id = "user.update",
    path = "/v1/admin/users/{id}",
    params(
        ("id" = Uuid, Path, description = "User ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated", body = UserResponse),
        (status = 404, description = "user not found"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Update user.
pub async fn update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let row = sqlx::query!(
        r#"UPDATE users SET
               first_name = COALESCE($2, first_name),
               last_name = COALESCE($3, last_name),
               status = COALESCE($4, status),
               email_verified = COALESCE($5, email_verified),
               mfa_enabled = COALESCE($6, mfa_enabled),
               updated_at = now()
           WHERE id = $1
           RETURNING
               id, env_id, email,
               first_name, last_name, status, email_verified, mfa_enabled,
               created_at, updated_at"#,
        id,
        req.first_name,
        req.last_name,
        req.status,
        req.email_verified,
        req.mfa_enabled,
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match row {
        Some(r) => {
            //- emit user.updated event to Bus outbox.
            crate::events::emit_event_tx(
                &mut conn,
                r.env_id,
                "sentin8:auth:user:updated",
                serde_json::json!({ "user_id": r.id }),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let _ = conn.commit().await; // SEC-2.4.8 - persist the write
            Ok(Json(UserResponse {
                id: r.id,
                env_id: r.env_id,
                email: r.email,
                first_name: r.first_name,
                last_name: r.last_name,
                status: r.status,
                email_verified: r.email_verified,
                mfa_enabled: r.mfa_enabled,
                created_at: r.created_at,
                updated_at: r.updated_at,
            }))
        }
        None => Err((StatusCode::NOT_FOUND, "user not found".into())),
    }
}

/// `DELETE /v1/admin/users/{id}` - delete a user.
#[utoipa::path(
    delete,
    operation_id = "user.archive",
    path = "/v1/admin/users/{id}",
    params(
        ("id" = Uuid, Path, description = "User ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 204, description = "User deleted"),
        (status = 404, description = "user not found"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Delete user.
pub async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let result = sqlx::query!("DELETE FROM users WHERE id = $1", id)
        .execute(&mut *conn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        Err((StatusCode::NOT_FOUND, "user not found".into()))
    } else {
        //- emit user.deleted event to Bus outbox.
        crate::events::emit_event_tx(
            &mut conn,
            _auth.env_id,
            "sentin8:auth:user:deleted",
            serde_json::json!({ "user_id": id }),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = conn.commit().await; // SEC-2.4.8 - persist the write
        Ok(StatusCode::NO_CONTENT)
    }
}

// ── Roles CRUD ────────────────────────────────────────
// A Role is a named bundle of scopes (permissions). Users are assigned Roles
// directly via sentin8_auth_user_roles, or transitively via a Group (sentin8_auth_groups
// + sentin8_auth_group_roles). Role nesting (sentin8_auth_role_nesting) lets a parent Role
// inherit the scopes of its child Roles.

#[derive(Serialize, ToSchema)]
/// Response payload for role.
pub struct RoleResponse {
    /// Identifier.
    pub id: Uuid,
    /// env identifier.
    pub env_id: Uuid,
    /// The name.
    pub name: String,
    /// The permissions.
    pub permissions: Vec<String>,
    /// Names of child roles nested under this role (from sentin8_auth_role_nesting).
    /// The role inherits all permissions of these child roles recursively.
    #[serde(default)]
    /// The includes.
    pub includes: Vec<String>,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// updated time.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, ToSchema)]
/// Response payload for rolelist.
pub struct RoleListResponse {
    /// The roles.
    pub roles: Vec<RoleResponse>,
    /// The total count.
    pub total: i64,
}

/// Deserialize permissions: accept either a JSON array of strings or a
/// comma-separated string (from RFW forms). e.g. "sentin8:auth:users:read" becomes
/// ["sentin8:auth:users:read"], and ["a", "b"] stays ["a", "b"].
fn deserialize_permissions<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Perms {
        Array(Vec<String>),
        String(String),
    }
    match Perms::deserialize(deserializer)? {
        Perms::Array(v) => Ok(v),
        Perms::String(s) => Ok(s
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()),
    }
}

/// Same as [`deserialize_permissions`] but for `Option<Vec<String>>` fields -
/// absent → None; present string → comma-split Vec; present array → as-is.
fn deserialize_opt_permissions<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OptPerms {
        Array(Vec<String>),
        String(String),
    }
    match Option::<OptPerms>::deserialize(deserializer)? {
        None => Ok(None),
        Some(OptPerms::Array(v)) => Ok(Some(v)),
        Some(OptPerms::String(s)) => Ok(Some(
            s.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        )),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for createrole.
pub struct CreateRoleRequest {
    /// The name.
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_permissions")]
    /// The permissions.
    pub permissions: Vec<String>,
}

/// `GET /v1/admin/roles` - list roles (paginated).
#[utoipa::path(
    get,
    operation_id = "role.list",
    path = "/v1/admin/roles",
    params(
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Paginated role list", body = RoleListResponse),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List roles.
pub async fn list_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Query(q): Query<PaginationQuery>,
) -> Result<Json<RoleListResponse>, (StatusCode, String)> {
    let auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire: sentin8_set_tenant_context
    // uses set_config(..., true) which is TRANSACTION-local - outside a
    // transaction it evaporates and RLS denies every write. All queries for
    // this request run inside this transaction on the same connection.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, auth.env_id).await;
    let limit = q.limit();
    let offset = q.offset();

    let rows = sqlx::query!(
        r#"SELECT
               id, env_id, name, permissions,
               created_at, updated_at
           FROM roles
           WHERE env_id = $1
           ORDER BY created_at DESC
           LIMIT $2 OFFSET $3"#,
        auth.env_id,
        limit,
        offset,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*)::BIGINT FROM roles WHERE env_id = $1"#,
        auth.env_id,
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .unwrap_or(0);

    // Fetch nesting (child role names) for each role in one query.
    let role_ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let nesting_rows = if role_ids.is_empty() {
        vec![]
    } else {
        sqlx::query!(
            r#"SELECT n.parent_role_id AS parent_id, c.name AS child_name
               FROM role_nesting n
               JOIN roles c ON c.id = n.child_role_id
               WHERE n.parent_role_id = ANY($1)"#,
            &role_ids,
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    // Build a map: parent_id → [child_names]
    let mut includes_map: std::collections::HashMap<Uuid, Vec<String>> =
        std::collections::HashMap::new();
    for n in &nesting_rows {
        includes_map
            .entry(n.parent_id)
            .or_default()
            .push(n.child_name.clone());
    }

    let roles = rows
        .into_iter()
        .map(|r| {
            let includes = includes_map.remove(&r.id).unwrap_or_default();
            RoleResponse {
                id: r.id,
                env_id: r.env_id,
                name: r.name,
                permissions: r.permissions,
                includes,
                created_at: r.created_at,
                updated_at: r.updated_at,
            }
        })
        .collect();

    Ok(Json(RoleListResponse { roles, total }))
}

/// Validate a role name: must be a DNS-label-style identifier
/// (lowercase, digits, dot, underscore, hyphen, colon; 1-63
/// chars; not all-numeric to avoid confusion with numeric IDs).
/// Mirrors the validation in the front-end `RoleSelector`
/// widget. Colons are allowed so that multi-word service
/// roles can use a scoped name like `ebank:customer` instead
/// of the older hyphen-separated form.
fn validate_role_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name is required".into());
    }
    if name.len() > 63 {
        return Err("name must be 63 characters or fewer".into());
    }
    let first = name.chars().next().unwrap();
    let last = name.chars().last().unwrap();
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err("name must start with a lowercase letter or digit".into());
    }
    if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
        return Err("name must end with a lowercase letter or digit".into());
    }
    for c in name.chars() {
        if !c.is_ascii_lowercase()
            && !c.is_ascii_digit()
            && c != '.'
            && c != '_'
            && c != '-'
            && c != ':'
        {
            return Err(
                "name may only contain lowercase letters, digits, '.', '_', '-', ':'".into(),
            );
        }
    }
    Ok(())
}

/// `POST /v1/admin/roles` - create a new role.
#[utoipa::path(
    post,
    operation_id = "role.create",
    path = "/v1/admin/roles",
    params(("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin")),
    request_body = CreateRoleRequest,
    responses(
        (status = 201, description = "Role created", body = RoleResponse),
        (status = 400, description = "Invalid role name"),
        (status = 409, description = "role name already exists"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Create role.
pub async fn create_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Json(req): Json<CreateRoleRequest>,
) -> Result<Response, (StatusCode, String)> {
    let name = req.name.trim().to_string();
    validate_role_name(&name).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // Derive the target org/env from the auth context. The
    // BFF proxy exchanges the sys-realm token for an
    // org/env-scoped token (via X-BFF-Target-Org-Id) so the
    // sentin8or can only create roles in their own org/env.
    let auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire: sentin8_set_tenant_context
    // uses set_config(..., true) which is TRANSACTION-local - outside a
    // transaction it evaporates and RLS denies every write. All queries for
    // this request run inside this transaction on the same connection.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, auth.env_id).await;

    let row = sqlx::query!(
        r#"INSERT INTO roles (env_id, name, permissions)
           VALUES ($1, $2, $3)
           RETURNING
               id, env_id, name, permissions,
               created_at, updated_at"#,
        auth.env_id,
        name,
        &req.permissions,
    )
    .fetch_one(&mut *conn)
    .await;

    let row = match row {
        Ok(r) => r,
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
            return Err((
                StatusCode::CONFLICT,
                "role name already exists for this org".into(),
            ));
        }
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };

    //- emit role.created event to Bus outbox.
    crate::events::emit_event_tx(
        &mut conn,
        row.env_id,
        "sentin8:auth:role:created",
        serde_json::json!({ "role_id": row.id, "name": row.name.clone() }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resp = RoleResponse {
        id: row.id,
        env_id: row.env_id,
        name: row.name,
        permissions: row.permissions,
        includes: vec![],
        created_at: row.created_at,
        updated_at: row.updated_at,
    };

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for updaterole.
pub struct UpdateRoleRequest {
    #[serde(default)]
    /// The name.
    pub name: Option<String>,
    #[serde(default)]
    /// The permissions.
    pub permissions: Option<Vec<String>>,
}

/// `PUT /v1/admin/roles/{id}` - update a role.
#[utoipa::path(
    put,
    operation_id = "role.update",
    path = "/v1/admin/roles/{id}",
    params(
        ("id" = Uuid, Path, description = "Role ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    request_body = UpdateRoleRequest,
    responses(
        (status = 200, description = "Role updated", body = RoleResponse),
        (status = 404, description = "role not found"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Update role.
pub async fn update_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let row = sqlx::query!(
        r#"UPDATE roles SET
               name = COALESCE($2, name),
               permissions = COALESCE($3, permissions),
               updated_at = now()
           WHERE id = $1
           RETURNING
               id, env_id, name, permissions,
               created_at, updated_at"#,
        id,
        req.name,
        req.permissions.as_deref(),
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match row {
        Some(r) => {
            crate::events::emit_event_tx(
                &mut conn,
                r.env_id,
                "sentin8:auth:role:updated",
                serde_json::json!({ "role_id": id }),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let _ = conn.commit().await; // SEC-2.4.8 - persist the write
            Ok(Json(RoleResponse {
                id: r.id,
                env_id: r.env_id,
                name: r.name,
                permissions: r.permissions,
                includes: vec![],
                created_at: r.created_at,
                updated_at: r.updated_at,
            }))
        }
        None => Err((StatusCode::NOT_FOUND, "role not found".into())),
    }
}

/// `DELETE /v1/admin/roles/{id}` - delete a role.
#[utoipa::path(
    delete,
    operation_id = "role.delete",
    path = "/v1/admin/roles/{id}",
    params(
        ("id" = Uuid, Path, description = "Role ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 204, description = "Role deleted"),
        (status = 404, description = "role not found"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Delete role.
pub async fn delete_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let result = sqlx::query!("DELETE FROM roles WHERE id = $1", id)
        .execute(&mut *conn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        Err((StatusCode::NOT_FOUND, "role not found".into()))
    } else {
        crate::events::emit_event_tx(
            &mut conn,
            _auth.env_id,
            "sentin8:auth:role:deleted",
            serde_json::json!({ "role_id": id }),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = conn.commit().await; // SEC-2.4.8 - persist the write
        Ok(StatusCode::NO_CONTENT)
    }
}

// ── Role Members (user↔role assignments) ────────────────────────────────

#[derive(Serialize, ToSchema)]
/// Response payload for rolemember.
pub struct RoleMemberResponse {
    /// role identifier.
    pub role_id: Uuid,
    /// user identifier.
    pub user_id: Uuid,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/admin/roles/{id}` - list role members.
#[utoipa::path(
    get,
    operation_id = "role.get",
    path = "/v1/admin/roles/{id}",
    params(
        ("id" = Uuid, Path, description = "Role ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 200, description = "Role members", body = [RoleMemberResponse]),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List role members.
pub async fn list_role_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(role_id): Path<Uuid>,
) -> Result<Json<Vec<RoleMemberResponse>>, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let rows = sqlx::query!(
        r#"SELECT role_id, user_id, created_at FROM user_roles WHERE role_id = $1"#,
        role_id,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let members = rows
        .into_iter()
        .map(|r| RoleMemberResponse {
            role_id: r.role_id,
            user_id: r.user_id,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(members))
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for addrolemember.
pub struct AddRoleMemberRequest {
    /// user identifier.
    pub user_id: Uuid,
}

/// `POST /v1/admin/roles/{role_id}/members` - add a member to a role.
#[utoipa::path(
    post,
    operation_id = "role.member-add",
    path = "/v1/admin/roles/{role_id}/members",
    params(
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    request_body = AddRoleMemberRequest,
    responses(
        (status = 201, description = "Member added"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Handle add role member.
pub async fn add_role_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(role_id): Path<Uuid>,
    Json(req): Json<AddRoleMemberRequest>,
) -> Result<Response, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    sqlx::query!(
        r#"INSERT INTO user_roles (role_id, user_id, env_id) VALUES ($1, $2, $3)
           ON CONFLICT (role_id, user_id) DO NOTHING"#,
        role_id,
        req.user_id,
        _auth.env_id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    crate::events::emit_event_tx(
        &mut conn,
        _auth.env_id,
        "sentin8:auth:role:member:added",
        serde_json::json!({ "role_id": role_id, "user_id": req.user_id }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok(StatusCode::CREATED.into_response())
}

/// `DELETE /v1/admin/roles/{role_id}/members/{user_id}` - remove a member from a role.
#[utoipa::path(
    delete,
    operation_id = "role.member-remove",
    path = "/v1/admin/roles/{role_id}/members/{user_id}",
    params(
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("user_id" = Uuid, Path, description = "User ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 204, description = "Member removed"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Remove role member.
pub async fn remove_role_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path((role_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    sqlx::query!(
        "DELETE FROM user_roles WHERE role_id = $1 AND user_id = $2",
        role_id,
        user_id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    crate::events::emit_event_tx(
        &mut conn,
        _auth.env_id,
        "sentin8:auth:role:member:removed",
        serde_json::json!({ "role_id": role_id, "user_id": user_id }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok(StatusCode::NO_CONTENT)
}

// ── Groups CRUD ────────────────────────────────────────────────────────
// A Group is a named bundle of *members* (users). Groups carry no scopes of
// their own; instead they are assigned one or more Roles via
// `sentin8_auth_group_roles`, and every member receives the union of scopes from
// those Roles. This lets operators reuse a Role across many Groups and
// bundle several Roles for a class of users.

#[derive(Serialize, ToSchema)]
/// Response payload for group.
pub struct GroupResponse {
    /// Identifier.
    pub id: Uuid,
    /// env identifier.
    pub env_id: Uuid,
    /// The name.
    pub name: String,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// updated time.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, ToSchema)]
/// Response payload for grouplist.
pub struct GroupListResponse {
    /// The groups.
    pub groups: Vec<GroupResponse>,
    /// The total count.
    pub total: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for creategroup.
pub struct CreateGroupRequest {
    /// The name.
    pub name: String,
}

/// `GET /v1/admin/groups` - list groups (paginated).
#[utoipa::path(
    get,
    operation_id = "group.list",
    path = "/v1/admin/groups",
    params(
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Paginated group list", body = GroupListResponse),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List groups.
pub async fn list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Query(q): Query<PaginationQuery>,
) -> Result<Json<GroupListResponse>, (StatusCode, String)> {
    let auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire: sentin8_set_tenant_context
    // uses set_config(..., true) which is TRANSACTION-local - outside a
    // transaction it evaporates and RLS denies every write. All queries for
    // this request run inside this transaction on the same connection.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, auth.env_id).await;
    let limit = q.limit();
    let offset = q.offset();

    let rows = sqlx::query!(
        r#"SELECT
               id, env_id, name,
               created_at, updated_at
           FROM groups
           WHERE env_id = $1
           ORDER BY created_at DESC
           LIMIT $2 OFFSET $3"#,
        auth.env_id,
        limit,
        offset,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*)::BIGINT FROM groups WHERE env_id = $1"#,
        auth.env_id,
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .unwrap_or(0);

    let groups = rows
        .into_iter()
        .map(|r| GroupResponse {
            id: r.id,
            env_id: r.env_id,
            name: r.name,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect();

    Ok(Json(GroupListResponse { groups, total }))
}

/// Validate a group name (same DNS-label rule used for roles).
fn validate_group_name(name: &str) -> Result<(), String> {
    validate_role_name(name)
}

/// `POST /v1/admin/groups` - create a new group.
#[utoipa::path(
    post,
    operation_id = "group.create",
    path = "/v1/admin/groups",
    params(("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin")),
    request_body = CreateGroupRequest,
    responses(
        (status = 201, description = "Group created", body = GroupResponse),
        (status = 400, description = "Invalid group name"),
        (status = 409, description = "group name already exists"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Create group.
pub async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Response, (StatusCode, String)> {
    let name = req.name.trim().to_string();
    validate_group_name(&name).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire: sentin8_set_tenant_context
    // uses set_config(..., true) which is TRANSACTION-local - outside a
    // transaction it evaporates and RLS denies every write. All queries for
    // this request run inside this transaction on the same connection.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, auth.env_id).await;

    let row = sqlx::query!(
        r#"INSERT INTO groups (env_id, name)
           VALUES ($1, $2)
           RETURNING
               id, env_id, name,
               created_at, updated_at"#,
        auth.env_id,
        name,
    )
    .fetch_one(&mut *conn)
    .await;

    let row = match row {
        Ok(r) => r,
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
            return Err((
                StatusCode::CONFLICT,
                "group name already exists for this org".into(),
            ));
        }
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };

    //- emit group.created event to Bus outbox.
    crate::events::emit_event_tx(
        &mut conn,
        row.env_id,
        "sentin8:auth:group:created",
        serde_json::json!({ "group_id": row.id, "name": row.name.clone() }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resp = GroupResponse {
        id: row.id,
        env_id: row.env_id,
        name: row.name,
        created_at: row.created_at,
        updated_at: row.updated_at,
    };

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for updategroup.
pub struct UpdateGroupRequest {
    #[serde(default)]
    /// The name.
    pub name: Option<String>,
    /// Optional list of user IDs - replaces the full set of members.
    #[serde(default)]
    /// The user ids.
    pub user_ids: Option<Vec<Uuid>>,
    /// Optional list of role IDs - replaces the full set of roles.
    #[serde(default)]
    /// The role ids.
    pub role_ids: Option<Vec<Uuid>>,
}

/// `PUT /v1/admin/groups/{id}` - update a group.
#[utoipa::path(
    put,
    operation_id = "group.update",
    path = "/v1/admin/groups/{id}",
    params(
        ("id" = Uuid, Path, description = "Group ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    request_body = UpdateGroupRequest,
    responses(
        (status = 200, description = "Group updated", body = GroupResponse),
        (status = 404, description = "group not found"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Update group.
pub async fn update_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
    body: axum::body::Bytes,
) -> Result<Json<GroupResponse>, (StatusCode, String)> {
    let req: UpdateGroupRequest = serde_json::from_slice(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid request body: {e}"),
        )
    })?;
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    // Only validate name if it's a non-empty string (empty means "don't change").
    if let Some(name) = req.name.as_deref() {
        if !name.is_empty() {
            validate_group_name(name).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        }
    }

    // Update the group name if provided (non-empty only).
    let update_name: Option<&str> = req.name.as_deref().filter(|s| !s.is_empty());
    let row = sqlx::query!(
        r#"UPDATE groups SET
               name = COALESCE($2, name),
               updated_at = now()
           WHERE id = $1
           RETURNING
               id, env_id, name,
               created_at, updated_at"#,
        id,
        update_name,
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let r = match row {
        Some(r) => r,
        None => return Err((StatusCode::NOT_FOUND, "group not found".into())),
    };

    // Replace members if user_ids is provided.
    if let Some(user_ids) = &req.user_ids {
        // Remove all existing members.
        sqlx::query!("DELETE FROM group_members WHERE group_id = $1", id)
            .execute(&mut *conn)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        // Add the new set.
        for uid in user_ids {
            sqlx::query!(
                r#"INSERT INTO group_members (group_id, user_id, env_id) VALUES ($1, $2, $3)
                   ON CONFLICT (group_id, user_id) DO NOTHING"#,
                id,
                uid,
                r.env_id,
            )
            .execute(&mut *conn)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }

    // Replace roles if role_ids is provided.
    if let Some(role_ids) = &req.role_ids {
        // Remove all existing roles.
        sqlx::query!("DELETE FROM group_roles WHERE group_id = $1", id)
            .execute(&mut *conn)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        // Add the new set.
        for rid in role_ids {
            sqlx::query!(
                r#"INSERT INTO group_roles (group_id, role_id, env_id) VALUES ($1, $2, $3)
                   ON CONFLICT (group_id, role_id) DO NOTHING"#,
                id,
                rid,
                r.env_id,
            )
            .execute(&mut *conn)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }

    crate::events::emit_event_tx(
        &mut conn,
        r.env_id,
        "sentin8:auth:group:updated",
        serde_json::json!({ "group_id": id }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok(Json(GroupResponse {
        id: r.id,
        env_id: r.env_id,
        name: r.name,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }))
}

/// `DELETE /v1/admin/groups/{id}` - delete a group.
#[utoipa::path(
    delete,
    operation_id = "group.delete",
    path = "/v1/admin/groups/{id}",
    params(
        ("id" = Uuid, Path, description = "Group ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 204, description = "Group deleted"),
        (status = 404, description = "group not found"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Delete group.
pub async fn delete_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let result = sqlx::query!("DELETE FROM groups WHERE id = $1", id)
        .execute(&mut *conn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        Err((StatusCode::NOT_FOUND, "group not found".into()))
    } else {
        crate::events::emit_event_tx(
            &mut conn,
            _auth.env_id,
            "sentin8:auth:group:deleted",
            serde_json::json!({ "group_id": id }),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = conn.commit().await; // SEC-2.4.8 - persist the write
        Ok(StatusCode::NO_CONTENT)
    }
}

// ── Group Members (user↔group membership) ───────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
/// Response payload for groupmember (wire-identical; derives complete).
pub struct GroupMemberResponse {
    /// group identifier.
    pub group_id: Uuid,
    /// user identifier.
    pub user_id: Uuid,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/admin/groups/{group_id}/members` - list group members.
#[utoipa::path(
    get,
    operation_id = "group.get",
    path = "/v1/admin/groups/{group_id}/members",
    params(
        ("group_id" = Uuid, Path, description = "Group ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 200, description = "Group members"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List group members.
pub async fn list_group_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(group_id): Path<Uuid>,
) -> Result<Json<crate::dtos::GroupMembersResponse>, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let rows = sqlx::query!(
        r#"SELECT group_id, user_id, created_at FROM group_members WHERE group_id = $1"#,
        group_id,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let members: Vec<GroupMemberResponse> = rows
        .into_iter()
        .map(|r| GroupMemberResponse {
            group_id: r.group_id,
            user_id: r.user_id,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(crate::dtos::GroupMembersResponse { members }))
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for addgroupmember.
pub struct AddGroupMemberRequest {
    /// user identifier.
    pub user_id: Uuid,
}

/// `POST /v1/admin/groups/{group_id}/members` - add a member to a group.
#[utoipa::path(
    post,
    operation_id = "group.member-add",
    path = "/v1/admin/groups/{group_id}/members",
    params(
        ("group_id" = Uuid, Path, description = "Group ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    request_body = AddGroupMemberRequest,
    responses(
        (status = 201, description = "Member added"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Handle add group member.
pub async fn add_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(group_id): Path<Uuid>,
    Json(req): Json<AddGroupMemberRequest>,
) -> Result<Response, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    sqlx::query!(
        r#"INSERT INTO group_members (group_id, user_id, env_id) VALUES ($1, $2, $3)
           ON CONFLICT (group_id, user_id) DO NOTHING"#,
        group_id,
        req.user_id,
        _auth.env_id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    crate::events::emit_event_tx(
        &mut conn,
        _auth.env_id,
        "sentin8:auth:group:member:added",
        serde_json::json!({ "group_id": group_id, "user_id": req.user_id }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Identity-cache invalidation (auth DESIGN §7.1): SYSTEM-env `policy`
    // row - the tenant-env fan-out above cannot reach the policy stream.
    crate::events::emit_identity_invalidation_tx(
        &mut conn,
        _auth.env_id,
        req.user_id,
        "sentin8:auth:membership:created",
    )
    .await;

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok(StatusCode::CREATED.into_response())
}

/// `DELETE /v1/admin/groups/{group_id}/members/{user_id}` - remove a member from
/// a group.
#[utoipa::path(
    delete,
    operation_id = "group.member-remove",
    path = "/v1/admin/groups/{group_id}/members/{user_id}",
    params(
        ("group_id" = Uuid, Path, description = "Group ID"),
        ("user_id" = Uuid, Path, description = "User ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 204, description = "Member removed"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Remove group member.
pub async fn remove_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    sqlx::query!(
        "DELETE FROM group_members WHERE group_id = $1 AND user_id = $2",
        group_id,
        user_id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    crate::events::emit_event_tx(
        &mut conn,
        _auth.env_id,
        "sentin8:auth:group:member:removed",
        serde_json::json!({ "group_id": group_id, "user_id": user_id }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Identity-cache invalidation (auth DESIGN §7.1): SYSTEM-env `policy`
    // row - the revocation must take effect on the next request.
    crate::events::emit_identity_invalidation_tx(
        &mut conn,
        _auth.env_id,
        user_id,
        "sentin8:auth:membership:deleted",
    )
    .await;

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok(StatusCode::NO_CONTENT)
}

// ── Group Roles (group↔role assignment) ────────────────────────────────

#[derive(Serialize, ToSchema)]
/// Response payload for grouprole.
pub struct GroupRoleResponse {
    /// group identifier.
    pub group_id: Uuid,
    /// role identifier.
    pub role_id: Uuid,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/admin/groups/{group_id}/roles` - list roles assigned to a group.
#[utoipa::path(
    get,
    path = "/v1/admin/groups/{group_id}/roles",
    params(
        ("group_id" = Uuid, Path, description = "Group ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 200, description = "Group roles"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List group roles.
pub async fn list_group_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(group_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let rows = sqlx::query!(
        r#"SELECT group_id, role_id, created_at FROM group_roles WHERE group_id = $1"#,
        group_id,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let roles: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "group_id": r.group_id,
                "role_id": r.role_id,
                "created_at": r.created_at,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({"roles": roles})))
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for addgrouprole.
pub struct AddGroupRoleRequest {
    /// role identifier.
    pub role_id: Uuid,
}

/// `POST /v1/admin/groups/{group_id}/roles` - assign a role to a group.
#[utoipa::path(
    post,
    operation_id = "group.role-assign",
    path = "/v1/admin/groups/{group_id}/roles",
    params(
        ("group_id" = Uuid, Path, description = "Group ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    request_body = AddGroupRoleRequest,
    responses(
        (status = 201, description = "Role assigned"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Handle add group role.
pub async fn add_group_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(group_id): Path<Uuid>,
    Json(req): Json<AddGroupRoleRequest>,
) -> Result<Response, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    sqlx::query!(
        r#"INSERT INTO group_roles (group_id, role_id, env_id) VALUES ($1, $2, $3)
           ON CONFLICT (group_id, role_id) DO NOTHING"#,
        group_id,
        req.role_id,
        _auth.env_id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    crate::events::emit_event_tx(
        &mut conn,
        _auth.env_id,
        "sentin8:auth:group:role:added",
        serde_json::json!({ "group_id": group_id, "role_id": req.role_id }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok(StatusCode::CREATED.into_response())
}

/// `DELETE /v1/admin/groups/{group_id}/roles/{role_id}` - remove a role from a group.
#[utoipa::path(
    delete,
    operation_id = "group.role-unassign",
    path = "/v1/admin/groups/{group_id}/roles/{role_id}",
    params(
        ("group_id" = Uuid, Path, description = "Group ID"),
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 204, description = "Role removed"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Remove group role.
pub async fn remove_group_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path((group_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    sqlx::query!(
        "DELETE FROM group_roles WHERE group_id = $1 AND role_id = $2",
        group_id,
        role_id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    crate::events::emit_event_tx(
        &mut conn,
        _auth.env_id,
        "sentin8:auth:group:role:removed",
        serde_json::json!({ "group_id": group_id, "role_id": role_id }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok(StatusCode::NO_CONTENT)
}

// ── OAuth Clients CRUD ──────────────────────────────────

#[derive(Serialize, ToSchema)]
/// Response payload for oauthclient.
pub struct OAuthClientResponse {
    /// Identifier.
    pub id: Uuid,
    /// env identifier.
    pub env_id: Uuid,
    /// client identifier.
    pub client_id: String,
    /// The client name.
    pub client_name: String,
    /// The redirect uris.
    pub redirect_uris: Vec<String>,
    /// The grant types.
    pub grant_types: Vec<String>,
    /// The response types.
    pub response_types: Vec<String>,
    /// The token endpoint auth method.
    pub token_endpoint_auth_method: String,
    /// The scopes.
    pub scopes: Vec<String>,
    /// The status.
    pub status: String,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// updated time.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, ToSchema)]
/// Response payload for oauthclientlist.
pub struct OAuthClientListResponse {
    /// The clients.
    pub clients: Vec<OAuthClientResponse>,
    /// The total count.
    pub total: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for createoauthclient.
pub struct CreateOAuthClientRequest {
    #[serde(default)]
    /// env identifier.
    pub env_id: Option<Uuid>,
    /// client identifier.
    pub client_id: String,
    /// The client name.
    pub client_name: String,
    #[serde(default)]
    /// The client secret.
    pub client_secret: Option<String>,
    #[serde(default, deserialize_with = "deserialize_permissions")]
    /// The redirect uris.
    pub redirect_uris: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_permissions")]
    /// The grant types.
    pub grant_types: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_permissions")]
    /// The response types.
    pub response_types: Vec<String>,
    #[serde(default = "default_auth_method")]
    /// The token endpoint auth method.
    pub token_endpoint_auth_method: String,
    #[serde(default, deserialize_with = "deserialize_permissions")]
    /// The scopes.
    pub scopes: Vec<String>,
    /// First-party consent bypass . When false, the authorize
    /// endpoint issues the code directly without consent. Default true (safe).
    #[serde(default = "default_consent_required")]
    /// The consent required.
    pub consent_required: bool,
}

fn default_auth_method() -> String {
    "none".into()
}

fn default_consent_required() -> bool {
    true
}

/// `GET /v1/admin/oauth-clients` - list OAuth clients (paginated).
#[utoipa::path(
    get,
    operation_id = "application.list",
    path = "/v1/admin/oauth-clients",
    params(
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Paginated OAuth client list", body = OAuthClientListResponse),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List OAuth clients.
pub async fn list_oauth_clients(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Query(q): Query<PaginationQuery>,
) -> Result<Json<OAuthClientListResponse>, (StatusCode, String)> {
    let auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire: sentin8_set_tenant_context
    // uses set_config(..., true) which is TRANSACTION-local - outside a
    // transaction it evaporates and RLS denies every write. All queries for
    // this request run inside this transaction on the same connection.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, auth.env_id).await;
    let limit = q.limit();
    let offset = q.offset();

    let rows = sqlx::query!(
        r#"SELECT
               id, env_id, client_id, client_name,
               redirect_uris, grant_types, response_types,
               token_endpoint_auth_method, scopes, status,
               created_at, updated_at
           FROM oauth_clients
           WHERE env_id = $1
           ORDER BY created_at DESC
           LIMIT $2 OFFSET $3"#,
        auth.env_id,
        limit,
        offset,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*)::BIGINT FROM oauth_clients WHERE env_id = $1"#,
        auth.env_id
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .unwrap_or(0);

    let clients = rows
        .into_iter()
        .map(|r| OAuthClientResponse {
            id: r.id,
            env_id: r.env_id,
            client_id: r.client_id,
            client_name: r.client_name,
            redirect_uris: r.redirect_uris,
            grant_types: r.grant_types,
            response_types: r.response_types,
            token_endpoint_auth_method: r.token_endpoint_auth_method,
            scopes: r.scopes,
            status: r.status,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect();

    Ok(Json(OAuthClientListResponse { clients, total }))
}

/// `POST /v1/admin/oauth-clients` - create an OAuth client.
#[utoipa::path(
    post,
    operation_id = "application.register",
    path = "/v1/admin/oauth-clients",
    params(("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin")),
    request_body = CreateOAuthClientRequest,
    responses(
        (status = 201, description = "OAuth client created", body = OAuthClientResponse),
        (status = 400, description = "client_id and client_name are required"),
        (status = 409, description = "client_id already exists"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Create OAuth client.
pub async fn create_oauth_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Json(req): Json<CreateOAuthClientRequest>,
) -> Result<Response, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    if req.client_id.is_empty() || req.client_name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "client_id and client_name are required".into(),
        ));
    }

    let secret_hash = match req.client_secret {
        Some(ref s) if !s.is_empty() => Some(
            bcrypt_hash(s, DEFAULT_COST)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        ),
        _ => None,
    };
    let grant_types = if req.grant_types.is_empty() {
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ]
    } else {
        req.grant_types
    };
    let response_types = if req.response_types.is_empty() {
        vec!["code".to_string()]
    } else {
        req.response_types
    };

    let row = sqlx::query!(
        r#"INSERT INTO oauth_clients
               (env_id, client_id, client_name,
                client_secret_hash, redirect_uris, grant_types, response_types,
                token_endpoint_auth_method, scopes, consent_required)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
           RETURNING
               id, env_id, client_id, client_name,
               redirect_uris, grant_types, response_types,
               token_endpoint_auth_method, scopes, status,
               consent_required,
               created_at, updated_at"#,
        _auth.env_id,
        req.client_id,
        req.client_name,
        secret_hash,
        &req.redirect_uris,
        &grant_types,
        &response_types,
        req.token_endpoint_auth_method,
        &req.scopes,
        req.consent_required,
    )
    .fetch_one(&mut *conn)
    .await;

    let row = match row {
        Ok(r) => r,
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
            return Err((StatusCode::CONFLICT, "client_id already exists".into()));
        }
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };

    //- emit client.created event to Bus outbox.
    crate::events::emit_event_tx(
        &mut conn,
        row.env_id,
        "sentin8:auth:client:created",
        serde_json::json!({ "client_id": row.id, "oauth_client_id": row.client_id.clone() }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resp = OAuthClientResponse {
        id: row.id,
        env_id: row.env_id,
        client_id: row.client_id,
        client_name: row.client_name,
        redirect_uris: row.redirect_uris,
        grant_types: row.grant_types,
        response_types: row.response_types,
        token_endpoint_auth_method: row.token_endpoint_auth_method,
        scopes: row.scopes,
        status: row.status,
        created_at: row.created_at,
        updated_at: row.updated_at,
    };

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

/// `GET /v1/admin/oauth-clients/{id}` - get an OAuth client by ID.
#[utoipa::path(
    get,
    path = "/v1/admin/oauth-clients/{id}",
    params(
        ("id" = Uuid, Path, description = "OAuth client ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 200, description = "OAuth client", body = OAuthClientResponse),
        (status = 404, description = "OAuth client not found"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Fetch OAuth client.
pub async fn get_oauth_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<Json<OAuthClientResponse>, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let row = sqlx::query!(
        r#"SELECT
               id, env_id, client_id, client_name,
               redirect_uris, grant_types, response_types,
               token_endpoint_auth_method, scopes, status,
               created_at, updated_at
           FROM oauth_clients WHERE id = $1"#,
        id,
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match row {
        Some(r) => Ok(Json(OAuthClientResponse {
            id: r.id,
            env_id: r.env_id,
            client_id: r.client_id,
            client_name: r.client_name,
            redirect_uris: r.redirect_uris,
            grant_types: r.grant_types,
            response_types: r.response_types,
            token_endpoint_auth_method: r.token_endpoint_auth_method,
            scopes: r.scopes,
            status: r.status,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })),
        None => Err((StatusCode::NOT_FOUND, "OAuth client not found".into())),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for updateoauthclient.
pub struct UpdateOAuthClientRequest {
    #[serde(default)]
    /// The client name.
    pub client_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_opt_permissions")]
    /// The redirect uris.
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_opt_permissions")]
    /// The grant types.
    pub grant_types: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_opt_permissions")]
    /// The response types.
    pub response_types: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_opt_permissions")]
    /// The scopes.
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    /// The status.
    pub status: Option<String>,
    #[serde(default)]
    /// The consent required.
    pub consent_required: Option<bool>,
}

/// `PUT /v1/admin/oauth-clients/{id}` - update an OAuth client.
#[utoipa::path(
    put,
    path = "/v1/admin/oauth-clients/{id}",
    params(
        ("id" = Uuid, Path, description = "OAuth client ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    request_body = UpdateOAuthClientRequest,
    responses(
        (status = 200, description = "OAuth client updated", body = OAuthClientResponse),
        (status = 404, description = "OAuth client not found"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Update OAuth client.
pub async fn update_oauth_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateOAuthClientRequest>,
) -> Result<Json<OAuthClientResponse>, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let row = sqlx::query!(
        r#"UPDATE oauth_clients SET
               client_name = COALESCE($2, client_name),
               redirect_uris = COALESCE($3, redirect_uris),
               grant_types = COALESCE($4, grant_types),
               response_types = COALESCE($5, response_types),
               scopes = COALESCE($6, scopes),
               status = COALESCE($7, status),
               updated_at = now()
           WHERE id = $1
           RETURNING
               id, env_id, client_id, client_name,
               redirect_uris, grant_types, response_types,
               token_endpoint_auth_method, scopes, status,
               created_at, updated_at"#,
        id,
        req.client_name,
        req.redirect_uris.as_deref(),
        req.grant_types.as_deref(),
        req.response_types.as_deref(),
        req.scopes.as_deref(),
        req.status,
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match row {
        Some(r) => {
            crate::events::emit_event_tx(
                &mut conn,
                r.env_id,
                "sentin8:auth:client:updated",
                serde_json::json!({ "client_id": id }),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let _ = conn.commit().await; // SEC-2.4.8 - persist the write
            Ok(Json(OAuthClientResponse {
                id: r.id,
                env_id: r.env_id,
                client_id: r.client_id,
                client_name: r.client_name,
                redirect_uris: r.redirect_uris,
                grant_types: r.grant_types,
                response_types: r.response_types,
                token_endpoint_auth_method: r.token_endpoint_auth_method,
                scopes: r.scopes,
                status: r.status,
                created_at: r.created_at,
                updated_at: r.updated_at,
            }))
        }
        None => Err((StatusCode::NOT_FOUND, "OAuth client not found".into())),
    }
}

/// `DELETE /v1/admin/oauth-clients/{id}` - delete an OAuth client.
#[utoipa::path(
    delete,
    path = "/v1/admin/oauth-clients/{id}",
    params(
        ("id" = Uuid, Path, description = "OAuth client ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 204, description = "OAuth client deleted"),
        (status = 404, description = "OAuth client not found"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Delete OAuth client.
pub async fn delete_oauth_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let result = sqlx::query!("DELETE FROM oauth_clients WHERE id = $1", id)
        .execute(&mut *conn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        Err((StatusCode::NOT_FOUND, "OAuth client not found".into()))
    } else {
        crate::events::emit_event_tx(
            &mut conn,
            _auth.env_id,
            "sentin8:auth:client:deleted",
            serde_json::json!({ "client_id": id }),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = conn.commit().await; // SEC-2.4.8 - persist the write
        Ok(StatusCode::NO_CONTENT)
    }
}

// ── Client Roles (app-role assignments to M2M clients) ────────────────
// Assigns a Role to an OAuth client (service principal). The client's
// M2M token scope = own scopes ∪ assigned roles' permissions (resolved
// over sentin8_auth_role_nesting). See auth design.

#[derive(Serialize, ToSchema)]
/// Response payload for clientrole.
pub struct ClientRoleResponse {
    /// client identifier.
    pub client_id: Uuid,
    /// role identifier.
    pub role_id: Uuid,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/admin/oauth-clients/{id}/roles` - list roles assigned to an OAuth client.
#[utoipa::path(
    get,
    path = "/v1/admin/oauth-clients/{id}/roles",
    params(
        ("id" = Uuid, Path, description = "OAuth client ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 200, description = "Client roles", body = [ClientRoleResponse]),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List client roles.
pub async fn list_client_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(client_id): Path<Uuid>,
) -> Result<Json<Vec<ClientRoleResponse>>, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let rows = sqlx::query!(
        r#"SELECT client_id, role_id, created_at FROM client_roles WHERE client_id = $1"#,
        client_id,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let roles = rows
        .into_iter()
        .map(|r| ClientRoleResponse {
            client_id: r.client_id,
            role_id: r.role_id,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(roles))
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for addclientrole.
pub struct AddClientRoleRequest {
    /// role identifier.
    pub role_id: Uuid,
}

/// `POST /v1/admin/oauth-clients/{id}/roles` - assign a role to an OAuth client.
#[utoipa::path(
    post,
    path = "/v1/admin/oauth-clients/{id}/roles",
    params(
        ("id" = Uuid, Path, description = "OAuth client ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    request_body = AddClientRoleRequest,
    responses(
        (status = 201, description = "Role assigned"),
        (status = 404, description = "OAuth client not found"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Handle add client role.
pub async fn add_client_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(client_id): Path<Uuid>,
    Json(req): Json<AddClientRoleRequest>,
) -> Result<Response, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    // Denormalize env_id from the client for direct RLS predicates.
    let client = sqlx::query!(
        r#"SELECT env_id FROM oauth_clients WHERE id = $1"#,
        client_id,
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let client = match client {
        Some(c) => c,
        None => return Err((StatusCode::NOT_FOUND, "OAuth client not found".into())),
    };

    sqlx::query!(
        r#"INSERT INTO client_roles (client_id, role_id, env_id)
           VALUES ($1, $2, $3)
           ON CONFLICT (client_id, role_id) DO NOTHING"#,
        client_id,
        req.role_id,
        client.env_id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    crate::events::emit_event_tx(
        &mut conn,
        _auth.env_id,
        "sentin8:auth:client:role:added",
        serde_json::json!({ "client_id": client_id, "role_id": req.role_id }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok(StatusCode::CREATED.into_response())
}

/// `DELETE /v1/admin/oauth-clients/{id}/roles/{role_id}` - remove a role from an OAuth client.
#[utoipa::path(
    delete,
    path = "/v1/admin/oauth-clients/{id}/roles/{role_id}",
    params(
        ("id" = Uuid, Path, description = "OAuth client ID"),
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 204, description = "Role removed"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Remove client role.
pub async fn remove_client_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path((client_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    sqlx::query!(
        "DELETE FROM client_roles WHERE client_id = $1 AND role_id = $2",
        client_id,
        role_id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    crate::events::emit_event_tx(
        &mut conn,
        _auth.env_id,
        "sentin8:auth:client:role:removed",
        serde_json::json!({ "client_id": client_id, "role_id": role_id }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok(StatusCode::NO_CONTENT)
}

// ── Federated Credentials (workload-identity trusts) ──────────────────
// Trust records on an OAuth client. Auth mints an M2M token for the
// client when presented with an external JWT whose iss/sub/aud match.
// See auth design

#[derive(Serialize, ToSchema)]
/// Response payload for federatedcredential.
pub struct FederatedCredentialResponse {
    /// Identifier.
    pub id: Uuid,
    /// client identifier.
    pub client_id: Uuid,
    /// The issuer.
    pub issuer: String,
    /// The subject.
    pub subject: String,
    /// The audience.
    pub audience: String,
    /// The description.
    pub description: String,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/admin/oauth-clients/{id}/federated-credentials` - list federated credentials for an OAuth client.
#[utoipa::path(
    get,
    path = "/v1/admin/oauth-clients/{id}/federated-credentials",
    params(
        ("id" = Uuid, Path, description = "OAuth client ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 200, description = "Federated credentials", body = [FederatedCredentialResponse]),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List federated credentials.
pub async fn list_federated_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(client_id): Path<Uuid>,
) -> Result<Json<Vec<FederatedCredentialResponse>>, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let rows = sqlx::query!(
        r#"SELECT id, client_id, issuer, subject, audience, description, created_at
           FROM federated_credentials WHERE client_id = $1"#,
        client_id,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let creds = rows
        .into_iter()
        .map(|r| FederatedCredentialResponse {
            id: r.id,
            client_id: r.client_id,
            issuer: r.issuer,
            subject: r.subject,
            audience: r.audience,
            description: r.description,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(creds))
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for createfederatedcredential.
pub struct CreateFederatedCredentialRequest {
    /// The issuer.
    pub issuer: String,
    /// The subject.
    pub subject: String,
    #[serde(default)]
    /// The audience.
    pub audience: String,
    #[serde(default)]
    /// The description.
    pub description: String,
}

/// `POST /v1/admin/oauth-clients/{id}/federated-credentials` - create a federated credential.
#[utoipa::path(
    post,
    path = "/v1/admin/oauth-clients/{id}/federated-credentials",
    params(
        ("id" = Uuid, Path, description = "OAuth client ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    request_body = CreateFederatedCredentialRequest,
    responses(
        (status = 201, description = "Federated credential created", body = FederatedCredentialResponse),
        (status = 400, description = "issuer and subject are required"),
        (status = 404, description = "OAuth client not found"),
        (status = 409, description = "federated credential already exists"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Create federated credential.
pub async fn create_federated_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(client_id): Path<Uuid>,
    Json(req): Json<CreateFederatedCredentialRequest>,
) -> Result<Response, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    if req.issuer.is_empty() || req.subject.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "issuer and subject are required".into(),
        ));
    }
    // Denormalize env_id from the client for direct RLS predicates.
    let client = sqlx::query!(
        r#"SELECT env_id FROM oauth_clients WHERE id = $1"#,
        client_id,
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let client = match client {
        Some(c) => c,
        None => return Err((StatusCode::NOT_FOUND, "OAuth client not found".into())),
    };

    let row = sqlx::query!(
        r#"INSERT INTO federated_credentials
               (client_id, env_id, issuer, subject, audience, description)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id, client_id, issuer, subject, audience, description, created_at"#,
        client_id,
        client.env_id,
        req.issuer,
        req.subject,
        req.audience,
        req.description,
    )
    .fetch_one(&mut *conn)
    .await;

    let row = match row {
        Ok(r) => r,
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
            return Err((
                StatusCode::CONFLICT,
                "federated credential already exists for this (client, issuer, subject)".into(),
            ));
        }
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };

    crate::events::emit_event_tx(
        &mut conn,
        client.env_id,
        "sentin8:auth:credential:created",
        serde_json::json!({ "credential_id": row.id, "client_id": row.client_id, "issuer": row.issuer, "subject": row.subject }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resp = FederatedCredentialResponse {
        id: row.id,
        client_id: row.client_id,
        issuer: row.issuer,
        subject: row.subject,
        audience: row.audience,
        description: row.description,
        created_at: row.created_at,
    };

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

/// `DELETE /v1/admin/oauth-clients/{id}/federated-credentials/{cred_id}` - delete a federated credential.
#[utoipa::path(
    delete,
    path = "/v1/admin/oauth-clients/{id}/federated-credentials/{cred_id}",
    params(
        ("id" = Uuid, Path, description = "OAuth client ID"),
        ("cred_id" = Uuid, Path, description = "Federated credential ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 204, description = "Federated credential deleted"),
        (status = 404, description = "federated credential not found"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Delete federated credential.
pub async fn delete_federated_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path((client_id, cred_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let result = sqlx::query!(
        "DELETE FROM federated_credentials WHERE id = $1 AND client_id = $2",
        cred_id,
        client_id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        Err((
            StatusCode::NOT_FOUND,
            "federated credential not found".into(),
        ))
    } else {
        crate::events::emit_event_tx(
            &mut conn,
            _auth.env_id,
            "sentin8:auth:credential:deleted",
            serde_json::json!({ "credential_id": cred_id, "client_id": client_id }),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = conn.commit().await; // SEC-2.4.8 - persist the write
        Ok(StatusCode::NO_CONTENT)
    }
}

// ── User introspection (roles + groups) ───────────────────────────────
// Admin endpoints returning the resolved Roles/Groups for a user. Used
// by Dash and clients that want role/group names without the JWT (the
// JWT only carries `scope`). See auth design.

/// `GET /v1/admin/users/{id}/roles` - list resolved role names for a user.
#[utoipa::path(
    get,
    operation_id = "user.roles",
    path = "/v1/admin/users/{id}/roles",
    params(
        ("id" = Uuid, Path, description = "User ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 200, description = "Resolved role names", body = [String]),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List user roles.
pub async fn list_user_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<String>>, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let scopes = fetch_role_scopes(&state.pool, user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Returns the resolved scope set; for role names, resolve the names of
    // roles granted directly or via groups.
    let rows = sqlx::query!(
        r#"WITH RECURSIVE seed_roles AS (
                SELECT r.id, r.name
                FROM roles r
                JOIN user_roles ur ON ur.role_id = r.id
                WHERE ur.user_id = $1
                UNION ALL
                SELECT gr.role_id AS id, r.name
                FROM group_members gm
                JOIN group_roles gr ON gr.group_id = gm.group_id
                JOIN roles r ON r.id = gr.role_id
                WHERE gm.user_id = $1
            ),
            role_closure AS (
                SELECT id, name FROM seed_roles
                UNION ALL
                SELECT child.id, child.name
                FROM roles child
                JOIN role_nesting nest ON nest.child_role_id = child.id
                JOIN role_closure parent ON parent.id = nest.parent_role_id
            )
            SELECT DISTINCT name FROM role_closure ORDER BY name"#,
        user_id,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let names: Vec<String> = rows.into_iter().filter_map(|r| r.name).collect();
    // Suppress unused-warning while keeping the scope-resolution path
    // documented (clients may want the scope set instead).
    let _ = scopes;
    Ok(Json(names))
}

/// `GET /v1/admin/users/{id}/groups` - list group names for a user.
#[utoipa::path(
    get,
    operation_id = "user.groups",
    path = "/v1/admin/users/{id}/groups",
    params(
        ("id" = Uuid, Path, description = "User ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 200, description = "Group names", body = [String]),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List user groups.
pub async fn list_user_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<String>>, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let rows = sqlx::query!(
        r#"SELECT g.name FROM groups g
           JOIN group_members gm ON gm.group_id = g.id
           WHERE gm.user_id = $1
           ORDER BY g.name"#,
        user_id,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let names: Vec<String> = rows.into_iter().map(|r| r.name).collect();
    Ok(Json(names))
}

// ── API Keys CRUD ───────────────────────────────────────

#[derive(Serialize, ToSchema)]
/// Response payload for apikey.
pub struct ApiKeyResponse {
    /// Identifier.
    pub id: Uuid,
    /// env identifier.
    pub env_id: Uuid,
    /// user identifier.
    pub user_id: Option<Uuid>,
    /// The name.
    pub name: String,
    /// The key prefix.
    pub key_prefix: String,
    /// The scopes.
    pub scopes: Vec<String>,
    /// The status.
    pub status: String,
    /// expires time.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// The last used at.
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize, ToSchema)]
/// Response payload for apikeylist.
pub struct ApiKeyListResponse {
    /// The API keys.
    pub api_keys: Vec<ApiKeyResponse>,
    /// The total count.
    pub total: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for createapikey.
pub struct CreateApiKeyRequest {
    /// Optional - the RFW form does not send it (env is resolved from the
    /// token's tenant context); the auth-context env is used when absent.
    #[serde(default)]
    /// env identifier.
    pub env_id: Option<Uuid>,
    #[serde(default)]
    /// user identifier.
    pub user_id: Option<Uuid>,
    /// The name.
    pub name: String,
    /// Accepts either a JSON array or a single comma-separated string -
    /// the RFW form sends text fields as strings (the field label is
    /// "Scopes (comma-separated)"). Same contract as role permissions.
    #[serde(default, deserialize_with = "deserialize_permissions")]
    /// The scopes.
    pub scopes: Vec<String>,
    #[serde(default)]
    /// expires time.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// `GET /v1/admin/api-keys` - list API keys (paginated).
#[utoipa::path(
    get,
    operation_id = "api-key.list",
    path = "/v1/admin/api-keys",
    params(
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Paginated API key list", body = ApiKeyListResponse),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List API keys.
pub async fn list_api_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Query(q): Query<PaginationQuery>,
) -> Result<Json<ApiKeyListResponse>, (StatusCode, String)> {
    let auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire: sentin8_set_tenant_context
    // uses set_config(..., true) which is TRANSACTION-local - outside a
    // transaction it evaporates and RLS denies every write. All queries for
    // this request run inside this transaction on the same connection.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, auth.env_id).await;
    let limit = q.limit();
    let offset = q.offset();

    let rows = sqlx::query!(
        r#"SELECT
               id, env_id, user_id, name,
               key_prefix, scopes, status, expires_at, created_at, last_used_at
           FROM api_keys
           WHERE env_id = $1
           ORDER BY created_at DESC
           LIMIT $2 OFFSET $3"#,
        auth.env_id,
        limit,
        offset,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*)::BIGINT FROM api_keys WHERE env_id = $1"#,
        auth.env_id
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .unwrap_or(0);

    let keys = rows
        .into_iter()
        .map(|r| ApiKeyResponse {
            id: r.id,
            env_id: r.env_id,
            user_id: r.user_id,
            name: r.name,
            key_prefix: r.key_prefix,
            scopes: r.scopes,
            status: r.status,
            expires_at: r.expires_at,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
        })
        .collect();

    Ok(Json(ApiKeyListResponse {
        api_keys: keys,
        total,
    }))
}

/// `POST /v1/admin/api-keys` - create an API key.
#[utoipa::path(
    post,
    operation_id = "api-key.create",
    path = "/v1/admin/api-keys",
    params(("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin")),
    request_body = CreateApiKeyRequest,
    responses(
        (status = 201, description = "API key created (includes plaintext key)"),
        (status = 400, description = "name is required"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Create API key.
pub async fn create_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<Response, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    if req.name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "name is required".into()));
    }

    let key_value = format!("sentin8_{}", uuid::Uuid::new_v4().simple());
    let key_prefix = &key_value[..16];
    let key_hash = bcrypt_hash(&key_value, DEFAULT_COST)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row = sqlx::query!(
        r#"INSERT INTO api_keys
               (env_id, user_id, name,
                key_prefix, key_hash, scopes, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING
               id, env_id, user_id, name,
               key_prefix, scopes, status, expires_at, created_at, last_used_at"#,
        req.env_id.unwrap_or(_auth.env_id),
        req.user_id,
        req.name,
        key_prefix,
        key_hash,
        &req.scopes,
        req.expires_at,
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    //- emit apikey.created event to Bus outbox.
    crate::events::emit_event_tx(
        &mut conn,
        row.env_id,
        "sentin8:auth:apikey:created",
        serde_json::json!({ "api_key_id": row.id, "user_id": row.user_id, "name": row.name.clone() }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resp = serde_json::json!({
        "id": row.id, "env_id": row.env_id,
        "user_id": row.user_id, "name": row.name, "key_prefix": row.key_prefix,
        "key": key_value, "scopes": row.scopes, "status": row.status,
        "expires_at": row.expires_at, "created_at": row.created_at, "last_used_at": row.last_used_at,
    });

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

/// `POST /v1/admin/api-keys/{id}/revoke` - revoke an API key.
#[utoipa::path(
    post,
    operation_id = "api-key.revoke",
    path = "/v1/admin/api-keys/{id}/revoke",
    params(
        ("id" = Uuid, Path, description = "API key ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 204, description = "API key revoked"),
        (status = 404, description = "API key not found"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Revoke API key.
pub async fn revoke_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let result = sqlx::query!(
        r#"UPDATE api_keys SET status = 'revoked' WHERE id = $1"#,
        id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        Err((StatusCode::NOT_FOUND, "API key not found".into()))
    } else {
        //- emit apikey.revoked event to Bus outbox.
        crate::events::emit_event_tx(
            &mut conn,
            _auth.env_id,
            "sentin8:auth:apikey:revoked",
            serde_json::json!({ "api_key_id": id }),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = conn.commit().await; // SEC-2.4.8 - persist the write
        Ok(StatusCode::NO_CONTENT)
    }
}

// ── Sessions List/Revoke ─────────────────────────────────

#[derive(Serialize, ToSchema)]
/// Response payload for sessionadmin.
pub struct SessionAdminResponse {
    /// Identifier.
    pub id: Uuid,
    /// user identifier.
    pub user_id: Uuid,
    /// env identifier.
    pub env_id: Uuid,
    /// token identifier.
    pub token_id: String,
    /// The status.
    pub status: String,
    /// expires time.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// updated time.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, ToSchema)]
/// Response payload for sessionlist.
pub struct SessionListResponse {
    /// The sessions.
    pub sessions: Vec<SessionAdminResponse>,
    /// The total count.
    pub total: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
/// The sessionquery type.
pub struct SessionQuery {
    #[serde(default)]
    /// user identifier.
    pub user_id: Option<Uuid>,
    #[serde(default = "default_page")]
    /// The page.
    pub page: i64,
    #[serde(default = "default_page_size")]
    /// The page size.
    pub page_size: i64,
}

/// `GET /v1/admin/sessions` - list sessions (paginated).
#[utoipa::path(
    get,
    operation_id = "session.list",
    path = "/v1/admin/sessions",
    params(
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
        ("user_id" = Option<Uuid>, Query, description = "Filter by user ID"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Paginated session list", body = SessionListResponse),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List sessions.
pub async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Query(q): Query<SessionQuery>,
) -> Result<Json<SessionListResponse>, (StatusCode, String)> {
    let auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire: sentin8_set_tenant_context
    // uses set_config(..., true) which is TRANSACTION-local - outside a
    // transaction it evaporates and RLS denies every write. All queries for
    // this request run inside this transaction on the same connection.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, auth.env_id).await;
    let limit = q.page_size.min(200);
    let offset = (q.page - 1).max(0) * limit;

    let rows = sqlx::query!(
        r#"SELECT
               id, user_id, env_id,
               token_id, status, expires_at, created_at, updated_at
           FROM sessions
           WHERE env_id = $1
             AND ($2::uuid IS NULL OR user_id = $2)
           ORDER BY created_at DESC
           LIMIT $3 OFFSET $4"#,
        auth.env_id,
        q.user_id,
        limit,
        offset,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*)::BIGINT FROM sessions
           WHERE env_id = $1
             AND ($2::uuid IS NULL OR user_id = $2)"#,
        auth.env_id,
        q.user_id,
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .unwrap_or(0);

    let sessions = rows
        .into_iter()
        .map(|r| SessionAdminResponse {
            id: r.id,
            user_id: r.user_id,
            env_id: r.env_id,
            token_id: r.token_id,
            status: r.status,
            expires_at: r.expires_at,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect();

    Ok(Json(SessionListResponse { sessions, total }))
}

/// `DELETE /v1/admin/sessions/{id}` - terminate a session.
#[utoipa::path(
    delete,
    operation_id = "session.terminate",
    path = "/v1/admin/sessions/{id}",
    params(
        ("id" = Uuid, Path, description = "Session ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 204, description = "Session terminated"),
        (status = 404, description = "session not found"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Terminate session.
pub async fn terminate_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;
    let result = sqlx::query!(
        r#"UPDATE sessions SET status = 'revoked', updated_at = now() WHERE id = $1"#,
        id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        Err((StatusCode::NOT_FOUND, "session not found".into()))
    } else {
        // Continuous access evaluation (auth DESIGN §10): payload-complete
        // `session:revoked` envelope - the BFF session-reaper kills the
        // cached BFF session for this subject. Same transaction as the
        // UPDATE (§6.7).
        let _ = crate::events::emit_session_revoked(
            &mut conn,
            _auth.env_id,
            &_auth.claims.sub,
            Some(&id.to_string()),
            "admin_terminate",
        )
        .await;
        //- emit session.terminated event to Bus outbox.
        crate::events::emit_event_tx(
            &mut conn,
            _auth.env_id,
            "sentin8:auth:session:terminated",
            serde_json::json!({ "session_id": id }),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = conn.commit().await; // SEC-2.4.8 - persist the write
        Ok(StatusCode::NO_CONTENT)
    }
}

// ── Memberships & Invitations ───────────────────────────

#[derive(Serialize, ToSchema)]
/// Response payload for membership.
pub struct MembershipResponse {
    /// Identifier.
    pub id: Uuid,
    /// user identifier.
    pub user_id: Uuid,
    /// org identifier.
    pub org_id: Uuid,
    /// The role.
    pub role: String,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/admin/memberships` - list memberships.
#[utoipa::path(
    get,
    operation_id = "membership.list",
    path = "/v1/admin/memberships",
    params(
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Memberships", body = [MembershipResponse]),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List memberships.
pub async fn list_memberships(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Query(q): Query<PaginationQuery>,
) -> Result<Json<Vec<MembershipResponse>>, (StatusCode, String)> {
    let auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire: sentin8_set_tenant_context
    // uses set_config(..., true) which is TRANSACTION-local - outside a
    // transaction it evaporates and RLS denies every write. All queries for
    // this request run inside this transaction on the same connection.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, auth.env_id).await;

    // List users with roles or group memberships in the target env.
    use sqlx::Row as _;
    let rows = sqlx::query(
        r#"SELECT DISTINCT u.id AS user_id, u.email, u.first_name, u.last_name
           FROM users u
           WHERE EXISTS (
               SELECT 1 FROM user_roles ur
               JOIN roles r ON r.id = ur.role_id
               WHERE ur.user_id = u.id AND r.env_id = $1
               UNION
               SELECT 1 FROM group_members gm
               JOIN groups g ON g.id = gm.group_id
               WHERE gm.user_id = u.id AND g.env_id = $1
           )
           ORDER BY u.email
           LIMIT $2 OFFSET $3"#,
    )
    .bind(auth.env_id)
    .bind(q.limit())
    .bind(q.offset())
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let memberships = rows
        .into_iter()
        .map(|r| MembershipResponse {
            id: r.get("user_id"),
            user_id: r.get("user_id"),
            org_id: auth.org_id,
            role: "member".into(),
            created_at: chrono::Utc::now(),
        })
        .collect();

    Ok(Json(memberships))
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for createmembership.
pub struct CreateMembershipRequest {
    /// user identifier.
    pub user_id: Uuid,
    /// org identifier.
    pub org_id: Uuid,
    #[serde(default = "default_role")]
    /// The role.
    pub role: String,
}

fn default_role() -> String {
    "member".into()
}

/// `POST /v1/admin/memberships` - create a membership.
#[utoipa::path(
    post,
    path = "/v1/admin/memberships",
    params(("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin")),
    request_body = CreateMembershipRequest,
    responses(
        (status = 201, description = "Membership created", body = MembershipResponse),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Create membership.
pub async fn create_membership(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Json(req): Json<CreateMembershipRequest>,
) -> Result<Response, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire (see the note above).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, _auth.env_id).await;

    // Assign the org-admin role to the user (RBAC replaces sentin8_sys_memberships).
    let row = sqlx::query(
        r#"INSERT INTO user_roles (role_id, user_id, env_id)
           SELECT r.id, $2, r.env_id
           FROM roles r
           WHERE r.name = 'sentin8:org:admin' AND r.env_id = $1
             AND NOT EXISTS (
               SELECT 1 FROM user_roles ur
               WHERE ur.role_id = r.id AND ur.user_id = $2
             )
           RETURNING user_id"#,
    )
    .bind(_auth.env_id)
    .bind(req.user_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    use sqlx::Row as _;
    let user_id: Uuid = row.get("user_id");
    //- emit membership.created event to Bus outbox.
    crate::events::emit_event_tx(
        &mut conn,
        _auth.env_id,
        "sentin8:auth:membership:created",
        serde_json::json!({ "user_id": user_id, "org_id": req.org_id, "role": req.role.clone() }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Identity-cache invalidation (policy design -1, outbox-first):
    // the user just received a role - every service's policy runtime must
    // drop its cached pre-grant identity. Transport: policy consumers are
    // M2M clients registered in the SYSTEM env, so the event rides the
    // system-env `policy` stream; the env to sweep rides in the payload.
    // DBX : local auth.outbox row (family `policy`); the relay pushes
    // it to Bus POST /v1/produce - no definer function, no inbox RLS gate.
    if let Err(e) = sentin8::bus::outbox::insert_outbox_row(
        &mut *conn,
        sentin8::config::SYSTEM_ENV_ID,
        "policy",
        "sentin8:auth:membership:created",
        &serde_json::json!({ "env_id": _auth.env_id, "user_id": user_id }),
    )
    .await
    {
        tracing::error!(error = %e, "auth: failed to emit policy identity event (invalidation degrades to 30s TTL)");
    }

    let resp = MembershipResponse {
        id: user_id,
        user_id,
        org_id: req.org_id,
        role: req.role,
        created_at: chrono::Utc::now(),
    };

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

/// `DELETE /v1/admin/memberships/{id}` - delete a membership.
#[utoipa::path(
    delete,
    path = "/v1/admin/memberships/{id}",
    params(
        ("id" = Uuid, Path, description = "User ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 204, description = "Membership deleted"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Delete membership.
pub async fn delete_membership(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire: sentin8_set_tenant_context
    // uses set_config(..., true) which is TRANSACTION-local - outside a
    // transaction it evaporates and RLS denies every write. All queries for
    // this request run inside this transaction on the same connection.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, auth.env_id).await;

    // Remove all role assignments and group memberships for this user in the env.
    let _ = sqlx::query(
        r#"DELETE FROM user_roles
           WHERE user_id = $1
             AND role_id IN (SELECT id FROM roles WHERE env_id = $2)"#,
    )
    .bind(id)
    .bind(auth.env_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let _ = sqlx::query(
        r#"DELETE FROM group_members
           WHERE user_id = $1
             AND group_id IN (SELECT id FROM groups WHERE env_id = $2)"#,
    )
    .bind(id)
    .bind(auth.env_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    //- emit membership.deleted event to Bus outbox.
    crate::events::emit_event_tx(
        &mut conn,
        auth.env_id,
        "sentin8:auth:membership:deleted",
        serde_json::json!({ "user_id": id, "org_id": auth.org_id }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Identity-cache invalidation (policy design -1, outbox-first) -
    // a revoked membership must take effect on the next request, not after
    // the 30s resolver TTL. System-env `policy` stream (consumer transport);
    // DBX : local auth.outbox row (family `policy`); the relay pushes
    // it to Bus POST /v1/produce - no definer function, no inbox RLS gate.
    if let Err(e) = sentin8::bus::outbox::insert_outbox_row(
        &mut *conn,
        sentin8::config::SYSTEM_ENV_ID,
        "policy",
        "sentin8:auth:membership:deleted",
        &serde_json::json!({ "env_id": auth.env_id, "user_id": id }),
    )
    .await
    {
        tracing::error!(error = %e, "auth: failed to emit policy identity event (invalidation degrades to 30s TTL)");
    }

    let _ = conn.commit().await; // SEC-2.4.8 - persist the write
    Ok(StatusCode::NO_CONTENT)
}

// ── Invitations ────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
/// Response payload for invitation.
pub struct InvitationResponse {
    /// Identifier.
    pub id: Uuid,
    /// org identifier.
    pub org_id: Uuid,
    /// The email.
    pub email: String,
    /// The role.
    pub role: String,
    /// The status.
    pub status: String,
    /// The token.
    pub token: String,
    /// expires time.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for createinvitation.
pub struct CreateInvitationRequest {
    #[serde(default)]
    /// org identifier.
    pub org_id: Option<Uuid>,
    /// The email.
    pub email: String,
    #[serde(default = "default_role")]
    /// The role.
    pub role: String,
    /// TTL in days. RFW forms submit number fields as strings ("7") -
    /// accept both JSON numbers and numeric strings.
    #[serde(
        default = "default_invitation_ttl_days",
        deserialize_with = "deserialize_i64_lenient"
    )]
    /// The ttl days.
    pub ttl_days: i64,
}

fn default_invitation_ttl_days() -> i64 {
    7
}

/// Deserialize an i64 from either a JSON number or a numeric string
/// (RFW number fields submit text). Non-numeric strings fall back to 0 -
/// the handler's default (7) then applies via `unwrap_or`.
fn deserialize_i64_lenient<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Num {
        I(i64),
        F(f64),
        S(String),
    }
    Ok(match Num::deserialize(deserializer)? {
        Num::I(i) => i,
        Num::F(f) => f as i64,
        Num::S(s) => s.trim().parse::<i64>().unwrap_or(0),
    })
}

/// ── Invitations - sys-API proxy ───────────────────────────
/// Invitations are OWNED by Sentin8:Sys (`sys.invitations` - the lifecycle
/// lives with org/env provisioning). Auth's admin surface below is a thin
/// PROXY: the signed-in operator's request is re-issued to sys's
/// `/v1/org/{id}/invitations` endpoints with the `auth-sys` M2M token
/// (`sentin8:sys:memberships:admin`). Auth reads/writes ZERO invitation
/// rows - its grants on `sys.invitations` are retired (platform.sql).
/// The URL surface is unchanged (dash admin UI + e2e call these paths).
///
/// Extract the raw Bearer token from request headers (for the delegated
/// token-exchange in [`sys_proxy_with_actor`]).
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// Fetch (or lazily DCR) the `auth-sys` M2M token and call sys.
///
/// Like [`sys_proxy`] but carries the ACTING USER through the hop: the
/// caller's user access token is exchanged (RFC 8693 token-exchange) for a
/// delegated token whose `act.sub` names the user, and THAT rides to Sys.
/// A plain auth-sys M2M token's `sub` is the client_id - Sys's org-membership
/// check resolves the acting USER from `act.sub` (RFC 8693), so without the
/// exchange the original caller's membership is invisible and every proxied
/// org-scoped call 403s. `acting_token` is the caller's own Bearer token
/// (None for pure service-to-service calls, which keep the M2M token).
async fn sys_proxy_with_actor(
    method: reqwest::Method,
    path_and_query: &str,
    body: Option<serde_json::Value>,
    acting_token: Option<&str>,
) -> Result<reqwest::Response, (StatusCode, String)> {
    // auth DESIGN §4.3f: the `auth-sys` CERTIFICATE is the
    // identity - the cert-presenting transport authenticates at Sys's TLS
    // layer; the registry map authorizes
    // `sentin8:sys:memberships:admin`.
    let issuer = sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer();
    let ca_cert_path = sentin8::auth::m2m::platform_ca_path();
    let cert = sentin8::auth::m2m::ensure_workload_certificate(
        &issuer,
        "auth-sys",
        &ca_cert_path,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "auth: auth-sys certificate ensure failed - sys proxy unavailable");
        (StatusCode::BAD_GATEWAY, format!("sys proxy identity: {e}"))
    })?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    let http = sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("sys proxy transport: {e}")))?;

    // Token-exchange: swap the USER's access token for a delegated token
    // carrying `act.sub` = the user (RFC 8693) - the delegated flow keeps
    // its JWT ( removes only the workload's own M2M token). The
    // call itself rides the cert-presenting transport.
    let delegated = match acting_token {
        Some(user_token) => {
            match crate::handlers::exchange_for_delegated(
                user_token,
                "sentin8:sys:memberships:admin",
            )
            .await
            {
                Ok(tok) => Some(tok),
                Err(e) => {
                    tracing::warn!(error = %e, "auth: user-token exchange for sys proxy failed - cert identity used directly");
                    None
                }
            }
        }
        None => None,
    };

    let sys_url = sentin8::config::Sentin8Config::from_env().sentin8_sys_url();
    let url = format!("{}{}", sys_url.trim_end_matches('/'), path_and_query);
    let mut req = http.request(method, &url);
    if let Some(tok) = delegated {
        req = req.bearer_auth(tok);
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    req.send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("sys proxy call: {e}")))
}

/// `GET /v1/admin/invitations` - list invitations (proxy → sys).
#[utoipa::path(
    get,
    path = "/v1/admin/invitations",
    params(
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Invitations", body = [InvitationResponse]),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List invitations.
pub async fn list_invitations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Query(q): Query<PaginationQuery>,
) -> Result<Json<Vec<InvitationResponse>>, (StatusCode, String)> {
    let auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    let _ = &q; // pagination handled by sys (fixed LIMIT 200 today)
    let resp = sys_proxy_with_actor(
        reqwest::Method::GET,
        &format!("/v1/org/{}/invitations", auth.org_id),
        None,
        bearer_token(&headers).as_deref(),
    )
    .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            format!("sys invitations list: {status} {body}"),
        ));
    }
    let raw: Vec<serde_json::Value> = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("sys decode: {e}")))?;
    // Map into the dash-facing shape (adds created_at: sys's list endpoint
    // keeps the same wire shape minus created_at - synthesize from now for
    // ordering stability; the UI shows email/role/status primarily).
    let invitations = raw
        .into_iter()
        .map(|v| InvitationResponse {
            id: v["id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .unwrap_or_default(),
            org_id: v["org_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .unwrap_or_default(),
            email: v["email"].as_str().unwrap_or_default().to_string(),
            role: v["role"].as_str().unwrap_or_default().to_string(),
            status: v["status"].as_str().unwrap_or_default().to_string(),
            token: v["token"].as_str().unwrap_or_default().to_string(),
            expires_at: v["expires_at"]
                .as_str()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&chrono::Utc))
                .unwrap_or_else(chrono::Utc::now),
            created_at: chrono::Utc::now(),
        })
        .collect();
    Ok(Json(invitations))
}

/// `POST /v1/admin/invitations` - create an invitation (proxy → sys).
#[utoipa::path(
    post,
    operation_id = "invitation.send",
    path = "/v1/admin/invitations",
    params(("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin")),
    request_body = CreateInvitationRequest,
    responses(
        (status = 201, description = "Invitation created", body = InvitationResponse),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Create invitation.
pub async fn create_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Json(req): Json<CreateInvitationRequest>,
) -> Result<Response, (StatusCode, String)> {
    let auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    let resp = sys_proxy_with_actor(
        reqwest::Method::POST,
        &format!("/v1/org/{}/invitations", auth.org_id),
        Some(serde_json::json!({ "email": req.email, "role": req.role })),
        bearer_token(&headers).as_deref(),
    )
    .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            format!("sys invitation create: {status} {body}"),
        ));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("sys decode: {e}")))?;
    let resp = InvitationResponse {
        id: v["id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .unwrap_or_default(),
        org_id: v["org_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .unwrap_or_default(),
        email: v["email"].as_str().unwrap_or_default().to_string(),
        role: v["role"].as_str().unwrap_or_default().to_string(),
        status: v["status"].as_str().unwrap_or_default().to_string(),
        token: v["token"].as_str().unwrap_or_default().to_string(),
        expires_at: v["expires_at"]
            .as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc::now().timezone()))
            .unwrap_or_else(chrono::Utc::now),
        created_at: chrono::Utc::now(),
    };
    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

/// `POST /v1/admin/invitations/{id}/revoke` - revoke an invitation
/// (proxy → sys).
#[utoipa::path(
    post,
    path = "/v1/admin/invitations/{id}/revoke",
    params(
        ("id" = Uuid, Path, description = "Invitation ID"),
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
    ),
    responses(
        (status = 204, description = "Invitation revoked"),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// Revoke invitation.
pub async fn revoke_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _auth =
        require_sentin8or_access_write(&state, &headers, teq.target_env_id.as_deref()).await?;
    let resp = sys_proxy_with_actor(
        reqwest::Method::POST,
        &format!("/v1/invitations/{id}/revoke"),
        None,
        bearer_token(&headers).as_deref(),
    )
    .await?;
    if resp.status().is_success() {
        Ok(StatusCode::NO_CONTENT)
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            format!("sys invitation revoke: {status} {body}"),
        ))
    }
}

// ── Audit Events Query ──────────────────────────────────

#[derive(Serialize, ToSchema)]
/// Response payload for auditevent.
pub struct AuditEventResponse {
    /// Identifier.
    pub id: Uuid,
    /// env identifier.
    pub env_id: Option<Uuid>,
    /// actor user identifier.
    pub actor_user_id: Option<String>,
    /// token identifier.
    pub token_id: Option<String>,
    /// correlation identifier.
    pub correlation_id: Option<String>,
    /// The action.
    pub action: String,
    /// The target resource type.
    pub target_resource_type: Option<String>,
    /// target resource identifier.
    pub target_resource_id: Option<String>,
    /// The timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// The schema version.
    pub schema_version: String,
}

#[derive(Serialize, ToSchema)]
/// Response payload for auditlist.
pub struct AuditListResponse {
    /// The events.
    pub events: Vec<AuditEventResponse>,
    /// The total count.
    pub total: i64,
    /// The page.
    pub page: i64,
    /// The page size.
    pub page_size: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
/// The auditquery type.
pub struct AuditQuery {
    #[serde(default)]
    /// The action.
    pub action: Option<String>,
    #[serde(default = "default_page")]
    /// The page.
    pub page: i64,
    #[serde(default = "default_page_size")]
    /// The page size.
    pub page_size: i64,
}

/// `GET /v1/admin/audit` - list audit events (paginated).
#[utoipa::path(
    get,
    operation_id = "audit.list",
    path = "/v1/admin/audit",
    params(
        ("target_env_id" = Option<String>, Query, description = "Target env for cross-env admin"),
        ("action" = Option<String>, Query, description = "Filter by action"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Paginated audit events", body = AuditListResponse),
        (status = 403, description = "Missing auth:admin scope"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "auth",
)]
/// List audit events.
pub async fn list_audit_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<AuditListResponse>, (StatusCode, String)> {
    let auth =
        require_sentin8or_access_with_env(&state, &headers, teq.target_env_id.as_deref()).await?;
    // SEC- - begin instead of acquire: sentin8_set_tenant_context
    // uses set_config(..., true) which is TRANSACTION-local - outside a
    // transaction it evaporates and RLS denies every write. All queries for
    // this request run inside this transaction on the same connection.
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, auth.env_id).await;
    let limit = q.page_size.min(200);
    let offset = (q.page - 1).max(0) * limit;

    let rows = sqlx::query!(
        r#"SELECT
               id, env_id, actor_user_id,
               token_id, correlation_id, action,
               target_resource_type, target_resource_id, timestamp, schema_version
           FROM audit_events
           WHERE env_id = $1
             AND ($2::text IS NULL OR action = $2)
           ORDER BY timestamp DESC
           LIMIT $3 OFFSET $4"#,
        auth.env_id,
        q.action,
        limit,
        offset,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*)::BIGINT FROM audit_events
           WHERE env_id = $1
             AND ($2::text IS NULL OR action = $2)"#,
        auth.env_id,
        q.action,
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .unwrap_or(0);

    let events = rows
        .into_iter()
        .map(|r| AuditEventResponse {
            id: r.id,
            env_id: Some(r.env_id),
            actor_user_id: r.actor_user_id,
            token_id: r.token_id,
            correlation_id: r.correlation_id,
            action: r.action,
            target_resource_type: r.target_resource_type,
            target_resource_id: r.target_resource_id,
            timestamp: r.timestamp,
            schema_version: r.schema_version,
        })
        .collect();

    Ok(Json(AuditListResponse {
        events,
        total,
        page: q.page,
        page_size: q.page_size,
    }))
}
