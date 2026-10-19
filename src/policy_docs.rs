// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Annotated thin wrappers for auth's inline-mounted Shield policy-admin
//! surface.
//!
//! Auth mounts the policy-admin routes inline (its own `AppState`, without
//! the shell's `Arc<AppState>` mount), and the underlying handlers are
//! GENERIC (`sentin8::shield::admin::*<T>`) - utoipa cannot reference a
//! generic handler from `paths()` (no turbofish support in 5.5). Each
//! route binds one of these concrete-state wrappers; the spec references
//! these (OAPEC design §2 rule 3). The wrappers add nothing: same handler
//! body, same gates, same state - only the concrete type is pinned.

use crate::handlers::AppState;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;

use sentin8::shield::admin::{
    check_relation, delete_attribute, delete_policy_set, delete_relation,
    get_policy_set, list_attributes, list_policy_sets, list_relations,
    put_attribute, put_policy_set, put_relation, admin_enforce_policy_set,
    admin_shadow_policy_set, admin_disable_policy_set, test_policy_set,
    PutAttributeBody, PutPolicySetBody, PutRelationBody,
};

/// `GET /v1/admin/policy-sets` - the env's policy sets.
#[utoipa::path(
    get,
    path = "/v1/admin/policy-sets",
    responses(
        (status = 200, description = "Policy sets of this service", body = Vec<serde_json::Value>),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("sentin8:admin" = [])),
    tag = "policy",
)]
pub async fn policy_list_sets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<sentin8::shield::admin::TargetEnv>,
) -> Result<Json<Vec<serde_json::Value>>, (axum::http::StatusCode, String)> {
    list_policy_sets(State(state), headers, Query(q)).await
}

/// `GET /v1/admin/policy-sets/{name}` - one policy set.
#[utoipa::path(
    get,
    path = "/v1/admin/policy-sets/{name}",
    params(("name" = String, Path, description = "Policy set name")),
    responses(
        (status = 200, description = "The policy set", body = serde_json::Value),
        (status = 404, description = "Unknown policy set name"),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("sentin8:admin" = [])),
    tag = "policy",
)]
pub async fn policy_get_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<sentin8::shield::admin::TargetEnv>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    get_policy_set(State(state), headers, Path(name), Query(q)).await
}

/// `PUT /v1/admin/policy-sets/{name}` - store a policy set.
#[utoipa::path(
    put,
    path = "/v1/admin/policy-sets/{name}",
    params(("name" = String, Path, description = "Policy set name")),
    request_body = PutPolicySetBody,
    responses(
        (status = 200, description = "Policy set stored", body = serde_json::Value),
        (status = 400, description = "Invalid policy set definition"),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("sentin8:admin" = [])),
    tag = "policy",
)]
pub async fn policy_put_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<sentin8::shield::admin::TargetEnv>,
    body: Json<PutPolicySetBody>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), (axum::http::StatusCode, String)> {
    put_policy_set(State(state), headers, Path(name), Query(q), body).await
}

/// `DELETE /v1/admin/policy-sets/{name}` - delete a policy set.
#[utoipa::path(
    delete,
    path = "/v1/admin/policy-sets/{name}",
    params(("name" = String, Path, description = "Policy set name")),
    responses(
        (status = 200, description = "Policy set deleted"),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("sentin8:admin" = [])),
    tag = "policy",
)]
pub async fn policy_delete_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<sentin8::shield::admin::TargetEnv>,
) -> Result<axum::http::StatusCode, (axum::http::StatusCode, String)> {
    delete_policy_set(State(state), headers, Path(name), Query(q)).await
}

/// `POST /v1/admin/policy-sets/{name}/test` - dry-run evaluate against
/// the set.
#[utoipa::path(
    post,
    path = "/v1/admin/policy-sets/{name}/test",
    params(("name" = String, Path, description = "Policy set name")),
    request_body = sentin8::shield::admin::TestPolicySetBody,
    responses(
        (status = 200, description = "Dry-run decision trace", body = serde_json::Value),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("sentin8:admin" = [])),
    tag = "policy",
)]
pub async fn policy_test_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<sentin8::shield::admin::TargetEnv>,
    body: Json<sentin8::shield::admin::TestPolicySetBody>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    test_policy_set(State(state), headers, Path(name), Query(q), body).await
}

/// `POST /v1/admin/policy-sets/enforce` - switch the named sets to
/// enforce mode (RFW row action).
#[utoipa::path(
    post,
    path = "/v1/admin/policy-sets/enforce",
    request_body = sentin8::shield::admin::PolicyModeBody,
    responses(
        (status = 200, description = "Sets switched to enforce mode"),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("sentin8:admin" = [])),
    tag = "policy",
)]
pub async fn policy_enforce(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<sentin8::shield::admin::TargetEnv>,
    body: Json<sentin8::shield::admin::PolicyModeBody>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    admin_enforce_policy_set(State(state), headers, Query(q), body).await
}

/// `POST /v1/admin/policy-sets/shadow` - switch the named sets to shadow
/// mode (RFW row action).
#[utoipa::path(
    post,
    path = "/v1/admin/policy-sets/shadow",
    request_body = sentin8::shield::admin::PolicyModeBody,
    responses(
        (status = 200, description = "Sets switched to shadow mode"),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("sentin8:admin" = [])),
    tag = "policy",
)]
pub async fn policy_shadow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<sentin8::shield::admin::TargetEnv>,
    body: Json<sentin8::shield::admin::PolicyModeBody>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    admin_shadow_policy_set(State(state), headers, Query(q), body).await
}

/// `POST /v1/admin/policy-sets/disable` - disable the named sets (RFW row
/// action).
#[utoipa::path(
    post,
    path = "/v1/admin/policy-sets/disable",
    request_body = sentin8::shield::admin::PolicyModeBody,
    responses(
        (status = 200, description = "Sets disabled"),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("sentin8:admin" = [])),
    tag = "policy",
)]
pub async fn policy_disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<sentin8::shield::admin::TargetEnv>,
    body: Json<sentin8::shield::admin::PolicyModeBody>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    admin_disable_policy_set(State(state), headers, Query(q), body).await
}

/// `GET /v1/admin/relations` - the env's ReBAC relations.
#[utoipa::path(
    get,
    path = "/v1/admin/relations",
    responses(
        (status = 200, description = "ReBAC relations of this service", body = Vec<serde_json::Value>),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("sentin8:admin" = [])),
    tag = "policy",
)]
pub async fn policy_relations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<sentin8::shield::admin::TargetEnv>,
) -> Result<Json<Vec<serde_json::Value>>, (axum::http::StatusCode, String)> {
    list_relations(State(state), headers, Query(q)).await
}

/// `PUT /v1/admin/relations` - store a relation tuple.
#[utoipa::path(
    put,
    path = "/v1/admin/relations",
    request_body = PutRelationBody,
    responses(
        (status = 200, description = "Relation stored", body = serde_json::Value),
        (status = 400, description = "Invalid relation definition"),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("sentin8:admin" = [])),
    tag = "policy",
)]
pub async fn policy_put_relation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<sentin8::shield::admin::TargetEnv>,
    body: Json<PutRelationBody>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), (axum::http::StatusCode, String)> {
    put_relation(State(state), headers, Query(q), body).await
}

/// `DELETE /v1/admin/relations` - delete a relation by id (query param).
#[utoipa::path(
    delete,
    path = "/v1/admin/relations",
    params(("id" = String, Query, description = "Relation id to delete")),
    responses(
        (status = 200, description = "Relation deleted"),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("sentin8:admin" = [])),
    tag = "policy",
)]
pub async fn policy_delete_relation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<sentin8::shield::admin::DeleteRelationQuery>,
) -> Result<axum::http::StatusCode, (axum::http::StatusCode, String)> {
    delete_relation(State(state), headers, Query(q)).await
}

/// `GET /v1/admin/relations/check` - dry-run relation check.
#[utoipa::path(
    get,
    path = "/v1/admin/relations/check",
    params(
        ("subject" = String, Query, description = "Subject key"),
        ("relation" = String, Query, description = "Relation name"),
        ("object" = String, Query, description = "Object key"),
    ),
    responses(
        (status = 200, description = "The check verdict", body = serde_json::Value),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("sentin8:admin" = [])),
    tag = "policy",
)]
pub async fn policy_check_relation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<sentin8::shield::admin::RelationCheckQuery>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    check_relation(State(state), headers, Query(q)).await
}

/// `GET /v1/admin/attributes` - the env's principal attributes.
#[utoipa::path(
    get,
    path = "/v1/admin/attributes",
    responses(
        (status = 200, description = "Principal attributes of this service", body = Vec<serde_json::Value>),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("sentin8:admin" = [])),
    tag = "policy",
)]
pub async fn policy_attributes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<sentin8::shield::admin::ListAttributesQuery>,
) -> Result<Json<Vec<serde_json::Value>>, (axum::http::StatusCode, String)> {
    list_attributes(State(state), headers, Query(q)).await
}

/// `PUT /v1/admin/attributes` - store a principal attribute.
#[utoipa::path(
    put,
    path = "/v1/admin/attributes",
    request_body = PutAttributeBody,
    responses(
        (status = 200, description = "Attribute stored", body = serde_json::Value),
        (status = 400, description = "Invalid attribute definition"),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("sentin8:admin" = [])),
    tag = "policy",
)]
pub async fn policy_put_attribute(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<sentin8::shield::admin::TargetEnv>,
    body: Json<PutAttributeBody>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), (axum::http::StatusCode, String)> {
    put_attribute(State(state), headers, Query(q), body).await
}

/// `DELETE /v1/admin/attributes` - delete an attribute by id (query
/// param).
#[utoipa::path(
    delete,
    path = "/v1/admin/attributes",
    params(("id" = String, Query, description = "Attribute id to delete")),
    responses(
        (status = 200, description = "Attribute deleted"),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("sentin8:admin" = [])),
    tag = "policy",
)]
pub async fn policy_delete_attribute(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<sentin8::shield::admin::DeleteAttributeQuery>,
) -> Result<axum::http::StatusCode, (axum::http::StatusCode, String)> {
    delete_attribute(State(state), headers, Query(q)).await
}