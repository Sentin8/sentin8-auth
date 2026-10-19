// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Auth Admin UI handlers - RFW definitions.
//! Served from `GET /v1/admin/ui/{page}`, rendered by Sentin8:Dash at runtime.

use crate::admin::TargetEnvQuery;
use crate::handlers::AppState;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;
use sqlx::Row;

/// Fetch admin ui.
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    params(
        ("page" = String, Path, description = "RFW page name (overview, users, roles, …)"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "RFW page definition (rendered by Sentin8:Dash)", body = sentin8::rfw::AdminUiResponse),
        (status = 403, description = "Caller lacks the admin scope"),
        (status = 404, description = "Unknown page"),
    ),
    security(("sentin8:auth:admin" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(page): Path<String>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    let a = crate::sentin8or_auth::require_sentin8or_access_with_env(
        &state,
        &headers,
        teq.target_env_id.as_deref(),
    )
    .await?;

    // Acquire a connection and set RLS tenant context - sentin8_auth_users
    // and sentin8_auth_roles have RLS enabled, so queries without tenant
    // context return empty results. The context is transaction-local, so we
    // must run all RLS-dependent queries inside a single transaction.
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(a.env_id)
        .execute(&mut *tx)
        .await;

    // Fetch available scopes from the vertical admin scopes table for role editing.
    let all_scopes: Vec<FormFieldOption> =
        sqlx::query("SELECT DISTINCT scope FROM vertical_admin_scopes ORDER BY scope")
            .fetch_all(&state.pool)
            .await
            .map(|rows| {
                rows.iter()
                    .filter_map(|r| {
                        let s: String = r.try_get("scope").ok()?;
                        Some(FormFieldOption {
                            value: s.clone(),
                            label: s,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

    // Fetch all users in this org/env for group member assignment.
    // Uses the tenant-context-aware transaction.
    let all_users: Vec<FormFieldOption> = if page.starts_with("groups/") && page.contains('/') {
        sqlx::query("SELECT id::text, email FROM users WHERE env_id = $1 ORDER BY email")
            .bind(a.env_id)
            .fetch_all(&mut *tx)
            .await
            .map(|rows| {
                rows.iter()
                    .filter_map(|r| {
                        let id: String = r.try_get("id").ok()?;
                        let email: String = r.try_get("email").ok()?;
                        Some(FormFieldOption {
                            value: id,
                            label: email,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![]
    };

    // Fetch all roles in this org/env for group role assignment.
    let all_roles: Vec<FormFieldOption> = if page.starts_with("groups/") && page.contains('/') {
        sqlx::query("SELECT id::text, name FROM roles WHERE env_id = $1 ORDER BY name")
            .bind(a.env_id)
            .fetch_all(&mut *tx)
            .await
            .map(|rows| {
                rows.iter()
                    .filter_map(|r| {
                        let id: String = r.try_get("id").ok()?;
                        let name: String = r.try_get("name").ok()?;
                        Some(FormFieldOption {
                            value: id,
                            label: name,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![]
    };

    // Fetch all groups in this env for the create user form's group autocomplete.
    let all_groups: Vec<FormFieldOption> = if page == "users/new" {
        sqlx::query("SELECT id::text, name FROM groups WHERE env_id = $1 ORDER BY name")
            .bind(a.env_id)
            .fetch_all(&mut *tx)
            .await
            .map(|rows| {
                rows.iter()
                    .filter_map(|r| {
                        let id: String = r.try_get("id").ok()?;
                        let name: String = r.try_get("name").ok()?;
                        Some(FormFieldOption {
                            value: id,
                            label: name,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![]
    };

    // Commit the transaction (we only read from it).
    let _ = tx.commit().await;

    let def = match page.as_str() {
        "overview" => AdminPage::new("Auth Overview")
            .widget(card("Summary", "Users, roles, apps, MFA adoption, active sessions, policy status."))
            .build(),
        "users" => AdminPage::new("Users")
            .action(link_action("Create User", "users/new"))
            .action(link_action("Invite User", "users/invite"))
            .widget(table_with_actions(vec![col_s("email","Email",true), col_s("status","Status",true), col_s("created_at","Created",true)], "/users", vec![
                row_action("Edit", "users/{id}"),
                row_action_post("Delete", "users/{id}/delete"),
            ]))
            .build(),
        "users/new" => AdminPage::new("Create User")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "first_name".into(),
                        label: "First Name".into(),
                        field_type: FormFieldType::Text,
                        required: false,
                        placeholder: None, default_value: None, options: None, validation: None, width: None, help_text: None, visible_if: None,
                    },
                    WidgetFormField {
                        key: "last_name".into(),
                        label: "Last Name".into(),
                        field_type: FormFieldType::Text,
                        required: false,
                        placeholder: None, default_value: None, options: None, validation: None, width: None, help_text: None, visible_if: None,
                    },
                    WidgetFormField {
                        key: "email".into(),
                        label: "Email".into(),
                        field_type: FormFieldType::Email,
                        required: true,
                        placeholder: Some("user@example.com".into()),
                        default_value: None, options: None, validation: None, width: None, help_text: None, visible_if: None,
                    },
                    WidgetFormField {
                        key: "password".into(),
                        label: "Password".into(),
                        field_type: FormFieldType::Password,
                        required: true,
                        placeholder: Some("Set initial password".into()),
                        default_value: None, options: None, validation: None, width: None,
                        help_text: Some("The user's initial password. They can change it later.".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "status".into(),
                        label: "Status".into(),
                        field_type: FormFieldType::Select,
                        required: false,
                        placeholder: None,
                        default_value: Some(serde_json::json!("active")),
                        options: Some(vec![
                            FormFieldOption { value: "active".into(), label: "Active".into() },
                            FormFieldOption { value: "disabled".into(), label: "Disabled".into() },
                        ]),
                        validation: None, width: None, help_text: None, visible_if: None,
                    },
                    WidgetFormField {
                        key: "group_ids".into(),
                        label: "Add to Groups".into(),
                        field_type: FormFieldType::Autocomplete,
                        required: false,
                        placeholder: Some("Search groups…".into()),
                        default_value: None,
                        options: Some(all_groups),
                        validation: None, width: None,
                        help_text: Some("Optionally add the user to one or more groups at creation time.".into()),
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/admin/users".into(),
                submit_label: "Create User".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        "users/invite" => AdminPage::new("Invite User")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "email".into(),
                        label: "Email".into(),
                        field_type: FormFieldType::Email,
                        required: true,
                        placeholder: Some("invitee@example.com".into()),
                        default_value: None, options: None, validation: None, width: None,
                        help_text: Some("The invitee's email address. They'll receive an invitation link.".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "role".into(),
                        label: "Role".into(),
                        field_type: FormFieldType::Select,
                        required: false,
                        placeholder: None,
                        default_value: Some(serde_json::json!("sentin8or")),
                        options: Some(vec![
                            FormFieldOption { value: "sentin8or".into(), label: "Sentin8or (standard access)".into() },
                            FormFieldOption { value: "sentin8:env:admin".into(), label: "Env Admin (environment admin)".into() },
                            FormFieldOption { value: "sentin8:org:admin".into(), label: "Org Admin (organization admin)".into() },
                        ]),
                        validation: None, width: None,
                        help_text: Some("The role to assign to the invited user.".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "ttl_days".into(),
                        label: "Invitation Expiry (days)".into(),
                        field_type: FormFieldType::Number,
                        required: false,
                        placeholder: None,
                        default_value: Some(serde_json::json!(7)),
                        options: None,
                        validation: Some(FormFieldValidation { min: Some(1.0), max: Some(30.0), pattern: None, min_length: None, max_length: None, custom_message: None }),
                        width: None,
                        help_text: Some("Number of days before the invitation expires.".into()),
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/admin/invitations".into(),
                submit_label: "Send Invitation".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        "roles" => AdminPage::new("Roles")
            .action(link_action("Create Role", "roles/new"))
            .widget(table_with_actions(vec![col_s("name","Name",true), col_s("scope_count","Scopes",true)], "/roles", vec![
                row_action("Edit", "roles/{id}"),
                row_action("Members", "roles/{id}/members"),
                row_action_post("Delete", "roles/{id}/delete"),
            ]))
            .build(),
        "roles/new" => AdminPage::new("Create Role")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "name".into(),
                        label: "Role Name".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. env-admin".into()),
                        default_value: None, options: None, validation: None, width: None,
                        help_text: Some("A unique role name within this org/env.".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "permissions".into(),
                        label: "Permissions (comma-separated scopes)".into(),
                        field_type: FormFieldType::Text,
                        required: false,
                        placeholder: Some("e.g. auth:users:read, auth:users:write".into()),
                        default_value: None, options: None, validation: None, width: None,
                        help_text: Some("Enter scopes separated by commas. Each scope grants a specific permission.".into()),
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/admin/roles".into(),
                submit_label: "Create Role".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        "groups" => AdminPage::new("Groups")
            .action(link_action("Create Group", "groups/new"))
            .widget(table_with_actions(vec![col_s("name","Name",true), col_s("member_count","Members",true)], "/groups", vec![
                row_action("Edit", "groups/{id}"),
                row_action("Members", "groups/{id}/members"),
                row_action_post("Delete", "groups/{id}/delete"),
            ]))
            .build(),
        "groups/new" => AdminPage::new("Create Group")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "name".into(),
                        label: "Group Name".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. developers".into()),
                        default_value: None, options: None, validation: None, width: None,
                        help_text: Some("A unique group name within this org/env.".into()),
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/admin/groups".into(),
                submit_label: "Create Group".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
 // ── Dynamic edit pages: roles/{id} and groups/{id} ──────────────
 // These match any UUID after roles/ or groups/ to show an edit form.
        _ if page.starts_with("roles/") && page != "roles/new" && !page.contains("/members") => {
            let role_id = page.strip_prefix("roles/").unwrap_or("");
            let submit = format!("/v1/admin/roles/{}/update", role_id);
            AdminPage::new("Edit Role")
                .widget(RemoteWidget::Form(WidgetForm {
                    fields: vec![
                        WidgetFormField {
                            key: "name".into(),
                            label: "Role Name".into(),
                            field_type: FormFieldType::Text,
                            required: true,
                            placeholder: None, default_value: None, options: None,
                            validation: None, width: None, help_text: None, visible_if: None,
                        },
                        WidgetFormField {
                            key: "permissions".into(),
                            label: "Scopes".into(),
                            field_type: FormFieldType::Multiselect,
                            required: false,
                            placeholder: None, default_value: None,
                            options: Some(all_scopes),
                            validation: None, width: None,
                            help_text: Some("Select all scopes this role should grant.".into()),
                            visible_if: None,
                        },
                    ],
                    submit_endpoint: submit,
                    submit_label: "Save Role".into(),
                    cancel_label: "Cancel".into(),
                    method: FormMethod::Post,
                }))
                .build()
        }
        _ if page.starts_with("groups/") && page != "groups/new" && !page.contains("/members") => {
            let group_id = page.strip_prefix("groups/").unwrap_or("");
            let submit = format!("/v1/admin/groups/{}/update", group_id);
            AdminPage::new("Edit Group")
                .widget(RemoteWidget::Form(WidgetForm {
                    fields: vec![
                        WidgetFormField {
                            key: "name".into(),
                            label: "Group Name".into(),
                            field_type: FormFieldType::Text,
                            required: true,
                            placeholder: None, default_value: None, options: None,
                            validation: None, width: None, help_text: None, visible_if: None,
                        },
                        WidgetFormField {
                            key: "user_ids".into(),
                            label: "Assign Users".into(),
                            field_type: FormFieldType::Multiselect,
                            required: false,
                            placeholder: None, default_value: None,
                            options: Some(all_users),
                            validation: None, width: None,
                            help_text: Some("Select users to add to this group.".into()),
                            visible_if: None,
                        },
                        WidgetFormField {
                            key: "role_ids".into(),
                            label: "Assign Roles".into(),
                            field_type: FormFieldType::Multiselect,
                            required: false,
                            placeholder: None, default_value: None,
                            options: Some(all_roles),
                            validation: None, width: None,
                            help_text: Some("Select roles to assign to this group.".into()),
                            visible_if: None,
                        },
                    ],
                    submit_endpoint: submit,
                    submit_label: "Save Group".into(),
                    cancel_label: "Cancel".into(),
                    method: FormMethod::Post,
                }))
                .build()
        }
        "sessions" => AdminPage::new("Sessions")
            .widget(table_with_actions(vec![col_s("user_email","User",true), col("ip","IP"), col_s("last_active","Last Active",true)], "/sessions", vec![
                row_action_post("Revoke", "sessions/{id}/revoke"),
            ]))
            .build(),
        "settings" => AdminPage::new("Auth Settings")
            .widget(text_form("Session policy, password policy, domain verification, security controls."))
            .build(),
        "mfa" => AdminPage::new("MFA Policy")
            .widget(text_form("MFA enforcement level, allowed factors, enrollment."))
            .build(),
        "api-keys" => AdminPage::new("API Keys")
            .action(link_action("Create API Key", "api-keys/new"))
            .widget(table_with_actions(vec![col_s("name","Name",true), col("fingerprint","Fingerprint"), col_s("created_at","Created",true)], "/api-keys", vec![
                row_action_post("Revoke", "api-keys/{id}/revoke"),
            ]))
            .build(),
        "connections" => AdminPage::new("Connections")
            .action(link_action("Add Connection", "connections/new"))
            .widget(table_with_actions(vec![col_s("name","Name",true), col_s("strategy","Strategy",true)], "/enterprise-connections", vec![
                row_action("Edit", "connections/{id}"),
                row_action_post("Delete", "enterprise-connections/{id}/delete"),
            ]))
            .build(),
        "applications" => AdminPage::new("Applications")
            .action(link_action("Register Application", "applications/new"))
            .widget(table_with_actions(vec![col_s("client_name","Name",true), col("client_id","Client ID"), col_s("status","Status",true)], "/oauth-clients", vec![
                row_action("Edit", "applications/{id}"),
                row_action_post("Delete", "oauth-clients/{id}/delete"),
            ]))
            .build(),
 // ── api-keys/new - create API key form ──
        "api-keys/new" => AdminPage::new("Create API Key")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "name".into(),
                        label: "Key Name".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. mobile-app-key".into()),
                        default_value: None, options: None, validation: None, width: None,
                        help_text: Some("A descriptive name for this API key.".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "scopes".into(),
                        label: "Scopes (comma-separated)".into(),
                        field_type: FormFieldType::Text,
                        required: false,
                        placeholder: Some("e.g. auth:users:read".into()),
                        default_value: None, options: None, validation: None, width: None,
                        help_text: Some("Scopes this API key grants. Leave empty for no scopes.".into()),
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/admin/api-keys".into(),
                submit_label: "Create API Key".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
 // ── connections/new - create enterprise connection form ──
        "connections/new" => AdminPage::new("Add Connection")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "name".into(),
                        label: "Connection Name".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. Google SSO".into()),
                        default_value: None, options: None, validation: None, width: None,
                        help_text: None, visible_if: None,
                    },
                    WidgetFormField {
                        key: "strategy".into(),
                        label: "Strategy".into(),
                        field_type: FormFieldType::Select,
                        required: true,
                        placeholder: None,
                        default_value: Some(serde_json::json!("oidc")),
                        options: Some(vec![
                            FormFieldOption { value: "oidc".into(), label: "OIDC".into() },
                            FormFieldOption { value: "saml".into(), label: "SAML".into() },
                            FormFieldOption { value: "google".into(), label: "Google".into() },
                            FormFieldOption { value: "azure-ad".into(), label: "Azure AD".into() },
                        ]),
                        validation: None, width: None,
                        help_text: Some("The identity provider strategy.".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "config".into(),
                        label: "Configuration (JSON)".into(),
                        field_type: FormFieldType::Text,
                        required: false,
                        placeholder: Some("{\"client_id\":\"...\",\"client_secret\":\"...\"}".into()),
                        default_value: None, options: None, validation: None, width: None,
                        help_text: Some("Provider-specific config as JSON (client_id, client_secret, etc.).".into()),
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/admin/enterprise-connections".into(),
                submit_label: "Add Connection".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
 // ── applications/new - register OAuth client form ──
        "applications/new" => AdminPage::new("Register Application")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "client_name".into(),
                        label: "Application Name".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. My App".into()),
                        default_value: None, options: None, validation: None, width: None,
                        help_text: None, visible_if: None,
                    },
                    WidgetFormField {
                        key: "client_id".into(),
                        label: "Client ID".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. my-app".into()),
                        default_value: None, options: None, validation: None, width: None,
                        help_text: Some("A unique client identifier for this OAuth client.".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "redirect_uris".into(),
                        label: "Redirect URIs (comma-separated)".into(),
                        field_type: FormFieldType::Text,
                        required: false,
                        placeholder: Some("https://my-app.example.com/callback".into()),
                        default_value: None, options: None, validation: None, width: None,
                        help_text: Some("OAuth redirect URIs, separated by commas.".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "scopes".into(),
                        label: "Scopes (comma-separated)".into(),
                        field_type: FormFieldType::Text,
                        required: false,
                        placeholder: Some("openid,profile,email".into()),
                        default_value: None, options: None, validation: None, width: None,
                        help_text: Some("Scopes this client can request.".into()),
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/admin/oauth-clients".into(),
                submit_label: "Register Application".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
 // ── Dynamic edit pages: users/{id}, connections/{id}, applications/{id} ──
        _ if page.starts_with("users/") && page != "users/new" && page != "users/invite" => {
            let user_id = page.strip_prefix("users/").unwrap_or("");
            let submit = format!("/v1/admin/users/{}", user_id);
            AdminPage::new("Edit User")
                .widget(RemoteWidget::Form(WidgetForm {
                    fields: vec![
                        WidgetFormField {
                            key: "first_name".into(),
                            label: "First Name".into(),
                            field_type: FormFieldType::Text,
                            required: false, placeholder: None, default_value: None, options: None,
                            validation: None, width: None, help_text: None, visible_if: None,
                        },
                        WidgetFormField {
                            key: "last_name".into(),
                            label: "Last Name".into(),
                            field_type: FormFieldType::Text,
                            required: false, placeholder: None, default_value: None, options: None,
                            validation: None, width: None, help_text: None, visible_if: None,
                        },
                        WidgetFormField {
                            key: "status".into(),
                            label: "Status".into(),
                            field_type: FormFieldType::Select,
                            required: false, placeholder: None,
                            default_value: Some(serde_json::json!("active")),
                            options: Some(vec![
                                FormFieldOption { value: "active".into(), label: "Active".into() },
                                FormFieldOption { value: "disabled".into(), label: "Disabled".into() },
                            ]),
                            validation: None, width: None, help_text: None, visible_if: None,
                        },
                    ],
                    submit_endpoint: submit,
                    submit_label: "Save User".into(),
                    cancel_label: "Cancel".into(),
                    method: FormMethod::Put,
                }))
                .build()
        }
        _ if page.starts_with("connections/") && page != "connections/new" => {
            let conn_id = page.strip_prefix("connections/").unwrap_or("");
            let submit = format!("/v1/admin/enterprise-connections/{}", conn_id);
            AdminPage::new("Edit Connection")
                .widget(RemoteWidget::Form(WidgetForm {
                    fields: vec![
                        WidgetFormField {
                            key: "name".into(), label: "Connection Name".into(),
                            field_type: FormFieldType::Text, required: true,
                            placeholder: None, default_value: None, options: None,
                            validation: None, width: None, help_text: None, visible_if: None,
                        },
                        WidgetFormField {
                            key: "strategy".into(), label: "Strategy".into(),
                            field_type: FormFieldType::Select, required: true,
                            placeholder: None, default_value: Some(serde_json::json!("oidc")),
                            options: Some(vec![
                                FormFieldOption { value: "oidc".into(), label: "OIDC".into() },
                                FormFieldOption { value: "saml".into(), label: "SAML".into() },
                                FormFieldOption { value: "google".into(), label: "Google".into() },
                                FormFieldOption { value: "azure-ad".into(), label: "Azure AD".into() },
                            ]),
                            validation: None, width: None, help_text: None, visible_if: None,
                        },
                        WidgetFormField {
                            key: "config".into(), label: "Configuration (JSON)".into(),
                            field_type: FormFieldType::Text, required: false,
                            placeholder: None, default_value: None, options: None,
                            validation: None, width: None, help_text: None, visible_if: None,
                        },
                    ],
                    submit_endpoint: submit, submit_label: "Save Connection".into(),
                    cancel_label: "Cancel".into(), method: FormMethod::Put,
                }))
                .build()
        }
        _ if page.starts_with("applications/") && page != "applications/new" => {
            let app_id = page.strip_prefix("applications/").unwrap_or("");
            let submit = format!("/v1/admin/oauth-clients/{}", app_id);
            AdminPage::new("Edit Application")
                .widget(RemoteWidget::Form(WidgetForm {
                    fields: vec![
                        WidgetFormField {
                            key: "client_name".into(), label: "Application Name".into(),
                            field_type: FormFieldType::Text, required: true,
                            placeholder: None, default_value: None, options: None,
                            validation: None, width: None, help_text: None, visible_if: None,
                        },
                        WidgetFormField {
                            key: "redirect_uris".into(), label: "Redirect URIs (comma-separated)".into(),
                            field_type: FormFieldType::Text, required: false,
                            placeholder: None, default_value: None, options: None,
                            validation: None, width: None, help_text: None, visible_if: None,
                        },
                        WidgetFormField {
                            key: "scopes".into(), label: "Scopes (comma-separated)".into(),
                            field_type: FormFieldType::Text, required: false,
                            placeholder: None, default_value: None, options: None,
                            validation: None, width: None, help_text: None, visible_if: None,
                        },
                    ],
                    submit_endpoint: submit, submit_label: "Save Application".into(),
                    cancel_label: "Cancel".into(), method: FormMethod::Put,
                }))
                .build()
        }
 // ── roles/{id}/members - role member management ──
        _ if page.starts_with("roles/") && page.contains("/members") => {
            let role_id = page.strip_prefix("roles/").unwrap_or("").trim_end_matches("/members");
            AdminPage::new("Role Members")
                .widget(table_with_actions(
                    vec![col_s("user_email","User",true), col_s("added_at","Added",true)],
                    &format!("/v1/admin/roles/{}/members", role_id),
                    vec![],
                ))
                .widget(RemoteWidget::Form(WidgetForm {
                    fields: vec![
                        WidgetFormField {
                            key: "user_id".into(), label: "User ID".into(),
                            field_type: FormFieldType::Autocomplete, required: true,
                            placeholder: Some("Search users…".into()),
                            default_value: None, options: Some(all_users),
                            validation: None, width: None,
                            help_text: Some("Select a user to add to this role.".into()),
                            visible_if: None,
                        },
                    ],
                    submit_endpoint: format!("/v1/admin/roles/{}/members", role_id),
                    submit_label: "Add Member".into(),
                    cancel_label: "Cancel".into(),
                    method: FormMethod::Post,
                }))
                .build()
        }
 // ── groups/{id}/members - group member + role management ──
        _ if page.starts_with("groups/") && page.contains("/members") => {
            let group_id = page.strip_prefix("groups/").unwrap_or("").trim_end_matches("/members");
            AdminPage::new("Group Members")
                .widget(table_with_actions(
                    vec![col_s("user_email","User",true), col_s("added_at","Added",true)],
                    &format!("/v1/admin/groups/{}/members", group_id),
                    vec![],
                ))
                .widget(RemoteWidget::Form(WidgetForm {
                    fields: vec![
                        WidgetFormField {
                            key: "user_id".into(), label: "User ID".into(),
                            field_type: FormFieldType::Autocomplete, required: true,
                            placeholder: Some("Search users…".into()),
                            default_value: None, options: Some(all_users),
                            validation: None, width: None,
                            help_text: Some("Select a user to add to this group.".into()),
                            visible_if: None,
                        },
                    ],
                    submit_endpoint: format!("/v1/admin/groups/{}/members", group_id),
                    submit_label: "Add Member".into(),
                    cancel_label: "Cancel".into(),
                    method: FormMethod::Post,
                }))
 // - assign a role to the group (members inherit its scopes).
                .widget(RemoteWidget::Form(WidgetForm {
                    fields: vec![
                        WidgetFormField {
                            key: "role_id".into(), label: "Role".into(),
                            field_type: FormFieldType::Select, required: true,
                            placeholder: None, default_value: None,
                            options: Some(all_roles),
                            validation: None, width: None,
                            help_text: Some("Every group member receives this role's scopes.".into()),
                            visible_if: None,
                        },
                    ],
                    submit_endpoint: format!("/v1/admin/groups/{}/roles", group_id),
                    submit_label: "Assign Role".into(),
                    cancel_label: "Cancel".into(),
                    method: FormMethod::Post,
                }))
                .build()
        }
        "security" => {
 // - the security page: HIGH-LEVEL selection only
 // (Profile + Extensions + Overlay). Submitting it resets the
 // detail flags to the selected profile's defaults.
 // The individual `require_*` flags live on the detail page
 // (`security/detail`) - linked from the header action.
            let current = crate::security_admin::read_current(&state.pool, a.env_id)
                .await
                .unwrap_or(crate::security_admin::SecuritySelectionResponse {
                    env_id: a.env_id,
                    profile: "fapi_2".into(),
                    extensions: vec![],
                    overlay: None,
                    env_row_exists: false,
                });
            let inherited = if current.env_row_exists {
                "Env-scoped row active - these values govern enforcement for this env."
            } else {
                "No env row yet - this env inherits the platform default. Saving creates the env row."
            };
            let ext_default = serde_json::Value::Array(
                current.extensions.iter().map(|e| serde_json::json!(e)).collect(),
            );
            let overlay_default = serde_json::json!(current.overlay.clone().unwrap_or_else(|| "none".into()));
            AdminPage::new("Security Profile")
                .action(link_action("Detail Flags", "security/detail"))
                .widget(card("Effective Profile", inherited))
                .widget(RemoteWidget::Form(WidgetForm {
                    fields: vec![
                        WidgetFormField {
                            key: "profile".into(),
                            label: "Profile".into(),
                            field_type: FormFieldType::Select,
                            required: true,
                            placeholder: None,
                            default_value: Some(serde_json::json!(current.profile)),
                            options: Some(vec![
                                FormFieldOption { value: "standard".into(), label: "Standard (OAuth 2.1)".into() },
                                FormFieldOption { value: "fapi_1_baseline".into(), label: "FAPI 1.0 Baseline".into() },
                                FormFieldOption { value: "fapi_1_advanced".into(), label: "FAPI 1.0 Advanced".into() },
                                FormFieldOption { value: "fapi_2".into(), label: "FAPI 2.0 (default)".into() },
                                FormFieldOption { value: "fapi_2_message_signing".into(), label: "FAPI 2.0 Message Signing".into() },
                                FormFieldOption { value: "fapi_ciba".into(), label: "FAPI CIBA".into() },
                            ]),
                            validation: None, width: None,
                            help_text: Some("Changing this resets the detail flags to the profile defaults.".into()),
                            visible_if: None,
                        },
                        WidgetFormField {
                            key: "extensions".into(),
                            label: "Extensions".into(),
                            field_type: FormFieldType::Multiselect,
                            required: false, placeholder: None,
                            default_value: Some(ext_default),
                            options: Some(vec![
                                FormFieldOption { value: "http_signatures".into(), label: "HTTP request signatures (RFC 9421)".into() },
                                FormFieldOption { value: "jwt_introspection".into(), label: "Signed introspection (RFC 9701)".into() },
                            ]),
                            validation: None, width: None,
                            help_text: Some("Additive protocol extensions - compose with any profile.".into()),
                            visible_if: None,
                        },
                        WidgetFormField {
                            key: "overlay".into(),
                            label: "Regulatory Overlay".into(),
                            field_type: FormFieldType::Select,
                            required: false, placeholder: None,
                            default_value: Some(overlay_default),
                            options: Some(vec![
                                FormFieldOption { value: "none".into(), label: "None".into() },
                                FormFieldOption { value: "obie".into(), label: "UK Open Banking (OBIE)".into() },
                                FormFieldOption { value: "cdr".into(), label: "Australia CDR".into() },
                                FormFieldOption { value: "brazil".into(), label: "Brazil Open Finance".into() },
                            ]),
                            validation: None, width: None,
                            help_text: Some("Env-scoped compliance regime - SSA/mTLS constraints. FDX is NOT an overlay (vertical-level).".into()),
                            visible_if: None,
                        },
                    ],
                    submit_endpoint: "/v1/admin/security".into(),
                    submit_label: "Save Selection".into(),
                    cancel_label: "Cancel".into(),
                    method: FormMethod::Post,
                }))
                .build()
        }
        "security/detail" => {
 // - the detail page: individual `require_*` flags.
 // Saving here never changes the high-level selection; only the
 // flags written on the env row change.
            let current = crate::security_admin::read_current(&state.pool, a.env_id)
                .await
                .unwrap_or(crate::security_admin::SecuritySelectionResponse {
                    env_id: a.env_id,
                    profile: "fapi_2".into(),
                    extensions: vec![],
                    overlay: None,
                    env_row_exists: false,
                });
 // Prefill: the env row's flags when present; otherwise the
 // selected profile's defaults (what a reset would apply).
            let row = crate::security_admin::read_detail_flags(&state.pool, a.env_id)
                .await
                .unwrap_or(None);
            let defs = crate::fapi::ProfileDefaults::for_profile(&current.profile);
            let flag_default = |key: &str| -> serde_json::Value {
                let from_row = row.as_ref().and_then(|r| match key {
                    "require_par" => Some(r.require_par),
                    "require_mtls" => Some(r.require_mtls),
                    "require_jarm" => Some(r.require_jarm),
                    "require_dpop" => Some(r.require_dpop),
                    "require_http_signatures" => Some(r.require_http_signatures),
                    "require_jwt_introspection" => Some(r.require_jwt_introspection),
                    "require_iss" => Some(r.require_iss),
                    "refresh_rotation" => Some(r.refresh_rotation),
                    _ => None,
                });
                let fallback = defs.as_ref().and_then(|d| match key {
                    "require_par" => Some(d.require_par),
                    "require_mtls" => Some(d.require_mtls),
                    "require_jarm" => Some(d.require_jarm),
                    "require_dpop" => Some(d.require_dpop),
                    "require_http_signatures" => Some(d.require_http_signatures),
                    "require_jwt_introspection" => Some(d.require_jwt_introspection),
                    "require_iss" => Some(d.require_iss),
                    "refresh_rotation" => Some(d.refresh_rotation),
                    _ => None,
                });
                match (from_row, fallback) {
                    (Some(v), _) => serde_json::json!(v),
                    (None, Some(v)) => serde_json::json!(v),
                    _ => serde_json::json!(false),
                }
            };
            let max_default = row.as_ref().map(|r| r.max_token_lifetime)
                .or(defs.as_ref().map(|d| d.max_token_lifetime))
                .unwrap_or(900);
            AdminPage::new("Security Profile - Detail Flags")
                .action(link_action("Back to Security", "security"))
                .widget(card("Profile", &format!("Current selection: {} (changing the selection on the Security page resets these flags)", current.profile)))
                .widget(RemoteWidget::Form(WidgetForm {
                    fields: vec![
                        WidgetFormField {
                            key: "require_par".into(), label: "Require PAR".into(),
                            field_type: FormFieldType::Toggle, required: false, placeholder: None,
                            default_value: Some(flag_default("require_par")),
                            options: None, validation: None, width: None,
                            help_text: Some("Pushed Authorization Requests (RFC 9126)".into()), visible_if: None,
                        },
                        WidgetFormField {
                            key: "require_mtls".into(), label: "Require mTLS".into(),
                            field_type: FormFieldType::Toggle, required: false, placeholder: None,
                            default_value: Some(flag_default("require_mtls")),
                            options: None, validation: None, width: None,
                            help_text: Some("Mutual TLS client auth (RFC 8705)".into()), visible_if: None,
                        },
                        WidgetFormField {
                            key: "require_jarm".into(), label: "Require JARM".into(),
                            field_type: FormFieldType::Toggle, required: false, placeholder: None,
                            default_value: Some(flag_default("require_jarm")),
                            options: None, validation: None, width: None,
                            help_text: Some("JWT-Secured Authorization Response Mode".into()), visible_if: None,
                        },
                        WidgetFormField {
                            key: "require_dpop".into(), label: "Require DPoP".into(),
                            field_type: FormFieldType::Toggle, required: false, placeholder: None,
                            default_value: Some(flag_default("require_dpop")),
                            options: None, validation: None, width: None,
                            help_text: Some("Demonstrating Proof-of-Possession (RFC 9449)".into()), visible_if: None,
                        },
                        WidgetFormField {
                            key: "require_http_signatures".into(), label: "Require HTTP request signatures".into(),
                            field_type: FormFieldType::Toggle, required: false, placeholder: None,
                            default_value: Some(flag_default("require_http_signatures")),
                            options: None, validation: None, width: None,
                            help_text: Some("RFC 9421 - FAPI 2.0 Message Signing".into()), visible_if: None,
                        },
                        WidgetFormField {
                            key: "require_jwt_introspection".into(), label: "Require signed introspection".into(),
                            field_type: FormFieldType::Toggle, required: false, placeholder: None,
                            default_value: Some(flag_default("require_jwt_introspection")),
                            options: None, validation: None, width: None,
                            help_text: Some("RFC 9701 - signed introspection responses".into()), visible_if: None,
                        },
                        WidgetFormField {
                            key: "require_iss".into(), label: "Require iss parameter".into(),
                            field_type: FormFieldType::Toggle, required: false, placeholder: None,
                            default_value: Some(flag_default("require_iss")),
                            options: None, validation: None, width: None,
                            help_text: Some("RFC 9207 issuer identifier in auth responses".into()), visible_if: None,
                        },
                        WidgetFormField {
                            key: "max_token_lifetime".into(), label: "Max token lifetime (seconds)".into(),
                            field_type: FormFieldType::Number, required: true, placeholder: Some("900".into()),
                            default_value: Some(serde_json::json!(max_default)),
                            options: None,
                            validation: Some(FormFieldValidation { min: Some(60.0), max: Some(3600.0), pattern: None, min_length: None, max_length: None, custom_message: None }),
                            width: None, help_text: None, visible_if: None,
                        },
                        WidgetFormField {
                            key: "refresh_rotation".into(), label: "Rotate refresh tokens".into(),
                            field_type: FormFieldType::Toggle, required: false, placeholder: None,
                            default_value: Some(flag_default("refresh_rotation")),
                            options: None, validation: None, width: None, help_text: None, visible_if: None,
                        },
                    ],
                    submit_endpoint: "/v1/admin/security/detail".into(),
                    submit_label: "Save Flags".into(),
                    cancel_label: "Cancel".into(),
                    method: FormMethod::Post,
                }))
                .build()
        },
        "branding" => AdminPage::new("Branding")
            .widget(text_form("Read-only view of effective org/env branding."))
            .build(),
        _ => return Err((axum::http::StatusCode::NOT_FOUND, format!("Unknown admin UI page: {page}"))),
    };
    Ok(Json(AdminUiResponse::page(def)))
}

fn col(key: &str, label: &str) -> WidgetDataTableColumn {
    col_s(key, label, false)
}
fn col_s(key: &str, label: &str, sortable: bool) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable,
        width: None,
        format: None,
    }
}
#[allow(dead_code)]
fn data_table(columns: Vec<WidgetDataTableColumn>, endpoint: &str) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions: vec![],
    })
}
fn table_with_actions(
    columns: Vec<WidgetDataTableColumn>,
    endpoint: &str,
    row_actions: Vec<WidgetButton>,
) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions,
    })
}
fn row_action(label: &str, route: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: None,
    }
}
fn row_action_post(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Primary,
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}
fn card(title: &str, body: &str) -> RemoteWidget {
    RemoteWidget::Card(WidgetCard {
        title: Some(title.into()),
        subtitle: None,
        children: vec![RemoteWidget::Text(WidgetText {
            text: body.into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        })],
        actions: vec![],
    })
}
fn text_form(desc: &str) -> RemoteWidget {
    card("Configuration", desc)
}
fn link_action(label: &str, route: &str) -> AdminUiAction {
    AdminUiAction {
        label: label.into(),
        action_type: AdminUiActionType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: Some("0xe145".into()),
    }
}
