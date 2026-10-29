// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Sentin8:Auth.
//!
//! Output via `--print-registration` flag. The CLI runs the binary with this
//! flag and consumes the JSON to register the service in the platform DB.
//! See `design/sentin8-service-self-registration-design.md`.

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, CrossSchemaGrant, PgRole, PolicySetDecl, Registration,
    RelationDecl, SqlMigration,
};
use utoipa::OpenApi;

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "sentin8:auth:read,sentin8:auth:write",
    role: "sentin8_auth_service",
    bypass_rls: false,
    database: "sentin8",
    // Cross-schema reads inside the platform database, explicitly
    // declared (architecture-principles §6.6 - never blanket schema
    // grants). auth resolves org_id from env_id via `sys.environments`
    // in the provisioning path (provision.rs / sentin8or_auth.rs §6.3)
    // and in delegation/ciba env resolution - the tables stay sys-owned;
    // auth only reads them under the FORCE-RLS tenant context.
    cross_schema_grants: &[CrossSchemaGrant {
        schema: "sys",
        table: "environments",
        privilege: "SELECT",
    }],
}];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "overview",
        label: "Overview",
        ui_endpoint: "/v1/admin/ui/overview",
        data_endpoint: "/v1/admin/overview",
        icon: "0xe1b1",
    },
    AdminUiPage {
        route: "users",
        label: "Users",
        ui_endpoint: "/v1/admin/ui/users",
        data_endpoint: "/v1/admin/users",
        icon: "0xe486",
    },
    AdminUiPage {
        route: "roles",
        label: "Roles",
        ui_endpoint: "/v1/admin/ui/roles",
        data_endpoint: "/v1/admin/roles",
        icon: "0xe062",
    },
    AdminUiPage {
        route: "groups",
        label: "Groups",
        ui_endpoint: "/v1/admin/ui/groups",
        data_endpoint: "/v1/admin/groups",
        icon: "0xe2ee",
    },
    AdminUiPage {
        route: "sessions",
        label: "Sessions",
        ui_endpoint: "/v1/admin/ui/sessions",
        data_endpoint: "/v1/admin/sessions",
        icon: "0xe3ae",
    },
    AdminUiPage {
        route: "settings",
        label: "Settings",
        ui_endpoint: "/v1/admin/ui/settings",
        data_endpoint: "/v1/admin/settings",
        icon: "0xe57f",
    },
    AdminUiPage {
        route: "mfa",
        label: "MFA",
        ui_endpoint: "/v1/admin/ui/mfa",
        data_endpoint: "/v1/admin/mfa",
        icon: "0xe69a",
    },
    AdminUiPage {
        route: "api-keys",
        label: "API Keys",
        ui_endpoint: "/v1/admin/ui/api-keys",
        data_endpoint: "/v1/admin/api-keys",
        icon: "0xf052b",
    },
    AdminUiPage {
        route: "connections",
        label: "Connections",
        ui_endpoint: "/v1/admin/ui/connections",
        data_endpoint: "/v1/admin/connections",
        icon: "0xf051d",
    },
    AdminUiPage {
        route: "applications",
        label: "Applications",
        ui_endpoint: "/v1/admin/ui/applications",
        data_endpoint: "/v1/admin/applications",
        icon: "0xe08f",
    },
    AdminUiPage {
        route: "security",
        label: "Security",
        ui_endpoint: "/v1/admin/ui/security",
        data_endpoint: "/v1/admin/security",
        icon: "0xe596",
    },
    AdminUiPage {
        route: "branding",
        label: "Branding",
        ui_endpoint: "/v1/admin/ui/branding",
        data_endpoint: "/v1/admin/branding",
        icon: "0xe46b",
    },
    AdminUiPage {
        route: "users/new",
        label: "Create User",
        ui_endpoint: "/v1/admin/ui/users/new",
        data_endpoint: "/v1/admin/users",
        icon: "0xe486",
    },
    AdminUiPage {
        route: "roles/new",
        label: "Create Role",
        ui_endpoint: "/v1/admin/ui/roles/new",
        data_endpoint: "/v1/admin/roles",
        icon: "0xe062",
    },
    AdminUiPage {
        route: "groups/new",
        label: "Create Group",
        ui_endpoint: "/v1/admin/ui/groups/new",
        data_endpoint: "/v1/admin/groups",
        icon: "0xe48d",
    },
    AdminUiPage {
        route: "users/invite",
        label: "Invite User",
        ui_endpoint: "/v1/admin/ui/users/invite",
        data_endpoint: "/v1/admin/invitations",
        icon: "0xe565",
    },
    AdminUiPage {
        route: "policy-sets",
        label: "Policy Sets",
        ui_endpoint: "/v1/admin/ui/policy-sets",
        data_endpoint: "/v1/admin/policy-sets",
        icon: "0xe8b8",
    },
    AdminUiPage {
        route: "policy-decisions",
        label: "Policy Decisions",
        ui_endpoint: "/v1/admin/ui/policy-decisions",
        data_endpoint: "/v1/admin/policy-decisions",
        icon: "0xf070",
    },
];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

/// Serialize the utoipa OpenAPI spec (used for the `all` and `openapi` sections).
fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::AuthOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
}

/// Default declarative policy sets (Sentin8:Policy design /):
/// action-granular scope permits over the LIVE effective scope set. Seeded
/// `origin='platform'`, `mode='enforced'` ( - step 5 is
/// the only gate; shadow is the emergency one-UPDATE rollback lever only).
const POLICIES: &[PolicySetDecl] = &[
    PolicySetDecl {
        policy_set_name: "scope-mirror",
        description: "Action-granular scope permits for sentin8:auth over the LIVE effective scope set. Enforced - step 5 is the only gate. The memberships grant mirrors the sys provisioning workload's certificate scope (auth-sys, auth DESIGN §4.3f) - its role/group provisioning calls present the certificate, and the map-granted `sentin8:sys:memberships:admin` is the authorization record.",
        policies: "permit(principal, action == Action::\"sentin8:auth:admin:read\", resource) when { principal.scopes.contains(\"sentin8:auth:admin:read\") };\npermit(principal, action == Action::\"sentin8:auth:admin:write\", resource) when { principal.scopes.contains(\"sentin8:auth:admin:write\") };\npermit(principal, action == Action::\"sentin8:auth:admin:read\", resource) when { principal.scopes.contains(\"sentin8:sys:memberships:admin\") };\npermit(principal, action == Action::\"sentin8:auth:admin:write\", resource) when { principal.scopes.contains(\"sentin8:sys:memberships:admin\") };",
        schema: None,
        mode: "enforced",
        default_enabled: true,
    },
];

/// Default ReBAC relation tuples (design ) - none declared by this
/// service today; env admins author their own graph via the admin API.
const RELATIONS: &[RelationDecl] = &[];

/// Print the registration JSON to stdout.
///
/// With no `--section` argument, outputs the full registration object.
/// With `--section=<name>`, outputs only that section as a standalone JSON value.
/// M2M DCR workload grants (self-registration ): this
/// service's own `certless:<workload>` rows, upserted by `vertical enroll`.
/// The static auth seed is retired - this declaration is the ONLY
/// provisioning path ( "DCR is dynamic").
/// Cover BOTH the full-identity `-policy` spelling (policy_bus_client) and
/// the bare `{short}-policy` spelling (stat_emit); the gate's superset
/// check admits any requested subset.
const M2M_GRANTS: &[sentin8::registration::M2mGrant] = &[
    sentin8::registration::M2mGrant {
        workload: "auth-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    // The platform workload also drives sign-up closure provisioning:
    // `auto_add_to_app_groups` learns the env's customer-mode app
    // instances via Sentin8:App's owner API (auth DESIGN invariant 12 -
    // no direct `sys.app_instances` read; auth's sys.* grants are
    // retired).
    sentin8::registration::M2mGrant {
        workload: "sentin8:auth",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:stat:measure",
            "sentin8:app:instances:read",
        ],
    },
    sentin8::registration::M2mGrant {
        workload: "auth",
        scopes: &["sentin8:stat:measure"],
    },
    sentin8::registration::M2mGrant {
        workload: "auth-post",
        scopes: &["sentin8:post:write"],
    },
    // Cron schedule self-registration (AUTH-1): the boot registers the
    // recurring JWKS rotation schedule with Cron.
    sentin8::registration::M2mGrant {
        workload: "auth-cron",
        scopes: &["sentin8:cron:write"],
    },
    // : auth's invitation admin surface proxies sys's invitation
    // lifecycle API (`/v1/org/{id}/invitations`) with this M2M client.
    sentin8::registration::M2mGrant {
        workload: "auth-sys",
        scopes: &["sentin8:sys:memberships:admin"],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:auth-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    sentin8::registration::M2mGrant {
        workload: "auth-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    // (design/sentin8-vertical-data-plane-contract.md §VDC.7): the database-free HostContextResolver’s resolve workload - cache miss calls Sys `GET /v1/resolve/hostname`.
    sentin8::registration::M2mGrant {
        workload: "sentin8-auth-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

/// Handle print.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "sentin8:auth",
        subdomain: "auth",
        health_path: "/v1/health",
        admin_scopes: &[
            // Granular vocabulary (read/write split):
            // admin read endpoints accept `sentin8:auth:admin:read` (or write),
            // mutations require `sentin8:auth:admin:write`.
            AdminScope::Tuple("sentin8:auth:admin", "sentin8:auth:admin"),
            AdminScope::Tuple("sentin8:auth:admin", "sentin8:auth:admin:read"),
            AdminScope::Tuple("sentin8:auth:admin", "sentin8:auth:admin:write"),
            // Policy-admin surface (policy design ; per-service scope).
            AdminScope::Tuple("sentin8:auth:admin", "sentin8:auth:policy:read"),
            AdminScope::Tuple("sentin8:auth:admin", "sentin8:auth:policy:write"),
        ],
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "Auth",
            icon: "0xe569",
            service_flag: "auth",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration {
            version: 1,
            name: "init",
            sql: SQL_1_INIT,
        }],
        pg_roles: PG_ROLES,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
