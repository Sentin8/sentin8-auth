// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Router ↔ OpenAPI drift guard (OAPEC design §3).
//!
//! Builds the production router and asserts the compiled spec covers every
//! served route (and vice versa) - the site API pages are rendered from the
//! `docs/openapi.json` dump of this same spec, so a route added without an
//! annotation fails here before the sites can trail.
//!
//! Exemptions (OAPEC §2 rule 8): the SPA fallback (the hosted Auth UI's
//! `fallback_service` - a route-level service endpoint with no method set,
//! skipped by the extractor) and `GET /openapi.json` itself (auto-exempt).
//!
//! The state's pool is `connect_lazy`: the router build dispatches no
//! request, so the guard is DB-independent - no live PostgreSQL required.

use sentin8::openapi::OpenApi;
use sentin8::shell::drift_guard::{
    assert_openapi_covers_router, served_routes, spec_pairs,
};
use sentin8_auth_server::openapi::AuthOpenApi;
use sentin8_auth_server::{build_router, AppState, SigningKeys, TestConfig};

#[tokio::test]
async fn openapi_spec_covers_every_served_route() {
    let Some(app) = spawn_router().await else {
        return;
    };

    let served = served_routes(&app);
    let spec = AuthOpenApi::openapi();
    let pairs = spec_pairs(&spec);

    assert_openapi_covers_router(&served, &pairs, &[]);
}

#[tokio::test]
async fn spec_carries_the_full_documented_surface() {
    // Sanity: the compiled spec must carry roughly the served route count -
    // guards against accidentally shrinking the paths() list (the sites'
    // api.md regenerates from the dumped file; a shrunk spec = shrunken
    // site API page).
    let pairs = spec_pairs(&AuthOpenApi::openapi());
    assert!(
        pairs.len() >= 150,
        "spec shrank to {} operations - the auth router serves far more; \
         check the paths() list in src/openapi.rs",
        pairs.len()
    );
}

/// Build the production router with a test state (LAZY pool: no request is
/// dispatched by the guard, so a live PostgreSQL is not required).
/// Returns None (skipping the guard) only when the config itself cannot
/// resolve.
async fn spawn_router() -> Option<axum::Router> {
    let _ = dotenvy::dotenv();
    let config = TestConfig::for_testing();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy(&config.database_url)
        .expect("lazy pool handle");
    let keys = std::sync::Arc::new(
        SigningKeys::generate_for_testing().expect("failed to generate keys"),
    );
    let state = AppState {
        config: std::sync::Arc::new(config),
        keys,
        pool: pool.clone(),
        policy: sentin8_auth_server::policy::engine(),
        workload_registry: sentin8::auth::workload_registry::WorkloadMap::boot_load_empty(
            "sentin8:auth",
        ),
        admin: sentin8::shield::admin::SharedAdminState::test("sentin8:auth", pool),
    };
    Some(build_router(state))
}