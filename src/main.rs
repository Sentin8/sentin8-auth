// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Auth — identity, OAuth/OIDC/FAPI, sessions, JWKS authority.
//!
//! See.
//!
//! Boot runs on the platform `sentin8-shell` crate (design
//! ): registration
//! flag, PQ provider, config, capped pool, PG18 check, middleware stack and
//! PQ-TLS listener are owned by the shell. The router comes from the lib's
//! `build_router` (shared with the integration tests); the shell applies the
//! standard middleware stack on top.

use sentin8_auth_server::{registration, server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("sentin8:auth", "SENTIN8_AUTH")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_prebuilt_router(server::build_router),
    )
    .await
}
