-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Auth
-- SPDX-License-Identifier: Apache-2.0

-- Sentin8:Auth - identity and access management tables.
-- Covers users, sessions, OAuth clients, API keys, groups, audit, outbox,
-- security profiles, MFA (factors/challenges/WebAuthn), password reset /
-- email verify tokens, enterprise SSO connections + SSO sessions, actor
-- token events + revocations, webhook endpoints, and the DCR (RFC 7591/7592),
-- OIDC back-channel logout and mSentin8:TLS (RFC 8705) columns on
-- auth.oauth_clients.

-- Sentin8:Auth users table
CREATE SCHEMA IF NOT EXISTS auth;
CREATE TABLE IF NOT EXISTS auth.users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    env_id  UUID NOT NULL,
    email           TEXT NOT NULL,
    password_hash   TEXT,
    first_name      TEXT,
    last_name       TEXT,
    phone           TEXT,
    -- OIDC `address` claim source (auth DESIGN §9a.4): the postal columns
    -- are assembled into the spec's address JSON object at mint time,
    -- gated on the consented `address` scope.
    street_address  TEXT,
    locality        TEXT,
    region          TEXT,
    postal_code     TEXT,
    country         TEXT,
    -- OIDC `profile` scope standard members (auth DESIGN §9a.11): the
    -- scope-consented claim members minted verbatim at userinfo/ID-token
    -- time. `name` + `updated_at` are DERIVED at mint (name falls back
    -- through the name parts) and never stored here.
    oidc_profile    JSONB NOT NULL DEFAULT '{}'::jsonb,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'archived')),
    email_verified  BOOLEAN NOT NULL DEFAULT false,
    mfa_enabled     BOOLEAN NOT NULL DEFAULT false,
    external_id     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-tenant email uniqueness: the same email can sign up on multiple
-- tenants (e.g. alice@a.com registers separately on iBank and on
-- iFintech). Email is unique only within an env (env_id is globally
-- unique, so (env_id, email) is the tenant key).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'auth_users_env_email_key'
          AND conrelid = 'auth.users'::regclass
    ) THEN
        ALTER TABLE auth.users
            ADD CONSTRAINT auth_users_env_email_key
            UNIQUE (env_id, email);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_auth_users_email ON auth.users (email);
CREATE INDEX IF NOT EXISTS idx_auth_users_env ON auth.users (env_id);

-- RLS: auth.users - users can only see rows matching their org/env scope.
-- Platform operators access via delegation (org-scoped token with real org UUID).
-- No bypass - every query is scoped to sentin8_current_env_id().
ALTER TABLE auth.users ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_users_select_policy ON auth.users;
CREATE POLICY auth_users_select_policy ON auth.users
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
            -- Platform plane (mirrors auth_oauth_clients_select_policy):
            -- sessions::user_env resolves a user's env by id from the
            -- SYSTEM env context before re-scoping (sign-in flows
            -- route by hostname and cannot know the env in advance).
            OR (sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid)
        )
    );

DROP POLICY IF EXISTS auth_users_insert_policy ON auth.users;
CREATE POLICY auth_users_insert_policy ON auth.users
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_users_update_policy ON auth.users;
CREATE POLICY auth_users_update_policy ON auth.users
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_users_delete_policy ON auth.users;
CREATE POLICY auth_users_delete_policy ON auth.users
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- Sentin8:Auth sessions table
CREATE TABLE IF NOT EXISTS auth.sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES auth.users(id),

    env_id  UUID NOT NULL,
    token_id        TEXT NOT NULL UNIQUE,
    refresh_token   TEXT,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth.sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_token ON auth.sessions (token_id);

ALTER TABLE auth.sessions ENABLE ROW LEVEL SECURITY;

-- ── App passwords (per-credential permission restrictions, EUDI.0.4) ─────
-- A user may mint additional credentials for MUAs/devices with a
-- RESTRICTED scope set. The raw secret is shown once at creation; Auth
-- stores only the bcrypt hash (same hashing discipline as the login
-- password). Tokens issued via an app password carry
-- `token_tp = 'app_password'` and the scope is downscoped to
-- (allowed_scopes ∩ requested) - never the full role set.
CREATE TABLE IF NOT EXISTS auth.app_passwords (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    env_id          UUID NOT NULL,
    label           TEXT NOT NULL,               -- user-chosen ("Mac Mail")
    password_hash   TEXT NOT NULL,               -- bcrypt of the raw secret
    -- Space-separated scope whitelist; empty = deny-all (safe default -
    -- the user must opt in to scopes at mint time).
    allowed_scopes  TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_app_passwords_user ON auth.app_passwords (user_id);
CREATE INDEX IF NOT EXISTS idx_auth_app_passwords_env ON auth.app_passwords (env_id);

ALTER TABLE auth.app_passwords ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.app_passwords FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_app_passwords_tenant ON auth.app_passwords;
CREATE POLICY auth_app_passwords_tenant ON auth.app_passwords
    FOR ALL USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_sessions_select_policy ON auth.sessions;
CREATE POLICY auth_sessions_select_policy ON auth.sessions
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
            -- Platform plane (mirrors auth_oauth_clients_select_policy):
            -- Session::find_by_token resolves a session by token from the
            -- SYSTEM env context before re-scoping to the session's env -
            -- a token lookup cannot know the env in advance.
            OR (sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid)
        )
    );

-- Sessions are written by every sign-in/sign-out/refresh - the table is
-- FORCE-RLS (hardening parity with the other auth tenant tables), so the
-- write policies must exist or every session write is denied (regression
-- caught by the integration suite under the NOBYPASSRLS service role; the
-- superuser's BYPASSRLS masked it).
DROP POLICY IF EXISTS auth_sessions_insert_policy ON auth.sessions;
CREATE POLICY auth_sessions_insert_policy ON auth.sessions
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_sessions_update_policy ON auth.sessions;
CREATE POLICY auth_sessions_update_policy ON auth.sessions
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_sessions_delete_policy ON auth.sessions;
CREATE POLICY auth_sessions_delete_policy ON auth.sessions
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

ALTER TABLE auth.sessions FORCE ROW LEVEL SECURITY;

-- ── EUDI credentials (OID4VCI, EUDI.2.1) ────────────────────────────
-- One row per verifiable credential Auth issued to a wallet. The wallet
-- holds the credential; Auth holds only the status/audit record (secret-free
-- - the wallet key is generated in the wallet, never transmitted here).
-- Revocation flips the status AND marks the Status List 2021 entry.
CREATE TABLE IF NOT EXISTS auth.credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    user_id         UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    format          TEXT NOT NULL DEFAULT 'sd_jwt',
    type            TEXT NOT NULL,                  -- e.g. 'VerifiedPersonCredential'
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    cnf_jwk         JSONB,                          -- the wallet's public key (proof of possession)
    credential_data JSONB NOT NULL DEFAULT '{}',    -- non-selective claims
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_auth_credentials_env_user ON auth.credentials (env_id, user_id);

ALTER TABLE auth.credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.credentials FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_credentials_select ON auth.credentials;
CREATE POLICY auth_credentials_select ON auth.credentials
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR env_id = sentin8_current_env_id()
        )
    );
DROP POLICY IF EXISTS auth_credentials_insert ON auth.credentials;
CREATE POLICY auth_credentials_insert ON auth.credentials
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR env_id = sentin8_current_env_id()
        )
    );
DROP POLICY IF EXISTS auth_credentials_update ON auth.credentials;
CREATE POLICY auth_credentials_update ON auth.credentials
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR env_id = sentin8_current_env_id()
        )
    );

-- ── FAPI 2.0 Grant Management (SEC.PROF.5) ─────────────────────────
-- One row per consent/authorization granted to a client by a user. The
-- grant_id claim on issued access/refresh tokens references these rows;
-- revoking a grant revokes the dependent tokens (via the jti denylist) so
-- resource servers stop accepting them.
CREATE TABLE IF NOT EXISTS auth.grants (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    client_id     TEXT NOT NULL,                -- OAuth client_id string
    client_db_id  UUID,                         -- FK to oauth_clients.id (nullable for resilience)
    user_id       UUID NOT NULL,
    scope         TEXT NOT NULL DEFAULT '',
    authorization_details JSONB,
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_auth_grants_env_user ON auth.grants (env_id, user_id);
CREATE INDEX IF NOT EXISTS idx_auth_grants_client ON auth.grants (client_id);

ALTER TABLE auth.grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.grants FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_grants_select ON auth.grants;
CREATE POLICY auth_grants_select ON auth.grants
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR env_id = sentin8_current_env_id()
        )
    );
DROP POLICY IF EXISTS auth_grants_insert ON auth.grants;
CREATE POLICY auth_grants_insert ON auth.grants
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR env_id = sentin8_current_env_id()
        )
    );
DROP POLICY IF EXISTS auth_grants_update ON auth.grants;
CREATE POLICY auth_grants_update ON auth.grants
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR env_id = sentin8_current_env_id()
        )
    );

-- ── Regulatory overlays (SEC.PROF.7) ────────────────────────
-- Env-scoped compliance constraints layered on the base profile
-- (design §5.2c). One overlay per env: OBIE/Brazil require an SSA
-- verified against the regime directory's JWKS; CDR forces mTLS.
CREATE TABLE IF NOT EXISTS auth.regulatory_overlays (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL UNIQUE,
    overlay         TEXT NOT NULL CHECK (overlay IN ('obie','cdr','brazil')),
    directory_jwks_uri TEXT NOT NULL,
    directory_issuer   TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE auth.regulatory_overlays ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.regulatory_overlays FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_regulatory_overlays_select ON auth.regulatory_overlays;
CREATE POLICY auth_regulatory_overlays_select ON auth.regulatory_overlays
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR env_id = sentin8_current_env_id()
        )
    );

-- Write policies (FORCE-RLS - env admins configure the overlay row).
DROP POLICY IF EXISTS auth_regulatory_overlays_insert ON auth.regulatory_overlays;
CREATE POLICY auth_regulatory_overlays_insert ON auth.regulatory_overlays
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR env_id = sentin8_current_env_id()
        )
    );

DROP POLICY IF EXISTS auth_regulatory_overlays_update ON auth.regulatory_overlays;
CREATE POLICY auth_regulatory_overlays_update ON auth.regulatory_overlays
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR env_id = sentin8_current_env_id()
        )
    );

DROP POLICY IF EXISTS auth_regulatory_overlays_delete ON auth.regulatory_overlays;
CREATE POLICY auth_regulatory_overlays_delete ON auth.regulatory_overlays
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR env_id = sentin8_current_env_id()
        )
    );

-- Sentin8:Auth OAuth clients table
-- Includes DCR (RFC 7591/7592, Story 1.1.35/1.1.36), OIDC back-channel
-- logout (Story 1.1.37), and mSentin8:TLS (RFC 8705, Story 1.1.40) columns.
CREATE TABLE IF NOT EXISTS auth.oauth_clients (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    env_id  UUID NOT NULL,
    client_id       TEXT NOT NULL UNIQUE,
    client_name     TEXT NOT NULL,
    client_secret_hash TEXT,
    redirect_uris   TEXT[] NOT NULL DEFAULT '{}',
    grant_types     TEXT[] NOT NULL DEFAULT '{}',
    response_types  TEXT[] NOT NULL DEFAULT '{}',
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none',
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'active',
    -- DCR (RFC 7591/7592) metadata.
    client_id_issued_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    client_secret_expires_at   TIMESTAMPTZ,
    software_id                TEXT,
    software_statement         TEXT,
    registration_access_token_hash TEXT,
    logo_uri                   TEXT,
    client_uri                 TEXT,
    policy_uri                 TEXT,
    tos_uri                    TEXT,
    contacts                   TEXT[]   NOT NULL DEFAULT '{}',

    jwks_uri                   TEXT,
    jwks                       JSONB,
    sector_identifier_uri      TEXT,
    application_type           TEXT     NOT NULL DEFAULT 'web',
    dcr_protected              BOOLEAN  NOT NULL DEFAULT false,
    -- OIDC Back-Channel Logout 1.0 (Story 1.1.37).
    backchannel_logout_uri                  TEXT,
    backchannel_logout_session_required     BOOLEAN NOT NULL DEFAULT false,
    -- OIDC CIBA 1.0 §4 (DESIGN §9a.3) - the client's ping-mode
    -- notification callback. When a CIBA request registered with
    -- request_mode=ping is approved/denied, auth POSTs the notification
    -- (auth_req_id) here, authorized by the client_notification_token
    -- as a bearer. Null = poll mode only.
    backchannel_client_notification_endpoint TEXT,
    -- mSentin8:TLS Client Authentication (RFC 8705, Story 1.1.40).
    tls_client_auth_subject_dn      TEXT,
    tls_client_auth_san_dns         TEXT,
    tls_client_auth_san_uri         TEXT,
    tls_client_auth_san_ip          TEXT,
    self_signed_tls_client_auth_thumbprint TEXT,
    -- First-party consent bypass (§4.16, §5.2e). When false, the authorize
    -- endpoint issues the authorization code directly without prompting
    -- the user for consent. First-party apps (Dash, eBank, eTeller) set
    -- this to false; third-party apps keep the default true.
    consent_required BOOLEAN NOT NULL DEFAULT true,
    -- Rich Authorization Requests (RFC 9396, SEC.PROF.4). The
    -- `authorization_details` request types this client may request. An
    -- empty array rejects all RAR requests for the client (default).
    authorization_details_types TEXT[] NOT NULL DEFAULT '{}',
    -- DPoP exemption flag (SEC-2.2.5 / design §13.3.4). When true, the
    -- client is exempt from profile-level DPoP enforcement on the token
    -- endpoint. Only platform-owned public clients (dash, sentin8-cli -
    -- seeded by auth's seed.sql) set this to true; it is NOT settable
    -- via DCR or the client-management API, so a third-party SPA can
    -- never self-exempt. Proofs presented by exempt clients are still
    -- verified (opt-in sender-constraining).
    dpop_exempt BOOLEAN NOT NULL DEFAULT false,
    -- RFC 7591 registration metadata the ID-token mint honors: the
    -- registered id_token_signed_response_alg preference (none | RS256 |
    -- ES256 | PS256). NULL = the profile's default signing family.
    id_token_signed_response_alg TEXT,
    -- RFC 7591 - the registered userinfo signing preference. RS256/ES256
    -- /PS256 = the userinfo response is a signed JWT (content-type
    -- application/jwt); none/NULL = plain JSON.
    userinfo_signed_response_alg TEXT,
    -- RFC 7591 - the registered subject type (public | pairwise). A
    -- pairwise client's `sub` is the client-pair-salted hash (the
    -- subject-type derivation; the Dynamic-OP plan's sector-uri family).
    subject_type TEXT,
    -- RP-Initiated Logout allow-list (SEC-2.1.5). `/oauth/logout`
    -- only redirects to URIs registered here; otherwise it falls back to
    -- the local /sign-in page (open-redirect defense).
    post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_oauth_clients_client_id ON auth.oauth_clients (client_id);

-- Index for DCR management lookups by registration_access_token.
CREATE INDEX IF NOT EXISTS idx_auth_oauth_clients_rat_hash
    ON auth.oauth_clients (registration_access_token_hash)
    WHERE registration_access_token_hash IS NOT NULL;

ALTER TABLE auth.oauth_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.oauth_clients FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_oauth_clients_select_policy ON auth.oauth_clients;
CREATE POLICY auth_oauth_clients_select_policy ON auth.oauth_clients
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
            -- Platform plane (mirrors sys_environments_select): auth's
            -- authorize/PAR/DCR paths resolve a client by client_id from the
            -- SYSTEM env context (`with_client_env`) - a hostname-routed
            -- request cannot know the client's env in advance.
            OR (sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid)
        )
    );

-- INSERT/UPDATE/DELETE - DCR (RFC 7591/7592) and the client-management
-- API run under the service role with the tenant context set on the
-- transaction (dcr.rs admin.rs). Without an INSERT policy, FORCE RLS
-- denies every write ("new row violates row-level security policy").
DROP POLICY IF EXISTS auth_oauth_clients_insert_policy ON auth.oauth_clients;
CREATE POLICY auth_oauth_clients_insert_policy ON auth.oauth_clients
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_oauth_clients_update_policy ON auth.oauth_clients;
CREATE POLICY auth_oauth_clients_update_policy ON auth.oauth_clients
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    )
    WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_oauth_clients_delete_policy ON auth.oauth_clients;
CREATE POLICY auth_oauth_clients_delete_policy ON auth.oauth_clients
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- Sentin8:Auth API keys table
CREATE TABLE IF NOT EXISTS auth.api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    env_id  UUID NOT NULL,
    user_id         UUID,
    name            TEXT NOT NULL,
    key_prefix      TEXT NOT NULL,
    key_hash        TEXT NOT NULL,
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'active',
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);

ALTER TABLE auth.api_keys ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_api_keys_select_policy ON auth.api_keys;
CREATE POLICY auth_api_keys_select_policy ON auth.api_keys
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- Write policies: the table is FORCE-RLS - without these every API-key
-- create/revoke is denied under the NOBYPASSRLS service role (the shared
-- superuser's BYPASSRLS masked the gap).
DROP POLICY IF EXISTS auth_api_keys_insert_policy ON auth.api_keys;
CREATE POLICY auth_api_keys_insert_policy ON auth.api_keys
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_api_keys_update_policy ON auth.api_keys;
CREATE POLICY auth_api_keys_update_policy ON auth.api_keys
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_api_keys_delete_policy ON auth.api_keys;
CREATE POLICY auth_api_keys_delete_policy ON auth.api_keys
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- Sentin8:Auth roles table.
-- A Role is a named bundle of scopes (permissions). Users are assigned Roles
-- (directly via auth.user_roles, or transitively via a Group). Roles may be
-- nested so that a parent Role inherits the scopes of its child Roles.
-- ── M2M DCR credentials store (auth-internal workloads only) ─────────────
-- RETIRED for other services' workloads (auth design §4.3c target state,
-- SBI-AUTH-3): credential material lives WITH the workload (its credential
-- cache + Sentin8:Secrets), never in an auth-side table. Auth keeps this
-- table only for its OWN in-process workloads' historical rows; the schema
-- is CREATE-only (new platform, no migration).
CREATE TABLE IF NOT EXISTS auth.m2m_dcr_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name    TEXT NOT NULL,
    sentin8_auth_base_url  TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    client_secret   TEXT NOT NULL DEFAULT '',
    auth_method     TEXT NOT NULL DEFAULT 'self_signed_tls_client_auth',
    cert_pem        TEXT,
    key_pem         TEXT,
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    cert_thumbprint TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (service_name, sentin8_auth_base_url)
);

-- Note: no RLS on this table - it's accessed by platform services
-- (bff, log-agent, etc.) using the platform DB role, not
-- tenant-scoped queries.

-- ── M2M DCR scope grants (SEC-AUTH-1, auth design §4.3c target state) ──
-- Certificate-bound DCR: a `client_credentials`-only registration is
-- accepted only when the TLS handshake carries an Acme-signed client
-- certificate whose subject `CN` equals the row's `service_name` and whose
-- granted scope set covers the requested scopes. `allowed_scopes` is the
-- closed set of platform scopes that cert-identified workload may request
-- at registration (vocabulary-constrained to the platform scope catalog).
-- Provisioned by `vertical enroll` from each service's `m2m_grants`
-- self-declaration - never by DCR itself, never by a static seed naming
-- another service.
CREATE TABLE IF NOT EXISTS auth.m2m_scope_grants (
    service_name    TEXT PRIMARY KEY,
    allowed_scopes  TEXT[] NOT NULL DEFAULT '{}',
    -- VDC-2 (design/sentin8-vertical-data-plane-contract.md §VDC.4): the
    -- vertical this workload belongs to - stamped by `vertical enroll` from
    -- the registry's `vertical` field. Auth embeds it as the M2M token's
    -- `vertical` claim; Bus rejects produce when the event_type's first
    -- colon segment disagrees (event ownership gate).
    vertical        TEXT NOT NULL DEFAULT 'sentin8',
    -- VDC-4 (§VDC.5): the service_type the workload performs work FOR
    -- (workload names are inconsistent - `bank8-ledger-bus` vs
    -- `ledger-audit` - so the registry must stamp the explicit mapping).
    -- Sys's tenant-snapshot API resolves the caller's service through this
    -- column for scoped discovery (answers only for envs where the
    -- caller's own service is enabled).
    service_type    TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Platform workload grants: PROVISIONED DYNAMICALLY (SBI-AUTH-1,
-- architecture-principles §4.7 "DCR is dynamic"). Every platform service
-- declares its own `m2m_grants` via `--print-registration --section=m2m_grants`
-- (SBI-AUTH-2, self-registration §3.11) and `vertical enroll` upserts the
-- rows into auth.m2m_scope_grants keyed by service_name exactly like
-- verticals'. Auth's SQL must contain ZERO rows naming other services. Do
-- NOT re-add rows here - add the service's `m2m_grants` registration instead.

-- Note: no RLS - platform-internal lookup during DCR (anonymous endpoint,
-- server-side evaluation only; never tenant-scoped).

-- Sentin8:Auth roles table.
CREATE TABLE IF NOT EXISTS auth.roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    name            TEXT NOT NULL,
    permissions     TEXT[] NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name)
);

ALTER TABLE auth.roles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_roles_select_policy ON auth.roles;
CREATE POLICY auth_roles_select_policy ON auth.roles
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
            -- Platform plane (mirrors auth_oauth_clients_select_policy):
            -- the live identity resolution (sessions::fetch_role_scopes /
            -- user_role_names) resolves a user's RBAC closure from the
            -- SYSTEM env context - a user's roles span their org's envs.
            OR (sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid)
        )
    );

DROP POLICY IF EXISTS auth_roles_insert_policy ON auth.roles;
CREATE POLICY auth_roles_insert_policy ON auth.roles
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_roles_update_policy ON auth.roles;
CREATE POLICY auth_roles_update_policy ON auth.roles
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_roles_delete_policy ON auth.roles;
CREATE POLICY auth_roles_delete_policy ON auth.roles
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- Sentin8:Auth user_roles table: assigns a Role directly to a User.
CREATE TABLE IF NOT EXISTS auth.user_roles (
    role_id         UUID NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    -- SEC-2.4.7 - junctions carry env_id (bank8 convention): direct
    -- env-scoped RLS instead of parent-row EXISTS chains.
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, user_id)
);

-- RLS on auth.user_roles: env_id-scoped (direct) + the parent
-- role's env as defense-in-depth.
ALTER TABLE auth.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.user_roles FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_user_roles_select ON auth.user_roles;
CREATE POLICY auth_user_roles_select ON auth.user_roles
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (
                -- SEC-2.4.7 - direct env scoping (junction carries env_id)
                auth.user_roles.env_id = sentin8_current_env_id()
                OR EXISTS (
                    SELECT 1 FROM auth.roles r
                    WHERE r.id = auth.user_roles.role_id
                      AND r.env_id = sentin8_current_env_id()
                )
            )
            -- Platform plane: fetch_role_scopes / user_role_names resolve
            -- the RBAC closure from the SYSTEM env context (a user's roles
            -- span their org's envs + the SYSTEM role catalog).
            OR (sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid)
        )
    );

DROP POLICY IF EXISTS auth_user_roles_insert ON auth.user_roles;
CREATE POLICY auth_user_roles_insert ON auth.user_roles
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (
                auth.user_roles.env_id = sentin8_current_env_id()
                OR EXISTS (
                    SELECT 1 FROM auth.roles r
                    WHERE r.id = auth.user_roles.role_id
                      AND r.env_id = sentin8_current_env_id()
                )
            )
        )
    );

DROP POLICY IF EXISTS auth_user_roles_delete ON auth.user_roles;
CREATE POLICY auth_user_roles_delete ON auth.user_roles
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR EXISTS (
                SELECT 1 FROM auth.roles r
                WHERE r.id = auth.user_roles.role_id
                 
                  AND r.env_id = sentin8_current_env_id()
            )
           
        )
    );

-- Sentin8:Auth groups table.
-- A Group is a named bundle of *members* (users). Groups do not carry scopes
-- themselves; instead they are assigned one or more Roles via
-- auth.group_roles, and every member of the Group receives the union of
-- scopes from those Roles.
CREATE TABLE IF NOT EXISTS auth.groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name)
);

ALTER TABLE auth.groups ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_groups_select_policy ON auth.groups;
CREATE POLICY auth_groups_select_policy ON auth.groups
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
            -- Platform plane: user_group_names / group-provisioning
            -- resolution read cross-env from the SYSTEM context.
            OR (sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid)
        )
    );

DROP POLICY IF EXISTS auth_groups_insert_policy ON auth.groups;
CREATE POLICY auth_groups_insert_policy ON auth.groups
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_groups_update_policy ON auth.groups;
CREATE POLICY auth_groups_update_policy ON auth.groups
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_groups_delete_policy ON auth.groups;
CREATE POLICY auth_groups_delete_policy ON auth.groups
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- Sentin8:Auth group_members table: membership link between a User and a Group.
CREATE TABLE IF NOT EXISTS auth.group_members (
    group_id        UUID NOT NULL REFERENCES auth.groups(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    -- SEC-2.4.7 - junctions carry env_id (bank8 convention).
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);

-- RLS on auth.group_members: env_id-scoped (direct) + the parent
-- group's env as defense-in-depth.
ALTER TABLE auth.group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.group_members FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_group_members_select ON auth.group_members;
CREATE POLICY auth_group_members_select ON auth.group_members
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR EXISTS (
                SELECT 1 FROM auth.groups g
                WHERE g.id = auth.group_members.group_id
                  AND g.env_id = sentin8_current_env_id()
            )
            -- Platform plane: user_group_names / fetch_role_scopes (group
            -- branch) resolve memberships cross-env from the SYSTEM context.
            OR (sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid)
        )
    );

DROP POLICY IF EXISTS auth_group_members_insert ON auth.group_members;
CREATE POLICY auth_group_members_insert ON auth.group_members
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR EXISTS (
                SELECT 1 FROM auth.groups g
                WHERE g.id = auth.group_members.group_id
                  AND g.env_id = sentin8_current_env_id()
                  AND g.env_id = sentin8_current_env_id()
            )
           
        )
    );

DROP POLICY IF EXISTS auth_group_members_delete ON auth.group_members;
CREATE POLICY auth_group_members_delete ON auth.group_members
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR EXISTS (
                SELECT 1 FROM auth.groups g
                WHERE g.id = auth.group_members.group_id
                  AND g.env_id = sentin8_current_env_id()
                  AND g.env_id = sentin8_current_env_id()
            )
           
        )
    );

-- Sentin8:Auth group_roles table: assigns one or more Roles to a Group. Every member
-- of the Group receives the union of scopes granted by these Roles (plus any
-- scopes inherited via Role nesting).
CREATE TABLE IF NOT EXISTS auth.group_roles (
    group_id        UUID NOT NULL REFERENCES auth.groups(id) ON DELETE CASCADE,
    role_id         UUID NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE,
    -- SEC-2.4.7 - junctions carry env_id (bank8 convention).
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, role_id)
);

-- RLS on auth.group_roles: env_id-scoped (direct) + both parents'
-- envs as defense-in-depth.
ALTER TABLE auth.group_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.group_roles FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_group_roles_select ON auth.group_roles;
CREATE POLICY auth_group_roles_select ON auth.group_roles
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (
                EXISTS (
                    SELECT 1 FROM auth.groups g
                    WHERE g.id = auth.group_roles.group_id
                      AND g.env_id = sentin8_current_env_id()
                )
                AND EXISTS (
                    SELECT 1 FROM auth.roles r
                    WHERE r.id = auth.group_roles.role_id
                      AND r.env_id = sentin8_current_env_id()
                )
            )
            -- Platform plane: the fetch_role_scopes recursive closure
            -- reads group→role edges cross-env from the SYSTEM context.
            OR (sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid)
        )
    );

DROP POLICY IF EXISTS auth_group_roles_insert ON auth.group_roles;
CREATE POLICY auth_group_roles_insert ON auth.group_roles
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (
                EXISTS (
                    SELECT 1 FROM auth.groups g
                    WHERE g.id = auth.group_roles.group_id
                      AND g.env_id = sentin8_current_env_id()
                      AND g.env_id = sentin8_current_env_id()
                )
                AND EXISTS (
                    SELECT 1 FROM auth.roles r
                    WHERE r.id = auth.group_roles.role_id
                     
                      AND r.env_id = sentin8_current_env_id()
                )
            )
           
        )
    );

DROP POLICY IF EXISTS auth_group_roles_delete ON auth.group_roles;
CREATE POLICY auth_group_roles_delete ON auth.group_roles
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (
                EXISTS (
                    SELECT 1 FROM auth.groups g
                    WHERE g.id = auth.group_roles.group_id
                      AND g.env_id = sentin8_current_env_id()
                      AND g.env_id = sentin8_current_env_id()
                )
                AND EXISTS (
                    SELECT 1 FROM auth.roles r
                    WHERE r.id = auth.group_roles.role_id
                     
                      AND r.env_id = sentin8_current_env_id()
                )
            )
           
        )
    );

-- Sentin8:Auth client_roles table: app-role assignments to OAuth clients
-- (service principals). An M2M client's token scope = its own
-- auth.oauth_clients.scopes ∪ the permissions of every Role assigned
-- here (resolved over auth.role_nesting). See auth design §4.8b.
-- env_id is denormalized from the client for direct RLS predicates
-- (faster than an EXISTS subquery on every row). Defined here (after
-- auth.roles) because it FK-references both auth.oauth_clients and
-- auth.roles.
CREATE TABLE IF NOT EXISTS auth.client_roles (
    client_id       UUID NOT NULL REFERENCES auth.oauth_clients(id) ON DELETE CASCADE,
    role_id         UUID NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE,
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (client_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_client_roles_env ON auth.client_roles (env_id);

ALTER TABLE auth.client_roles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_client_roles_select_policy ON auth.client_roles;
CREATE POLICY auth_client_roles_select_policy ON auth.client_roles
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- Write policies (FORCE-RLS - role assignment on service principals).
DROP POLICY IF EXISTS auth_client_roles_insert_policy ON auth.client_roles;
CREATE POLICY auth_client_roles_insert_policy ON auth.client_roles
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_client_roles_update_policy ON auth.client_roles;
CREATE POLICY auth_client_roles_update_policy ON auth.client_roles
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_client_roles_delete_policy ON auth.client_roles;
CREATE POLICY auth_client_roles_delete_policy ON auth.client_roles
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- Sentin8:Auth federated_credentials table: workload-identity trust records on
-- an OAuth client. Sentin8:Auth mints an M2M token for client_id when presented
-- with an external JWT whose iss=issuer, sub=subject, aud=audience. See
-- auth design §4.9.
-- env_id is denormalized from the client for direct RLS predicates.
-- Defined here because it FK-references auth.oauth_clients.
CREATE TABLE IF NOT EXISTS auth.federated_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       UUID NOT NULL REFERENCES auth.oauth_clients(id) ON DELETE CASCADE,
    env_id          UUID NOT NULL,
    issuer          TEXT NOT NULL,
    subject         TEXT NOT NULL,
    audience        TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (client_id, issuer, subject)
);

CREATE INDEX IF NOT EXISTS idx_auth_federated_credentials_lookup
    ON auth.federated_credentials (issuer, subject);
CREATE INDEX IF NOT EXISTS idx_auth_federated_credentials_env
    ON auth.federated_credentials (env_id);

ALTER TABLE auth.federated_credentials ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_federated_credentials_select_policy ON auth.federated_credentials;
CREATE POLICY auth_federated_credentials_select_policy ON auth.federated_credentials
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- Write policies (FORCE-RLS - federated identity linking/unlinking).
DROP POLICY IF EXISTS auth_federated_credentials_insert_policy ON auth.federated_credentials;
CREATE POLICY auth_federated_credentials_insert_policy ON auth.federated_credentials
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_federated_credentials_update_policy ON auth.federated_credentials;
CREATE POLICY auth_federated_credentials_update_policy ON auth.federated_credentials
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_federated_credentials_delete_policy ON auth.federated_credentials;
CREATE POLICY auth_federated_credentials_delete_policy ON auth.federated_credentials
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- Sentin8:Auth audit events table
CREATE TABLE IF NOT EXISTS auth.audit_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID NOT NULL,
    actor_user_id       TEXT,

    token_id            TEXT,
    correlation_id      TEXT,
    action              TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id  TEXT,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT now(),
    schema_version      TEXT NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS idx_auth_audit_env ON auth.audit_events (env_id);
CREATE INDEX IF NOT EXISTS idx_auth_audit_action ON auth.audit_events (action);

ALTER TABLE auth.audit_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_audit_select_policy ON auth.audit_events;
CREATE POLICY auth_audit_select_policy ON auth.audit_events
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- Write policies: audit rows are inserted by handlers (same-transaction
-- audit emission) and revoked by admin flows - FORCE-RLS denies them
-- without the WITH CHECK clauses.
DROP POLICY IF EXISTS auth_audit_insert_policy ON auth.audit_events;
CREATE POLICY auth_audit_insert_policy ON auth.audit_events
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_audit_update_policy ON auth.audit_events;
CREATE POLICY auth_audit_update_policy ON auth.audit_events
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_audit_delete_policy ON auth.audit_events;
CREATE POLICY auth_audit_delete_policy ON auth.audit_events
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- ──────────────────────────────────────────────────────────────────────────
-- Sentin8:Auth security profiles - FAPI compliance levels for platform, org, and env auth
-- Each auth instance (platform, org, env) can have a security profile:
--   - standard: Basic OAuth 2.0 / OIDC
--   - fapi_1_baseline: FAPI 1.0 Baseline (RFC 9701)
--   - fapi_1_advanced: FAPI 1.0 Advanced (PAR, JARM, mSentin8:TLS)
--   - fapi_2: FAPI 2.0 (the default for platform auth)
CREATE TABLE IF NOT EXISTS auth.security_profiles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope           TEXT NOT NULL,                     -- 'platform', 'org', 'env'
    org_id UUID,                              -- NULL for platform scope
    env_id  UUID,                              -- NULL for platform/org scope
    profile         TEXT NOT NULL CHECK (profile IN ('standard', 'fapi_1_baseline', 'fapi_1_advanced', 'fapi_2', 'fapi_2_message_signing', 'fapi_ciba', 'vci', 'vci_haip')),
    require_par     BOOLEAN NOT NULL DEFAULT false,    -- Pushed Authorization Request
    require_mtls    BOOLEAN NOT NULL DEFAULT false,    -- Mutual Sentin8:TLS for token endpoint
    require_jarm    BOOLEAN NOT NULL DEFAULT false,    -- JWT-Secured Authorization Response Mode
    require_dpop    BOOLEAN NOT NULL DEFAULT false,    -- Demonstrating Proof-of-Possession
    -- FAPI 2.0 Message Signing (SEC.PROF.1): RFC 9421 request signatures on
    -- token/PAR/introspect + RFC 9701 signed introspection responses.
    require_http_signatures  BOOLEAN NOT NULL DEFAULT false,
    require_jwt_introspection BOOLEAN NOT NULL DEFAULT false,
    require_iss     BOOLEAN NOT NULL DEFAULT true,          -- Require issuer identifier in authorize
    max_token_lifetime INTEGER NOT NULL DEFAULT 3600,  -- seconds
    refresh_rotation BOOLEAN NOT NULL DEFAULT true,    -- Rotate refresh tokens on use
    -- JWT signing algorithm family for tokens minted under this profile
    -- (DESIGN §9a.9). MLDSA65 is the platform default (PQ signatures);
    -- RS256 serves suite-compatible tenants (the OIDF conformance
    -- rig's Java client cannot verify ML-DSA JOSE). Resolved
    -- platform → org → env alongside the flags; the TLS transport mode
    -- (SENTIN8_TLS_PQ_MODE) stays process-level by physical necessity.
    signing_alg     TEXT NOT NULL DEFAULT 'MLDSA65'
                     CHECK (signing_alg IN ('MLDSA65', 'RS256', 'ES256')),
    -- Attestation-based client authentication (draft-ietf-oauth-
    -- attestation-based-client-auth; DESIGN §9a.19): the vci_haip profile
    -- admits `OAuth-Client-Attestation` + `OAuth-Client-Attestation-PoP`
    -- header auth on the token endpoint. The trust anchor is the attester
    -- CA/leaf PEM the attestation's x5c chain must chain to; the issuer
    -- is the attestation's expected `iss` (the attester's policy trust
    -- domain). Empty values keep the feature disabled.
    allow_client_attestation            BOOLEAN NOT NULL DEFAULT false,
    client_attestation_trust_anchor_pem TEXT NOT NULL DEFAULT '',
    client_attestation_issuer           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The table UNIQUE treats NULLs as distinct - (platform, NULL, NULL) could
-- be inserted repeatedly (SEC.PROF.10 conformance caught exactly this);
-- resolution then picked an arbitrary row via LIMIT 1. NULLS NOT DISTINCT
-- makes NULLs equal so only one platform row can exist.
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_security_profiles_unique
    ON auth.security_profiles (scope, org_id, env_id) NULLS NOT DISTINCT;

-- Seed platform default: FAPI 2.0 (PQ signatures - the default family)
INSERT INTO auth.security_profiles (scope, profile, require_par, require_mtls, require_jarm, require_dpop, require_iss, max_token_lifetime, refresh_rotation, signing_alg)
VALUES ('platform', 'fapi_2', true, false, true, true, true, 900, true, 'MLDSA65')
ON CONFLICT (scope, org_id, env_id) DO NOTHING;

-- fapi_ciba / fapi_2_message_signing are opt-in per env (SEC.PROF.6): when an
-- env selects one, the operator INSERTs the env-scoped row via
-- PUT /v1/security-profile (scope='env'). Nothing is seeded here - the
-- platform default row above is the only automatic value.

CREATE INDEX IF NOT EXISTS idx_auth_security_profiles_scope ON auth.security_profiles (scope);
CREATE INDEX IF NOT EXISTS idx_auth_security_profiles_env ON auth.security_profiles (env_id);

-- RLS: platform-scoped rows visible to platform admins only
-- org/env-scoped rows visible to org/env admins
ALTER TABLE auth.security_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.security_profiles FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_security_profiles_select ON auth.security_profiles;
CREATE POLICY auth_security_profiles_select ON auth.security_profiles
    FOR SELECT USING (
        (scope = 'platform')
        OR (sentin8_current_env_id() = env_id)
        OR (sentin8_bypass_rls())
    );
DROP POLICY IF EXISTS auth_security_profiles_insert ON auth.security_profiles;
CREATE POLICY auth_security_profiles_insert ON auth.security_profiles
    FOR INSERT WITH CHECK (
        (scope = 'platform')
        OR (sentin8_current_env_id() = env_id)
        OR (sentin8_bypass_rls())
    );
DROP POLICY IF EXISTS auth_security_profiles_update ON auth.security_profiles;
CREATE POLICY auth_security_profiles_update ON auth.security_profiles
    FOR UPDATE USING (
        (scope = 'platform')
        OR (sentin8_current_env_id() = env_id)
        OR (sentin8_bypass_rls())
    );
-- DELETE: env rows may be dropped by their own env (profile reset to inherit);
-- platform rows are platform-admin land - no DELETE for them (the admin API
-- resets the platform row via UPDATE). SEC-RLS-fix 2026-09-04: the missing
-- DELETE policy silently blocked every cleanup path (default-deny under
-- FORCE RLS) - caught by the revived auth conformance tests.
DROP POLICY IF EXISTS auth_security_profiles_delete ON auth.security_profiles;
CREATE POLICY auth_security_profiles_delete ON auth.security_profiles
    FOR DELETE USING (
        sentin8_current_env_id() IS NOT NULL
        AND sentin8_current_env_id() = env_id
    );

-- ──────────────────────────────────────────────────────────────────────────
-- Sentin8:Auth MFA factors - TOTP and (later) WebAuthn/passkey credentials.
-- Story 1.1.16: MFA enrollment and verification (TOTP).
-- Story 1.1.17: passkey enrollment and verification (WebAuthn) - factor_kind='webauthn'.
CREATE TABLE IF NOT EXISTS auth.mfa_factors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,

    env_id  UUID NOT NULL,
    factor_kind     TEXT NOT NULL CHECK (factor_kind IN ('totp', 'webauthn', 'backup_code')),
    name            TEXT NOT NULL DEFAULT '',
    -- Encrypted TOTP secret (base32 of the HMAC key, encrypted with the
    -- Sentin8:Auth M2M/MFA key). NULL for webauthn (uses `public_key` instead).
    secret_cipher  BYTEA,
    -- Base32-encoded TOTP secret BEFORE encryption - only populated transiently
    -- during enrollment so the UI can render the QR code. Cleared once
    -- enrollment is confirmed.
    secret_preview  TEXT,
    -- WebAuthn credential fields (story 1.1.17).
    public_key      BYTEA,
    credential_id   BYTEA,
    counter         BIGINT NOT NULL DEFAULT 0,
    -- Backup codes are stored as bcrypt hashes (story 1.1.16 extension).
    -- Status: pending (enrollment started, not yet verified), active, disabled.
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'active', 'disabled')),
    is_default      BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_mfa_factors_user ON auth.mfa_factors (user_id);
CREATE INDEX IF NOT EXISTS idx_auth_mfa_factors_user_kind ON auth.mfa_factors (user_id, factor_kind);
CREATE INDEX IF NOT EXISTS idx_auth_mfa_factors_env ON auth.mfa_factors (env_id);

ALTER TABLE auth.mfa_factors ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_mfa_factors_select ON auth.mfa_factors;
CREATE POLICY auth_mfa_factors_select ON auth.mfa_factors
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id()
                AND env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_mfa_factors_insert ON auth.mfa_factors;
CREATE POLICY auth_mfa_factors_insert ON auth.mfa_factors
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id()
                AND env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_mfa_factors_update ON auth.mfa_factors;
CREATE POLICY auth_mfa_factors_update ON auth.mfa_factors
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id()
                AND env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_mfa_factors_delete ON auth.mfa_factors;
CREATE POLICY auth_mfa_factors_delete ON auth.mfa_factors
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id()
                AND env_id = sentin8_current_env_id())
        )
    );

-- Pending MFA challenge state - short-lived records used to validate the TOTP
-- code submitted to /v1/mfa/verify. The challenge references the factor being
-- enrolled and expires after 10 minutes.
CREATE TABLE IF NOT EXISTS auth.mfa_challenges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    factor_id       UUID NOT NULL REFERENCES auth.mfa_factors(id) ON DELETE CASCADE,
    challenge_kind  TEXT NOT NULL CHECK (challenge_kind IN ('enroll', 'verify')),
    -- For sign-in MFA: the pending session token id that should be activated
    -- on successful verification.
    pending_token_id TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_mfa_challenges_user ON auth.mfa_challenges (user_id);

ALTER TABLE auth.mfa_challenges ENABLE ROW LEVEL SECURITY;

-- Challenges are scoped to the user's org/env (denormalized via the factor).
DROP POLICY IF EXISTS auth_mfa_challenges_select ON auth.mfa_challenges;
CREATE POLICY auth_mfa_challenges_select ON auth.mfa_challenges
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR EXISTS (
                SELECT 1 FROM auth.mfa_factors f
                WHERE f.id = auth.mfa_challenges.factor_id
                  AND f.env_id = sentin8_current_env_id()
                  AND f.env_id = sentin8_current_env_id()
            )
        )
    );

DROP POLICY IF EXISTS auth_mfa_challenges_insert ON auth.mfa_challenges;
CREATE POLICY auth_mfa_challenges_insert ON auth.mfa_challenges
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR EXISTS (
                SELECT 1 FROM auth.mfa_factors f
                WHERE f.id = auth.mfa_challenges.factor_id
                  AND f.env_id = sentin8_current_env_id()
                  AND f.env_id = sentin8_current_env_id()
            )
        )
    );

DROP POLICY IF EXISTS auth_mfa_challenges_update ON auth.mfa_challenges;
CREATE POLICY auth_mfa_challenges_update ON auth.mfa_challenges
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR EXISTS (
                SELECT 1 FROM auth.mfa_factors f
                WHERE f.id = auth.mfa_challenges.factor_id
                  AND f.env_id = sentin8_current_env_id()
                  AND f.env_id = sentin8_current_env_id()
            )
        )
    );

DROP POLICY IF EXISTS auth_mfa_challenges_delete ON auth.mfa_challenges;
CREATE POLICY auth_mfa_challenges_delete ON auth.mfa_challenges
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR EXISTS (
                SELECT 1 FROM auth.mfa_factors f
                WHERE f.id = auth.mfa_challenges.factor_id
                  AND f.env_id = sentin8_current_env_id()
                  AND f.env_id = sentin8_current_env_id()
            )
        )
    );

-- WebAuthn challenge bytes (story 1.1.17). Stores the raw 32-byte nonce for
-- each ceremony so the server can verify the clientDataJSON challenge field.
-- Referenced by challenge_id from auth.mfa_challenges.
CREATE TABLE IF NOT EXISTS auth.webauthn_challenges (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge   BYTEA NOT NULL,
    user_id     UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '5 minutes'),
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_webauthn_challenges_user ON auth.webauthn_challenges (user_id);

ALTER TABLE auth.webauthn_challenges ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_webauthn_challenges_select ON auth.webauthn_challenges;
CREATE POLICY auth_webauthn_challenges_select ON auth.webauthn_challenges
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR EXISTS (
                SELECT 1 FROM auth.users u
                WHERE u.id = auth.webauthn_challenges.user_id
                  AND u.env_id = sentin8_current_env_id()
                  AND u.env_id = sentin8_current_env_id()
            )
        )
    );

DROP POLICY IF EXISTS auth_webauthn_challenges_insert ON auth.webauthn_challenges;
CREATE POLICY auth_webauthn_challenges_insert ON auth.webauthn_challenges
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR EXISTS (
                SELECT 1 FROM auth.users u
                WHERE u.id = auth.webauthn_challenges.user_id
                  AND u.env_id = sentin8_current_env_id()
            )
        )
    );

DROP POLICY IF EXISTS auth_webauthn_challenges_update ON auth.webauthn_challenges;
CREATE POLICY auth_webauthn_challenges_update ON auth.webauthn_challenges
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR EXISTS (
                SELECT 1 FROM auth.users u
                WHERE u.id = auth.webauthn_challenges.user_id
                  AND u.env_id = sentin8_current_env_id()
            )
        )
    );

DROP POLICY IF EXISTS auth_webauthn_challenges_delete ON auth.webauthn_challenges;
CREATE POLICY auth_webauthn_challenges_delete ON auth.webauthn_challenges
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR EXISTS (
                SELECT 1 FROM auth.users u
                WHERE u.id = auth.webauthn_challenges.user_id
                  AND u.env_id = sentin8_current_env_id()
            )
        )
    );

-- ──────────────────────────────────────────────────────────────────────────
-- Sentin8:Auth password reset & email verification tokens - stories 1.1.18 and 1.1.19.
CREATE TABLE IF NOT EXISTS auth.tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,

    env_id  UUID NOT NULL,
    token_kind      TEXT NOT NULL CHECK (token_kind IN ('password_reset', 'email_verify')),
    token_hash      TEXT NOT NULL UNIQUE,         -- SHA-256 hex of the raw token
    -- The first 8 chars of the raw token, shown to the user as a "code" for
    -- short out-of-band channels (e.g. admin-shared code). NULL when the full
    -- token is delivered by email link.
    short_code      TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_tokens_user ON auth.tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_kind ON auth.tokens (token_kind);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_hash ON auth.tokens (token_hash);

ALTER TABLE auth.tokens ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_tokens_select ON auth.tokens;
CREATE POLICY auth_tokens_select ON auth.tokens
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_tokens_insert ON auth.tokens;
CREATE POLICY auth_tokens_insert ON auth.tokens
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_tokens_update ON auth.tokens;
CREATE POLICY auth_tokens_update ON auth.tokens
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_tokens_delete ON auth.tokens;
CREATE POLICY auth_tokens_delete ON auth.tokens
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- ──────────────────────────────────────────────────────────────────────────
-- Sentin8:Auth enterprise connections - SAML / OIDC identity providers (story 1.1.27).
CREATE TABLE IF NOT EXISTS auth.enterprise_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    env_id  UUID,                             -- NULL for org-scoped connections
    name            TEXT NOT NULL,
    strategy        TEXT NOT NULL CHECK (strategy IN ('oidc', 'saml')),
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'disabled')),
    -- OIDC fields.
    issuer_url      TEXT,                             -- OIDC issuer (for discovery)
    discovery_url   TEXT,                             -- .well-known URL override
    client_id       TEXT,
    client_secret_cipher BYTEA,                       -- encrypted client secret
    scopes          TEXT[] NOT NULL DEFAULT '{"openid","profile","email"}',
    -- SAML fields.
    metadata_url    TEXT,                             -- IdP metadata URL
    metadata_xml    TEXT,                             -- cached IdP metadata XML
    entity_id       TEXT,                             -- this SP's entity id
    acs_url         TEXT,                             -- assertion consumer service URL
    -- Domain hint: emails matching this domain are redirected to this IdP.
    domain_hint     TEXT,
    -- Attribute mapping: which IdP claim maps to email / name.
    email_attribute TEXT NOT NULL DEFAULT 'email',
    name_attribute  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name)
);

CREATE INDEX IF NOT EXISTS idx_auth_enterprise_conn_env ON auth.enterprise_connections (env_id);
CREATE INDEX IF NOT EXISTS idx_auth_enterprise_conn_domain ON auth.enterprise_connections (domain_hint);

ALTER TABLE auth.enterprise_connections ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_enterprise_conn_select ON auth.enterprise_connections;
CREATE POLICY auth_enterprise_conn_select ON auth.enterprise_connections
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_enterprise_conn_insert ON auth.enterprise_connections;
CREATE POLICY auth_enterprise_conn_insert ON auth.enterprise_connections
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_enterprise_conn_update ON auth.enterprise_connections;
CREATE POLICY auth_enterprise_conn_update ON auth.enterprise_connections
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_enterprise_conn_delete ON auth.enterprise_connections;
CREATE POLICY auth_enterprise_conn_delete ON auth.enterprise_connections
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- SSO session state - short-lived records used to track the in-flight SSO
-- flow between the IdP redirect and the callback.
CREATE TABLE IF NOT EXISTS auth.sso_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id   UUID NOT NULL REFERENCES auth.enterprise_connections(id) ON DELETE CASCADE,

    env_id  UUID,
    state           TEXT NOT NULL,                    -- OAuth state / SAML RelayState
    nonce           TEXT,                             -- OIDC nonce
    pkce_verifier   TEXT,                             -- PKCE code verifier (OIDC)
    -- The original Sentin8:Auth flow context that triggered SSO (e.g. the OAuth
    -- authorize request that delegated to the IdP). Stored as JSON.
    return_to       TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_sso_sessions_state ON auth.sso_sessions (state);

ALTER TABLE auth.sso_sessions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_sso_sessions_select ON auth.sso_sessions;
CREATE POLICY auth_sso_sessions_select ON auth.sso_sessions
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_sso_sessions_insert ON auth.sso_sessions;
CREATE POLICY auth_sso_sessions_insert ON auth.sso_sessions
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_sso_sessions_update ON auth.sso_sessions;
CREATE POLICY auth_sso_sessions_update ON auth.sso_sessions
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_sso_sessions_delete ON auth.sso_sessions;
CREATE POLICY auth_sso_sessions_delete ON auth.sso_sessions
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- ──────────────────────────────────────────────────────────────────────────
-- Sentin8:Auth actor tokens - support / delegated admin audit (story 1.1.31).
-- Records every actor token issuance and revocation for strict audit.
CREATE TABLE IF NOT EXISTS auth.actor_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id   UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    target_user_id  UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token_id        UUID NOT NULL,                   -- the JWT jti
    scope           TEXT NOT NULL DEFAULT '',
    reason          TEXT NOT NULL,
    action          TEXT NOT NULL CHECK (action IN ('issue', 'revoke')),
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_actor_events_actor ON auth.actor_events (actor_user_id);
CREATE INDEX IF NOT EXISTS idx_auth_actor_events_target ON auth.actor_events (target_user_id);
CREATE INDEX IF NOT EXISTS idx_auth_actor_events_token ON auth.actor_events (token_id);

ALTER TABLE auth.actor_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_actor_events_select ON auth.actor_events;
CREATE POLICY auth_actor_events_select ON auth.actor_events
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (actor_user_id IN (
                SELECT id FROM auth.users
                WHERE env_id = sentin8_current_env_id()
            ))
            OR (target_user_id IN (
                SELECT id FROM auth.users
                WHERE env_id = sentin8_current_env_id()
            ))
        )
    );

DROP POLICY IF EXISTS auth_actor_events_insert ON auth.actor_events;
CREATE POLICY auth_actor_events_insert ON auth.actor_events
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (actor_user_id IN (
                SELECT id FROM auth.users
                WHERE env_id = sentin8_current_env_id()
            ))
        )
    );

DROP POLICY IF EXISTS auth_actor_events_update ON auth.actor_events;
CREATE POLICY auth_actor_events_update ON auth.actor_events
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (actor_user_id IN (
                SELECT id FROM auth.users
                WHERE env_id = sentin8_current_env_id()
            ))
        )
    );

-- No DELETE policy on auth.actor_events: the table is an append-only
-- audit trail - auth's code paths INSERT/SELECT/UPDATE only, so no
-- policy exists to admit DELETE rows (the former bypass-only policy
-- admitted nothing for any NOBYPASSRLS role and was removed).

-- Active revocations - when an actor token is revoked, its jti is recorded
-- here so verifiers can reject it before natural expiry.
CREATE TABLE IF NOT EXISTS auth.actor_revocations (
    token_id        UUID PRIMARY KEY,
    revoked_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_actor_revocations_token ON auth.actor_revocations (token_id);

-- ──────────────────────────────────────────────────────────────────────────
-- Sentin8:Auth webhooks - outbox + delivery attempts (story 1.1.32).
-- Webhooks are emitted by Sentin8:Auth events (user.created, session.started,
-- password.reset, etc.) and delivered to registered endpoints via the
-- outbox relay. Each endpoint has a signing secret (HMAC-SHA256).
CREATE TABLE IF NOT EXISTS auth.webhook_endpoints (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    env_id  UUID,                             -- NULL for org-scoped endpoints
    url             TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'disabled')),
    -- HMAC-SHA256 signing secret (encrypted at rest).
    secret_cipher   BYTEA NOT NULL,
    -- Event types this endpoint subscribes to ('*' = all).
    event_types     TEXT[] NOT NULL DEFAULT '{"*"}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_webhook_endpoints_env ON auth.webhook_endpoints (env_id);

ALTER TABLE auth.webhook_endpoints ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_webhook_endpoints_select ON auth.webhook_endpoints;
CREATE POLICY auth_webhook_endpoints_select ON auth.webhook_endpoints
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_webhook_endpoints_insert ON auth.webhook_endpoints;
CREATE POLICY auth_webhook_endpoints_insert ON auth.webhook_endpoints
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_webhook_endpoints_update ON auth.webhook_endpoints;
CREATE POLICY auth_webhook_endpoints_update ON auth.webhook_endpoints
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_webhook_endpoints_delete ON auth.webhook_endpoints;
CREATE POLICY auth_webhook_endpoints_delete ON auth.webhook_endpoints
    FOR DELETE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- Outbox - one row per webhook event to deliver. The relay worker reads
-- rows with delivered_at IS NULL, attempts delivery, and records attempts
-- in auth.webhook_attempts. On success (2xx) the row is marked delivered.
-- On failure, retry_count increments; after max retries (default 5), the
-- row is marked failed.
CREATE TABLE IF NOT EXISTS auth.webhook_outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id     UUID NOT NULL REFERENCES auth.webhook_endpoints(id) ON DELETE CASCADE,

    env_id  UUID,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    max_retries     INTEGER NOT NULL DEFAULT 5,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ,
    failed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_webhook_outbox_pending
    ON auth.webhook_outbox (next_attempt_at)
    WHERE delivered_at IS NULL AND failed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_auth_webhook_outbox_endpoint ON auth.webhook_outbox (endpoint_id);

ALTER TABLE auth.webhook_outbox ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_webhook_outbox_select ON auth.webhook_outbox;
CREATE POLICY auth_webhook_outbox_select ON auth.webhook_outbox
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_webhook_outbox_insert ON auth.webhook_outbox;
CREATE POLICY auth_webhook_outbox_insert ON auth.webhook_outbox
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

DROP POLICY IF EXISTS auth_webhook_outbox_update ON auth.webhook_outbox;
CREATE POLICY auth_webhook_outbox_update ON auth.webhook_outbox
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (env_id = sentin8_current_env_id())
        )
    );

-- Delivery attempt records (audit + debugging).
CREATE TABLE IF NOT EXISTS auth.webhook_attempts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    outbox_id       UUID NOT NULL REFERENCES auth.webhook_outbox(id) ON DELETE CASCADE,
    status_code     INTEGER,
    response_body   TEXT,
    error           TEXT,
    duration_ms     INTEGER,
    attempted_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_webhook_attempts_outbox ON auth.webhook_attempts (outbox_id);


-- Sentin8:Auth role_nesting support.
-- Adds a parent-child relationship table for Roles, allowing a Role to
-- inherit the scopes of other Roles. This enables a hierarchy like:
--   org-admin → ledger-admin, payments-admin, fdx-admin, ...
-- where each service-admin Role contains only that service's granular scopes.

CREATE TABLE IF NOT EXISTS auth.role_nesting (
    parent_role_id   UUID NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE,
    child_role_id    UUID NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (parent_role_id, child_role_id),
    CHECK (parent_role_id <> child_role_id)
);

ALTER TABLE auth.role_nesting ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_role_nesting_select_policy ON auth.role_nesting;
CREATE POLICY auth_role_nesting_select_policy ON auth.role_nesting
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            -- SEC-2.4.7 - the PARENT role's env must match the caller's
            -- env (the previous empty EXISTS made nesting edges visible to
            -- any tenant context).
            OR EXISTS (
                SELECT 1 FROM auth.roles r
                WHERE r.id = auth.role_nesting.parent_role_id
                  AND r.env_id = sentin8_current_env_id()
            )
        )
    );

-- Sentin8:Auth signing keys - persists JWT signing keys across restarts.
-- Without this, SigningKeys::generate() creates new random keys at every
-- startup, invalidating all existing JWTs (access tokens, ID tokens, etc.)
-- across the entire platform. By persisting the private key material, auth
-- restarts are transparent - existing tokens remain valid until they expire.
--
-- Key rotation is done by inserting a new row with a new key_id and deleting
-- the old row (or keeping it for overlap, if graceful rotation is needed).
CREATE TABLE IF NOT EXISTS auth.signing_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id      TEXT NOT NULL UNIQUE,
    alg         TEXT NOT NULL,
    -- PKCS#8-encoded private key (base64). For ML-DSA-65 this is the
    -- ml_dsa::SigningKey encode() output. For RSA this is PKCS#8 PEM.
    priv_key    TEXT NOT NULL,
    -- Base64url-encoded public key material for JWKS.
    -- For ML-DSA-65: verifying_key encode() output.
    -- For RSA: modulus (n) and exponent (e) stored separately below.
    pub_key_b64 TEXT,
    rsa_n_b64   TEXT,
    rsa_e_b64   TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE auth.signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.signing_keys FORCE ROW LEVEL SECURITY;
-- Platform-global table (no env_id column - the JWKS material serves the
-- whole platform). Admits only the SYSTEM-env tenant context, which auth's
-- boot sets around load/persist (load_or_generate). Under DBX the auth
-- service connects with its NOBYPASSRLS role - without a policy the boot
-- INSERT fails closed and auth crash-loops.
DROP POLICY IF EXISTS signing_keys_select ON auth.signing_keys;
CREATE POLICY signing_keys_select ON auth.signing_keys FOR SELECT
    USING (sentin8_context_initialized()
           AND sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid);
DROP POLICY IF EXISTS signing_keys_insert ON auth.signing_keys;
CREATE POLICY signing_keys_insert ON auth.signing_keys FOR INSERT
    WITH CHECK (sentin8_context_initialized()
           AND sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid);

-- ── FORCE ROW LEVEL SECURITY on all auth tenant tables ─────────────────
-- Story 12.4.36 - RLS is now fully enforced. The Delegation Gateway model
-- means all tokens (user, delegated, M2M) carry the target org/env, so RLS
-- naturally scopes to the right tenant. No bypass is needed.
-- Join tables (auth.user_roles, auth.group_members, auth.group_roles)
-- have no org/env columns - they're protected transitively by the parent
-- tables via EXISTS subquery RLS policies (see above).
-- auth.m2m_dcr_credentials is a platform-internal table - no RLS.

ALTER TABLE auth.users FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.oauth_clients FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.api_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.roles FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.groups FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.user_roles FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.group_members FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.group_roles FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.client_roles FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.federated_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.mfa_factors FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.mfa_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.webauthn_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.enterprise_connections FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.sso_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.actor_events FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.webhook_endpoints FORCE ROW LEVEL SECURITY;
ALTER TABLE auth.webhook_outbox FORCE ROW LEVEL SECURITY;

-- ── Write policies (SEC-2.4.7) ──────────────────────────────────
-- Every env-scoped auth table needs INSERT/UPDATE/DELETE policies. With
-- FORCE ROW LEVEL SECURITY, a table that only has a SELECT policy denies
-- ALL writes by default - the handlers connect as the NOBYPASSRLS app
-- role, so sign-ups, session creation, and client registration all
-- failed with "new row violates row-level security policy". Each policy
-- allows writes only when the tenant context is initialized and the row's
-- env matches (or the platform-admin bypass applies).
DO $$
DECLARE
    t TEXT;
    tables_with_env TEXT[] := ARRAY[
        'sessions', 'oauth_clients', 'api_keys',
        'mfa_factors', 'mfa_challenges', 'webauthn_challenges',
        'tokens', 'enterprise_connections', 'sso_sessions',
        'webhook_endpoints', 'webhook_outbox',
        'audit_events', 'actor_events', 'client_roles',
        'federated_credentials', 'security_profiles'
    ];
BEGIN
    FOREACH t IN ARRAY tables_with_env LOOP
        BEGIN
            EXECUTE format(
                'DROP POLICY IF EXISTS %I_write_policy ON sentin8.%I', t, t);
            EXECUTE format(
                'CREATE POLICY %I_write_policy ON sentin8.%I
                 FOR ALL USING (
                     sentin8_context_initialized()
                     AND (sentin8_bypass_rls() OR env_id = sentin8_current_env_id())
                 ) WITH CHECK (
                     sentin8_context_initialized()
                     AND (sentin8_bypass_rls() OR env_id = sentin8_current_env_id())
                 )', t, t);
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'write policy for % skipped: %', t, SQLERRM;
        END;
    END LOOP;
END $$;

-- Users table (env-scoped) - write policy.
DROP POLICY IF EXISTS auth_users_write_policy ON auth.users;
CREATE POLICY auth_users_write_policy ON auth.users
    FOR ALL USING (
        sentin8_context_initialized()
        AND (sentin8_bypass_rls() OR env_id = sentin8_current_env_id())
    ) WITH CHECK (
        sentin8_context_initialized()
        AND (sentin8_bypass_rls() OR env_id = sentin8_current_env_id())
    );

-- Roles / groups (env-scoped) - write policies.
DROP POLICY IF EXISTS auth_roles_write_policy ON auth.roles;
CREATE POLICY auth_roles_write_policy ON auth.roles
    FOR ALL USING (
        sentin8_context_initialized()
        AND (sentin8_bypass_rls() OR env_id = sentin8_current_env_id())
    ) WITH CHECK (
        sentin8_context_initialized()
        AND (sentin8_bypass_rls() OR env_id = sentin8_current_env_id())
    );
DROP POLICY IF EXISTS auth_groups_write_policy ON auth.groups;
CREATE POLICY auth_groups_write_policy ON auth.groups
    FOR ALL USING (
        sentin8_context_initialized()
        AND (sentin8_bypass_rls() OR env_id = sentin8_current_env_id())
    ) WITH CHECK (
        sentin8_context_initialized()
        AND (sentin8_bypass_rls() OR env_id = sentin8_current_env_id())
    );

-- Role nesting (no env column - gate on the PARENT role's env, matching the
-- select policy's SEC-2.4.7 rule). The nesting edge belongs to the parent
-- role's tenant; a caller with context on that env may add/remove edges.
-- The bypass_rls escape hatch remains for platform-internal paths.
DROP POLICY IF EXISTS auth_role_nesting_write_policy ON auth.role_nesting;
CREATE POLICY auth_role_nesting_write_policy ON auth.role_nesting
    FOR ALL USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR EXISTS (
                SELECT 1 FROM auth.roles r
                WHERE r.id = auth.role_nesting.parent_role_id
                  AND r.env_id = sentin8_current_env_id()
            )
        )
    ) WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR EXISTS (
                SELECT 1 FROM auth.roles r
                WHERE r.id = auth.role_nesting.parent_role_id
                  AND r.env_id = sentin8_current_env_id()
            )
        )
    );

-- Actor revocations (no env column - platform-internal write path).
DROP POLICY IF EXISTS auth_actor_revocations_write_policy ON auth.actor_revocations;
CREATE POLICY auth_actor_revocations_write_policy ON auth.actor_revocations
    FOR ALL USING (true) WITH CHECK (true);

-- Webhook attempts (delivery logs - written by the relay).
DROP POLICY IF EXISTS auth_webhook_attempts_write_policy ON auth.webhook_attempts;
CREATE POLICY auth_webhook_attempts_write_policy ON auth.webhook_attempts
    FOR ALL USING (true) WITH CHECK (true);

-- ── Grants ──

-- sentin8_auth_service: DML on all auth tables.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    auth.users, auth.sessions, auth.oauth_clients,
    auth.api_keys, auth.m2m_dcr_credentials, auth.roles,
    auth.user_roles, auth.groups, auth.group_members,
    auth.group_roles, auth.client_roles, auth.federated_credentials,
    auth.audit_events, auth.security_profiles, auth.mfa_factors,
    auth.mfa_challenges, auth.webauthn_challenges, auth.tokens,
    auth.enterprise_connections, auth.sso_sessions, auth.actor_events,
    auth.actor_revocations, auth.webhook_endpoints, auth.webhook_outbox,
    auth.webhook_attempts, auth.role_nesting, auth.signing_keys
    TO sentin8_auth_service;

-- Cross-service grants - RETIRED (SBI-SYS-3 / SBI, architecture-principles
-- §6.6a): sys and app provision membership rows through AUTH's provisioning
-- API (`/v1/admin/provision/*`, SBI-AUTH-6) with their M2M
-- `sentin8:auth:admin:write` clients - no direct INSERTs into auth.* from
-- any other service. Auth's tables are read/written by `sentin8_auth_service`
-- only (plus the dash/CLI admin surface under Shield).

-- M2M DCR credential storage - AUTH-PRIVATE (SBI-AUTH-4, architecture-
-- principles §6.6a): credentials persist via the secrets client now
-- (SBI-AUTH-3 - `dcr/{service_name}/{auth_base}` + local file cache);
-- the table is retained only for auth's OWN workloads. The former
-- cross-service GRANT block is retired; only `sentin8_auth_service` (the
-- implicit owner via the service's own DSN) touches it.
-- ── Seed data (bootstrap roles, groups, clients, admin user) ──

-- hash unless you regenerate it with the same crate version - a stale or
-- hand-edited hash will cause sign-in to silently fail with 401.
INSERT INTO auth.users (id, env_id, email, password_hash, first_name, last_name, status, email_verified, mfa_enabled)
VALUES (
    gen_random_uuid(),
    '00000000-0000-0000-0000-000000000002',
    'a@m.n',
    '$2b$12$V5/j0GG5oTEEQCnfZIbDRun93mXHUYsey9OkhNynugJgwtyRJkAJe',
    'Sentin8',
    'Admin',
    'active',
    true,
    false
)
-- Email is now per-tenant unique (sentin8_auth_users_org_env_email_key).
-- The admin is in System Env - match that pair.
ON CONFLICT (env_id, email) DO UPDATE SET
    status = EXCLUDED.status;

-- ── sys:admin security role ──────────────────────────────────────────
-- The sys:admin role grants full platform + tenant access. Bound to System
-- Org + System Env. Its scopes are merged into the JWT at sign-in.
-- This is the super-user role: a@m.n belongs here and can access
-- ════════════════════════════════════════════════════════════════════════
-- SCOPE MODEL: Per-service admin roles + nesting
-- 
-- Each service has its own admin role containing only that service's
-- granular scopes. Major roles (sys:admin, org-admin, env-admin)
-- nest the service-admin roles as children, inheriting their scopes
-- via the auth.role_nesting table.
--
-- Hierarchy (uniform RBAC naming, architecture-principles §6.0b - every
-- name starts with its vertical; the platform vertical uses `sentin8:`):
--   sentin8:sys:admin ─┬── sentin8:sys:admin, sentin8:dash:admin, sentin8:auth:admin, sentin8:app:admin
--                      ├── bank8:ledger:admin, bank8:payments:admin, bank8:fdx:admin
--                      ├── sentin8:db:admin, sentin8:storage:admin, sentin8:bus:admin
--                      └── sentin8:stat:admin, sentin8:flow:admin, sentin8:func:admin, sentin8:cron:admin
--
--   sentin8:org:admin ─├── sentin8:sys:org:admin, sentin8:dash:org:admin, sentin8:auth:admin
--                      ├── bank8:ledger:admin, bank8:payments:admin, bank8:fdx:admin
--                      └── sentin8:db:admin, sentin8:storage:admin, sentin8:bus:admin
--
--   sentin8:env:admin ─├── sentin8:sys:env:admin, sentin8:auth:admin, sentin8:app:admin
--                      ├── bank8:ledger:admin, bank8:payments:admin, bank8:fdx:admin
--                      └── sentin8:db:admin, sentin8:storage:admin, sentin8:bus:admin
-- ════════════════════════════════════════════════════════════════════════

-- ── Per-service admin roles (contain only that service's granular scopes) ──

INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    'sentin8:sys:admin', ARRAY['sentin8:sys:admin', 'sentin8:sys:org:admin', 'sentin8:sys:org:create', 'sentin8:sys:org:write', 'sentin8:sys:org:delete', 'sentin8:sys:env:admin', 'sentin8:sys:env:create', 'sentin8:sys:env:delete', 'sentin8:sys:features:admin', 'sentin8:sys:app:admin', 'sentin8:sys:audit:read']
) ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    'sentin8:sys:org:admin', ARRAY['sentin8:sys:org:admin', 'sentin8:sys:env:admin', 'sentin8:sys:features:admin', 'sentin8:sys:app:admin', 'sentin8:sys:audit:read', 'sentin8:sys:memberships:admin']
) ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    'sentin8:sys:env:admin', ARRAY['sentin8:sys:env:admin', 'sentin8:sys:features:admin', 'sentin8:sys:app:admin', 'sentin8:sys:audit:read']
) ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    'sentin8:dash:admin', ARRAY['sentin8:dash:admin', 'sentin8:dash:org:create', 'sentin8:dash:org:write', 'sentin8:dash:org:delete', 'sentin8:dash:env:create', 'sentin8:dash:env:delete', 'sentin8:dash:sentin8ors:read', 'sentin8:dash:sentin8ors:write']
) ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    'sentin8:dash:org:admin', ARRAY['sentin8:dash:admin', 'sentin8:dash:org:write', 'sentin8:dash:env:write', 'sentin8:dash:sentin8ors:read', 'sentin8:dash:sentin8ors:write']
) ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    'sentin8:auth:admin', ARRAY['sentin8:auth:admin:read', 'sentin8:auth:admin:write']
) ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    'sentin8:app:admin', ARRAY['sentin8:app:store:admin', 'sentin8:app:store:read', 'sentin8:app:instances:write', 'sentin8:app:instances:read', 'sentin8:app:instances:admin']
) ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

-- NOTE: Vertical service-admin roles (e.g. bank8:ledger:admin, bank8:payments:admin,
-- bank8:fdx:admin, hotel8:pms:admin) are NOT seeded here. They are runtime-registered
-- via each vertical's vertical-registry.json `admin_scopes` section during `sentin8-cli vertical enroll`.
-- The platform seed only defines platform service roles (auth, app, db, storage, bus, stat, flow, func, cron).
-- See AGENTS.md § "No vertical references in sentin8 services".

INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    'sentin8:db:admin', ARRAY['sentin8:db:table:admin', 'sentin8:db:data:read', 'sentin8:db:data:write', 'sentin8:db:posture:read']
) ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    -- All six storage scopes (storage design §6): handlers gate delete/move/
    -- copy on `sentin8:storage:env:admin` / `sentin8:storage:org:admin` - read/write alone
    -- would 403 every destructive operation.
    'sentin8:storage:admin', ARRAY['sentin8:storage:admin', 'sentin8:storage:env:read', 'sentin8:storage:env:write',
                           'sentin8:storage:env:admin', 'sentin8:storage:org:read', 'sentin8:storage:org:write',
                           'sentin8:storage:org:admin']
) ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    -- 'sentin8:bus:admin' itself is required by the DLQ list/replay and metrics
    -- handlers (design §6.5: admin-tier operations require bus:admin).
    'sentin8:bus:admin', ARRAY['sentin8:bus:admin', 'sentin8:bus:produce', 'sentin8:bus:consume']
) ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    'sentin8:stat:admin', ARRAY['sentin8:stat:admin', 'sentin8:stat:data:read']
) ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    'sentin8:flow:admin', ARRAY['sentin8:flow:read', 'sentin8:flow:write']
) ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    'sentin8:func:admin', ARRAY['sentin8:func:write', 'sentin8:func:execute']
) ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    'sentin8:cron:admin', ARRAY['sentin8:cron:write']
) ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

-- ── sentin8:captain:admin role (DEVUI-1.2, 2026-09-08) ────────────────
-- Captain's management API is Shield-gated on an enforced scope-mirror set
-- keyed on `sentin8:captain:admin` (captain design §6.1). The role must
-- exist and be nested under sys:admin or even the platform super-user gets
-- 403 (the live role closure never contains the scope). Permissions are the
-- exact action set of the enforced scope-mirror; the scope is intentionally
-- NOT in the sys scope catalog - machine-operations scopes are minted only
-- through the role closure, never requested at the front door.
INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    'sentin8:captain:admin', ARRAY['sentin8:captain:admin', 'sentin8:captain:policy:read', 'sentin8:captain:policy:write']
) ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

-- ── sentin8:sys:admin role (platform super-user, nests all service-admin roles) ──
-- The role's OWN permissions carry ONLY the marker scope
-- 'sentin8:sys:admin' - what is_platform_admin() and the scope-mirror
-- policies match on (auth DESIGN §3 "Platform-admin contract"). All
-- remaining scopes come from the NESTED service-admin roles below.
-- An empty ARRAY here severs the marker from every user: no one can be
-- platform admin on a fresh apply (the bootstrap admin's sys:read
-- calls fail the scope-mirror policy).
INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(),
    '00000000-0000-0000-0000-000000000002',
    'sentin8:sys:admin', ARRAY['sentin8:sys:admin']::TEXT[]  -- marker scope; service scopes come from the nested roles
)
ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

-- Nest all service-admin roles under sentin8:sys:admin
-- NOTE: 'sentin8:sys:admin' is excluded from the child list to avoid a self-reference
-- (parent_role_id = child_role_id), which violates the check constraint.
INSERT INTO auth.role_nesting (parent_role_id, child_role_id)
SELECT p.id, c.id FROM auth.roles p, auth.roles c
WHERE p.name = 'sentin8:sys:admin'
  AND c.name IN ('sentin8:dash:admin', 'sentin8:auth:admin', 'sentin8:app:admin',
                  'sentin8:db:admin', 'sentin8:storage:admin', 'sentin8:bus:admin',
                  'sentin8:stat:admin', 'sentin8:flow:admin', 'sentin8:func:admin', 'sentin8:cron:admin',
                  'sentin8:captain:admin')
ON CONFLICT DO NOTHING;

-- NOTE: sys:admin nesting is dynamic - vertical service-admin roles
-- (e.g. bank8:ledger:admin, hotel8:pms:admin) are added to the nesting at
-- runtime by `sentin8-cli vertical enroll` which inserts into
-- auth.role_nesting for each module's admin_scopes. The platform
-- seed only nests platform service-admin roles.

-- ── Add admin user to sentin8:sys:admin role ─────────────────────────
-- Assign the default admin user the sentin8:sys:admin role. We resolve the IDs
-- dynamically since they were generated by gen_random_uuid() above.
INSERT INTO auth.user_roles (role_id, user_id, env_id)
SELECT r.id, u.id, r.env_id
FROM auth.roles r, auth.users u
WHERE r.name = 'sentin8:sys:admin'
  AND u.email = 'a@m.n'
ON CONFLICT DO NOTHING;

-- ── sentin8:org:sys:admin role + sentin8:org:sys:admins group ────────────
-- A platform-level admin role + group for the platform operator. The
-- sentin8:org:sys:admin role nests sentin8:sys:admin so group members inherit all
-- platform scopes. The default admin user is added to sentin8:org:sys:admins.
INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    'sentin8:org:sys:admin', ARRAY[]::TEXT[]  -- scopes come from nested sentin8:sys:admin role
)
ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

-- Nest sentin8:sys:admin under sentin8:org:sys:admin so group members inherit platform scopes.
INSERT INTO auth.role_nesting (parent_role_id, child_role_id)
SELECT p.id, c.id FROM auth.roles p, auth.roles c
WHERE p.name = 'sentin8:org:sys:admin' AND c.name = 'sentin8:sys:admin'
ON CONFLICT DO NOTHING;
INSERT INTO auth.groups (id, env_id, name)
VALUES (
    gen_random_uuid(), '00000000-0000-0000-0000-000000000002',
    'sentin8:org:sys:admins'
)
ON CONFLICT (env_id, name) DO UPDATE SET updated_at = now();

-- Assign the sentin8:org:sys:admin role to the sentin8:org:sys:admins group.
INSERT INTO auth.group_roles (group_id, role_id, env_id)
SELECT g.id, r.id, g.env_id
FROM auth.groups g, auth.roles r
WHERE g.name = 'sentin8:org:sys:admins'
  AND r.name = 'sentin8:org:sys:admin'
ON CONFLICT DO NOTHING;

-- Add the default admin user to the sentin8:org:sys:admins group.
INSERT INTO auth.group_members (group_id, user_id, env_id)
SELECT g.id, u.id, g.env_id
FROM auth.groups g, auth.users u
WHERE g.name = 'sentin8:org:sys:admins'
  AND u.email = 'a@m.n'
ON CONFLICT DO NOTHING;

-- ── Remove pre-uniform-naming role names ───
-- Day-one cleanup: drop any legacy hyphen-form or unprefixed role names
-- (sentin8-admin, sys:admin, org:sys:admin, …) and their assignments so
-- stale scopes can't linger alongside the uniform sentin8:*-prefixed set.
DELETE FROM auth.user_roles WHERE role_id IN (
    SELECT id FROM auth.roles
    WHERE name = 'sentin8-admin' OR name NOT LIKE 'sentin8:%'
);
DELETE FROM auth.roles
WHERE name = 'sentin8-admin' OR name NOT LIKE 'sentin8:%';

-- ── sentin8:sys:users role (auto-assigned at sign-up for platform operators) ──
-- Every new platform operator who signs up is automatically added to this
-- role so they get the basic scopes needed for self-service (create org,
-- read dash, etc.). This role does NOT include org-admin scopes - those
-- are granted by the `sentin8:org:admin` role which is auto-assigned when the
-- operator creates an org.
INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(),
    '00000000-0000-0000-0000-000000000002',
    'sentin8:sys:users',
    ARRAY[
        -- Sentin8:Dash: operators can create orgs and envs
        'sentin8:dash:org:create', 'sentin8:dash:env:create',
        -- Sentin8:App: browse store + read instances
        'sentin8:app:store:read', 'sentin8:app:instances:read',
        -- Sentin8:Storage: read storage
        'sentin8:storage:env:read',
        -- Sentin8:Bus: consume events
        'sentin8:bus:consume'
    ]
)
ON CONFLICT (env_id, name) DO UPDATE SET
    permissions = EXCLUDED.permissions;

-- ── sentin8:sys:view role (read-only platform access for platform operators) ──
INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(),
    '00000000-0000-0000-0000-000000000002',
    'sentin8:sys:view',
    ARRAY[
        -- Sentin8:App: read store + instances
        'sentin8:app:store:read', 'sentin8:app:instances:read',
        -- Sentin8:Storage: read
        'sentin8:storage:env:read',
        -- Sentin8:Bus: consume
        'sentin8:bus:consume'
    ]
)
ON CONFLICT (env_id, name) DO UPDATE SET
    permissions = EXCLUDED.permissions;

-- ── sentin8:org:admin role (nests service-admin roles for org-level admin) ──
INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(),
    '00000000-0000-0000-0000-000000000002',
    'sentin8:org:admin', ARRAY[]::TEXT[]  -- scopes come from nested service-admin roles
)
ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

-- Nest service-admin roles under sentin8:org:admin
INSERT INTO auth.role_nesting (parent_role_id, child_role_id)
SELECT p.id, c.id FROM auth.roles p, auth.roles c
WHERE p.name = 'sentin8:org:admin'
  AND c.name IN ('sentin8:sys:org:admin', 'sentin8:dash:org:admin', 'sentin8:auth:admin', 'sentin8:app:admin',
                  'sentin8:db:admin', 'sentin8:storage:admin', 'sentin8:bus:admin')
ON CONFLICT DO NOTHING;

-- NOTE: org-admin nesting is dynamic - vertical service-admin roles are
-- added at runtime by `sentin8-cli vertical enroll`.

-- ── sentin8:org:view role (read-only org access) ─────────────────────
INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(),
    '00000000-0000-0000-0000-000000000002',
    'sentin8:org:view',
    ARRAY[
        'sentin8:app:store:read', 'sentin8:app:instances:read',
        'sentin8:storage:env:read',
        'sentin8:bus:consume'
    ]
)
ON CONFLICT (env_id, name) DO UPDATE SET
    permissions = EXCLUDED.permissions;

-- ── sentin8:env:admin role (nests service-admin roles for env-level admin) ──
INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(),
    '00000000-0000-0000-0000-000000000002',
    'sentin8:env:admin', ARRAY[]::TEXT[]  -- scopes come from nested service-admin roles
)
ON CONFLICT (env_id, name) DO UPDATE SET permissions = EXCLUDED.permissions;

-- Nest service-admin roles under sentin8:env:admin
INSERT INTO auth.role_nesting (parent_role_id, child_role_id)
SELECT p.id, c.id FROM auth.roles p, auth.roles c
WHERE p.name = 'sentin8:env:admin'
  AND c.name IN ('sentin8:sys:env:admin', 'sentin8:auth:admin', 'sentin8:app:admin',
                  'sentin8:db:admin', 'sentin8:storage:admin', 'sentin8:bus:admin')
ON CONFLICT DO NOTHING;

-- NOTE: env-admin nesting is dynamic - vertical service-admin roles are
-- added at runtime by `sentin8-cli vertical enroll`.

-- ── sentin8:env:view role (read-only environment access) ─────────────
INSERT INTO auth.roles (id, env_id, name, permissions)
VALUES (
    gen_random_uuid(),
    '00000000-0000-0000-0000-000000000002',
    'sentin8:env:view',
    ARRAY[
        'sentin8:app:instances:read',
        'sentin8:storage:env:read',
        'sentin8:bus:consume'
    ]
)
ON CONFLICT (env_id, name) DO UPDATE SET
    permissions = EXCLUDED.permissions;

-- ── Sentin8:Dash OAuth client ──────────────────────────────────────────────────
-- Platform-level PKCE public client for the Sentin8:Dash dashboard.
-- The client_id is `dash` - the Flutter app passes this during the
-- authorization code flow. The redirect_uri uses the BFF host since
-- Sentin8:BFF handles the callback server-side before redirecting
-- to the Sentin8:Dash frontend.
INSERT INTO auth.oauth_clients (env_id, client_id, client_name, redirect_uris, grant_types, response_types, token_endpoint_auth_method, scopes, consent_required, dpop_exempt)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    'dash',
    'Sentin8:Dash Dashboard',
    ARRAY['https://bff.dash.ops.sys.' || :'sentin8.domain' || '/auth/callback'],
    ARRAY['authorization_code','refresh_token'],
    ARRAY['code'],
    'none',
    ARRAY['openid','profile','email','offline_access',
    -- Sentin8:Sys granular
    'sentin8:sys:admin', 'sentin8:sys:org:admin', 'sentin8:sys:org:create', 'sentin8:sys:org:write', 'sentin8:sys:org:delete',
    'sentin8:sys:env:admin', 'sentin8:sys:env:create', 'sentin8:sys:env:delete', 'sentin8:sys:features:admin', 'sentin8:sys:app:admin',
    -- Sentin8:Auth granular
    'sentin8:auth:admin:read', 'sentin8:auth:admin:write',
    -- Sentin8:App granular
    'sentin8:app:store:admin', 'sentin8:app:store:read', 'sentin8:app:instances:write', 'sentin8:app:instances:read', 'sentin8:app:instances:admin',
    -- NOTE: Vertical service scopes (e.g. bank8:ledger:*, hotel8:pms:*) are
    -- NOT hardcoded here. They are runtime-registered via each vertical's
    -- vertical-registry.json `admin_scopes` during `sentin8-cli vertical enroll`.
    -- The dash OAuth client requests only platform scopes at seed time.
    -- Sentin8:DB granular
    'sentin8:db:table:admin', 'sentin8:db:data:read', 'sentin8:db:data:write', 'sentin8:db:posture:read',
    -- Sentin8:Storage granular
    'sentin8:storage:env:read', 'sentin8:storage:env:write',
    -- Sentin8:Bus granular
    'sentin8:bus:produce', 'sentin8:bus:consume',
    -- Sentin8:Dash granular
    'sentin8:dash:org:create', 'sentin8:dash:org:write', 'sentin8:dash:org:delete', 'sentin8:dash:env:create', 'sentin8:dash:env:delete',
    'sentin8:dash:sentin8ors:read', 'sentin8:dash:sentin8ors:write'],
    false, -- consent_required: first-party app, no consent prompt
    true  -- dpop_exempt: platform-owned public client (cannot produce DPoP proofs)
)
ON CONFLICT (client_id) DO UPDATE SET
    client_name = EXCLUDED.client_name,
    redirect_uris = EXCLUDED.redirect_uris,
    grant_types = EXCLUDED.grant_types,
    response_types = EXCLUDED.response_types,
    token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
    scopes = EXCLUDED.scopes,
    consent_required = false,
    dpop_exempt = true;

-- ── Sentin8:CLI OAuth client ────────────────────────────────────────────────
--
-- Platform-level PKCE public client for the sentin8-cli. Uses the OAuth 2.0
-- Device Authorization Grant (RFC 8628): `POST /oauth/device` resolves the
-- client by id (no secret - token_endpoint_auth_method = 'none'), and token
-- polling is bound to the same client_id. redirect_uris is empty (no browser
-- redirect in the device flow). The grant merges the requested scope with
-- the signing user's role scopes, so the registered scope list stays
-- minimal - CLI commands request the scope each command needs.
INSERT INTO auth.oauth_clients (env_id, client_id, client_name, redirect_uris, grant_types, response_types, token_endpoint_auth_method, scopes, consent_required, dpop_exempt)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    'sentin8-cli',
    'Sentin8 CLI',
    ARRAY[]::text[],
    ARRAY['urn:ietf:params:oauth:grant-type:device_code'],
    ARRAY[]::text[],
    'none',
    ARRAY['openid','profile','email','offline_access'],
    false, -- consent_required: first-party client, no consent prompt
    true   -- dpop_exempt: platform-owned public client (cannot produce DPoP proofs)
)
ON CONFLICT (client_id) DO UPDATE SET
    client_name = EXCLUDED.client_name,
    grant_types = EXCLUDED.grant_types,
    token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
    scopes = EXCLUDED.scopes,
    consent_required = false,
    dpop_exempt = true;


-- ── Local outbox (DBX, architecture-principles §6.7) ─────────────────────
-- Producer path: auth.outbox rows commit in the SAME transaction as the
-- domain change; a post-commit relay pushes them to Bus POST /v1/produce.
-- Generated from sentin8-outbox::outbox_table_sql("auth").
CREATE TABLE IF NOT EXISTS auth.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    -- WARN-5 (bus DESIGN §4.3, SDK outbox DDL): the retryable-failure
    -- backoff column - a 429/5xx/transport failure parks the row until
    -- this timestamp; the drain predicate skips future rows so a burst
    -- backlog drains at the rate limit instead of burning the retry
    -- budget. Matches the shared outbox DDL in the SDK outbox crate.
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_auth_outbox_unrelayed
    ON auth.outbox (created_at) WHERE relayed = false;
ALTER TABLE auth.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON auth.outbox;
CREATE POLICY outbox_select ON auth.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON auth.outbox;
CREATE POLICY outbox_insert ON auth.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON auth.outbox;
CREATE POLICY outbox_update ON auth.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION auth.auth_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('auth_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON auth.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON auth.outbox
    FOR EACH ROW
    EXECUTE FUNCTION auth.auth_notify_outbox();


-- ── Local audit journal (DBX §6.8) ────────────────────────────────────────
-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write), then
-- marked pushed. A Sys outage never drops audit. Generated from
-- sentin8-audit::audit_journal_sql("auth").
CREATE TABLE IF NOT EXISTS auth.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_auth_audit_journal_unpushed
    ON auth.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE auth.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON auth.audit_journal;
CREATE POLICY audit_journal_dml ON auth.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- ── Local post_outbox (DBX-POST-3) ────────────────────────────────────────
-- Queue for Sentin8:Post notifications (welcome emails, resets, MFA alerts).
-- The auth post pusher drains it to POST post /v1/send (M2M,
-- sentin8:post:write) - no direct post.inbox writes.
CREATE TABLE IF NOT EXISTS auth.post_outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    message_type    TEXT NOT NULL,
    category        TEXT NOT NULL DEFAULT 'system',
    priority        TEXT NOT NULL DEFAULT 'normal',
    recipient_user_id UUID,
    recipient_email TEXT,
    subject         TEXT NOT NULL,
    body            TEXT NOT NULL,
    metadata        JSONB NOT NULL DEFAULT '{}',
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_auth_post_outbox_unpushed
    ON auth.post_outbox (created_at) WHERE pushed = false;
ALTER TABLE auth.post_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth.post_outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS post_outbox_dml ON auth.post_outbox;
CREATE POLICY post_outbox_dml ON auth.post_outbox
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());


-- ── Schema grants (service-owned - the 2026-10-03 ownership pass) ─────
-- This service's own schema: USAGE for its role (platform.sql no longer
-- seeds per-service USAGE; the service declares it here).
GRANT USAGE ON SCHEMA auth TO sentin8_auth_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.outbox TO sentin8_auth_service;
-- GRANT-2: DCR gate table (read by the DCR endpoint on the pool role),
-- the secondary auth-domain read surfaces, and the local audit journal.
GRANT SELECT ON auth.m2m_scope_grants TO sentin8_auth_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    auth.app_passwords, auth.credentials, auth.grants, auth.regulatory_overlays
    TO sentin8_auth_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.audit_journal TO sentin8_auth_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.post_outbox TO sentin8_auth_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA auth TO sentin8_auth_service;
