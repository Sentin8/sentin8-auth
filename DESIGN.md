# Sentin8:Auth - Detailed Design Document

## 1. Scope & Context

Sentin8:Auth is the platform's **single identity plane**: the only issuer
of every token family, the only JWKS authority, the DCR registrar, the
RBAC substrate (roles, groups, nesting, membership provisioning API),
consent grants, sessions, MFA/passkeys, SSO federation, webhooks, and the
OID4VCI/SD-JWT wallet surface.

- **Owns** (schema `auth`): identity + credentials (users, sessions, app
  passwords, MFA factors/challenges, WebAuthn challenges, reset/verify
  tokens, enterprise connections, SSO sessions), OAuth clients (incl. DCR
  records, federated credentials, M2M thumbprints), M2M scope grants, RBAC
  (roles, user_roles, groups, group_members, group_roles, role_nesting),
  consent grants (FAPI 2.0), wallet credentials + regulatory overlays +
  security profiles, actor tokens, webhook endpoints/outbox/attempts,
  signing keys, and the DBX producer tables (`outbox`, `audit_journal`,
  `post_outbox`).
- **Does NOT own**: org/env business records (sys provisions those and
  calls back via the provisioning API), tenant app instances, Shield
  policy storage (sys's `policy_sets` is the substrate; auth runs an
  engine on it), invitations (proxied to sys), e-signature (QES delegated
  to bank8-payments - `signature_request` returns NOT IMPLEMENTED).

```mermaid
graph TD
    subgraph callers["Callers"]
        BFF["sentin8:bff (user flows)"]
        CLI["sentin8-cli (device flow)"]
        SVC["All services (M2M + bearer verify SDK)"]
        SYS["sentin8:sys (provisioning)"]
        SCIM["SCIM clients"]
        WAL["EUDI wallet"]
    end

    subgraph AUTH["sentin8:auth"]
        OAUTH["OAuth/OIDC core<br/>authorize · PAR · token · mtls token ·<br/>device · CIBA · introspect · revoke ·<br/>userinfo · grants · logout"]
        DCR["DCR /oauth/register<br/>(cert-bound for client_credentials)"]
        IDP["Identity surface<br/>sign-in/up/out · sessions · MFA · passkeys ·<br/>recovery · app passwords · branding"]
        RBAC["RBAC + provisioning API<br/>/v1/admin/provision/*"]
        ADMIN["Admin API + RFW UI"]
        JWKS["JWKS + signing keys<br/>(ML-DSA-65 / RS256)"]
        HOOKS["Webhook relay + outbox"]
    end

    SYS -- "provision verbs" --> AUTH
    SVC -- "verify bearer (SDK, JWKS)" --> AUTH
    SVC -- "DCR / client-cert mints" --> DCR
    BFF --> OAUTH
    CLI --> OAUTH
    WAL -- "OID4VCI / SD-JWT VP" --> AUTH
    AUTH -- "webhooks (HMAC)" --> HOOKS
    AUTH -- "post_outbox → POST /v1/send" --> POST["sentin8:post"]
    AUTH -- "audit spill → POST /v1/audit" --> SYS
    AUTH -- "auth.outbox → produce" --> BUS["sentin8:bus"]
```

## 2. Runtime Architecture

```mermaid
graph TD
    subgraph EDGE["Edge (shell-owned)"]
        MW["correlation · host-context · TLS-context ·<br/>logging · CORS · outbox relay (5s)"]
    end
    subgraph ROUTES["Router groups (no extra middleware)"]
        OAUTH["oauth.rs - authorize/par/token/mtls/<br/>device/ciba/introspect/grants/revoke/userinfo"]
        DCR["dcr.rs - register/manage clients"]
        ID["identity handlers - sign-in/up, sessions,<br/>MFA, passkeys, recovery, app-passwords"]
        LOGIN["login_page.rs - HTML login form<br/>(automated clients, §9a.8)"]
        ADM["admin.rs - users/roles/groups/clients/<br/>sessions/api-keys/memberships/audit + RFW"]
        PROV["provision.rs - /v1/admin/provision/*"]
        SCIMR["scim.rs - SCIM 2.0"]
        WALLET["wallet.rs + sd_jwt.rs"]
        SSO["enterprise SSO + SAML"]
        HOOKS["webhooks.rs admin"]
    end
    subgraph TASKS["Spawned tasks"]
        PUSH["post pusher (10s loop)"]
        WREL["webhook relay (1s tick, batch 25)"]
    end
    subgraph STORE["State"]
        POOL[("capped PG pool<br/>schema auth")]
        VK[("Valkey: authcodes, PAR, CIBA,<br/>device codes, denylists, rate/lockout")]
        KEYS[("auth.signing_keys")]
    end

    EDGE --> OAUTH & DCR & IDP & ADM & SCIMR & WALLET & SSO & HOOKS
    IDP --> ID["identity handlers"]
    ADM --> POOL
    OAUTH --> VK
    OAUTH --> KEYS
    PUSH --> POST2["post"]
    HOOKS --> POOL
```

**Request lifecycle - authorization-code token issuance (FAPI 2.0
posture, platform profile):**

```mermaid
sequenceDiagram
    autonumber
    participant CL as client (BFF/app)
    participant T as POST /oauth/token
    participant VK as Valkey
    participant DB as auth schema
    participant P as SecurityProfile

    CL->>T: grant_type=authorization_code + code + PKCE verifier
    T->>T: authenticate_client (method per client:<br/>secret/basic/private_key_jwt/tls/thumbprint/none)
    alt client auth fails
        T-->>CL: 401 invalid_client (uniform - no existence oracle)
    end
    T->>VK: GETDEL auth:authcode:{code} (one-time)
    T->>T: PKCE verify + redirect allowlist + profile flags<br/>(PAR consumed, JARM, DPoP proof optional→cnf)
    T->>DB: sessions INSERT + claims build (scopes = requested ∪ live roles)
    T-->>CL: 200 {access(900s), refresh(30d, rotated), id_token}
    T->>VK: SETEX auth:revoked:{old refresh jti}
    Note over T: replay of rotated refresh → invalid_grant
```

**M2M issuance (cert-bound, the platform identity path):**

```mermaid
sequenceDiagram
    autonumber
    participant W as workload
    participant M as /mtls/oauth/token
    participant DB as auth schema

    W->>M: client_credentials + mTLS client cert
    M->>M: mtls_alias guard (cert header present)
    M->>DB: load oauth_clients by thumbprint/DN
    alt thumbprint mismatch (cert re-issued)
        M-->>W: 401 invalid client
    end
    M->>M: build cnf.x5t#S256 + RFC 8707 aud
    M->>DB: trace insert + outbox
    M-->>W: 200 m2m token (token_tp="m2m", 3600s)
```

## 3. Data Model

```mermaid
erDiagram
    USERS ||--o{ SESSIONS : "holds"
    USERS ||--o{ USER_ROLES : "assigned"
    USERS ||--o{ GROUP_MEMBERS : "member of"
    USERS ||--o{ APP_PASSWORDS : "owns"
    USERS ||--o{ MFA_FACTORS : "enrolled"
    USERS ||--o{ ACTOR_EVENTS : "actor/target"
    ROLES ||--o{ USER_ROLES : "grants"
    ROLES ||--o{ GROUP_ROLES : "via groups"
    GROUPS ||--o{ GROUP_MEMBERS : "contains"
    GROUPS ||--o{ GROUP_ROLES : "binds"
    ROLE_NESTING {
        uuid parent_role_id PK
        uuid child_role_id PK
    }
    OAUTH_CLIENTS ||--o{ CLIENT_ROLES : "assigned"
    OAUTH_CLIENTS ||--o{ FEDERATED_CREDENTIALS : "federates"
    OAUTH_CLIENTS ||--o{ GRANTS : "consented"
    USERS ||--o{ CREDENTIALS : "wallet"
    USERS ||--o{ ENTERPRISE_CONNECTIONS : "SSO"
    WEBHOOK_ENDPOINTS ||--o{ WEBHOOK_OUTBOX : "queues"
    WEBHOOK_OUTBOX ||--o{ WEBHOOK_ATTEMPTS : "logs"
    USERS {
        uuid id PK
        string email
        string status "active|suspended|archived|locked"
        bool mfa_enabled
    }
    SESSIONS {
        string token_id UK
        string status "active|revoked|expired"
        timestamptz expires_at
    }
    OAUTH_CLIENTS {
        string client_id UK
        string token_endpoint_auth_method
        text[] grant_types
        string tls_client_auth_subject_dn
        string self_signed_tls_client_auth_thumbprint
        bool consent_required
        bool dpop_exempt
    }
    MFA_FACTORS {
        string factor_kind "totp|webauthn|backup_code"
        bytea secret_cipher "AES-encrypted"
        string status "pending|active|disabled"
    }
    CREDENTIALS {
        string format "sd_jwt"
        string status "active|revoked"
        jsonb cnf_jwk
    }
    SECURITY_PROFILES {
        string scope "platform|org|env"
        string profile "fapi_2|…"
        bool require_dpop
        int max_token_lifetime
    }
```

- **RLS**: FORCE RLS on all tenant tables (env policies; junctions carry
  their own `env_id` for direct RLS; `role_nesting` gated on the parent
  role's env). **No-RLS exceptions** (platform-internal): `m2m_dcr_credentials`
  (auth's own workloads only), `m2m_scope_grants` (anonymous DCR endpoint
  evaluates server-side), `webhook_attempts` (relay-written), and
  `actor_revocations` (`USING (true)` - revocation is jti-scoped, not
  env-scoped).
- **State machines**:

```mermaid
stateDiagram-v2
    direction LR
    state session {
        [*] --> active: sign-in
        active --> revoked : sign-out / admin
        active --> expired : expiry
    }
    state factor {
        [*] --> pending: enroll begin
        pending --> active: verify
        active --> disabled
    }
    state grant {
        [*] --> active: record_grant
        active --> revoked: delete (cascade jti)
    }
    state listings {
        [*] --> listing: RFW admin surface mounted
        listing --> revoked : admin (RFW admin surface)
        revoked --> active : access re-granted
    }
```

- **Secrets posture**: TOTP secrets, webhook secrets, client secrets are
  encrypted (`secret_cipher` BYTEA / hash); signing keys persisted
  AES-sealed under the master key; no plaintext secrets in any table.
- **Seeds**: platform admin user + the platform role/nesting catalog +
  `dash` (public PKCE, dpop_exempt) + `sentin8-cli` (device flow) clients.

## 4. API Surface

| Audience | Group | Gate |
|----------|-------|------|
| public | `/.well-known/*`, `/oauth/authorize(+continue)`, `/oauth/par`, `/oauth/token`, `/oauth/device`+`/device/verify`, `/oauth/userinfo`, `/oauth/logout`, `/oauth/login` (HTML form, §9a.8), `/v1/sign-in\|up\|out`, `/v1/branding`, `/v1/health` | session/cookie or client auth per flow; bot protection + lockout on sign-in |
| mTLS | `/mtls/oauth/token`, `/mtls/oauth/revoke` | cert-presence guard; client auth per DCR method - retained for out-of-band/tenant clients only; **platform workloads never fetch tokens (§4.3f)** |
| workload | `POST /oauth/register` (DCR) | interactive clients open; **client_credentials-only requires mTLS cert** + CN ∈ `m2m_scope_grants` + scopes ⊆ grant - retained for out-of-band tenant clients; platform workloads never DCR (§4.3f) |
| delegated | `POST /delegate/access-token` | verified M2M bearer + `sentin8:delegate:read` + cnf match |
| wallet | `/oauth/credentials*`, `/oauth/vp/response`, `/v1/auth/wallet/metadata` | bearer / VP verified (SD-JWT key binding + status list) |
| consent | `/v1/auth/consent/*` | session-validated; proxied to owning vertical |
| admin | `/v1/admin/{users,roles,groups,oauth-clients,api-keys,sessions,memberships,invitations,audit}` + RFW UI | `route_guard` + `require_sentin8or_access(_write)` + Shield |
| provisioning | `POST /v1/admin/provision/{role,role_nesting,group,group_role,group_member,user_role}` | admin bearer + `x-sentin8-target-env-id` header (env-scoped), idempotent upserts |
| SCIM | `/scim/v2/Users`, `/scim/v2/Groups`, metadata | `sentin8:scim:read`/`write` |
| security | `/v1/security-profile`, `/v1/admin/security` | admin bearer |
| webhooks | `/v1/admin/webhooks/{endpoints,outbox,attempts}` | Shield |
| health | `/v1/health` | none |
| MFA / passkey | `/v1/mfa/*`, `/v1/passkey/*` | bearer / session (+ rate limits) |
| recovery | `/v1/password/reset(+confirm)`, `/v1/email/verify(+confirm)` | none (enumeration-safe, token-gated confirm) |
| app passwords | `/v1/me/app-passwords` | self service (session/bearer) |
| CIBA | `/oauth/bc-authorize`, `/v1/ciba/*` | client auth on bc-authorize; session on approve/assisted |
| grants (FAPI 2.0 GM) | `/oauth/grants(/{id})` | user or admin per action |
| policy (Shield) | `/v1/admin/policy-sets(/{name})`, `/v1/admin/{relations,attributes}` | shield admin gate (`sentin8:admin`) |
| internal | `POST /v1/internal/keys/rotate` | admin (route-guard backstop) |

**OpenAPI spec.** The single source of truth for the served surface is the
`#[utoipa::path]` annotations on the handlers + the `#[openapi(paths(...))]`
list in `src/openapi.rs`; `docs/openapi.json` is the dumped artifact via
`--print-registration --section=openapi` (regenerated from the binary, never
hand-edited) and renders each service site's API reference page (sites
design §4.2). The generic Shield handlers cannot be pathed directly
(utoipa 5.5 resolves paths to non-generic `__path_` structs), so the inline
policy mount binds the annotated wrappers in `src/policy_docs.rs` and the
RFW POST-aliases bind `src/rfw_aliases.rs` (same operations, alias paths,
annotated per OAPEC design §2 rule 3).

**Drift guard.** `tests/openapi_drift.rs` asserts BOTH directions - every
served route appears in the compiled spec and every spec pair is served -
via the shared shell helper (`sentin8::shell::drift_guard`, router
introspection without HTTP round-trips; SPA fallback + `/openapi.json`
exempt per OAPEC §2 rule 8). A route added without an annotation fails the
test before the site pages can trail the routers.

**Event flow (outbox → Bus):**

```mermaid
sequenceDiagram
    autonumber
    participant H as handler tx
    participant O as auth.outbox
    participant R as relay (shell, LISTEN auth_outbox_changed)
    participant B as bus stream auth
    participant W as webhook relay (1s tick)

    H->>O: INSERT event (same tx)
    R->>B: POST /v1/produce (M2M sentin8:bus:produce)
    H->>W: enqueue_event → webhook_outbox (subscriber filter)
    W->>W: HMAC-SHA256 sign payload
    W->>W: POST endpoint.url (x-sentin8-signature)
    alt delivery fails
        W->>W: backoff 30s·2^n, max 5 → failed_at
    end
```

Event family `auth`; names `sentin8:auth:{user,role,group,client,credential,apikey,session,membership,dcr,connection,mfa,passkey,actortoken,securityprofile,webhook,grant,ciba}:{action}` - payload-complete envelopes. Session revocations
(`sign-out`, OAuth refresh-token revoke, password reset, admin terminate) emit
`sentin8:auth:session:revoked` - payload-complete envelope `{subject_id,
env_id, session_id, revoked_by, reason}` (continuous access evaluation,
README §7): the BFF session-reaper subscription (bff DESIGN §10) consumes the
`auth` family (group `bff-session-reaper`) and kills every cached BFF session
for the subject, so role/consent changes take effect immediately instead of at
the store TTL.

Grant lifecycle (FAPI 2.0 Grant Management, grants.rs): every standing
authorization emits its transition. Code issuance records/merges the grant
(`record_grant` at the authorization-code exchange) and emits
`sentin8:auth:grant:created` - payload `{grant_id, client_id, user_id,
env_id, scope, state, selected_account_ids}` where `state` is the client's
opaque OAuth state (the consent handle a vertical's consent flow packed into
PAR) and `selected_account_ids` are the accounts the customer selected on a
hosted consent screen. Downstream consent authorities (e.g. Bank8:FDX's
provider plane, fdx DESIGN §1) seed their data-holder grant ledgers from this
event - the authorization server is the seed of open-banking grant truth.
Grant revocation emits `sentin8:auth:grant:revoked`
(`{grant_id, user_id, client_id}`).

## 5. Cross-Cutting Concerns

```mermaid
graph LR
    REQ["request"] --> V["verify bearer<br/>(issuer·sig·exp·aud·token_tp)"]
    V --> T["resolve tenant (env_id)"]
    T --> P["Shield require_policy<br/>(live roles+scopes)"]
    P --> RLS["set_tenant_context (tx-local)"]
    RLS --> EXEC["handler executes"]
    EXEC --> AUD["audit + outbox + journal"]
```

- **Token verification** is SDK-reused by every service
  (`sentin8::auth::client`) - auth is the only JWKS authority.
- **Rate limiting / bot protection**: IP 10/min, email 5/min sliding
  windows; 5 failures → durable `locked` status (config TTL); dummy bcrypt
  compare on unknown accounts (no email enumeration).
- **DPoP**: proof validation (htm/htu/iat/nonce/ath) with jti replay
  protection (SETNX 300s); `cnf.jkt` on access tokens; clients opt out via
  `dpop_exempt`.
- **FAPI 2.0 posture**: platform profile enforces PAR + JARM + DPoP +
  RFC 9449 issuer binding + 900s max token lifetime + refresh rotation;
  env/org profiles override (`security_profiles`).
- **Introspection honesty**: `none`-auth clients hard-rejected;
  JWT-introspection responses signed per profile.
- **Back-channel logout**: logout token issued to registered
  `backchannel_logout_uri` per client.

### 4.3f Token-free platform M2M (CERTFREE-1) - the certificate is the service identity

Platform workloads authenticate with **no token at all**: the caller presents
its Acme-issued client certificate (`CN=m2m-{workload}`) in the TLS
handshake, `sentin8-tls` CA-verifies it and injects
`X-Sentin8-Client-Cert-Subject` / `-Thumbprint` headers (client-supplied
copies stripped), and the receiving service trusts those headers exactly as
it trusts `X-Sentin8-Env-Id` - the TLS layer is the authentication. Auth's
role in platform M2M shrinks to **issuing identity material (the
certificate, via Acme) and provisioning the authorization record (the
grant rows, via `vertical enroll`)**. No M2M JWT is minted, fetched,
cached, or verified for platform service→service calls.

**Why (the defect class this closes):** the M2M token was a second identity
surface that had to stay synchronized with the certificate identity across
three stores (SDK credential cache → `oauth_clients` → JWT claims). A
database reset desynchronized them by construction - cached `client_id`s
outlived their rows - producing the fleet-wide
`M2M token fetch failed: status 401` storm after every reset. A token is
also a redundant proof: the TLS handshake ALREADY establishes exclusive
possession of the certificate's private key on every call; a bearer minted
from that same possession adds no strength, only state.

```mermaid
sequenceDiagram
    participant W as Workload (client cert, no token)
    participant TLS as sentin8-tls (platform CA)
    participant S as Receiving service
    participant V as Valkey m2m:workloads<br/>(boot-load + TTL cache)
    W->>TLS: HTTPS call, handshake presents CN=m2m-{workload}
    TLS->>S: X-Sentin8-Client-Cert-Subject/-Thumbprint<br/>(CA-verified, client copies stripped)
    Note over S: TLS context middleware → identity = {workload, thumbprint}
    S->>V: local cache: workload → {vertical, service_type, scopes, enabled}
    alt row missing or enabled=false
        S-->>W: 401/403 (not enrolled / revoked)
    end
    S->>S: Shield evaluates scopes (RequestCtx: subject=workload, scopes=map)
    S->>S: Bus vertical gate / audit service=workload
```

**The authorization record travels as the registry map.** `sentin8-cli
vertical enroll` already provisions `auth.m2m_scope_grants` and publishes
`captain:*` Valkey keys; it additionally publishes a `m2m:workloads` hash -
`{workload} → {vertical, service_type, scopes[], enabled}` - and every
service boot-loads it and TTL-caches it (the platform's mandated pattern:
owner data is seeded on cold start / cache miss, never read on the request
path - §4.14/§6.6). This answers the three consumers the token previously
fed:

| Consumer | Was (token claim) | Now (map field) |
|---|---|---|
| Shield `RequestCtx` (scope-gated rules) | `scope` | `scopes` (roles: none - M2M workloads never had role assignments) |
| Bus VDC-2 event-ownership gate | `vertical` | `vertical` (produce + consume identity checks) |
| Audit `service` stamp / Sys tenant-snapshot | `sub` (opaque hex) / `service_type` | CN directly / `service_type` |

**Revocation** is the map's `enabled` flag: `vertical enroll` (or the admin
surface) flips it, every service's cache observes it within the TTL, and the
workload's calls are refused. This is *more immediate* than the token path
(a minted token lives to expiry regardless) and is bounded by the cache
TTL. Handshake-level certificate revocation (a stolen cert's *validity*)
remains a follow-up (CERTFREE-2) - a pre-existing gap, not a regression.

**Security posture vs the token design (2026-10-07 review):** the move is a
net improvement - per-call proof-of-possession (the token was a pure bearer
at the target; `verify_cert_binding` was a stub) and fleet-wide revocation
where none existed for M2M JWTs. The multi-tenant boundary does not move:
tenancy was never carried by machine identity (WARN-21: the request's env
is authoritative for M2M), and RLS + explicit `env_id` clauses + Shield
remain the tenant gates. Two new risks are ACCEPTED-AND-FILED:

- **The map's write surface is authorization escalation.** Any process
  with Valkey write access can `HSET m2m:workloads` itself any scope set,
  and the 30s TTL propagates it fleet-wide - a primitive the
  signature-verified token design denied (scopes were minted from a DB row
  Auth signed). Countermeasure: Valkey ACLs (CERTFREE-4) - m2m:* writes
  restricted to the operator/enroll writer identity; services hold a
  read-only reader identity.
- **Certificate lifetime bounds the theft window.** The 365-day default
  mint + no expiry check in the load path (a day-366 fleet brick) is
  tightened to a 30-day default with load-path NotAfter verification and
  auto re-mint (CERTFREE-5), alongside CERTFREE-2's CRL.
- Per-instance distinguishability collapses to the workload name (two
  instances share `{workload}.crt`) - accepted; audit identifies
  workloads, never instances.

**Invariants (CERTFREE-1):**

- The certificate is the *only* platform-workload credential: no secret, no
  bearer, no assertion. The `m2m-` CN prefix is minted exclusively by
  Acme's guarded issuance channels (bootstrap enrollment - pinned to the
  declared set by CERTFREE-3; self-issuance `sub == service_name`; the
  enroll operator scope).
- The TLS-injected headers are trustworthy because (a) `sentin8-tls`
  injects them only after CA verification, (b) client-supplied copies are
  stripped before the app sees them, and (c) they exist only on
  TLS-terminated platform hops - the same trust model `X-Sentin8-Env-Id`
  already carries.
- A workload can only ever exercise scopes its map entry allows (Shield
  evaluates from the map; policy rules are unchanged).
- `oauth_clients` and DCR survive for interactive clients (auth-code,
  device flow, BFF apps, dash) and out-of-band tenant clients
  (`client_secret_basic`/`private_key_jwt` per registration) - Auth
  remains the single identity plane for every HUMAN-facing flow; the
  token-free plane covers machine-to-machine platform calls only.
- **Rejected:** keeping the token as "extra" (it was the storm's root
  cause and adds no proof beyond the handshake); services reading
  `auth.m2m_scope_grants` directly (§4.7 - the map is the transport, no
  cross-schema grants); a live Auth resolve API per request (per-request
  dependency, banned by the runtime discipline).

**What is deleted for the platform path:** `/mtls/oauth/token`
`client_credentials` use by platform workloads; the `sentin8-m2m` token
source, DCR helper, credential cache, boot probe, and 401 self-heal
machinery (the crate shrinks to certificate mint-if-missing, renamed for
its real job); `build_with_dcr` background DCR retries in bus-client; every
service's boot-time DCR block; the `cli-producer` / `cli-delegator` /
`bff-delegator` token workloads (the CLI and BFF present certificates);
BFF's env-credential fallback. Delegated tokens keep their `cnf`
cert-binding (unchanged) - BFF presents its certificate and receives a
delegated JWT as today; only the *workload's own* M2M JWT disappears.

## 6. Failure Modes & Recovery

```mermaid
flowchart TD
    A[refresh replay] --> B{denylist hit?}
    B -- yes --> C[invalid_grant - replay detected]
    B -- no --> D[rotate + denylist old jti]
    E[Valkey down] --> F[denylist fail-open = false<br/>rate-limit checks skip]
    F --> G[DB predicates backstop expiry]
    H[webhook delivery fail] --> I[retry 30s·2^n ×5]
    I --> J[failed_at marked]
    K[master key wrong] --> L[boot failure - refuse to start]
    M[Bus down] --> N[outbox rows persist<br/>5s safety poll]
    O[Post down] --> P[post_outbox unpushed rows retried]
```

- **JWKS rotation**: insert-new-key overlap (all persisted keys published);
  no scheduled rotation task - old tokens verify until expiry.
- **Session expiry**: enforced by predicates; no sweeper (rows are
  harmless after expiry).
- **DCR storm protection**: anonymous DCR gated by `m2m_scope_grants`
  (service must be enrolled) + cert channel possession proof. Platform
  workloads never DCR and never fetch tokens (§4.3f) - a DB reset can no
  longer strand cached `client_id`s; a missing grant row surfaces as a
  named workload refusal (`workload not enrolled`) from the registry map,
  fixed by enrollment.
- **Token-free M2M failure modes (§4.3f)**: certificate missing at boot →
  Acme mint (bootstrap channel, declared-set-pinned) → retry with backoff;
  map row missing/disabled → 401/403 until enroll/revocation is reverted
  (the map is the authorization record); Valkey down at boot → services
  start with the last cache file / an empty map and refuse unenrolled
  workloads fail-closed (enrolled workloads ride the persisted cache
  copy); map edit → next TTL refresh reflects it.

## 7. Concurrency & Performance Model

```mermaid
graph LR
    REQ["request tasks (axum)"] --> POOL[("capped pool (3)")]
    VAL[("Valkey")] -- "codes, PAR, CIBA, denylists, rate" --> REQ
    PP["post pusher task (10s)"] --> POST["POST /v1/send<br/>(category vocabulary:<br/>transaction|security|<br/>marketing|system)"]
    PO2[("auth.post_outbox")] --> PP
    WR["webhook relay task (1s, batch 25)"] --> WO[("auth.webhook_outbox")]
    WR --> EP["webhook endpoints"]
    RELAY["outbox relay (shell)"] --> O[("auth.outbox")]
    O --> RELAY
```

- Sign-in hot path: 2 PG round-trips + 3 Valkey ops (rate, lockout,
  session); JWKS cached 5 min in every consumer SDK.
- Token minting: one signing op (ML-DSA-65); key material cached in
  process.
- Webhook relay batches 25 per tick to bound endpoint fan-out.
- **Post pusher identity is process-lifetime.** The `auth-post`
  `TokenSource` is resolved once and reused across passes (audit-pusher
  pattern, `crates/audit` §6.8): the cached token covers ~10 passes
  before the 60s-before-expiry refresh, and a 401 triggers the m2m
  crate's single-flight self-heal (re-issue + re-DCR, 60s cooldown) -
  never a per-pass `register_or_load_m2m_client` load + credential
  probe + fresh mTLS client. A per-pass rebuild would run two PQ TLS
  handshakes + two token POSTs every 10s whose transient allocations
  ratchet glibc arenas (observed idle RSS growth ~2 MB/min, AGENTS
  target-state rule: no transitional churn paths).

### 7.1 Invalidation triggers on access-grant mutations (policy family)

Identity-cache invalidation (policy runtime's recognized triggers:
`sentin8:sys:identity:updated`, `sentin8:auth:membership:created|deleted`
- sentin8-policy runtime.rs `invalidation_env_id`) rides the SYSTEM-env
`policy` stream because policy consumers (every service's M2M workload)
are registered in the SYSTEM env - that is the transport, not a policy
choice. The shell outbox relay holds exactly one M2M workload
(SYSTEM-env, `sentin8:bus:produce`), and Bus's produce gate
(`env_id does not match the authenticated tenant`) rejects any row whose
`env_id` differs from the token's env: **tenant-env outbox rows can
never reach the `policy` stream**. Therefore every mutation that grants
or revokes access emits, in the SAME transaction as the domain change,
a SYSTEM-env row (`SENTIN8_SYSTEM_ENV_ID`, family `policy`, event
`sentin8:auth:membership:created`/`sentin8:auth:membership:deleted`,
payload `{"env_id": <affected tenant env>, "user_id": <subject>}`) -
env to sweep rides the payload (the tenant-env fan-out row for domain
consumers stays, on the `auth` family). Covered mutations: sign-up
closure provisioning (`auto_add_to_app_groups`, one invalidation per
env touched), admin group member add/remove, and the cross-service
provisioning endpoint `provision_group_member`. Emission is
best-effort: an RLS/failure drop logs and degrades to the RoleResolver
30s TTL. The tenant context on the emitting transaction is switched to
SYSTEM for the invalidation INSERT (`set_config` is transaction-local)
and restored for any subsequent tenant-plane statement - policies on
`auth.outbox` match `env_id = current`, so the row must be written
under the env it carries.

## 8. Invariants, Insecure-Defaults Rejected, Unsafe Rationale

1. **Single identity plane** - no other service mints tokens/JWKS; the
   provisioning API is the only cross-service write path to `auth.*`
   (cross-schema INSERTs retired).
2. **M2M is certificate-bound by default** - a stolen token without the
   key is useless; DCR for `client_credentials` requires the mTLS cert
   channel (no dev fallback).
3. **`scope` is not the decision** - handlers never re-check scopes; step
   5 resolves live identity.
4. **Refresh rotation + jti denylist** - replay within TTL is detectable;
   fail-open only on cache outage (expiry predicates backstop).
5. **No existence oracle** - uniform `invalid_client`; dummy bcrypt on
   unknown accounts.
6. **Tenant-scoped uniqueness** - emails/roles/groups unique per
   `(env_id, …)`; sessions carry `token_id` UNIQUE.
7. **Actor tokens are time-boxed and audited** - TTL clamp ≤ 3600s,
   `auth.actor_events` + jti revocation table.
8. **Keys persisted + encrypted**; wrong/rotated master key refuses boot.
9. No `unsafe` in the service; manual ML-DSA-65 signing wrapped in the
   crypto provider boundary.
10. **No per-pass identity churn.** Long-lived background pushers bind
    their M2M `TokenSource` for the process lifetime; identities are
    re-established by the token-source self-heal on 401, not by
    rebuilding clients every pass (DESIGN §7).
11. **Invalidation rows carry SYSTEM env.** An access-grant mutation's
    invalidation row is written under the SYSTEM tenant context with
    `env_id = SENTIN8_SYSTEM_ENV_ID`; a tenant-env row is silently
    dropped by RLS at emit time (policy `outbox_insert`: `env_id =
    current`) and denied at the Bus produce gate - both fail closed
    (DESIGN §7.1).
12. **Auth reads `sys.app_instances` only through Sentin8:App's owner
    API.** The sign-up closure provisioning needs the env's
    customer-mode (allow_signup) instance ids: the former direct-table
    read violated DBX §6.6a (auth held no grant on `sys.app_instances`
    after the sys.* grant retirement - the read failed RLS-grantless
    and "provisioned NO permission closure" on every customer-env
    sign-up). Target state: `auto_add_to_app_groups` calls Sentin8:App
    `GET /v1/app/instances/customer-mode?env_id=…` (M2M workload
    `auth-sys`, scope `sentin8:app:instances:read`, env-bound) - the
    owner never shares tables (DESIGN §7.1).

## 9. Testing Strategy

```mermaid
graph TD
    U["In-module unit tests (26 modules)<br/>DPoP/JAR/JARM/mTLS/SD-JWT/webhook-HMAC/<br/>MFA roundtrip/JWKS dual-keyset/bot protection"]
    I1["integration.rs (21)<br/>flows, tenant isolation, admin gates,<br/>consent, DCR cert gate"]
    OG["openapi_drift.rs (2)<br/>router ↔ spec drift guard<br/>(OAPEC §3, both directions)"]
    I2["conformance.rs (11)<br/>PAR single-use, rotation replay,<br/>DPoP/PKCE replay, CSRF"]
    I3["conformance_profiles + sec_auth2 +<br/>publisher_exchange (17)<br/>profile overrides, forged tokens,<br/>act chains"]
    C["OIDF conformance rig (§9a)<br/>Basic+Config+Dynamic+Logout OP ·<br/>FAPI2+FAPI1+CIBA · OID4VCI/VP · IDA<br/>(local OIDF suite, classical mode)"]
    E["E2E - browser auth flows via BFF"]
    U --> I1 & I2 & I3
    OG -.fails CI on any unannotated route.-> I1
    I1 --> E
    E --> C
    C -.gate before any certification submission.-> SUB["OIDF submission<br/>(open-source fee waiver)"]
```

- OpenID certification live flows run against a dedicated local
  conformance rig (§9a) - the OIDF suite's own tests are not part of the
  in-service test binary. The rig is the pre-certification gate: every
  profile in §9a must be green locally before a certification submission
  is prepared.
- Deliberately not covered in-service: real IdP SSO round-trips, PQ TLS
  transport (platform-level).

## 9a. OIDF Certification Program (conformance rig)

Sentin8:Auth is certified through the OpenID Foundation conformance
suite (gitlab.com/openid/conformance-suite). The suite is open source
and free to run; certification fees are waived for this project under
the OIDF open-source project certification policy. The program covers
every profile the platform implements except two deliberate exclusions.

### 9a.1 Certification scope (target state)

| Profile family | Certifiable profiles | Suite posture |
|---|---|---|
| OIDC Core | Basic OP, Config OP, Dynamic OP | code flow + discovery + DCR; the deprecated response types are excluded (below) |
| OIDC Logout | RP-Initiated Logout, Back-Channel Logout | both endpoints implemented; Front-Channel Logout is an exclusion |
| FAPI 2 | Security Profile OP, Message Signing OP | the platform-default `fapi_2` profile |
| FAPI 1 | Advanced OP (final) | `fapi_1_advanced` profile |
| FAPI-CIBA | Poll mode, Ping mode | `bc-authorize` + CIBA grant + ping delivery |
| OID4VCI | Issuer | wallet credential-issuance surface |
| OID4VP | Verifier | wallet presentation surface |
| Identity Assurance (eKYC-IDA) | OP | `claims`/`verified_claims` at authorize |

**Deliberate exclusions (design decisions, never to be reintroduced):**

- **Implicit OP / Hybrid OP** - the implicit and hybrid response types
  (`token`, `id_token`, `id_token token`, `code token`, …) are deprecated
  by OAuth 2.1 and forbidden by FAPI. `response_types_supported` is
  exactly `["code"]` and the authorize handler rejects any other value.
- **Front-Channel Logout** - third-party iframes are a tracking surface
  and silent-failure mode; logout signaling is back-channel only
  (`backchannel_logout_supported: true` is advertised in discovery, no
  `frontchannel_logout_uri` client field, no session iframe).

### 9a.2 Local conformance rig (how the tests run)

The certification pipeline is fully local and reproducible. No OIDF
account or payment is needed until a certification submission is filed.

```mermaid
graph TD
    subgraph RIG["conformance rig (.tmp/conformance/, docker network)"]
        M[("mongodb<br/>suite result store")]
        S["conformance-suite server<br/>(OIDF prebuilt image)"]
        N["suite ingress nginx<br/>https://localhost.emobix.co.uk:8443"]
        A["automated browser<br/>(suite Visit button / Playwright)"]
    end
    subgraph PLAT["local platform (classical mode)"]
        P["Sentin8:Proxy ingress<br/>*.local.sentin8.dev:443"]
        AUTH["sentin8:auth"]
    end
    N -- "redirect_uri + bc<br/>https://localhost.emobix.co.uk:8443/test/a/{alias}/callback" --> AUTH
    S -- "PAR / token / introspect /<br/>JWKS / DCR / bc-authorize" --> P
    A -- "sign-in + consent via UI" --> P
    M --- S
```

**Rig mechanics:**

1. **Suite stack** - the OIDF `docker-compose-prebuilt.yml` (mongo +
   server + nginx) runs under `.tmp/conformance/` with
   `BASE_URL=https://localhost.emobix.co.uk:8443`, pinned via
   `IMAGE_TAG` for reproducible runs. `localhost.emobix.co.uk` resolves
  to 127.0.0.1 in `/etc/hosts`.
2. **Certification environment** - a dedicated org + env (`cert`) whose
   security profile is `standard` (for OIDC Core/Config/Dynamic runs)
   or `fapi_2` / `fapi_1_advanced` (FAPI runs). One test user with a
   known password, seeded through the BFF API exactly like an E2E test
   (no direct SQL - AGENTS E2E rule applies to the rig too).
3. **Suite-visible posture (classical mode)** - the rig environment
   sets `SENTIN8_TLS_PQ_MODE=classical` (TLS 1.2/1.3 + RSA/ECDSA certs,
   JWT signing RS256) because the suite's Java client cannot speak the
   platform's post-quantum-only TLS or verify ML-DSA-65 JOSE. The
   production posture (exclusive PQ) is unchanged; classical mode is the
   suite-compatible lens over the same protocol logic, and the
   platform's emergency-rollback mode is exactly this mode.
4. **Conformance clients** - registered through the DCR endpoint (for
   Dynamic OP runs) or admin API: a `client_secret_basic` client, a
   `client_secret_post` client, a `private_key_jwt` client, a
   `tls_client_auth` client, and a public PKCE client, each with the
   suite callback `https://localhost.emobix.co.uk:8443/test/a/{alias}/callback`
   in `redirect_uris` and the CIBA ping callback in
   `backchannel_uri`/ping fields where relevant.
5. **Browser automation** - the suite's browser-interaction tests
   (sign-in + consent at the hosted UI) are driven via the suite's
   `Visit` flow with a scripted test user; the Flutter auth-ui E2E
   driver may be reused. No captcha or bot-protection challenge is
   present for the cert env (bot protection stays on for real tenants).
6. **Result capture** - each run is exported from the suite
   (`log-detail.html` / JSON) into `.tmp/conformance/results/`, and the
   top-level `make conformance` target boots the suite, seeds, and
   prints a per-profile pass/fail matrix.

### 9a.3 Profile-by-profile implementation state

| Capability | Status | Notes |
|---|---|---|
| Discovery (`/.well-known/openid-configuration`) | implemented | §4 surface; required-when-supported honesty fields in §9a.4 |
| Basic OP (code + PKCE S256, ID token with `nonce`/`auth_time`/`at_hash`/`c_hash`/`s_hash`) | implemented | `c_hash` binds the ID token to the exchanged code; `s_hash` binds it to `state` when present |
| Config OP (discovery completeness) | implemented | fields in §9a.4 |
| Dynamic OP (DCR + management + WebFinger) | implemented | WebFinger at `/.well-known/webfinger` (`webfinger.rs`) |
| RP-Initiated Logout | implemented | `state` echoed on the registered `post_logout_redirect_uri` redirect |
| Back-Channel Logout | implemented | logout tokens carry `events`/`sid`; discovery advertises support |
| `prompt=none/login/consent` + `max_age` re-auth | implemented | silent issuance or `error=login_required` back to the redirect_uri; `max_age` gates session freshness |
| FAPI 2 Security Profile (PAR + DPoP + JARM + `iss` + rotation) | implemented | platform default |
| FAPI 2 Message Signing | implemented | HTTP message signatures + signed introspection (RFC 9701) |
| FAPI 1 Advanced (PAR + JAR + mTLS + JARM + `iss`) | implemented | `s_hash` on `state`; `resource` parameter rejected under the `fapi_1_advanced` profile |
| FAPI-CIBA poll mode | implemented | `bc-authorize` + CIBA grant + discovery block |
| FAPI-CIBA ping mode | implemented | notification POST to the registered `backchannel_client_notification_endpoint`, `client_notification_token` as bearer |
| OID4VCI issuer | implemented | standard endpoint shapes in §9a.7 (credential-issuer metadata, `/credential`, offer URI, deferred, notification) over the existing SD-JWT/KB-JWT/status-list core |
| OID4VP verifier | implemented | standard `/.well-known/openid-credential-verifier` metadata + `presentation_definition` handling at the wallet endpoint |
| eKYC-IDA (claims / verified_claims) | implemented | `claims` request parameter (§5.5, narrowing selection) + `verified_claims` in ID token/userinfo from the credential store's assurance data |
| JAR `request_uri` | implemented | the AS fetches the request-object JWT from the client-supplied URI (https scheme only), same verification path as the inline `request` parameter |
| CIBA signed request objects | implemented | `request` JWT (or `request_uri` fetch) at `bc-authorize`, verified against the client's registered keys (CIBA §7.1) |

### 9a.4 Discovery honesty fields

The discovery document carries the following required-when-supported /
recommended fields (advertised only when actually supported):

- `token_endpoint_auth_signing_alg_values_supported` (required when
  `private_key_jwt` is advertised)
- `claims_parameter_supported: true` (completed with the claims parameter)
- `claims_supported` (static list of the claims the ID token / userinfo
  can carry)
- `backchannel_logout_supported: true` + `backchannel_logout_session_supported`
- `revocation_endpoint_auth_methods_supported`,
  `introspection_endpoint_auth_methods_supported`
- CIBA: `backchannel_authentication_endpoint`,
  `backchannel_token_delivery_modes_supported: ["poll","ping"]`,
  `backchannel_authentication_request_signing_alg_values_supported`,
  plus `urn:openid:params:grant-type:ciba` in `grant_types_supported`
- OAuth 2.1 posture: `code_challenge_methods_supported` already `S256`
  only; PKCE stays mandatory for public clients.

### 9a.5 Certification runbook (per profile)

The rig lives in the platform group: `scripts/conformance/` (compose
file, seed script, runbook) driven by `make conformance-up` /
`conformance-down` / `conformance-purge` / `conformance-seed` from
`sentin8/` (the group Makefile). The suite's Java runtime must trust the
platform CA: import `.run/secrets/acme-ca/root-ca.crt` into the
server container's truststore (runbook §1).

1. Start the platform in classical mode (`SENTIN8_TLS_PQ_MODE=classical`
   in the root `.env` for rig runs) and `make conformance-up`.
2. `make conformance-seed` - provisions the certification tenant
   (org `conformance-local`, env `cert`, test user, suite clients via
   DCR with the suite callback) through the platform API only
   (no direct SQL; inputs land in `.tmp/conformance/cert-user.env`).
3. Create the test plan in the suite UI: "OpenID Connect Core: Basic OP"
   (then Config, Dynamic; Logout: RP-Initiated + Back-Channel; FAPI 2:
   Security Profile then Message Signing; FAPI 1: Advanced; CIBA: Poll
   then Ping; OID4VCI issuer; OID4VP verifier; IDA) with alias
   `sentin8-local` and the cert env's discovery URL.
4. Run each test; the suite's browser automation completes sign-in via
   the HTML login page (§9a.8) with the seeded test user.
5. All tests must be PASSED / WARNING / REVIEW (no FAILED, no
   INTERRUPTED) before the profile is considered green locally.
6. Export logs to `.tmp/conformance/results/`, then `make conformance-down`.

### 9a.6 Sequence - a suite browser interaction (authorize round-trip)

```mermaid
sequenceDiagram
    autonumber
    participant SU as suite client
    participant NG as suite nginx (8443)
    participant AU as suite browser automation
    participant OP as sentin8:auth (cert env)
    SU->>OP: PAR /oauth/par (client auth) → request_uri
    SU->>NG: redirect browser → /oauth/authorize?client_id&request_uri
    AU->>OP: GET /oauth/authorize → login-page redirect (§9a.8)
    AU->>OP: POST /oauth/login (seeded user) → session cookie
    OP-->>NG: 302 to suite callback?code=…&state=…&iss=…
    SU->>OP: POST /oauth/token (code + PKCE verifier)
    OP-->>SU: access / refresh / id_token (RS256 in classical mode)
    SU->>SU: verify ID token against /oauth/grants? no - JWKS URI
```

### 9a.7 Wire-level certification surfaces

**JAR `request_uri` (RFC 9101 §5.2.1).** When the authorize request
carries `request_uri` (and it is NOT a PAR urn), the AS fetches the
request-object JWT from the URI — `https` scheme only, response body
size-capped, 10s timeout — then runs the same verification path as the
inline `request` parameter: unverified decode, `validate_jar_claims`,
`exp` freshness (±10 min), signature against the client's registered
`jwks`/`jwks_uri`. The fetched JWT overlays inline params identically.
This is what the FAPI 1 Advanced suite exercises (it pushes request
objects by URI).

**CIBA signed request objects (CIBA §7.1).** `bc-authorize` accepts a
`request` JWT (or `request_uri` fetch, same mechanics as above) signed
by the client's registered keys. Its claims carry the CIBA parameters
(`scope`, `client_notification_token`, `request_mode`, `login_hint`,
`binding_message`, `requested_expiry`, `exp`). On success the JWT's
parameters REPLACE the form parameters (signed wins); verification is
the same verifier as JAR's. Unsigned (form) parameters remain supported
for poll-mode and platform-internal callers.

**OID4VCI issuer (SD-JWT VC profile).** Standard endpoint shapes over
the existing SD-JWT/KB-JWT/Status-List core, all issuer-hosted on auth:

- `/.well-known/openid-credential-issuer` — metadata:
  `credential_issuer`, `credential_configurations_supported` (one entry
  per credential type auth mints), `credential_endpoint`,
  `deferred_credential_endpoint`, `notification_endpoint`,
  `credential_issuer_session` metadata as needed by the flow variant.
- `POST /oauth/credential` — single-credential issuance request:
  `credential_configuration_id`, optional `proof` (a `jwt` proof holding
  the wallet's attestation key: `iss=client_id`, `aud=issuer`, `exp`,
  nonce-bound); authorization rides the existing grant families
  (authorization_code with the credential scope via the standard
  authorize flow, or pre-authorized_code for QR-initiated flows).
  Response: the signed SD-JWT credential (format `sd-jwt`), or
  `transaction_id` + HTTP 202 for deferred issuance.
- `POST /oauth/deferred_credential` — poll a `transaction_id` →
  credential once minted.
- `POST /oauth/notifications` — the wallet's events (credential
  received/failed) are recorded against the credential record.
- The internal offer record (credentials table) is the same store; the
  standard `/oauth/credentials` endpoints remain as the platform-native
  alias surface.

```mermaid
sequenceDiagram
    autonumber
    participant W as wallet
    participant OP as sentin8:auth issuer
    W->>OP: GET /.well-known/openid-credential-issuer
    OP-->>W: credential_configurations_supported
    W->>OP: authorize (scope incl. credential) → code
    W->>OP: POST /oauth/token (code) → access_token
    W->>OP: POST /oauth/credential (proof jwt, cnf key)
    alt immediate
        OP-->>W: 200 sd-jwt credential
    else deferred
        OP-->>W: 202 {transaction_id}
        W->>OP: POST /oauth/deferred_credential (transaction_id)
        OP-->>W: 200 sd-jwt credential
    end
    W->>OP: POST /oauth/notifications (credential received)
```

**OID4VP verifier.** `/.well-known/openid-credential-verifier` publishes
the verifier metadata (redirect_uris, presentation definitions
supported, client_id schemes). The existing wallet sign-in endpoint
accepts a standard `presentation_definition` (or by reference:
`presentation_definition_uri`) alongside the existing SD-JWT VP
handling; the request object binding (`client_id`,
`client_id_uri_scheme`) follows OID4VP §5.

**eKYC-IDA `verified_claims` (OIDC eKYC-IDA §5).** The `claims` request
parameter (`id_token`/`userinfo` sub-objects, `essential` flags) is
accepted at authorize and applied at the ID-token/userinfo mint as a
claim SELECTION (never widening — a claim the consented scope did not
grant stays absent). When the request selects `verified_claims` (or the
user holds an active wallet credential of the matching type), the
ID token/userinfo carries `verified_claims` built from the credentials
store: `verification` (trust framework, evidence, time) + `claims`
(the verified subset), per the eKYC-IDA claim shape. `claims_supported`
lists `verified_claims`; discovery advertises
`claims_parameter_supported: true`.

### 9a.8 Server-rendered HTML login page (automated-client surface)

The hosted UI at `/sign-in` is the full **Flutter auth-ui** (canvas
SPA) — the product surface for humans. Canvas apps expose no DOM input
elements, so DOM-driven automation (the OIDF conformance suite's
browser runner, Selenium-class RPs, CI clients) cannot complete the
interactive login. Auth therefore serves a **server-rendered HTML
login page** as a first-class surface for automated clients — the
human flow stays on the Flutter UI.

**Endpoints (both public, form-encoded; DESIGN §4 table updated):**

- `GET /oauth/login` — the HTML page. The authorize handler's sign-in
  redirect targets this path for OAuth flows (the `/sign-in` SPA route
  remains for human navigation and app-initiated sign-in). The page
  carries the OAuth context in a signed hidden field (HMAC over the
  authorize params, TTL 10 min — the form cannot be used to steer a
  different authorization request) plus visible fields with stable
  element ids the suite's browser commands drive:
  `input#username`, `input#password`, `input#submit` (`type=submit`).
- `POST /oauth/login` — the form handler: verifies the context HMAC,
  authenticates via the same password path as `POST /v1/sign-in`
  (shared credential + lockout + rate-limit logic), creates the
  session cookie, then re-dispatches the preserved authorize request
  through the authorize-continue code path. Wrong credentials
  re-render the page with `#error_message` visible (the suite's
  negative tests read it); a valid login issues the code and 302s to
  the client's `redirect_uri`.

**Why a form POST, not fetch/XHR:** the page is deliberately
JavaScript-free — a canvas-free, JS-free form works under every
headless driver. The CSRF posture matches `POST /v1/sign-in` (the
login form IS the cross-site concern; the OAuth context HMAC binds the
form to one authorize request, and the session cookie is set with the
platform's same-site/Csrf cookie attributes).

**First-party consent bypass keeps the flow one-page:** the platform's
existing `consent_required=false` client flag (§4.16) makes the login
page the ONLY interactive step — after authentication the code is
issued directly. Conformance clients register with the flag set, so
the suite's browser automation completes in one form submission.

```mermaid
sequenceDiagram
    autonumber
    participant SU as suite client (OIDF)
    participant BR as suite browser (DOM driver)
    participant OP as sentin8:auth
    SU->>OP: GET /oauth/authorize (code flow)
    OP-->>BR: 302 /oauth/login (signed context)
    BR->>OP: GET /oauth/login
    OP-->>BR: 200 HTML form (#username, #password, #submit)
    BR->>OP: POST /oauth/login (ctx, credentials)
    alt invalid credentials
        OP-->>BR: 200 re-render (#error_message)
    else valid
        OP->>OP: session create (shared /v1/sign-in path)
        OP->>OP: authorize-continue (code mint, PKCE binding)
        OP-->>SU: 302 redirect_uri?code=…&state=…&iss=…
    end
    SU->>OP: POST /oauth/token (code + verifier)
```

### 9a.9 Per-tenant JWT signing algorithm (security-profile plane)

`SENTIN8_TLS_PQ_MODE` is a **process-level** switch that selects the JWT
signing algorithm family (`MLDSA65` vs `RS256`) for the whole service.
That is the right shape for the **TLS transport** half it also controls
(the ClientHello's key exchange completes before the SNI hostname - and
therefore the tenant - is known, so per-tenant TLS groups are
physically impossible on one listening socket). But the **JWT signing**
half is decided per-request, after tenant resolution - and a fleet-wide
classical flip just to serve one suite-compatible tenant (the
certification rig) demotes every other tenant's token security.

The target state moves JWT signing onto the security-profile plane:

- `security_profiles` gains a `signing_alg` column
  (`MLDSA65` | `RS256`, default `MLDSA65`), resolved
  platform → org → env exactly like the profile flags
  (`resolve_security_profile`).
- `SigningKeys` loads **both** algorithm key sets at boot (it already
  verifies both for rotation overlap; both are persisted). The active
  key per family is selected at **sign time**: `sign_value_alg(claims,
  alg)` picks the ML-DSA or RSA active key from the requested family.
  Absent key material for a family fails loudly (it is generated on
  boot, so absence means the store was tampered with).
- Every mint site that resolves a tenant context (ID token, access
  token, refresh token, JARM, logout token, SD-JWT credential) signs
  with the caller's env-resolved `signing_alg`. `SENTIN8_TLS_PQ_MODE`
  remains the **process default** for contexts with no profile row
  (the platform-plane row seeds `MLDSA65`, so the platform keeps PQ
  signatures everywhere by default).
- Discovery/JWKS honesty: the JWKS endpoint publishes **all** persisted
  keys (both families - verifiers need the overlap set), and discovery
  advertises the **caller's env-resolved** `id_token_signing_alg_values_supported`
  (the resolved family), so a suite tenant advertises `RS256` while the
  platform plane advertises `MLDSA65`.
- **Acme cert families are out of scope here**: leaf certs are minted
  per-hostname by Acme; the family follows the TLS transport mode
  (process-level) - the per-tenant setting governs JWTs only.

```mermaid
sequenceDiagram
    autonumber
    participant C as client (cert env)
    participant OP as sentin8:auth
    participant P as security_profiles (env row)
    OP->>P: resolve_security_profile(env)
    P-->>OP: signing_alg = RS256 (cert env) / MLDSA65 (default)
    OP->>OP: sign_value_alg(claims, alg) - active key of that family
    OP-->>C: id_token (alg per the env's row; JWKS serves both families)
    C->>C: verify via JWKS (kid-routed, family-agnostic)
```

**Why not per-tenant keys?** One key set per family (platform-global)
keeps rotation (`jwks rotation timer`) and revocation semantics
unchanged; per-tenant keys multiply rotation surface ×N with no
security gain at the JWT layer (the tenant boundary is the claim set,
not the key). Rejected as future-work if a tenant ever demands BYOK.

## 10. Open Questions

- Webhook delivery gains a DLQ replay surface mirroring post's `replay_dlq`
  shape (`POST /v1/admin/webhooks/attempts/{id}/replay`).

- SAML flows beyond metadata/ACS are a declared non-goal for the platform IdP
  (enterprise SSO is served by OIDC federation).
- Status List keeps the per-credential bit (standard model: verifiers fetch
  the credential status); fleet-wide aggregation is out of scope.
- Webhook delivery gains a DLQ replay surface mirroring post's `replay_dlq`
  shape (`POST /v1/admin/webhooks/attempts/{id}/replay`).
- Push-based identity invalidation is already implemented as events
  (`sentin8:sys:identity:updated`); role resolvers subscribe instead of
  relying only on TTL polling.

> JWKS rotation is internal: a daily in-process timer (03:00, 30-day
> staleness gate) calls the in-process rotate path directly - auth links
> no scheduler client and makes no cross-service calls (SDD §2.5, root
> service rule).

---

**Design attribution:** sentin8:auth and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
