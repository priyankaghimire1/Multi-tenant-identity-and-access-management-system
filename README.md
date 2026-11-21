# Multi-tenant Identity and Access Management System

A multi-tenant authentication and fine-grained authorization gateway. **Keycloak** (unmodified) handles OIDC login with PKCE and token signing. A custom **Node.js gateway** verifies tokens, manages tenants and memberships in **PostgreSQL**, and answers every permission question through **OpenFGA** (relationship-based access control, ReBAC).

> **Status:** working prototype for the CS5903 final submission. Core flows (login, tenant provisioning, memberships, role-based course access, suspension, session revocation, audit logging, AI-agent delegation) are implemented and covered by an automated suite. Known limitations are listed under [Known limitations](#known-limitations).

- Final report: `docs/<final-report-file>` *(add link)*
- Architecture decisions: [`docs/01-architecture.md`](docs/01-architecture.md) and the ADR log in `docs/` *(add links)*
- Requirements matrix: [`docs/requirements.md`](docs/requirements.md)
- Stable version: tag `cs5903-final-2026` (commit `<SHA>`) *(fill in after tagging)*

---

## Architecture

```
 Browser ──(OIDC code + PKCE)──▶ Keycloak (realm "dat")  ◀──(federated login)── acme-idp (realm "acme-idp")
    │                                  │ signs JWT (RS256)
    │ Bearer JWT                       ▼
    └──────────────▶ Gateway (Node.js / Express, :3000)
                         │  verify JWT via Keycloak JWKS, check revoked sessions
                         │  authorize via OpenFGA Check
                         ├──▶ PostgreSQL  (tenants, memberships, courses, audit, revocations, outbox, delegations)
                         └──▶ OpenFGA     (relationship tuples; kept in sync from Postgres by an outbox worker)
```

Key decisions:

- **Decoupled identity.** Keycloak is only an identity and token engine. All tenant data, memberships, consent and audit records live in PostgreSQL. No custom Keycloak code is needed.
- **No Redis.** The Keycloak signing keys (JWKS) are cached in memory, and session revocation checks are indexed PostgreSQL queries.
- **Transactional outbox.** Membership and tenant changes are written to Postgres together with an `outbox_events` row. A background worker (polling every second) mirrors each event into OpenFGA, so the two stores stay consistent. Permission changes therefore take roughly one second to take effect.
- **ReBAC model.** The OpenFGA model (`openfga/model.fga`) defines `platform`, `organization` (admin / instructor / learner, `suspended`, `tenant_active`) and `course`. A course permission is derived from the user's live role in the course's organization.
- **Federated login.** The `dat` realm has an identity provider (`acme-okta`) that points to a second Keycloak realm (`acme-idp`) standing in for a customer's own IdP.
- **AI-agent delegation.** A user can delegate scoped, time-limited access to an agent (`POST /api/agents/delegate`).

## Tech stack

| Component | Technology |
| --- | --- |
| Identity provider | Keycloak 26.0 (`quay.io/keycloak/keycloak:26.0`) |
| Gateway | Node.js 20, Express 4, `jose`, `jsonwebtoken`, `pg`, `@openfga/sdk` |
| Database | PostgreSQL 16 (plain SQL schema in `infra/postgres/init.sql`) |
| Authorization | OpenFGA (in-memory datastore, `openfga/openfga:latest` *(pin a version before submitting)*) |
| Tests | Python 3.11+, pytest, requests, psycopg2, BeautifulSoup |
| Orchestration | Docker Compose |

## Repository layout

```
docker-compose.yml        Full stack: postgres, keycloak, acme-idp, openfga, openfga-init, seed, gateway
.env.example              Environment variables (placeholders only)
gateway/                  Node.js gateway (src/, public/ demo pages, scripts/seed.js, Dockerfile)
infra/postgres/init.sql   Database schema
keycloak/realm/           Realm "dat" export (web-app client, users, federation)
keycloak/acme-idp/        Realm "acme-idp" export (simulated customer IdP)
openfga/                  Authorization model (model.fga human-readable, model.json used by the init job)
test/                     Automated test suite, results in test/results/
docs/                     ADRs and requirements matrix
```

## Prerequisites

- Docker Engine 24+ with the Compose plugin (v2)
- Free ports: `3000` (gateway), `3001` (OpenFGA playground), `5432` (Postgres), `8080` (OpenFGA API), `8081` (Keycloak), `8083` (acme-idp)
- To run the tests: Python 3.11 or newer
- Node.js is **not** needed locally; the gateway runs inside Docker

## Quick start

```bash
git clone https://github.com/priyankaghimire1/Multi-tenant-identity-and-access-management-system.git
cd Multi-tenant-identity-and-access-management-system

docker compose up -d --build
docker compose ps          # wait until keycloak and acme-idp are healthy and gateway is running
```

First start takes a few minutes (Keycloak import). The startup order is handled by Compose: Postgres, then acme-idp and Keycloak, then OpenFGA, then `openfga-init` (creates the store and loads the model), then `seed` (creates tenants, users, tuples), then the gateway.

Check that it works:

```bash
curl -i http://localhost:3000/api/me
# Expected: HTTP/1.1 401 (no token supplied) - the gateway is up and enforcing authentication
```

Then open <http://localhost:3000/login.html> and sign in with a demo user.

### Demo users (local demo only)

All demo passwords are `password`. These are synthetic accounts defined in the realm export. **Never reuse this setup outside a local demo.**

| User | Tenant | Role |
| --- | --- | --- |
| `master` | platform | Super admin (can provision and suspend tenants) |
| `alice` | Acme Corp (`organization:acme`) | Admin |
| `carol` | Acme Corp | Instructor |
| `bob` | Acme Corp | Learner |
| `dave` | Globex Institute (`organization:globex`) | Admin (an outsider to Acme) |

Keycloak admin console: <http://localhost:8081> (`admin` / `adminpassword`). OpenFGA playground: <http://localhost:3001>.

### Demo path (about 5 minutes)

1. Sign in as `bob` (learner) at `http://localhost:3000/login.html`. The dashboard shows Acme's courses. Bob can view but not edit.
2. Sign in as `dave` (Globex admin). Opening an Acme course is denied, which shows tenant isolation.
3. Sign in as `alice` (Acme admin), then suspend Bob's membership. Within about a second Bob loses access, and the change appears in the audit log (`GET /api/orgs/organization:acme/audit-logs`).
4. Sign in as `master` and suspend the whole Acme tenant. Every Acme member is denied. Unsuspend to restore access.

## Configuration

The gateway reads these environment variables. Defaults are set in `docker-compose.yml` for local use.

| Variable | Purpose | Local default |
| --- | --- | --- |
| `PORT` | Gateway port | `3000` |
| `DATABASE_URL` | Postgres connection string | `postgres://dat:dat@postgres:5432/dat` |
| `KEYCLOAK_URL` | Keycloak base URL (JWKS source) | `http://keycloak:8081` |
| `KEYCLOAK_REALM` | Realm name | `dat` |
| `FGA_API_URL` | OpenFGA API URL | `http://openfga:8080` |
| `FGA_STORE_ID`, `FGA_MODEL_ID` | Set automatically at startup from the `openfga-init` job | generated |
| `KEYCLOAK_ADMIN`, `KEYCLOAK_ADMIN_PASSWORD` | Used by the seed script only | `admin` / `adminpassword` |
| `AGENT_SECRET` | Signing secret for agent delegation tokens | **must be set in any real deployment** |

Copy `.env.example` to `.env` for local overrides. Never commit `.env`.

## Running the tests

The tests drive the **running stack** through the real gateway API and real PKCE logins. Start the stack first (see Quick start).

```bash
cd test
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest                                                # full suite, about 74 tests
```

Run one module, for example the PKCE and OIDC tests:

```bash
pytest test_03_pkce_oidc.py
```

| File | Covers |
| --- | --- |
| `test_01_scoped_memberships.py` | Roles scoped to a tenant |
| `test_02_membership_integrity.py` | Membership consistency and concurrency |
| `test_03_pkce_oidc.py` | Authorization-code + PKCE flow and redirect handling |
| `test_04_authorization_boundaries.py` | Role/permission matrix, cross-tenant denial, suspension, Postgres/OpenFGA agreement |
| `test_05_revocation_audit_agents.py` | Session revocation, audit logging, agent delegation |
| `test_06_timings.py` | Propagation delay and request latency measurements |

Environment variables for the tests (all optional): `GATEWAY_URL`, `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `FGA_API_URL`, `DATABASE_URL`, `KC_ADMIN_USER`, `KC_ADMIN_PASSWORD`, `TEST_PASSWORD`, `SYNC_TIMEOUT_S`, `SKIP_PREFLIGHT`.

**Pre-flight check.** Before running, the suite checks that the stack is healthy and exits with a diagnosis if it is not.

**Expected outcome.** Tests marked `xfail` document known gaps and are expected to "fail". Last recorded run (`test/results/results.md`): **62 passed, 1 failed, 11 known gaps confirmed (xfail), 0 skipped, out of 74** *(refresh these numbers after your final run)*. Results are written to `test/results/results.md` and `results.json`.

## Evaluation results

`test_06_timings.py` records how fast permission changes propagate and how fast requests are served (p50 / p95 / max). Last recorded run, in milliseconds:

| Measurement | p50 | p95 |
| --- | --- | --- |
| Member suspended, access denied | 912 | 1000 |
| Tenant suspended, all members denied | 934 | 1061 |
| Allowed course read | 8.6 | 11.9 |
| Denied course read (outsider) | 7.9 | 10.7 |

Propagation is about 1 second because the outbox worker polls every second. To regenerate: run `pytest` in `test/`, then read `test/results/results.md`.

## Operations

| Task | Command |
| --- | --- |
| Start | `docker compose up -d --build` |
| Stop (keep data) | `docker compose stop` |
| Full restart | `docker compose down && docker compose up -d` |
| Reset everything (wipe Postgres) | `docker compose down -v && docker compose up -d --build` |
| Logs | `docker compose logs -f gateway` (also `keycloak`, `openfga`, `postgres`, `seed`) |

**Troubleshooting**

- **Every request returns 403/500 after restarting only OpenFGA or the whole machine.** OpenFGA uses an in-memory datastore, so a restart wipes its store while the gateway keeps the old store ID. Use `docker compose down && docker compose up -d` (not `restart`) so `openfga-init` and `seed` run again. Use `down -v` for a clean slate.
- **Tests exit with `PRE-FLIGHT FAILED`.** Read the listed reasons; they name the failing component. Set `SKIP_PREFLIGHT=1` only if you know why the check is wrong.
- **Keycloak takes a long time to become healthy.** The first start imports two realms; wait for `docker compose ps` to show `healthy`.
- **Port already in use.** Stop whatever is using the port or change the host side of the `ports:` mapping in `docker-compose.yml`.

External services needed: none beyond the containers above. No paid APIs or accounts are used.

## Known limitations

These are documented and tested as strict `xfail` cases, so they will start failing the suite the moment someone fixes them. See the open GitHub issues for each.

- Concurrent conflicting membership adds can create two roles for one user.
- Malformed `user_sub` values are accepted by the memberships API.
- The outbox can mark an event processed even when OpenFGA rejected it.
- The realm allows any path on the app origin as an OAuth callback (wildcard redirect URI).
- The gateway does not check `aud`/`azp`, so a token issued to another client in the realm is accepted.
- The organization-level cutoff is not applied to course reads and `/overview`.
- Course reads are not audited.
- Agent delegation: the default `AGENT_SECRET` fallback allows forged tokens, and the caller's org membership, duration and scopes are not validated.
- OpenFGA data is in memory only; there is no reconcile job to rebuild tuples from Postgres.

## Security and provenance

- No real credentials, API keys or user data are committed. Everything in the realm exports and seed script is synthetic, for local demos only.
- `.env` is git-ignored; `.env.example` contains placeholders only.
- No external APIs or models are required, so everything here is reproducible without authorized access.