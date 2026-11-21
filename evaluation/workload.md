# Workload and data identifiers

All data is synthetic. The seed script `gateway/scripts/seed.js` is deterministic: fixed names, fixed course ids, no random values.
The tests create their own tenants through the gateway API, named with a per-run random suffix (`RUN` in `test/conftest.py`), so repeated runs on the same stack do not collide.

## Seed dataset

| Organization | Domain | Members (role) | Courses |
| --- | --- | --- | --- |
| `organization:acme` (Acme Corp) | acme.edu | alice (admin), carol (instructor), bob (learner) | `course:cs101`, `course:cs201` |
| `organization:globex` (Globex Institute) | globex.com | dave (admin) | `course:gx100` |

Platform: `master` holds `super_admin` on `platform:root` and has no organization membership.

Identities (`keycloak/realm/multitenant-realm.json`, realm `dat`, password `password` for all):

| User | Keycloak sub | Realm role |
| --- | --- | --- |
| master | `super-admin-000` | platform-admin |
| alice | `alice-sub-123` | tenant-admin |
| bob | `bob-sub-456` | tenant-user |
| carol | `carol-sub-789` | tenant-user |
| dave | `dave-sub-012` | tenant-user |

Initial OpenFGA tuples written by the seed: `user:<master-sub> super_admin platform:root`; for each organization `platform:root platform <org>` and `user:* tenant_active <org>`;
`user:<sub> <role> <org>` for each member; `<org> org <course>` for each course.
Authorization model: `openfga/model.json` (readable form in `openfga/model.fga`).

The test modules do not rely on the seeded organizations. Each module builds its own tenants, using the same five users in different roles, so scenarios are independent of the seed state.

## Scenarios and the metric each one feeds

| Metric in the report | Test (file::name) | Repetitions | What it does |
| --- | --- | --- | --- |
| Member revocation delay | `test_06_timings.py::test_revocation_propagation_delay` | n=8 per direction | An admin suspends and then reinstates a learner. Measures the time until the course read flips between 403 and 200 (poll interval 20 ms). |
| Tenant revocation delay | `test_06_timings.py::test_tenant_suspension_propagation_delay` | n=8 | The platform admin suspends a tenant. Measures the time until all members are denied. |
| Role-change delay | `test_06_timings.py::test_role_change_propagation_delay` | n=8 per direction | A learner is promoted to instructor and demoted back. Measures the time until the `edit` decision flips. |
| Propagation budget | `test_06_timings.py::test_propagation_stays_within_budget` | all propagation samples | Asserts p95 below 2500 ms and no sample above the sync timeout. |
| Request latency | `test_06_timings.py::test_request_latency[...]` | 4 operations, 10 warm-ups then n=100 each | Allowed course read, denied course read (outsider), `/api/me`, access trace (9 FGA checks). |
| Authorization correctness | `test_04_authorization_boundaries.py` | 11 tests | Role/permission matrix, cross-tenant denial, member and tenant suspension, platform-only APIs, Postgres/OpenFGA agreement. |
| 40-scenario matrix | `authorization_matrix.csv` | 40 rows | See `docs/evaluation.md` for how each row maps to tests. |
| Scoped memberships, integrity, PKCE/OIDC, revocation, audit, agents | `test_01`, `test_02`, `test_03`, `test_05` | 11 + 9 + 15 + 20 tests | Security and correctness tests outside the latency/propagation metrics. |
| Known gaps | tests marked `known_gap` (strict xfail) | 11 | Documented defects. The run fails if one is fixed without updating the marker. |

Latency and propagation samples are stored individually in `test/results/results.json` under `samples`; p50/p95/max/mean are computed from them.
