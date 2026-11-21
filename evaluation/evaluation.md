# Evaluation guide

How the reported numbers are produced and where the raw evidence lives. Final results correspond to tag `cs5903-final-2026`.

## Evidence map

| Checklist item | Location |
| --- | --- |
| Submitted-system scripts | `test/test_01_scoped_memberships.py` to `test/test_06_timings.py`, shared helpers in `test/conftest.py`, configuration in `test/pytest.ini` and `test/requirements.txt` |
| Baseline scripts | none yet (see "Baseline" below) |
| Workload and data identifiers | `docs/workload.md` |
| Raw result files | `test/results/results.json` (outcomes plus every timing sample), `test/results/results.md` (summary) |
| Environment and seed information | `docs/environment.md` |
| Authorization matrix | `docs/authorization_matrix.csv` |
| How to regenerate the metrics | this file and the root `README.md` |

## Regenerate the reported metrics

1. Start the stack from a clean state: `docker compose down -v && docker compose up -d --build`. Wait until the gateway answers on `http://localhost:3000` (an unauthenticated `GET /api/me` returns 401).
2. Install test dependencies: `pip install -r test/requirements.txt`.
3. Run the suite: `cd test && pytest`.
4. Read the results from `test/results/results.json` and `test/results/results.md`.

The tests stop with a diagnosis if the stack is unhealthy. Defaults assume the ports in `docker-compose.yml`; override with `GATEWAY_URL`, `KEYCLOAK_URL`, `FGA_API_URL`, `DATABASE_URL`, `KC_ADMIN_USER`, `KC_ADMIN_PASSWORD`.
Each run overwrites `test/results/`; copy the files elsewhere if you want to keep earlier runs. Every run records its `run_id` inside `results.json`.

## Which file each reported number comes from

| Reported number | Source |
| --- | --- |
| Tests passed, failed, known gaps; acceptance pass rate | `results.json` `summary.counts`, and the list in `tests` |
| Revocation propagation table (n=8 per row; p50, p95, max) | `results.json` `summary.timings`, group `propagation`, from `test_06_timings.py` |
| Request latency table (n=100 per row; p50, p95, max) | `results.json` `summary.timings`, group `latency`, from `test_06_timings.py` |
| Known-gap list | `results.md`, section "Known gaps confirmed" |
| Authorization matrix | `docs/authorization_matrix.csv`, with outcomes from `test_04_authorization_boundaries.py` in `results.json` |

Percentiles use the nearest-rank method implemented in `_pct` in `test/conftest.py`.

## The 40-scenario authorization matrix

`docs/authorization_matrix.csv` lists 40 scenarios (milestone M4): actor, actor state, tenant state, resource, action, expected decision and the rule that produces it.

- **Expected decisions are derived from `openfga/model.fga` and the gateway routes, not from a test run.** Notably, the platform admin (`super_admin`) is expected to be denied course content, because `super_admin` is not part of `org_member`.
- **Coverage is stated per row**, in the `coverage` column:
  - `direct`: a test in `test_04_authorization_boundaries.py` asserts this exact decision.
  - `indirect`: a test asserts the cause (for example suspension denies course reads) but not this specific action.
  - `none`: no test exercises this scenario.
- `result_run_8090af` records what run 8090af showed: `pass` for `direct` rows (all `test_04` tests passed in that run), `not asserted` for `indirect` rows and `no test` for `none` rows.
- Current counts: 19 direct, 12 indirect, 9 none. So only 19 of the 40 scenarios have direct test evidence today. The report should not claim 40 verified scenarios until the indirect and untested rows are covered by tests or the claim is worded accordingly.

## Baseline

No baseline comparison has been run, so the report presents absolute numbers only. A Keycloak-roles-only baseline would measure the same course-read operations using only realm roles from the token, without OpenFGA, and would fill a "Baseline" column for the n=100 latency table. Until it exists, do not report baseline figures.

## State of the results currently in `test/results/`

- Run `8090af` (2026-11-15): 62 passed, 1 failed, 11 known gaps confirmed, out of 74. Acceptance pass rate 62/63 = 98.4%.
- The one failure is `test_03_pkce_oidc.py::test_password_grant_is_disabled_on_the_public_client`. It is marked as a strict known gap (password grant enabled on the public client), but `keycloak/realm/multitenant-realm.json` now sets `directAccessGrantsEnabled` to `false`, so the test passes unexpectedly and strict xfail turns that into a failure. Resolve it (remove the marker, since the gap is fixed) before the final run.
- The final run has not been done. Replace the numbers above with the final run's values and update `docs/environment.md`.
