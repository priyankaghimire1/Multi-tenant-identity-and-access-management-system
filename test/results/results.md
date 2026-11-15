# Test results (run 8090af, 2026-11-15T09:08:06+0530)

**62 passed, 1 failed, 11 known gaps confirmed (xfail), 0 gaps unexpectedly fixed (xpass), 0 skipped** out of 74.

Pass rate over the acceptance tests (excluding known-gap tests): 62/63 = 98.4%

## Timings (ms)

| Group | Measurement | n | p50 | p95 | max |
| --- | --- | --- | --- | --- | --- |
| propagation | member suspended -> access denied | 8 | 911.9 | 1000.4 | 1000.4 |
| propagation | member reinstated -> access restored | 8 | 911.7 | 920.5 | 920.5 |
| propagation | tenant suspended -> all members denied | 8 | 933.6 | 1061.0 | 1061.0 |
| propagation | learner -> instructor: edit granted | 8 | 906.8 | 965.0 | 965.0 |
| propagation | instructor -> learner: edit revoked | 8 | 905.6 | 985.3 | 985.3 |
| latency | allowed course read | 100 | 8.6 | 11.9 | 82.6 |
| latency | denied course read (outsider) | 100 | 7.9 | 10.7 | 59.9 |
| latency | identity (/api/me) | 100 | 6.6 | 9.5 | 65.5 |
| latency | access trace (9 FGA checks) | 100 | 31.7 | 53.3 | 95.3 |

## Known gaps confirmed

- `test_concurrent_conflicting_adds_never_create_two_roles`: KNOWN GAP: POST memberships is SELECT-then-INSERT with no lock and UNIQUE(user_sub, org_id, role) omits the role-free key, so concurrent adds create two roles (12/12 trials)
- `test_malformed_user_sub_is_rejected_at_the_api`: KNOWN GAP: POST memberships accepts any user_sub with no existence/format check; the outbox then silently drops the rejected tuple
- `test_outbox_never_drops_an_event_it_failed_to_apply`: KNOWN GAP: outbox marks events processed even when OpenFGA rejects the tuple (any HTTP 400 is treated as 'already exists')
- `test_same_origin_unregistered_path_is_rejected`: KNOWN GAP: realm registers the wildcard http://localhost:3000/*, so any path on the app origin is an accepted callback (requirement: exact match)
- `test_gateway_rejects_a_token_issued_to_a_different_client`: KNOWN GAP: gateway verifies the signature only; it never checks aud/azp, so a token minted for ANY client in the realm is accepted
- `test_org_scoped_cutoff_also_applies_to_course_reads`: KNOWN GAP: the org-scoped cutoff is enforced only by requirePermission routes; course reads and /overview ignore it
- `test_course_reads_are_audited`: KNOWN GAP: GET /api/courses/:id never calls recordAudit, so course reads (the most common decision) leave no audit row
- `test_default_agent_secret_does_not_allow_forged_delegations`: KNOWN GAP: AGENT_SECRET falls back to a hard-coded default and the delegator claim is trusted from the token, so anyone who knows the default can act as any user
- `test_delegation_requires_membership_of_the_org`: KNOWN GAP: POST /api/agents/delegate does not check that the caller belongs to the org it delegates
- `test_delegation_duration_is_capped`: KNOWN GAP: delegation duration is unbounded
- `test_delegation_scopes_are_validated`: KNOWN GAP: delegation scopes are not validated against an allow-list
