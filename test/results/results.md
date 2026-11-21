# Test results (run b17ade, 2026-11-21T23:06:51+0530)

**62 passed, 2 failed, 10 known gaps confirmed (xfail), 0 gaps unexpectedly fixed (xpass), 0 skipped** out of 74.

Pass rate over the acceptance tests (excluding known-gap tests): 62/64 = 96.9%

## Timings (ms)

| Group | Measurement | n | p50 | p95 | max |
| --- | --- | --- | --- | --- | --- |
| propagation | member suspended -> access denied | 8 | 951.8 | 1059.0 | 1059.0 |
| propagation | member reinstated -> access restored | 8 | 1081.7 | 1231.2 | 1231.2 |
| propagation | tenant suspended -> all members denied | 8 | 995.5 | 1091.2 | 1091.2 |
| propagation | learner -> instructor: edit granted | 8 | 980.0 | 1249.0 | 1249.0 |
| propagation | instructor -> learner: edit revoked | 8 | 947.3 | 1098.3 | 1098.3 |
| latency | allowed course read | 100 | 8.3 | 17.3 | 92.6 |
| latency | denied course read (outsider) | 100 | 8.1 | 10.2 | 11.8 |
| latency | identity (/api/me) | 100 | 7.3 | 12.4 | 32.7 |
| latency | access trace (9 FGA checks) | 100 | 13.0 | 17.8 | 152.3 |

## Known gaps confirmed

- `test_concurrent_conflicting_adds_never_create_two_roles`: KNOWN GAP: POST memberships is SELECT-then-INSERT with no lock and UNIQUE(user_sub, org_id, role) omits the role-free key, so concurrent adds create two roles (12/12 trials)
- `test_malformed_user_sub_is_rejected_at_the_api`: KNOWN GAP: POST memberships accepts any user_sub with no existence/format check; the outbox then silently drops the rejected tuple
- `test_outbox_never_drops_an_event_it_failed_to_apply`: KNOWN GAP: outbox marks events processed even when OpenFGA rejects the tuple (any HTTP 400 is treated as 'already exists')
- `test_same_origin_unregistered_path_is_rejected`: KNOWN GAP: realm registers the wildcard http://localhost:3000/*, so any path on the app origin is an accepted callback (requirement: exact match)
- `test_gateway_rejects_a_token_issued_to_a_different_client`: KNOWN GAP: gateway verifies the signature only; it never checks aud/azp, so a token minted for ANY client in the realm is accepted
- `test_org_scoped_cutoff_also_applies_to_course_reads`: KNOWN GAP: the org-scoped cutoff is enforced only by requirePermission routes; course reads and /overview ignore it
- `test_course_reads_are_audited`: KNOWN GAP: GET /api/courses/:id never calls recordAudit, so course reads (the most common decision) leave no audit row
- `test_delegation_requires_membership_of_the_org`: KNOWN GAP: POST /api/agents/delegate does not check that the caller belongs to the org it delegates
- `test_delegation_duration_is_capped`: KNOWN GAP: delegation duration is unbounded
- `test_delegation_scopes_are_validated`: KNOWN GAP: delegation scopes are not validated against an allow-list
