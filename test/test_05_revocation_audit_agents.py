"""
Revocation, audit trail and delegated AI-agent access (milestones M3, M6, M8).
"""
import base64
import hashlib
import hmac
import json
import time

import psycopg2
import pytest

from conftest import (DB_URL, RUN, add_member, api, course_status, db_rows, known_gap, login, make_course, make_org, q, wait_for, whitebox)


@pytest.fixture(scope="module")
def world(users):
    a = make_org(users.master, users.alice, "t5a")
    b = make_org(users.master, users.bob, "t5b")
    add_member(a, users.carol, "learner")
    return {"A": a, "B": b, "course_a": make_course(a), "course_b": make_course(b)}


# ================================================================ session revocation
def test_global_session_revocation_kills_only_that_session(users, world):
    s1, s2 = login("carol", fresh=True), login("carol", fresh=True)
    assert s1.claims["sid"] != s2.claims["sid"]
    assert api("GET", "/api/me", s1).status_code == 200
    assert api("POST", "/api/auth/revoke-session", s1).status_code == 200
    assert api("GET", "/api/me", s1).status_code == 401
    assert course_status(s1, world["course_a"]) == 401, "a revoked session must be refused everywhere"
    assert api("GET", "/api/me", s2).status_code == 200, "other sessions of the same user are unaffected"
    assert api("POST", "/api/auth/revoke-session", s1).status_code == 401


@whitebox
def test_org_scoped_cutoff_rejects_tokens_issued_before_it(users):
    """WHITE-BOX: no endpoint sets session_revoked_at, so this writes the column directly to prove the enforcement path works."""
    org = make_org(users.master, users.alice, "t5cut")
    assert api("GET", f"/api/orgs/{q(org.id)}/audit-logs", org.admin).status_code == 200
    conn = psycopg2.connect(DB_URL)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE tenant_memberships SET session_revoked_at = NOW() WHERE user_sub=%s AND org_id=%s", (users.alice.sub, org.id))
        r = api("GET", f"/api/orgs/{q(org.id)}/audit-logs", org.admin)
        assert r.status_code == 401 and "revoked" in r.text.lower()
    finally:
        with conn.cursor() as cur:
            cur.execute("UPDATE tenant_memberships SET session_revoked_at = NULL WHERE user_sub=%s AND org_id=%s", (users.alice.sub, org.id))
        conn.close()
    assert api("GET", f"/api/orgs/{q(org.id)}/audit-logs", org.admin).status_code == 200


@known_gap("the org-scoped cutoff is enforced only by requirePermission routes; course reads and /overview ignore it")
@whitebox
def test_org_scoped_cutoff_also_applies_to_course_reads(users):
    org = make_org(users.master, users.alice, "t5cut2")
    cid = make_course(org)
    conn = psycopg2.connect(DB_URL)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE tenant_memberships SET session_revoked_at = NOW() WHERE user_sub=%s AND org_id=%s", (users.alice.sub, org.id))
        assert course_status(users.alice, cid) == 401
    finally:
        with conn.cursor() as cur:
            cur.execute("UPDATE tenant_memberships SET session_revoked_at = NULL WHERE user_sub=%s AND org_id=%s", (users.alice.sub, org.id))
        conn.close()


# ================================================================ audit trail
def audit(org, **params):
    r = api("GET", f"/api/orgs/{q(org.id)}/audit-logs", org.admin, params={"limit": 1000, **params})
    assert r.status_code == 200, r.text
    return r.json()


def test_denied_request_is_audited_against_the_real_org_and_forged_header_is_only_a_claim(users, world):
    a = world["A"]
    marker = f"forged-{RUN}"
    assert api("GET", f"/api/orgs/{q(a.id)}/audit-logs", users.dave, headers={"X-Tenant-ID": marker}).status_code == 403
    rows = [r for r in audit(a, decision="DENY") if r["user_sub"] == users.dave.sub and r["context"].get("claimed_tenant") == marker]
    assert rows, "the denied attempt must be in the real org's audit log"
    assert rows[0]["org_id"] == a.id and rows[0]["decision"] == "DENY" and rows[0]["resource"] == a.id


def test_allowed_admin_action_is_audited(users, world):
    a = world["A"]
    assert api("GET", f"/api/orgs/{q(a.id)}/audit-logs", a.admin).status_code == 200
    rows = [r for r in audit(a, decision="ALLOW") if r["user_sub"] == users.alice.sub and r["resource"] == a.id]
    assert rows and rows[0]["org_id"] == a.id


def test_decision_filter_and_csv_export_agree_with_json(users, world):
    a = world["A"]
    deny = audit(a, decision="DENY")
    assert deny and all(r["decision"] == "DENY" for r in deny)
    r = api("GET", f"/api/orgs/{q(a.id)}/audit-logs", a.admin, params={"format": "csv", "decision": "DENY", "limit": 1000})
    assert r.status_code == 200 and r.headers["Content-Type"].startswith("text/csv")
    lines = r.text.strip().split("\n")
    assert lines[0] == "id,timestamp,user_sub,org_id,action,resource,decision"
    assert len(lines) - 1 >= len(deny) - 1, "CSV must contain the same filtered rows"


def test_audit_log_is_tenant_isolated(users, world):
    a, b = world["A"], world["B"]
    assert api("GET", f"/api/orgs/{q(a.id)}/audit-logs", users.carol).status_code == 403
    assert api("GET", f"/api/orgs/{q(a.id)}/audit-logs", b.admin).status_code == 403
    assert all(r["org_id"] == a.id for r in audit(a)), "an org's log must never contain another org's rows"


@known_gap("GET /api/courses/:id never calls recordAudit, so course reads (the most common decision) leave no audit row")
def test_course_reads_are_audited(users, world):
    assert course_status(users.carol, world["course_a"]) == 200
    rows = [r for r in audit(world["A"]) if r["resource"] == world["course_a"] and r["user_sub"] == users.carol.sub and r["action"] != "trace"]
    assert rows


# ================================================================ AI agent delegation
def delegate(user, org_id, scopes=("course:read",), minutes=5, agent="test-agent"):
    return api("POST", "/api/agents/delegate", user, json={"agent_id": agent, "org_id": org_id, "scopes": list(scopes), "duration_minutes": minutes})


def forge_agent_token(secret, delegator, did, org_id, scopes=("course:read",)):
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    head = f"{b({'alg': 'HS256', 'typ': 'JWT'})}.{b({'sub': 'forger', 'delegator': delegator, 'org_id': org_id, 'scopes': list(scopes), 'did': did, 'exp': int(time.time()) + 600})}"
    return head + "." + base64.urlsafe_b64encode(hmac.new(secret.encode(), head.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()


def test_agent_with_read_scope_reads_as_its_delegator(users, world):
    tok = delegate(users.carol, world["A"].id).json()["token"]
    assert course_status(tok, world["course_a"]) == 200


def test_agent_without_read_scope_is_denied(users, world):
    tok = delegate(users.carol, world["A"].id, scopes=("course:edit",)).json()["token"]
    assert course_status(tok, world["course_a"]) == 403


def test_agent_cannot_reach_a_course_outside_its_delegated_org(users, world):
    tok = delegate(users.carol, world["A"].id).json()["token"]
    assert course_status(tok, world["course_b"]) == 403


def test_agent_never_exceeds_its_delegators_rights(users, world):
    tok = delegate(users.dave, world["A"].id).json()["token"]  # dave is not a member of A
    assert course_status(tok, world["course_a"]) == 403


def test_tampered_agent_token_is_rejected(users, world):
    tok = delegate(users.carol, world["A"].id).json()["token"]
    assert course_status(tok[:-3] + ("AAA" if not tok.endswith("AAA") else "BBB"), world["course_a"]) == 401


def test_agent_token_is_not_a_human_session(users, world):
    tok = delegate(users.carol, world["A"].id).json()["token"]
    for method, path in (("GET", "/api/me"), ("GET", f"/api/orgs/{q(world['A'].id)}/overview"), ("POST", "/api/auth/revoke-session")):
        assert api(method, path, tok).status_code == 401, path
    assert api("GET", f"/api/orgs/{q(world['A'].id)}/audit-logs", tok).status_code == 401


def test_expired_agent_token_stops_working(users, world):
    tok = delegate(users.carol, world["A"].id, minutes=0.03).json()["token"]
    wait_for(lambda: course_status(tok, world["course_a"]) != 200, "short-lived agent token to expire", timeout=8)
    assert course_status(tok, world["course_a"]) in (401, 403)


def test_agent_loses_access_when_its_delegator_is_suspended(users):
    org = make_org(users.master, users.alice, "t5ag")
    add_member(org, users.carol, "learner")
    cid = make_course(org)
    tok = delegate(users.carol, org.id).json()["token"]
    assert course_status(tok, cid) == 200
    api("PATCH", f"/api/orgs/{q(org.id)}/members/{users.carol.sub}/suspend", org.admin)
    wait_for(lambda: course_status(tok, cid) == 403, "agent to lose access with its delegator")


@known_gap("AGENT_SECRET falls back to a hard-coded default and the delegator claim is trusted from the token, so anyone who knows the default can act as any user")
def test_default_agent_secret_does_not_allow_forged_delegations(users, world):
    a = world["A"]
    own = delegate(users.dave, a.id).json()["token"]              # dave (outsider) may mint a delegation for org A (see gap below)
    did = json.loads(base64.urlsafe_b64decode(own.split(".")[1] + "==="))["did"]
    forged = forge_agent_token("super-secret-agent-key", users.alice.sub, did, a.id)
    assert course_status(forged, world["course_a"]) in (401, 403), "forged token acted as alice"


@known_gap("POST /api/agents/delegate does not check that the caller belongs to the org it delegates")
def test_delegation_requires_membership_of_the_org(users, world):
    assert delegate(users.dave, world["A"].id).status_code in (400, 403)


@known_gap("delegation duration is unbounded")
def test_delegation_duration_is_capped(users, world):
    assert delegate(users.carol, world["A"].id, minutes=10_000_000).status_code == 400


@known_gap("delegation scopes are not validated against an allow-list")
def test_delegation_scopes_are_validated(users, world):
    assert delegate(users.carol, world["A"].id, scopes=("course:read", "root:everything")).status_code == 400
