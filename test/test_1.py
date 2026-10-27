"""
Verifies that membership APIs return two *scoped* memberships for a single
global user, and that no global-role (Keycloak realm role) leaks into the
scoped authorization decisions.
"""

import os
import time
import pytest
import requests

GATEWAY = os.getenv("GATEWAY_URL", "http://localhost:3000")
KC = os.getenv("KEYCLOAK_URL", "http://localhost:8081")
REALM = os.getenv("KEYCLOAK_REALM", "dat")
CLIENT_ID = os.getenv("KC_CLIENT_ID", "web-app")

DAVE_SUB = "dave-sub-012"
MASTER_SUB = "super-admin-000"
GLOBAL_ROLES = {"tenant-user", "tenant-admin", "platform-admin"}

ORG_A = "organization:acme-test"
ORG_B = "organization:globex-test"
ORG_A_NAME = "Acme Test University"
ORG_B_NAME = "Globex Test Corp"

# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------
def login(username: str, password: str = "password") -> dict:
    """Password grant against the public web-app client (directAccessGrantsEnabled)."""
    resp = requests.post(
        f"{KC}/realms/{REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "username": username,
            "password": password,
            "scope": "openid",
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()

def bearer(token: dict) -> dict:
    return {"Authorization": f"Bearer {token['access_token']}"}

def api(method: str, path: str, token: dict, **kw) -> requests.Response:
    return requests.request(method, f"{GATEWAY}{path}", headers=bearer(token), timeout=15, **kw)

def wait_for_outbox(seconds: float = 3.0):
    """fga.js polls the outbox every 1s; give it a moment to mirror tuples."""
    time.sleep(seconds)

def provision_org(admin_token, org_id: str, name: str, domain: str, admin_email: str):
    """Idempotent org provisioning via master admin."""
    r = api("POST", "/api/orgs", admin_token, json={
        "org_id": org_id,
        "name": name,
        "domain": domain,
        "admin_email": admin_email,
    })
    # 201 first time, 409 (already exists) on re-run — accept both
    assert r.status_code in (201, 409), f"provision {org_id} -> {r.status_code}: {r.text}"
    return r

# ---------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------
@pytest.fixture(scope="module")
def master_token():
    t = login("master")
    r = api("GET", "/api/me", t)
    assert r.status_code == 200, r.text
    assert r.json()["user"]["is_super_admin"] is True
    return t

@pytest.fixture(scope="module")
def dave_token():
    return login("dave")

@pytest.fixture(scope="module")
def seeded_orgs(master_token):
    """Ensure two orgs exist, with Alice as the admin."""
    # 1. Force Alice's profile into the DB
    alice_tok = login("alice")
    api("GET", "/api/me", alice_tok)

    # 2. Now we can provision the orgs
    provision_org(master_token, ORG_A, ORG_A_NAME, "acme-test.edu", "alice@acme.edu")
    provision_org(master_token, ORG_B, ORG_B_NAME, "globex-test.com", "alice@acme.edu")
    wait_for_outbox(3.0)
    return {"org_a": ORG_A, "org_b": ORG_B}

@pytest.fixture(scope="module")
def dave_two_memberships(master_token, seeded_orgs):
    """
    Put Dave into org A as `learner` and org B as `instructor`.
    """
    # 1. Force Dave's profile into the DB
    dave_tok = login("dave")
    api("GET", "/api/me", dave_tok)

    # 2. Now Alice can add him
    alice = login("alice")

    for org, role in ((ORG_A, "learner"), (ORG_B, "instructor")):
        slug = org.split(":", 1)[1]
        r = api("POST", f"/api/orgs/{slug}/memberships", alice, json={
            "user_sub": DAVE_SUB,
            "role": role,
        })
        assert r.status_code in (201, 409), f"add dave to {org} -> {r.status_code}: {r.text}"

    wait_for_outbox(3.0)
    return {ORG_A: "learner", ORG_B: "instructor"}
# ---------------------------------------------------------------
# Tests
# ---------------------------------------------------------------
def test_me_returns_two_scoped_memberships_and_no_global_roles(dave_token, dave_two_memberships):
    r = api("GET", "/api/me", dave_token)
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["user"]["sub"] == DAVE_SUB
    assert body["user"]["is_super_admin"] is False

    orgs = body["orgs"]
    org_ids = {m["org_id"] for m in orgs}
    assert ORG_A in org_ids and ORG_B in org_ids, f"expected {ORG_A} and {ORG_B} to be in {org_ids}"

    by_org = {m["org_id"]: m for m in orgs}
    assert by_org[ORG_A]["role"] == "learner", by_org[ORG_A]
    assert by_org[ORG_B]["role"] == "instructor", by_org[ORG_B]

    for m in orgs:
        assert m["role"] not in GLOBAL_ROLES, f"realm role leaked into scoped role: {m}"

    assert by_org[ORG_A]["role"] != by_org[ORG_B]["role"]


def test_overview_scopes_role_per_org(dave_token, dave_two_memberships):
    slug_a = ORG_A.split(":", 1)[1]
    slug_b = ORG_B.split(":", 1)[1]

    r_a = api("GET", f"/api/orgs/{slug_a}/overview", dave_token)
    assert r_a.status_code == 200, r_a.text
    body_a = r_a.json()
    assert body_a["me"]["role"] == "learner", body_a["me"]
    assert body_a["me"]["roles"] == ["learner"], body_a["me"]
    assert set(body_a["me"]["roles"]).isdisjoint(GLOBAL_ROLES)

    r_b = api("GET", f"/api/orgs/{slug_b}/overview", dave_token)
    assert r_b.status_code == 200, r_b.text
    body_b = r_b.json()
    assert body_b["me"]["role"] == "instructor", body_b["me"]
    assert body_b["me"]["roles"] == ["instructor"], body_b["me"]
    assert set(body_b["me"]["roles"]).isdisjoint(GLOBAL_ROLES)

    assert "learner" not in body_b["me"]["roles"]
    assert "instructor" not in body_a["me"]["roles"]


def test_admin_scoped_endpoints_reject_dave_in_learner_org(dave_token, dave_two_memberships):
    slug_a = ORG_A.split(":", 1)[1]

    for path in (
        f"/api/orgs/{slug_a}/members",
        f"/api/orgs/{slug_a}/audit-logs",
    ):
        r = api("GET", path, dave_token)
        assert r.status_code == 403, f"{path} should be 403 for learner, got {r.status_code}: {r.text}"


def test_member_list_in_one_org_does_not_echo_other_org_role(master_token, dave_token, dave_two_memberships):
    slug_a = ORG_A.split(":", 1)[1]
    alice = login("alice")

    r = api("GET", f"/api/orgs/{slug_a}/members", alice)
    assert r.status_code == 200, r.text
    rows = r.json()

    dave_rows = [m for m in rows if m["user_sub"] == DAVE_SUB]
    assert len(dave_rows) == 1, f"expected exactly one Dave row in ORG_A, got {dave_rows}"
    assert dave_rows[0]["role"] == "learner", dave_rows[0]
    assert dave_rows[0]["role"] not in GLOBAL_ROLES
    assert dave_rows[0]["role"] != "instructor"


def test_trace_endpoint_role_checks_are_org_scoped(dave_token, dave_two_memberships):
    slug_a = ORG_A.split(":", 1)[1]

    r = api("GET", f"/api/orgs/{slug_a}/overview", dave_token)
    assert r.status_code == 200, r.text
    courses = r.json().get("courses", [])
    if not courses:
        pytest.skip("No courses seeded in ORG_A; trace assertion skipped")

    course_id = courses[0]["id"]
    trace = api("GET", f"/api/orgs/{slug_a}/courses/{course_id}/trace", dave_token)
    assert trace.status_code == 200, trace.text
    body = trace.json()

    steps = {s["key"]: s for s in body["steps"]}
    assert steps["authenticated"]["passed"] is True
    assert steps["membership"]["passed"] is True
    assert "learner" in steps["membership"]["detail"]
    assert steps["policy_edit"]["passed"] is False
    assert steps["policy_delete"]["passed"] is False
    assert "instructor" not in steps["membership"]["detail"]