"""
test_2.py

Verifies Duplicate membership / cross-org role assignment:
1. Reject duplicate memberships in the same org (409 Conflict).
2. Reject org-A membership trying to write an org-B role binding (403 Forbidden).
3. Ensure the database does not contain partial or leaked rows.
"""

import os
import time
import pytest
import requests
import psycopg2

GATEWAY = os.getenv("GATEWAY_URL", "http://localhost:3000")
KC = os.getenv("KEYCLOAK_URL", "http://localhost:8081")
REALM = os.getenv("KEYCLOAK_REALM", "dat")
CLIENT_ID = os.getenv("KC_CLIENT_ID", "web-app")

DAVE_SUB = "dave-sub-012"
BOB_SUB = "bob-sub-456"
ALICE_SUB = "alice-sub-123"

ORG_A = "organization:acme-duplicate-test"
ORG_B = "organization:globex-cross-test"

# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------
def login(username: str, password: str = "password") -> dict:
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

def wait_for_outbox(seconds: float = 2.0):
    time.sleep(seconds)

def provision_org(admin_token, org_id: str, name: str, domain: str, admin_email: str):
    r = api("POST", "/api/orgs", admin_token, json={
        "org_id": org_id,
        "name": name,
        "domain": domain,
        "admin_email": admin_email,
    })
    assert r.status_code in (201, 409), f"provision {org_id} -> {r.status_code}: {r.text}"

def get_db_conn():
    return psycopg2.connect(
        host="localhost", database="dat", user="dat", password="dat", port="5432"
    )

# ---------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------
@pytest.fixture(scope="module")
def master_token():
    t = login("master")
    r = api("GET", "/api/me", t)
    assert r.status_code == 200
    assert r.json()["user"]["is_super_admin"] is True
    return t

@pytest.fixture(scope="module")
def admin_tokens(master_token):
    """Returns tokens for Alice (admin in A) and Bob (admin in B)."""
    alice_tok = login("alice")
    api("GET", "/api/me", alice_tok) # Force profile creation
    
    bob_tok = login("bob")
    api("GET", "/api/me", bob_tok) # Force profile creation

    # Provision Org A (Alice admin) and Org B (Bob admin)
    provision_org(master_token, ORG_A, "Acme Dup Test", "acme-dup.edu", "alice@acme.edu")
    provision_org(master_token, ORG_B, "Globex Cross Test", "globex-cross.com", "bob@acme.edu")
    wait_for_outbox(2.0)
    
    return {"alice": alice_tok, "bob": bob_tok}

@pytest.fixture(scope="module")
def dave_token():
    t = login("dave")
    api("GET", "/api/me", t) # Force profile creation
    return t

# ---------------------------------------------------------------
# Tests
# ---------------------------------------------------------------
def test_duplicate_membership_rejected(admin_tokens, dave_token):
    """
    1. Alice adds Dave to Org A as 'learner' -> 201 Created.
    2. Alice tries to add Dave to Org A again as 'instructor' -> 409 Conflict.
    """
    alice = admin_tokens["alice"]
    slug_a = ORG_A.split(":", 1)[1]

    # 1. First add (should succeed)
    r1 = api("POST", f"/api/orgs/{slug_a}/memberships", alice, json={
        "user_sub": DAVE_SUB,
        "role": "learner",
    })
    assert r1.status_code == 201, f"First add failed: {r1.text}"
    
    # 2. Duplicate add (should fail)
    r2 = api("POST", f"/api/orgs/{slug_a}/memberships", alice, json={
        "user_sub": DAVE_SUB,
        "role": "instructor",
    })
    assert r2.status_code == 409, f"Expected 409 Conflict, got {r2.status_code}: {r2.text}"
    assert "Already a member" in r2.text, f"Unexpected error message: {r2.text}"


def test_database_preserves_first_membership(admin_tokens):
    """
    Verifies that the database only contains ONE row for Dave in Org A,
    and that the role is still 'learner' (the duplicate 'instructor' attempt didn't overwrite it).
    """
    conn = get_db_conn()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT role FROM tenant_memberships WHERE user_sub = %s AND org_id = %s",
            (DAVE_SUB, ORG_A)
        )
        rows = cur.fetchall()
    conn.close()

    assert len(rows) == 1, f"Expected exactly 1 row for Dave in Org A, got {len(rows)}"
    assert rows[0][0] == "learner", f"Role was overwritten! Expected 'learner', got '{rows[0][0]}'"


def test_cross_org_role_assignment_rejected(admin_tokens, dave_token):
    """
    1. Bob is an admin in Org B (globex-cross-test).
    2. Bob tries to add Dave to Org A (acme-duplicate-test) using the Org B slug.
    3. The API should reject this with a 403 Forbidden.
    """
    bob = admin_tokens["bob"]
    slug_a = ORG_A.split(":", 1)[1]
    
    # Bob has no permissions in Org A, so he cannot add members
    r = api("POST", f"/api/orgs/{slug_a}/memberships", bob, json={
        "user_sub": DAVE_SUB,
        "role": "admin",
    })
    
    assert r.status_code == 403, f"Expected 403 Forbidden, got {r.status_code}: {r.text}"


def test_database_no_cross_org_contamination(admin_tokens):
    """
    Verifies the database doesn't contain a row where Dave is an 'admin' in Org A
    (which Bob tried to do) or Dave is 'instructor' in Org A.
    """
    conn = get_db_conn()
    with conn.cursor() as cur:
        # Check Dave's memberships in Org A
        cur.execute(
            "SELECT role FROM tenant_memberships WHERE user_sub = %s AND org_id = %s",
            (DAVE_SUB, ORG_A)
        )
        roles_org_a = [r[0] for r in cur.fetchall()]

        # Check Dave's memberships in Org B (Bob's org)
        cur.execute(
            "SELECT role FROM tenant_memberships WHERE user_sub = %s AND org_id = %s",
            (DAVE_SUB, ORG_B)
        )
        roles_org_b = [r[0] for r in cur.fetchall()]
    conn.close()

    # Dave should ONLY be a learner in Org A. Bob's malicious cross-org attempt must not appear.
    assert roles_org_a == ["learner"], f"Org A contaminated. Roles: {roles_org_a}"
    # Dave should not be in Org B at all yet.
    assert len(roles_org_b) == 0, f"Org B contaminated. Roles: {roles_org_b}"


def test_cross_org_role_assignment_in_fga_rejected(admin_tokens, dave_token):
    """
    Proves that even if a user has a valid token, OpenFGA does not leak permissions
    across the organization boundary.
    """
    dave = dave_token
    
    # Dave tries to access the member list for Org B (Bob's org) where Dave is NOT a member
    slug_b = ORG_B.split(":", 1)[1]
    r = api("GET", f"/api/orgs/{slug_b}/members", dave)
    assert r.status_code == 403, f"Dave should not see Org B members. Got {r.status_code}: {r.text}"