"""
pytest: the membership API returns two scoped memberships for one global user,
and the global role does not leak into either scope.

Live mode:   set MEMBERSHIP_BASE_URL (and optionally MEMBERSHIP_TOKEN)
Fixture mode: leave MEMBERSHIP_BASE_URL unset; a built-in response is used.

Other env vars (defaults in parentheses):
    MEMBERSHIP_USER_ID (u-1)
    MEMBERSHIP_GLOBAL_ROLE (GlobalAdmin)
    MEMBERSHIP_SCOPE_IDS (org-1,prj-9)

ASSUMED RESPONSE SHAPE for GET {base}/users/{id}/memberships (adjust
fetch_response() and the field names below if yours differs):
{
  "userId": "u-1",
  "globalRoles": ["GlobalAdmin"],
  "memberships": [
    {"id": "m-1", "userId": "u-1", "scopeType": "org",     "scopeId": "org-1", "roles": ["Viewer"]},
    {"id": "m-2", "userId": "u-1", "scopeType": "project", "scopeId": "prj-9", "roles": ["Editor"]}
  ]
}

Run:  pip install pytest requests && pytest test_membership.py -v
"""
import json
import os

import pytest

BASE_URL = os.getenv("MEMBERSHIP_BASE_URL", "").rstrip("/")
TOKEN = os.getenv("MEMBERSHIP_TOKEN", "")
USER_ID = os.getenv("MEMBERSHIP_USER_ID", "u-1")
GLOBAL_ROLE = os.getenv("MEMBERSHIP_GLOBAL_ROLE", "GlobalAdmin")
SCOPE_IDS = os.getenv("MEMBERSHIP_SCOPE_IDS", "org-1,prj-9").split(",")

GLOBAL_ROLE_FIELDS = {"globalRoles", "globalRole", "isGlobalAdmin"}


def fixture_response():
    return {
        "userId": USER_ID,
        "globalRoles": [GLOBAL_ROLE],
        "memberships": [
            {"id": "m-1", "userId": USER_ID, "scopeType": "org",
             "scopeId": SCOPE_IDS[0], "roles": ["Viewer"]},
            {"id": "m-2", "userId": USER_ID, "scopeType": "project",
             "scopeId": SCOPE_IDS[1], "roles": ["Editor"]},
        ],
    }


def fetch_response():
    if not BASE_URL:
        return fixture_response()
    import requests

    headers = {"Accept": "application/json"}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    r = requests.get(f"{BASE_URL}/users/{USER_ID}/memberships",
                     headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()


@pytest.fixture(scope="module")
def response():
    return fetch_response()


@pytest.fixture(scope="module")
def memberships(response):
    return response["memberships"]


# ---- Shape -----------------------------------------------------------------

def test_returns_exactly_two_memberships(memberships):
    assert len(memberships) == 2


def test_memberships_belong_to_requested_user(memberships):
    assert all(m["userId"] == USER_ID for m in memberships)


def test_two_expected_distinct_scopes(memberships):
    actual = sorted(m["scopeId"] for m in memberships)
    assert actual == sorted(SCOPE_IDS)
    assert len(set(actual)) == 2


def test_membership_ids_are_distinct(memberships):
    assert len({m["id"] for m in memberships}) == 2


# ---- No global-role leakage ------------------------------------------------

def test_global_role_reported_only_at_user_level(response):
    assert GLOBAL_ROLE in response["globalRoles"]


def test_global_role_not_in_any_membership_roles(memberships):
    for m in memberships:
        assert GLOBAL_ROLE not in m["roles"], (
            f"scope {m['scopeId']} must not inherit the global role"
        )


def test_no_global_role_fields_on_memberships(memberships):
    for m in memberships:
        assert GLOBAL_ROLE_FIELDS.isdisjoint(m.keys()), (
            f"unexpected global-role field(s) on {m['id']}: "
            f"{GLOBAL_ROLE_FIELDS & set(m.keys())}"
        )


def test_global_role_name_absent_from_serialized_memberships(memberships):
    for m in memberships:
        assert GLOBAL_ROLE not in json.dumps(m)


def test_scoped_roles_are_independent(memberships):
    a, b = (set(m["roles"]) for m in memberships)
    # Scenario assumes different roles per scope; drop this test if yours share roles.
    if a and b:
        assert a.isdisjoint(b), "roles appear copied between scopes"
