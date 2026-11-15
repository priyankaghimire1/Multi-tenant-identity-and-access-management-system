"""
Type 1: one global user, several SCOPED memberships; no global (Keycloak realm) role leaks into authorization.

Real architecture notes:
- There is no GET /members route. Member lists are returned by the admin-only /overview, so that is what is tested.
- Authorization comes from OpenFGA tuples that the outbox mirrors from Postgres, never from realm roles.
"""
import json

import pytest

from conftest import (GLOBAL_ROLES, ROLES, add_member, api, make_course, make_org, overview, q, trace)


@pytest.fixture(scope="module")
def world(users):
    a = make_org(users.master, users.alice, "t1a")
    b = make_org(users.master, users.alice, "t1b")
    c = make_org(users.master, users.bob, "t1c")  # administered by bob; alice has the realm role tenant-admin but no membership here
    add_member(a, users.dave, "learner")
    add_member(b, users.dave, "instructor")
    return {"A": a, "B": b, "C": c, "course_a": make_course(a), "course_b": make_course(b)}


def test_me_returns_two_scoped_memberships_and_no_global_roles(users, world):
    body = api("GET", "/api/me", users.dave).json()
    assert body["user"]["sub"] == users.dave.sub and body["user"]["is_super_admin"] is False
    by_org = {m["org_id"]: m for m in body["orgs"]}
    assert by_org[world["A"].id]["role"] == "learner"
    assert by_org[world["B"].id]["role"] == "instructor"
    assert all(m["role"] in ROLES and m["role"] not in GLOBAL_ROLES for m in body["orgs"])
    assert "realm_access" not in json.dumps(body)


def test_token_carries_a_realm_role_but_it_confers_nothing(users):
    """Proves the leak test below is meaningful: the realm role really is in Dave's token."""
    assert "tenant-user" in users.dave.claims["realm_access"]["roles"]


def test_overview_scopes_role_per_org(users, world):
    oa = overview(users.dave, world["A"].id)
    ob = overview(users.dave, world["B"].id)
    assert (oa["me"]["role"], oa["me"]["roles"]) == ("learner", ["learner"])
    assert (ob["me"]["role"], ob["me"]["roles"]) == ("instructor", ["instructor"])


@pytest.mark.parametrize("key", ["A", "B"])
def test_non_admin_cannot_use_admin_endpoints_in_either_org(users, world, key):
    org = world[key]
    assert api("GET", f"/api/orgs/{q(org.id)}/audit-logs", users.dave).status_code == 403
    assert api("POST", f"/api/orgs/{q(org.id)}/memberships", users.dave, json={"user_sub": users.carol.sub, "role": "admin"}).status_code == 403
    assert api("PATCH", f"/api/orgs/{q(org.id)}/members/{users.dave.sub}/role", users.dave, json={"role": "admin"}).status_code == 403
    ov = overview(users.dave, org.id)
    assert ov["members"] == [] and ov["stats"] is None, "non-admins must not receive the member list"


def test_admin_member_list_has_exactly_one_scoped_row_per_org(users, world):
    for key, role in (("A", "learner"), ("B", "instructor")):
        rows = [m for m in overview(users.alice, world[key].id)["members"] if m["user_sub"] == users.dave.sub]
        assert len(rows) == 1 and rows[0]["role"] == role


def test_trace_permissions_are_scoped_per_org(users, world):
    ta = trace(users.dave, world["A"].id, world["course_a"])
    tb = trace(users.dave, world["B"].id, world["course_b"])
    assert ta.status_code == tb.status_code == 200
    assert ta.json()["decision"] == {"view": True, "edit": False, "delete": False}
    assert tb.json()["decision"] == {"view": True, "edit": True, "delete": False}
    steps_a = {s["key"]: s for s in ta.json()["steps"]}
    steps_b = {s["key"]: s for s in tb.json()["steps"]}
    assert "learner" in steps_a["membership"]["detail"] and "instructor" not in steps_a["membership"]["detail"]
    assert "instructor" in steps_b["membership"]["detail"] and "learner" not in steps_b["membership"]["detail"]


def test_trace_rejects_a_course_from_a_different_org(users, world):
    r = trace(users.dave, world["A"].id, world["course_b"])
    assert r.status_code == 404, "course must be resolved inside the org named in the path"


def test_org_id_with_and_without_prefix_are_equivalent(users, world):
    a = api("GET", f"/api/orgs/{world['A'].slug}/overview", users.dave)
    b = api("GET", f"/api/orgs/{q(world['A'].id)}/overview", users.dave)
    assert a.status_code == b.status_code == 200
    assert a.json()["me"] == b.json()["me"]


def test_realm_role_tenant_admin_gives_no_power_in_an_org_without_membership(users, world):
    c = world["C"]
    assert users.alice.claims["realm_access"]["roles"].count("tenant-admin") == 1
    assert api("GET", f"/api/orgs/{q(c.id)}/overview", users.alice).status_code == 403
    assert api("GET", f"/api/orgs/{q(c.id)}/audit-logs", users.alice).status_code == 403
    assert api("POST", f"/api/orgs/{q(c.id)}/memberships", users.alice, json={"user_sub": users.carol.sub, "role": "learner"}).status_code == 403


def test_platform_admin_realm_role_gives_no_tenant_access(users, world):
    a, course = world["A"], world["course_a"]
    assert "platform-admin" in users.master.claims["realm_access"]["roles"]
    assert api("GET", f"/api/orgs/{q(a.id)}/overview", users.master).status_code == 403
    assert api("GET", f"/api/orgs/{q(a.id)}/audit-logs", users.master).status_code == 403
    assert api("GET", f"/api/courses/{q(course)}", users.master).status_code == 403
