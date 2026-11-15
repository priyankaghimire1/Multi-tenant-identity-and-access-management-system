"""
Type 4: core OpenFGA authorization boundaries on real tenant-owned resources.

Unlike the original, nothing is written to OpenFGA directly. Every tuple arrives the way it does in production:
API call -> Postgres row + outbox event -> worker -> OpenFGA. The tests wait for that pipeline by polling.
At the end an invariant test reads BOTH stores and proves they agree.
"""
import pytest

from conftest import (add_member, api, course_status, db_rows, fga_has, make_course, make_org, overview, q, trace, wait_for)


@pytest.fixture(scope="module")
def world(users):
    a = make_org(users.master, users.alice, "t4a")
    b = make_org(users.master, users.bob, "t4b")
    add_member(a, users.carol, "learner")
    add_member(a, users.dave, "instructor")
    return {"A": a, "B": b, "course_a": make_course(a), "course_b": make_course(b)}


def test_role_permission_matrix_on_one_course(users, world):
    expect = {"alice": (True, True, True), "dave": (True, True, False), "carol": (True, False, False)}
    for name, (v, e, d) in expect.items():
        dec = trace(getattr(users, name), world["A"].id, world["course_a"]).json()["decision"]
        assert (dec["view"], dec["edit"], dec["delete"]) == (v, e, d), name


def test_allowed_own_resource(users, world):
    assert course_status(users.carol, world["course_a"]) == 200


def test_denied_changed_tenant_resource(users, world):
    assert course_status(users.carol, world["course_b"]) == 403
    assert course_status(users.alice, world["course_b"]) == 403, "an admin of tenant A must not read tenant B"


def test_denied_member_admin_on_another_tenant(users, world):
    a, bob = world["A"], world["B"].admin
    assert api("GET", f"/api/orgs/{q(a.id)}/audit-logs", bob).status_code == 403
    assert api("POST", f"/api/orgs/{q(a.id)}/memberships", bob, json={"user_sub": users.master.sub, "role": "admin"}).status_code == 403
    assert api("GET", f"/api/orgs/{q(a.id)}/overview", bob).status_code == 403


def test_only_tenant_admins_can_create_courses_and_only_in_their_org(users, world):
    a, b = world["A"], world["B"]
    for who, org in ((users.carol, a), (users.dave, a), (users.alice, b), (users.bob, a)):
        r = api("POST", "/api/courses", who, json={"course_id": f"course:nope-{who.name}-{org.slug}", "org_id": org.id, "title": "x"})
        assert r.status_code == 403, f"{who.name} in {org.slug}: {r.status_code}"


def test_tenant_admin_cannot_use_platform_apis(users):
    assert api("GET", "/api/admin/orgs", users.alice).status_code == 403
    assert api("POST", "/api/orgs", users.alice, json={"org_id": "organization:evil", "name": "e", "domain": "evil.test", "admin_sub": users.alice.sub}).status_code == 403
    assert api("GET", "/api/admin/orgs", users.master).status_code == 200


def test_suspended_membership_is_denied_then_restored(users):
    org = make_org(users.master, users.alice, "t4s")
    add_member(org, users.carol, "learner")
    cid = make_course(org)
    assert api("PATCH", f"/api/orgs/{q(org.id)}/members/{users.carol.sub}/suspend", org.admin).status_code == 200
    wait_for(lambda: course_status(users.carol, cid) == 403, "suspended member to be denied")
    steps = {s["key"]: s for s in trace(users.carol, org.id, cid).json()["steps"]}
    assert steps["not_suspended"]["passed"] is False and steps["membership"]["passed"] is True, "role tuple must survive suspension"
    assert fga_has(f"user:{users.carol.sub}", "suspended", org.id) is True
    assert api("PATCH", f"/api/orgs/{q(org.id)}/members/{users.carol.sub}/unsuspend", org.admin).status_code == 200
    wait_for(lambda: course_status(users.carol, cid) == 200, "reinstated member to regain access")
    wait_for(lambda: overview(org.admin, org.id)["sync"]["in_sync"], "dashboard to report in_sync")


def test_suspended_admin_loses_admin_power_everywhere(users):
    org = make_org(users.master, users.alice, "t4sa")
    add_member(org, users.bob, "admin")
    cid = make_course(org)
    assert api("GET", f"/api/orgs/{q(org.id)}/audit-logs", users.bob).status_code == 200
    assert api("PATCH", f"/api/orgs/{q(org.id)}/members/{users.bob.sub}/suspend", org.admin).status_code == 200
    wait_for(lambda: api("GET", f"/api/orgs/{q(org.id)}/audit-logs", users.bob).status_code == 403, "suspended admin to lose audit access")
    assert course_status(users.bob, cid) == 403
    assert api("POST", f"/api/orgs/{q(org.id)}/memberships", users.bob, json={"user_sub": users.carol.sub, "role": "admin"}).status_code == 403


def test_suspended_tenant_denies_every_role_and_spares_other_tenants(users, world):
    org = make_org(users.master, users.alice, "t4t")
    add_member(org, users.carol, "learner")
    add_member(org, users.dave, "instructor")
    cid = make_course(org)
    assert api("PATCH", f"/api/orgs/{q(org.id)}/suspend", users.master).status_code == 200
    wait_for(lambda: all(course_status(u, cid) == 403 for u in (users.alice, users.carol, users.dave)), "all roles denied in suspended tenant")
    assert api("GET", f"/api/orgs/{q(org.id)}/audit-logs", users.alice).status_code == 403, "even the admin loses admin power"
    assert fga_has("user:anyone", "tenant_active", org.id) is False
    assert course_status(world["B"].admin, world["course_b"]) == 200, "other tenants must be unaffected"
    assert api("PATCH", f"/api/orgs/{q(org.id)}/suspend", users.master).status_code == 409
    assert api("PATCH", f"/api/orgs/{q(org.id)}/unsuspend", users.master).status_code == 200
    wait_for(lambda: all(course_status(u, cid) == 200 for u in (users.alice, users.carol, users.dave)), "all roles restored after reactivation")
    assert fga_has("user:anyone", "tenant_active", org.id) is True


def test_only_the_platform_admin_can_suspend_a_tenant(users, world):
    a = world["A"]
    assert api("PATCH", f"/api/orgs/{q(a.id)}/suspend", users.alice).status_code == 403
    assert api("PATCH", f"/api/orgs/{q(a.id)}/suspend", users.bob).status_code == 403
    assert course_status(users.carol, world["course_a"]) == 200


def test_postgres_and_openfga_agree_for_every_object_this_module_created(users, world):
    """The key invariant of the outbox design: after it drains, both stores describe the same world."""
    org_ids = tuple(r[0] for r in db_rows("SELECT id FROM organizations WHERE id LIKE %s", ("organization:t4%-" + __import__("conftest").RUN + "-%",)))
    assert len(org_ids) >= 5
    for org_id in org_ids:
        wait_for(lambda: db_rows("SELECT count(*) FROM outbox_events WHERE processed=FALSE AND payload->>'object'=%s", (org_id,))[0][0] == 0, "outbox to drain")
    problems = []
    for org_id, active in db_rows("SELECT id, is_active FROM organizations WHERE id = ANY(%s)", (list(org_ids),)):
        if fga_has("user:anyone", "tenant_active", org_id) != active:
            problems.append(f"{org_id}: tenant_active mismatch (db active={active})")
        if not fga_has("platform:root", "platform", org_id):
            problems.append(f"{org_id}: missing platform link")
    for sub, org_id, role, suspended in db_rows("SELECT user_sub, org_id, role, is_suspended FROM tenant_memberships WHERE org_id = ANY(%s)", (list(org_ids),)):
        if not fga_has(f"user:{sub}", role, org_id):
            problems.append(f"{org_id}: {sub} {role} missing in OpenFGA")
        if fga_has(f"user:{sub}", "suspended", org_id) != suspended:
            problems.append(f"{org_id}: {sub} suspended mismatch (db={suspended})")
    for cid, org_id in db_rows("SELECT id, org_id FROM courses WHERE org_id = ANY(%s)", (list(org_ids),)):
        if not fga_has(org_id, "org", cid):
            problems.append(f"{cid}: ownership tuple missing")
    assert not problems, "\n".join(problems)
