"""
Type 2: duplicate memberships and cross-org role assignment.
Checks the API response, the Postgres rows AND the OpenFGA tuples, because the outbox must keep all three consistent.
"""
import threading

import pytest

from conftest import (add_member, api, db_rows, fga_has, fga_tuples, known_gap, make_org, overview, q, wait_for)


@pytest.fixture(scope="module")
def world(users):
    a = make_org(users.master, users.alice, "t2a")   # alice admin
    b = make_org(users.master, users.bob, "t2b")     # bob admin
    add_member(a, users.dave, "learner")
    return {"A": a, "B": b}


def roles_in_db(sub, org_id):
    return sorted(r[0] for r in db_rows("SELECT role FROM tenant_memberships WHERE user_sub=%s AND org_id=%s", (sub, org_id)))


def test_duplicate_membership_is_rejected_and_first_role_survives(users, world):
    a = world["A"]
    r = api("POST", f"/api/orgs/{q(a.id)}/memberships", a.admin, json={"user_sub": users.dave.sub, "role": "instructor"})
    assert r.status_code == 409 and "Already a member" in r.text
    assert roles_in_db(users.dave.sub, a.id) == ["learner"]
    assert fga_has(f"user:{users.dave.sub}", "learner", a.id) is True
    assert fga_has(f"user:{users.dave.sub}", "instructor", a.id) is False


def test_cross_org_admin_cannot_assign_roles_in_another_org(users, world):
    a, b = world["A"], world["B"]
    bob = b.admin
    attempts = [
        ("POST", f"/api/orgs/{q(a.id)}/memberships", {"user_sub": users.carol.sub, "role": "admin"}),
        ("PATCH", f"/api/orgs/{q(a.id)}/members/{users.dave.sub}/role", {"role": "admin"}),
        ("PATCH", f"/api/orgs/{q(a.id)}/members/{users.dave.sub}/suspend", None),
        ("DELETE", f"/api/orgs/{q(a.id)}/members/{users.dave.sub}", None),
    ]
    for method, path, body in attempts:
        r = api(method, path, bob, json=body) if body else api(method, path, bob)
        assert r.status_code == 403, f"{method} {path} -> {r.status_code}"
    assert roles_in_db(users.dave.sub, a.id) == ["learner"]
    assert roles_in_db(users.carol.sub, a.id) == []
    assert fga_has(f"user:{users.carol.sub}", "admin", a.id) is False


def test_adding_a_member_to_own_org_does_not_touch_the_other_org(users, world):
    a, b = world["A"], world["B"]
    add_member(b, users.carol, "learner")
    assert roles_in_db(users.carol.sub, b.id) == ["learner"]
    assert roles_in_db(users.carol.sub, a.id) == []
    assert fga_has(f"user:{users.carol.sub}", "learner", a.id) is False


def test_outsider_cannot_read_other_org(users, world):
    assert overview(users.dave, world["B"].id) == {}
    assert api("GET", f"/api/orgs/{q(world['B'].id)}/overview", users.dave).status_code == 403


def test_role_change_leaves_exactly_one_row_and_one_tuple(users, world):
    a = world["A"]
    r = api("PATCH", f"/api/orgs/{q(a.id)}/members/{users.dave.sub}/role", a.admin, json={"role": "instructor"})
    assert r.status_code == 200 and r.json()["changed"] is True
    wait_for(lambda: fga_has(f"user:{users.dave.sub}", "instructor", a.id) and not fga_has(f"user:{users.dave.sub}", "learner", a.id),
             "FGA to show instructor and no learner after role change")
    assert roles_in_db(users.dave.sub, a.id) == ["instructor"]


def test_invalid_role_is_rejected_and_nothing_is_written(users, world):
    a = world["A"]
    before = db_rows("SELECT count(*) FROM outbox_events")[0][0]
    r = api("POST", f"/api/orgs/{q(a.id)}/memberships", a.admin, json={"user_sub": users.bob.sub, "role": "superuser"})
    assert r.status_code == 400
    assert roles_in_db(users.bob.sub, a.id) == []
    assert db_rows("SELECT count(*) FROM outbox_events")[0][0] == before, "a rejected request must not emit outbox events"


@known_gap("POST memberships is SELECT-then-INSERT with no lock and UNIQUE(user_sub, org_id, role) omits the role-free key, so concurrent adds create two roles (12/12 trials)")
def test_concurrent_conflicting_adds_never_create_two_roles(users):
    """Two admins' requests race to give the same new user different roles. Exactly one may win."""
    double = 0
    for _ in range(12):
        org = make_org(users.master, users.alice, "t2race")
        results = []
        barrier = threading.Barrier(2)

        def go(role):
            barrier.wait()
            results.append(api("POST", f"/api/orgs/{q(org.id)}/memberships", org.admin, json={"user_sub": users.carol.sub, "role": role}).status_code)

        ts = [threading.Thread(target=go, args=(r,)) for r in ("learner", "admin")]
        [t.start() for t in ts]
        [t.join() for t in ts]
        if len(roles_in_db(users.carol.sub, org.id)) > 1:
            double += 1
    assert double == 0, f"{double}/12 races produced two simultaneous roles for one user in one org"


@known_gap("POST memberships accepts any user_sub with no existence/format check; the outbox then silently drops the rejected tuple")
def test_malformed_user_sub_is_rejected_at_the_api(users):
    org = make_org(users.master, users.alice, "t2bad")
    r = api("POST", f"/api/orgs/{q(org.id)}/memberships", org.admin, json={"user_sub": "bad sub with spaces", "role": "learner"})
    assert r.status_code in (400, 404)


@known_gap("outbox marks events processed even when OpenFGA rejects the tuple (any HTTP 400 is treated as 'already exists')")
def test_outbox_never_drops_an_event_it_failed_to_apply(users):
    org = make_org(users.master, users.alice, "t2drop")
    api("POST", f"/api/orgs/{q(org.id)}/memberships", org.admin, json={"user_sub": "bad sub with spaces", "role": "learner"})
    wait_for(lambda: outbox_clear(org.id), "outbox to drain for the org")
    in_db = db_rows("SELECT count(*) FROM tenant_memberships WHERE org_id=%s AND user_sub=%s", (org.id, "bad sub with spaces"))[0][0] == 1
    in_fga = ("user:bad sub with spaces", "learner") in fga_tuples(org.id)
    assert in_db, "precondition: the API stored the membership"
    assert in_fga, "DB has a membership (and its outbox event is marked processed) but OpenFGA never received the tuple"


def outbox_clear(org_id):
    return db_rows("SELECT count(*) FROM outbox_events WHERE processed=FALSE AND payload->>'object'=%s", (org_id,))[0][0] == 0
