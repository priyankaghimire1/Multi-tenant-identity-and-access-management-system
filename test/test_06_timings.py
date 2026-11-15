"""
Quantitative evidence: how long revocation takes to become effective, and request latency.
Samples are written to results/results.json and summarised in results/results.md.
Thresholds are deliberately loose; the point is the recorded numbers.
"""
import time

import pytest
import requests

from conftest import (GATEWAY, SYNC_TIMEOUT, add_member, api, course_status, make_course, make_org, q, record_timing, wait_for, _pct)

N_PROP = 8
N_LAT = 100


@pytest.fixture(scope="module")
def world(users):
    org = make_org(users.master, users.alice, "t6")
    add_member(org, users.carol, "learner")
    add_member(org, users.bob, "learner")
    return {"org": org, "course": make_course(org)}


def test_revocation_propagation_delay(users, world):
    org, cid = world["org"], world["course"]
    for _ in range(N_PROP):
        api("PATCH", f"/api/orgs/{q(org.id)}/members/{users.carol.sub}/suspend", org.admin)
        t0 = time.perf_counter()
        wait_for(lambda: course_status(users.carol, cid) == 403, "suspension to take effect", interval=0.02)
        record_timing("propagation", "member suspended -> access denied", (time.perf_counter() - t0) * 1000)

        api("PATCH", f"/api/orgs/{q(org.id)}/members/{users.carol.sub}/unsuspend", org.admin)
        t0 = time.perf_counter()
        wait_for(lambda: course_status(users.carol, cid) == 200, "reinstatement to take effect", interval=0.02)
        record_timing("propagation", "member reinstated -> access restored", (time.perf_counter() - t0) * 1000)


def test_tenant_suspension_propagation_delay(users, world):
    org, cid = world["org"], world["course"]
    for _ in range(N_PROP):
        api("PATCH", f"/api/orgs/{q(org.id)}/suspend", users.master)
        t0 = time.perf_counter()
        wait_for(lambda: course_status(users.alice, cid) == 403 and course_status(users.bob, cid) == 403, "tenant suspension to take effect", interval=0.02)
        record_timing("propagation", "tenant suspended -> all members denied", (time.perf_counter() - t0) * 1000)
        api("PATCH", f"/api/orgs/{q(org.id)}/unsuspend", users.master)
        wait_for(lambda: course_status(users.alice, cid) == 200, "tenant reactivation", interval=0.02)


def test_role_change_propagation_delay(users, world):
    org, cid = world["org"], world["course"]
    for _ in range(N_PROP):
        api("PATCH", f"/api/orgs/{q(org.id)}/members/{users.bob.sub}/role", org.admin, json={"role": "instructor"})
        t0 = time.perf_counter()
        wait_for(lambda: api("GET", f"/api/orgs/{q(org.id)}/courses/{q(cid)}/trace", users.bob).json()["decision"]["edit"] is True, "promotion", interval=0.02)
        record_timing("propagation", "learner -> instructor: edit granted", (time.perf_counter() - t0) * 1000)
        api("PATCH", f"/api/orgs/{q(org.id)}/members/{users.bob.sub}/role", org.admin, json={"role": "learner"})
        t0 = time.perf_counter()
        wait_for(lambda: api("GET", f"/api/orgs/{q(org.id)}/courses/{q(cid)}/trace", users.bob).json()["decision"]["edit"] is False, "demotion", interval=0.02)
        record_timing("propagation", "instructor -> learner: edit revoked", (time.perf_counter() - t0) * 1000)


def test_propagation_stays_within_budget():
    """Worker polls every 1 s, so p95 should stay under ~2.5 s. This is the effective revocation latency."""
    from conftest import _TIMINGS
    vals = [t["ms"] for t in _TIMINGS if t["group"] == "propagation"]
    if not vals:
        pytest.skip("no propagation samples were recorded (the measuring tests did not run)")
    assert len(vals) >= 4 * N_PROP
    assert _pct(vals, 95) < 2500, f"p95 revocation delay {_pct(vals, 95)} ms"
    assert max(vals) < SYNC_TIMEOUT * 1000


@pytest.mark.parametrize("label,who,path_fn,want", [
    ("allowed course read", "carol", lambda w: f"/api/courses/{q(w['course'])}", 200),
    ("denied course read (outsider)", "dave", lambda w: f"/api/courses/{q(w['course'])}", 403),
    ("identity (/api/me)", "carol", lambda w: "/api/me", 200),
    ("access trace (9 FGA checks)", "carol", lambda w: f"/api/orgs/{q(w['org'].id)}/courses/{q(w['course'])}/trace", 200),
])
def test_request_latency(users, world, label, who, path_fn, want):
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {getattr(users, who).token}"
    url = GATEWAY + path_fn(world)
    for _ in range(10):
        s.get(url, timeout=20)  # warm-up
    for _ in range(N_LAT):
        t0 = time.perf_counter()
        r = s.get(url, timeout=20)
        record_timing("latency", label, (time.perf_counter() - t0) * 1000)
        assert r.status_code == want
    vals = [t["ms"] for t in __import__("conftest")._TIMINGS if t["group"] == "latency" and t["name"] == label]
    assert _pct(vals, 95) < 1000, f"{label}: p95 {_pct(vals, 95)} ms"
