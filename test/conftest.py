"""
Shared test infrastructure for the multi-tenant IAM suite.

Architecture rules this suite follows (and why):

1. State is changed ONLY through the gateway API. No direct OpenFGA writes and no SQL writes
   (one clearly marked white-box test excepted). The outbox is part of the system under test;
   bypassing it hides exactly the bugs worth finding.
2. OpenFGA and Postgres are READ-ONLY oracles: used to prove the two stores agree, never to arrange state.
3. Tests wait by polling an observable condition (wait_for), never by sleeping a fixed time.
4. Logins use the real authorization-code + PKCE flow, so the suite keeps working after direct grants are disabled.
5. Every module creates its own uniquely named tenants, so runs are repeatable on a dirty stack.
6. Known gaps are strict xfail: they pass the suite today and FAIL the moment someone fixes the gap,
   forcing the marker (and the report) to be updated.
"""
import base64
import hashlib
import json
import os
import secrets
import statistics
import time
import uuid
from types import SimpleNamespace
from urllib.parse import parse_qs, quote, urlparse

import psycopg2
import pytest
import requests
from bs4 import BeautifulSoup

GATEWAY = os.getenv("GATEWAY_URL", "http://localhost:3000")
KC = os.getenv("KEYCLOAK_URL", "http://localhost:8081")
REALM = os.getenv("KEYCLOAK_REALM", "dat")
CLIENT_ID = os.getenv("KC_CLIENT_ID", "web-app")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:3000/login.html")
FGA_URL = os.getenv("FGA_API_URL", "http://localhost:8080")
DB_URL = os.getenv("DATABASE_URL", "postgres://dat:dat@localhost:5432/dat")
KC_ADMIN_USER = os.getenv("KC_ADMIN_USER", "admin")
KC_ADMIN_PASSWORD = os.getenv("KC_ADMIN_PASSWORD", "adminpassword")
PASSWORD = os.getenv("TEST_PASSWORD", "password")
SYNC_TIMEOUT = float(os.getenv("SYNC_TIMEOUT_S", "20"))

RUN = uuid.uuid4().hex[:6]
SUBS = {
    "master": "super-admin-000",
    "alice": "alice-sub-123",
    "bob": "bob-sub-456",
    "carol": "carol-sub-789",
    "dave": "dave-sub-012",
}
ROLES = ("admin", "instructor", "learner")
GLOBAL_ROLES = {"tenant-user", "tenant-admin", "platform-admin"}

known_gap = lambda why: pytest.mark.xfail(reason="KNOWN GAP: " + why, strict=True)  # noqa: E731
whitebox = pytest.mark.whitebox


def q(value: str) -> str:
    return quote(value, safe="")


# ---------------------------------------------------------------- polling
def wait_for(predicate, desc, timeout=SYNC_TIMEOUT, interval=0.05):
    """Poll until predicate() is truthy. Returns elapsed seconds. Fails with a clear message on timeout."""
    t0 = time.perf_counter()
    last_err = None
    while time.perf_counter() - t0 < timeout:
        try:
            if predicate():
                return time.perf_counter() - t0
        except Exception as e:  # transient errors while the system settles
            last_err = e
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout}s waiting for: {desc}" + (f" (last error: {last_err})" if last_err else ""))


# ---------------------------------------------------------------- PKCE / OIDC
def pkce_pair():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode().rstrip("=")
    return verifier, challenge


def _like_a_browser_on_localhost(session):
    """Keycloak marks its cookies Secure even over http. Browsers still accept them on localhost; `requests` would not send them back."""
    for c in session.cookies:
        c.secure = False


def start_auth(session, challenge=None, method="S256", redirect_uri=REDIRECT_URI, state=None, response_type="code"):
    params = {"client_id": CLIENT_ID, "response_type": response_type, "scope": "openid", "redirect_uri": redirect_uri,
              "state": state or secrets.token_urlsafe(8)}
    if challenge:
        params["code_challenge"] = challenge
    if method and challenge:
        params["code_challenge_method"] = method
    elif method == "S256-without-challenge":
        params["code_challenge_method"] = "S256"
    resp = session.get(f"{KC}/realms/{REALM}/protocol/openid-connect/auth", params=params, allow_redirects=False, timeout=15)
    _like_a_browser_on_localhost(session)
    return resp


def submit_login(session, resp, username, password=PASSWORD):
    """Submit the Keycloak login form found in resp. Returns the response, or resp itself if there is no form."""
    soup = BeautifulSoup(resp.text, "html.parser")
    form = soup.find("form", id="kc-form-login")
    if form is None:
        return resp
    _like_a_browser_on_localhost(session)
    return session.post(form["action"].replace("&amp;", "&"), data={"username": username, "password": password, "credentialId": ""},
                        allow_redirects=False, timeout=15)


def location_params(resp):
    loc = resp.headers.get("Location", "")
    u = urlparse(loc)
    return {**parse_qs(u.query), **parse_qs(u.fragment)}, loc


def get_auth_code(username, challenge, redirect_uri=REDIRECT_URI, method="S256"):
    s = requests.Session()
    r = start_auth(s, challenge=challenge, method=method, redirect_uri=redirect_uri)
    r = submit_login(s, r, username)
    params, loc = location_params(r)
    return (params.get("code") or [None])[0], r, loc


def exchange_code(code, verifier=None, redirect_uri=REDIRECT_URI):
    data = {"grant_type": "authorization_code", "client_id": CLIENT_ID, "code": code, "redirect_uri": redirect_uri}
    if verifier is not None:
        data["code_verifier"] = verifier
    return requests.post(f"{KC}/realms/{REALM}/protocol/openid-connect/token", data=data, timeout=15)


def decode_claims(token):
    p = token.split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))


class User:
    """A signed-in user. The token is transparently renewed (a new PKCE login) when it is about to expire."""

    def __init__(self, name, token, expires_in):
        self.name, self.sub, self._token = name, SUBS[name], token
        self.expires_at = time.time() + expires_in - 30

    @property
    def token(self):
        if time.time() > self.expires_at:
            fresh = login(self.name, fresh=True)
            self._token, self.expires_at = fresh._token, fresh.expires_at
        return self._token

    @property
    def claims(self):
        return decode_claims(self.token)


_login_cache = {}


def login(name, fresh=False):
    """Real authorization-code + PKCE login. Cached per user for the token lifetime unless fresh=True."""
    cached = _login_cache.get(name)
    if cached and not fresh and cached.expires_at > time.time():
        return cached
    verifier, challenge = pkce_pair()
    code, resp, loc = get_auth_code(name, challenge)
    assert code, f"login for {name} produced no code: {resp.status_code} {loc}"
    tr = exchange_code(code, verifier)
    assert tr.status_code == 200, f"token exchange failed for {name}: {tr.status_code} {tr.text}"
    body = tr.json()
    user = User(name, body["access_token"], body.get("expires_in", 300))
    if not fresh:
        _login_cache[name] = user
    return user


# ---------------------------------------------------------------- gateway helpers
def api(method, path, who=None, **kw):
    headers = kw.pop("headers", {})
    if who is not None:
        headers["Authorization"] = f"Bearer {who.token if isinstance(who, User) else who}"
    return requests.request(method, GATEWAY + path, headers=headers, timeout=20, **kw)


def overview(user, org_id):
    r = api("GET", f"/api/orgs/{q(org_id)}/overview", user)
    return r.json() if r.status_code == 200 else {}


class Org:
    def __init__(self, org_id, admin):
        self.id, self.admin = org_id, admin
        self.slug = org_id.split(":", 1)[1]
        self.courses = []


_counter = [0]


def new_slug(prefix):
    _counter[0] += 1
    return f"{prefix}-{RUN}-{_counter[0]}"


def make_org(master, admin, prefix="t"):
    slug = new_slug(prefix)
    org_id = f"organization:{slug}"
    r = api("POST", "/api/orgs", master, json={"org_id": org_id, "name": f"Test {slug}", "domain": f"{slug}.test", "admin_sub": admin.sub})
    assert r.status_code == 201, f"provision failed: {r.status_code} {r.text}"
    wait_for(lambda: overview(admin, org_id).get("me", {}).get("role") == "admin", f"{admin.name} to become effective admin of {slug}")
    return Org(org_id, admin)


def add_member(org, member, role):
    r = api("POST", f"/api/orgs/{q(org.id)}/memberships", org.admin, json={"user_sub": member.sub, "role": role})
    assert r.status_code == 201, f"add member failed: {r.status_code} {r.text}"
    wait_for(lambda: overview(member, org.id).get("me", {}).get("role") == role, f"{member.name} to become effective {role} in {org.slug}")


def make_course(org, name="c"):
    cid = f"course:{org.slug}-{name}"
    r = api("POST", "/api/courses", org.admin, json={"course_id": cid, "org_id": org.id, "title": f"Course {name}"})
    assert r.status_code == 201, f"create course failed: {r.status_code} {r.text}"
    wait_for(lambda: api("GET", f"/api/courses/{q(cid)}", org.admin).status_code == 200, f"course {cid} to be readable by its admin")
    org.courses.append(cid)
    return cid


def course_status(user, course_id):
    return api("GET", f"/api/courses/{q(course_id)}", user).status_code


def trace(user, org_id, course_id):
    return api("GET", f"/api/orgs/{q(org_id)}/courses/{q(course_id)}/trace", user)


# ---------------------------------------------------------------- read-only oracles
_store = {}


def fga_store_id():
    if "id" not in _store:
        env = os.getenv("FGA_STORE_ID")
        if env:
            _store["id"] = env
        else:
            stores = requests.get(f"{FGA_URL}/stores", timeout=10).json().get("stores", [])
            stores = [s for s in stores if s["name"] == "multitenant-iam"] or stores
            _store["id"] = sorted(stores, key=lambda s: s["created_at"])[-1]["id"]
    return _store["id"]


def fga_has(user, relation, obj):
    """Read-only OpenFGA Check, used as an oracle only."""
    r = requests.post(f"{FGA_URL}/stores/{fga_store_id()}/check", json={"tuple_key": {"user": user, "relation": relation, "object": obj}}, timeout=10)
    assert r.status_code == 200, r.text
    return r.json()["allowed"]


def fga_tuples(obj):
    """Read-only: every tuple stored for an object, as (user, relation) pairs. Unlike Check, it tolerates odd user strings."""
    r = requests.post(f"{FGA_URL}/stores/{fga_store_id()}/read", json={"tuple_key": {"object": obj}, "page_size": 100}, timeout=10)
    assert r.status_code == 200, r.text
    return {(t["key"]["user"], t["key"]["relation"]) for t in r.json().get("tuples", [])}


def db_rows(sql, params=()):
    """Read-only SQL oracle."""
    conn = psycopg2.connect(DB_URL)
    try:
        conn.set_session(readonly=True, autocommit=True)
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()
    finally:
        conn.close()


def outbox_pending(org_id=None):
    if org_id:
        return db_rows("SELECT count(*) FROM outbox_events WHERE processed = FALSE AND payload->>'object' = %s", (org_id,))[0][0]
    return db_rows("SELECT count(*) FROM outbox_events WHERE processed = FALSE")[0][0]


# ---------------------------------------------------------------- keycloak admin (used only to build negative fixtures)
def kc_admin_token():
    r = requests.post(f"{KC}/realms/master/protocol/openid-connect/token", timeout=15,
                      data={"grant_type": "password", "client_id": "admin-cli", "username": KC_ADMIN_USER, "password": KC_ADMIN_PASSWORD})
    if r.status_code != 200:
        pytest.skip(f"Keycloak admin API unavailable ({r.status_code}); set KC_ADMIN_USER / KC_ADMIN_PASSWORD")
    return r.json()["access_token"]


# ---------------------------------------------------------------- fixtures
def _diagnose():
    """Return a list of human-readable problems with the running stack (empty list = healthy)."""
    try:
        g = requests.get(f"{GATEWAY}/api/me", timeout=10)
    except Exception as e:
        return [f"Gateway not reachable at {GATEWAY} ({type(e).__name__}). Is `docker compose up` finished and the gateway container running?"]
    if g.status_code != 401:
        return [f"Gateway answered {g.status_code} to an unauthenticated /api/me; expected 401."]
    try:
        master = login("master", fresh=True)
    except Exception as e:
        return [f"Cannot sign in through Keycloak at {KC} (realm {REALM}): {e}"]
    r = api("GET", "/api/me", master)
    if r.status_code == 200:
        return []
    notes = [f"GET /api/me as the platform admin returned {r.status_code} {r.text[:120]} (should be 200). Every other test depends on it."]
    try:
        stores = requests.get(f"{FGA_URL}/stores", timeout=10).json().get("stores", [])
    except Exception as e:
        return notes + [f"OpenFGA is not reachable at {FGA_URL} ({type(e).__name__}); the gateway cannot evaluate permissions."]
    if not stores:
        notes.append("OpenFGA has NO stores. It uses the in-memory datastore, so a restart wipes every store and tuple, while the gateway keeps the old FGA_STORE_ID "
                     "and fails every permission check. openfga-init and seed only run on `up`, never on a plain restart.")
    else:
        _store.clear()
        try:
            super_ok = fga_has("user:super-admin-000", "super_admin", "platform:root")
        except Exception as e:
            super_ok, _ = False, notes.append(f"Check against store {fga_store_id()} failed: {e}")
        if not super_ok:
            notes.append(f"OpenFGA has {len(stores)} store(s) but the seed tuple (super-admin-000 super_admin platform:root) is missing, so the seed job did not run against the current store.")
        else:
            notes.append(f"OpenFGA has {len(stores)} store(s) and the seed tuple exists in the newest, so the gateway is probably bound to an older store id.")
    try:
        missing = [t for t in ("organizations", "user_profiles", "tenant_memberships", "outbox_events", "audit_logs") if not db_rows("SELECT to_regclass(%s)", (t,))[0][0]]
        if missing:
            notes.append(f"Postgres is missing tables: {', '.join(missing)} (init.sql did not run).")
    except Exception as e:
        notes.append(f"Postgres not reachable with DATABASE_URL ({type(e).__name__}).")
    notes.append("FIX: `docker compose down` then `docker compose up -d` (a plain `restart` is not enough because openfga-init/seed must rerun). "
                 "Tenants created before the wipe stay in Postgres but have no OpenFGA tuples (there is no reconcile job); use `docker compose down -v` for a clean slate. "
                 "Set SKIP_PREFLIGHT=1 to bypass this check.")
    return notes


@pytest.fixture(scope="session", autouse=True)
def preflight():
    if os.getenv("SKIP_PREFLIGHT"):
        return
    notes = _diagnose()
    if notes:
        pytest.exit("PRE-FLIGHT FAILED: the stack is not healthy, so no test was run.\n  - " + "\n  - ".join(notes), returncode=3)


@pytest.fixture(scope="session")
def users():
    ns = {n: login(n) for n in SUBS}
    for u in ns.values():  # first sign-in creates the profile row the API needs before a user can be added
        assert api("GET", "/api/me", u).status_code == 200
    return SimpleNamespace(**ns)


@pytest.fixture(scope="session")
def timings():
    return _TIMINGS


# ---------------------------------------------------------------- results recording
_TIMINGS = []
_OUTCOMES = []


def record_timing(group, name, ms):
    _TIMINGS.append({"group": group, "name": name, "ms": round(ms, 1)})


def _pct(vals, p):
    s = sorted(vals)
    return round(s[min(len(s) - 1, max(0, int(round(p / 100 * len(s) + 0.4999)) - 1))], 1)


def pytest_configure(config):
    config.addinivalue_line("markers", "whitebox: writes to the database directly because the API offers no way to do it")


def pytest_runtest_logreport(report):
    if report.when == "call" or (report.when == "setup" and report.outcome != "passed"):
        _OUTCOMES.append({"test": report.nodeid, "outcome": "xfailed" if hasattr(report, "wasxfail") and report.skipped else
                          ("xpassed" if hasattr(report, "wasxfail") and report.passed else report.outcome),
                          "seconds": round(report.duration, 3), "reason": getattr(report, "wasxfail", "")})


def pytest_sessionfinish(session, exitstatus):
    if not _OUTCOMES:  # collect-only or an empty selection must not clobber the last real results
        return
    out = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(out, exist_ok=True)
    counts = {}
    for o in _OUTCOMES:
        counts[o["outcome"]] = counts.get(o["outcome"], 0) + 1
    groups = {}
    for t in _TIMINGS:
        groups.setdefault((t["group"], t["name"]), []).append(t["ms"])
    summary = {"run_id": RUN, "date": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "gateway": GATEWAY, "counts": counts, "total": len(_OUTCOMES),
               "timings": [{"group": g, "name": n, "n": len(v), "p50": _pct(v, 50), "p95": _pct(v, 95), "max": max(v), "mean": round(statistics.mean(v), 1)}
                           for (g, n), v in groups.items()]}
    with open(os.path.join(out, "results.json"), "w") as f:
        json.dump({"summary": summary, "tests": _OUTCOMES, "samples": _TIMINGS}, f, indent=2)
    passed, failed = counts.get("passed", 0), counts.get("failed", 0) + counts.get("error", 0)
    xf = counts.get("xfailed", 0)
    md = [f"# Test results (run {RUN}, {summary['date']})", "",
          f"**{passed} passed, {failed} failed, {xf} known gaps confirmed (xfail), {counts.get('xpassed', 0)} gaps unexpectedly fixed (xpass), {counts.get('skipped', 0)} skipped** out of {len(_OUTCOMES)}.", "",
          "Pass rate over the acceptance tests (excluding known-gap tests): "
          f"{passed}/{passed + failed + counts.get('xpassed', 0)} = {round(100 * passed / max(1, passed + failed + counts.get('xpassed', 0)), 1)}%", "",
          "## Timings (ms)", "", "| Group | Measurement | n | p50 | p95 | max |", "| --- | --- | --- | --- | --- | --- |"]
    md += [f"| {t['group']} | {t['name']} | {t['n']} | {t['p50']} | {t['p95']} | {t['max']} |" for t in summary["timings"]]
    md += ["", "## Known gaps confirmed", ""] + [f"- `{o['test'].split('::')[-1]}`: {o['reason']}" for o in _OUTCOMES if o["outcome"] == "xfailed"]
    with open(os.path.join(out, "results.md"), "w") as f:
        f.write("\n".join(md) + "\n")
