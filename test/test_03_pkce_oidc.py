"""
Type 3: web authorization-code + PKCE login, callback matching, issuer/audience enforcement.

Your original file used the password grant with an unused code_verifier, which proves nothing about PKCE.
Here every positive and negative case runs the REAL browser flow: authorize -> login form -> code -> token exchange.
"""
import base64
import hashlib
import hmac
import json
import time

import pytest
import requests

from conftest import (CLIENT_ID, GATEWAY, KC, KC_ADMIN_PASSWORD, PASSWORD, REALM, REDIRECT_URI, RUN, SUBS, api, decode_claims, exchange_code,
                      get_auth_code, kc_admin_token, known_gap, location_params, login, pkce_pair, start_auth, submit_login)


# ------------------------------------------------------------- positive path
def test_real_pkce_flow_yields_a_token_the_gateway_accepts():
    verifier, challenge = pkce_pair()
    code, resp, loc = get_auth_code("dave", challenge)
    assert code, f"no code issued: {resp.status_code} {loc}"
    tr = exchange_code(code, verifier)
    assert tr.status_code == 200, tr.text
    me = api("GET", "/api/me", tr.json()["access_token"])
    assert me.status_code == 200 and me.json()["user"]["sub"] == SUBS["dave"]


# ------------------------------------------------------------- PKCE negatives (all use a REAL code)
def test_wrong_verifier_is_rejected_for_a_real_code():
    verifier, challenge = pkce_pair()
    code, *_ = get_auth_code("dave", challenge)
    tr = exchange_code(code, pkce_pair()[0])
    assert tr.status_code == 400 and tr.json()["error"] == "invalid_grant"


def test_missing_verifier_is_rejected_for_a_challenge_bound_code():
    _, challenge = pkce_pair()
    code, *_ = get_auth_code("dave", challenge)
    tr = exchange_code(code, None)
    assert tr.status_code == 400 and tr.json()["error"] == "invalid_grant"


def test_authorization_request_without_code_challenge_issues_no_code():
    s = requests.Session()
    r = start_auth(s, challenge=None, method=None)
    r = submit_login(s, r, "dave")
    params, loc = location_params(r)
    assert "code" not in params, f"code issued without PKCE: {loc}"


def test_plain_challenge_method_is_refused():
    verifier, _ = pkce_pair()
    code, resp, loc = get_auth_code("dave", verifier, method="plain")  # plain: challenge == verifier
    assert code is None, f"client enforces S256 but plain produced a code: {loc}"


def test_authorization_code_cannot_be_replayed():
    verifier, challenge = pkce_pair()
    code, *_ = get_auth_code("dave", challenge)
    assert exchange_code(code, verifier).status_code == 200
    second = exchange_code(code, verifier)
    assert second.status_code == 400 and second.json()["error"] == "invalid_grant"


def test_code_is_bound_to_the_redirect_uri_used_at_authorization():
    verifier, challenge = pkce_pair()
    code, *_ = get_auth_code("dave", challenge, redirect_uri=REDIRECT_URI)
    tr = exchange_code(code, verifier, redirect_uri="http://localhost:3000/dashboard.html")
    assert tr.status_code == 400 and tr.json()["error"] == "invalid_grant"


def test_implicit_flow_is_disabled():
    s = requests.Session()
    r = start_auth(s, challenge=None, method=None, response_type="token")
    r = submit_login(s, r, "dave")
    params, loc = location_params(r)
    assert "access_token" not in params, f"implicit flow returned a token: {loc}"


# ------------------------------------------------------------- callback matching
def test_foreign_host_redirect_uri_is_rejected():
    _, challenge = pkce_pair()
    r = start_auth(requests.Session(), challenge=challenge, redirect_uri="http://evil.example/cb")
    assert r.status_code == 400 and "kc-form-login" not in r.text


@known_gap("realm registers the wildcard http://localhost:3000/*, so any path on the app origin is an accepted callback (requirement: exact match)")
def test_same_origin_unregistered_path_is_rejected():
    _, challenge = pkce_pair()
    r = start_auth(requests.Session(), challenge=challenge, redirect_uri="http://localhost:3000/evil-stealer.html")
    assert r.status_code == 400 and "kc-form-login" not in r.text


# ------------------------------------------------------------- issuer / audience
def test_token_issuer_is_the_configured_realm_and_authorized_party_is_the_client():
    claims = login("dave", fresh=True).claims
    assert claims["iss"] == f"{KC}/realms/{REALM}"
    assert claims["azp"] == CLIENT_ID


@pytest.fixture
def rogue_realm_token():
    """A correctly signed token minted by a DIFFERENT realm, for a user named like Alice (Keycloak user ids are unique across realms, so the sub differs)."""
    admin = kc_admin_token()
    h = {"Authorization": f"Bearer {admin}"}
    name = f"rogue-{RUN}"
    body = {"realm": name, "enabled": True, "sslRequired": "none",
            "users": [{"username": "mallory", "enabled": True, "email": "alice@acme.edu", "emailVerified": True, "firstName": "Mal", "lastName": "Lory",
                       "credentials": [{"type": "password", "value": PASSWORD, "temporary": False}]}],
            "clients": [{"clientId": CLIENT_ID, "publicClient": True, "directAccessGrantsEnabled": True, "enabled": True}]}
    assert requests.post(f"{KC}/admin/realms", json=body, headers=h, timeout=30).status_code == 201
    try:
        r = requests.post(f"{KC}/realms/{name}/protocol/openid-connect/token", timeout=15,
                          data={"grant_type": "password", "client_id": CLIENT_ID, "username": "mallory", "password": PASSWORD, "scope": "openid"})
        assert r.status_code == 200, r.text
        yield r.json()["access_token"]
    finally:
        requests.delete(f"{KC}/admin/realms/{name}", headers=h, timeout=30)


def test_gateway_rejects_a_valid_token_from_another_realm(rogue_realm_token):
    claims = decode_claims(rogue_realm_token)
    assert claims["iss"].endswith(f"/realms/rogue-{RUN}") and claims["email"] == "alice@acme.edu"
    assert api("GET", "/api/me", rogue_realm_token).status_code == 401


def _b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def test_gateway_rejects_alg_none_and_hs256_forgeries():
    claims = {"sub": SUBS["master"], "iss": f"{KC}/realms/{REALM}", "azp": CLIENT_ID, "exp": int(time.time()) + 600, "iat": int(time.time())}
    none_tok = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(claims)}."
    h = f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64(claims)}"
    hs_tok = h + "." + base64.urlsafe_b64encode(hmac.new(b"guess", h.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    for tok in (none_tok, hs_tok):
        assert api("GET", "/api/me", tok).status_code == 401


@known_gap("gateway verifies the signature only; it never checks aud/azp, so a token minted for ANY client in the realm is accepted")
def test_gateway_rejects_a_token_issued_to_a_different_client():
    admin = kc_admin_token()
    h = {"Authorization": f"Bearer {admin}"}
    cid = f"other-app-{RUN}"
    assert requests.post(f"{KC}/admin/realms/{REALM}/clients", headers=h, timeout=15,
                         json={"clientId": cid, "publicClient": True, "directAccessGrantsEnabled": True, "enabled": True}).status_code == 201
    try:
        r = requests.post(f"{KC}/realms/{REALM}/protocol/openid-connect/token", timeout=15,
                          data={"grant_type": "password", "client_id": cid, "username": "dave", "password": PASSWORD, "scope": "openid"})
        assert r.status_code == 200, r.text
        assert api("GET", "/api/me", r.json()["access_token"]).status_code in (401, 403)
    finally:
        cl = requests.get(f"{KC}/admin/realms/{REALM}/clients", params={"clientId": cid}, headers=h, timeout=15).json()
        if cl:
            requests.delete(f"{KC}/admin/realms/{REALM}/clients/{cl[0]['id']}", headers=h, timeout=15)


@known_gap("web-app is a public client with directAccessGrantsEnabled=true, so the password grant bypasses PKCE entirely")
def test_password_grant_is_disabled_on_the_public_client():
    r = requests.post(f"{KC}/realms/{REALM}/protocol/openid-connect/token", timeout=15,
                      data={"grant_type": "password", "client_id": CLIENT_ID, "username": "dave", "password": PASSWORD, "scope": "openid"})
    assert r.status_code in (400, 401)
