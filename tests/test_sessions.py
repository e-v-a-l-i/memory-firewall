"""M3 acceptance-criteria tests for T2: cookie sessions, one sub-session per
arm (CLAUDE.md §3 "Sessions are keyed by cookie; reset clears them", §10.1
"two cookies never share memory; reset clears everything").

Contract under test (none of this exists yet as of M3's red state):

- `app.SESSION_COOKIE == "mf_sid"`.
- `app._session_id(request)` reads that cookie and returns it only if it
  matches `^[A-Za-z0-9_-]{16,64}$`; anything else (missing, too short, too
  long, containing characters outside that set) reads as absent (`None`).
- `app._new_session_id()` returns `secrets.token_urlsafe(16)`.
- `GET /` sets the cookie (httponly, samesite=lax) when the incoming
  request has none valid; a request that already carries a valid one is
  not re-issued a new one.
- `app._arm_session(sid, arm)` returns `f"{sid}#undefended"` or
  `f"{sid}#defended"` -- the actual row key used in `store`'s `memory`
  table, so the two arms of one visitor never share memory even though
  they share one browser cookie.
- No route accepts a session id supplied by the client (query string or
  otherwise) in place of the cookie-derived one.

`app` today (M2) has none of `SESSION_COOKIE`, `_session_id`,
`_new_session_id`, `_arm_session`, or any cookie-setting behavior on `GET
/`. Every test below is expected to fail with AttributeError on a missing
name, or a plain assertion failure (no Set-Cookie header at all) -- not an
import error or a fixture bug.
"""
import re

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

import app
import store

SID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


def _client() -> TestClient:
    return TestClient(app.app)


def _make_request(cookie_header: str | None) -> Request:
    """A bare starlette Request carrying only a Cookie header, for testing
    `app._session_id` directly without going through a full HTTP round
    trip."""
    headers = []
    if cookie_header is not None:
        headers.append((b"cookie", cookie_header.encode()))
    scope = {"type": "http", "headers": headers, "method": "GET", "path": "/"}
    return Request(scope)


# =============================================================================
# AC1 -- GET / issues mf_sid when absent; does not re-issue when present.
# =============================================================================


def test_t2_1_get_root_with_no_cookie_sets_mf_sid_matching_the_pattern():
    """AC1: a first GET / with no cookie at all sets `mf_sid` in the
    response, matching `^[A-Za-z0-9_-]{16,64}$`."""
    client = _client()
    r = client.get("/")
    assert r.status_code == 200

    sid = client.cookies.get(app.SESSION_COOKIE)
    assert sid, f"GET / did not set the {app.SESSION_COOKIE!r} cookie"
    assert SID_RE.match(sid), f"{sid!r} does not match {SID_RE.pattern}"


def test_t2_1b_a_second_get_root_carrying_the_cookie_does_not_reissue_it():
    """AC1: once a client carries a valid `mf_sid`, a subsequent GET / does
    not send a new Set-Cookie -- the session is stable across requests."""
    client = _client()
    client.get("/")
    sid_before = client.cookies.get(app.SESSION_COOKIE)
    assert sid_before

    r2 = client.get("/")
    assert r2.status_code == 200
    assert r2.headers.get("set-cookie") is None, (
        "GET / re-issued a cookie even though a valid one was already present: "
        f"{r2.headers.get('set-cookie')!r}"
    )
    assert client.cookies.get(app.SESSION_COOKIE) == sid_before


def test_t2_1c_cookie_is_httponly_and_samesite_lax():
    """AC1: the Set-Cookie header for `mf_sid` carries HttpOnly and
    SameSite=Lax -- a session id is not something client JS should read,
    and the cookie should not ride along on cross-site requests."""
    client = _client()
    r = client.get("/")
    raw = r.headers.get("set-cookie", "")
    assert app.SESSION_COOKIE in raw
    assert "httponly" in raw.lower()
    assert "samesite=lax" in raw.lower()


# =============================================================================
# AC2 -- an invalid incoming cookie value is replaced, and never reaches
# the store.
# =============================================================================


@pytest.mark.parametrize(
    "bad_value",
    ["../../etc", "x" * 500, "short", "!!!!!!!!!!!!!!!!"],
    ids=["path-traversal-shaped", "too-long", "too-short", "bad-charset"],
)
def test_t2_2_invalid_incoming_cookie_is_replaced_with_a_fresh_valid_id(bad_value):
    """AC2: a request carrying an `mf_sid` that fails the pattern (too
    short, too long, or outside the allowed charset -- including
    `../../etc`, a path-traversal-shaped value) is treated as absent: the
    response issues a fresh, valid session id, never the bad value."""
    client = _client()
    client.cookies.set(app.SESSION_COOKIE, bad_value)

    r = client.get("/")
    assert r.status_code == 200

    raw = r.headers.get("set-cookie")
    assert raw is not None, (
        f"an invalid incoming cookie ({bad_value!r}) must trigger a fresh Set-Cookie"
    )
    match = re.search(rf"{re.escape(app.SESSION_COOKIE)}=([^;]+)", raw)
    assert match, f"Set-Cookie header did not carry {app.SESSION_COOKIE!r}: {raw!r}"
    issued = match.group(1)
    assert SID_RE.match(issued), f"issued id {issued!r} does not match {SID_RE.pattern}"
    assert issued != bad_value


def test_t2_2b_session_id_helper_treats_invalid_or_missing_cookies_as_absent():
    """AC2 (direct unit test of `_session_id`): a valid cookie round-trips
    unchanged; each invalid shape (bad charset, too short, too long) and a
    missing Cookie header all resolve to `None`, so a caller downstream can
    never receive `../../etc` or similar as if it were a real session id."""
    good = "A" * 20
    assert app._session_id(_make_request(f"{app.SESSION_COOKIE}={good}")) == good

    for bad in ["../../etc", "x" * 500, "short", "!!!!!!!!!!!!!!!!"]:
        req = _make_request(f"{app.SESSION_COOKIE}={bad}")
        assert app._session_id(req) is None, f"{bad!r} should read as absent, not as a session id"

    assert app._session_id(_make_request(None)) is None


def test_t2_2c_new_session_id_uses_secrets_token_urlsafe_16():
    """AC2 support: `_new_session_id()` produces ids matching the same
    pattern GET / issues, via `secrets.token_urlsafe(16)` -- URL-safe
    base64 of 16 random bytes, ~22 characters, well inside [16, 64]."""
    ids = {app._new_session_id() for _ in range(20)}
    assert len(ids) == 20, "two calls returned the same id -- not actually random"
    for sid in ids:
        assert SID_RE.match(sid), f"{sid!r} does not match {SID_RE.pattern}"


# =============================================================================
# AC3 -- _arm_session differs per arm, shares the base id's prefix.
# =============================================================================


def test_t2_3_arm_session_differs_per_arm_and_both_start_with_the_base_id():
    sid = "abcdefghij0123456789"
    undefended = app._arm_session(sid, "undefended")
    defended = app._arm_session(sid, "defended")

    assert undefended != defended
    assert undefended.startswith(sid)
    assert defended.startswith(sid)
    assert undefended == f"{sid}#undefended"
    assert defended == f"{sid}#defended"


# =============================================================================
# AC4 -- two cookie jars, two sessions, memory never crosses.
# =============================================================================


def test_t2_4_running_s2_undefended_isolates_memory_between_two_cookie_jars():
    """AC4: two separate TestClients (each its own cookie jar, standing in
    for two browsers) each run S2 undefended, then GET /api/memory -- each
    sees only the record its own run wrote."""
    client_a = _client()
    client_b = _client()
    client_a.get("/")
    client_b.get("/")

    params = {"scenario": "S2", "arm": "undefended", "stage": 1, "mode": "mock"}
    r_a = client_a.get("/api/run", params=params)
    r_b = client_b.get("/api/run", params=params)
    assert r_a.status_code == 200
    assert r_b.status_code == 200

    mem_a = client_a.get("/api/memory").json()
    mem_b = client_b.get("/api/memory").json()
    ids_a = {rec["id"] for rec in mem_a["undefended"]}
    ids_b = {rec["id"] for rec in mem_b["undefended"]}

    assert ids_a, "session A should have written a memory record from S2 undefended"
    assert ids_b, "session B should have written a memory record from S2 undefended"
    assert ids_a.isdisjoint(ids_b), f"sessions shared memory records: {ids_a & ids_b}"


# =============================================================================
# AC5 -- a client-supplied session_id query param is ignored everywhere.
# =============================================================================


def test_t2_5_session_id_query_param_is_ignored_by_the_memory_route():
    """AC5: passing `?session_id=<other session's id>` to /api/memory
    returns the CALLER's own data, not the named session's -- no route
    accepts a session id from the client."""
    client_a = _client()
    client_b = _client()
    client_a.get("/")
    client_b.get("/")
    sid_a = client_a.cookies.get(app.SESSION_COOKIE)
    sid_b = client_b.cookies.get(app.SESSION_COOKIE)
    assert sid_a and sid_b and sid_a != sid_b

    conn = app.get_db()
    rec_a = store.save_memory(
        conn, app._arm_session(sid_a, "undefended"), "belongs to session A", tier="quarantine"
    )
    rec_b = store.save_memory(
        conn, app._arm_session(sid_b, "undefended"), "belongs to session B", tier="quarantine"
    )

    # client_a tries to read client_b's memory by naming it in the query string.
    r = client_a.get("/api/memory", params={"session_id": sid_b})
    assert r.status_code == 200
    ids = {rec["id"] for rec in r.json()["undefended"]}
    assert rec_a.id in ids, "the route should still return the caller's own record"
    assert rec_b.id not in ids, (
        "GET /api/memory honoured a client-supplied session_id and leaked another "
        "session's record"
    )
