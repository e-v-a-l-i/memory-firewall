"""M3 acceptance-criteria tests for T5: quarantine/approve/reject/reset
routes (CLAUDE.md §5 D2 "The UI shows quarantined items with approve and
reject buttons", §6 "the quarantine panel, and a reset button", §10.1 "D2:
... approve and reject work").

None of `GET /api/memory`, `POST /api/memory/{id}/approve`,
`POST /api/memory/{id}/reject`, or `POST /api/reset` exist yet as of M3's
red state. Every test below is expected to fail with a 404 (missing route)
-- not an import error or a fixture bug.

Contract under test:

- `GET /api/memory` -> `{"undefended": [...], "defended": [...]}`, each
  record shaped `{id, tier, status, content, trust, provenance,
  created_at}` (`session_id` is NOT exposed -- it would leak the other
  arm's row key).
- `POST /api/memory/{record_id}/approve` and `.../reject` call
  `store.approve|reject(conn, record_id, session_id=<derived arm
  session>)`. The JSON body supplies only `{"arm": "undefended" |
  "defended"}` (the two literal values, nothing else); the session id
  itself is always derived from the caller's own cookie, never from the
  request.
- `POST /api/reset` calls `store.reset_session` for both of the caller's
  arm sessions -- NOT `app.reset_db()` (which would be a process-wide
  corpus rebuild affecting every visitor, per D-033/§3's "reset clears
  them" being per-session).
"""
import json

from fastapi.testclient import TestClient

import app


def _client() -> TestClient:
    return TestClient(app.app)


def _last_event(response) -> dict:
    blocks = [b for b in response.text.strip("\n").split("\n\n") if b.strip()]
    last = blocks[-1]
    data_line = next(line for line in last.splitlines() if line.startswith("data:"))
    return json.loads(data_line[len("data:") :].strip())


def _run_s2_stage1_defended_with_d2(client: TestClient):
    client.get("/")
    r = client.get(
        "/api/run",
        params={"scenario": "S2", "arm": "defended", "stage": 1, "mode": "mock", "d2": "1"},
    )
    assert r.status_code == 200
    return r


# =============================================================================
# AC1 -- quarantine shows up in the defended arm only.
# =============================================================================


def test_t5_1_s2_stage1_defended_with_d2_quarantines_into_the_defended_arm_only():
    client = _client()
    _run_s2_stage1_defended_with_d2(client)

    mem = client.get("/api/memory").json()
    assert set(mem.keys()) == {"undefended", "defended"}
    assert mem["undefended"] == [], "nothing ran in the undefended arm"
    assert len(mem["defended"]) == 1, f"expected one quarantined record, got {mem['defended']}"

    record = mem["defended"][0]
    for key in ("id", "tier", "status", "content", "trust", "provenance", "created_at"):
        assert key in record, f"memory record missing {key!r}: {record}"
    assert record["tier"] == "quarantine"


# =============================================================================
# AC2 -- approve promotes and stage 2 recalls it.
# =============================================================================


def test_t5_2_approving_a_quarantined_record_lets_stage_2_recall_it():
    client = _client()
    _run_s2_stage1_defended_with_d2(client)
    record_id = client.get("/api/memory").json()["defended"][0]["id"]

    r = client.post(f"/api/memory/{record_id}/approve", json={"arm": "defended"})
    assert r.status_code == 200

    mem = client.get("/api/memory").json()
    approved = next(rec for rec in mem["defended"] if rec["id"] == record_id)
    assert approved["tier"] == "long_term"
    assert approved["status"] == "approved"

    r2 = client.get(
        "/api/run",
        params={"scenario": "S2", "arm": "defended", "stage": 2, "mode": "mock", "d2": "1"},
    )
    assert r2.status_code == 200
    outcome = _last_event(r2)["outcome"]
    assert outcome["attacker_goal_achieved"] is True, (
        "stage 2 should recall the now-approved fact and close ALR-1002 as benign"
    )


# =============================================================================
# AC3 -- reject leaves it unrecalled.
# =============================================================================


def test_t5_3_rejecting_a_quarantined_record_keeps_it_unrecalled_by_stage_2():
    client = _client()
    _run_s2_stage1_defended_with_d2(client)
    record_id = client.get("/api/memory").json()["defended"][0]["id"]

    r = client.post(f"/api/memory/{record_id}/reject", json={"arm": "defended"})
    assert r.status_code == 200

    mem = client.get("/api/memory").json()
    rejected = next(rec for rec in mem["defended"] if rec["id"] == record_id)
    assert rejected["tier"] == "quarantine"
    assert rejected["status"] == "rejected"

    r2 = client.get(
        "/api/run",
        params={"scenario": "S2", "arm": "defended", "stage": 2, "mode": "mock", "d2": "1"},
    )
    assert r2.status_code == 200
    outcome = _last_event(r2)["outcome"]
    assert outcome["attacker_goal_achieved"] is False, (
        "stage 2 must not recall a rejected fact"
    )


# =============================================================================
# AC4 -- cross-session approve is a no-op.
# =============================================================================


def test_t5_4_cross_session_approve_is_404_and_leaves_the_owning_records_untouched():
    client_a = _client()
    client_b = _client()
    client_b.get("/")

    _run_s2_stage1_defended_with_d2(client_a)
    record_id = client_a.get("/api/memory").json()["defended"][0]["id"]

    r = client_b.post(f"/api/memory/{record_id}/approve", json={"arm": "defended"})
    assert r.status_code == 404, (
        "approving another session's record id must 404, not silently succeed"
    )

    still = client_a.get("/api/memory").json()["defended"][0]
    assert still["id"] == record_id
    assert still["tier"] == "quarantine"
    assert still["status"] == "active"


# =============================================================================
# AC5 -- /api/reset scopes to the caller, doesn't rebuild the corpus.
# =============================================================================


def test_t5_5_reset_clears_both_arms_for_the_caller_leaves_others_alone_no_corpus_rebuild():
    client_a = _client()
    client_b = _client()
    client_a.get("/")
    client_b.get("/")

    client_a.get(
        "/api/run", params={"scenario": "S2", "arm": "undefended", "stage": 1, "mode": "mock"}
    )
    _run_s2_stage1_defended_with_d2(client_a)
    client_b.get(
        "/api/run", params={"scenario": "S2", "arm": "undefended", "stage": 1, "mode": "mock"}
    )

    conn_before = app.get_db()
    chunk_count_before = conn_before.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]

    r = client_a.post("/api/reset")
    assert r.status_code == 200

    mem_a = client_a.get("/api/memory").json()
    assert mem_a["undefended"] == []
    assert mem_a["defended"] == []

    mem_b = client_b.get("/api/memory").json()
    assert mem_b["undefended"], "session B's memory must survive session A's reset"

    conn_after = app.get_db()
    chunk_count_after = conn_after.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
    assert chunk_count_after == chunk_count_before, (
        "/api/reset must not rebuild the corpus (that is app.reset_db(), a different, "
        "process-wide operation)"
    )


# =============================================================================
# AC6 -- approving a nonexistent id is 404, not 500.
# =============================================================================


def test_t5_6_approving_a_nonexistent_record_id_is_404_not_500():
    client = _client()
    client.get("/")
    r = client.post("/api/memory/mem-doesnotexist/approve", json={"arm": "undefended"})
    assert r.status_code == 404


def test_t5_6b_rejecting_a_nonexistent_record_id_is_404_not_500():
    client = _client()
    client.get("/")
    r = client.post("/api/memory/mem-doesnotexist/reject", json={"arm": "undefended"})
    assert r.status_code == 404
