"""M1 acceptance-criteria tests for `store.py` (CLAUDE.md §10.1: retrieval,
memory tiers, sessions).

`store.py` does not exist yet as of M1's red state, so every test here is
expected to fail with ModuleNotFoundError until the main session adds it.

Contract under test (see the approved M1 interface, `CLAUDE.md` §3):

    @dataclass(frozen=True)
    class Chunk: id: str; text: str; source: str; trust: str; doc_type: str; score: float
    @dataclass
    class MemoryRecord: id, session_id, tier, content, provenance: list[str], trust,
                         status, created_at

    build_db(path) -> conn
    search(conn, query, limit=5) -> list[Chunk]
    save_memory(conn, session_id, content, provenance, tier="long_term") -> MemoryRecord
    recall_memory(conn, session_id) -> list[MemoryRecord]
    approve(conn, rec_id) / reject(conn, rec_id) / reset_session(conn, session_id)

Criteria encoded here (CLAUDE.md §10.1):
  AC-STORE-1 - build_db creates `chunks`, `chunks_fts` (an FTS5 virtual
               table), and `memory`.
  AC-STORE-2 - build_db is idempotent: calling it twice against the same
               path does not duplicate rows.
  AC-STORE-3 - search returns <= limit Chunks, ordered by descending score.
  AC-STORE-4 - every search result has non-empty id/text/source and trust in
               {"internal", "attacker_controllable"}.
  AC-STORE-5 - a term unique to the injected user-agent returns chunk id
               "log:evt-00042:user_agent" with trust "attacker_controllable".
  AC-STORE-6 - a no-match query returns [].
  AC-STORE-7 - non-listed fields (e.g. src_ip) produce "internal" chunks.
  AC-STORE-8 - FTS5 special syntax in a query does not raise.
  AC-STORE-9  - save_memory returns a fully populated record with an
                ISO-8601 created_at.
  AC-STORE-10 - recall_memory returns only long_term records with status in
                {active, approved}; a quarantine record is never returned.
  AC-STORE-11 - approve() makes a quarantine record appear in recall_memory;
                reject() means it never does.
  AC-STORE-12 - two sessions never share memory.
  AC-STORE-13 - reset_session(A) deletes A's records and leaves B's count
                unchanged.
"""
import re
import sqlite3
from datetime import datetime

import pytest

import store


# --- helpers ----------------------------------------------------------------


def _build(tmp_path, name="kb.db"):
    return store.build_db(str(tmp_path / name))


def _table_names(conn):
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
    ).fetchall()
    return {r[0] for r in rows}


_STOPWORDS = {
    "the", "and", "that", "this", "with", "from", "your", "have", "will",
    "https", "http", "www", "user", "agent", "please", "system",
}


def _candidate_terms(text, min_len=5, max_candidates=8):
    """Distinctive-looking words from `text`, longest first, stopwords out."""
    words = re.findall(r"[A-Za-z]{%d,}" % min_len, text)
    uniq = sorted(set(words), key=len, reverse=True)
    out = [w for w in uniq if w.lower() not in _STOPWORDS]
    return out[:max_candidates]


def _sample_terms(conn, min_len=4, scan=50):
    """Distinctive terms from the first chunk that actually contains words.

    Not every chunk is prose -- a `ts` or `dest_port` field is all digits and
    yields no candidate terms. Scanning for a text-bearing chunk keeps these
    tests about search behaviour rather than about which field happens to sort
    first in the corpus.
    """
    rows = conn.execute("SELECT text FROM chunks LIMIT ?", (scan,)).fetchall()
    for (text,) in rows:
        terms = _candidate_terms(text, min_len=min_len)
        if terms:
            return terms
    raise AssertionError(
        f"no chunk in the first {scan} rows yielded a usable search term"
    )


# --- AC-STORE-1: schema ------------------------------------------------------


def test_build_db_creates_chunks_chunks_fts_and_memory_tables(tmp_path):
    """AC-STORE-1: build_db creates `chunks`, an FTS5 `chunks_fts`, and
    `memory`."""
    conn = _build(tmp_path)
    names = _table_names(conn)
    assert "chunks" in names
    assert "chunks_fts" in names
    assert "memory" in names

    fts_sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE name = 'chunks_fts'"
    ).fetchone()[0]
    assert "fts5" in fts_sql.lower(), (
        f"chunks_fts is not declared as an FTS5 virtual table: {fts_sql!r}"
    )


# --- AC-STORE-2: idempotency --------------------------------------------------


def test_build_db_is_idempotent(tmp_path):
    """AC-STORE-2: calling build_db twice against the same path does not
    duplicate rows in `chunks`."""
    db_path = tmp_path / "kb.db"

    conn1 = store.build_db(str(db_path))
    count1 = conn1.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
    conn1.close()

    assert count1 > 0, "build_db produced no chunks from data/ on first call"

    conn2 = store.build_db(str(db_path))
    count2 = conn2.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]

    assert count2 == count1, (
        f"build_db duplicated rows on a second call against the same path: "
        f"{count1} -> {count2}"
    )


# --- chunk id shape -----------------------------------------------------------


def test_all_chunk_ids_follow_doc_type_doc_id_field_format(tmp_path):
    """Chunk ids are documented as `doc_type:doc_id:field`, e.g.
    'log:evt-00042:user_agent'."""
    conn = _build(tmp_path)
    ids = [r[0] for r in conn.execute("SELECT id FROM chunks LIMIT 200")]
    assert ids
    for cid in ids:
        parts = cid.split(":")
        assert len(parts) == 3, f"chunk id {cid!r} is not doc_type:doc_id:field"
        assert all(parts), f"chunk id {cid!r} has an empty segment"


# --- AC-STORE-3: search ordering and limit ------------------------------------


def test_search_respects_limit_and_orders_by_descending_score(tmp_path):
    """AC-STORE-3: search returns <= limit Chunks, ordered by descending
    score."""
    conn = _build(tmp_path)
    terms = _sample_terms(conn)

    results = store.search(conn, terms[0], limit=3)
    assert len(results) <= 3
    scores = [c.score for c in results]
    assert scores == sorted(scores, reverse=True)


def test_search_default_limit_is_five(tmp_path):
    """search(conn, query) with no explicit limit defaults to 5."""
    conn = _build(tmp_path)
    terms = _sample_terms(conn)
    results = store.search(conn, terms[0])
    assert len(results) <= 5


# --- AC-STORE-4: result field / trust invariants ------------------------------


_ALLOWED_TRUST = {"internal", "attacker_controllable"}


def test_every_search_result_has_required_fields_and_allowed_trust(tmp_path):
    """AC-STORE-4: every search result has non-empty id/text/source and
    trust drawn from the allowed set (§10.1)."""
    conn = _build(tmp_path)
    terms = _sample_terms(conn)

    results = store.search(conn, terms[0], limit=10)
    assert results, "expected at least one search hit to check fields on"
    for c in results:
        assert isinstance(c, store.Chunk)
        assert c.id
        assert c.text
        assert c.source
        assert c.trust in _ALLOWED_TRUST
        assert isinstance(c.score, (int, float))


# --- AC-STORE-5: the S1 injection is retrievable and tagged correctly --------


def test_evt00042_user_agent_chunk_exists_with_attacker_controllable_trust(
    tmp_path,
):
    """Data fact: log record evt-00042 has a user_agent field carrying the
    S1 injection text, and it must be tagged attacker_controllable."""
    conn = _build(tmp_path)
    row = conn.execute(
        "SELECT trust, source, text FROM chunks WHERE id = ?",
        ("log:evt-00042:user_agent",),
    ).fetchone()
    assert row is not None, (
        "expected chunk id 'log:evt-00042:user_agent' in the chunks table"
    )
    trust, source, text = row
    assert trust == "attacker_controllable"
    assert source
    assert text


def test_search_finds_injected_user_agent_chunk_by_distinctive_term(
    tmp_path, s1_scenario
):
    """AC-STORE-5: a term unique to the injected user-agent returns chunk id
    'log:evt-00042:user_agent' with trust attacker_controllable.

    Derives the search term from the S1 scenario's own injection payload
    rather than hardcoding it, so this stays correct regardless of exactly
    how the payload is worded.
    """
    conn = _build(tmp_path)
    payload = s1_scenario["injection"]["payload"]
    candidates = _candidate_terms(payload)
    assert candidates, "S1 injection payload had no distinctive search terms"

    found = None
    for term in candidates:
        results = store.search(conn, term, limit=5)
        match = next(
            (c for c in results if c.id == "log:evt-00042:user_agent"), None
        )
        if match is not None:
            found = match
            break

    assert found is not None, (
        f"none of the candidate terms {candidates!r} (from the S1 injection "
        "payload) retrieved chunk id 'log:evt-00042:user_agent' via search()"
    )
    assert found.trust == "attacker_controllable"


# --- AC-STORE-6: no-match query -----------------------------------------------


def test_search_no_match_returns_empty_list(tmp_path):
    """AC-STORE-6: a query with no matches returns []."""
    conn = _build(tmp_path)
    results = store.search(conn, "zzzznonexistentqueryxyzzy999", limit=5)
    assert results == []


# --- AC-STORE-7: unlisted fields default to internal --------------------------


def test_unlisted_fields_like_src_ip_are_internal(tmp_path):
    """AC-STORE-7: fields not listed in trust_map.yaml (e.g. src_ip) default
    to internal trust."""
    conn = _build(tmp_path)
    rows = conn.execute(
        "SELECT id, trust FROM chunks WHERE id LIKE '%:src_ip'"
    ).fetchall()
    assert rows, "expected at least one ':src_ip' chunk to check the default"
    for cid, trust in rows:
        assert trust == "internal", f"{cid} should default to internal trust"


# --- AC-STORE-8: FTS5 special syntax doesn't raise ----------------------------


@pytest.mark.parametrize(
    "raw_query",
    [
        '"',
        "*",
        'NEAR(foo bar)',
        'foo" OR 1=1 --',
        'foo*bar"unterminated',
        "()",
        '""""',
        "AND OR NOT",
    ],
)
def test_search_fts5_special_syntax_does_not_raise(tmp_path, raw_query):
    """AC-STORE-8: FTS5 special syntax in a query does not raise."""
    conn = _build(tmp_path)
    results = store.search(conn, raw_query, limit=5)
    assert isinstance(results, list)


# --- AC-STORE-9: save_memory populates a full record --------------------------


def test_save_memory_returns_fully_populated_record(tmp_path):
    """AC-STORE-9: save_memory returns a fully populated record with an
    ISO-8601 created_at."""
    conn = _build(tmp_path)
    rec = store.save_memory(
        conn,
        session_id="sess-a",
        content="10.0.4.17 is a known scanner.",
        provenance=["log:evt-00042:user_agent"],
    )
    assert isinstance(rec, store.MemoryRecord)
    assert rec.id
    assert rec.session_id == "sess-a"
    assert rec.tier == "long_term"
    assert rec.content == "10.0.4.17 is a known scanner."
    assert rec.provenance == ["log:evt-00042:user_agent"]
    assert rec.status == "active"
    assert isinstance(rec.trust, str) and rec.trust != ""
    # Must parse as ISO-8601; datetime.fromisoformat raises ValueError on
    # anything else.
    datetime.fromisoformat(rec.created_at)


def test_save_memory_accepts_explicit_quarantine_tier(tmp_path):
    conn = _build(tmp_path)
    rec = store.save_memory(
        conn,
        session_id="sess-a",
        content="10.0.4.17 is an authorized scanner.",
        provenance=["ticket:tkt-1:comment"],
        tier="quarantine",
    )
    assert rec.tier == "quarantine"


# --- AC-STORE-10/11: memory tiers and approve/reject --------------------------


def test_recall_memory_returns_long_term_active_records(tmp_path):
    """AC-STORE-10: recall_memory returns long_term records with status
    active."""
    conn = _build(tmp_path)
    rec = store.save_memory(
        conn, session_id="sess-b", content="fact one", provenance=["log:x:y"]
    )
    recalled = store.recall_memory(conn, "sess-b")
    assert [r.id for r in recalled] == [rec.id]


def test_recall_memory_never_returns_quarantine_records(tmp_path):
    """AC-STORE-10: a quarantine record is never returned by recall_memory,
    regardless of status."""
    conn = _build(tmp_path)
    store.save_memory(
        conn,
        session_id="sess-c",
        content="unverified claim",
        provenance=["ticket:tkt-1:comment"],
        tier="quarantine",
    )
    assert store.recall_memory(conn, "sess-c") == []


def test_approve_moves_quarantine_record_into_recall(tmp_path):
    """AC-STORE-11: approve() makes a quarantined record appear in
    recall_memory."""
    conn = _build(tmp_path)
    rec = store.save_memory(
        conn,
        session_id="sess-d",
        content="10.0.4.17 is an authorized scanner.",
        provenance=["ticket:tkt-1:comment"],
        tier="quarantine",
    )
    assert store.recall_memory(conn, "sess-d") == []

    store.approve(conn, rec.id)

    recalled = store.recall_memory(conn, "sess-d")
    assert [r.id for r in recalled] == [rec.id]
    assert recalled[0].status == "approved"


def test_reject_keeps_quarantine_record_out_of_recall(tmp_path):
    """AC-STORE-11: reject() means a quarantined record never appears in
    recall_memory."""
    conn = _build(tmp_path)
    rec = store.save_memory(
        conn,
        session_id="sess-e",
        content="false claim",
        provenance=["ticket:tkt-1:comment"],
        tier="quarantine",
    )
    store.reject(conn, rec.id)
    assert store.recall_memory(conn, "sess-e") == []


# --- AC-STORE-12: session isolation -------------------------------------------


def test_sessions_never_share_memory(tmp_path):
    """AC-STORE-12: two sessions never share memory."""
    conn = _build(tmp_path)
    store.save_memory(
        conn, session_id="sess-A", content="A's fact", provenance=["log:x:y"]
    )
    store.save_memory(
        conn, session_id="sess-B", content="B's fact", provenance=["log:x:y"]
    )

    a_contents = {r.content for r in store.recall_memory(conn, "sess-A")}
    b_contents = {r.content for r in store.recall_memory(conn, "sess-B")}

    assert a_contents == {"A's fact"}
    assert b_contents == {"B's fact"}


# --- AC-STORE-13: reset_session ------------------------------------------------


def test_reset_session_clears_only_that_session(tmp_path):
    """AC-STORE-13: reset_session(A) deletes A's records (both tiers) and
    leaves B's count unchanged."""
    conn = _build(tmp_path)
    store.save_memory(
        conn, session_id="sess-A", content="A long-term", provenance=["log:x:y"]
    )
    store.save_memory(
        conn,
        session_id="sess-A",
        content="A quarantined",
        provenance=["ticket:tkt-1:comment"],
        tier="quarantine",
    )
    store.save_memory(
        conn, session_id="sess-B", content="B long-term", provenance=["log:x:y"]
    )

    b_count_before = conn.execute(
        "SELECT COUNT(*) FROM memory WHERE session_id = ?", ("sess-B",)
    ).fetchone()[0]

    store.reset_session(conn, "sess-A")

    a_count_after = conn.execute(
        "SELECT COUNT(*) FROM memory WHERE session_id = ?", ("sess-A",)
    ).fetchone()[0]
    b_count_after = conn.execute(
        "SELECT COUNT(*) FROM memory WHERE session_id = ?", ("sess-B",)
    ).fetchone()[0]

    assert a_count_after == 0, "reset_session left rows behind for session A"
    assert store.recall_memory(conn, "sess-A") == []
    assert b_count_after == b_count_before, (
        "reset_session(A) changed session B's row count"
    )
