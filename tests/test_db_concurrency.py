"""M3 acceptance-criteria tests for T1: a per-connection DB over a WAL file
(CLAUDE.md §2 "SQLite ... DB built at startup from data/", §7 "Cloud Run:
--max-instances 1 so in-memory sessions stay consistent" -- M3 puts this
behind real HTTP concurrency for the first time via SSE, D-033).

Contract under test (none of this exists yet as of M3's red state):

- `store.build_db` sets `PRAGMA journal_mode=WAL` on the connection it
  returns, when given a real file path (WAL is meaningless for `:memory:`).
- `app.get_db()` builds the corpus exactly once, guarded by a
  `threading.Lock`, into `os.environ.get("DB_PATH")` or a tempdir path, and
  returns a FRESH `sqlite3.connect(path)` on every call, with
  `PRAGMA busy_timeout=10000` set on that fresh connection.
- `app.reset_db()` clears the "already built" flag and unlinks the file it
  built.

`app.py` today (M2) builds a single `:memory:` connection once and hands out
the *same* connection object forever (`_DB` global). Every test below is
expected to fail against that implementation: AttributeError on missing
PRAGMA behavior, or straightforward assertion failures (`conn1 is conn2`,
`journal_mode != "wal"`, no `DB_PATH` file ever created) -- not import
errors or fixture bugs.

The M1 `_isolate_app_db` autouse fixture (tests/conftest.py) already calls
`app.reset_db()` before and after every test, so tests here don't need to
manage that themselves beyond what each AC specifically exercises.
"""
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import app
import clients
import store

REPO_ROOT = Path(__file__).resolve().parent.parent

NO_DEFENSES = {"D1": False, "D2": False, "D3": False}


# =============================================================================
# store.build_db sets WAL mode (a prerequisite for T1's whole design: WAL is
# what lets one writer and several readers share a single on-disk file
# without SQLITE_BUSY under normal load).
# =============================================================================


def test_t1_0_build_db_on_a_real_file_sets_wal_journal_mode(tmp_path):
    """T1: `store.build_db(path)` against a real file sets
    `PRAGMA journal_mode=WAL`. (WAL doesn't apply to `:memory:`, so this
    needs an actual file path -- unlike every other `build_db(":memory:")`
    call in the existing suite.)"""
    db_path = tmp_path / "corpus.sqlite3"
    conn = store.build_db(str(db_path))
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert str(mode).lower() == "wal", f"journal_mode is {mode!r}, expected 'wal'"
    finally:
        conn.close()


# =============================================================================
# T1 AC1 -- four threads, no conn= argument, all reach done cleanly, one
# memory record per session.
# =============================================================================


def test_t1_1_four_concurrent_run_scenario_calls_with_no_conn_arg_each_reach_done_cleanly():
    """T1 AC1: four threads each call `app.run_scenario("S2",
    MockClient(gullible=True), defenses=all-off, session_id=f"t{n}")` with
    NO `conn=` argument (so each goes through `app.get_db()` internally).
    All four must reach a "done" event, raise no sqlite3.InterfaceError or
    sqlite3.OperationalError, and each session ends with exactly one memory
    record (S2 stage 1's gullible save_memory call)."""
    n_threads = 4
    results: dict[str, list[dict]] = {}
    errors: dict[str, BaseException] = {}
    lock = threading.Lock()

    def worker(i: int) -> None:
        sid = f"t1-conc-{i}"
        try:
            events = app.run_scenario(
                "S2",
                clients.MockClient(gullible=True),
                defenses=dict(NO_DEFENSES),
                session_id=sid,
            )
        except BaseException as exc:  # noqa: BLE001 - captured for the assertion below
            with lock:
                errors[sid] = exc
            return
        with lock:
            results[sid] = events

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
        assert not t.is_alive(), "a worker thread did not finish within 30s"

    assert not errors, f"threads raised exceptions: {errors}"
    assert len(results) == n_threads

    for sid, events in results.items():
        assert events, f"{sid} produced no events at all"
        assert events[-1]["type"] == "done", f"{sid} did not end on done: {events[-1]}"

    conn = app.get_db()
    for sid in results:
        count = conn.execute(
            "SELECT COUNT(*) FROM memory WHERE session_id = ?", (sid,)
        ).fetchone()[0]
        assert count == 1, f"{sid} has {count} memory records, expected exactly 1"


# =============================================================================
# T1 AC2 -- distinct connection objects, shared committed state.
# =============================================================================


def test_t1_2_two_get_db_calls_return_distinct_connections_that_see_each_others_writes():
    """T1 AC2: two `app.get_db()` calls return distinct connection objects
    (not the same cached `sqlite3.Connection`), and a write committed
    through one is visible to a read through the other -- i.e. both point
    at the same underlying file, not two independent in-memory DBs."""
    conn1 = app.get_db()
    conn2 = app.get_db()
    assert conn1 is not conn2, "get_db() must return a fresh connection every call"

    record1 = store.save_memory(conn1, "t1-visibility", "written via conn1", tier="long_term")
    row = conn2.execute(
        "SELECT content FROM memory WHERE id = ?", (record1.id,)
    ).fetchone()
    assert row is not None, "conn2 cannot see a row committed through conn1"
    assert row[0] == "written via conn1"

    record2 = store.save_memory(conn2, "t1-visibility", "written via conn2", tier="long_term")
    row2 = conn1.execute(
        "SELECT content FROM memory WHERE id = ?", (record2.id,)
    ).fetchone()
    assert row2 is not None, "conn1 cannot see a row committed through conn2"
    assert row2[0] == "written via conn2"


def test_t1_2b_get_db_sets_busy_timeout_10000_on_every_fresh_connection():
    """T1: every connection `get_db()` hands out carries
    `PRAGMA busy_timeout=10000`, so a writer contending with WAL's single
    writer waits instead of raising `database is locked` immediately."""
    for _ in range(3):
        conn = app.get_db()
        timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert timeout == 10000, f"busy_timeout is {timeout!r}, expected 10000"


# =============================================================================
# T1 AC3 -- reset_db() then get_db() matches a fresh build; prior memory
# is gone.
# =============================================================================


def test_t1_3_reset_db_then_get_db_matches_a_fresh_build_and_drops_prior_memory():
    """T1 AC3: after `reset_db()`, the next `get_db()` yields a corpus with
    the same chunk count as a fresh `store.build_db(":memory:")`, and any
    memory rows written before the reset are gone."""
    conn = app.get_db()
    store.save_memory(conn, "t1-reset-check", "should not survive reset_db", tier="long_term")

    app.reset_db()
    rebuilt = app.get_db()

    reference = store.build_db(":memory:")
    try:
        expected_count = reference.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
    finally:
        reference.close()
    actual_count = rebuilt.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
    assert actual_count > 0
    assert actual_count == expected_count

    leftover = rebuilt.execute(
        "SELECT COUNT(*) FROM memory WHERE session_id = ?", ("t1-reset-check",)
    ).fetchone()[0]
    assert leftover == 0, "reset_db() must drop memory rows written before it ran"


def test_t1_3b_db_path_env_var_controls_where_the_corpus_file_is_built(tmp_path, monkeypatch):
    """T1: `app.get_db()` builds into `os.environ.get("DB_PATH")` when set,
    rather than always defaulting to a tempdir path chosen internally."""
    target = tmp_path / "custom_corpus.sqlite3"
    monkeypatch.setenv("DB_PATH", str(target))
    app.reset_db()
    try:
        app.get_db()
        assert target.exists(), "get_db() did not build the corpus at DB_PATH"
    finally:
        app.reset_db()
        monkeypatch.delenv("DB_PATH", raising=False)
        app.reset_db()


def test_t1_3c_reset_db_unlinks_the_corpus_file(tmp_path, monkeypatch):
    """T1: `app.reset_db()` unlinks the file it built, not just the cached
    flag/connection -- a stray corpus file left behind after a rebuild
    would let a later `get_db()` silently attach to stale data."""
    target = tmp_path / "corpus_to_unlink.sqlite3"
    monkeypatch.setenv("DB_PATH", str(target))
    app.reset_db()
    try:
        app.get_db()
        assert target.exists()
        app.reset_db()
        assert not target.exists(), "reset_db() should have unlinked the corpus file"
    finally:
        monkeypatch.delenv("DB_PATH", raising=False)
        app.reset_db()


# =============================================================================
# T1 AC4 -- the M0 import-time guard (tests/test_health.py) still passes
# against whatever file-backed get_db()/reset_db() implementation lands.
# =============================================================================


def test_t1_4_import_time_guard_regression_still_passes():
    """T1 AC4: re-runs
    tests/test_health.py::test_import_app_with_no_env_has_no_import_time_side_effects
    as its own process. A `get_db()` rewritten around `DB_PATH` and a
    `threading.Lock` must still build nothing at import time -- the DB stays
    lazy, built on first `get_db()` call, exactly as before."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests/test_health.py::test_import_app_with_no_env_has_no_import_time_side_effects",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        "the M0 import-time guard regressed under the T1 DB changes:\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )


# T1 AC5 ("all 310 existing tests still pass") is not a unit test in this
# file -- it is verified by running the full suite (`.venv/bin/pytest -q`)
# after implementation, as reported by the test-engineer/main session, the
# same way D-006c's guard is verified by the suite as a whole rather than
# by a test that shells out to pytest recursively over itself.
