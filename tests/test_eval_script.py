"""Tests for `scripts/eval.py` (CLAUDE.md §10.4, D-035).

The eval itself is not CI — it calls a real model. What is testable, and
worth testing, is that the script measures the right thing: the right
scenarios, the right defended arm, isolated runs, and the honesty notes that
§10.4 requires. A reporting script that quietly drops an inconvenient result
is worse than no script.
"""
import importlib.util
import socket
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
EVAL_PATH = REPO_ROOT / "scripts" / "eval.py"


@pytest.fixture(scope="module")
def evalmod():
    spec = importlib.util.spec_from_file_location("eval_script", EVAL_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["eval_script"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("the eval script attempted a network connection in dry-run")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)


def test_defended_arm_is_d1_only(evalmod):
    """D-035, asserted on the code rather than on the prose that explains it."""
    assert evalmod.ARMS["D1"] == {"D1": True, "D2": False, "D3": False}
    assert evalmod.ARMS["undefended"] == {"D1": False, "D2": False, "D3": False}
    assert set(evalmod.ARMS) == {"undefended", "D1"}


def test_scope_is_the_three_canonical_scenarios(evalmod):
    """The 19 red-teamer variants are CI regression fixtures, not eval
    material: they would multiply spend without telling us anything about
    model behaviour that the three canonical attacks do not."""
    assert evalmod.SCENARIOS == ("S1", "S2", "S3")


def test_dry_run_writes_a_table_and_touches_no_network(evalmod, tmp_path):
    out = tmp_path / "eval.md"
    assert evalmod.main(["--dry-run", "--runs", "2", "--out", str(out)]) == 0

    body = out.read_text()
    assert "| Scenario | Arm | Stage |" in body
    rows = [
        line for line in body.splitlines()
        if line.startswith("| S") and not line.startswith("| Scenario")
    ]
    assert rows, "no result rows"
    # S1 and S3 are single-stage, S2 has two -> 2 arms x (1 + 2 + 1) stages.
    assert len(rows) == 8, f"expected 8 rows, got {len(rows)}:\n" + "\n".join(rows)
    assert "D2" not in body.split("| Scenario")[1] or "D1 only" in body


def test_no_row_reports_d2_or_d3_as_an_arm(evalmod, tmp_path):
    out = tmp_path / "eval.md"
    evalmod.main(["--dry-run", "--runs", "1", "--out", str(out)])
    for line in out.read_text().splitlines():
        if line.startswith("| S") and not line.startswith("| Scenario"):
            arm = line.split("|")[2].strip()
            assert arm in {"undefended", "D1"}, f"unexpected arm in results: {arm!r}"


def test_runs_are_isolated_from_each_other(evalmod, monkeypatch):
    """Each run gets its own session and database, or S2's poisoned memory
    leaks between runs and the rate measures contagion, not the attack."""
    seen_sessions = []
    real_run = evalmod.app.run_scenario

    def spy(scenario_id, client, **kwargs):
        seen_sessions.append(kwargs.get("session_id"))
        return real_run(scenario_id, client, **kwargs)

    monkeypatch.setattr(evalmod.app, "run_scenario", spy)
    evalmod.run_cell("S2", evalmod.UNDEFENDED, runs=3, dry_run=True)

    # S2 runs two stages per run; both stages share a session (that IS the
    # attack), but no two runs may.
    bases = {s.split("#")[0] for s in seen_sessions}
    assert len(bases) == 3, f"runs shared a session: {seen_sessions!r}"


def test_a_resisted_scenario_gets_the_honesty_note(evalmod, tmp_path, monkeypatch):
    """§10.4: if the model resists with no defense on, say so and keep the
    scenario. A table that silently showed 0/3 with no explanation would read
    as a broken fixture rather than as a finding."""
    def all_failures(scenario_id, defenses, runs, dry_run):
        return {"stage1": [False] * runs, "stage2": [], "tokens": [10] * runs,
                "traces": [], "errors": 0}

    monkeypatch.setattr(evalmod, "run_cell", all_failures)
    out = tmp_path / "eval.md"
    evalmod.main(["--dry-run", "--runs", "3", "--out", str(out), "--scenarios", "S1"])

    body = out.read_text()
    assert evalmod.RESISTED_NOTE in body


def test_a_successful_undefended_cell_gets_no_honesty_note(evalmod, tmp_path, monkeypatch):
    def all_successes(scenario_id, defenses, runs, dry_run):
        return {"stage1": [True] * runs, "stage2": [], "tokens": [10] * runs,
                "traces": [], "errors": 0}

    monkeypatch.setattr(evalmod, "run_cell", all_successes)
    out = tmp_path / "eval.md"
    evalmod.main(["--dry-run", "--runs", "3", "--out", str(out), "--scenarios", "S1"])
    assert evalmod.RESISTED_NOTE not in out.read_text()


def test_d1_not_helping_is_reported_rather_than_hidden(evalmod, tmp_path, monkeypatch):
    """The inverse case: D1 failing to reduce the rate is a result, not an
    embarrassment to omit."""
    def same_rate(scenario_id, defenses, runs, dry_run):
        return {"stage1": [True] * runs, "stage2": [], "tokens": [10] * runs,
                "traces": [], "errors": 0}

    monkeypatch.setattr(evalmod, "run_cell", same_rate)
    out = tmp_path / "eval.md"
    evalmod.main(["--dry-run", "--runs", "2", "--out", str(out), "--scenarios", "S1"])
    assert evalmod.INVERTED_NOTE in out.read_text()


def test_recorded_replays_match_the_replay_schema(evalmod, tmp_path, monkeypatch):
    """`--record` output must load in ReplayClient, or the recording step
    produces files the demo cannot use."""
    import clients

    monkeypatch.chdir(tmp_path)
    (tmp_path / "replays").mkdir()
    out = tmp_path / "replays" / "eval.md"
    evalmod.main(["--dry-run", "--runs", "1", "--record", "--out", str(out),
                  "--scenarios", "S1"])

    written = sorted((tmp_path / "replays").glob("*.json"))
    assert written, "--record wrote no replay files"
    for path in written:
        scenario, arm, stage = path.stem.split("_")
        client = clients.ReplayClient(scenario, arm, int(stage.replace("stage", "")),
                                      dir=tmp_path / "replays")
        assert client.name == "replay"
        completion = client.complete(system="s", messages=[], tools=[])
        assert completion.stop_reason in {"tool_use", "end_turn", "max_tokens"}
