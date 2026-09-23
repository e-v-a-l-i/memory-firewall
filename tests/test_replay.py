"""M3 acceptance-criteria tests for T7: `clients.ReplayClient`, the replay
file schema, and `clients.FallbackClient` (CLAUDE.md §1 "Must work without
the LLM: replay mode serves recorded runs", §7 "Automatic fallback to
replay if a live call errors or times out", §10.3 "A VertexClient error or
timeout falls back to replay, and the UI says so").

None of `clients.ReplayClient`, `clients.ReplayMissing`, or
`clients.FallbackClient` exist yet as of M3's red state. Every test below
is expected to fail with AttributeError -- not an import error or a
fixture bug.

Contract under test:

- Replays record MODEL COMPLETIONS, not full traces.
  `replays/{scenario}_{arm}_stage{n}.json` (scenario lower-cased), keys
  `scenario, arm, stage, defenses, model, recorded_at, outcome,
  completions[]`; each completion is `{text, stop_reason,
  tool_calls[{id, name, input}], usage{input_tokens, output_tokens}}`.
- `clients.ReplayClient(scenario, arm, stage, dir=...)`: `name ==
  "replay"`, loads on construction, returns completions in order, and on
  exhaustion returns a graceful `Completion(stop_reason="end_turn",
  tool_calls=[])` rather than raising. Missing file -> `ReplayMissing`.
- `clients.FallbackClient(primary, fallback)`: delegates to `primary`; on
  ANY exception from `primary`, sets `.fell_back = True` and serves every
  remaining call from `fallback`. `iter_scenario` sets `detail["fallback"]`
  on `model` events from `getattr(client, "fell_back", False)`.

Fixture replay files for these tests live under
`tests/fixtures/replays/` (this test suite's own scratch fixtures) -- NOT
under a repo-root `replays/`, which stays empty until §10.4's eval
populates it for real.
"""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app
import clients

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "replays"

NO_DEFENSES = {"D1": False, "D2": False, "D3": False}


def _client() -> TestClient:
    return TestClient(app.app)


# =============================================================================
# Replay file schema validator, and AC4 (repo-root replays/*.json, which
# passes vacuously today since that directory does not exist yet).
# =============================================================================


def _validate_replay_schema(path: Path) -> None:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    assert isinstance(data, dict), f"{path}: a replay file must be a JSON object"
    required_top = {
        "scenario", "arm", "stage", "defenses", "model", "recorded_at", "outcome", "completions",
    }
    missing = required_top - set(data.keys())
    assert not missing, f"{path}: missing top-level keys {missing}"

    assert data["scenario"] == data["scenario"].lower(), (
        f"{path}: scenario id must be lower-cased ({data['scenario']!r})"
    )
    assert data["arm"] in {"undefended", "defended"}, f"{path}: bad arm {data['arm']!r}"
    assert isinstance(data["stage"], int), f"{path}: stage must be an int"
    assert isinstance(data["completions"], list) and data["completions"], (
        f"{path}: completions must be a non-empty list"
    )

    for i, completion in enumerate(data["completions"]):
        for key in ("text", "stop_reason", "tool_calls", "usage"):
            assert key in completion, f"{path}: completions[{i}] missing {key!r}"
        assert isinstance(completion["tool_calls"], list), (
            f"{path}: completions[{i}].tool_calls must be a list"
        )
        for j, call in enumerate(completion["tool_calls"]):
            for key in ("id", "name", "input"):
                assert key in call, f"{path}: completions[{i}].tool_calls[{j}] missing {key!r}"
        usage = completion["usage"]
        for key in ("input_tokens", "output_tokens"):
            assert key in usage, f"{path}: completions[{i}].usage missing {key!r}"


def test_t7_4_every_repo_root_replay_file_matches_the_schema():
    """AC4: validates every `replays/*.json` at the repo root against the
    recorded-completions schema. Passes vacuously (0 files checked) until
    the eval (§10.4, scripts/eval.py) populates `replays/` -- creating that
    directory is not this test suite's job."""
    paths = sorted(REPO_ROOT.glob("replays/*.json"))
    for path in paths:
        _validate_replay_schema(path)


def test_t7_4b_this_suites_own_fixture_replays_match_the_same_schema():
    """Sanity check on our own scratch fixtures (not one of T7's numbered
    ACs, but cheap insurance that the fixtures the other tests below load
    are themselves schema-valid)."""
    paths = sorted(FIXTURES_DIR.glob("*.json"))
    assert paths, "expected at least one fixture under tests/fixtures/replays/"
    for path in paths:
        _validate_replay_schema(path)


# =============================================================================
# AC1, AC2 -- ReplayClient playback and graceful exhaustion.
# =============================================================================


def test_t7_1_replayclient_returns_recorded_completions_in_order():
    rc = clients.ReplayClient("S3", "undefended", 1, dir=FIXTURES_DIR)
    assert rc.name == "replay"

    first = rc.complete(system="s", messages=[], tools=[], max_tokens=10)
    assert first.stop_reason == "tool_use"
    assert len(first.tool_calls) == 1
    assert first.tool_calls[0].name == "unisolate_host"
    assert first.tool_calls[0].input == {
        "host": "10.0.4.17", "reason": "false positive per KB-88213",
    }

    second = rc.complete(system="s", messages=[], tools=[], max_tokens=10)
    assert second.stop_reason == "end_turn"
    assert second.tool_calls == []
    assert "restored" in second.text


def test_t7_2_replayclient_exhaustion_returns_a_graceful_end_turn_instead_of_raising():
    rc = clients.ReplayClient("S3", "undefended", 1, dir=FIXTURES_DIR)
    rc.complete(system="s", messages=[], tools=[], max_tokens=10)
    rc.complete(system="s", messages=[], tools=[], max_tokens=10)

    third = rc.complete(system="s", messages=[], tools=[], max_tokens=10)
    assert third.stop_reason == "end_turn"
    assert third.tool_calls == []


# =============================================================================
# AC3 -- defenses stay live over a replayed run.
# =============================================================================


def test_t7_3_defenses_are_still_enforced_live_against_a_replayed_run():
    """AC3: the fixture above was 'recorded' undefended -- its scripted
    turn unconditionally calls unisolate_host. Re-running it through the
    agent loop with D3 turned on must still produce a blocked event: D3
    reads the loop's own live state (untrusted content in context), not
    anything baked into the replay file, so defenses stay live no matter
    what supplied the model's turns."""
    rc = clients.ReplayClient("S3", "undefended", 1, dir=FIXTURES_DIR)
    events = app.run_scenario(
        "S3", rc, defenses={"D1": False, "D2": False, "D3": True}, session_id="t7-replay-d3"
    )
    blocked = [e for e in events if e["type"] == "blocked"]
    assert blocked, "D3 must still fire against a replayed model turn"
    assert blocked[0]["defense"]["id"] == "D3"
    assert events[-1]["type"] == "done"


# =============================================================================
# AC5, AC6 -- FallbackClient.
# =============================================================================


class _AlwaysRaises:
    name = "flaky-primary"

    def complete(self, **kwargs):
        raise RuntimeError("primary down")


def test_t7_5_fallback_client_whose_primary_fails_on_the_first_call_completes_via_fallback():
    primary = _AlwaysRaises()
    fallback = clients.MockClient(gullible=True)
    fb_client = clients.FallbackClient(primary, fallback)

    events = app.run_scenario(
        "S1", fb_client, defenses=dict(NO_DEFENSES), session_id="t7-fallback-first"
    )

    assert events[-1]["type"] == "done"
    assert fb_client.fell_back is True

    model_events = [e for e in events if e["type"] == "model"]
    assert model_events
    assert any(e["detail"].get("fallback") is True for e in model_events), (
        "at least one model event should record detail['fallback'] is True"
    )


class _RaisesOnThirdCall:
    name = "flaky-primary"

    def __init__(self):
        self._n = 0

    def complete(self, **kwargs):
        self._n += 1
        if self._n < 3:
            return clients.Completion(
                text="",
                tool_calls=[
                    clients.ToolCall(id=f"c{self._n}", name="search_logs", input={"query": "scanner"})
                ],
                stop_reason="tool_use",
                usage={"input_tokens": 1, "output_tokens": 1},
            )
        raise RuntimeError("primary down on call 3")


def test_t7_6_fallback_client_whose_primary_fails_on_the_third_call_still_reaches_done():
    primary = _RaisesOnThirdCall()
    fallback = clients.MockClient(
        script=[
            clients.Completion(
                text="wrapping up", tool_calls=[], stop_reason="end_turn",
                usage={"input_tokens": 1, "output_tokens": 1},
            )
        ]
    )
    fb_client = clients.FallbackClient(primary, fallback)

    events = app.run_scenario(
        "S1", fb_client, defenses=dict(NO_DEFENSES), session_id="t7-fallback-third"
    )

    assert events[-1]["type"] == "done"
    assert fb_client.fell_back is True


# =============================================================================
# AC7 -- missing replay file: ReplayMissing directly, and 404 with no
# partial stream over HTTP.
# =============================================================================


def test_t7_7a_replayclient_for_a_missing_file_raises_replaymissing():
    with pytest.raises(clients.ReplayMissing):
        clients.ReplayClient("S1", "undefended", 99, dir=FIXTURES_DIR)


def test_t7_7b_replay_mode_via_http_for_a_missing_file_is_404_with_no_partial_stream():
    """The HTTP half of AC7: a recording that does not exist must 404 before
    the stream opens, not open a stream and die inside it.

    Retargeted at a scenario/stage combination that is never recorded. This
    originally used
    S1/undefended/stage1 on the premise that repo-root `replays/` is empty —
    true when it was written, and false as soon as M3 recorded the replays
    that make the demo work without a model (§1). The invariant under test is
    "missing recording → clean 404", not "the directory is empty".
    """
    client = _client()
    r = client.get(
        "/api/run",
        # S3 is single-stage, so no stage-2 recording exists or ever will.
        # (A nonexistent stage number is now a 422 from validation, which
        # tests the validator rather than the missing-recording path.)
        params={"scenario": "S3", "arm": "undefended", "stage": 2, "mode": "replay"},
    )
    assert r.status_code == 404
    assert not r.headers.get("content-type", "").startswith("text/event-stream")
    assert "event:" not in r.text


def test_t7_7c_replay_mode_streams_a_recorded_run_to_done():
    """The other half: a recording that DOES exist plays back over SSE and
    terminates. §1 requires the demo to work with no model at all."""
    client = _client()
    r = client.get(
        "/api/run",
        params={"scenario": "S1", "arm": "undefended", "stage": 1, "mode": "replay"},
    )
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("text/event-stream")
    assert "event: done" in r.text
    assert "event: retrieval" in r.text
