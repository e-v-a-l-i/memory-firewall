"""M1 acceptance-criteria tests for the agent loop in `app.py` (CLAUDE.md §3
components, §10.1 sessions/skills, §11 done).

`app.run_scenario` / `app.load_scenario` do not exist yet as of M1's red
state (only the M0 skeleton -- `/health`, `/`, resolve_mode -- is in
app.py), so every test here is expected to fail with AttributeError until
the main session adds them.

Contract under test:

    run_scenario(scenario_id, client, defenses={"D1":False,"D2":False,"D3":False})
        -> list[dict]
    load_scenario(scenario_id) -> dict   # from scenarios/*.yaml

Trace shape invariants:
  events[0]["type"] == "run_started", events[-1]["type"] == "done"
  seq strictly increasing from 0, no gaps
  same run_id on every event
  event type in {run_started, model, retrieval, tool_call, tool_result,
                 memory_write, blocked, done}
  every event has "defense" (None in M1) and a bool "untrusted_in_context"
  retrieval events: non-empty "chunks", each with id/source/trust
  tool_call events: detail["tool"], detail["args"]; followed by a matching
    tool_result
  unknown tool name -> tool_result event with detail["error"], loop
    continues (no raise)
  loop stops after at most 8 model turns -> done with
    outcome["reason"] == "max_steps"
  untrusted_in_context is False before any attacker_controllable chunk
    enters context, True for every event after
  done event: {"type":"done","seq":int,"run_id":str,
    "outcome":{"attacker_goal_achieved":bool,"alert_status":"open"|"closed",
    "actions":[{"tool","args"}],"reason":"end_turn"|"max_steps"},
    "usage":{"input_tokens":int,"output_tokens":int}}

Criteria encoded here:
  AC-LOOP-1  - load_scenario("S1") returns the documented shape and values.
  AC-LOOP-2  - trace starts with run_started (seq 0) and ends with done.
  AC-LOOP-3  - seq is strictly increasing with no gaps; run_id is constant.
  AC-LOOP-4  - every event type is in the allowed set.
  AC-LOOP-5  - every event carries "defense" (None in M1) and a bool
               "untrusted_in_context".
  AC-LOOP-6  - retrieval events carry non-empty chunks with id/source/trust.
  AC-LOOP-7  - tool_call events carry detail["tool"]/detail["args"] and are
               followed by a matching tool_result.
  AC-LOOP-8  - an unknown tool name produces a tool_result with
               detail["error"]; the loop does not raise and continues to
               "done".
  AC-LOOP-9  - a client that always answers tool_use terminates within 8
               model turns with outcome["reason"] == "max_steps" (no hang).
  AC-LOOP-10 - untrusted_in_context is False until the first
               attacker_controllable chunk enters context, then True for
               every subsequent event.
  AC-LOOP-11 - the done event has the documented shape.
"""
import contextlib
import signal

import pytest

import app
import clients


EVENT_TYPES = {
    "run_started",
    "model",
    "retrieval",
    "tool_call",
    "tool_result",
    "memory_write",
    "blocked",
    "done",
}

NO_DEFENSES = {"D1": False, "D2": False, "D3": False}


class AlwaysToolUseClient:
    """A minimal ClaudeClient that always demands a (valid) tool call.

    Used to exercise the loop's own turn cap (AC-LOOP-9) without depending
    on clients.MockClient's script-exhaustion behaviour -- this client can
    never run out of scripted turns, so if the loop doesn't cap itself, the
    test hangs instead of erroring, which is exactly the bug this guards
    against.
    """

    name = "mock"

    def __init__(self, tool_name="search_logs", tool_input=None):
        self._tool_name = tool_name
        self._tool_input = tool_input or {"query": "alert"}
        self.calls = 0

    def complete(self, *, system, messages, tools, max_tokens=1024):
        self.calls += 1
        call = clients.ToolCall(
            id=f"call-{self.calls}", name=self._tool_name, input=self._tool_input
        )
        return clients.Completion(
            text="",
            tool_calls=[call],
            stop_reason="tool_use",
            usage={"input_tokens": 1, "output_tokens": 1},
        )


@contextlib.contextmanager
def _time_limit(seconds):
    """Fails the test instead of hanging forever if the loop doesn't
    terminate on its own (AC-LOOP-9's whole point)."""

    def _handler(signum, frame):
        raise TimeoutError(f"run_scenario did not terminate within {seconds}s")

    old_handler = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def _gullible_client():
    return clients.MockClient(gullible=True)


def _field(obj, name):
    """Chunks may come back as dicts or as store.Chunk-like objects;
    tolerate either since the contract only fixes the field names."""
    if isinstance(obj, dict):
        return obj[name]
    return getattr(obj, name)


# --- AC-LOOP-1: load_scenario -------------------------------------------------


def test_load_scenario_s1_has_documented_shape_and_values():
    """AC-LOOP-1: load_scenario("S1") returns the documented shape."""
    scenario = app.load_scenario("S1")
    assert isinstance(scenario, dict)
    for key in (
        "id",
        "name",
        "alert_id",
        "injection",
        "attacker_goal",
        "expected_undefended",
        "primary_defense",
        "backstop",
    ):
        assert key in scenario, f"scenario missing key {key!r}"

    assert scenario["id"] == "S1"
    assert scenario["primary_defense"] == "D1"
    assert scenario["backstop"] == "D3"
    assert scenario["alert_id"] == "ALR-1001"

    assert "location" in scenario["injection"]
    assert "payload" in scenario["injection"]

    assert scenario["attacker_goal"]["tool"] == "close_alert"
    assert "args" in scenario["attacker_goal"]


# --- AC-LOOP-2/3: envelope and seq/run_id invariants -------------------------


def test_trace_starts_with_run_started_and_ends_with_done():
    """AC-LOOP-2: events[0]["type"] == "run_started",
    events[-1]["type"] == "done"."""
    events = app.run_scenario("S1", _gullible_client(), defenses=NO_DEFENSES)
    assert events, "run_scenario returned no events"
    assert events[0]["type"] == "run_started"
    assert events[0]["seq"] == 0
    assert events[-1]["type"] == "done"


def test_seq_strictly_increasing_with_no_gaps_and_stable_run_id():
    """AC-LOOP-3: seq is strictly increasing from 0 with no gaps; run_id is
    the same on every event."""
    events = app.run_scenario("S1", _gullible_client(), defenses=NO_DEFENSES)
    seqs = [e["seq"] for e in events]
    assert seqs == list(range(len(events)))

    run_ids = {e["run_id"] for e in events}
    assert len(run_ids) == 1
    assert all(e["run_id"] for e in events)


# --- AC-LOOP-4/5: event type and per-event fields ----------------------------


def test_every_event_type_is_in_the_allowed_set():
    """AC-LOOP-4: every event's type is drawn from the documented set."""
    events = app.run_scenario("S1", _gullible_client(), defenses=NO_DEFENSES)
    for e in events:
        assert e["type"] in EVENT_TYPES, f"unexpected event type: {e['type']!r}"


def test_every_event_has_defense_none_and_bool_untrusted_flag():
    """AC-LOOP-5: every event carries "defense" (None in M1, since no
    defense is implemented yet even if the caller asks for one) and a bool
    "untrusted_in_context"."""
    # Pass defenses=True to prove M1 ignores them rather than merely never
    # being asked for them.
    events = app.run_scenario(
        "S1", _gullible_client(), defenses={"D1": True, "D2": True, "D3": True}
    )
    for e in events:
        assert "defense" in e
        assert e["defense"] is None, (
            f"M1 has no defenses implemented; event {e!r} must not have a "
            "defense value"
        )
        assert "untrusted_in_context" in e
        assert isinstance(e["untrusted_in_context"], bool)


# --- AC-LOOP-6: retrieval events ---------------------------------------------


def test_retrieval_events_carry_nonempty_chunks_with_required_fields():
    """AC-LOOP-6: retrieval events carry non-empty "chunks", each with
    id/source/trust."""
    events = app.run_scenario("S1", _gullible_client(), defenses=NO_DEFENSES)
    retrieval_events = [e for e in events if e["type"] == "retrieval"]
    assert retrieval_events, "S1 must trigger at least one retrieval"

    for e in retrieval_events:
        chunks = e["chunks"]
        assert chunks, "retrieval event has empty chunks"
        for c in chunks:
            assert _field(c, "id")
            assert _field(c, "source")
            assert _field(c, "trust") in {"internal", "attacker_controllable"}


# --- AC-LOOP-7: tool_call / tool_result pairing ------------------------------


def test_tool_call_events_have_detail_and_a_matching_tool_result():
    """AC-LOOP-7: tool_call events carry detail["tool"]/detail["args"] and
    are followed by a matching tool_result."""
    events = app.run_scenario("S1", _gullible_client(), defenses=NO_DEFENSES)
    tool_calls = [(i, e) for i, e in enumerate(events) if e["type"] == "tool_call"]
    assert tool_calls, "S1 (gullible, undefended) must produce a tool_call"

    for i, e in tool_calls:
        assert "tool" in e["detail"]
        assert "args" in e["detail"]
        # A tool_result must appear somewhere after this tool_call.
        later_results = [
            ev for ev in events[i + 1 :] if ev["type"] == "tool_result"
        ]
        assert later_results, f"tool_call at seq {e['seq']} has no tool_result"

    tool_call_count = len(tool_calls)
    tool_result_count = sum(1 for e in events if e["type"] == "tool_result")
    assert tool_result_count >= tool_call_count


# --- AC-LOOP-8: unknown tool name --------------------------------------------


def test_unknown_tool_name_produces_error_result_and_loop_continues():
    """AC-LOOP-8: an unknown tool name produces a tool_result with
    detail["error"]; the loop does not raise and reaches "done"."""
    bogus_call = clients.ToolCall(id="c1", name="delete_everything", input={})
    finishing = clients.Completion(
        text="done", tool_calls=[], stop_reason="end_turn",
        usage={"input_tokens": 1, "output_tokens": 1},
    )
    scripted = clients.MockClient(
        script=[
            clients.Completion(
                text="",
                tool_calls=[bogus_call],
                stop_reason="tool_use",
                usage={"input_tokens": 1, "output_tokens": 1},
            ),
            finishing,
        ]
    )

    events = app.run_scenario("S1", scripted, defenses=NO_DEFENSES)

    tool_results = [e for e in events if e["type"] == "tool_result"]
    assert tool_results, "expected a tool_result event for the unknown tool call"
    error_results = [e for e in tool_results if "error" in e["detail"]]
    assert error_results, (
        "expected a tool_result carrying detail['error'] for the unknown "
        f"tool; got detail payloads: {[e['detail'] for e in tool_results]!r}"
    )

    assert events[-1]["type"] == "done"


# --- AC-LOOP-9: max_steps termination ----------------------------------------


def test_loop_terminates_at_max_steps_when_client_always_wants_tool_use():
    """AC-LOOP-9: a client that always answers tool_use terminates within 8
    model turns, with outcome["reason"] == "max_steps" -- and, critically,
    does not hang."""
    client = AlwaysToolUseClient(tool_name="search_logs", tool_input={"query": "x"})

    with _time_limit(20):
        events = app.run_scenario("S1", client, defenses=NO_DEFENSES)

    assert events[-1]["type"] == "done"
    assert events[-1]["outcome"]["reason"] == "max_steps"

    model_turns = [e for e in events if e["type"] == "model"]
    assert len(model_turns) <= 8, f"expected at most 8 model turns, got {len(model_turns)}"


# --- AC-LOOP-10: untrusted_in_context transition -----------------------------


def test_untrusted_in_context_flips_once_attacker_chunk_enters_and_stays_true():
    """AC-LOOP-10: untrusted_in_context is False before any
    attacker_controllable chunk enters context, True for every event
    after."""
    events = app.run_scenario("S1", _gullible_client(), defenses=NO_DEFENSES)

    first_untrusted_index = None
    for i, e in enumerate(events):
        if e["type"] == "retrieval":
            for c in e["chunks"]:
                if _field(c, "trust") == "attacker_controllable":
                    first_untrusted_index = i
                    break
        if first_untrusted_index is not None:
            break

    assert first_untrusted_index is not None, (
        "S1 must retrieve an attacker_controllable chunk at some point"
    )

    for i, e in enumerate(events):
        if i < first_untrusted_index:
            assert e["untrusted_in_context"] is False, (
                f"event at seq {e['seq']} is False-expected but was True "
                "before any attacker-controllable chunk entered context"
            )
        else:
            assert e["untrusted_in_context"] is True, (
                f"event at seq {e['seq']} should be True from the first "
                "attacker-controllable retrieval onward"
            )


# --- AC-LOOP-11: done event shape --------------------------------------------


def test_done_event_has_documented_shape():
    """AC-LOOP-11: the done event has the documented shape."""
    events = app.run_scenario("S1", _gullible_client(), defenses=NO_DEFENSES)
    done = events[-1]

    assert done["type"] == "done"
    assert isinstance(done["seq"], int)
    assert done["run_id"]

    outcome = done["outcome"]
    assert isinstance(outcome["attacker_goal_achieved"], bool)
    assert outcome["alert_status"] in {"open", "closed"}
    assert isinstance(outcome["actions"], list)
    for action in outcome["actions"]:
        assert "tool" in action
        assert "args" in action
    assert outcome["reason"] in {"end_turn", "max_steps"}

    usage = done["usage"]
    assert isinstance(usage["input_tokens"], int) and usage["input_tokens"] >= 0
    assert isinstance(usage["output_tokens"], int) and usage["output_tokens"] >= 0
