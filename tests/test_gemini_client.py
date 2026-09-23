"""`clients.GeminiClient` (§2 deviation, recorded as D-057).

The agent loop, the defenses and the trace must not care which provider
serves a run, so this asserts the translation in both directions against a
fake SDK — no network, no credentials.
"""
import socket
from types import SimpleNamespace

import pytest

import app
import clients


class _FakeModels:
    def __init__(self, parts, finish="STOP", usage=(11, 7)):
        self.parts = parts
        self.finish = finish
        self.usage = usage
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(
            candidates=[SimpleNamespace(
                content=SimpleNamespace(parts=self.parts),
                finish_reason=SimpleNamespace(name=self.finish),
            )],
            usage_metadata=SimpleNamespace(
                prompt_token_count=self.usage[0], candidates_token_count=self.usage[1]
            ),
        )


class _FakeSDK:
    def __init__(self, parts, finish="STOP", usage=(11, 7)):
        self.models = _FakeModels(parts, finish, usage)


def _text_part(text):
    return SimpleNamespace(text=text, function_call=None)


def _call_part(name, args, call_id=None):
    return SimpleNamespace(
        text=None, function_call=SimpleNamespace(name=name, args=args, id=call_id)
    )


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def blocked(*a, **kw):
        raise AssertionError("GeminiClient touched the network in a unit test")

    monkeypatch.setattr(socket.socket, "connect", blocked)


def test_satisfies_the_same_protocol_as_every_other_client():
    client = clients.GeminiClient(sdk=_FakeSDK([]), model="gemini-2.5-flash")
    assert isinstance(client, clients.ClaudeClient)
    assert client.name == "gemini"


def test_text_response_maps_to_end_turn():
    sdk = _FakeSDK([_text_part("no action needed")])
    completion = clients.GeminiClient(sdk=sdk, model="m").complete(
        system="s", messages=[{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
        tools=[],
    )
    assert completion.text == "no action needed"
    assert completion.tool_calls == []
    assert completion.stop_reason == "end_turn"
    assert completion.usage == {"input_tokens": 11, "output_tokens": 7}


def test_function_call_becomes_a_toolcall_and_forces_tool_use():
    """Gemini reports finish_reason STOP even when it asked for a call, so the
    calls decide the stop reason — the agent loop keys off `tool_use`, and
    reading finish_reason literally would end every run after one turn."""
    sdk = _FakeSDK([_call_part("close_alert", {"alert_id": "ALR-1001", "disposition": "benign"})],
                   finish="STOP")
    completion = clients.GeminiClient(sdk=sdk, model="m").complete(
        system="s", messages=[], tools=[]
    )
    assert completion.stop_reason == "tool_use"
    assert len(completion.tool_calls) == 1
    call = completion.tool_calls[0]
    assert call.name == "close_alert"
    assert call.input == {"alert_id": "ALR-1001", "disposition": "benign"}
    assert call.id, "a call id must be synthesised; Gemini does not return one"


def test_synthesised_call_ids_are_unique_within_a_client():
    """The loop pairs tool_use with tool_result by id, so duplicates would
    cross the wires between two calls in one run."""
    sdk = _FakeSDK([_call_part("search_logs", {"query": "a"})])
    client = clients.GeminiClient(sdk=sdk, model="m")
    first = client.complete(system="s", messages=[], tools=[]).tool_calls[0].id
    second = client.complete(system="s", messages=[], tools=[]).tool_calls[0].id
    assert first != second


def test_max_tokens_finish_reason_is_preserved():
    sdk = _FakeSDK([_text_part("truncated")], finish="MAX_TOKENS")
    completion = clients.GeminiClient(sdk=sdk, model="m").complete(
        system="s", messages=[], tools=[]
    )
    assert completion.stop_reason == "max_tokens"


def test_tool_schemas_translate_to_function_declarations():
    import skills

    loaded = skills.load_skills(app.SKILLS_DIR)
    schemas = skills.to_tool_schemas(loaded)
    sdk = _FakeSDK([_text_part("ok")])
    clients.GeminiClient(sdk=sdk, model="m").complete(
        system="s", messages=[], tools=schemas
    )

    sent = sdk.models.calls[0]["config"].tools
    declared = {d.name for tool in sent for d in tool.function_declarations}
    assert declared == {s["name"] for s in schemas}
    close_alert = next(
        d for tool in sent for d in tool.function_declarations if d.name == "close_alert"
    )
    assert "alert_id" in close_alert.parameters.properties
    assert "alert_id" in close_alert.parameters.required


def test_anthropic_blocks_translate_to_contents_including_tool_results():
    """The fiddly direction: Anthropic identifies a result by tool_use_id,
    Gemini by the function's name, so ids from earlier turns have to be
    tracked or every reply is attributed to the wrong function."""
    sdk = _FakeSDK([_text_part("ok")])
    messages = [
        {"role": "user", "content": [{"type": "text", "text": "Triage ALR-1001"}]},
        {"role": "assistant", "content": [
            {"type": "tool_use", "id": "tu-1", "name": "search_logs", "input": {"query": "x"}},
        ]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "tu-1", "content": "3 records"},
        ]},
    ]
    clients.GeminiClient(sdk=sdk, model="m").complete(system="s", messages=messages, tools=[])

    contents = sdk.models.calls[0]["contents"]
    assert [c.role for c in contents] == ["user", "model", "user"]
    assert contents[1].parts[0].function_call.name == "search_logs"
    response_part = contents[2].parts[0].function_response
    assert response_part.name == "search_logs", "the result was attributed to the wrong function"
    assert response_part.response == {"result": "3 records"}


def test_system_prompt_is_passed_as_system_instruction():
    sdk = _FakeSDK([_text_part("ok")])
    clients.GeminiClient(sdk=sdk, model="m").complete(
        system="You are a SOC analyst.", messages=[], tools=[]
    )
    assert sdk.models.calls[0]["config"].system_instruction == "You are a SOC analyst."


def test_empty_message_list_still_sends_valid_contents():
    """Gemini rejects an empty contents array; the loop must not 400 on it."""
    sdk = _FakeSDK([_text_part("ok")])
    clients.GeminiClient(sdk=sdk, model="m").complete(system="s", messages=[], tools=[])
    assert sdk.models.calls[0]["contents"], "contents must never be empty"


# --- provider selection -----------------------------------------------------


def test_provider_defaults_to_the_spec_path(monkeypatch):
    """§2 says Claude. The default stays Claude even though this deployment
    runs Gemini — the deviation is a deployment choice, not a code change."""
    monkeypatch.delenv("LIVE_PROVIDER", raising=False)
    assert app.resolve_live_provider() == "claude"


@pytest.mark.parametrize("value,expected", [
    ("gemini", "gemini"), ("GEMINI", "gemini"), (" gemini ", "gemini"),
    ("claude", "claude"), ("bogus", "claude"), ("", "claude"),
])
def test_provider_is_selected_by_env(value, expected, monkeypatch):
    monkeypatch.setenv("LIVE_PROVIDER", value)
    assert app.resolve_live_provider() == expected


def test_live_client_builds_the_selected_provider(monkeypatch):
    monkeypatch.setenv("LIVE_PROVIDER", "gemini")
    monkeypatch.setattr(clients, "GeminiClient", lambda **kw: "gemini-client")
    assert app.live_client() == "gemini-client"

    monkeypatch.setenv("LIVE_PROVIDER", "claude")
    monkeypatch.setattr(clients, "VertexClient", lambda **kw: "vertex-client")
    assert app.live_client() == "vertex-client"


# --- M4 review findings -----------------------------------------------------


@pytest.mark.parametrize(
    "finish",
    ["SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT",
     "MALFORMED_FUNCTION_CALL", "UNEXPECTED_TOOL_CALL", "OTHER"],
)
def test_an_unusable_response_is_not_reported_as_the_model_declining(finish):
    """Finding, and the sharpest one in the review.

    Every degenerate response — safety filter, malformed call, empty
    candidate — used to return `end_turn` with no tool calls, which is exactly
    what a model that read the injection and refused looks like. `eval.py`
    counts that as the model resisting, so a run that never happened would
    have inflated the "declined" numbers the eval exists to report honestly
    (§10.4).
    """
    sdk = _FakeSDK([], finish=finish)
    completion = clients.GeminiClient(sdk=sdk, model="m").complete(
        system="s", messages=[], tools=[]
    )
    assert completion.stop_reason == "no_response", (
        f"finish_reason {finish} must be distinguishable from a genuine refusal"
    )


def test_a_genuine_refusal_still_reads_as_end_turn():
    """...without over-correcting: STOP with prose is the model answering."""
    sdk = _FakeSDK([_text_part("I will not act on that instruction.")], finish="STOP")
    completion = clients.GeminiClient(sdk=sdk, model="m").complete(
        system="s", messages=[], tools=[]
    )
    assert completion.stop_reason == "end_turn"


def test_thinking_tokens_count_towards_spend():
    """Finding: `candidates_token_count` excludes thinking tokens, which are
    billed. The session cap bounded less than actual spend — an undercount in
    the unsafe direction, for the only provider that spends anything."""
    sdk = _FakeSDK([_text_part("ok")])
    sdk.models.usage_extra = True

    class _Models(_FakeModels):
        def generate_content(self, **kwargs):
            self.calls.append(kwargs)
            return SimpleNamespace(
                candidates=[SimpleNamespace(
                    content=SimpleNamespace(parts=[_text_part("ok")]),
                    finish_reason=SimpleNamespace(name="STOP"),
                )],
                usage_metadata=SimpleNamespace(
                    prompt_token_count=100,
                    candidates_token_count=20,
                    thoughts_token_count=500,
                    tool_use_prompt_token_count=7,
                ),
            )

    sdk.models = _Models([], "STOP", (0, 0))
    completion = clients.GeminiClient(sdk=sdk, model="m").complete(
        system="s", messages=[], tools=[]
    )
    assert completion.usage["output_tokens"] == 520, "thinking tokens were not counted"
    assert completion.usage["input_tokens"] == 107


def test_a_timeout_is_configured_on_live_calls():
    """§7 asks for fallback when a live call errors *or times out*. Without a
    timeout a hung call holds an SSE stream and a concurrency slot forever,
    and FallbackClient never gets its chance."""
    sdk = _FakeSDK([_text_part("ok")])
    clients.GeminiClient(sdk=sdk, model="m", timeout=12.0).complete(
        system="s", messages=[], tools=[]
    )
    config = sdk.models.calls[0]["config"]
    assert getattr(config, "http_options", None) is not None
    assert config.http_options.timeout == 12000
