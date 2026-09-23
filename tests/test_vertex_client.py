"""M3 acceptance-criteria tests for T6: `clients.VertexClient` (CLAUDE.md
§2 "Claude via Vertex AI (`anthropic[vertex]`, region `global`) behind a
`ClaudeClient` interface with `VertexClient`, `MockClient`, and
`ReplayClient`").

None of `clients.VertexClient` exists yet as of M3's red state. Every test
below is expected to fail with AttributeError -- not an import error or a
fixture bug. `import clients` itself must keep succeeding with no GCP env
configured (D-005's import-time-side-effect-freedom, extended to this new
class): `AnthropicVertex` is imported lazily, inside `__init__`, only when
no `sdk=` override is supplied.

Contract under test:

- `clients.VertexClient(*, project=None, region=None, model=None,
  timeout=45.0, sdk=None)`.
- `complete()` calls `sdk.messages.create(model=, system=, messages=,
  tools=, max_tokens=)` and maps the response's text blocks (concatenated)
  and tool_use blocks into a `Completion`/`ToolCall`.
- `name = "vertex"`.

A fake SDK stands in for `AnthropicVertex` throughout (`sdk=` is exactly
the seam the contract offers for this), so no test here touches the
network -- enforced by an autouse fixture that makes any real
`socket.socket.connect` fail the test outright.
"""
import json
import os
import socket
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

import clients

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _block_sockets(monkeypatch):
    def _boom(self, *a, **kw):
        raise AssertionError("a VertexClient test attempted a real network connection")

    monkeypatch.setattr(socket.socket, "connect", _boom)
    yield


# --- a fake AnthropicVertex SDK ---------------------------------------------


class _TextBlock:
    def __init__(self, text: str):
        self.type = "text"
        self.text = text


class _ToolUseBlock:
    def __init__(self, id_: str, name: str, input_: dict):
        self.type = "tool_use"
        self.id = id_
        self.name = name
        self.input = input_


class _FakeResponse:
    def __init__(self, blocks, stop_reason, usage):
        self.content = blocks
        self.stop_reason = stop_reason
        self.usage = SimpleNamespace(**usage)


class _FakeMessages:
    def __init__(self, blocks, stop_reason, usage):
        self.calls: list[dict] = []
        self._blocks = blocks
        self._stop_reason = stop_reason
        self._usage = usage

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return _FakeResponse(self._blocks, self._stop_reason, self._usage)


class _FakeSDK:
    def __init__(self, blocks=None, stop_reason="end_turn", usage=None):
        self.messages = _FakeMessages(
            blocks or [], stop_reason, usage or {"input_tokens": 10, "output_tokens": 5}
        )


# =============================================================================
# AC1
# =============================================================================


def test_t6_1_vertex_client_satisfies_the_claudeclient_protocol_and_is_named_vertex():
    vc = clients.VertexClient(sdk=_FakeSDK(), model="m")
    assert isinstance(vc, clients.ClaudeClient)
    assert vc.name == "vertex"


# =============================================================================
# AC2
# =============================================================================


def test_t6_2_maps_text_and_tool_use_blocks_into_a_completion():
    blocks = [
        _TextBlock("here is my answer"),
        _TextBlock("continued"),
        _ToolUseBlock("tu-1", "close_alert", {"alert_id": "ALR-1001", "disposition": "benign"}),
    ]
    sdk = _FakeSDK(blocks=blocks, stop_reason="tool_use", usage={"input_tokens": 123, "output_tokens": 45})
    vc = clients.VertexClient(sdk=sdk, model="m")

    result = vc.complete(
        system="sys", messages=[{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
        tools=[], max_tokens=999,
    )

    assert "here is my answer" in result.text
    assert "continued" in result.text
    assert result.text.index("here is my answer") < result.text.index("continued"), (
        "text blocks must be concatenated in order"
    )

    assert len(result.tool_calls) == 1
    tc = result.tool_calls[0]
    assert tc.id == "tu-1"
    assert tc.name == "close_alert"
    assert tc.input == {"alert_id": "ALR-1001", "disposition": "benign"}

    assert result.stop_reason == "tool_use"
    assert result.usage["input_tokens"] == 123
    assert result.usage["output_tokens"] == 45
    assert isinstance(result.usage["input_tokens"], int)
    assert isinstance(result.usage["output_tokens"], int)


# =============================================================================
# AC3
# =============================================================================


def test_t6_3_forwards_model_system_messages_tools_max_tokens_unchanged():
    sdk = _FakeSDK(blocks=[_TextBlock("ok")], stop_reason="end_turn")
    vc = clients.VertexClient(sdk=sdk, model="claude-x")

    system = "system prompt text"
    messages = [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]
    tools = [
        {
            "name": "search_logs",
            "description": "d",
            "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}},
        }
    ]
    tools_before = json.loads(json.dumps(tools))

    vc.complete(system=system, messages=messages, tools=tools, max_tokens=777)

    assert len(sdk.messages.calls) == 1
    call = sdk.messages.calls[0]
    assert call["model"] == "claude-x"
    assert call["system"] == system
    assert call["messages"] == messages
    assert call["tools"] == tools
    assert call["tools"] == tools_before, "no key was added to or removed from a tool schema"
    assert call["max_tokens"] == 777


# =============================================================================
# AC4
# =============================================================================


def test_t6_4_text_only_response_has_no_tool_calls_and_end_turn():
    sdk = _FakeSDK(blocks=[_TextBlock("just an answer")], stop_reason="end_turn")
    vc = clients.VertexClient(sdk=sdk, model="m")
    result = vc.complete(system="s", messages=[], tools=[], max_tokens=10)
    assert result.tool_calls == []
    assert result.stop_reason == "end_turn"


# =============================================================================
# AC5
# =============================================================================

_VERTEX_ENV_SCRIPT = textwrap.dedent(
    """
    import clients
    print("IMPORT_OK")
    try:
        clients.VertexClient()
    except KeyError as exc:
        print("KEYERROR:" + str(exc))
    else:
        print("NO_KEYERROR")
    """
)


def _minimal_env() -> dict:
    env = {"PATH": os.environ.get("PATH", "")}
    for key in ("SYSTEMROOT", "HOME", "LANG", "LC_ALL"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def test_t6_5_import_clients_with_no_gcp_env_succeeds_and_bare_vertexclient_needs_env_vars():
    """AC5: `import clients` succeeds with no GCP_PROJECT/MODEL_AGENT set
    and constructs nothing at import time; `VertexClient()` with no `sdk=`
    override and those env vars unset raises `KeyError` naming the missing
    variable."""
    result = subprocess.run(
        [sys.executable, "-c", _VERTEX_ENV_SCRIPT],
        cwd=str(REPO_ROOT),
        env=_minimal_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    assert "IMPORT_OK" in result.stdout
    assert "KEYERROR:" in result.stdout, (
        f"VertexClient() with no GCP_PROJECT/MODEL_AGENT should raise KeyError; "
        f"stdout={result.stdout!r}"
    )
    keyerror_line = next(l for l in result.stdout.splitlines() if l.startswith("KEYERROR:"))
    message = keyerror_line[len("KEYERROR:") :]
    assert "GCP_PROJECT" in message or "MODEL_AGENT" in message, (
        f"the KeyError should name the missing variable; got {message!r}"
    )


# AC6 ("no test here opens a socket") is the autouse `_block_sockets` fixture
# above, applied to every test in this file.
