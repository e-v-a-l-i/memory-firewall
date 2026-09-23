"""Model clients behind one interface.

`VertexClient` (M3) calls Claude through Vertex AI; `ReplayClient` (M3) serves
recorded runs so the demo works with no model at all; `MockClient` drives the
tests.

`MockClient` has two modes, and the second one is a deliberate piece of the
threat model (D-008):

- **scripted** — returns a fixed list of completions. Deterministic unit tests.
- **gullible** — reads whatever is in context and, if it finds text naming an
  available tool, calls it. It is a model with no judgement at all.

The gullible mode exists because §10.2 wants the scenario matrix to test the
*enforcement layer*, not the model. If the matrix passes with a model that
follows every instruction it sees, the defenses are doing the work. A test
that relies on Claude declining the injection is measuring Claude, which is
what §10.4's live eval is for.
"""
from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass(frozen=True)
class Completion:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = "end_turn"  # "tool_use" | "end_turn" | "max_tokens"
    usage: dict = field(default_factory=dict)


@runtime_checkable
class ClaudeClient(Protocol):
    """What the agent loop needs from a model.

    `messages` uses Anthropic block format so `VertexClient` can pass them
    through untouched in M3.
    """

    name: str

    def complete(
        self, *, system: str, messages: list[dict], tools: list[dict], max_tokens: int = 1024
    ) -> Completion: ...


class MockExhausted(Exception):
    """A scripted MockClient ran out of scripted completions."""


def iter_text_blocks(messages: list[dict], include_assistant: bool = False):
    """Every text block the model *read*, in order.

    Tool results count: content an attacker planted in a log reaches the model
    as a tool result, and a model that reads it reads it there. The model's own
    prior sentences do not count by default — a model quoting an instruction
    back to itself and then "obeying" it is a mock artefact, not a threat.
    """
    for message in messages or ():
        if not include_assistant and message.get("role") == "assistant":
            continue
        content = message.get("content")
        if isinstance(content, str):
            yield content
            continue
        for block in content or ():
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text" and block.get("text"):
                yield block["text"]
            elif block.get("type") == "tool_result":
                inner = block.get("content")
                if isinstance(inner, str):
                    yield inner
                else:
                    for sub in inner or ():
                        if isinstance(sub, dict) and sub.get("text"):
                            yield sub["text"]


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ALERT_RE = re.compile(r"\bALR-\d+\b")
_DISPOSITIONS = ("benign", "false_positive", "resolved")


def _extract_args(text: str, schema: dict, directive_text: str | None = None) -> dict:
    """Best-effort argument extraction from the instruction text.

    The gullible model takes its arguments from the same untrusted text that
    told it what to call — which is the point. An attacker who can write the
    instruction can write the arguments.

    `directive_text` is the span right after the tool name, used only for the
    last-resort free-text fallback. Without it, a required prose parameter
    (`save_memory`'s `content`) fell back to the start of the whole context
    block — the alert summary, not the attacker's claim — so the poisoned
    fact never reached memory intact. The regex fallbacks still scan the full
    text, because an alert id or host often sits in the prompt header rather
    than in the injected sentence.
    """
    args: dict = {}
    properties = (schema or {}).get("properties", {}) or {}
    required = set((schema or {}).get("required", []) or [])

    for param in properties:
        explicit = re.search(
            rf"{re.escape(param)}\s*(?:is|=|:|to)?\s*[\"']?([A-Za-z0-9._\-/]+)", text
        )
        value = explicit.group(1) if explicit else None

        if value is None:
            if param.endswith("alert_id") or param == "alert":
                match = _ALERT_RE.search(text)
                value = match.group(0) if match else None
            elif param in {"host", "hostname", "ip"}:
                match = _IP_RE.search(text)
                value = match.group(0) if match else None
            elif param == "disposition":
                value = next((d for d in _DISPOSITIONS if d in text.lower()), None)

        if value is None and param in required:
            value = (directive_text or text).strip()[:200]

        if value is not None:
            # Right-strip only: a sentence-ending period is punctuation, but
            # an IP address's interior dots are part of the value.
            args[param] = value.rstrip(".,;:!?") if isinstance(value, str) else value
    return args


def _first_directive(messages: list[dict], available: dict):
    """Module-level view of the directive scan, for direct testing."""
    return MockClient(gullible=True)._first_directive(messages, available)


class MockClient:
    """A model that either replays a script or follows whatever it reads."""

    name = "mock"

    def __init__(self, script: list[Completion] | None = None, gullible: bool = False):
        self._script = list(script or [])
        self._cursor = 0
        self.gullible = gullible
        self._counter = itertools.count(1)
        #: Tools already acted on. A gullible model follows an instruction
        #: once; without this it re-reads the same injected sentence every
        #: turn and the loop only ends by hitting its cap.
        self._obeyed: set[str] = set()

    def complete(
        self, *, system: str, messages: list[dict], tools: list[dict], max_tokens: int = 1024
    ) -> Completion:
        if self._script:
            if self._cursor >= len(self._script):
                raise MockExhausted(
                    f"MockClient script exhausted after {len(self._script)} completions"
                )
            completion = self._script[self._cursor]
            self._cursor += 1
            return completion
        if self.gullible:
            return self._follow_instructions(messages, tools)
        raise MockExhausted("MockClient was given neither a script nor gullible=True")

    # -- gullible mode ---------------------------------------------------

    def _follow_instructions(self, messages: list[dict], tools: list[dict]) -> Completion:
        available = {t["name"]: t for t in tools or []}
        usage = {"input_tokens": sum(len(t) for t in iter_text_blocks(messages)), "output_tokens": 24}

        hit = self._first_directive(messages, available)
        if hit is None:
            return Completion(
                text="No further action indicated; leaving the alert open.",
                tool_calls=[],
                stop_reason="end_turn",
                usage=usage,
            )

        position, tool_name, text = hit
        # The instruction's own sentence, not the whole block it sits in.
        snippet = text[position + len(tool_name) : position + len(tool_name) + 400]
        snippet = snippet.lstrip(" :,.-")
        args = _extract_args(
            text, available[tool_name].get("input_schema", {}), directive_text=snippet
        )
        self._obeyed.add(tool_name)
        return Completion(
            text=f"The retrieved content says to call {tool_name}; doing that.",
            tool_calls=[
                ToolCall(id=f"mock-{next(self._counter)}", name=tool_name, input=args)
            ],
            stop_reason="tool_use",
            usage=usage,
        )

    def _first_directive(self, messages: list[dict], available: dict):
        """The earliest mention of an available tool: (position, name, text).

        Only tools actually offered are considered: a model cannot call a tool
        it was not given, however loudly the text demands it.
        """
        best = None
        for text in iter_text_blocks(messages):
            for tool_name in available:
                if tool_name in self._obeyed:
                    continue
                position = text.find(tool_name)
                if position == -1:
                    continue
                if best is None or position < best[0]:
                    best = (position, tool_name, text)
            if best is not None:
                return best
        return None


# =============================================================================
# Live and recorded clients
# =============================================================================

import json
import os
from pathlib import Path

REPLAYS_DIR = Path(__file__).resolve().parent / "replays"


class ReplayMissing(Exception):
    """No recorded run exists for this scenario, arm and stage."""


class VertexClient:
    """Claude through Vertex AI.

    Close to a passthrough by design: `iter_scenario` already builds messages
    in Anthropic block format and `to_tool_schemas` already emits tool
    definitions the API accepts (D-016), so nothing is translated on the way
    in and only the response is mapped on the way out.

    The `sdk` seam exists so this is testable with no network and no
    credentials — the whole suite runs offline (§11).
    """

    name = "vertex"

    def __init__(self, *, project=None, region=None, model=None, timeout=45.0, sdk=None):
        self._model = model or os.environ["MODEL_AGENT"]
        if sdk is None:
            # Imported here, not at module scope: importing `app` must stay
            # side-effect free and must not pull in the SDK (D-005).
            from anthropic import AnthropicVertex

            sdk = AnthropicVertex(
                project_id=project or os.environ["GCP_PROJECT"],
                region=region or os.environ.get("VERTEX_REGION", "global"),
                timeout=timeout,
                # One attempt. §7's retry story is the replay fallback; an SDK
                # that retries internally just delays it behind a timeout.
                max_retries=1,
            )
        self._sdk = sdk

    def complete(
        self, *, system: str, messages: list[dict], tools: list[dict], max_tokens: int = 1024
    ) -> Completion:
        response = self._sdk.messages.create(
            model=self._model,
            system=system,
            messages=messages,
            tools=tools,
            max_tokens=max_tokens,
        )

        text_parts, tool_calls = [], []
        for block in getattr(response, "content", None) or ():
            kind = getattr(block, "type", None)
            if kind == "text":
                text_parts.append(getattr(block, "text", "") or "")
            elif kind == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=getattr(block, "id", ""),
                        name=getattr(block, "name", ""),
                        input=dict(getattr(block, "input", None) or {}),
                    )
                )

        usage = getattr(response, "usage", None)
        return Completion(
            text="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=getattr(response, "stop_reason", "end_turn") or "end_turn",
            usage={
                "input_tokens": int(getattr(usage, "input_tokens", 0) or 0),
                "output_tokens": int(getattr(usage, "output_tokens", 0) or 0),
            },
        )


class ReplayClient:
    """Serves a recorded run so the demo works with no model at all (§1).

    A replay holds the model's **completions**, not the trace. Retrieval, D1's
    per-run nonce and wrapping, D2's gate and D3's policy all execute for real
    on every replayed run — only what the model said comes off disk. A frozen
    trace would have made replay mode a video of the demo rather than the
    demo, with the defense toggles inert.
    """

    name = "replay"

    def __init__(self, scenario: str, arm: str = "undefended", stage: int = 1, dir=None):
        directory = Path(dir) if dir is not None else REPLAYS_DIR
        self.path = directory / f"{str(scenario).lower()}_{arm}_stage{stage}.json"
        if not self.path.exists():
            raise ReplayMissing(
                f"no recorded run at {self.path.name}; record one with scripts/eval.py --record"
            )
        # Anything unreadable is "no usable recording", raised as the same
        # error a missing file raises. Replay mode is what §1 promises works
        # without a model, so a truncated write or a bad merge must degrade
        # to a clean 404 rather than escaping as a parse error mid-request.
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                recording = json.load(fh)
        except (ValueError, OSError) as exc:
            raise ReplayMissing(f"{self.path.name} is not readable JSON: {exc}") from exc
        if not isinstance(recording, dict):
            raise ReplayMissing(
                f"{self.path.name} is {type(recording).__name__}, expected an object"
            )
        completions = recording.get("completions")
        if completions is not None and not isinstance(completions, list):
            raise ReplayMissing(
                f"{self.path.name} has a {type(completions).__name__} where its "
                "completions list should be"
            )
        self.recording = recording
        self._completions = list(completions or [])
        self._cursor = 0

    def complete(
        self, *, system: str, messages: list[dict], tools: list[dict], max_tokens: int = 1024
    ) -> Completion:
        if self._cursor >= len(self._completions):
            # Graceful end rather than an exception: a toggle combination the
            # recording never saw must still reach `done`. A short run is a
            # much better failure than a stream that dies mid-demo.
            return Completion(
                text="The recorded run ended here.",
                tool_calls=[],
                stop_reason="end_turn",
                usage={"input_tokens": 0, "output_tokens": 0},
            )
        raw = self._completions[self._cursor]
        self._cursor += 1
        return Completion(
            text=raw.get("text", ""),
            tool_calls=[
                ToolCall(id=tc.get("id", ""), name=tc.get("name", ""), input=dict(tc.get("input") or {}))
                for tc in raw.get("tool_calls") or ()
            ],
            stop_reason=raw.get("stop_reason", "end_turn"),
            usage={
                "input_tokens": int((raw.get("usage") or {}).get("input_tokens", 0)),
                "output_tokens": int((raw.get("usage") or {}).get("output_tokens", 0)),
            },
        )


class FallbackClient:
    """Primary model, with a recorded run as the safety net (§7).

    Failover is mid-run, not per-run: if Vertex times out on turn three, the
    remaining turns come from the recording and the stream continues. The
    trace says so, so a viewer is never shown a replay while being told it is
    live.
    """

    def __init__(self, primary, fallback):
        self._primary = primary
        self._fallback = fallback
        self.fell_back = False

    @property
    def name(self) -> str:
        return getattr(self._fallback if self.fell_back else self._primary, "name", "unknown")

    def complete(self, **kwargs) -> Completion:
        if not self.fell_back:
            try:
                return self._primary.complete(**kwargs)
            except Exception:  # noqa: BLE001 - any live failure falls back
                self.fell_back = True
        return self._fallback.complete(**kwargs)
