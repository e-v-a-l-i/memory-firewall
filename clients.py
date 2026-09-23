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


def _extract_args(text: str, schema: dict) -> dict:
    """Best-effort argument extraction from the instruction text.

    The gullible model takes its arguments from the same untrusted text that
    told it what to call — which is the point. An attacker who can write the
    instruction can write the arguments.
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
            value = text.strip()[:200]

        if value is not None:
            args[param] = value
    return args


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

        tool_name, text = hit
        args = _extract_args(text, available[tool_name].get("input_schema", {}))
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
        """The earliest mention of an available tool, and the text around it.

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
                return best[1], best[2]
        return None
