"""The enforcement layer, independent of how it is served (§5).

D1, D2 and D3 are decisions about content and privilege, not about HTTP. They
live in their own module so the web demo and the MCP server share exactly one
implementation — a second copy of a defense is a second thing to get wrong,
and this whole project is an argument that the enforcement layer is the part
that has to be real.

Everything here is a pure function: the caller owns the state (what is in
context, what has been spent), these only decide.
"""
from __future__ import annotations

import re

import store

#: What counts as tag-like, in two rules.
#:
#: 1. A named tag: `<` or `</`, then optionally `!`/`?`, then a letter, then
#:    anything up to `>`. No length cap — `<system ` followed by 250
#:    characters walked through an earlier `{0,200}` body.
#: 2. Any bracketed run containing no whitespace at all: `<1system>`,
#:    `</_system>`, `<untrusted-abc>`. A leading letter is not required,
#:    because `<1system>` walked through an `[A-Za-z]`-only gate.
#:
#: Deliberately NOT matched: a bracketed run that carries whitespace and has
#: no tag name, like `latency < 5ms and count > 3`. Stripping applies only to
#: attacker-controllable chunks, which are exactly the evidence an analyst is
#: reading — and a prose comparison is not what a model reads as a boundary.
#: §5 asks for tag-like text to go; a defense that silently corrupts evidence
#: has a cost of its own.
#: 3. An HTML comment, which carries whitespace and has no tag name and so
#:    would otherwise fall through both rules above.
TAGLIKE_PATTERNS = (
    re.compile(r"<!--.*?-->", re.S),
    re.compile(r"</?\s*[!?]?[A-Za-z][^<>]*>"),
    re.compile(r"</?[^<>\s]*>"),
)


def strip_taglike(text: str, nonce: str) -> str:
    """Remove tag-shaped spans, and the run's nonce, from untrusted content.

    Spotlighting only works if the boundary is unforgeable. Two things could
    forge it: a literal `</untrusted-{nonce}>` (if the attacker learns the
    nonce) and any other tag-shaped text that makes the model read the wrapper
    as having ended — `</user>`, `<system>`, `<tool_result>`. Both go.

    Stripping repeats to a fixed point. A single pass is defeated by nesting:
    `</us<x>er>` has its inner `<x>` removed and reassembles into a working
    `</user>`. Each pass strictly shortens the text, so this terminates.

    The nonce is stripped even as bare text, so content cannot reconstruct a
    closing tag out of pieces.
    """
    cleaned = text or ""
    while True:
        stripped = cleaned
        for pattern in TAGLIKE_PATTERNS:
            stripped = pattern.sub("", stripped)
        if stripped == cleaned:
            break
        cleaned = stripped
    if nonce:
        cleaned = cleaned.replace(nonce, "")
    return cleaned


def render_chunks(chunks: list[store.Chunk], nonce: str | None = None) -> str:
    """Retrieved context as the model sees it.

    With no nonce (D1 off) chunks render plainly, which is the faithful
    undefended baseline — S1f's forged tags have to survive verbatim for the
    before/after to mean anything. With a nonce, every attacker-controllable
    chunk is wrapped and its content stripped of tag-like text first.

    This is the single choke point: the first prompt and every `search_logs`
    result both render through here, so D1 covers both paths (D-018).
    """
    lines = []
    for chunk in chunks:
        if nonce and chunk.trust == store.ATTACKER_CONTROLLABLE:
            body = strip_taglike(chunk.text, nonce)
            lines.append(
                f'<untrusted-{nonce} source="{chunk.id}">\n{body}\n</untrusted-{nonce}>'
            )
        else:
            lines.append(f"[{chunk.id}] (source: {chunk.source})\n{chunk.text}")
    return "\n\n".join(lines)


def render_memory(records, nonce: str | None = None) -> str:
    """Recalled facts as the model sees them.

    Recalled memory is untrusted text in the prompt exactly as a retrieved
    chunk is (D-013): the fact may have been derived from an attacker-written
    ticket comment, and a human approving it does not make its wording safe.
    Rendering it raw gave D1 a second, unspotlighted path into the prompt —
    including a same-run round trip where content inside a wrapper asked the
    model to copy the live nonce into a fact, and recall handed the real
    closing tag back outside any wrapper.
    """
    lines = []
    for record in records:
        if nonce and record.trust == store.ATTACKER_CONTROLLABLE:
            body = strip_taglike(record.content, nonce)
            lines.append(
                f'<untrusted-{nonce} source="{record.id}">\n- {body}\n</untrusted-{nonce}>'
            )
        else:
            lines.append(f"- {record.content}")
    return "\n".join(lines)


def d1_annotation(chunks: list[store.Chunk], nonce: str | None) -> dict | None:
    """What D1 did to a retrieval, for the trace (§5)."""
    if not nonce:
        return None
    wrapped = [c.id for c in chunks if c.trust == store.ATTACKER_CONTROLLABLE]
    stripped = [
        c.id
        for c in chunks
        if c.trust == store.ATTACKER_CONTROLLABLE
        and strip_taglike(c.text, nonce) != c.text
    ]
    return {
        "id": "D1",
        # Named for what it does rather than for the technique. The technique
        # is known in the literature as spotlighting; that name is kept in
        # CLAUDE.md §5 and DECISIONS so the prior art stays findable, but it
        # collided with the UI's own red-border highlight — which is the
        # "spotlight" a viewer actually sees, and is not this defense.
        "name": "untrusted_tagging",
        "action": "tagged",
        "nonce": nonce,
        "trigger_chunks": wrapped,
        "stripped_chunks": stripped,
    }


def memory_tier(defenses: dict, untrusted_in_context: bool, untrusted_provenance_ids) -> str:
    """D2: where a memory write lands.

    Two signals, either of which is enough. `untrusted_in_context` is the
    authoritative record of what the model actually read (D-013); the
    provenance ids catch the case where a source cannot be resolved at all,
    which D-012 already treats as untrusted. Fail closed: quarantine is
    recoverable by a human clicking approve, a poisoned long-term fact is not.
    """
    if not defenses.get("D2"):
        return "long_term"
    return "quarantine" if (untrusted_in_context or list(untrusted_provenance_ids or [])) else "long_term"


def d3_blocks(defenses: dict, skill, untrusted_in_context: bool) -> bool:
    """D3: whether a privileged call is refused.

    Deterministic and narrow — privilege plus untrusted context, nothing
    about what the content says. A read_only skill is never blocked: the
    agent has to stay able to investigate, or the defense would simply stop
    the demo working.
    """
    return bool(defenses.get("D3")) and skill.is_privileged and untrusted_in_context


