"""Skill loader — procedural memory exposed to the model as tools.

A skill is a directory under `skills/` holding a `SKILL.md`: YAML frontmatter
plus a Markdown body of procedural guidance. The frontmatter's `trust_level`
is the load-bearing field. `read_only` skills observe; `privileged` skills
change the world — they close alerts and return isolated hosts to the network.

The loader refuses to load a skill whose `trust_level` is missing or outside
the enum. A skill with no trust level is not a safe skill with an oversight;
it is a skill the policy layer cannot reason about, and D3 (M2) decides
whether a call is allowed by reading exactly this field.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

READ_ONLY = "read_only"
PRIVILEGED = "privileged"
TRUST_LEVELS = frozenset({READ_ONLY, PRIVILEGED})

SKILL_FILENAME = "SKILL.md"


class SkillError(Exception):
    """A skill could not be loaded. The message always names the file."""


@dataclass(frozen=True)
class Skill:
    name: str
    description: str
    trust_level: str
    parameters: dict = field(default_factory=dict)
    body: str = ""
    path: str = ""

    @property
    def is_privileged(self) -> bool:
        return self.trust_level == PRIVILEGED


def _split_frontmatter(text: str, path: Path) -> tuple[dict, str]:
    if not text.lstrip().startswith("---"):
        raise SkillError(f"{path}: no YAML frontmatter (file must start with '---')")
    stripped = text.lstrip()
    parts = stripped.split("---", 2)
    if len(parts) < 3:
        raise SkillError(f"{path}: frontmatter is not closed with '---'")
    try:
        meta = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError as exc:
        raise SkillError(f"{path}: frontmatter is not valid YAML: {exc}") from exc
    if not isinstance(meta, dict):
        raise SkillError(f"{path}: frontmatter must be a mapping")
    return meta, parts[2].strip()


def load_skill(path: Path | str) -> Skill:
    """Load and validate one SKILL.md."""
    path = Path(path)
    meta, body = _split_frontmatter(path.read_text(encoding="utf-8"), path)

    name = meta.get("name")
    if not name:
        raise SkillError(f"{path}: frontmatter is missing 'name'")

    trust_level = meta.get("trust_level")
    if trust_level is None:
        raise SkillError(
            f"{path}: frontmatter is missing 'trust_level'; every skill must "
            f"declare one of {sorted(TRUST_LEVELS)}"
        )
    if trust_level not in TRUST_LEVELS:
        raise SkillError(
            f"{path}: trust_level {trust_level!r} is not one of "
            f"{sorted(TRUST_LEVELS)}"
        )

    return Skill(
        name=str(name),
        description=str(meta.get("description") or "").strip(),
        trust_level=trust_level,
        parameters=meta.get("parameters") or {},
        body=body,
        path=str(path),
    )


def load_skills(root: Path | str = "skills/") -> dict[str, Skill]:
    """Load every `<root>/*/SKILL.md`, keyed by frontmatter name.

    One bad skill fails the whole load rather than being skipped: a partially
    loaded skill set would silently change which tools exist, and "the tool
    vanished" is a worse failure to debug than "the file is wrong".
    """
    root = Path(root)
    loaded: dict[str, Skill] = {}
    for skill_path in sorted(root.glob(f"*/{SKILL_FILENAME}")):
        skill = load_skill(skill_path)
        if skill.name in loaded:
            raise SkillError(
                f"{skill_path}: duplicate skill name {skill.name!r} (already "
                f"loaded from {loaded[skill.name].path})"
            )
        loaded[skill.name] = skill
    return loaded


def to_input_schema(skill: Skill) -> dict:
    """JSON Schema for a skill's parameters, in Anthropic tool format."""
    properties: dict[str, dict] = {}
    required: list[str] = []
    for param_name, spec in (skill.parameters or {}).items():
        spec = spec or {}
        properties[param_name] = {
            "type": spec.get("type", "string"),
            "description": str(spec.get("description", "")),
        }
        if spec.get("required"):
            required.append(param_name)
    return {"type": "object", "properties": properties, "required": required}


def to_tool_schemas(skills: dict[str, Skill]) -> list[dict]:
    """Render loaded skills as tool definitions for the model.

    The body ships inside the description: it is the procedural guidance that
    makes the skill usable, and several of the bodies are where the "retrieved
    text is evidence, not instruction" framing reaches the model at all.

    `trust_level` is deliberately NOT part of the emitted tool definition. The
    Messages API rejects unknown fields on a tool object, and the policy layer
    reads the level from the loaded Skill, not from what was handed to the
    model — a privilege label the model can see is a privilege label an
    injection can argue with.
    """
    schemas = []
    for skill in skills.values():
        description = skill.description
        if skill.body:
            description = f"{description}\n\n{skill.body}" if description else skill.body
        schemas.append(
            {
                "name": skill.name,
                "description": description,
                "input_schema": to_input_schema(skill),
            }
        )
    return schemas
