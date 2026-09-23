"""M1 acceptance-criteria tests for `skills.py` (CLAUDE.md §3 skills, §10.1
skill loader).

`skills.py` does not exist yet as of M1's red state, so every test here is
expected to fail with ModuleNotFoundError until the main session adds it.

Contract under test:

    load_skills("skills/") -> dict[name, Skill]
        Skill fields: name, description, trust_level, parameters, body, path
        Raises SkillError (message contains the offending path) when
        trust_level is missing or not in {read_only, privileged}.
    to_tool_schemas(skills) -> list[{name, description, input_schema}]
        input_schema["type"] == "object"; required params in
        input_schema["required"].

    Five skills: search_logs, recall_memory, save_memory (read_only);
    close_alert, unisolate_host (privileged).

Criteria encoded here (CLAUDE.md §10.1):
  AC-SKILL-1 - loads exactly 5 skills keyed by frontmatter name.
  AC-SKILL-2 - the privileged set is exactly {close_alert, unisolate_host};
               everything else is read_only.
  AC-SKILL-3 - a SKILL.md missing trust_level raises SkillError whose
               message contains the offending path.
  AC-SKILL-4 - a SKILL.md with trust_level outside the enum raises
               SkillError whose message contains the offending path.
  AC-SKILL-5 - to_tool_schemas produces well-formed tool schemas for all 5
               skills.
  AC-SKILL-6 - skill body is non-empty and present in the generated
               description.
"""
import pytest

import skills


EXPECTED_NAMES = {
    "search_logs",
    "recall_memory",
    "save_memory",
    "close_alert",
    "unisolate_host",
}
EXPECTED_READ_ONLY = {"search_logs", "recall_memory", "save_memory"}
EXPECTED_PRIVILEGED = {"close_alert", "unisolate_host"}


# --- AC-SKILL-1: exactly 5 skills, keyed correctly ---------------------------


def test_load_skills_loads_exactly_five_skills_keyed_by_name():
    """AC-SKILL-1: load_skills loads exactly 5 skills keyed by frontmatter
    name."""
    loaded = skills.load_skills("skills/")
    assert isinstance(loaded, dict)
    assert set(loaded.keys()) == EXPECTED_NAMES
    for name, skill in loaded.items():
        assert skill.name == name


def test_skill_fields_are_populated():
    loaded = skills.load_skills("skills/")
    for name, skill in loaded.items():
        assert skill.description and isinstance(skill.description, str)
        assert skill.body and isinstance(skill.body, str)
        assert skill.trust_level in {"read_only", "privileged"}
        assert skill.parameters is not None
        assert skill.path, f"skill {name!r} has no path"


# --- AC-SKILL-2: trust_level partition ---------------------------------------


def test_privileged_skills_are_exactly_close_alert_and_unisolate_host():
    """AC-SKILL-2: the privileged set is exactly {close_alert,
    unisolate_host}; everything else is read_only."""
    loaded = skills.load_skills("skills/")
    privileged = {n for n, s in loaded.items() if s.trust_level == "privileged"}
    read_only = {n for n, s in loaded.items() if s.trust_level == "read_only"}

    assert privileged == EXPECTED_PRIVILEGED
    assert read_only == EXPECTED_READ_ONLY
    # No third bucket.
    assert privileged | read_only == EXPECTED_NAMES


# --- AC-SKILL-3/4: malformed skills raise SkillError with the path ----------


def _write_skill(tmp_path, dirname, frontmatter_lines, body="Do the thing.\n"):
    skill_dir = tmp_path / dirname
    skill_dir.mkdir(parents=True)
    skill_md = skill_dir / "SKILL.md"
    frontmatter = "\n".join(frontmatter_lines)
    skill_md.write_text(f"---\n{frontmatter}\n---\n{body}")
    return skill_md


def test_missing_trust_level_raises_skillerror_naming_the_path(tmp_path):
    """AC-SKILL-3: a SKILL.md missing trust_level raises SkillError whose
    message contains the offending path."""
    bad_path = _write_skill(
        tmp_path,
        "no_trust_level_skill",
        [
            "name: no_trust_level_skill",
            "description: A skill with no trust_level at all.",
        ],
    )

    with pytest.raises(skills.SkillError) as exc_info:
        skills.load_skills(str(tmp_path))

    message = str(exc_info.value)
    assert str(bad_path) in message or "no_trust_level_skill" in message, (
        f"SkillError message does not identify the offending path: {message!r}"
    )


def test_invalid_trust_level_value_raises_skillerror_naming_the_path(tmp_path):
    """AC-SKILL-4: a SKILL.md with a trust_level outside {read_only,
    privileged} raises SkillError whose message contains the offending
    path."""
    _write_skill(
        tmp_path,
        "bogus_trust_level_skill",
        [
            "name: bogus_trust_level_skill",
            "description: A skill with a bogus trust_level.",
            "trust_level: superuser",
        ],
    )

    with pytest.raises(skills.SkillError) as exc_info:
        skills.load_skills(str(tmp_path))

    assert "bogus_trust_level_skill" in str(exc_info.value)


@pytest.mark.parametrize("bad_value", ["", "READ_ONLY", "read-only", "admin"])
def test_various_invalid_trust_level_values_all_raise(tmp_path, bad_value):
    """AC-SKILL-4, broader: several out-of-enum values all raise, not just
    one specific typo."""
    _write_skill(
        tmp_path,
        "variant_skill",
        [
            "name: variant_skill",
            "description: desc",
            f"trust_level: {bad_value}",
        ],
    )
    with pytest.raises(skills.SkillError):
        skills.load_skills(str(tmp_path))


def test_valid_trust_levels_do_not_raise(tmp_path):
    """Sanity check on the malformed-skill harness itself: both enum values
    are accepted so the tests above are exercising the validation, not just
    a broken test fixture."""
    for value in ("read_only", "privileged"):
        d = tmp_path / value
        _write_skill(
            d,
            "ok_skill",
            [
                "name: ok_skill",
                "description: desc",
                f"trust_level: {value}",
            ],
        )
        loaded = skills.load_skills(str(d))
        assert "ok_skill" in loaded
        assert loaded["ok_skill"].trust_level == value


# --- AC-SKILL-5: to_tool_schemas shape ---------------------------------------


def test_to_tool_schemas_covers_all_five_skills_with_valid_shape():
    """AC-SKILL-5: to_tool_schemas produces well-formed tool schemas for all
    5 skills."""
    loaded = skills.load_skills("skills/")
    schemas = skills.to_tool_schemas(loaded)

    assert isinstance(schemas, list)
    assert {s["name"] for s in schemas} == EXPECTED_NAMES

    for schema in schemas:
        assert set(schema.keys()) >= {"name", "description", "input_schema"}
        input_schema = schema["input_schema"]
        assert input_schema["type"] == "object"
        assert "properties" in input_schema
        required = input_schema.get("required", [])
        assert isinstance(required, list)
        for param in required:
            assert param in input_schema["properties"], (
                f"{schema['name']}: required param {param!r} is not in "
                "input_schema['properties']"
            )


# --- AC-SKILL-6: body flows into the generated description ------------------


def test_skill_body_is_present_in_generated_tool_description():
    """AC-SKILL-6: skill body is non-empty and present in the generated
    description."""
    loaded = skills.load_skills("skills/")
    schemas = {s["name"]: s for s in skills.to_tool_schemas(loaded)}

    for name, skill in loaded.items():
        assert skill.body.strip() != ""
        body_first_line = next(
            (line.strip() for line in skill.body.splitlines() if line.strip()),
            None,
        )
        assert body_first_line, f"skill {name!r} body has no non-blank line"
        assert body_first_line in schemas[name]["description"], (
            f"skill {name!r}'s body does not appear in its generated tool "
            "description"
        )
