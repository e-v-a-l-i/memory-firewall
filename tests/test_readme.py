"""M4 acceptance-criteria tests for T6: README.md (CLAUDE.md §9 M4
"README", §11 "README explains how to use the demo in under a minute").

README.md does not exist yet as of M4's red state -- every test below is
expected to fail on a missing/empty file (an AssertionError from `_read()`),
not on a fixture bug.
"""
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"

DEPLOYED_URL = "https://memory-firewall-366819802884.us-central1.run.app"

#: §2's env vars, plus TRUSTED_PROXY_HOPS and DB_PATH (both added by M3/M4
#: work that postdates §2's own list).
ENV_VARS = {
    "GCP_PROJECT",
    "VERTEX_REGION",
    "MODEL_AGENT",
    "MODEL_FAST",
    "MODE",
    "SESSION_TOKEN_CAP",
    "RATE_LIMIT_PER_MIN",
    "TRUSTED_PROXY_HOPS",
    "DB_PATH",
}

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN"),
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r'"private_key"'),
    re.compile(r"sk-"),
]


def _read() -> str:
    assert README.exists(), "README.md is missing at repo root"
    text = README.read_text(encoding="utf-8")
    assert text.strip(), "README.md exists but is empty"
    return text


def test_readme_exists_and_is_nonempty():
    _read()


def test_readme_contains_the_deployed_url():
    text = _read()
    assert DEPLOYED_URL in text, "README does not link the deployed Cloud Run URL"


def test_readme_has_a_quickstart_heading_with_at_most_five_numbered_steps():
    """A heading naming the "under a minute" promise (§11), whose own
    numbered list is short enough to actually be a minute's worth of
    reading, not a 20-item setup guide dressed up with a friendly title."""
    text = _read()
    heading_re = re.compile(
        r"^#{1,6}[^\n]*(under a minute|60 seconds|quick ?start)[^\n]*$",
        re.I | re.M,
    )
    match = heading_re.search(text)
    assert match, (
        "no heading matches /under a minute|60 seconds|quick ?start/i"
    )

    rest = text[match.end():]
    next_heading = re.search(r"^#{1,6}\s", rest, re.M)
    section = rest[: next_heading.start()] if next_heading else rest

    steps = re.findall(r"^\s*\d+[.)]\s", section, re.M)
    assert steps, "the quickstart section under that heading has no numbered list"
    assert len(steps) <= 5, f"quickstart section has {len(steps)} numbered steps, expected <= 5"


def test_readme_mentions_every_scenario_and_defense_id():
    text = _read()
    missing = [tok for tok in ("S1", "S2", "S3", "D1", "D2", "D3") if not re.search(rf"\b{tok}\b", text)]
    assert not missing, f"README never mentions: {missing}"


def test_readme_names_every_env_var():
    text = _read()
    missing = sorted(v for v in ENV_VARS if v not in text)
    assert not missing, f"README is missing env vars: {missing}"


def test_readme_backtick_paths_that_look_repo_relative_all_exist_on_disk():
    text = _read()
    candidates = re.findall(r"`([^`\n]+)`", text)
    checked = 0
    for candidate in candidates:
        if " " in candidate or "/" not in candidate:
            continue
        # Route paths (`/api/run`, `/health`) and other non-filesystem
        # tokens are backtick-quoted throughout this README too; a
        # repo-relative path here is never written with a leading slash.
        if candidate.startswith(("http://", "https://", "-", "$", "<", "/")):
            continue
        checked += 1
        path = REPO_ROOT / candidate
        assert path.exists(), f"README references a path that does not exist on disk: {candidate!r}"
    assert checked > 0, "no repo-relative (contains '/') backtick-quoted paths were found to check"


def test_readme_has_no_secret_shaped_strings():
    text = _read()
    for pattern in SECRET_PATTERNS:
        assert not pattern.search(text), (
            f"README contains a secret-shaped string matching /{pattern.pattern}/"
        )


def test_readme_scopes_the_eval_to_the_model_actually_tested():
    """§10.4 honesty, in its current shape.

    This test originally required the words "not a live eval", which was the
    honest statement while the table came from `--dry-run`. The table is now a
    real eval — of Gemini, because this project has no Anthropic partner-model
    entitlement. The requirement did not go away, it changed: a reader must
    not come away thinking these are Claude numbers, and D1's efficacy claim
    must be scoped to the model that was actually tested.
    """
    text = _read()
    assert re.search(r"gemini", text, re.I), "README must name the model the eval used"
    assert re.search(r"not\s+claude|describe\s+gemini|measures\s+gemini", text, re.I), (
        "README must say plainly that the eval's numbers are not about Claude"
    )
    assert re.search(r"D1[^.]{0,120}(model that was actually tested|claim about the model)", text, re.I), (
        "README must scope D1's measured efficacy to the model under test"
    )
    # And the part that is unaffected must be said too, or a reader
    # over-corrects and distrusts the deterministic results as well.
    assert re.search(r"D2 and D3 are deterministic", text, re.I)


def test_readme_names_the_cloud_run_instance_flags():
    """§7: --max-instances 1 keeps in-memory sessions consistent; the deploy
    story must be visible in the README, not only in DECISIONS.md."""
    text = _read()
    assert "--min-instances" in text, "README does not mention --min-instances"
    assert "--max-instances 1" in text, "README does not mention --max-instances 1"
