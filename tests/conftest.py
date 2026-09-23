"""Pytest configuration for the Memory Firewall test suite.

Ensures the repo root is on ``sys.path`` so ``import app`` works no matter
which directory pytest is invoked from, and provides a shared TestClient
fixture for tests that only care about the default (in-process) env.

Tests that need to control MODE (or other env vars) *before* app import runs
a subprocess instead of relying on this fixture, since import-time env
reads can't be un-done by monkeypatching an already-imported module. See
test_health.py for that pattern.
"""
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(scope="session")
def client():
    """A TestClient bound to the app, imported once for the whole session.

    Uses whatever MODE (if any) is present in this pytest process's own
    environment -- fine for assertions that don't pin a specific mode value.
    """
    from fastapi.testclient import TestClient

    import app as app_module

    return TestClient(app_module.app)


# --- M1 fixtures -----------------------------------------------------------
#
# Added for the M1 test suite (store/skills/clients/agent-loop). These read
# real repo fixtures (`data/`, `skills/`, `scenarios/`) rather than synthetic
# ones, per CLAUDE.md §10: M1's tests are meant to bind to the actual bundled
# data so a genuine data/implementation mismatch fails loudly instead of
# being hidden behind a mock. They deliberately do NOT exist yet during M0's
# red state and will raise (not skip) until the main session adds those
# files -- that's the expected failure mode, not a fixture bug.

DATA_DIR = REPO_ROOT / "data"
SKILLS_DIR = REPO_ROOT / "skills"
SCENARIOS_DIR = REPO_ROOT / "scenarios"


@pytest.fixture(scope="session")
def data_dir():
    """Path to the bundled synthetic data directory (`data/`)."""
    return DATA_DIR


@pytest.fixture(scope="session")
def skills_dir():
    """Path to the bundled skills directory (`skills/`)."""
    return SKILLS_DIR


@pytest.fixture
def s1_scenario():
    """The parsed S1 scenario fixture (`scenarios/s1_retrieval_hijack.yaml`).

    Tests use this instead of hardcoding the injection payload text, so they
    stay correct however the main session phrases the actual injected
    sentence -- the assertion is "the payload's own distinctive words are
    retrievable", not "this exact string appears".
    """
    import yaml

    path = SCENARIOS_DIR / "s1_retrieval_hijack.yaml"
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(autouse=True)
def _isolate_app_db():
    """Drop `app`'s cached DB around every test.

    `run_scenario` defaults to `session_id="default"` and a process-global
    in-memory DB, so a test that saves memory would otherwise be visible to
    every test that ran after it. No M1 test triggers that today, which is
    exactly why it is worth pinning now rather than debugging an
    order-dependent failure in M2.
    """
    import app as app_module

    app_module.reset_db()
    yield
    app_module.reset_db()
