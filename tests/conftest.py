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
