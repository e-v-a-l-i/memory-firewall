"""`scripts/smoke.py` runs against a real server, so it is tested against one.

§10.5 asks for a smoke test after every deploy. A smoke test that cannot
fail is worse than none, so the second test here deliberately breaks an
expectation and requires a non-zero exit.
"""
import importlib.util
import socket
import subprocess
import sys
import textwrap
import time
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SMOKE_PATH = REPO_ROOT / "scripts" / "smoke.py"


@pytest.fixture(scope="module")
def live_server(tmp_path_factory):
    """A real uvicorn on an ephemeral port, with rate limiting turned low."""
    tmp = tmp_path_factory.mktemp("smoke")
    stub = tmp / "smoke_server.py"
    stub.write_text(
        textwrap.dedent(
            f"""
            import os, sys
            sys.path.insert(0, {str(REPO_ROOT)!r})
            os.environ["RATE_LIMIT_PER_MIN"] = "25"
            os.environ["DB_PATH"] = {str(tmp / "smoke.db")!r}
            import app
            application = app.app
            """
        )
    )
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "--app-dir", str(tmp),
         "smoke_server:application", "--host", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url + "/health", timeout=1).read()
            break
        except Exception:
            if proc.poll() is not None:
                raise AssertionError("smoke test server exited during startup")
            time.sleep(0.2)
    else:
        proc.terminate()
        raise AssertionError("smoke test server never became healthy")

    yield url
    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture(scope="module")
def smoke():
    spec = importlib.util.spec_from_file_location("smoke_script", SMOKE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["smoke_script"] = module
    spec.loader.exec_module(module)
    return module


def test_smoke_passes_against_a_healthy_server(smoke, live_server):
    assert smoke.main(["--url", live_server, "--expect-mode", "mock"]) == 0


def test_smoke_fails_when_an_expectation_is_wrong(smoke, live_server):
    """A smoke test that always passes is decoration."""
    assert smoke.main(
        ["--url", live_server, "--expect-mode", "live", "--skip-rate-limit"]
    ) == 1
