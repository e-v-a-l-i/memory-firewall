"""Memory Firewall — FastAPI application.

M0 scope: the skeleton only. `/health` reports liveness and the resolved run
mode; `/` serves the static placeholder page. The agent loop, retrieval,
memory tiers and defenses (D1-D3) land in M1 and M2.

Import-time contract: importing this module must be side-effect free. No
model client is constructed, no network call is made, and nothing is written
to disk until a request arrives. Every test in the suite depends on this, and
it is what lets the module be imported with no environment configured at all.
"""
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

VERSION = "0.1.0"

#: Run modes. `live` calls Vertex, `replay` serves recorded runs, and `mock`
#: drives the scripted MockClient used by local dev and CI. §2 of the spec
#: names only live|replay; `mock` is an approved addition so that "all tests
#: pass with no network access" (§11) is an explicit mode rather than an
#: implicit fallback.
MODES = frozenset({"mock", "replay", "live"})
DEFAULT_MODE = "mock"

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


def resolve_mode(raw: str | None = None) -> str:
    """Resolve the run mode from `MODE`, falling back to `mock`.

    An unrecognised value falls back to `mock` rather than raising: an
    unparseable mode should not take the service down, and `mock` is the
    mode that cannot reach the network.
    """
    value = (raw if raw is not None else os.environ.get("MODE", "")).strip().lower()
    return value if value in MODES else DEFAULT_MODE


#: `openapi_url=None` alongside the docs routes: once M1 and M2 add run,
#: approve and reject routes, a public schema hands an attacker the tool
#: surface for free. Nothing in the demo needs it.
app = FastAPI(
    title="Memory Firewall",
    version=VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

#: `static/` is deliberately NOT mounted as a directory. §2 calls for one
#: `index.html`, served below by an explicit route, so a replay dump or
#: scratch fixture dropped into `static/` later cannot be fetched.


@app.get("/health")
def health() -> dict:
    """Liveness plus the mode the service is actually running in.

    Read at request time, not import time, so the deployed service reports
    the mode Cloud Run gave it without a restart-order dependency.
    """
    return {"status": "ok", "mode": resolve_mode(), "version": VERSION}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
