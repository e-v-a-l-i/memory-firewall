# Memory Firewall — decision log

Key tradeoffs, recorded as they are made (§12). Format:

`D-nnn | decision | options considered | reason`

## M0 — repo, skeleton, /health

### D-001 Python 3.12 in a dedicated venv
- **Decision:** `.venv` built from `/opt/homebrew/bin/python3.12`; `.python-version`
  pins `3.12` so the Cloud Run buildpack picks the same runtime.
- **Options:** use the system interpreter; pin 3.12 explicitly.
- **Reason:** system `python3` on this machine is 3.9.6. §2 specifies 3.12, and
  `str | None` syntax in `app.py` already requires it. Pinning avoids a class of
  "works locally, fails on deploy" surprises.

### D-002 First Cloud Run deploy moved to the top of M1
- **Decision:** M0 closes on a green local `/health`; the first deploy is M1's
  first task.
- **Options:** deploy inside M0 as §9 specifies and accept a ~10m overrun; defer.
- **Reason:** the planner estimated M0 at exactly its 20m box with the deploy as
  the riskiest item — a fresh project needs `run`, `cloudbuild` and
  `artifactregistry` APIs enabled plus a cold buildpack build (3-6m). Deferring
  protects the box while keeping "deploy early" intact: the live URL still
  arrives early, just inside M1.
- **Cost:** M0's demoable result is a local `/health`, not a live URL. M1 is the
  milestone most likely to overrun as a result.

### D-003 Four modules instead of §2's two
- **Decision:** `app.py` (API, agent loop, defenses, SSE), `clients.py` (model
  clients), `store.py` (SQLite: FTS5 retrieval + memory tiers), `skills.py`
  (skill loader).
- **Options:** keep everything in `app.py` per §2's layout.
- **Reason:** a deliberate deviation from the spec's layout, taken so M1's units
  are testable without importing the API layer. Retrieval and the skill loader
  are where the security-relevant invariants live (`trust` on every chunk,
  `trust_level` on every skill); they deserve direct unit tests.

### D-004 `MODE=mock` added as a third value
- **Decision:** `MODE` accepts `mock | replay | live`; unset or unrecognised
  resolves to `mock`.
- **Options:** §2's `live|replay` only, selecting `MockClient` implicitly by the
  absence of `GCP_PROJECT`.
- **Reason:** makes §11's "all tests pass with no network access" an explicit,
  inspectable mode rather than an implicit fallback. An unrecognised value falls
  back to `mock` rather than raising, because `mock` is the mode that cannot
  reach the network — a bad env var should degrade, not take the service down.

### D-005 Import-time side-effect freedom is a tested invariant
- **Decision:** importing `app` constructs no model client, opens no socket and
  writes no file. The DB is built on first use, not at import.
- **Options:** build the SQLite DB at import, as "DB built at startup from
  `data/`" (§2) suggests.
- **Reason:** every test in the suite imports the module; if import reached the
  network, the suite would need mocks everywhere and CI would be flaky. The M0
  test enforces this with a scrubbed-env subprocess that patches `socket.connect`
  and write-mode `open` to raise, so a future module-level `VertexClient()` fails
  loudly instead of silently hanging.

### D-006 Runtime and dev dependencies split
- **Decision:** `requirements.txt` holds only what Cloud Run needs
  (`fastapi`, `uvicorn[standard]`, `pyyaml`, `anthropic[vertex]`);
  `requirements-dev.txt` adds `pytest` and `httpx`.
- **Options:** one manifest.
- **Reason:** §12 requires asking before adding dependencies beyond §2. `httpx`
  is a transitive requirement of FastAPI's `TestClient`, not of the service;
  keeping it dev-only means the deployed image's dependency set is exactly what
  §2 specifies. `.gcloudignore` excludes `tests/` and the dev manifest.
- **Also noted:** `pyyaml` is not named in §2 either, but is implied by §4's
  `scenarios/*.yaml` and §3's SKILL.md frontmatter. It ships as a runtime dep.
- **Pins:** all four runtime deps are pinned with `==`. D-001 pins the
  interpreter; leaving the libraries floating would leave the more volatile half
  to resolve fresh at deploy time, and M3's `VertexClient` is written against
  whatever `anthropic[vertex]` the local venv has.

### D-006b `.gcloudignore` re-includes `.gitignore`
- **Decision:** `.gcloudignore` starts with `#!include:.gitignore` and restates
  the credential patterns (`.env*`, `*.pem`, `*key*.json`) below.
- **Reason:** found in review. When a `.gcloudignore` exists, gcloud uses it
  verbatim instead of the generated one that inherits `.gitignore`. Without the
  include, a local `.env` or downloaded service-account key would be git-ignored
  but still uploaded to Cloud Build and baked into the image — §7's "no secrets
  in the repo" violated without anything showing up in `git status`.

### D-006c The import-time guard is itself tested
- **Decision:** seven parametrized cases assert that AC1's guard actually fails
  on each side effect it claims to catch, plus one asserting it still passes a
  clean module.
- **Reason:** also found in review. The first guard patched `builtins.open`
  only, so `pathlib.Path.write_text`, `os.open`, and `sqlite3.connect` all sailed
  through — the exact shape of the DB-at-startup code M1 will write. A guard that
  catches nothing is indistinguishable from a clean app in the test report, so
  the guard needs its own failing case.

## M1 — planned decisions (not yet implemented)

### D-007 Trust is per-field, not per-document
- **Decision:** each data record yields several retrieval chunks;
  `data/trust_map.yaml` marks `user_agent`, `url`, `referer`, `dns_query`,
  `comment` and `filename` as `attacker_controllable`, everything else
  `internal`.
- **Reason:** this is what makes S1 legible in the trace — one chunk of an
  otherwise internal log line carries the injection, and the UI can point at it.

### D-008 `MockClient` has two modes
- **Decision:** scripted (deterministic unit tests) and "gullible" — follows any
  instruction it finds in context that names an available tool.
- **Options:** have each scenario YAML declare the tool call the mock emits.
- **Reason:** §10.2 wants the scenario matrix to test the enforcement layer, not
  model behavior. A gullible model makes a matrix failure mean the enforcement
  layer failed. The YAML-declared alternative is simpler but makes the test
  partly assert its own fixture.

### D-009 Memory tiers exist in M1; the D2 gate lands in M2
- **Decision:** the `tier`, `status` and `provenance` columns exist from the
  first schema; M1 always writes `long_term`.
- **Reason:** D2 then arrives as a policy change, not a schema migration.

### D-010 One trace event schema, two transports
- **Decision:** M1 returns the trace as a list of event dicts; M3 re-emits
  byte-identical objects over SSE. Every event carries `defense` and
  `untrusted_in_context` keys from M1, unfilled until M2.
- **Reason:** the UI and the tests read one shape, and M2 adds defenses without
  reshaping the trace.
