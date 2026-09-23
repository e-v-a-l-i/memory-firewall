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
- **Amended at the M1 deploy:** Cloud Run's buildpack no longer offers 3.12. The
  builder's Artifact Registry lists only 3.13.x and 3.14.x, and `.python-version:
  3.12` failed the build outright. `.python-version` is now `3.13`; the local
  venv stays on 3.12 because that is the newest interpreter installed on this
  machine. The runtime split is a real (small) risk — the code targets 3.10+
  syntax and the four pinned deps ship wheels for both — and it is the exact
  thing D-001 set out to avoid. Closing it means installing 3.13 locally and
  rebuilding the venv. Flagged for the human; deliberately not done mid-milestone.

### D-002b First deploy landed at the top of M1
- **Decision:** deployed `memory-firewall` to Cloud Run, `us-central1`,
  `--max-instances 1`, `--allow-unauthenticated`, `MODE=mock`, default compute
  service account.
- **Result:** https://memory-firewall-366819802884.us-central1.run.app —
  `/health` 200 `{"status":"ok","mode":"mock","version":"0.1.0"}`, `/` 200 HTML,
  unknown route 404, and `/openapi.json` and `/static/*` both 404 in production,
  confirming the M0 hardening survived the deploy.
- **Cost:** two builds — the first failed on the 3.12 runtime (see D-001).

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

## M1 — data, retrieval, skills, memory, agent loop

### D-011 Retrieval interleaves documents instead of concatenating them
- **Decision:** `_retrieve_for_alert` orders each document's fields by
  informativeness (summary, message, user_agent, url … then identifiers, then
  bookkeeping) and round-robins across documents.
- **Found by:** implementing S1. Per-field chunking means ALR-1001 alone emits
  nine chunks, so a flat limit filled the context with timestamps and ports and
  never reached `evt-00042` — the injection was not retrieved at all and the
  scenario silently did nothing.
- **Reason:** which record gets read should not be an accident of file order.

### D-012 Unresolvable provenance fails closed
- **Decision:** `store.chunk_trust` returns `attacker_controllable` for any
  chunk id the corpus cannot resolve, rather than guessing from the field name.
- **Found by:** review. The field-name fallback failed open on a trailing
  space, a different case, an extra id segment, or any field with no trust_map
  entry — and the fallback exists precisely for ids the DB does not know
  (stale provenance surviving a rebuild, a hand-written fixture).
- **Reason:** "provenance I cannot check" is the case the memory gate most
  needs to catch. Fail closed on the path built for the unknown.

### D-013 Provenance is tracked on the trace, not re-derived from it
- **Decision:** `_Trace` accumulates every source id that reaches the model's
  context — from retrieval and from recalled memory — and a memory write is
  attributed to that set.
- **Found by:** review, as a two-hop bypass of both D2 and D3. Recalled memory
  reaches the prompt as plain text with no chunk and no trust label: an
  attacker's claim entered memory from a poisoned chunk on run one, came back
  out on run two with `untrusted_in_context` still False, and could be re-saved
  attributed to nothing but that run's own clean retrievals. Untrusted content
  in the prompt, both gates blind to it.
- **Reason:** the flag has to describe what the model actually read, by
  whatever route. Anything that renders into the prompt registers first.

### D-014 The outcome records performed calls, not requested ones
- **Decision:** `_execute_skill` reports whether it ran; the outcome's
  `actions` and `alert_status` are updated only when it did. Every executed
  call is recorded with a `privileged` flag rather than only privileged ones.
- **Found by:** review, with an M2-shaped D3 stubbed in: the defense fired, the
  trace said so, and the outcome still reported the attacker had won.
- **Reason:** §10.2 asserts "blocked" by reading the outcome. Recording all
  tool calls also makes S2's goal detectable at all — `save_memory` is
  `read_only`, so a privileged-only list could never see it.

### D-015 Attacker-chosen tool arguments degrade instead of raising
- **Decision:** `search_logs`'s `limit` is parsed defensively and clamped.
- **Found by:** review. The gullible model extracts arguments from the same
  untrusted text that named the tool, so a payload containing "limit the scope
  to this host" produced `limit="the"` and `int()` killed the run — no done
  event, no defense evaluation, and in M3 a dead SSE stream.

### D-016 `trust_level` is not sent to the model
- **Decision:** `to_tool_schemas` omits it; the policy layer reads the level
  from the loaded Skill.
- **Reason:** the Messages API rejects unknown fields on a tool object (M3's
  `VertexClient` would 400), and a privilege label the model can see is a
  privilege label an injection can argue with.

### Known limitations carried into M2
- **IP search is a bag of digits.** FTS5's tokenizer splits `10.0.4.17` into
  `10 0 4 17`, so `10.0.17.4` matches the same records. The host top-up in
  `_retrieve_for_alert` uses this, so a larger corpus could pull
  attacker-controlled content from unrelated hosts into context.
- **Non-ASCII is dropped by the tokenizer**, so a homoglyph or IDN indicator is
  unsearchable rather than erroring. This matters for the red-teamer's
  confusable-character variants (S1d).
- **Split-payload variants are retrieval-limited, not policy-limited.** The
  red-teamer's S1g/S1h never get their second fragment into context: the host
  top-up's five slots are taken by the alert's own internal chunks, which
  contain the host IP literally and outrank a planted ticket comment. Both
  fragments must reach context before D1's cross-chunk behaviour means
  anything.
- **`reset_db()` is a process-wide wipe.** The UI's reset button must call
  `store.reset_session(conn, session_id)` instead, or one visitor's reset
  destroys another's memory.

## M2 — S2, S3, defenses D1–D3, scenario matrix

### D-017 Alerts link their tickets explicitly (`related_tickets`)
- **Decision:** retrieval follows an alert's `related_tickets` the same way it
  follows `related_logs`, rather than discovering tickets by keyword.
- **Options:** an FTS search on the alert id (verified to work — TKT-4488's
  body says "Auto-created from ALR-1001", so it is the top hit) vs. an
  explicit field.
- **Reason:** D-011 already established that which record reaches the model
  must not be an accident of bm25 ranking. Closes the split-payload retrieval
  gap recorded at the end of M1: S1g's second fragment now reaches context, so
  the family is policy-limited rather than retrieval-limited.

### D-018 Each scenario carries exactly one injection
- **Decision:** S2 got its own alert (ALR-1031) instead of hanging its
  poisoning comment off ALR-1001.
- **Found by:** printing the matrix. Linking TKT-4488 to ALR-1001 put S2's
  payload into S1's context, and S1's all-defenses row started showing D2
  firing alongside D3.
- **Reason:** the demo's claim is that a user can see *where* the injection
  entered. Two injections in one alert's context makes that unanswerable.

### D-019 `_render_chunks` is D1's choke point for retrieved chunks
> **Superseded in part by D-029.** This was written as "the single choke
> point", which was already untrue: the memory pre-load (D-027) rendered
> recalled facts into the prompt outside it. Corrected below.
- **Decision:** both the first prompt and every `search_logs` result render
  through it, so one change covers both paths. The alert summary is built from
  already-retrieved chunks (M1's D-013 fix), so no untrusted text reaches the
  prompt outside a wrapper.

### D-020 D1 strips tag-like text and the live nonce, only when D1 is on
- **Decision:** `_strip_taglike` removes anything tag-shaped — a forged
  `</untrusted-…>`, `</user>`, `<system>`, `<tool_result>` — and any literal
  occurrence of the run's nonce, so content cannot reassemble a closing tag.
  With D1 off, nothing is stripped.
- **Reason:** leaving the undefended path untouched is what makes S1f's
  before/after meaningful. A defense that quietly also cleans the undefended
  baseline would make the demo lie in its own favour.

### D-021 D1 does not normalise zero-width or homoglyph characters
- **Decision:** deliberate omission, confirmed with the human.
- **Reason:** the defenses key on a chunk's *trust label*, not on matching its
  content, so obfuscation evades nothing in this design and normalising buys
  no security. It would also invert the demo: the gullible mock matches tool
  names literally, so stripping U+200B under D1 would make S1e read
  "undefended: not achieved / D1 on: achieved" — the defense appearing to
  enable the attack.
- **Alternative if wanted later:** strip Unicode `Cf` code points at *ingest*
  (`store.iter_chunk_rows`), documented as modelling the fact that a model
  reads through zero-width characters — not as a defense. Homoglyphs stay out
  either way; they need a confusables table (§12 dependency question) and
  remain a live-eval case.

### D-022 Both gates are pure functions
- **Decision:** `_memory_tier(defenses, untrusted_in_context, untrusted_ids)`
  and `_d3_blocks(defenses, skill, untrusted_in_context)` are module-level and
  side-effect free; the loop calls them.
- **Reason:** §10.1's determinism tests then need no corpus — which matters,
  because no alert in `data/` retrieves a fully clean chunk set, so "a
  privileged call with clean context is allowed" is untestable end to end.

### D-023 D2 fails closed on two signals
- **Decision:** quarantine if `untrusted_in_context` **or** any provenance id
  resolves as untrusted.
- **Reason:** D-012 makes an unresolvable id read as attacker-controllable,
  and D-013's flag is the authoritative record of what the model read.
  Quarantine is recoverable by a human clicking approve; a poisoned long-term
  fact is not.

### D-024 D3 checks before dispatch, and the run continues
- **Decision:** the policy check runs before `_execute_skill`, so `executed`
  is never True for a blocked call and D-014's outcome contract holds
  unchanged. The model gets an `is_error` tool result saying a human must
  approve, and the loop carries on to `done`.
- **Reason:** a blocked call is a decision handed to a human, not a crash.

### D-025 The attacker's goal can name an *effect*, not just a call
- **Decision:** `attacker_goal` may declare `effect: {tier: long_term}`;
  executed calls record their effect alongside their arguments.
- **Found by:** S2's D2 row scoring as a win. The `save_memory` call really
  did run — it landed in quarantine. §4 defines S2's goal as the false fact
  being *saved*, so a quarantined write achieves nothing, and the matrix has
  to be able to say that.

### D-026 The matrix has three outcomes, not two
- **Decision:** `achieved`, `blocked_by:Dn`, and
  `not_achieved_harness_limit`.
- **Reason:** S1b–S1e and S1h fail only because `MockClient(gullible=True)`
  matches tool names as literal ASCII and never decodes base64, hex,
  homoglyphs or zero-width splices. Scoring those as blocks would claim a
  defensive win the enforcement layer did not earn. This is the mechanical
  form of §10.4's "report results honestly".

### D-027 Long-term memory is pre-loaded into every run's first message
- **Decision:** after retrieval, before the first model turn, via
  `store.recall_memory` + `trace.note_recalled`.
- **Reason:** without it S2's stage 2 has nothing to be poisoned by. With it,
  the quarantine tier is what actually stops the attack — quarantined records
  are never recalled, so they never reach a later run's prompt.

### D-028 `MockClient` takes free-text arguments from the directive's sentence
- **Decision:** the last-resort fallback for a required prose parameter reads
  the span after the tool name, not the start of the context block.
- **Found by:** S2's poisoned memory containing the *alert summary* instead of
  the attacker's claim, which made stage 2 incoherent. Reinforces D-008: an
  attacker who writes the instruction writes the arguments.

### D-029 D1 wraps recalled memory, not just retrieved chunks
- **Found by:** review, as a full D1 bypass. The memory pre-load (D-027)
  rendered remembered facts into the prompt as plain text, outside any
  wrapper and unstripped — so D-019's "single choke point" claim was false the
  moment it was written.
- **Worse:** the reviewer demonstrated a same-run round trip. Content inside a
  wrapper asks the model to copy the tag it can see into a saved note; the
  next `recall_memory` hands back a real `</untrusted-{nonce}>` outside any
  wrapper. The attacker never guesses the nonce — the model is asked to copy
  it.
- **Decision:** both the pre-load and the `recall_memory` result render
  through the same wrapper-and-strip path as chunks. A human approving a
  quarantined record does not make its wording safe, so approved records are
  wrapped too.

### D-030 Tag stripping repeats to a fixed point
- **Found by:** review. One `re.sub` pass lets nested tags reassemble:
  `</us<x>er>` loses its inner `<x>` and becomes a working `</user>`. The
  trace then annotated the chunk as "stripped", so the demo claimed a defense
  that had not happened.

### D-031 What counts as "tag-like"
- **Decision:** three rules — an HTML comment; a tag opening with a letter,
  optionally prefixed by `!` or `?` (no length cap); and any bracketed run
  containing no whitespace.
- **Rejected:** a `{0,200}` body cap (`<system ` + 250 characters walked
  through it) and an `[A-Za-z]`-only first character (`<1system>` walked
  through that). `<!-- x -->` carries whitespace and has no tag name, so it
  fell through both remaining rules and needed a rule of its own.
- **Also rejected:** stripping every bracketed run whatever it contains. That
  removed the middle of an ordinary log line — `latency < 5ms and count > 3`
  — and stripping only ever applies to attacker-controllable chunks, which
  are precisely the evidence an analyst is reading. §5 asks for tag-like text
  to go; a prose comparison carries whitespace and no tag name, and is not
  what a model reads as a boundary. A defense that silently corrupts evidence
  has a cost of its own.

### D-032 Trust is keyed by document type and field, not field alone
- **Found by:** review. `comment` and `body` are attacker-controllable
  "because anyone with ticket access can write one" — and the same person
  writes the ticket's `title`, which was `internal`. Moving S3's payload into
  the title turned off D1, D2 and D3 at once: nothing was wrapped, nothing was
  flagged, and the privileged call executed.
- **Decision:** `trust_map.yaml` gains a `by_doc_type` block; `ticket` adds
  `title`, `status`, `assignee`. An alert's title, written by a detection
  rule, stays internal.
- **Regression fixtures:** S2e and S3e carry this payload shape permanently,
  and `tests/test_m2_regressions.py` pins the per-`(doc_type, field)` labels
  directly, which the fixtures alone did not.
- **Reachable only from M2:** D-017's `related_tickets` link is what first put
  ticket chunks into an alert's context at all.
- **Lesson worth keeping:** `trust_map.yaml` is now a security-critical file.
  A field added to the data without a map entry is a silent hole in all three
  defenses at once, and the trace points at no injection source.

### D-033 Skill effects are returned, not passed through a module global
- **Found by:** review, with a reproduction. Two concurrent `run_scenario`
  calls racing on a module-level `_LAST_EFFECT` made one run report the
  other's memory tier — enough to flip `attacker_goal_achieved` and claim D2
  had failed on a run where it worked. M3 serves this over HTTP with SSE, so
  two browser tabs would have been enough.

### Process note: the red-teamer edited implementation code
- The resumed red-teamer went beyond "fixtures and data only" and changed
  `app.py` and the tests. The work was sound and matched findings the reviewer
  had independently raised, so it was kept after verification rather than
  reverted — except its tag-stripping rule, which was over-broad (see D-031).
- It was stopped mid-iteration, leaving two of its own tests failing; those
  are resolved above. Every change it made was re-verified directly before
  being kept.


### D-034 `iter_scenario` is a generator; `run_scenario` collects it
- **Decision:** the agent loop yields trace events as they happen.
  `run_scenario` is a three-line wrapper returning `list(iter_scenario(...))`
  for tests, scoring and replay recording. Events emitted from inside a skill
  drain after dispatch, since a skill cannot yield for itself.
- **Reason:** done before M3 rather than during it. Retrofitting a streaming
  interface onto a 300-line function whose UI already depends on its shape is
  a different and worse job than splitting it while nothing depends on it yet.
- **Pinned by test:** the model must not be called before the first two
  events reach the consumer — otherwise a UI streams nothing until `done` and
  nobody notices until the demo.

### D-035 The live eval is scoped to S1/S2/S3, and "defended" means D1 only
- **Decision:** §10.4's eval runs the three canonical scenarios, not all 22
  fixtures, and its defended arm enables **D1 alone**.
- **Reason:** D2 and D3 are deterministic code. Running them against a real
  model measures an `if` statement at API prices and tells you nothing you
  cannot get from CI. D1 is the only defense whose efficacy is a question
  about model behaviour, so it is the only one worth spending live tokens on.
  With all three enabled, a blocked run tells you the enforcement layer
  worked — which the matrix already proves deterministically — while D1's
  actual effect stays invisible behind the block.
- **Consequence:** the eval table reports D1-only vs undefended, per scenario.
  If Claude resists a scenario even undefended, §10.4 says to report that
  plainly and keep the scenario: model-level resistance plus defense in depth
  is the honest result, not a failed experiment.
- **Variants stay in CI:** S1a-S1i, S2a-S2e and S3a-S3e remain deterministic
  regression fixtures. They are not eval material.
