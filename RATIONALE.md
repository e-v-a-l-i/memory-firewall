# Design rationale

## The problem, and why it isn't obvious

An agent with retrieval, memory and tools has no way to tell the difference
between *what it read* and *what it was told*. Everything arrives as text in
one context window. A log line, a ticket comment, a remembered fact and its
own operator's instructions are the same substance by the time the model sees
them.

The obvious framing is "stop the model from being fooled." That framing leads
to better prompts, and better prompts lose. The non-obvious framing — the one
this project is built on — is that **the model's judgement is the wrong place
to put the control**. What you can control is what a piece of text is
*permitted to cause*, based on where it came from.

So the primitive here is not a filter. It's a label that travels: every
retrieved chunk carries `source` and `trust`, and that label propagates into
memory provenance and into tool-call decisions. The defenses are three
different answers to one question — *what may text from an untrusted origin be
allowed to do?*

A SOC triage agent is the setting because the stakes are legible without
domain expertise: a log field tells the agent to close a real alert, and it
does. You don't need to know what LSASS is to see that something went wrong.

## What the demo actually shows

Two columns, same alert, same model, same injected text; only the defenses
differ. The server forces the left column's defenses off regardless of the
request, so the baseline can't be quietly altered — a control arm you can
tamper with is a control arm that can lie.

Four cases, chosen so each teaches something different:

- **S1 — text becomes action.** An instruction in a log's user-agent closes
  the alert.
- **S2 — a belief persists.** A ticket comment is saved as a durable fact;
  the *next* alert on that host is dismissed because of it. Nothing in the
  second run is poisoned. It just believes what the first run wrote down.
- **S4 — the cost.** No attacker at all. An authorised scan that should be
  closed, and D3 refuses it. Across this corpus, **25 of 26 alerts retrieve
  at least one attacker-controllable chunk**, so D3 does not distinguish an
  attacked run from a normal one: it blocks essentially every privileged
  action. The one alert it leaves alone is S5's — the one where the attack
  succeeds, because the label is wrong.
- **S5 — the label was wrong.** The same payload moved into a field the trust
  map calls internal. It succeeds with every defense enabled — not because
  one was bypassed, but because none engaged.

S4 and S5 exist because a demo that only shows its defenses winning is an
advertisement. The first question anyone serious asks is "what does this
break, and when does it not fire" — and both answers were already latent in
the system, unmeasured.

## Key decisions and tradeoffs

**D1 is probabilistic; D2 and D3 are code.** Spotlighting wraps untrusted
chunks in per-run nonce tags and tells the model they're data. Whether the
model listens is a question about the model, so it's measured by eval and
never asserted in CI. D2 (a memory write made with untrusted content in
context is quarantined) and D3 (a privileged tool called with untrusted
content in context doesn't execute) are deterministic, and they're what the
test suite actually guarantees. Mixing those two kinds of claim is the main
way this sort of work overstates itself.

**The test model is scripted to obey everything it reads.** A "gullible"
mock means a scenario-matrix failure is always the enforcement layer's fault
and never the model's mood. It also makes every CI claim independent of which
provider serves live traffic — which is why swapping the live model mid-build
changed the eval and nothing else.

**Replays record model completions, not traces.** Retrieval, the nonce,
the gates and the policy all re-execute on a replayed run; only what the model
*said* comes off disk. A frozen trace would have made the offline mode a video
of the demo instead of the demo, with the toggles inert.

**Three outcomes, not two.** "Attack not achieved" is not "defended". The
model may simply have declined, or the harness may be unable to drive the
payload. That distinction has its own vocabulary in the scenario matrix
(`not_achieved_harness_limit`), in the eval (`no_response` counted apart from
refusals), and in the UI (an amber verdict that says nothing stopped it). Each
of those was added after the conflation was caught making the system look
better than it was.

**Enforcement lives in a server, not a prompt.** The same defenses ship as an
MCP server, so the agent under attack can be someone else's client and the
policy still holds. A model can be talked out of an instruction; it cannot be
talked out of a tool that refuses to execute. Both surfaces import the *same*
functions — a test asserts they are the same objects, and it caught a
divergence the moment one appeared.

## What I'd do next

1. **Make the render path the only path.** Three of the six defense bypasses
   found in review were new routes into the prompt that skipped provenance —
   the memory pre-load, the alert summary, a recall result. That's
   architectural, not a review checklist item.
2. **Treat the trust map as code.** S5 shows one misclassified field disabling
   all three defenses. It wants schema-level provenance — fields the collector
   *composed* versus fields it *copied* — rather than a name-matching list.
3. **Make D3 discriminating.** Blocking every privileged action is a defensible
   demo posture and an untenable product. The useful version keys on whether
   the untrusted content plausibly *motivated* this specific call, which is a
   much harder question and the right next problem.
4. **Larger evals.** Two 3-run evals of the same suite disagreed by up to 33
   points. At n=10 the direction is stable; the confidence interval is still
   wide, and a claim about a probabilistic defense needs more than one table.

## What this doesn't claim

- **The eval measures Gemini, not Claude.** The project has no Anthropic
  partner-model entitlement on this cloud account, so live runs are served by
  Gemini 2.5 Flash. `VertexClient` is implemented and tested; one environment
  variable switches back. Those numbers describe the model that was tested.
- **D1's measured effect is directional, not precise.** S1 5/10 → 2/10 with
  spotlighting on; S2 9/10 → 6/10 and 3/10 → 1/10 across its two stages.
- **The MCP server needs local installation**, so it's an extension of the
  hosted prototype rather than part of it.
- **Nothing here is a product.** It's an argument, made executable: that the
  enforcement layer is the part that has to be real, and the way to show that
  is to write the attacks first and let them win.
