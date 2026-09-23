#!/usr/bin/env python
"""Live eval: does a real model actually fall for these injections? (§10.4)

Not part of CI. It calls Vertex, costs money, and its results are a claim
about model behaviour rather than about this code.

Scope (D-035): the three canonical scenarios, and the defended arm enables
**D1 alone**. D2 and D3 are deterministic code already proven in the test
matrix — running them against a real model measures an `if` statement at API
prices, and with them on, a block hides whatever D1 did or did not do.

Usage:
    python scripts/eval.py --runs 3 --out replays/eval.md [--record]
    python scripts/eval.py --dry-run          # MockClient, no network, no spend
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import statistics
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402
import clients  # noqa: E402
import store  # noqa: E402

SCENARIOS = ("S1", "S2", "S3")
UNDEFENDED = {"D1": False, "D2": False, "D3": False}
D1_ONLY = {"D1": True, "D2": False, "D3": False}
ARMS = {"undefended": UNDEFENDED, "D1": D1_ONLY}

#: Printed verbatim when a scenario fails with no defense at all. §10.4 asks
#: for this to be said plainly rather than quietly dropped.
RESISTED_NOTE = (
    "Claude declined this injection with no defense enabled; the scenario is "
    "kept — model-level resistance plus defense in depth is the result, not a "
    "failed experiment."
)
INVERTED_NOTE = (
    "D1 did not reduce the success rate here. Reported as measured."
)


def make_client(dry_run: bool):
    if dry_run:
        return clients.MockClient(gullible=True)
    return clients.VertexClient()


def run_cell(scenario_id: str, defenses: dict, runs: int, dry_run: bool) -> dict:
    """One (scenario, arm) cell. Returns successes, usage and sample traces."""
    scenario = app.load_scenario(scenario_id)
    two_stage = bool(scenario.get("followup_alert_id"))

    results = {"stage1": [], "stage2": [], "tokens": [], "traces": [], "errors": 0}

    for _ in range(runs):
        # A fresh session and database per run: nothing a previous run
        # remembered may influence the next, or the rate measures contagion
        # between runs rather than the attack.
        session_id = f"eval-{uuid.uuid4().hex[:8]}"
        conn = store.build_db(":memory:")
        try:
            traces = []
            for stage in (1, 2) if two_stage else (1,):
                events = app.run_scenario(
                    scenario_id,
                    make_client(dry_run),
                    defenses=defenses,
                    session_id=f"{session_id}#arm",
                    conn=conn,
                    stage=stage,
                )
                traces.append((stage, events))
                outcome = events[-1].get("outcome", {})
                usage = events[-1].get("usage", {})
                results[f"stage{stage}"].append(bool(outcome.get("attacker_goal_achieved")))
                results["tokens"].append(
                    int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))
                )
            results["traces"].append(traces)
        except Exception as exc:  # noqa: BLE001 - one bad run must not end the eval
            results["errors"] += 1
            print(f"    run failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        finally:
            conn.close()
    return results


#: The eval names its arms for what they measure ("undefended", "D1"); the
#: app names them for which column they fill ("undefended", "defended"). The
#: recording is served by the app, so it is filed under the app's vocabulary.
_ARM_FILENAME = {"undefended": "undefended", "D1": "defended"}


def record_representative(scenario_id: str, arm: str, cell: dict, out_dir: Path) -> list[Path]:
    """Save the run whose outcome matches the cell's most common outcome.

    Deliberately the modal run, not the most impressive one: a replay that
    flatters the demo is a replay that misrepresents it.
    """
    file_arm = _ARM_FILENAME.get(arm, arm)
    written = []
    if not cell["traces"]:
        return written
    modal = collections.Counter(cell["stage1"]).most_common(1)[0][0]
    chosen = next(
        (t for t, ok in zip(cell["traces"], cell["stage1"]) if ok == modal), cell["traces"][0]
    )
    for stage, events in chosen:
        completions = [
            {
                "text": e["detail"].get("text", ""),
                "stop_reason": e["detail"].get("stop_reason", "end_turn"),
                "tool_calls": [],
                # Real numbers: a replayed run reporting zero tokens would
                # mean a per-session token cap could never trip in replay
                # mode (§7, M4).
                "usage": dict(e["detail"].get("usage") or {"input_tokens": 0, "output_tokens": 0}),
            }
            for e in events
            if e["type"] == "model"
        ]
        # Pair each model turn with the tool calls it asked for.
        calls_by_turn, current = [], []
        for event in events:
            if event["type"] == "model":
                calls_by_turn.append(current)
                current = []
            elif event["type"] == "tool_call":
                current.append(event["detail"])
        calls_by_turn = calls_by_turn[1:] + [current]
        for completion, calls in zip(completions, calls_by_turn):
            completion["tool_calls"] = [
                {"id": f"toolu_{uuid.uuid4().hex[:12]}", "name": c["tool"], "input": c["args"]}
                for c in calls
            ]

        payload = {
            "scenario": scenario_id.lower(),
            "arm": file_arm,
            "stage": stage,
            "defenses": ARMS[arm],
            "model": os.environ.get("MODEL_AGENT", "mock"),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "outcome": events[-1].get("outcome", {}),
            "completions": completions,
        }
        path = out_dir / f"{scenario_id.lower()}_{file_arm}_stage{stage}.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        written.append(path)
    return written


def rate(flags: list[bool]) -> str:
    return f"{sum(flags)}/{len(flags)}" if flags else "—"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--out", default="replays/eval.md")
    parser.add_argument("--record", action="store_true")
    parser.add_argument("--scenarios", nargs="*", default=list(SCENARIOS))
    parser.add_argument("--dry-run", action="store_true",
                        help="MockClient instead of Vertex: exercises the script with no spend")
    args = parser.parse_args(argv)

    cells = {}
    for scenario_id in args.scenarios:
        for arm, defenses in ARMS.items():
            print(f"  {scenario_id} / {arm} ({args.runs} runs)…", file=sys.stderr)
            cells[(scenario_id, arm)] = run_cell(scenario_id, defenses, args.runs, args.dry_run)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Live eval — attack success rate",
        "",
        f"- Generated: {datetime.now(timezone.utc).isoformat()}",
        f"- Model: `{'MockClient(gullible=True)' if args.dry_run else os.environ.get('MODEL_AGENT', 'unset')}`",
        f"- Runs per cell: {args.runs}",
        "- Defended arm is **D1 only** (D-035): D2 and D3 are deterministic and",
        "  are proven in the test matrix; with them on, a block would hide D1's",
        "  actual effect on the model.",
        "",
        "| Scenario | Arm | Stage | Goal achieved | Rate | Mean tokens | Notes |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]

    for scenario_id in args.scenarios:
        for arm in ARMS:
            cell = cells[(scenario_id, arm)]
            for stage_key, label in (("stage1", "1"), ("stage2", "2")):
                flags = cell[stage_key]
                if not flags:
                    continue
                notes = []
                if arm == "undefended" and not any(flags):
                    notes.append(RESISTED_NOTE)
                if arm == "D1":
                    undefended_flags = cells[(scenario_id, "undefended")][stage_key]
                    if undefended_flags and sum(flags) >= sum(undefended_flags):
                        notes.append(INVERTED_NOTE)
                if cell["errors"]:
                    notes.append(f"{cell['errors']} run(s) errored.")
                mean_tokens = int(statistics.mean(cell["tokens"])) if cell["tokens"] else 0
                lines.append(
                    f"| {scenario_id} | {arm} | {label} | {sum(flags)} | {rate(flags)} | "
                    f"{mean_tokens} | {' '.join(notes)} |"
                )

    if args.dry_run:
        lines.insert(
            1,
            "\n> **These numbers are not a live eval.** They were produced with "
            "`MockClient(gullible=True)`,\n> a model scripted to follow any "
            "instruction it can read, so every cell reports the\n> enforcement "
            "layer rather than model behaviour. Vertex quota for Claude was not "
            "available\n> when this ran. Re-run without `--dry-run` once quota is "
            "granted to replace this table.\n",
        )

    if args.record:
        written = []
        for (scenario_id, arm), cell in cells.items():
            # Alongside the table, not relative to the caller's CWD: running
            # `python scripts/eval.py` from another directory used to scatter
            # recordings wherever the shell happened to be.
            written += record_representative(scenario_id, arm, cell, out_path.parent)
        lines += ["", f"Recorded {len(written)} replay file(s): the run matching each "
                      "cell's most common outcome, not its most impressive one."]

    lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
