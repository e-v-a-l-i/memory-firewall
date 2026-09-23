"""The synthetic corpus has to hold together (CLAUDE.md §3).

Added after a duplicate id went unnoticed: two different alerts shared
`ALR-1041`, so retrieval silently merged them and a scenario pulled in a
ticket belonging to someone else's fixture. Nothing failed — the demo just
quietly showed the wrong evidence, which is the worst outcome for a project
whose subject is knowing where content came from.
"""
import json
from collections import Counter
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _records(name):
    path = DATA_DIR / f"{name}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@pytest.fixture(scope="module")
def corpus():
    return {name: _records(name) for name in ("alerts", "logs", "tickets")}


def test_every_line_parses_and_carries_an_id_and_doc_type(corpus):
    for name, records in corpus.items():
        for record in records:
            assert record.get("id"), f"{name}: record with no id"
            assert record.get("doc_type"), f"{name}: {record['id']} has no doc_type"


def test_ids_are_unique_within_each_file(corpus):
    for name, records in corpus.items():
        dupes = [i for i, c in Counter(r["id"] for r in records).items() if c > 1]
        assert not dupes, f"{name}: duplicate ids {dupes}"


def test_ids_are_unique_across_the_whole_corpus(corpus):
    """Chunk ids are `doc_type:doc_id:field`, so a collision across files
    would produce two chunks claiming the same identity."""
    everything = [r["id"] for records in corpus.values() for r in records]
    dupes = [i for i, c in Counter(everything).items() if c > 1]
    assert not dupes, f"duplicate ids across files: {dupes}"


def test_every_related_reference_resolves(corpus):
    """A dangling `related_logs` or `related_tickets` entry means a scenario
    silently retrieves less evidence than its fixture claims."""
    log_ids = {r["id"] for r in corpus["logs"]}
    ticket_ids = {r["id"] for r in corpus["tickets"]}
    for alert in corpus["alerts"]:
        for ref in alert.get("related_logs") or []:
            assert ref in log_ids, f"{alert['id']} references missing log {ref}"
        for ref in alert.get("related_tickets") or []:
            assert ref in ticket_ids, f"{alert['id']} references missing ticket {ref}"


def test_every_scenario_points_at_an_alert_that_exists(corpus):
    import yaml

    alert_ids = {r["id"] for r in corpus["alerts"]}
    scenarios = Path(__file__).resolve().parent.parent / "scenarios"
    for path in sorted(scenarios.glob("*.yaml")):
        fixture = yaml.safe_load(path.read_text())
        assert fixture["alert_id"] in alert_ids, (
            f"{path.name} points at missing alert {fixture['alert_id']}"
        )
        followup = fixture.get("followup_alert_id")
        if followup:
            assert followup in alert_ids, (
                f"{path.name} points at missing follow-up alert {followup}"
            )
