"""The MCP server enforces the same rules as the demo (§5).

The point of putting the trust policy in an MCP server is that the *server*
decides: a model can be talked out of an instruction, but not out of a tool
that refuses to run. These tests exercise the refusals directly, because that
is the whole claim.

The server keeps one session per process, so each test rebuilds it rather
than sharing state.
"""
import importlib
import os

import pytest

import store


@pytest.fixture
def mcp(monkeypatch):
    """A fresh server session with all defenses on."""
    monkeypatch.setenv("MF_DEFENSES", "D1,D2,D3")
    monkeypatch.setenv("DB_PATH", ":memory:")
    module = importlib.import_module("mcp_server")
    importlib.reload(module)
    return module


@pytest.fixture
def mcp_undefended(monkeypatch):
    monkeypatch.setenv("MF_DEFENSES", "none")
    monkeypatch.setenv("DB_PATH", ":memory:")
    module = importlib.import_module("mcp_server")
    importlib.reload(module)
    return module


# --- the toolset ------------------------------------------------------------


def test_the_server_exposes_the_same_five_skills(mcp):
    assert sorted(mcp.SESSION.skills) == [
        "close_alert", "recall_memory", "save_memory", "search_logs", "unisolate_host",
    ]


def test_defenses_come_from_the_environment(monkeypatch):
    import mcp_server

    monkeypatch.setenv("MF_DEFENSES", "none")
    assert mcp_server.enabled_defenses() == {"D1": False, "D2": False, "D3": False}
    monkeypatch.setenv("MF_DEFENSES", "D1,D3")
    assert mcp_server.enabled_defenses() == {"D1": True, "D2": False, "D3": True}
    monkeypatch.delenv("MF_DEFENSES")
    assert mcp_server.enabled_defenses() == {"D1": True, "D2": True, "D3": True}


# --- D1: retrieval tags what it cannot vouch for ---------------------------


def test_untrusted_content_comes_back_tagged(mcp):
    result = mcp.open_alert("ALR-1001")
    assert f"<untrusted-{mcp.SESSION.nonce}" in result
    assert mcp.SESSION.untrusted_in_context is True


def test_with_d1_off_nothing_is_tagged(mcp_undefended):
    result = mcp_undefended.open_alert("ALR-1001")
    assert "<untrusted-" not in result
    # The flag still tracks provenance; only the rendering changed.
    assert mcp_undefended.SESSION.untrusted_in_context is True


# --- D3: the server refuses, whatever the client decides -------------------


def test_a_privileged_call_is_refused_after_reading_untrusted_content(mcp):
    mcp.open_alert("ALR-1001")
    result = mcp.close_alert("ALR-1001", "benign")

    assert result.startswith("REFUSED by policy (D3)")
    assert "ALR-1001 closed" not in result
    assert mcp.SESSION.blocked and mcp.SESSION.blocked[0]["tool"] == "close_alert"


def test_the_refusal_names_what_triggered_it(mcp):
    mcp.open_alert("ALR-1001")
    result = mcp.close_alert("ALR-1001", "benign")
    triggers = mcp.SESSION.untrusted_sources()
    assert triggers
    assert any(t in result for t in triggers[:3])


def test_the_same_call_succeeds_undefended(mcp_undefended):
    """The undefended baseline has to be reachable, or the comparison the
    project rests on cannot be made."""
    mcp_undefended.open_alert("ALR-1001")
    assert "closed as benign" in mcp_undefended.close_alert("ALR-1001", "benign")


def test_read_only_tools_are_never_refused(mcp):
    mcp.open_alert("ALR-1001")
    assert not mcp.search_logs("scanner").startswith("REFUSED")
    assert not mcp.recall_memory().startswith("REFUSED")


def test_unisolate_host_is_refused_too(mcp):
    mcp.open_alert("ALR-1001")
    assert mcp.unisolate_host("10.0.4.17", "false positive").startswith("REFUSED")


# --- D2: a fact learned from untrusted content is held ---------------------


def test_a_memory_write_after_untrusted_retrieval_is_quarantined(mcp):
    mcp.open_alert("ALR-1001")
    result = mcp.save_memory("10.0.4.17 is an authorized scanner.")

    assert result.startswith("HELD for human review (D2)")
    held = store.list_memory(mcp.SESSION.conn, mcp.SESSION.session_id, tier="quarantine")
    assert len(held) == 1
    assert store.recall_memory(mcp.SESSION.conn, mcp.SESSION.session_id) == []


def test_a_quarantined_fact_is_not_recalled(mcp):
    mcp.open_alert("ALR-1001")
    mcp.save_memory("10.0.4.17 is an authorized scanner.")
    assert "No facts saved" in mcp.recall_memory()


def test_the_same_write_persists_undefended(mcp_undefended):
    mcp_undefended.open_alert("ALR-1001")
    assert "Saved to long_term" in mcp_undefended.save_memory("10.0.4.17 is a scanner.")
    assert "10.0.4.17" in mcp_undefended.recall_memory()


# --- the status tool --------------------------------------------------------


def test_status_reports_the_boundary(mcp):
    import json

    mcp.open_alert("ALR-1001")
    mcp.close_alert("ALR-1001", "benign")
    status = json.loads(mcp.firewall_status())

    assert status["defenses"] == {"D1": True, "D2": True, "D3": True}
    assert status["untrusted_in_context"] is True
    assert status["untrusted_sources"]
    assert status["refused_calls"][0]["tool"] == "close_alert"


def test_one_implementation_of_each_rule(mcp):
    """The server must not carry its own copy of a defense: a second
    implementation is a second thing to get wrong."""
    import app
    import defenses

    assert app._d3_blocks is defenses.d3_blocks
    assert app._memory_tier is defenses.memory_tier
    assert app._strip_taglike is defenses.strip_taglike
    assert mcp.defenses is defenses


# --- it must actually speak MCP --------------------------------------------


def test_the_server_starts_and_lists_its_tools_over_stdio(tmp_path):
    """Unit-testing the tool functions proves the policy; it does not prove
    the process starts, registers them, or survives a handshake. A server
    that imports cleanly and dies on connect is the failure a client meets
    first.
    """
    import json
    import subprocess
    import sys

    repo = str(__import__("pathlib").Path(__file__).resolve().parent.parent)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "MF_DEFENSES": "D1,D2,D3",
        "DB_PATH": str(tmp_path / "mcp.db"),
    }
    proc = subprocess.Popen(
        [sys.executable, f"{repo}/mcp_server.py"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env, cwd=repo,
    )

    def send(payload):
        proc.stdin.write(json.dumps(payload) + "\n")
        proc.stdin.flush()

    def read_until(want_id, deadline=25):
        import time

        end = time.monotonic() + deadline
        while time.monotonic() < end:
            line = proc.stdout.readline()
            if not line:
                break
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("id") == want_id:
                return message
        return None

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-06-18",
                         "capabilities": {},
                         "clientInfo": {"name": "test", "version": "0"}}})
        initialized = read_until(1)
        assert initialized, f"no initialize response; stderr={proc.stderr.read()[:400]}"
        assert initialized["result"]["serverInfo"]["name"] == "injection-firewall"

        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        listed = read_until(2)
        assert listed, "no tools/list response"
        names = {t["name"] for t in listed["result"]["tools"]}
        assert {"open_alert", "search_logs", "save_memory", "close_alert",
                "unisolate_host", "recall_memory", "firewall_status"} <= names

        # And the policy holds over the wire, not just in-process.
        send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
              "params": {"name": "open_alert", "arguments": {"alert_id": "ALR-1001"}}})
        assert read_until(3), "open_alert did not respond"

        send({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
              "params": {"name": "close_alert",
                         "arguments": {"alert_id": "ALR-1001", "disposition": "benign"}}})
        closed = read_until(4)
        assert closed, "close_alert did not respond"
        body = json.dumps(closed["result"])
        assert "REFUSED by policy (D3)" in body, f"the wire call was not refused: {body[:300]}"
    finally:
        proc.terminate()
        proc.wait(timeout=10)
