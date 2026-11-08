"""Tooling feedback: on the Tools pages since 2026-11-04 (spec activity-jobs-
tools) — the full list on /tools, each tool's own on /tools/<name>; the
agent pages no longer carry it."""
import json
import re

from test_agent_tool_calls import _inv
from test_overview_console import _client, _healthy_agents, _iso

from heim.agents import agent_key_for


def _fb(s, inv, tool, text, mins=5):
    s.add_tool_feedback(inv, tool, text, created_at=_iso(mins))


def _seed(s):
    _healthy_agents(s)
    a = _inv(s, "investigator", 120, [("ssh_diagnostic", {"command": "df"}, False, 5)])
    b = _inv(s, "investigator", 60, [("ssh_diagnostic", {"command": "df"}, False, 5)])
    c = _inv(s, "security_auditor", 30, [("proxmox_api", {"path": "/x"}, False, 5)])
    _fb(s, a, "ssh_diagnostic", "old ssh idea", 100)
    _fb(s, b, "ssh_diagnostic", "newer ssh idea", 50)
    _fb(s, b, "nonexistent_tool", "stray note", 49)
    _fb(s, c, "proxmox_api", "audit wants storage paths", 20)


def test_agent_key_mapping():
    assert agent_key_for("investigator") == "investigator"
    assert agent_key_for("security_auditor") == "security"
    assert agent_key_for("nope") == ""


def test_store_reader_joins_agent_and_filters(tmp_path, monkeypatch):
    from heim.incidents.store import IncidentStore
    s = IncidentStore(tmp_path / "x.db")
    _seed(s)
    rows = s.tool_feedback_rows(limit=None)
    assert [r["suggestion"] for r in rows] == [
        "audit wants storage paths", "stray note", "newer ssh idea", "old ssh idea"]
    assert rows[0]["agent_name"] == "security_auditor" and rows[0]["investigation_id"] > 0
    assert len(s.tool_feedback_rows(limit=2)) == 2
    only = s.tool_feedback_rows(limit=None, agent_names=["security_auditor"])
    assert [r["tool"] for r in only] == ["proxmox_api"]
    assert s.tool_feedback_rows(limit=None, agent_names=[]) == []


def test_tools_page_panel(tmp_path, monkeypatch):
    html = _client(tmp_path, monkeypatch, _seed).get("/tools").text
    panel = html[html.index('aria-labelledby="h-fb"'):]
    assert "4 suggestions" in panel
    for col in ("Tool", "Suggestion", "Agent", "Investigation", "Age"):
        assert f'<th scope="col" class="label">{col}</th>' in panel
    rows = re.findall(r"<tr>.*?</tr>", panel, re.S)[1:]
    assert "audit wants storage paths" in rows[0]            # newest first
    assert 'href="/agents/auditor">Security auditor</a>' in rows[0]
    assert re.search(r'href="/investigations/\d+">investigation \d+</a>', rows[0])
    assert 'href="/agents/investigator">Investigator</a>' in rows[2]
    assert "All " not in panel                                # under the cap: no more link


def test_tools_page_empty_state(tmp_path, monkeypatch):
    html = _client(tmp_path, monkeypatch, _healthy_agents).get("/tools").text
    assert "No tooling feedback yet. Agents add it at the end of a report." in html
    assert "0 suggestions" in html


def test_tools_page_cap_and_all_view(tmp_path, monkeypatch):
    def seed(s):
        _healthy_agents(s)
        i = _inv(s, "investigator", 10, [("ssh_diagnostic", {"command": "df"}, False, 5)])
        for n in range(53):
            _fb(s, i, "ssh_diagnostic", f"idea {n:02d}", 9)
    client = _client(tmp_path, monkeypatch, seed)
    html = client.get("/tools").text
    panel = html[html.index('aria-labelledby="h-fb"'):]
    assert panel.count("investigation ") >= 50 and "idea 03" in panel and "idea 02" not in panel
    assert "All 53 suggestions" in panel and "53 suggestions" in panel
    full = client.get("/tools?feedback=all").text
    assert "idea 00" in full and "All 53" not in full


def test_tool_page_shows_its_own_feedback_newest_first(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, _seed)
    html = client.get("/tools/ssh_diagnostic").text
    fb = html[html.index('aria-labelledby="h-fb"'):]
    assert fb.index("newer ssh idea") < fb.index("old ssh idea")
    assert "audit wants storage paths" not in fb and "stray note" not in fb
    assert "audit wants storage paths" in client.get("/tools/proxmox_api").text


def test_general_feedback_is_on_the_tools_list(tmp_path, monkeypatch):
    html = _client(tmp_path, monkeypatch, _seed).get("/tools").text
    assert "Suggestion, general: nonexistent_tool: stray note" in html


def test_agent_pages_no_longer_carry_feedback(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, _seed)
    for path in ("/agents", "/agents/investigator", "/agents/auditor", "/jobs/uptime"):
        html = client.get(path).text
        assert 'aria-labelledby="h-fb"' not in html, path
        assert "Suggestion: " not in html and "Suggestion, general" not in html, path
        assert "newer ssh idea" not in html and "audit wants storage paths" not in html, path
    assert 'href="/tools"' in client.get("/agents/investigator").text
