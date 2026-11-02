"""Tooling feedback on the Agents page and on each tool-calling agent's page."""
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


def test_agents_page_panel(tmp_path, monkeypatch):
    html = _client(tmp_path, monkeypatch, _seed).get("/agents").text
    panel = html[html.index('aria-labelledby="h-fb"'):]
    assert "4 suggestions" in panel
    for col in ("Tool", "Suggestion", "Agent", "Investigation", "Age"):
        assert f'<th scope="col" class="label">{col}</th>' in panel
    rows = re.findall(r"<tr>.*?</tr>", panel, re.S)[1:]
    assert "audit wants storage paths" in rows[0]            # newest first
    assert 'href="/agents/security">Security audit</a>' in rows[0]
    assert re.search(r'href="/investigations/\d+">investigation \d+</a>', rows[0])
    assert 'href="/agents/investigator">Investigator</a>' in rows[2]
    assert "All " not in panel                                # under the cap: no more link


def test_agents_page_empty_state(tmp_path, monkeypatch):
    html = _client(tmp_path, monkeypatch, _healthy_agents).get("/agents").text
    assert "No tooling feedback yet. Agents add it at the end of a report." in html
    assert "0 suggestions" in html


def test_agents_page_cap_and_all_view(tmp_path, monkeypatch):
    def seed(s):
        _healthy_agents(s)
        i = _inv(s, "investigator", 10, [("ssh_diagnostic", {"command": "df"}, False, 5)])
        for n in range(53):
            _fb(s, i, "ssh_diagnostic", f"idea {n:02d}", 9)
    client = _client(tmp_path, monkeypatch, seed)
    html = client.get("/agents").text
    assert html.count("investigation ") >= 50 and "idea 03" in html and "idea 02" not in html
    assert "All 53 suggestions" in html and "53 suggestions" in html
    full = client.get("/agents?feedback=all").text
    assert "idea 00" in full and "All 53" not in full


def test_agent_page_only_its_own_feedback(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, _seed)
    inv = client.get("/agents/investigator").text
    assert "audit wants storage paths" not in inv
    hist = inv[inv.index('aria-labelledby="h-tools"'):]
    # latest per tool under the summary row, with link + age
    assert re.search(r'class="tufb">.*?Suggestion: newer ssh idea.*?href="/investigations/\d+"',
                     hist, re.S)
    assert hist.count("Suggestion: ") == 1                    # not the older one
    assert "Suggestion, general: nonexistent_tool: stray note" in hist
    lst = hist[hist.index('<caption class="label">Tooling feedback'):hist.index("Calls, newest first")]
    assert lst.index("stray note") < lst.index("newer ssh idea") < lst.index("old ssh idea")
    assert "investigation " in lst
    sec = client.get("/agents/security").text
    assert "Suggestion: audit wants storage paths" in sec and "newer ssh idea" not in sec


def test_non_tool_agent_page_has_no_feedback(tmp_path, monkeypatch):
    html = _client(tmp_path, monkeypatch, _seed).get("/agents/uptime").text
    assert "Tooling feedback" not in html and "Suggestion" not in html


def test_agent_page_without_feedback_renders_no_list(tmp_path, monkeypatch):
    def seed(s):
        _healthy_agents(s)
        _inv(s, "investigator", 10, [("ssh_diagnostic", {"command": "df"}, False, 5)])
    html = _client(tmp_path, monkeypatch, seed).get("/agents/investigator").text
    assert "Tooling feedback" not in html


def test_feedback_for_configured_tool_not_in_recent_summary_is_not_general(tmp_path, monkeypatch):
    def seed(s):
        _healthy_agents(s)
        i = _inv(s, "investigator", 10, [("ssh_diagnostic", {"command": "df"}, False, 5)])
        _fb(s, i, "loki_query", "wants a label filter", 9)
        _fb(s, i, "made_up_tool", "who knows", 8)
    html = _client(tmp_path, monkeypatch, seed).get("/agents/investigator").text
    hist = html[html.index('aria-labelledby="h-tools"'):]
    assert "Suggestion, general: loki_query" not in hist
    assert "Suggestion, general: made_up_tool: who knows" in hist
    assert 'class="tufb"' not in hist.split("Calls, newest first")[0].split("Tooling feedback")[0]
    lst = hist[hist.index('<caption class="label">Tooling feedback'):hist.index("Calls, newest first")]
    assert "wants a label filter" in lst
