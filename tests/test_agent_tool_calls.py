"""Tool calls on the Agents table and the per-agent tool history.

A step has no clock, so a call is dated by its investigation's start; the
window is live/24h (last 24 hours) or 7d.
"""
import json
import re

from test_overview_console import _agents, _client, _healthy_agents, _iso, _rows

from heim.agents import short_args, tool_summary


def _inv(s, name, minutes_ago, steps):
    """steps: list of (tool, args dict, blocked, duration_ms)."""
    i = s.create_investigation(fingerprint="h|q|n", host="ubuntu-server", agent_name=name,
                               trigger="daily", status="complete",
                               started_at=_iso(minutes_ago), finished_at=_iso(minutes_ago - 1))
    for n, (tool, args, blocked, ms) in enumerate(steps):
        s.add_step(i, n, tool, json.dumps(args), blocked=blocked, duration_ms=ms)
    return i


def _row(html, name):
    return next(r for r in _rows(_agents(html)) if name in r)


def _seed(s):
    _healthy_agents(s)
    _inv(s, "investigator", 60, [("ssh_diagnostic", {"command": "df -h"}, False, 100)] * 3
         + [("ssh_diagnostic", {"command": "rm"}, True, 5)])      # 4 calls, 1 blocked, in 24h
    _inv(s, "investigator", 60 * 24 * 3, [("prometheus_query", {"promql": "up"}, False, 50)] * 5)
    _inv(s, "security_auditor", 60 * 24 * 2, [("proxmox_api", {"path": "/x"}, False, 20)] * 2)


def test_counts_follow_the_window(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, _seed)
    for url in ("/agents", "/agents?window=24h"):          # live counts the last 24 h
        html = client.get(url).text
        cell = re.search(r'<td class="num">(.*?)</td>', _row(html, "Investigator"), re.S).group(1)
        assert re.sub(r"<[^>]+>", "", cell) == "4 · 1 blocked"
        assert re.search(r'<td class="num">0</td>', _row(html, "Security audit"))
    week = client.get("/agents?window=7d").text
    assert re.search(r'<td class="num">9<span class="ink3"> · 1 blocked</span></td>',
                     _row(week, "Investigator"))
    assert re.search(r'<td class="num">2</td>', _row(week, "Security audit"))
    assert "Tool calls" in client.get("/").text


def test_non_tool_agents_show_a_dash(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, _seed)
    panel = _agents(client.get("/agents").text)
    for name in ("Alert poller", "Threshold watch", "Uptime monitor", "Daily analysis",
                 "Backup verifier"):
        assert 'title="this agent does not call tools">—</td>' in _row(
            client.get("/agents").text, name)
    assert panel.count('title="this agent does not call tools"') == 5


def test_history_is_capped_at_fifty_newest_first(tmp_path, monkeypatch):
    def seed(s):
        _healthy_agents(s)
        _inv(s, "investigator", 600, [("ssh_diagnostic", {"command": f"old{n}"}, False, 1)
                                     for n in range(40)])
        _inv(s, "investigator", 30, [("loki_query", {"logql": f"new{n}"}, n == 3, 7)
                                    for n in range(30)])
        _inv(s, "security_auditor", 20, [("proxmox_api", {"path": "/a"}, False, 1)])

    html = _client(tmp_path, monkeypatch, seed).get("/agents/investigator").text
    hist = html[html.index('aria-labelledby="h-tools"'):]
    calls = _rows(hist[hist.index("Calls, newest first"):])
    assert len(calls) == 50
    assert "new29" in calls[0] and "old" not in "".join(calls[:30])
    assert "path=/a" not in "".join(calls)                      # the auditor's calls are not here
    assert 'class="word crit">blocked</span>' in calls[26]  # new3, 4th oldest of the 30
    assert sum('word crit' in c for c in calls) == 1
    assert 'href="/investigations/' in calls[0]
    stats = _rows(hist[:hist.index("Calls, newest first")])
    assert "30" in stats[0] and "loki_query" in stats[0]
    assert "20" in stats[1] and "ssh_diagnostic" in stats[1]


def test_non_tool_agent_page_says_so(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, _seed)
    assert "This agent does not call tools." in client.get("/agents/alert_poller").text
    assert "This agent does not call tools." not in client.get("/agents/investigator").text
    assert "Tool history" in client.get("/agents/security").text


def test_short_args():
    assert short_args("ssh_diagnostic", '{"command": "df -h"}') == ("df -h", "df -h")
    assert short_args("prometheus_query", '{"promql": "up{job=\\"a\\"}", "range": "1h"}')[0] == 'up{job="a"}'
    assert short_args("proxmox_api", '{"path": "/nodes", "n": 2}')[0] == "path=/nodes n=2"
    long = "x" * 200
    short, full = short_args("ssh_diagnostic", json.dumps({"command": long}))
    assert len(short) == 80 and short.endswith("…") and full == long
    assert short_args("ssh_diagnostic", "not json")[0] == "not json"
    assert short_args("ssh_diagnostic", "") == ("", "")


def test_tool_summary():
    rows = tool_summary([{"tool": "a", "blocked": 1, "duration_ms": 10},
                         {"tool": "b", "blocked": 0, "duration_ms": 5},
                         {"tool": "a", "blocked": 0, "duration_ms": 30}])
    assert rows == [{"tool": "a", "calls": 2, "blocked": 1, "avg_ms": 20.0},
                    {"tool": "b", "calls": 1, "blocked": 0, "avg_ms": 5.0}]
