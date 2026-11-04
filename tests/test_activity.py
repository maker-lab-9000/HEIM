"""Activity: the map and the causal timeline (spec 2026-11-04-activity-jobs-tools).

The timeline nests a child under a parent only by an id recorded when the
child was created; nothing is matched up by time.
"""
from __future__ import annotations

from test_overview_console import _client, _healthy_agents, _iso

from heim.activity import MAP_EDGES, map_model, timeline


def hb(id_, agent, at, ok=True, error="", **detail):
    return {"id": id_, "agent": agent, "started_at": at, "finished_at": at, "ok": ok,
            "error": error, "detail": detail}


def inv(id_, parent, trigger="daily", agent="investigator", at="2026-11-04T07:05:00+01:00",
        host="ubuntu-server", status="complete", n_steps=9):
    return {"id": id_, "parent_run_id": parent, "trigger": trigger, "agent_name": agent,
            "started_at": at, "host": host, "status": status, "n_steps": n_steps,
            "model": "claude-sonnet-5-5"}


T7 = "2026-11-04T07:00:00+01:00"


def _keys(node):
    out = [node["key"]]
    for c in node.get("children") or []:
        out += _keys(c)
    return out


def test_daily_tree():
    nodes = timeline(
        [hb(1, "daily", T7)],
        {1: {"model_used": "deepseek/deepseek-v4.1-flash-1017",
             "attempts_json": '[{"ok": false}, {"ok": true}]', "counts_json": "{}"}},
        [inv(10, 1)],
        {1: [{"event": "new", "fingerprint": "ubuntu-server|mem|Mem", "severity": "warning",
              "host": "ubuntu-server"}]},
        {10: {"ssh_diagnostic": 6, "prometheus_query": 3}})
    assert len(nodes) == 1
    job = nodes[0]
    assert (job["kind"], job["key"]) == ("job", "daily")
    analyst = job["children"][0]
    assert (analyst["kind"], analyst["key"]) == ("agent", "analyst")
    assert "deepseek/deepseek-v4.1-flash-1017" in analyst["text"] and "fallback" in analyst["text"]
    kinds = [(c["kind"], c["key"]) for c in analyst["children"]]
    assert kinds == [("event", "ubuntu-server|mem|Mem"), ("agent", "investigator")]
    investigation = analyst["children"][1]
    assert "9 tool calls" in investigation["text"] and investigation["href"] == "/investigations/10"
    assert {c["key"] for c in investigation["children"]} == {"ssh_diagnostic", "prometheus_query"}


def test_poller_tree_with_escalation():
    nodes = timeline(
        [hb(2, "alert_poller", T7)], {}, [inv(11, 2, trigger="poller")],
        {2: [{"event": "escalated", "fingerprint": "homelab|disk|D", "severity": "critical",
              "host": "homelab"}]}, {})
    job = nodes[0]
    assert [c["kind"] for c in job["children"]] == ["event", "agent"]
    assert "escalated" in job["children"][0]["text"]


def test_security_tree():
    nodes = timeline([hb(3, "security", T7)], {},
                     [inv(12, 3, trigger="security_audit", agent="security_auditor")], {}, {})
    assert nodes[0]["children"][0]["key"] == "auditor"


def test_unlinked_and_legacy_rows_top_level_labelled():
    nodes = timeline([], {}, [inv(20, 0, trigger="manual"),
                              inv(21, 0, trigger="dashboard", at="2026-11-04T08:00:00+01:00"),
                              inv(22, 0, trigger="daily", at="2026-11-04T06:00:00+01:00"),
                              inv(23, 99, trigger="poller", at="2026-11-04T05:00:00+01:00")],
                     {}, {})
    assert [n["href"] for n in nodes] == ["/investigations/21", "/investigations/20",
                                         "/investigations/22", "/investigations/23"]
    assert "dashboard" in nodes[0]["text"] and "manual" in nodes[1]["text"]
    assert "started before run links were recorded" in nodes[2]["text"]
    assert "outside" in nodes[3]["text"]


def test_filter_by_part_keeps_ancestors():
    args = ([hb(1, "daily", T7), hb(2, "alert_poller", "2026-11-04T07:10:00+01:00")],
            {1: {"model_used": "m", "attempts_json": "[]"}}, [inv(10, 1)], {},
            {10: {"ssh_diagnostic": 2}})
    nodes = timeline(*args, part="ssh_diagnostic")
    assert len(nodes) == 1 and nodes[0]["key"] == "daily"
    assert "ssh_diagnostic" in _keys(nodes[0])
    assert [n["key"] for n in timeline(*args, part="alert_poller")] == ["alert_poller"]
    assert [n["key"] for n in timeline(*args, part="analyst")] == ["daily"]


def test_filter_with_no_match_is_empty():
    assert timeline([hb(1, "daily", T7)], {}, [], {}, {}, part="backup") == []


def test_kind_filters():
    beats = [hb(1, "daily", T7), hb(2, "alert_poller", "2026-11-04T07:10:00+01:00"),
             hb(3, "backup", "2026-11-04T03:30:00+01:00")]
    invs = [inv(10, 1), inv(20, 0, trigger="manual", at="2026-11-04T09:00:00+01:00")]
    triggered = timeline(beats, {}, invs, {}, {}, kind="triggered")
    assert [n["key"] for n in triggered] == ["daily"]
    jobs = timeline(beats, {}, invs, {}, {}, kind="jobs")
    assert {n["kind"] for n in jobs} == {"job"} and len(jobs) == 3
    agents = timeline(beats, {}, invs, {}, {}, kind="agents")
    assert {n["kind"] for n in agents} == {"agent"}
    assert {n["href"] for n in agents} == {"/investigations/10", "/investigations/20"}


def test_paused_heartbeat_reads_paused():
    nodes = timeline([hb(1, "backup", T7, paused=True, until="2026-11-04T08:00:00+01:00")],
                     {}, [], {}, {})
    assert nodes[0]["word"] == "Paused" and nodes[0]["lamp"] == "paused"


def test_quiet_runs_collapse():
    beats = [hb(i, "alert_poller", f"2026-11-04T07:{55 - 5 * i:02d}:00+01:00", hosts=4)
             for i in range(1, 6)]
    beats.insert(2, hb(9, "alert_poller", "2026-11-04T07:42:00+01:00", ok=False, error="boom"))
    nodes = timeline(beats, {}, [], {}, {})
    assert [n.get("count", 1) for n in nodes] == [2, 1, 3]
    assert "2 quiet runs" in nodes[0]["text"] and nodes[1]["word"] == "Failed"


def test_map_edges_follow_agent_yaml(tmp_path, monkeypatch):
    from test_tools_pages import _cfg
    cfg = _cfg(tmp_path)
    m = map_model(cfg, {})
    assert [b["key"] for b in m["jobs"]] == ["daily", "alert_poller", "thresholds", "uptime",
                                            "security", "backup"]
    assert [b["key"] for b in m["agents"]] == ["analyst", "investigator", "auditor"]
    assert {b["key"] for b in m["tools"]} == set(cfg.tools)
    assert ("daily", "analyst") in MAP_EDGES and ("security", "auditor") in MAP_EDGES
    for t in cfg.agents["investigator"].tools:
        assert ("investigator", t) in m["edges"]
    assert ("auditor", "ssh_diagnostic") not in m["edges"]
    auditor = next(b for b in m["agents"] if b["key"] == "auditor")
    assert "proxmox_api" in auditor["feeds"]


# -------------------------------------------------------------------- route


def _seed(s):
    _healthy_agents(s)
    rid = s.start_agent_run("daily", _iso(60))
    s.finish_agent_run(rid, _iso(58), True, "", {"queries": 50})
    s.insert_run(kind="daily", run_at=_iso(60), agent_run_id=rid, model_used="claude-opus-5-5")
    i = s.create_investigation(host="ubuntu-server", agent_name="investigator", trigger="daily",
                               status="complete", started_at=_iso(57), finished_at=_iso(50),
                               parent_run_id=rid, n_steps=1)
    s.add_step(i, 1, "ssh_diagnostic", '{"command": "df"}', blocked=False, duration_ms=5)
    s.add_incident_events(rid, _iso(59), [{"fingerprint": "ubuntu-server|mem|Mem",
                                           "event": "new", "severity": "warning",
                                           "host": "ubuntu-server"}])


def test_activity_page_renders_map_and_timeline(tmp_path, monkeypatch):
    html = _client(tmp_path, monkeypatch, _seed).get("/activity").text
    assert "<title>Activity" in html and 'id="h-map"' in html and 'id="h-timeline"' in html
    for href in ("/activity?part=daily", "/activity?part=analyst", "/activity?part=ssh_diagnostic"):
        assert href in html, href
    tl = html[html.index('id="h-timeline"'):]
    assert tl.index("Daily analysis") < tl.index("Daily analyst") < tl.index("ubuntu-server|mem|Mem")
    assert 'href="/investigations/' in tl


def test_activity_part_filter_link_toggles(tmp_path, monkeypatch):
    html = _client(tmp_path, monkeypatch, _seed).get("/activity?part=daily").text
    m = html[html.index('id="h-map"'):html.index('id="h-timeline"')]
    box = m[m.index("Daily analysis") - 300:m.index("Daily analysis")]
    assert 'href="/activity"' in box or "href=\"/activity?\"" in box
    assert "Alert poller" not in html[html.index('id="h-timeline"'):]


def test_activity_empty_part_shows_empty_state(tmp_path, monkeypatch):
    r = _client(tmp_path, monkeypatch, _seed).get("/activity?part=backup&kind=triggered")
    assert r.status_code == 200 and "Nothing ran" in r.text
