"""The console overview (redesign 2026-11-01): the four instrument cards, Needs
attention with what HEIM is doing about each row, Needs you, and the Agents
panel, all above the overview's existing blocks.

Fixtures follow tests/test_dashboard_system.py: the committed example config
and a temp store seeded before the app starts. Times are relative to the real
clock because the app reads it.
"""
import json
import re
from datetime import datetime, timedelta, timezone
from importlib.metadata import version

import pytest
from fastapi.testclient import TestClient

from heim.dashboard import format as fmt
from heim.dashboard.app import create_app
from heim.incidents.store import IncidentStore
from test_dashboard import _config, _seed

UPTIME_URL = "http://10.0.0.10:3001"

PHYSICAL_REPORT = """## Summary
The jellymedia SSD ran hot; the enclosure fan reports 0 RPM.

## Remediation
1. Look at the dashboards again tomorrow.
2. Check the USB enclosure fan by hand.

## Confidence
Medium.
"""

REMOTE_REPORT = """## Summary
Zigbee radio dropped off twice.

## Remediation
1. Ask the operator whether the coordinator firmware was updated.

## Confidence
Low.
"""


def _iso(minutes_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat(
        timespec="milliseconds")


def _client(tmp_path, monkeypatch, seed, *, uptime: bool = True) -> TestClient:
    cfg = _config(tmp_path, monkeypatch)
    if uptime:                       # the example config leaves Uptime Kuma off
        cfg.settings.uptime_kuma.url = UPTIME_URL
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    store = IncidentStore(db)
    seed(store)
    store.close()
    return TestClient(create_app(cfg))


def _beat(store, agent, minutes_ago, ok=True, error="", detail=None):
    store.record_agent_run(agent, _iso(minutes_ago), _iso(minutes_ago), ok, error, detail)


def _healthy_agents(store, *, backup_minutes=60):
    """Every recorded agent fresh (the backup's age is the knob), and one
    complete investigation so the investigator reads Idle rather than No data."""
    for m in (22, 17, 12, 7, 2):
        _beat(store, "alert_poller", m, detail={"hosts": 4})
        _beat(store, "thresholds", m, detail={"queries": 50})
        _beat(store, "uptime", m, detail={"monitors": 45, "report_only": 15})
    _beat(store, "daily", 120, detail={"queries": 49, "hosts": 4})
    _beat(store, "security", 60 * 24 * 2, detail={"checks": 47})
    _beat(store, "backup", backup_minutes, detail={"backup_file": "heim-20261101.sqlite3"})
    store.create_investigation(fingerprint="ubuntu-server|cpu|Load", host="ubuntu-server",
                               agent_name="investigator", trigger="daily", status="complete",
                               started_at=_iso(300), finished_at=_iso(290))


def _incident(fp, host, severity, minutes_old, description, status="open"):
    return {"fingerprint": fp, "host": host, "metric": fp.split("|")[2] or fp.split("|")[1],
            "severity": severity, "status": status, "firstSeen": _iso(minutes_old),
            "lastSeen": _iso(1), "timesSeen": 2, "missedRuns": 0,
            "description": description}


def _section(html: str, start: str, end: str) -> str:
    i = html.index(start)
    return html[i:html.index(end, i)]


def _cards(html: str) -> dict[str, str]:
    block = _section(html, 'class="cards"', "</section>")
    parts = block.split('<div class="card">')[1:]
    return {re.search(r'<p class="label">(.*?)</p>', p).group(1): p for p in parts}


def _rows(table_html: str) -> list[str]:
    body = table_html[table_html.index("<tbody"):]
    body = body[:body.index("</tbody>")]
    return re.findall(r"<tr[ >].*?</tr>", body, re.S)


def _attention(html: str) -> str:
    return _section(html, 'aria-labelledby="h-att"', "</section>")


def _agents(html: str) -> str:
    return _section(html, 'id="agents"', "</section>")


# ------------------------------------------------------------------- cards

def test_cards_show_condition_coverage_observations_and_requires_you(tmp_path, monkeypatch):
    def seed(s):
        _healthy_agents(s)
        s.upsert([
            _incident("ubuntu-server|uptime_down|n8n", "ubuntu-server", "critical", 30,
                      "[uptime] n8n is down in Uptime Kuma"),
            _incident("homelab|smart|photos", "homelab", "critical", 90, "[alert] SMART failing"),
            _incident("home-assistant|ha_unavailable|", "home-assistant", "warning", 300,
                      "[metric] HA unavailable entities: 14"),
        ])
        s.create_investigation(fingerprint="homelab|smart|photos", host="homelab",
                               agent_name="investigator", status="pending_approval",
                               started_at=_iso(20),
                               findings_json=json.dumps([{"metric": "SMART photos"}]))
        s.create_investigation(fingerprint="homelab|drive_temp|jellymedia", host="homelab",
                               agent_name="investigator", status="needs_human",
                               outcome="needs_human", started_at=_iso(600),
                               finished_at=_iso(590), report_md=PHYSICAL_REPORT)

    with _client(tmp_path, monkeypatch, seed) as c:
        html = c.get("/").text
    cards = _cards(html)
    assert list(cards) == ["Infrastructure", "Agent coverage", "Observations", "Requires you"]

    infra = cards["Infrastructure"]
    assert 'class="lamp lg red"' in infra
    assert '<span class="big num">02' in infra
    assert "Critical" in infra and "1 warning open" in infra

    cover = cards["Agent coverage"]
    assert '<span class="big num">7 / 7</span>' in cover and "Reporting" in cover
    discs = _section(cover, 'class="discs"', "</div>")
    assert discs.count("<i") == 7 and 'class="open"' not in discs
    assert 'aria-label="7 agents, 7 reporting"' in cover

    obs = cards["Observations"]
    assert '<span class="big num">2 min</span>' in obs and "Since last sync" in obs
    assert "Prometheus · Uptime Kuma" in obs
    assert 'class="ruler"' in obs

    you = cards["Requires you"]
    assert '<span class="big num">02</span>' in you
    assert "1 approval · 1 physical check" in you

    # the top bar: the window switch, Live engaged; the others are plain links
    switch = _section(html, 'aria-label="Window"', "</div>")
    live = re.search(r"<a[^>]*>.*?Live</a>", switch, re.S).group(0)
    assert 'aria-current="true"' in live
    assert 'href="?window=24h"' in switch and 'href="?window=7d"' in switch
    assert switch.count('aria-current="true"') == 1
    # the footer line
    assert "HEIM / H 01" in html and f"heim {version('heim')}" in html


def test_no_heartbeats_reads_unknown_not_normal(tmp_path, monkeypatch):
    """A silent daemon is not good news: no heartbeats is Unknown with a grey
    lamp, nothing reporting, and every agent row says No data yet."""
    def seed(s):
        s.upsert([_incident("homelab|temp|Drive", "homelab", "warning", 60, "sdb warm.")])

    with _client(tmp_path, monkeypatch, seed, uptime=False) as c:
        html = c.get("/").text
    cards = _cards(html)
    infra = cards["Infrastructure"]
    assert 'class="lamp lg"' in infra and "Unknown" in infra
    assert "Normal" not in html
    cover = cards["Agent coverage"]
    assert '<span class="big num">0 / 7</span>' in cover
    assert _section(cover, 'class="discs"', "</div>").count('class="open"') == 7
    assert "Not reporting: Alert poller" in cover
    obs = cards["Observations"]
    assert "No sync yet" in obs and "Prometheus" in obs and "Uptime Kuma" not in obs
    rows = _rows(_agents(html))
    assert len(rows) == 7
    paused = [r for r in rows if "Uptime monitor" in r]
    assert "Paused" in paused[0]
    assert sum("No data yet" in r for r in rows) == 6


# --------------------------------------------------------- needs attention

def test_attention_rows_carry_workflow_and_order(tmp_path, monkeypatch):
    ids = {}

    def seed(s):
        _healthy_agents(s)
        s.upsert([
            # critical, oldest first: the report-only target, then the one under way
            _incident("10.0.0.24|uptime_down|k8s-w1 kubelet", "10.0.0.24", "critical", 120,
                      "[uptime] k8s-w1 kubelet is down in Uptime Kuma"),
            _incident("ubuntu-server|uptime_down|n8n", "ubuntu-server", "critical", 30,
                      "[uptime] n8n is down in Uptime Kuma"),
            # warnings, oldest first: the one awaiting approval, then the threshold
            _incident("homelab|drive_temp|jellymedia", "homelab", "warning", 60 * 48,
                      "[alert] Drive at 58°C"),
            _incident("home-assistant|ha_unavailable|", "home-assistant", "warning", 300,
                      "[metric] HA unavailable entities: 14"),
            # muted: never listed
            _incident("homelab|pve_unbacked|", "homelab", "warning", 600,
                      "5 guests not backed up", status="suppressed"),
        ])
        ids["running"] = s.create_investigation(
            fingerprint="ubuntu-server|uptime_down|n8n", host="ubuntu-server",
            agent_name="investigator", status="running", started_at=_iso(4))
        ids["pending"] = s.create_investigation(
            fingerprint="homelab|drive_temp|jellymedia", host="homelab",
            agent_name="investigator", status="pending_approval", started_at=_iso(50))
        ids["failed"] = s.create_investigation(
            fingerprint="heim|mem_used|", host="heim", agent_name="investigator",
            status="failed", started_at=_iso(60 * 24), incomplete_reason="anthropic API: 529")
        # declined: nothing runs, so the threshold watch is what is on it
        s.create_investigation(
            fingerprint="home-assistant|ha_unavailable|", host="home-assistant",
            agent_name="investigator", status="declined", started_at=_iso(280))

    with _client(tmp_path, monkeypatch, seed) as c:
        html = c.get("/").text
    panel = _attention(html)
    assert '<h2 id="h-att">Needs attention</h2>' in panel
    assert "5 findings" in panel
    assert 'href="/incidents"' in panel and "View incidents" in panel
    rows = _rows(panel)
    assert len(rows) == 5
    k8s, n8n, failed, temp, ha = rows
    # critical, then the runs that ended badly, then warnings — oldest first
    assert "k8s-w1 kubelet" in k8s and "n8n" in n8n
    assert "529" in failed and "jellymedia" in temp.lower() and "HA unavailable" in ha
    assert all('class="lamp red"' in r for r in (k8s, n8n))
    assert all('class="lamp amber"' in r for r in (temp, ha))
    assert "pve_unbacked" not in panel and "not backed up" not in panel
    # the workflow column says what HEIM is doing about each one
    assert "Open" in k8s and "Report-only target" in k8s
    assert "Investigating" in n8n and f"investigation {ids['running']}" in n8n
    assert f'href="/investigations/{ids["running"]}"' in n8n
    assert "Awaiting approval" in temp and f'href="/investigations/{ids["pending"]}"' in temp
    assert "Open" in ha and "Monitoring threshold" in ha
    # the run that ended badly keeps its link and its re-run form
    assert f'href="/investigations/{ids["failed"]}"' in failed
    assert 'action="/actions/retrigger"' in failed and f'value="{ids["failed"]}"' in failed
    assert panel.count('action="/actions/retrigger"') == 1
    # hosts in mono, ages in the last column
    assert '<td class="mono">10.0.0.24</td>' in k8s
    assert "2 h" in k8s and "2 d" in temp


def test_attention_table_soft_caps_at_six_but_never_hides_a_critical(tmp_path, monkeypatch):
    """The first screen must reach the Agents panel: past six rows the table
    stops and one line links the rest, but a critical row is never the one cut."""
    def warnings(s):
        _healthy_agents(s)
        s.upsert([_incident(f"homelab|w{i}|Warn {i}", "homelab", "warning", 100 - i,
                            "[alert] warm") for i in range(7)])

    def criticals(s):
        _healthy_agents(s)
        s.upsert([_incident(f"homelab|c{i}|Crit {i}", "homelab", "critical", 100 - i,
                            "[alert] hot") for i in range(7)])

    with _client(tmp_path / "w", monkeypatch, warnings) as c:
        panel = _attention(c.get("/").text)
    assert "7 findings" in panel                       # the header keeps the full count
    assert len(_rows(panel)) == 6
    assert "Warn 6" not in panel                       # the newest warning is the one cut
    assert re.search(r'<a class="more" href="/incidents">all \(7\)', panel)
    assert panel.count("all (") == 1

    with _client(tmp_path / "c", monkeypatch, criticals) as c:
        panel = _attention(c.get("/").text)
    assert "7 findings" in panel and len(_rows(panel)) == 7
    assert "all (" not in panel


def test_attention_counts_every_run_and_links_the_cut_rows_to_their_page(tmp_path, monkeypatch):
    """Runs are findings too: seven failed runs read "7 findings", show six,
    and one line links the rest — to /investigations, because every row it
    hides is a run. Once an incident is among the hidden rows, /incidents."""
    def runs(s):
        _healthy_agents(s)
        for i in range(7):
            s.create_investigation(fingerprint=f"homelab|m{i}|Metric {i}", host="homelab",
                                   agent_name="investigator", trigger="daily",
                                   status="failed", started_at=_iso(600 - i),
                                   incomplete_reason="ssh connection refused")

    def runs_and_a_warning(s):
        runs(s)
        s.upsert([_incident("homelab|temp|Drive", "homelab", "warning", 90, "[alert] warm")])

    with _client(tmp_path / "r", monkeypatch, runs) as c:
        panel = _attention(c.get("/").text)
    assert "7 findings" in panel and len(_rows(panel)) == 6
    assert panel.count("all (") == 1
    assert re.search(r'<a class="more" href="/investigations">all \(7\)', panel)

    with _client(tmp_path / "w", monkeypatch, runs_and_a_warning) as c:
        panel = _attention(c.get("/").text)
    assert "8 findings" in panel and len(_rows(panel)) == 6
    assert panel.count("all (") == 1
    assert re.search(r'<a class="more" href="/incidents">all \(8\)', panel)


def test_workflow_for_each_incident_kind():
    investigable = {"ubuntu-server", "homelab", "home-assistant", "heim"}

    def inc(fp, description=""):
        return {"fingerprint": fp, "host": fp.split("|")[0], "description": description}

    def inv(i, status):
        return {"id": i, "status": status}

    n8n = inc("ubuntu-server|uptime_down|n8n", "[uptime] n8n is down")
    assert fmt.workflow_for(n8n, [inv(9, "running")], investigable) == {
        "title": "Investigating", "sub": "Agent is checking · investigation 9",
        "href": "/investigations/9"}
    assert fmt.workflow_for(n8n, [inv(8, "pending_approval")], investigable) == {
        "title": "Awaiting approval", "sub": "investigation 8", "href": "/investigations/8"}
    assert fmt.workflow_for(n8n, [inv(7, "needs_human")], investigable) == {
        "title": "Needs a human", "sub": "investigation 7", "href": "/investigations/7"}
    # running wins over an older pending one; an old needs-human run under a
    # newer complete one no longer speaks for the incident
    assert fmt.workflow_for(n8n, [inv(9, "running"), inv(8, "pending_approval")],
                            investigable)["title"] == "Investigating"
    assert fmt.workflow_for(n8n, [inv(9, "complete"), inv(7, "needs_human")],
                            investigable)["title"] == "Open"

    def opened(incident, invs=()):
        out = fmt.workflow_for(incident, list(invs), investigable)
        assert out["title"] == "Open" and out["href"] == ""
        return out["sub"]

    assert opened(n8n) == "Needs attention"            # investigable, nothing started
    assert opened(inc("10.0.0.24|uptime_down|kubelet", "[uptime] kubelet down")) \
        == "Report-only target"
    assert opened(inc("10.0.0.24|ha_unavailable|", "[metric] HA unavailable: 14")) \
        == "Monitoring threshold"
    assert opened(inc("10.0.0.24|smart|photos", "[alert] SMART failing")) == "Alert rule"
    # investigable but already looked at: the source says who is watching it
    assert opened(inc("homelab|ha|", "[metric] HA unavailable: 14"),
                  [inv(3, "complete")]) == "Monitoring threshold"
    assert opened(inc("homelab|smart|photos", "[alert] SMART"), [inv(3, "declined")]) \
        == "Alert rule"
    # a daily-analysis incident no agent can look at
    assert opened(inc("10.0.0.24|mem|", "Memory climbing")) == "Daily analysis"


# ---------------------------------------------------------------- needs you

def test_needs_you_lists_approvals_then_checks_and_links_to_detail(tmp_path, monkeypatch):
    ids = {}

    def seed(s):
        _healthy_agents(s)
        ids["human"] = s.create_investigation(
            fingerprint="home-assistant|zigbee|Radio", host="home-assistant",
            agent_name="investigator", status="needs_human", outcome="needs_human",
            started_at=_iso(60 * 30), finished_at=_iso(60 * 30), report_md=REMOTE_REPORT)
        ids["check"] = s.create_investigation(
            fingerprint="homelab|drive_temp|jellymedia", host="homelab",
            agent_name="investigator", status="needs_human", outcome="needs_human",
            started_at=_iso(60 * 20), finished_at=_iso(60 * 20), report_md=PHYSICAL_REPORT,
            findings_json=json.dumps([{"metric": "DriveTempWarning jellymedia"}]))
        ids["approval"] = s.create_investigation(
            fingerprint="homelab|drive_temp|jellymedia", host="homelab",
            agent_name="investigator", status="pending_approval", started_at=_iso(30),
            findings_json=json.dumps([{"severity": "warning",
                                       "metric": "DriveTempWarning jellymedia",
                                       "detail": "Drive sdd at 58°C"}]))

    with _client(tmp_path, monkeypatch, seed) as c:
        html = c.get("/").text
    you = _section(html, 'aria-labelledby="h-you"', "</section>")
    tasks = re.findall(r"<article.*?</article>", you, re.S)
    assert len(tasks) == 3
    approval, check, human = tasks
    assert 'class="lamp orange"' in approval and ">Approval<" in approval
    assert "Investigate DriveTempWarning jellymedia" in approval
    assert f"homelab · investigation {ids['approval']}" in approval
    assert "Review the proposed diagnostic scope." in approval
    assert f'class="btn primary" href="/investigations/{ids["approval"]}"' in approval
    assert "Review investigation" in approval

    assert 'class="lamp amber"' in check and ">Physical check<" in check
    assert "Check the USB enclosure fan by hand." in check
    assert f'class="btn" href="/investigations/{ids["check"]}"' in check
    assert "View evidence" in check

    assert ">Needs a human<" in human
    assert "Needs human — re-proposed next run" in human
    assert f'href="/investigations/{ids["human"]}"' in human
    # the card counts the same three
    assert "1 approval · 1 physical check · 1 for a human" in _cards(html)["Requires you"]


def test_needs_you_empty_state(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, _healthy_agents) as c:
        html = c.get("/").text
    you = _section(html, 'aria-labelledby="h-you"', "</section>")
    assert "Nothing needs you. The agents are handling it." in you
    assert "<article" not in you
    assert '<span class="big num">00</span>' in _cards(html)["Requires you"]


def test_needs_you_label_physical_vs_human():
    assert fmt.needs_you_label({"status": "pending_approval"}) == "Approval"
    assert fmt.needs_you_label({"status": "needs_human",
                                "report_md": PHYSICAL_REPORT}) == "Physical check"
    assert fmt.needs_you_label({"status": "needs_human",
                                "report_md": REMOTE_REPORT}) == "Needs a human"
    # only the remediation section counts: a fan in the summary is evidence
    summary_only = "## Summary\nThe fan curve is flat.\n\n## Remediation\n1. Wait a day.\n"
    assert fmt.needs_you_label({"status": "needs_human",
                                "report_md": summary_only}) == "Needs a human"
    for word in ("reseat the cable", "Replace the drive", "unplug the dock",
                 "power-cycle the switch", "physically inspect it", "swap the hardware"):
        report = f"## Remediation\n1. Please {word}.\n"
        assert fmt.needs_you_label({"status": "needs_human",
                                    "report_md": report}) == "Physical check", word
    # a word that merely contains a keyword is not one
    assert fmt.needs_you_label({"status": "needs_human",
                                "report_md": "## Remediation\n1. Lower power_on_hours.\n"}) \
        == "Needs a human"
    assert fmt.needs_you_label({"status": "needs_human", "report_md": ""}) == "Needs a human"


# ------------------------------------------------------------------ agents

def test_agents_panel_has_seven_rows_filter_and_flag(tmp_path, monkeypatch):
    def seed(s):
        _healthy_agents(s, backup_minutes=31 * 60)       # the backup is overdue

    with _client(tmp_path, monkeypatch, seed) as c:
        html = c.get("/").text
        attention = c.get("/?agents=attention").text
        running = c.get("/?agents=running").text

    panel = _agents(html)
    assert '<h2 id="h-ag">Agents</h2>' in panel
    rows = _rows(panel)
    assert [re.search(r'class="name"><a href="([^"]+)">(.*?)</a>', r).groups() for r in rows] == [
        ("/agents/alert_poller", "Alert poller"), ("/agents/thresholds", "Threshold watch"),
        ("/agents/uptime", "Uptime monitor"), ("/agents/investigator", "Investigator"),
        ("/agents/daily", "Daily analysis"), ("/agents/security", "Security audit"),
        ("/agents/backup", "Backup verifier")]
    for row in rows:                                 # the chevron opens the agent too
        href, name = re.search(r'class="name"><a href="([^"]+)">(.*?)</a>', row).groups()
        assert f'<td class="go"><a href="{href}" aria-label="Open {name}">›</a></td>' in row
    flagged = [r for r in rows if r.startswith('<tr class="flag"')]
    assert len(flagged) == 1 and "Backup verifier" in flagged[0]
    assert 'class="lamp amber"' in flagged[0] and "Overdue" in flagged[0]
    poller = rows[0]
    assert "Healthy" in poller and 'class="lamp blue"' in poller
    assert "Prometheus alerts · 4 hosts" in poller
    assert poller.count("<i") == 5                   # five runs, all ok
    assert "45 monitors · 15 report-only" in rows[2]
    # the strip ends hollow where the backup result never arrived
    strip = _section(flagged[0], 'class="runs"', "</span>")
    assert strip.rstrip().endswith('<i class="open"></i>')
    # one monitoring-gap line per flagged agent, linking its runs
    assert "Monitoring gap: latest backup verifier result not received." in panel
    assert re.search(r'href="/agents/backup">Review backup verifier runs', panel)
    # the switch: counts from the same list, All engaged
    switch = _section(panel, 'aria-label="Filter agents"', "</div>")
    assert re.search(r'aria-current="true">.*?All<span class="n">7</span>', switch, re.S)
    assert 'Running<span class="n">0</span>' in switch
    assert 'Attention<span class="n">1</span>' in switch

    only = _rows(_agents(attention))
    assert len(only) == 1 and "Backup verifier" in only[0]
    seg = _section(_agents(attention), 'aria-label="Filter agents"', "</div>")
    engaged = re.search(r'<a [^>]*aria-current="true"[^>]*>.*?</a>', seg, re.S).group(0)
    assert "Attention" in engaged and seg.count('aria-current="true"') == 1
    assert "Monitoring gap: latest backup verifier result not received." in _agents(attention)

    assert 'class="name"' not in _agents(running)
    assert "No agent is running right now." in _agents(running)


def test_failed_agent_gap_names_the_error(tmp_path, monkeypatch):
    def seed(s):
        _healthy_agents(s)
        _beat(s, "uptime", 1, ok=False, error="Uptime Kuma unreachable")

    with _client(tmp_path, monkeypatch, seed) as c:
        panel = _agents(c.get("/").text)
    flagged = [r for r in _rows(panel) if r.startswith('<tr class="flag"')]
    assert len(flagged) == 1 and "Uptime monitor" in flagged[0] and "Failed" in flagged[0]
    assert "Monitoring gap: uptime monitor failed: Uptime Kuma unreachable." in panel
    assert re.search(r'href="/agents/uptime">Review uptime monitor runs', panel)


# ----------------------------------------------------------- honest counts

def test_counts_agree_with_rows(tmp_path, monkeypatch):
    def seed(s):
        _healthy_agents(s, backup_minutes=31 * 60)
        s.upsert([
            _incident("ubuntu-server|uptime_down|n8n", "ubuntu-server", "critical", 30,
                      "[uptime] n8n is down"),
            _incident("homelab|temp|Drive", "homelab", "warning", 90, "[alert] warm"),
            _incident("heim|mem|Memory", "heim", "warning", 120, "[metric] memory 91%"),
            _incident("homelab|pve_unbacked|", "homelab", "warning", 600, "muted",
                      status="suppressed"),
        ])
        s.create_investigation(fingerprint="heim|mem|Memory", host="heim",
                               agent_name="investigator", status="pending_approval",
                               started_at=_iso(10))
        s.create_investigation(fingerprint="homelab|temp|Drive", host="homelab",
                               agent_name="investigator", status="needs_human",
                               outcome="needs_human", started_at=_iso(80),
                               report_md=PHYSICAL_REPORT)

    with _client(tmp_path, monkeypatch, seed) as c:
        html = c.get("/").text

    def rail(href: str) -> int:
        item = re.search(rf'<a href="{href}"[^>]*>.*?</a>', html, re.S).group(0)
        return int(re.search(r'<span class="n">(\d+)</span>', item).group(1))

    attention = _rows(_attention(html))
    incident_rows = [r for r in attention if 'action="/actions/retrigger"' not in r]
    assert rail("/incidents") == len(incident_rows) == 3
    assert f"{len(attention)} findings" in _attention(html)
    agents = _rows(_agents(html))
    assert rail("/agents") == len(agents) == 7

    cards = _cards(html)
    crit_rows = [r for r in incident_rows if 'class="lamp red"' in r]
    warn_rows = [r for r in incident_rows if 'class="lamp amber"' in r]
    assert f'<span class="big num">{len(crit_rows):02d}' in cards["Infrastructure"]
    assert f"{len(warn_rows)} warnings open" in cards["Infrastructure"]
    tasks = re.findall(r"<article", _section(html, 'aria-labelledby="h-you"', "</section>"))
    assert f'<span class="big num">{len(tasks):02d}</span>' in cards["Requires you"]
    reporting = sum("Overdue" not in r and "No data yet" not in r and "Paused" not in r
                    for r in agents)
    assert f'<span class="big num">{reporting} / 7</span>' in cards["Agent coverage"]
    assert "Not reporting: Backup verifier" in cards["Agent coverage"]


# --------------------------------------------------------- existing blocks

def test_existing_overview_blocks_still_render(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    _seed(db)
    with TestClient(create_app(cfg)) as c:
        html = c.get("/").text
    agents_end = html.index('id="agents"')
    for heading in ('class="kpis"', 'class="card health"', "latest runs", "tool usage",
                    "token usage", "recent investigations", "recent findings"):
        assert heading in html, heading
        assert html.index(heading) > agents_end, heading     # below the console
    assert "open incidents" in html and "running invest." in html     # the five figures
    assert "waiting for your approval" in html and "👍" not in html
