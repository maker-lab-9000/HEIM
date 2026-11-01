"""The Agents page (/agents) and the agent detail page (/agents/{key}).

Fixtures are the overview console's: committed example config, a temp store
seeded before the app starts, times relative to the real clock.
"""
import re

from test_overview_console import _agents, _beat, _client, _healthy_agents, _iso, _rows


def test_agents_page_lists_seven_and_filters(tmp_path, monkeypatch):
    def seed(s):
        _healthy_agents(s, backup_minutes=60 * 40)   # backup overdue -> flagged

    client = _client(tmp_path, monkeypatch, seed)
    html = client.get("/agents").text
    assert "<title>Agents" in html
    panel = _agents(html)
    assert len(_rows(panel)) == 7
    assert 'href="/agents/backup"' in panel
    assert "Monitoring gap: latest backup verifier result not received." in panel

    flagged = _agents(client.get("/agents?agents=attention").text)
    rows = _rows(flagged)
    assert len(rows) == 1 and "Backup verifier" in rows[0]
    assert re.search(r'href="/agents\?agents=attention#agents" class="on" aria-current="true"',
                     flagged)
    assert 'href="/agents#agents"' in flagged      # the All link goes back to the page


def test_agent_detail_shows_runs_strip_and_evidence_link(tmp_path, monkeypatch):
    def seed(s):
        _beat(s, "alert_poller", 38, detail={"hosts": 4})
        _beat(s, "alert_poller", 30, ok=False, error="Prometheus unreachable")
        _beat(s, "alert_poller", 10, detail={"hosts": 4})   # 20 min gap > 2 x 5 min: a miss
        _beat(s, "alert_poller", 4, detail={"hosts": 4})
        _beat(s, "backup", 60, detail={"backup_file": "heim-20261101.sqlite3"})

    client = _client(tmp_path, monkeypatch, seed)
    html = client.get("/agents/alert_poller").text
    assert "<title>Agents / alert poller" in html
    assert "every 5 min" in html
    assert 'href="/incidents"' in html
    assert "Prometheus unreachable" in html
    strip = re.search(r'<span class="runs" role="img" aria-label="([^"]*)"', html)
    assert strip and "1 failed" in strip.group(1) and "1 missed" in strip.group(1)
    table = html[html.index('aria-labelledby="h-runs"'):]
    rows = _rows(table)
    words = [re.search(r"</span>(OK|Error|Missed)", r).group(1) for r in rows]
    assert words == ["OK", "OK", "Missed", "Error", "OK"]
    assert "4 hosts" in rows[0]

    backup = client.get("/agents/backup").text
    assert "heim-20261101.sqlite3" in backup
    assert "daily at 03:30" in backup
    for key, href in (("daily", "/findings"), ("security", "/security"),
                      ("uptime", "/incidents"), ("thresholds", "/incidents")):
        assert f'href="{href}"' in client.get(f"/agents/{key}").text


def test_agent_detail_404_for_unknown_key(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, lambda s: None)
    r = client.get("/agents/nope")
    assert r.status_code == 404
    assert "No agent" in r.text


def test_investigator_detail_lists_investigations(tmp_path, monkeypatch):
    ids = {}

    def seed(s):
        ids["a"] = s.create_investigation(
            fingerprint="ubuntu-server|cpu|Load", host="ubuntu-server", agent_name="investigator",
            trigger="daily", status="complete", started_at=_iso(300), finished_at=_iso(290),
            input_tokens=9000, output_tokens=1000, n_steps=6)
        ids["b"] = s.create_investigation(
            fingerprint="homelab|mem|Mem", host="homelab", agent_name="investigator",
            trigger="poller", status="failed", started_at=_iso(100), finished_at=_iso(95),
            n_steps=2)
        s.create_investigation(
            fingerprint="x|y|z", host="homelab", agent_name="security_auditor",
            trigger="security_audit", status="complete", started_at=_iso(50))

    client = _client(tmp_path, monkeypatch, seed)
    html = client.get("/agents/investigator").text
    assert "on demand" in html
    assert 'href="/investigations"' in html
    table = html[html.index('aria-labelledby="h-runs"'):]
    rows = _rows(table)
    assert len(rows) == 2                      # the security auditor's row is not its run
    assert f'href="/investigations/{ids["b"]}"' in rows[0] and "homelab" in rows[0]
    assert f'href="/investigations/{ids["a"]}"' in rows[1]
    assert "6 / 10k" in rows[1]


def test_rail_marks_agents_current(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, lambda s: None)
    for path in ("/agents", "/agents/backup"):
        html = client.get(path).text
        assert re.search(r'<a href="/agents" class="on" aria-current="page">', html), path
        assert not re.search(r'<a href="/" class="on"', html)
