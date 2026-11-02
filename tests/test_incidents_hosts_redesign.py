"""Task 7 of the dashboard redesign: /incidents and /hosts on the console system.

An incident's ownership is a word read from its description prefix; the lock
stays a word with its hook; the hosts page keeps report-only addresses (open
`[uptime] ` incidents on a host HEIM has no profile for) in their own group.
"""
import pytest
from fastapi.testclient import TestClient

from heim.dashboard import format as fmt
from heim.dashboard.app import create_app
from heim.incidents.store import IncidentStore
from test_dashboard import _config, _iso


def _row(fp, host, description, **kw):
    return {"fingerprint": fp, "host": host, "metric": "m", "severity": "warning",
            "status": "open", "firstSeen": _iso(900), "lastSeen": _iso(5),
            "timesSeen": 2, "missedRuns": 0, "description": description, **kw}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    store = IncidentStore(db)
    store.upsert([
        _row("ubuntu-server|a|One", "ubuntu-server", "[alert] disk is filling"),
        _row("ubuntu-server|b|Two", "ubuntu-server", "[metric] load is high"),
        _row("ubuntu-server|c|Three", "ubuntu-server", "[uptime] probe is down"),
        _row("homelab|d|Four", "homelab", "Trend worsening over three days",
             investigated=True, timesSeen=7),
        _row("nas.lan|up|Probe", "nas.lan", "[uptime] nas.lan is down",
             severity="critical"),
    ])
    store.close()
    with TestClient(create_app(cfg)) as c:
        yield c, cfg


def test_ownership_word_is_pure():
    assert fmt.ownership_word("[alert] x") == "Alert"
    assert fmt.ownership_word("[metric] x") == "Metric"
    assert fmt.ownership_word("[uptime] x") == "Uptime"
    assert fmt.ownership_word("plain text") == "Daily analysis"
    assert fmt.ownership_word("") == "Daily analysis"
    assert fmt.ownership_word(None) == "Daily analysis"


def test_incident_ownership_words(client):
    html = client[0].get("/incidents").text
    for word in ("Alert", "Metric", "Uptime", "Daily analysis"):
        assert f'<td class="own">{word}</td>' in html
    assert html.count('<td class="own">Daily analysis</td>') == 1
    assert '<th scope="col">ownership</th>' in html


def test_lock_is_a_word_not_an_emoji_and_keeps_its_hook(client):
    html = client[0].get("/incidents").text
    assert html.count('class="lock"') == 1
    assert '>Locked</span>' in html
    assert "🔒" not in html


def test_hosts_page_lists_report_only_addresses_separately(client):
    c, cfg = client
    html = c.get("/hosts").text
    assert "Watched, not investigated" in html
    group = html[html.index("Watched, not investigated"):]
    assert "nas.lan" in group
    assert "action=" not in group                    # report-only: nothing to dispatch
    before = html[:html.index("Watched, not investigated")]
    assert "nas.lan" not in before                   # never among the config hosts
    assert html.count('action="/actions/investigate"') == len(cfg.hosts)


def test_hosts_page_has_no_report_only_group_without_uptime_incidents(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    cfg.settings.db_path = str(tmp_path / "e.sqlite3")
    IncidentStore(cfg.settings.db_path).close()
    with TestClient(create_app(cfg)) as c:
        assert "Watched, not investigated" not in c.get("/hosts").text


def test_every_incident_action_form_still_posts_to_its_route(client):
    html = client[0].get("/incidents").text
    # five open incidents: each offers investigate + mark-false-positive
    assert html.count('action="/actions/investigate"') == 5
    assert html.count('action="/actions/mute"') == 5
    assert html.count('hx-post="/actions/investigate"') == 5
    assert html.count(">Investigate now<") == 5
    assert html.count(">Mark false positive<") == 5
    assert 'hx-confirm="Mark this a false positive and mute the fingerprint?"' in html
    assert 'name="fingerprint" value="homelab|d|Four"' in html
