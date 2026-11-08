"""Jobs with timed pauses; Agents narrowed to the three that call a model
(spec 2026-11-04-activity-jobs-tools)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from test_dashboard_models import _client, _store

from heim.dashboard import app as dash
from heim.dashboard.app import create_app


@pytest.fixture()
def client(tmp_path):
    cfg, _c = _client(tmp_path, [])
    cfg.settings.uptime_kuma.url = ""          # one job Off in config
    return cfg, TestClient(create_app(cfg))


def test_jobs_list_has_six_jobs_with_controls(client):
    _cfg, c = client
    html = c.get("/jobs").text
    for name in ("Daily analysis", "Alert poller", "Threshold watch", "Uptime monitor",
                 "Security audit", "Backup verifier"):
        assert name in html, name
    assert "Investigator" not in html
    assert html.count('action="/actions/pause"') == 5         # uptime is Off
    assert "switched off in config" in html


def test_pause_action_writes_row_and_shows_until(client):
    cfg, c = client
    r = c.post("/actions/pause", data={"job": "alert_poller", "for": "4h", "back": "/jobs"},
               follow_redirects=False)
    assert r.status_code == 303
    row = _store(cfg).job_pauses()["alert_poller"]
    assert row["set_by"] == "dashboard" and row["until"]
    html = c.get("/jobs").text
    assert "Paused until" in html and 'action="/actions/resume"' in html


def test_pause_htmx_returns_the_control(client):
    _cfg, c = client
    r = c.post("/actions/pause", data={"job": "backup", "for": "1h"},
               headers={"HX-Request": "true"})
    assert r.status_code == 200 and "Paused until" in r.text


@pytest.mark.parametrize("data", [
    {"job": "alert_poller", "for": "2h"},
    {"job": "investigator", "for": "1h"},
    {"job": "nope", "for": "1h"},
])
def test_pause_rejects_bad_duration_and_unknown_job(client, data):
    cfg, c = client
    assert c.post("/actions/pause", data=data).status_code == 400
    assert _store(cfg).job_pauses() == {}


def test_pause_off_job_rejected(client):
    cfg, c = client
    r = c.post("/actions/pause", data={"job": "uptime", "for": "1h"})
    assert r.status_code == 400 and "switched off in config" in r.text
    assert _store(cfg).job_pauses() == {}


def test_resume_action(client):
    cfg, c = client
    _store(cfg).pause_job("backup", "2099-01-01T00:00:00+00:00")
    r = c.post("/actions/resume", data={"job": "backup"}, follow_redirects=False)
    assert r.status_code == 303
    assert _store(cfg).job_pauses()["backup"]["until"] < "2099"
    assert "Paused until" not in c.get("/jobs").text


def test_job_detail_page(client):
    _cfg, c = client
    html = c.get("/jobs/alert_poller").text
    assert "Alert poller" in html and 'action="/actions/pause"' in html
    assert c.get("/jobs/investigator").status_code == 404


def test_agents_page_lists_three(client):
    _cfg, c = client
    html = c.get("/agents").text
    for name, href in (("Daily analyst", "/agents/analyst"),
                       ("Investigator", "/agents/investigator"),
                       ("Security auditor", "/agents/auditor")):
        assert name in html and href in html
    assert "Alert poller" not in html and "Backup verifier" not in html


@pytest.mark.parametrize("old,new", [
    ("/agents/daily", "/agents/analyst"), ("/agents/security", "/agents/auditor"),
    ("/agents/alert_poller", "/jobs/alert_poller"), ("/agents/thresholds", "/jobs/thresholds"),
    ("/agents/uptime", "/jobs/uptime"), ("/agents/backup", "/jobs/backup"),
])
def test_old_agent_urls_redirect_302(client, old, new):
    _cfg, c = client
    r = c.get(old, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == new


def test_analyst_page_has_models_panel_and_prompt(client):
    cfg, c = client
    _store(cfg).insert_run(kind="daily", run_at="2026-11-04T07:00:00+01:00",
                           input_text="PAYLOAD-MARKER mem_used")
    html = c.get("/agents/analyst").text
    assert 'id="h-models"' in html and 'id="h-prompt"' in html
    first = (cfg.prompts_dir / "analyst.md").read_text().strip().splitlines()[0]
    assert first.strip("# ").split()[0] in html
    assert "PAYLOAD-MARKER" in html
    assert "/jobs/daily" in html                       # job and agent link each other


def test_investigator_prompt_renders_for_host(client):
    cfg, c = client
    host = next(h for h in cfg.hosts.values() if h.facts.strip())
    html = c.get(f"/agents/investigator?host={host.name}").text
    assert 'id="h-prompt"' in html
    assert host.facts.strip().splitlines()[0][:30] in html.replace("&#39;", "'")


def test_auditor_page(client):
    _cfg, c = client
    html = c.get("/agents/auditor").text
    assert "Security auditor" in html and 'id="h-prompt"' in html and "/jobs/security" in html


def test_rail_order(client):
    _cfg, c = client
    html = c.get("/jobs").text
    nav = html[html.index('class="rail"'):html.index("rail-foot")]
    order = [nav.index(f'>{w}<') for w in ("Overview", "Activity", "Jobs", "Agents", "Tools",
                                           "Investigations", "Incidents")]
    assert order == sorted(order)


def test_pause_helpers_allow_listed():
    assert "pause_job" in dash._ACTION_HELPERS and "resume_job" in dash._ACTION_HELPERS
