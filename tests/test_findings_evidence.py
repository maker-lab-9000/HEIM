"""Every finding links to its evidence (dashboard redesign, task 8).

A finding says what is wrong; the links say where to look: the metric row it
came from, its incident, its latest investigation. A link is only drawn for
something that exists, and each is labelled with what it opens.
"""
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.dashboard import format as fmt
from heim.dashboard.app import create_app
from heim.incidents.store import IncidentStore
from test_dashboard import _config, _iso
from test_metrics_page import FakeProm


def _seed(db_path: Path) -> int:
    store = IncidentStore(db_path)
    run_at = _iso(5)
    rid = store.insert_run(run_at=run_at, kind="daily", overall="warning",
                           model_used="claude-opus-4-6", duration_s=1.0,
                           counts_json=json.dumps({"crit": 1, "warn": 1}))
    store.insert_findings(rid, run_at, "daily", [
        {"host": "ubuntu-server", "metric": "mem_used", "severity": "critical",
         "summary": "Memory climbing on ubuntu-server"},
        {"host": "homelab", "metric": "bespoke", "severity": "warning",
         "summary": "Something the catalog has never heard of"},
    ], fingerprints=["ubuntu-server|mem_used|Memory climbing",
                     "homelab|not_a_catalog_qid|Bespoke"])
    inv = store.create_investigation(
        fingerprint="ubuntu-server|mem_used|Memory climbing", host="ubuntu-server",
        host_role="guest", trigger="daily", status="complete",
        started_at=_iso(60), finished_at=_iso(58), n_steps=2)
    store.upsert([
        {"fingerprint": "ubuntu-server|mem_used|Memory climbing", "host": "ubuntu-server",
         "metric": "mem_used", "severity": "critical", "status": "open",
         "firstSeen": _iso(900), "lastSeen": _iso(5), "timesSeen": 3,
         "description": "climbing"},
    ])
    store.close()
    return inv


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    cfg.settings.db_path = str(tmp_path / "heim.sqlite3")
    inv = _seed(Path(cfg.settings.db_path))
    monkeypatch.setattr("heim.dashboard.app._fetch_query_ranges", FakeProm())
    with TestClient(create_app(cfg)) as client:
        yield client, inv


def _row(html: str, summary: str) -> str:
    start = html.index(summary)
    return html[html.rindex("<tr", 0, start):html.index("</tr>", start)]


def test_daily_finding_links_to_its_metric_incident_and_investigation(seeded):
    client, inv = seeded
    row = _row(client.get("/findings").text, "Memory climbing on ubuntu-server")
    assert '<a href="/metrics#q-mem_used">metric</a>' in row
    assert '<a href="/incidents">incident</a>' in row
    assert f'<a href="/investigations/{inv}">investigation {inv}</a>' in row
    assert "→" not in row.split('class="evidence label"')[1].split("</p>")[0]


def test_finding_without_catalog_qid_has_no_metric_link(seeded):
    client, _ = seeded
    row = _row(client.get("/findings").text, "Something the catalog has never heard of")
    assert "/metrics#" not in row
    assert ">metric</a>" not in row
    assert ">incident</a>" not in row        # none stored for it either
    assert "investigation " not in row.replace("detail &amp; recommendation", "")


def test_metrics_rows_carry_q_anchors(seeded):
    client, _ = seeded
    html = client.get("/metrics").text
    assert 'id="q-mem_used"' in html
    assert 'id="q-drive_temp"' in html
    assert len(re.findall(r'id="q-mem_used"', html)) == 1     # ids stay unique


def test_verdict_and_mute_forms_unchanged(seeded):
    client, _ = seeded
    html = client.get("/findings").text
    assert html.count('action="/actions/verdict"') == 4        # 2 findings x 2 buttons
    assert html.count(">Confirm<") == 2 and html.count(">False positive<") == 2
    assert 'name="finding_id"' in html and 'value="false_positive"' in html
    assert 'hx-post="/actions/verdict"' in html and "hx-confirm=" in html


def test_evidence_links_helper_is_pure_and_honest():
    finding = {"source": "daily", "fingerprint": "h|cpu_busy|x"}
    assert fmt.evidence_links(finding, {"id": 7}, {"cpu_busy"}) == [
        {"label": "metric", "href": "/metrics#q-cpu_busy"},
        {"label": "incident", "href": "/incidents"},
        {"label": "investigation 7", "href": "/investigations/7"}]
    assert fmt.evidence_links(finding, None, set(), incident_exists=False) == []
    audit = {"source": "security_audit", "fingerprint": "pve|pve_ssh_root|root"}
    assert fmt.evidence_links(audit, None, {"pve_ssh_root"}) == [
        {"label": "check", "href": "/security#check-pve_ssh_root"}]
    assert fmt.evidence_links({"source": "daily", "fingerprint": ""}, None, set()) == []
