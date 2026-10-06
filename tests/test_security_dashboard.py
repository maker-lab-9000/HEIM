import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.config import load_config
from heim.dashboard.app import create_app
from heim.incidents.store import IncidentStore

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("HEIM_DASHBOARD_TOKEN", raising=False)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    store = IncidentStore(db)
    run_id = store.insert_run(kind="security_audit", run_at="2026-09-28T06:00:00", overall="warning")
    rows = [{"host": "homelab", "metric": "pve.tfa_missing", "severity": "warning", "trend": "new",
             "summary": "root@pam can log in with a password alone", "detail": "d", "recommendation": "add TOTP",
             "fingerprint": "homelab|pve.tfa_missing|root@pam"}]
    store.insert_findings(run_id, "2026-09-28T06:00:00", "security_audit", rows, [r["fingerprint"] for r in rows])
    store.create_investigation(fingerprint="all|security_audit|run-1", host="all", host_role="audit",
                               agent_name="security_auditor", model="claude-sonnet-5", trigger="security_audit",
                               status="complete", started_at="2026-09-28T06:00:00", finished_at="2026-09-28T06:04:00",
                               report_md="## Summary\n\nweekly audit\n\n## AI assessment\n\n### Summary\n\nfine",
                               findings_json=json.dumps(rows), brief_md="brief")
    store.close()
    with TestClient(create_app(cfg)) as c:
        yield c


def test_trigger_filter_offers_and_applies_security_audit(client):
    page = client.get("/investigations").text
    assert 'value="security_audit"' in page
    filtered = client.get("/investigations?trigger=security_audit").text
    assert "security_audit" in filtered and "all" in filtered


def test_detail_page_shows_agent_and_findings(client):
    inv_id = 1
    html = client.get(f"/investigations/{inv_id}").text
    assert "security_auditor" in html and "pve.tfa_missing" in html and "weekly audit" in html


def test_findings_page_lists_the_audit_row_with_a_verdict_form(client):
    html = client.get("/findings").text
    assert "pve.tfa_missing" in html and "root@pam" in html and "/actions/verdict" in html
