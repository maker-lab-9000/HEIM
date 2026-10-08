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


@pytest.fixture()
def empty_client(tmp_path, monkeypatch):
    monkeypatch.delenv("HEIM_DASHBOARD_TOKEN", raising=False)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    store = IncidentStore(db)
    store.close()
    with TestClient(create_app(cfg)) as c:
        yield c


def test_trigger_filter_offers_and_applies_security_audit(client):
    page = client.get("/investigations").text
    assert 'value="security_audit"' in page
    filtered = client.get("/investigations?trigger=security_audit").text
    assert "security_audit" in filtered and "all" in filtered


def test_trigger_filter_offers_security_audit_before_its_first_run(empty_client):
    # Store has zero rows — no insert_run, no create_investigation. The dropdown must
    # still offer "security_audit" from _TRIGGERS alone, not from any stored row.
    page = empty_client.get("/investigations").text
    assert 'value="security_audit"' in page


def test_detail_page_shows_agent_and_findings(client):
    inv_id = 1
    html = client.get(f"/investigations/{inv_id}").text
    assert "security_auditor" in html and "pve.tfa_missing" in html and "weekly audit" in html


def test_findings_page_lists_the_audit_row_with_a_verdict_form(client):
    html = client.get("/findings").text
    assert "pve.tfa_missing" in html and "root@pam" in html and "/actions/verdict" in html


XSS = "<img src=x onerror=alert(1)>\n\n<script>alert(1)</script>"


@pytest.fixture()
def xss_client(tmp_path, monkeypatch):
    monkeypatch.delenv("HEIM_DASHBOARD_TOKEN", raising=False)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    store = IncidentStore(db)
    store.create_investigation(fingerprint="all|security_audit|run-1", host="all", host_role="audit",
                               agent_name="security_auditor", model="claude-sonnet-5", trigger="security_audit",
                               status="complete", started_at="2026-09-28T06:00:00", finished_at="2026-09-28T06:04:00",
                               report_md="## Summary\n\nreport text\n\n" + XSS,
                               findings_json="[]", brief_md="EVIDENCE EXCERPTS\n\n" + XSS)
    store.close()
    with TestClient(create_app(cfg)) as c:
        yield c


def test_fr1_detail_page_escapes_raw_html_in_stored_brief_and_report(xss_client):
    html = xss_client.get("/investigations/1").text
    assert "report text" in html and "EVIDENCE EXCERPTS" in html
    assert "<img src=x" not in html and "<script>alert" not in html
    assert html.count("&lt;img") >= 2 and html.count("&lt;script") >= 2


# ------------------------------------------------------------ /security page

def _row(host, metric, subject, severity, trend, summary):
    return {"host": host, "metric": metric, "severity": severity, "trend": trend, "summary": summary,
            "detail": "", "recommendation": "", "fingerprint": f"{host}|{metric}|{subject}"}


@pytest.fixture()
def audit_client(tmp_path, monkeypatch):
    """Two audits a week apart: one finding fixed, one muted, one persisting, two new."""
    monkeypatch.delenv("HEIM_DASHBOARD_TOKEN", raising=False)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    store = IncidentStore(db)
    week1 = [_row("homelab", "pve.tfa_missing", "root@pam", "warning", "new", "root@pam has no second factor"),
             _row("homelab", "pve.updates", "pending", "warning", "new", "FIXED-LAST-WEEK updates pending"),
             _row("ubuntu-server", "ssh.listeners_unexpected", "8000", "warning", "new", "MUTED-ONE port 8000")]
    r1 = store.insert_run(kind="security_audit", run_at="2026-09-28T06:00:00", overall="warning",
                          counts_json=json.dumps({"checks": 47, "critical": 0, "warning": 3, "new": 3,
                                                  "resolved": 0, "unavailable": 2, "findings": 3}))
    store.insert_findings(r1, "2026-09-28T06:00:00", "security_audit", week1, [r["fingerprint"] for r in week1])
    # a dry run in between must never show up, nor become the "previous" audit
    dry = store.insert_run(kind="security_audit_dryrun", run_at="2026-10-01T10:00:00", overall="critical")
    store.insert_findings(dry, "2026-10-01T10:00:00", "security_audit_dryrun",
                          [_row("homelab", "x.dry", "s", "critical", "new", "DRY-RUN-ONLY")], ["homelab|x.dry|s"])
    week2 = [_row("homelab", "pve.tfa_missing", "root@pam", "warning", "persisting", "root@pam has no second factor"),
             _row("ubuntu-server", "ssh.listeners_unexpected", "2375", "critical", "new",
                  "Docker API <script>alert(1)</script> on 2375"),
             _row("homelab", "ha.public", "ha", "warning", "new", "HA reachable from outside")]
    r2 = store.insert_run(kind="security_audit", run_at="2026-10-05T06:00:00", overall="critical",
                          headline="3 findings · 2 new · 2 resolved",
                          counts_json=json.dumps({"checks": 47, "critical": 1, "warning": 2, "new": 2,
                                                  "resolved": 2, "unavailable": 1, "findings": 3}))
    store.insert_findings(r2, "2026-10-05T06:00:00", "security_audit", week2, [r["fingerprint"] for r in week2])
    store.suppress("ubuntu-server|ssh.listeners_unexpected|8000", reason="false positive",
                   created_at="2026-10-02T00:00:00")
    store.create_investigation(fingerprint=f"all|security_audit|run-{r2}", host="all", host_role="audit",
                               agent_name="security_auditor", model="claude-sonnet-5", trigger="security_audit",
                               status="complete", started_at="2026-10-05T06:00:00",
                               report_md="## Summary\n\nr\n\n## AI assessment\n\n### Summary\n\nx\n\n"
                                         "### Audit feedback\n\n#### Improve the audit\n\n"
                                         "- ssh.* — key unreadable <img src=x onerror=alert(1)> — fix ownership\n\n"
                                         "#### What else to check\n\n- PVE token expiry — pve.tfa_missing — GET /access/users\n",
                               findings_json="[]", brief_md="b")
    store.close()
    with TestClient(create_app(cfg)) as c:
        yield c, {"r1": r1, "r2": r2, "dry": dry}


def test_security_page_groups_latest_audit_by_severity(audit_client):
    c, ids = audit_client
    page = c.get("/security").text
    assert 'href="/security"' in page  # nav entry
    crit, warn = page.index('id="sev-critical"'), page.index('id="sev-warning"')
    assert crit < warn < page.index('id="resolved"')
    assert page.index("Docker API") > crit and page.index("Docker API") < warn
    # inside the warning group, new comes before persisting
    assert page.index("HA reachable from outside") < page.index("root@pam has no second factor")
    assert "2 weeks" in page  # the persisting finding was seen in both audits
    assert f"/investigations/" in page and "full report" in page


def test_security_page_lists_resolved_and_flags_muted(audit_client):
    c, _ = audit_client
    page = c.get("/security").text
    resolved = page[page.index('id="resolved"'):]
    assert "FIXED-LAST-WEEK" in resolved and "MUTED-ONE" in resolved
    muted_line = resolved[resolved.index("MUTED-ONE"):].split("</tr>")[0]
    assert "muted, not fixed" in muted_line
    fixed_line = resolved[resolved.index("FIXED-LAST-WEEK"):].split("</tr>")[0]
    assert "muted" not in fixed_line


def test_security_page_never_shows_dry_runs(audit_client):
    c, ids = audit_client
    page = c.get("/security").text
    assert "DRY-RUN-ONLY" not in page
    assert c.get(f"/security?run={ids['dry']}").status_code == 404


def test_security_page_opens_a_past_audit_from_history(audit_client):
    c, ids = audit_client
    latest = c.get("/security").text
    assert f'href="/security?run={ids["r1"]}"' in latest
    past = c.get(f"/security?run={ids['r1']}").text
    assert "FIXED-LAST-WEEK" in past and "Docker API" not in past
    assert "first audit" in past  # nothing older to diff against
    assert "no AI assessment for this run" in past
    # weeks are counted as of that audit, not as of today
    assert "2 weeks" not in past


def test_security_page_escapes_finding_text(audit_client):
    c, _ = audit_client
    page = c.get("/security").text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_security_page_unknown_run_is_404(audit_client):
    c, _ = audit_client
    assert c.get("/security?run=9999").status_code == 404


def test_security_page_before_the_first_audit(empty_client):
    r = empty_client.get("/security")
    assert r.status_code == 200
    assert "No security audit has run yet" in r.text


def test_security_page_shows_the_auditor_feedback(audit_client):
    c, _ = audit_client
    page = c.get("/security").text
    card = page[page.index('id="feedback"'):page.index('id="sev-critical"')]
    assert "improve the audit" in card and "what else to check" in card
    assert "key unreadable" in card and "PVE token expiry" in card
    assert "<img" not in card and "&lt;img" in card  # model output, raw HTML off


def test_security_page_without_feedback_shows_no_card(audit_client):
    c, ids = audit_client
    assert 'id="feedback"' not in c.get(f"/security?run={ids['r1']}").text
