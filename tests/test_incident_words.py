"""The incidents list reads as coloured words (no lamps), the "what this
incident says" toggle lives in the incident's own row, and a false-positive
verdict wears a lamp like "confirmed" does."""
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.dashboard.app import create_app
from heim.incidents.store import IncidentStore
from test_dashboard import _config

ROOT = Path(__file__).resolve().parent.parent
CSS = (ROOT / "src/heim/dashboard/static/heim.css").read_text()


def _inc(i, severity, status):
    return {"fingerprint": f"ubuntu-server|m{i}|n{i}", "host": "ubuntu-server", "metric": f"m{i}",
            "severity": severity, "status": status, "firstSeen": "2026-09-19T00:00:00",
            "lastSeen": f"2026-09-19T00:00:0{i}", "resolvedAt": "", "timesSeen": 1, "missedRuns": 0,
            "description": "d", "investigated": False}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    s = IncidentStore(db)
    s.upsert([_inc(1, "critical", "open"), _inc(2, "warning", "resolved"),
              _inc(3, "warning", "clearing"), _inc(4, "warning", "suppressed")])
    run_id = s.insert_run(kind="daily", run_at="2026-09-28T06:00:00", overall="warning")
    rows = [{"host": "ubuntu-server", "metric": "m", "severity": "warning", "trend": "new", "summary": "s",
             "detail": "d", "recommendation": "r", "fingerprint": "ubuntu-server|m|n"}]
    s.insert_findings(run_id, "2026-09-28T06:00:00", "daily", rows, [r["fingerprint"] for r in rows])
    sec = s.insert_run(kind="security_audit", run_at="2026-09-28T06:00:00", overall="warning")
    rows[0]["fingerprint"] = "ubuntu-server|pve.x|y"
    s.insert_findings(sec, "2026-09-28T06:00:00", "security_audit", rows, [r["fingerprint"] for r in rows])
    for f in s._db.execute("SELECT id FROM findings").fetchall():
        s.set_finding_verdict(f["id"], "false_positive")
    s._db.commit()
    s.close()
    with TestClient(create_app(cfg)) as c:
        yield c


def _rows(html):
    return re.findall(r"<tr(?: [^>]*)?>.*?</tr>", html.split("<tbody>", 1)[1], re.S)


def test_severity_and_status_cells_have_no_lamps(client):
    for row in _rows(client.get("/incidents").text):
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
        for cell in cells[:2]:
            assert 'class="dot"' not in cell and 'class="lamp' not in cell, cell


def test_words_carry_their_colour_classes(client):
    html = client.get("/incidents").text
    for cls, word in [("crit", "critical"), ("warn", "warning"), ("open", "open"),
                      ("done", "resolved"), ("other", "clearing"), ("other", "suppressed")]:
        assert f'<span class="word {cls}">{word}</span>' in html, word


def test_toggle_is_inside_the_incident_row(client):
    rows = _rows(client.get("/incidents").text)
    assert len(rows) == 4
    for row in rows:
        assert row.count("<details") == 1 and "what this incident says" in row
        assert row.rstrip().endswith("</details>\n        </td>\n      </tr>")


def test_false_positive_verdict_has_a_lamp_before_its_words(client):
    for page in ("/findings", "/security"):
        html = client.get(page).text
        assert re.search(r'<span class="verdict"><span class="dot" aria-hidden="true"></span>'
                         r'false positive</span>', html), page


def test_text_tokens_exist_per_mode_and_light_has_no_ok():
    for token in ("--t-crit", "--t-warn", "--t-open"):
        assert CSS.count(token + ":") == 3, token
