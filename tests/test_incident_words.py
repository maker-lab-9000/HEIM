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
    rows = re.findall(r"<tr(?: [^>]*)?>.*?</tr>", html.split("<tbody>", 1)[1], re.S)
    return [r for r in rows if not r.startswith('<tr class="xbody"')]  # the detail rows are separate


def test_severity_and_status_cells_have_no_lamps(client):
    for row in _rows(client.get("/incidents").text):
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
        for cell in cells[:2]:
            assert 'class="dot"' not in cell and 'class="lamp' not in cell, cell


def test_words_carry_their_colour_classes(client):
    html = client.get("/incidents").text
    for cls, word in [("crit", "critical"), ("warn", "warning"), ("you", "open"),
                      ("ok", "resolved"), ("go", "clearing"), ("other", "suppressed")]:
        assert f'<span class="word {cls}">{word}</span>' in html, word


def test_toggle_is_inside_the_incident_row(client):
    rows = _rows(client.get("/incidents").text)
    assert len(rows) == 4
    for row in rows:
        assert row.count("<details") == 1 and ">Details</summary>" in row
        assert row.rstrip().endswith("</details>\n        </td>\n      </tr>")


def test_false_positive_verdict_has_a_lamp_before_its_words(client):
    for page in ("/findings", "/security"):
        html = client.get(page).text
        # a pressed, set-aside key since 2026-11-02: the dark lamp, then the words
        assert re.search(r'<button class="btn pressed other"[^>]*><span class="dot" aria-hidden="true">'
                         r'</span><span class="verdict">false positive</span>', html), page


def test_text_tokens_exist_per_mode_and_light_has_no_ok():
    for token in ("--t-crit", "--t-warn", "--t-open"):
        assert CSS.count(token + ":") == 3, token


def test_detail_opens_as_its_own_row_with_the_forms(client):
    html = client.get("/incidents").text
    body = html.split("<tbody>", 1)[1]
    assert body.count('<tr class="xbody">') == 4 and body.count('class="xrow"') == 4
    for row in _rows(html):
        after = body[body.index(row) + len(row):].lstrip()
        assert after.startswith('<tr class="xbody"><td colspan="11">')
        assert "<form" not in row                       # the forms live in the body row
    assert body.count("<form") >= 4 and 'hx-post="/actions/' in body
    css = open("src/heim/dashboard/static/heim.css").read()
    assert "tr:has(details[open]) + tr.xbody { display: table-row; }" in css


def test_fingerprints_break_only_after_a_pipe(client):
    html = client.get("/incidents").text
    assert "|<wbr>" in html.split("<tbody>", 1)[1]


def test_flagged_first_cells_leave_room_for_the_bar(client):
    html = client.get("/incidents").text
    assert '<tr class="flag">\n        <td>' in html and 'class="tbl dense flg incs"' in html
    css = open("src/heim/dashboard/static/heim.css").read()
    assert ".tbl.flg td:first-child { padding-left: 12px; }" in css.replace(
        ".tbl.flg th:first-child, ", "")
    assert "tr.flag td:first-child { box-shadow: inset 4px 0 0 var(--signal); }" in css
