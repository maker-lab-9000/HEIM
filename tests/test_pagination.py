"""Pagination: offset on the store's list readers, and the "LOAD 50 MORE"
button the three list pages grow when the store has more than one page.

The pages stay server-rendered: the button is a plain link first (a no-JS
browser lands on the next window as a full page) and an htmx swap second.
"""
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.config import load_config
from heim.dashboard.app import create_app
from heim.incidents.store import IncidentStore

ROOT = Path(__file__).resolve().parent.parent

DUMMY_ENV = {
    "HEIM_SERVER_IP": "10.0.0.10",
    "HEIM_PROXMOX_IP": "10.0.0.2",
    "HEIM_HA_IP": "10.0.0.3",
    "HEIM_TELEGRAM_CHAT_ID": "111111111",
    "HEIM_EMAIL_TO": "test@example.com",
    "HEIM_EMAIL_FROM": "test@example.com",
}


@pytest.fixture()
def store(tmp_path):
    s = IncidentStore(tmp_path / "p.sqlite3")
    yield s
    s.close()


# ------------------------------------------------------------------- store


def test_investigations_offset(store):
    for i in range(7):
        store.create_investigation(fingerprint=f"f{i}", host="h", trigger="manual",
                                   status="complete", started_at=f"2026-09-1{i}T00:00:00")
    first = store.investigations(limit=5)
    rest = store.investigations(limit=5, offset=5)
    assert len(first) == 5 and len(rest) == 2
    assert first[0]["id"] != rest[0]["id"]
    assert {r["id"] for r in first}.isdisjoint({r["id"] for r in rest})


def test_incidents_offset(store):
    store.upsert([{"fingerprint": f"fp{i}", "host": "h", "metric": "m", "severity": "warning",
                   "status": "open", "firstSeen": f"2026-09-0{i+1}", "lastSeen": f"2026-09-0{i+1}",
                   "resolvedAt": "", "timesSeen": 1, "missedRuns": 0, "description": "d",
                   "investigated": False} for i in range(6)])
    assert len(store.all_rows(limit=4)) == 4
    assert len(store.all_rows(limit=4, offset=4)) == 2


def test_findings_and_runs_offset(store):
    run_id = store.insert_run(kind="daily", run_at="2026-09-18T00:00:00")
    store.insert_findings(run_id, "2026-09-18T00:00:00", "daily",
                          [{"severity": "warning", "host": "h", "metric": f"m{i}",
                            "summary": f"s{i}"} for i in range(6)])
    first = store.recent_findings(limit=4)
    rest = store.recent_findings(limit=4, offset=4)
    assert len(first) == 4 and len(rest) == 2
    assert {r["id"] for r in first}.isdisjoint({r["id"] for r in rest})
    for i in range(3):
        store.insert_run(kind="poller", run_at=f"2026-09-19T0{i}:00:00")
    assert len(store.runs(limit=2)) == 2
    assert len(store.runs(limit=2, offset=2)) == 2
    assert len(store.runs(limit=10, offset=3)) == 1


def test_investigations_offset_composes_with_status(store):
    for i in range(6):
        store.create_investigation(fingerprint=f"f{i}", host="h", trigger="manual",
                                   status="running" if i % 2 else "resolved",
                                   started_at=f"2026-09-1{i}T00:00:00")
    running = store.investigations(limit=10, status="running")
    assert len(running) == 3
    assert len(store.investigations(limit=10, status="running", offset=2)) == 1


# -------------------------------------------------------------- app fixture


def _config(tmp_path, monkeypatch):
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("HEIM_DASHBOARD_TOKEN", raising=False)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    return load_config(croot)


def _client(tmp_path, monkeypatch, seed):
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    s = IncidentStore(db)
    seed(s)
    s.close()
    app = create_app(cfg)
    return TestClient(app)


@pytest.fixture()
def client_with_60_investigations(tmp_path, monkeypatch):
    def seed(s):
        for i in range(60):
            s.create_investigation(fingerprint=f"ubuntu-server|m{i}|Thing {i}",
                                   host="ubuntu-server", trigger="manual",
                                   status="resolved", started_at=f"2026-09-18T00:{i:02d}:00")
    with _client(tmp_path, monkeypatch, seed) as c:
        yield c


@pytest.fixture()
def client_with_60_incidents(tmp_path, monkeypatch):
    def seed(s):
        s.upsert([{"fingerprint": f"ubuntu-server|m{i}|Thing {i}", "host": "ubuntu-server",
                   "metric": f"m{i}", "severity": "warning", "status": "open",
                   "firstSeen": f"2026-09-18T00:{i:02d}:00",
                   "lastSeen": f"2026-09-18T00:{i:02d}:00", "resolvedAt": "",
                   "timesSeen": 1, "missedRuns": 0, "description": "d",
                   "investigated": False} for i in range(60)])
    with _client(tmp_path, monkeypatch, seed) as c:
        yield c


@pytest.fixture()
def client_with_60_findings(tmp_path, monkeypatch):
    """12 runs × 5 findings = 60 findings, so a page boundary falls on a run
    boundary (50 = 10 whole runs) and the grouping can be checked."""
    def seed(s):
        for r in range(12):
            run_id = s.insert_run(kind="daily", run_at=f"2026-09-{r+1:02d}T00:00:00")
            s.insert_findings(run_id, f"2026-09-{r+1:02d}T00:00:00", "daily",
                              [{"severity": "warning", "host": "ubuntu-server",
                                "metric": f"m{r}-{i}", "summary": f"run {r} finding {i}"}
                               for i in range(5)])
    with _client(tmp_path, monkeypatch, seed) as c:
        yield c


def _unesc(html: str) -> str:
    return html.replace("&amp;", "&")


# -------------------------------------------------------------- list routes


def test_investigations_page_paginates(client_with_60_investigations):
    c = client_with_60_investigations
    html = c.get("/investigations").text
    assert html.count('href="/investigations/') == 50
    assert "LOAD 50 MORE" in html
    assert 'href="/investigations?offset=50' in _unesc(html)
    page2 = c.get("/investigations?offset=50").text
    assert page2.count('href="/investigations/') == 10
    assert "LOAD 50 MORE" not in page2          # exhausted


def test_investigations_pagination_keeps_filters(client_with_60_investigations):
    c = client_with_60_investigations
    html = _unesc(c.get("/investigations?status=resolved").text)
    assert "LOAD 50 MORE" in html
    assert "status=resolved" in html and "offset=50" in html
    # a filter that matches nothing has nothing more to load
    empty = c.get("/investigations?status=failed").text
    assert "LOAD 50 MORE" not in empty


def test_investigations_rows_partial_paginates(client_with_60_investigations):
    """The htmx partial (filter row + 5s poll) carries the same window, so a
    poll refreshes the page the operator is looking at instead of page one."""
    c = client_with_60_investigations
    rows = c.get("/investigations/rows?offset=50").text
    assert rows.strip().startswith("<tbody")
    assert rows.count('href="/investigations/') == 10
    assert "LOAD 50 MORE" not in rows
    first = c.get("/investigations/rows").text
    assert first.count('href="/investigations/') == 50
    assert "LOAD 50 MORE" in first
    assert "offset=50" in _unesc(first)


def test_incidents_page_paginates(client_with_60_incidents):
    c = client_with_60_incidents
    html = c.get("/incidents").text
    assert html.count('class="xrow"') == 50
    assert "LOAD 50 MORE" in html
    assert 'href="/incidents?offset=50"' in _unesc(html)
    page2 = c.get("/incidents?offset=50").text
    assert page2.count('class="xrow"') == 10
    assert "LOAD 50 MORE" not in page2


def test_findings_page_paginates_on_run_boundaries(client_with_60_findings):
    c = client_with_60_findings
    html = c.get("/findings").text
    # 50 findings = 10 whole runs; the 11th run opens the next page
    assert html.count("<tbody>") == 10
    assert html.count("run 0 finding") == 5
    assert "run 10 finding 0" not in html
    assert "LOAD 50 MORE" in html
    assert 'href="/findings?offset=50"' in _unesc(html)
    page2 = c.get("/findings?offset=50").text
    assert page2.count("<tbody>") == 2
    assert "run 10 finding 0" in page2 and "run 11 finding 4" in page2
    assert "run 9 finding 0" not in page2
    assert "LOAD 50 MORE" not in page2


def test_findings_page_never_splits_a_run(tmp_path, monkeypatch):
    """A run straddling the 50th finding is pushed whole to the next page, so
    no run header is ever printed twice."""
    def seed(s):
        for r in range(6):
            run_id = s.insert_run(kind="daily", run_at=f"2026-09-{r+1:02d}T00:00:00")
            s.insert_findings(run_id, f"2026-09-{r+1:02d}T00:00:00", "daily",
                              [{"severity": "info", "host": "ubuntu-server",
                                "metric": f"m{r}-{i}", "summary": f"run {r} finding {i}"}
                               for i in range(11)])
    with _client(tmp_path, monkeypatch, seed) as c:
        html = c.get("/findings").text
        # newest first: runs 5..1 are 55 findings, so the window stops at 4
        # whole runs (44 findings) rather than cutting run 1 in half
        assert html.count("<tbody>") == 4
        assert "run 1 finding" not in html
        assert "LOAD 50 MORE" in html
        assert 'href="/findings?offset=44"' in _unesc(html)
        page2 = c.get("/findings?offset=44").text
        assert page2.count("<tbody>") == 2
        assert "run 1 finding 0" in page2 and "run 0 finding 10" in page2
        assert "LOAD 50 MORE" not in page2


def test_pagination_ignores_junk_offsets(client_with_60_investigations):
    c = client_with_60_investigations
    for bad in ("-10", "abc", "", "1e9999"):
        r = c.get(f"/investigations?offset={bad}")
        assert r.status_code == 200
    assert c.get("/investigations?offset=abc").text.count('href="/investigations/') == 50
    assert c.get("/investigations?offset=-10").text.count('href="/investigations/') == 50
    # past the end: an empty window, and nothing more to load
    beyond = c.get("/investigations?offset=500").text
    assert "LOAD 50 MORE" not in beyond


def test_ghost_rows_are_never_paginated(tmp_path, monkeypatch):
    """Queued jobs sit above the real rows on every window, not just page one."""
    def seed(s):
        for i in range(60):
            s.create_investigation(fingerprint=f"f{i}", host="ubuntu-server",
                                   trigger="manual", status="resolved",
                                   started_at=f"2026-09-18T00:{i:02d}:00")
        s.enqueue_job("investigate", {"host": "ubuntu-server", "fingerprint": "queued|me|Q"},
                      requested_by="test")
    with _client(tmp_path, monkeypatch, seed) as c:
        for url in ("/investigations", "/investigations?offset=50"):
            html = c.get(url).text
            assert 'class="ghost"' in html, url


def test_loadmore_button_is_a_plain_link_first(client_with_60_investigations):
    """No-JS path (global constraint): the control is an <a href>, and the
    href alone reaches the next window."""
    c = client_with_60_investigations
    html = _unesc(c.get("/investigations").text)
    i = html.index("LOAD 50 MORE")
    anchor = html[html.rindex("<a", 0, i):i]
    assert anchor.startswith("<a ") and 'href="/investigations?offset=50"' in anchor
    assert 'class="btn"' in anchor


def test_css_has_a_loadmore_row(client_with_60_investigations):
    css = client_with_60_investigations.get("/static/heim.css").text
    assert ".loadmore" in css
