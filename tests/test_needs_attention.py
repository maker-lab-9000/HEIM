"""Needs attention (spec §12): the operator's triage queue.

The store side is two small readers over ``investigations`` — the runs that did
not finish cleanly (incomplete / failed / needs_human), newest first, plus the
count behind the "all (N)" link. The page side is one overview card placed
directly under the health card, because bad news travels first.

The client fixtures follow tests/test_token_chart.py: the committed example
config, a temp db seeded before the app starts.
"""
import shutil
from datetime import datetime, timedelta, timezone
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


def _config(tmp_path, monkeypatch):
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("HEIM_DASHBOARD_TOKEN", raising=False)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    return load_config(croot)


def _iso(days_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat(
        timespec="milliseconds")


def _client(tmp_path, monkeypatch, seed) -> TestClient:
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    store = IncidentStore(db)
    seed(store)
    store.close()
    app = create_app(cfg)
    with TestClient(app) as client:
        yield client


@pytest.fixture()
def seeded_client(tmp_path, monkeypatch):
    """All three attention statuses, plus a clean run that must stay out."""
    def seed(s):
        s.create_investigation(fingerprint="ubuntu-server|mem|Memory", host="ubuntu-server",
                               trigger="poller", status="incomplete", started_at=_iso(1),
                               incomplete_reason="budget exhausted after 12 steps")
        s.create_investigation(fingerprint="homelab|temp|Drive", host="homelab",
                               trigger="daily", status="failed", started_at=_iso(2),
                               incomplete_reason="ssh timed out")
        s.create_investigation(fingerprint="home-assistant|zigbee|Radio",
                               host="home-assistant", trigger="poller",
                               status="needs_human", started_at=_iso(3),
                               outcome="needs a physical power cycle")
        s.create_investigation(fingerprint="homelab|cpu|Load", host="homelab",
                               trigger="daily", status="complete", started_at=_iso(0))
    yield from _client(tmp_path, monkeypatch, seed)


@pytest.fixture()
def many_client(tmp_path, monkeypatch):
    """Seven failed runs — one more than the card shows, so the footer link
    has a reason to exist."""
    def seed(s):
        for i in range(7):
            s.create_investigation(fingerprint=f"homelab|m{i}|Metric", host="homelab",
                                   trigger="daily", status="failed", started_at=_iso(i + 1),
                                   incomplete_reason="ssh timed out")
    yield from _client(tmp_path, monkeypatch, seed)


@pytest.fixture()
def empty_client(tmp_path, monkeypatch):
    """Activity, but nothing that failed: one open incident keeps the page off
    its own "no activity yet" state, so the card's empty state is what is under
    test rather than the page's."""
    def seed(s):
        s.upsert([{"fingerprint": "homelab|temp|Drive", "host": "homelab",
                   "metric": "temp", "severity": "warning", "status": "open",
                   "firstSeen": _iso(1), "lastSeen": _iso(0), "timesSeen": 2,
                   "missedRuns": 0, "description": "sdb warm."}])
    yield from _client(tmp_path, monkeypatch, seed)


# ------------------------------------------------------------------- store

def test_store_needs_attention(tmp_path):
    from heim.incidents.store import IncidentStore
    s = IncidentStore(tmp_path / "n.sqlite3")
    for i, st in enumerate(["complete", "incomplete", "failed", "needs_human", "running"]):
        s.create_investigation(fingerprint=f"f{i}", host="h", trigger="daily", status=st,
                               started_at=f"2026-09-1{i}T00:00:00",
                               incomplete_reason="budget" if st == "incomplete" else "")
    rows = s.needs_attention()
    assert [r["status"] for r in rows] == ["needs_human", "failed", "incomplete"]  # newest first
    assert s.needs_attention_count() == 3
    s.close()


def test_store_needs_attention_limit_and_empty(tmp_path):
    s = IncidentStore(tmp_path / "n.sqlite3")
    assert s.needs_attention() == [] and s.needs_attention_count() == 0
    for i in range(8):
        s.create_investigation(fingerprint=f"f{i}", host="h", trigger="daily",
                               status="failed", started_at=f"2026-09-0{i}T00:00:00")
    assert len(s.needs_attention()) == 6                 # spec §12: latest 6
    assert len(s.needs_attention(limit=2)) == 2
    assert s.needs_attention_count() == 8                # the count is unlimited
    s.close()


# -------------------------------------------------------------------- card

def test_overview_needs_attention_card(seeded_client):
    html = seeded_client.get("/").text
    card = html[html.index("needs attention"):]
    assert "incomplete" in card and "RE-RUN" in card and "budget" in card


def test_card_sits_under_the_health_card(seeded_client):
    html = seeded_client.get("/").text
    # bad news travels first: after the health card, before the latest runs
    assert html.index("card health") < html.index("needs attention") \
        < html.index("latest runs")


def test_card_shows_every_attention_status_and_no_clean_run(seeded_client):
    card = seeded_client.get("/").text
    card = card[card.index("needs attention"):card.index("latest runs")]
    assert "incomplete" in card and "failed" in card and "needs human" in card
    assert "ssh timed out" in card and "needs a physical power cycle" in card
    assert "cpu|Load" not in card and "#4" not in card     # the complete run
    # each row links its investigation and carries its own retrigger form
    for inv_id in (1, 2, 3):
        assert f'href="/investigations/{inv_id}"' in card
        assert f'value="{inv_id}"' in card
    assert card.count('action="/actions/retrigger"') == 3
    assert "all (" not in card      # three rows fit, so no overflow link


def test_card_rerun_form_enqueues_a_retry(seeded_client):
    """The card hand-rolls nothing: it posts the same form the investigation
    page posts, so a plain no-JS submit queues a job and comes back to /."""
    resp = seeded_client.post("/actions/retrigger",
                              data={"investigation_id": "1", "back": "/"})
    assert resp.status_code == 200                       # 303 followed back to /
    assert "waiting for the daemon" in resp.text         # the queued KPI moved
    # the htmx face of the same form re-renders the panel with the flash line
    hx = seeded_client.post("/actions/retrigger",
                            data={"investigation_id": "2", "back": "/"},
                            headers={"hx-request": "true"})
    assert hx.status_code == 200 and "Queued as job #2" in hx.text


def test_footer_link_appears_past_six(many_client):
    many = many_client.get("/").text
    many = many[many.index("needs attention"):many.index("latest runs")]
    assert "all (7)" in many and 'href="/investigations"' in many


def test_overview_needs_attention_empty_is_good_news(empty_client):
    assert "Nothing needs attention." in empty_client.get("/").text
