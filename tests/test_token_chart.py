"""Token usage by weekday (spec §11): the store's zero-filled daily totals, the
pure geometry helper that turns them into bars, and the overview card that
renders them as a server-side SVG.

The store reader takes ``now_iso`` so the 14-day window is a fact about the
argument, not about the machine's clock.
"""
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.config import load_config
from heim.dashboard import format as fmt
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
    """The committed example config, exactly like tests/test_dashboard.py."""
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
    def seed(s):
        # two days inside the window carry tokens; every other day is a zero
        s.create_investigation(fingerprint="ubuntu-server|mem|Memory", host="ubuntu-server",
                               trigger="poller", status="complete", started_at=_iso(1),
                               input_tokens=120_000, output_tokens=4_000)
        s.create_investigation(fingerprint="homelab|temp|Drive", host="homelab",
                               trigger="daily", status="resolved", started_at=_iso(3),
                               input_tokens=9_000, output_tokens=400)
        s.insert_run(kind="daily", run_at=_iso(1), overall="healthy",
                     model_used="claude-opus-4-6", duration_s=12.0,
                     counts_json=json.dumps({}), input_tokens=2_000, output_tokens=300)
    yield from _client(tmp_path, monkeypatch, seed)


@pytest.fixture()
def empty_client(tmp_path, monkeypatch):
    """A store with activity but *no* tokens: one open incident keeps the page
    off its own "no activity yet" state, so the card's empty state is what is
    under test rather than the page's."""
    def seed(s):
        s.upsert([{"fingerprint": "homelab|temp|Drive", "host": "homelab",
                   "metric": "temp", "severity": "warning", "status": "open",
                   "firstSeen": _iso(1), "lastSeen": _iso(0), "timesSeen": 2,
                   "missedRuns": 0, "description": "sdb warm."}])
    yield from _client(tmp_path, monkeypatch, seed)


# ------------------------------------------------------------------- store

def test_daily_token_totals_zero_filled_and_summed(tmp_path):
    s = IncidentStore(tmp_path / "t.sqlite3")
    s.create_investigation(fingerprint="f", host="h", trigger="daily", status="complete",
                           started_at="2026-09-16T10:00:00", input_tokens=1000, output_tokens=200)
    s.insert_run(kind="daily", run_at="2026-09-16T22:00:00", overall="healthy",
                 model_used="m", duration_s=1.0, counts_json="{}",
                 input_tokens=300, output_tokens=50)
    rows = s.daily_token_totals(days=3, now_iso="2026-09-17T12:00:00")
    assert [r["date"] for r in rows] == ["2026-09-15", "2026-09-16", "2026-09-17"]
    assert rows[0]["tokens"] == 0 and rows[1]["tokens"] == 1550 and rows[2]["tokens"] == 0
    assert rows[1]["weekday"] == "we"   # 2026-09-16 is a Wednesday
    s.close()


def test_daily_token_totals_window_excludes_older_days(tmp_path):
    s = IncidentStore(tmp_path / "t.sqlite3")
    s.create_investigation(fingerprint="old", host="h", trigger="daily", status="complete",
                           started_at="2026-09-01T10:00:00", input_tokens=5000, output_tokens=0)
    rows = s.daily_token_totals(days=14, now_iso="2026-09-17T12:00:00")
    assert len(rows) == 14
    assert rows[0]["date"] == "2026-09-04" and rows[-1]["date"] == "2026-09-17"
    assert sum(r["tokens"] for r in rows) == 0      # the old row is out of window
    s.close()


def test_daily_token_totals_empty_store_is_all_zero(tmp_path):
    s = IncidentStore(tmp_path / "t.sqlite3")
    rows = s.daily_token_totals(days=14, now_iso="2026-09-17T12:00:00")
    assert len(rows) == 14 and all(r["tokens"] == 0 for r in rows)
    assert [r["weekday"] for r in rows][-1] == "th"   # 2026-09-17 is a Thursday
    s.close()


# ---------------------------------------------------------------- geometry

def _points():
    return [{"date": "2026-09-15", "weekday": "tu", "tokens": 0},
            {"date": "2026-09-16", "weekday": "we", "tokens": 1550},
            {"date": "2026-09-17", "weekday": "th", "tokens": 775}]


def test_bar_chart_geometry_scales_to_the_max_and_stubs_zero_days():
    chart = fmt.bar_chart(_points())
    bars = chart["bars"]
    assert [b["h"] for b in bars] == [fmt.CHART_STUB, chart["span"], round(chart["span"] / 2)]
    # every bar sits on the baseline, tallest bar tops out at CHART_TOP
    assert all(b["y"] + b["h"] == fmt.CHART_BASELINE for b in bars)
    assert bars[1]["y"] == fmt.CHART_TOP
    # 2px gaps: slots are bar width + gap, first bar inset by half a gap
    assert bars[1]["x"] - bars[0]["x"] == fmt.CHART_SLOT
    assert bars[0]["w"] == fmt.CHART_SLOT - fmt.CHART_GAP
    assert chart["width"] == 3 * fmt.CHART_SLOT and chart["max"] == 1550


def test_bar_chart_labels_only_the_max_bar_but_titles_every_bar():
    chart = fmt.bar_chart(_points())
    assert [b["is_max"] for b in chart["bars"]] == [False, True, False]
    assert [b["label"] for b in chart["bars"]] == ["", "1.6k", ""]
    assert chart["bars"][0]["title"] == "2026-09-15 · 0 tokens"
    assert chart["bars"][1]["title"] == "2026-09-16 · 1,550 tokens"
    assert chart["total"] == 2325
    assert chart["busiest"]["date"] == "2026-09-16"


def test_bar_chart_all_zero_has_no_max_bar():
    chart = fmt.bar_chart([{"date": "2026-09-15", "weekday": "tu", "tokens": 0}] * 3)
    assert chart["total"] == 0 and chart["max"] == 0 and chart["busiest"] is None
    assert all(b["h"] == fmt.CHART_STUB and not b["is_max"] for b in chart["bars"])


def test_bar_chart_is_reusable_for_a_second_series():
    """Task 8's cost-by-day chart reuses the geometry with its own formatters."""
    chart = fmt.bar_chart(
        [{"date": "2026-09-16", "weekday": "we", "cost": 0.42},
         {"date": "2026-09-17", "weekday": "th", "cost": 0.21}],
        value_key="cost", unit="", fmt_label=fmt.money, fmt_exact=fmt.money)
    assert chart["bars"][0]["label"] == "$0.42"
    assert chart["bars"][1]["title"] == "2026-09-17 · $0.21"
    assert chart["bars"][0]["h"] == chart["span"]


# ------------------------------------------------------------------ render

def test_overview_renders_token_chart(seeded_client):
    html = seeded_client.get("/").text
    assert "token usage" in html and "<svg" in html and 'class="tchart"' in html
    assert html.count("<rect") >= 14                      # one bar per day incl. zero stubs
    assert 'title>' in html or "<title>" in html          # per-bar tooltips
    assert "14d:" in html and "busiest" in html


def test_token_chart_marks_one_value_label_and_tooltips_every_day(seeded_client):
    html = seeded_client.get("/").text
    assert html.count('class="val"') == 1                 # selective labels
    assert html.count("</title>") >= 14                   # incl. the zero days
    assert 'fill="var(--ember)"' in html or "tchart" in html
    # the busiest day is yesterday's investigation + run: 126.3k tokens
    assert fmt.tokens(120_000 + 4_000 + 2_000 + 300) in html


def test_token_chart_empty_state(empty_client):
    assert "No token usage recorded yet." in empty_client.get("/").text
