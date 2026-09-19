"""Cost monitor (spec §13): where the money goes, by model and by day.

The store aggregations take ``since_iso``/``now_iso`` so a window is a fact
about the argument rather than about this machine's clock; the page prices
those aggregates through ``heim.costing.cost_of`` and the configured
``model_prices``, so a model with no price renders an em dash — never ``$0.00``,
which would claim the calls were free.
"""
import json
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
    """The committed example config, exactly like tests/test_token_chart.py."""
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
    cfg.settings.timezone = "UTC"      # stored stamps and the window share a clock
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
    """Two sonnet investigations and one opus run inside the window, plus an
    old haiku investigation that only `window=all` should see."""
    def seed(s):
        s.create_investigation(fingerprint="a", host="ubuntu-server", trigger="daily",
                               status="complete", model="claude-sonnet-4-6",
                               started_at=_iso(1), input_tokens=100_000,
                               output_tokens=4_000, cost=0.36)
        s.create_investigation(fingerprint="b", host="homelab", trigger="poller",
                               status="complete", model="claude-sonnet-4-6",
                               started_at=_iso(2), input_tokens=50_000,
                               output_tokens=2_000, cost=0.18)
        s.insert_run(kind="daily", run_at=_iso(1), overall="healthy",
                     model_used="claude-opus-4-6", duration_s=1.0,
                     counts_json=json.dumps({}), input_tokens=20_000,
                     output_tokens=1_500, cost=0.14)
        s.create_investigation(fingerprint="old", host="homelab", trigger="daily",
                               status="complete", model="claude-haiku-4-5",
                               started_at=_iso(40), input_tokens=10_000,
                               output_tokens=1_000, cost=0.015)
    yield from _client(tmp_path, monkeypatch, seed)


@pytest.fixture()
def unpriced_client(tmp_path, monkeypatch):
    """One priced model and one the settings have never heard of."""
    def seed(s):
        s.create_investigation(fingerprint="a", host="ubuntu-server", trigger="daily",
                               status="complete", model="claude-sonnet-4-6",
                               started_at=_iso(1), input_tokens=100_000,
                               output_tokens=4_000, cost=0.36)
        s.create_investigation(fingerprint="c", host="homelab", trigger="manual",
                               status="complete", model="mystery-model-9",
                               started_at=_iso(1), input_tokens=9_000,
                               output_tokens=800, cost=0.0)
    yield from _client(tmp_path, monkeypatch, seed)


@pytest.fixture()
def free_client(tmp_path, monkeypatch):
    """A model whose configured price IS zero — a free tier is a fact, not a
    gap, so it renders $0.00 rather than the unpriced em dash (spec §13)."""
    def seed(s):
        s.create_investigation(fingerprint="f", host="homelab", trigger="daily",
                               status="complete", model="google/gemma-4-31b-it:free",
                               started_at=_iso(1), input_tokens=12_000,
                               output_tokens=900, cost=0.0)
    yield from _client(tmp_path, monkeypatch, seed)


@pytest.fixture()
def empty_client(tmp_path, monkeypatch):
    yield from _client(tmp_path, monkeypatch, lambda s: None)


# ------------------------------------------------------------------- store

def test_cost_by_model_groups_and_sums(tmp_path):
    s = IncidentStore(tmp_path / "c.sqlite3")
    s.create_investigation(fingerprint="a", host="h", trigger="daily", status="complete",
                           model="claude-sonnet-4-6", started_at="2026-09-18T10:00:00",
                           input_tokens=100000, output_tokens=4000, cost=0.36)
    s.create_investigation(fingerprint="b", host="h", trigger="daily", status="complete",
                           model="claude-sonnet-4-6", started_at="2026-09-18T11:00:00",
                           input_tokens=50000, output_tokens=2000, cost=0.18)
    s.insert_run(kind="daily", run_at="2026-09-18T22:00:00", overall="healthy",
                 model_used="claude-opus-4-6", duration_s=1.0, counts_json="{}",
                 input_tokens=20000, output_tokens=1500, cost=0.14)
    rows = s.cost_by_model(since_iso=None)
    inv = next(r for r in rows if r["model"] == "claude-sonnet-4-6")
    assert inv["calls"] == 2 and inv["tokens_in"] == 150000 and round(inv["cost"], 2) == 0.54
    assert inv["role"] == "investigator"
    run = next(r for r in rows if r["model"] == "claude-opus-4-6")
    assert run["role"] == "analyst" and run["calls"] == 1
    # window filter
    assert s.cost_by_model(since_iso="2026-09-19T00:00:00") == []
    s.close()


def test_cost_by_model_names_a_missing_model_unknown(tmp_path):
    s = IncidentStore(tmp_path / "c.sqlite3")
    s.create_investigation(fingerprint="a", host="h", trigger="daily", status="complete",
                           model="", started_at="2026-09-18T10:00:00",
                           input_tokens=1000, output_tokens=100, cost=0.0)
    s.insert_run(kind="daily", run_at="2026-09-18T22:00:00", overall="healthy",
                 duration_s=1.0, counts_json="{}", input_tokens=500, output_tokens=50)
    rows = s.cost_by_model(since_iso=None)
    assert {r["model"] for r in rows} == {"unknown"}
    assert {r["role"] for r in rows} == {"investigator", "analyst"}
    s.close()


def test_cost_by_day_zero_filled_and_summed(tmp_path):
    s = IncidentStore(tmp_path / "c.sqlite3")
    s.create_investigation(fingerprint="a", host="h", trigger="daily", status="complete",
                           model="m", started_at="2026-09-16T10:00:00",
                           input_tokens=1000, output_tokens=200, cost=0.25)
    s.insert_run(kind="daily", run_at="2026-09-16T22:00:00", overall="healthy",
                 model_used="m", duration_s=1.0, counts_json="{}",
                 input_tokens=300, output_tokens=50, cost=0.05)
    rows = s.cost_by_day(days=3, now_iso="2026-09-17T12:00:00")
    assert [r["date"] for r in rows] == ["2026-09-15", "2026-09-16", "2026-09-17"]
    assert rows[0]["cost"] == 0 and round(rows[1]["cost"], 2) == 0.30
    assert rows[1]["weekday"] == "we"       # 2026-09-16 is a Wednesday
    s.close()


def test_cost_by_day_empty_store_is_all_zero(tmp_path):
    s = IncidentStore(tmp_path / "c.sqlite3")
    rows = s.cost_by_day(days=14, now_iso="2026-09-17T12:00:00")
    assert len(rows) == 14 and all(r["cost"] == 0 for r in rows)
    s.close()


# ------------------------------------------------------------------ render

def test_costs_page_renders_models_and_total(seeded_client):
    html = seeded_client.get("/costs").text
    assert "claude-sonnet-4-6" in html and "investigator" in html
    assert "$0.54" in html and "$0.68" in html          # model row and window total
    # the share bars themselves, not just the column header: one magnitude bar
    # per model row, each sized by that model's share of the window's spend
    assert html.count('class="tubar"') == 2
    assert 'class="seg" style="width:79.7%"' in html    # sonnet: 0.54 of 0.6775
    assert 'class="seg" style="width:20.3%"' in html    # opus: the rest
    assert 'href="/costs?window=7d"' in html            # window switcher


def test_costs_page_flags_unpriced_models(unpriced_client):
    html = unpriced_client.get("/costs").text
    assert "no price" in html and "add it to model_prices" in html
    assert "$0.00" not in html                          # unpriced renders —, never zero


def test_nav_has_costs(seeded_client):
    assert 'href="/costs"' in seeded_client.get("/").text


def test_costs_window_switcher_changes_the_window(seeded_client):
    """Default is 30d; only `all` reaches the 40-day-old haiku run."""
    assert "claude-haiku-4-5" not in seeded_client.get("/costs").text
    assert "claude-haiku-4-5" not in seeded_client.get("/costs?window=7d").text
    # and the wider window's total grows by exactly that run's price
    assert "$0.69" in seeded_client.get("/costs?window=all").text
    assert "$0.68" in seeded_client.get("/costs?window=7d").text


def test_costs_page_charts_spend_by_day(seeded_client):
    html = seeded_client.get("/costs").text
    assert 'class="tchart"' in html                      # the §11 chart, cost series
    assert html.count("<rect") >= 14                     # one bar per day incl. stubs
    assert "$0.50" in html or "$0.5" in html             # the busiest day's label
    # the chart sums what each run booked, the table re-prices from settings —
    # say so, so the two totals can never disagree in silence
    assert "as booked when each run happened" in html


def test_costs_free_tier_renders_zero_not_a_dash(free_client):
    """A configured price of 0 is a real number — only a MISSING price dashes."""
    html = free_client.get("/costs").text
    assert "$0.00" in html and "no price" not in html


def test_costs_empty_state(empty_client):
    html = empty_client.get("/costs").text
    assert empty_client.get("/costs").status_code == 200
    assert "No spend recorded" in html


def test_both_charts_come_from_the_one_shared_macro():
    """Task 6 left the SVG inline in overview.html; §13's chart is the same
    geometry, so the markup lives in a macro with two call sites."""
    tpl = ROOT / "src/heim/dashboard/templates"
    macros = (tpl / "partials/_macros.html").read_text()
    assert "macro daychart" in macros and "clipPath" in macros
    for page in ("overview.html", "costs.html"):
        body = (tpl / page).read_text()
        assert "m.daychart(" in body
        assert "<clipPath" not in body      # no copy-pasted SVG left behind
