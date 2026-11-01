"""Functional charts (Task 9): every chart names its question, unit, window and
observation count; thresholds are labelled hairlines; a null is a gap, not 0."""
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.config import load_config
from heim.dashboard import format as fmt
from heim.dashboard.app import create_app
from heim.incidents.store import IncidentStore

import test_metrics_page as mp

ROOT = Path(__file__).resolve().parent.parent


def _app_client(tmp_path, monkeypatch, seed):
    for k, v in mp.DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("HEIM_DASHBOARD_TOKEN", raising=False)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    cfg.settings.timezone = "UTC"
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    store = IncidentStore(db)
    seed(store)
    store.close()
    with TestClient(create_app(cfg)) as c:
        yield c


def _iso(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat(
        timespec="milliseconds")


def _seed(s):
    s.create_investigation(fingerprint="a", host="ubuntu-server", trigger="daily",
                           status="complete", started_at=_iso(1),
                           input_tokens=120_000, output_tokens=4_000, cost=0.5)


@pytest.fixture()
def spend(tmp_path, monkeypatch):
    yield from _app_client(tmp_path, monkeypatch, _seed)


def test_token_chart_has_question_unit_and_window(spend):
    html = spend.get("/").text
    assert "Is agent spend steady?" in html
    assert re.search(r"tokens per day · 14 days · 14 observations", html)


def test_cost_chart_caption(spend):
    html = spend.get("/costs").text
    assert "What did the agents cost?" in html
    assert re.search(r"USD per day · 14 days · 14 observations", html)


def test_metrics_row_draws_warn_and_crit_lines(tmp_path, monkeypatch):
    # fs/mem rows come from the shared fake Prometheus of the metrics page tests
    monkeypatch.setattr("heim.dashboard.app._fetch_query_ranges", mp.FakeProm())
    for c in _app_client(tmp_path, monkeypatch, lambda s: None):
        t = c.get("/metrics").text
    # mem_used: high-is-bad 85 / 95 over 82 → 86 → 91
    assert "Is memory running out?" in t
    assert "% · 3 days · 3 observations" in t
    assert 'class="thr warn"' in t and 'class="thr crit"' in t
    assert '<title>warn at 85.0%</title>' in t and '<title>crit at 95.0%</title>' in t


def test_missing_observation_is_a_gap_not_zero():
    c = fmt.trend_chart([5.0, None, 0.0], "%", direction="high", warn=8, crit=9)
    assert [b["gap"] for b in c["bars"]] == [False, True, False]
    assert c["n"] == 2 and c["gaps"] == 1
    assert c["bars"][1]["title"].endswith("no data")
    assert c["bars"][2]["h"] == fmt.CHART_STUB and not c["bars"][2]["gap"]  # a real zero
    b = fmt.bar_chart([{"date": "2026-09-15", "weekday": "tu", "tokens": None},
                       {"date": "2026-09-16", "weekday": "we", "tokens": 0},
                       {"date": "2026-09-17", "weekday": "th", "tokens": 10}])
    assert [x["gap"] for x in b["bars"]] == [True, False, False]
    assert b["bars"][0]["title"] == "2026-09-15 · no data"
    assert b["bars"][1]["title"] == "2026-09-16 · 0 tokens"
    assert b["n"] == 2 and b["gaps"] == 1
    # no thresholds unless the catalog direction has a numeric line
    assert fmt.trend_chart([1, 2, 3], "", direction="info", warn=1, crit=2)["lines"] == []
