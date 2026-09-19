"""Metrics page tests (design spec §6).

The page is the only one that leaves the box, so the tests cut the wire at the
lowest useful point: ``_fetch_query_ranges`` is replaced by a fake that hands
back canned Prometheus matrix JSON for a handful of catalog queries. Everything
downstream — ``aggregate``, the flag thresholds, the per-day buckets, the sort,
the humanizer — runs for real, so a change in any of them shows up here.
"""
import shutil
from dataclasses import asdict
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.config import load_config
from heim.dashboard.app import create_app

ROOT = Path(__file__).resolve().parent.parent

DUMMY_ENV = {
    "HEIM_SERVER_IP": "10.0.0.10",
    "HEIM_PROXMOX_IP": "10.0.0.2",
    "HEIM_HA_IP": "10.0.0.3",
    "HEIM_TELEGRAM_CHAT_ID": "111111111",
    "HEIM_EMAIL_TO": "test@example.com",
    "HEIM_EMAIL_FROM": "test@example.com",
}

DAY = 86400.0
T_END = 1_760_000_000.0


def _matrix(metric: dict, values: list[float]) -> dict:
    """A query_range success response: one series, one sample per day."""
    n = len(values)
    return {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [{
                "metric": metric,
                "values": [[T_END - (n - 1 - i) * DAY, str(v)]
                           for i, v in enumerate(values)],
            }],
        },
    }


EMPTY = {"status": "success", "data": {"resultType": "matrix", "result": []}}

#: qid -> canned response. Chosen to cover every rendering branch:
#: a warn row, two ok rows (one flat, one big mover), a crit row in another
#: category, an n/a row on a second host, and one query that failed outright.
CANNED = {
    # Memory · ubuntu-server — 85/95 thresholds, so 91% is a warn
    "mem_used": _matrix({"instance": "10.0.0.10:9100"}, [82.0, 86.0, 91.0]),
    # ok, but the biggest mover in the table: must still sort below the warn
    "swap_used": _matrix({"instance": "10.0.0.10:9100"}, [1.0, 1.0, 2.0]),
    # ok and flat: sorts last, renders the ▬ delta
    "mem_psi": _matrix({"instance": "10.0.0.10:9100"}, [0.001, 0.001, 0.001]),
    # Temperature · ubuntu-server — 55/65, so 68°C is crit
    "drive_temp": _matrix({"instance": "10.0.0.10:9100", "device": "sdb"},
                          [60.0, 62.0, 68.0]),
    # Proxmox · homelab — dir "vmup": below 1 is not "bad", it is unknown
    "pve_vm_up": _matrix({"instance": "10.0.0.2:9221"}, [0.0, 0.0, 0.0]),
}

#: the one query that fails — it is what the header's "no-data" count counts
BROKEN = "oom"


class FakeProm:
    """Stands in for ``_fetch_query_ranges`` and counts how often it is asked."""

    def __init__(self):
        self.calls = 0
        self.down = False

    async def __call__(self, base_url, qdefs, window):
        self.calls += 1
        self.base_url, self.window = base_url, window
        out = []
        for q in qdefs:
            item = {"query": asdict(q), "data": None, "error": None}
            if self.down:
                item["error"] = "ConnectError: All connection attempts failed"
            elif q.qid == BROKEN:
                item["error"] = "ReadTimeout: timed out"
            else:
                item["data"] = CANNED.get(q.qid, EMPTY)
            out.append(item)
        return out


@pytest.fixture()
def prom(monkeypatch):
    fake = FakeProm()
    monkeypatch.setattr("heim.dashboard.app._fetch_query_ranges", fake)
    return fake


@pytest.fixture()
def client(tmp_path, monkeypatch, prom):
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("HEIM_DASHBOARD_TOKEN", raising=False)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot,
                    ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    cfg.settings.db_path = str(tmp_path / "heim.sqlite3")
    with TestClient(create_app(cfg)) as c:
        yield c


# ------------------------------------------------------------------ the page

def test_page_renders_host_sections_and_categories(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    # config order puts homelab before ubuntu-server, both before unknown hosts
    assert '<h2 class="mhost mono">homelab ' in r.text
    assert '<h2 class="mhost mono">ubuntu-server ' in r.text
    assert r.text.index("homelab ") < r.text.index("ubuntu-server ")
    for eyebrow in ("Memory", "Temperature", "Proxmox"):
        assert f'class="eyebrow mcat">{eyebrow}<' in r.text
    assert "Memory used" in r.text and "Drive temp" in r.text


def test_rows_sort_by_flag_then_movement(client):
    """warn above ok, and among the ok rows the bigger mover first."""
    t = client.get("/metrics").text
    assert t.index("Memory used") < t.index("Swap used") < t.index("Memory PSI stall")


def test_trend_and_delta_cells(client):
    t = client.get("/metrics").text
    # the three day averages, unit dropped (the current column carries it)
    assert "82.0 → 86.0 → 91.0" in t
    assert "60.0 → 62.0 → 68.0" in t
    assert "▲ 11.0%" in t            # mem_used: 82 → 91
    assert "▬" in t                  # mem_psi: flat
    # the crit row's delta is colored; the ok rows' deltas are not
    assert '<td class="num mono c-delta st-crit">▲ 13.3%</td>' in t
    assert '<td class="num mono c-delta">▲ 100.0%</td>' in t
    # humanized current values and the min/max title on the avg cell
    assert "91.0%" in t and "68.0°C" in t
    assert 'title="min 82.0% · max 91.0%"' in t


def test_na_row_is_muted_and_dashed(client):
    t = client.get("/metrics").text
    assert '<span class="pill st-muted"><span class="dot" aria-hidden="true">·</span>n/a' in t
    assert '<td class="num mono c-delta">—</td>' in t   # changePct is null for a state


def test_header_counts_and_overall_pill(client):
    t = client.get("/metrics").text
    assert "1 crit · 1 warn · 1 no-data" in t
    assert "3-day window · as of" in t
    assert ('<span class="pill st-crit"><span class="dot" aria-hidden="true">✕'
            '</span>critical</span>') in t
    assert 'class="btn" type="submit">refresh<' in t


def test_host_filter_narrows(client):
    t = client.get("/metrics?host=homelab").text
    assert '<h2 class="mhost mono">homelab ' in t
    assert '<h2 class="mhost mono">ubuntu-server ' not in t
    assert "Memory used" not in t


def test_category_filter_narrows(client):
    t = client.get("/metrics?category=Temperature").text
    assert "Drive temp" in t
    assert "Memory used" not in t
    assert 'class="eyebrow mcat">Memory<' not in t


def test_filters_that_match_nothing_say_so(client):
    t = client.get("/metrics?host=homelab&category=Temperature").text
    assert "No metrics match these filters" in t
    # the header describes the payload, not the filtered view — it stays
    assert "1 crit · 1 warn · 1 no-data" in t


# -------------------------------------------------------------------- cache

def test_two_requests_share_one_fetch(client, prom):
    client.get("/metrics")
    client.get("/metrics")
    assert prom.calls == 1


def test_refresh_forces_a_refetch(client, prom):
    client.get("/metrics")
    r = client.get("/metrics?refresh=1")
    assert r.status_code == 200 and prom.calls == 2
    assert "Memory used" in r.text


# ------------------------------------------------------------------- errors

def test_failure_with_a_warm_cache_keeps_the_numbers(client, prom):
    client.get("/metrics")
    prom.down = True
    r = client.get("/metrics?refresh=1")
    assert r.status_code == 200
    assert "Memory used" in r.text                    # the cached payload
    assert "Prometheus unreachable at http://10.0.0.10:9090" in r.text
    assert "All connection attempts failed" in r.text


def test_failure_with_no_cache_shows_the_unreachable_copy(client, prom):
    prom.down = True
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "Prometheus unreachable at http://10.0.0.10:9090" in r.text
    assert "Check `heim check`." in r.text
    assert "nothing was cached before it went away" in r.text
    assert "Memory used" not in r.text


def test_nav_has_metrics_between_findings_and_hosts(client):
    t = client.get("/").text
    assert '<a href="/metrics"' in t
    assert t.index('href="/findings"') < t.index('href="/metrics"') < t.index('href="/hosts"')
