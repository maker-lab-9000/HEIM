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
        #: serve only the one ok series — the "nothing is wrong" page
        self.ok_only = False

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
            elif self.ok_only:
                item["data"] = CANNED["swap_used"] if q.qid == "swap_used" else EMPTY
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


def test_header_is_freshness_and_refresh_only(client):
    """The counts line, the overall pill and the window text were removed: the
    offenders table below names every flagged row, so they only restated it.
    Freshness is the one fact that table cannot carry."""
    head = _header(client.get("/metrics").text)
    assert "as of" in head
    assert 'class="btn" type="submit">refresh<' in head
    assert "no-data" not in head          # counts line gone
    assert "3-day window" not in head     # window text gone
    assert "pill st-crit" not in head.split("<table")[0]   # overall pill gone
    assert "pill st-crit" in head          # ...but a crit ROW still has its pill


# ------------------------------------------------- the header names offenders


def _header(text: str) -> str:
    """Just the header card — everything above the filters form."""
    return text.split('id="mall"', 1)[0]


def test_header_names_the_offending_host_and_resource(client):
    """The counts say how many; this says which (spec Part B)."""
    h = _header(client.get("/metrics").text)
    # the crit row: ubuntu-server's sdb drive temperature, worst first
    assert '<span class="hbadge"><span class="hdot"' in h
    assert ">ubuntu-server</span>" in h
    assert 'class="c-mname">Drive temp <span class="mono ink2">sdb</span>' in h
    assert '<td class="num mono c-cur">68.0°C</td>' in h
    assert '<td class="num mono c-delta st-crit">▲ 13.3%</td>' in h
    # ...and the warn row below it
    assert 'class="c-mname">Memory used' in h
    assert h.index("Drive temp") < h.index("Memory used")


def test_header_table_is_absent_when_nothing_is_flagged(client, prom):
    prom.ok_only = True
    t = client.get("/metrics?refresh=1").text
    assert "as of" in _header(t)                   # freshness is all the header keeps
    assert "Swap used" in t                        # the ok row still renders
    assert "c-mname" in _tables(t)                 # ...in the tables below
    assert "c-mname" not in _header(t)             # but the header names nobody


def test_header_table_caps_and_links_to_the_rest(client, monkeypatch):
    """Past the cap the header defers to the full tables below."""
    monkeypatch.setattr("heim.dashboard.app._OFFENDER_ROWS", 1)
    h = _header(client.get("/metrics").text)
    assert "Drive temp" in h and "Memory used" not in h   # only the worst
    assert '<a class="mono" href="#mall">+1 more</a>' in h


def test_offenders_never_disagree_with_the_counts():
    """``+N more`` counts the whole payload, not just what topAlerts kept."""
    from heim.dashboard.app import _offenders

    payload = {"counts": {"crit": 9, "warn": 12},
               "topAlerts": [{"host": f"h{i}"} for i in range(15)]}
    out = _offenders(payload)
    assert len(out["rows"]) == 8 and out["more"] == 13    # 21 flagged - 8 shown


def _tables(text: str) -> str:
    """Everything below the header card — the part a filter narrows.

    The header (counts *and* the offenders table under them) describes the
    whole payload by design, so a filter assertion has to say where it looks.
    """
    return text.split('id="mall"', 1)[-1]


def test_host_filter_narrows(client):
    t = _tables(client.get("/metrics?host=homelab").text)
    assert '<h2 class="mhost mono">homelab ' in t
    assert '<h2 class="mhost mono">ubuntu-server ' not in t
    assert "Memory used" not in t


def test_category_filter_narrows(client):
    t = _tables(client.get("/metrics?category=Temperature").text)
    assert "Drive temp" in t
    assert "Memory used" not in t
    assert 'class="eyebrow mcat">Memory<' not in t


def test_filters_that_match_nothing_say_so(client):
    t = client.get("/metrics?host=homelab&category=Temperature").text
    assert "No metrics match these filters" in t
    # the header describes the payload, not the filtered view — its offenders
    # table still names the flagged rows even though none of them match here
    assert "c-mname" in _header(t)


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


def test_header_offenders_are_sorted_by_status_then_by_the_biggest_mover():
    """Severity order is stated by this table alone now that the counts line
    is gone, so it is applied here rather than inherited from aggregate()."""
    from heim.dashboard.app import _offenders
    payload = {
        "counts": {"crit": 2, "warn": 2},
        "topAlerts": [                                   # deliberately unsorted
            {"sev": "warn", "label": "Memory used", "changePct": 10.1},
            {"sev": "crit", "label": "Drive temp", "changePct": 13.3},
            {"sev": "warn", "label": "Guests not backed up", "changePct": 100.0},
            {"sev": "crit", "label": "VM CPU", "changePct": 3091.7},
        ],
    }
    assert [r["label"] for r in _offenders(payload)["rows"]] == [
        "VM CPU", "Drive temp",                  # crit first, biggest mover first
        "Guests not backed up", "Memory used",   # then warn, same rule
    ]


def test_header_keeps_only_the_freshness_stamp(client):
    """The offenders table names every flagged row, so the pill, the
    crit/warn/no-data counts and the window text were removed as restatement."""
    html = client.get("/metrics?refresh=1").text
    head = html[html.index('class="mline"'):html.index("</section>")]
    assert "as of" in head                       # the one thing the table cannot say
    assert "no-data" not in head and "crit ·" not in head and "3-day window" not in head
