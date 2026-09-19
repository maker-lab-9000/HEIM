"""The findings table and the host badge (design spec §3 "Findings", §1 colors).

The Findings page renders one real ``<table>`` per run — severity, host,
metric, finding, verdict — and the host column carries a badge whose dot color
is assigned from five categorical slots in config order. The same badge is
reused on the investigations and incidents tables, so these tests check all
three surfaces plus the pure ``host_color`` slot assignment.
"""
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.dashboard import format as fmt
from heim.dashboard.app import _findings_line, create_app
from heim.incidents.store import IncidentStore
from test_dashboard import _config, _iso

CONFIG_HOSTS = ("home-assistant", "homelab", "ubuntu-server")  # config order


def _seed(db_path: Path) -> dict:
    """One daily run with four findings: the three configured hosts at three
    severities plus a Proxmox guest that has no host file of its own."""
    store = IncidentStore(db_path)
    ids = {}
    run_at = _iso(5)
    ids["run"] = store.insert_run(run_at=run_at, kind="daily", overall="warning",
                                  model_used="claude-opus-4-6", duration_s=41.5,
                                  counts_json=json.dumps({"crit": 1, "warn": 1}))
    store.insert_findings(ids["run"], run_at, "daily", [
        {"host": "ubuntu-server", "metric": "mem_used", "severity": "critical",
         "trend": "up", "summary": "Memory climbing on ubuntu-server",
         "detail": "Working set grew 18% over three days.",
         "recommendation": "Cap the PhotoPrism container."},
        {"host": "homelab", "metric": "drive_temp", "severity": "warning",
         "trend": "up", "summary": "Drive temperature high",
         "detail": "sdb peaked at 48C.", "recommendation": "Raise the fan curve."},
        {"host": "home-assistant", "metric": "api_slow", "severity": "info",
         "summary": "API latency nudged up"},
        {"host": "vm-nextcloud", "metric": "disk_free", "severity": "warning",
         "summary": "Root filesystem at 91%"},
    ], fingerprints=["ubuntu-server|mem_used|Memory climbing",
                     "homelab|drive_temp|Drive temperature high",
                     "home-assistant|api_slow|API latency",
                     "vm-nextcloud|disk_free|Root filesystem"])
    findings = {f["metric"]: f["id"] for f in store.recent_findings(limit=10)}
    ids.update(findings)
    store.set_finding_verdict(findings["drive_temp"], "confirmed")

    # one investigation + one incident, so the shared badge can be checked there
    ids["inv"] = store.create_investigation(
        fingerprint="ubuntu-server|mem_used|Memory climbing", host="ubuntu-server",
        host_role="guest", trigger="daily", status="resolved",
        started_at=_iso(60), finished_at=_iso(58), n_steps=2)
    store.upsert([
        {"fingerprint": "homelab|drive_temp|Drive temperature high", "host": "homelab",
         "metric": "drive_temp", "severity": "warning", "status": "open",
         "firstSeen": _iso(900), "lastSeen": _iso(5), "timesSeen": 3,
         "description": "sdb peaked at 48C."},
    ])
    store.close()
    return ids


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    ids = _seed(db)
    with TestClient(create_app(cfg)) as client:
        yield client, ids


@pytest.fixture()
def client(seeded):
    return seeded[0]


@pytest.fixture()
def ids(seeded):
    return seeded[1]


def _table(html: str) -> str:
    return html[html.index('<table class="tbl dense ftbl"'):html.index("</table>")]


# ------------------------------------------------------------ the table

def test_findings_render_as_a_table_with_header_cells(client):
    html = client.get("/findings").text
    table = _table(html)
    for col in ("severity", "host", "metric", "finding", "verdict"):
        assert f'<th scope="col"' in table and f">{col}</th>" in table
    assert table.count("<tr>") - 1 == 4                  # header + one per finding
    # fixed column classes keep the widths stable between runs
    for cls in ("c-sev", "c-host", "c-metric", "c-verdict"):
        assert cls in table
    assert '<ul class="flist">' not in html              # the old list is gone


def test_rows_keep_severity_order_and_show_severity_pills(client):
    table = _table(client.get("/findings").text)
    assert "st-crit" in table and "st-warn" in table and "st-muted" in table
    for label in ("critical", "warning", "info"):
        assert f">{label}</span>" in table
    order = [table.index(s) for s in ("Memory climbing on ubuntu-server",
                                      "Drive temperature high",
                                      "API latency nudged up")]
    assert order == sorted(order)                        # worst first, as before


def test_metric_and_summary_sit_in_their_own_cells(client):
    table = _table(client.get("/findings").text)
    assert '<td class="c-metric mono ink2">mem_used</td>' in table
    assert '<span class="fsum">Memory climbing on ubuntu-server</span>' in table


def test_detail_and_recommendation_fold_into_the_finding_cell(client):
    table = _table(client.get("/findings").text)
    # only the two findings that stored a detail get a disclosure
    assert table.count("detail &amp; recommendation") == 2
    # the details element is inside the cell that holds the summary
    cell = table[table.index('<span class="fsum">Memory climbing'):]
    cell = cell[:cell.index("</td>")]
    assert "<details>" in cell
    assert "Working set grew 18% over three days." in cell
    assert "Cap the PhotoPrism container." in cell


def test_verdict_cell_offers_the_pair_or_shows_the_pill(client, ids):
    table = _table(client.get("/findings").text)
    assert table.count("✓ CONFIRM") == 3                 # drive_temp is judged
    assert 'class="verdict st-ok"' in table and "confirmed" in table
    # the form lives inside the verdict cell, with its finding id and back field
    cells = re.findall(r'<td class="c-verdict">(.*?)</td>', table, re.S)
    assert len(cells) == 4
    assert any(f'name="finding_id" value="{ids["mem_used"]}"' in c
               and 'method="post"' in c and 'name="back"' in c for c in cells)
    assert any('class="verdict st-ok"' in c for c in cells)


def test_verdict_post_still_updates_the_cell(client, ids):
    r = client.post("/actions/verdict",
                    data={"finding_id": ids["mem_used"], "verdict": "confirmed"},
                    headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "<html" not in r.text                         # a fragment for the cell
    assert 'class="verdict st-ok"' in r.text
    assert "✓ CONFIRM" not in r.text
    assert "confirmed" in _table(client.get("/findings").text)


def test_empty_state_unchanged(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    cfg.settings.db_path = str(tmp_path / "empty.sqlite3")
    with TestClient(create_app(cfg)) as client:
        html = client.get("/findings").text
        assert "No findings recorded yet." in html
        assert "<table" not in html


# ------------------------------------------------------------ host badges

def _badges(html: str) -> list[tuple[str, str]]:
    """(css var, host name) for every host badge in the page."""
    return re.findall(r'style="background: var\((--[a-z0-9-]+)\)"></span>([^<]+)</span>',
                      html)


def test_host_color_assigns_slots_in_config_order():
    assert fmt.host_color("home-assistant", CONFIG_HOSTS) == "--host-1"
    assert fmt.host_color("homelab", CONFIG_HOSTS) == "--host-2"
    assert fmt.host_color("ubuntu-server", CONFIG_HOSTS) == "--host-3"


def test_host_color_mutes_unknown_and_overflow_hosts():
    assert fmt.host_color("vm-nextcloud", CONFIG_HOSTS) == "--ink-3"
    assert fmt.host_color("", CONFIG_HOSTS) == "--ink-3"
    assert fmt.host_color(None, CONFIG_HOSTS) == "--ink-3"
    assert fmt.host_color("anything", ()) == "--ink-3"
    six = [f"h{i}" for i in range(6)]
    assert fmt.host_color("h4", six) == "--host-5"       # the last colored slot
    assert fmt.host_color("h5", six) == "--ink-3"        # beyond the palette
    assert fmt.HOST_SLOTS == 5


def test_findings_table_badges_are_dot_plus_name(client):
    table = _table(client.get("/findings").text)
    badges = dict((name, var) for var, name in _badges(table))
    assert badges == {"ubuntu-server": "--host-3", "homelab": "--host-2",
                      "home-assistant": "--host-1", "vm-nextcloud": "--ink-3"}
    # the dot is decoration only — the name is always spelled out next to it
    assert table.count('<span class="hdot" aria-hidden="true"') == 4


def test_investigations_and_incidents_reuse_the_badge(client):
    invs = client.get("/investigations").text
    assert ("--host-3", "ubuntu-server") in _badges(invs)
    assert client.get("/investigations/rows").text.count('class="hbadge"') == 1
    incidents = client.get("/incidents").text
    assert ("--host-2", "homelab") in _badges(incidents)


def test_host_slots_are_defined_in_the_stylesheet(client):
    css = client.get("/static/heim.css").text
    for slot in range(1, 6):
        assert f"--host-{slot}:" in css
    assert ".hbadge" in css and ".hbadge .hdot" in css
    # the aliases point at the already-validated categorical palette
    assert "#C97A35" in css and "#8A6FD1" in css


# ------------------------------------------- overview: the compact run card

def test_findings_line_counts():
    sev = lambda *vals: [{"severity": v} for v in vals]        # noqa: E731
    assert _findings_line(sev("critical", "warning", "warning", "info")) == \
        "4 findings (1 crit · 2 warn)"
    assert _findings_line(sev("critical")) == "1 finding (1 crit)"
    assert _findings_line(sev("warning", "info")) == "2 findings (1 warn)"
    assert _findings_line(sev("info", "info")) == "2 findings"
    assert _findings_line([]) == ""
    # the analyst's short spellings count the same as the long ones
    assert _findings_line(sev("crit", "warn")) == "2 findings (1 crit · 1 warn)"


def test_overview_run_card_lists_recent_runs_with_details_links(client):
    html = client.get("/").text
    card = html[html.index("latest runs"):html.index("recent investigations")]
    assert "claude-opus-4-6" in card and "overall" in card
    assert "4 findings (1 crit · 2 warn)" in card
    # every listed run links to its group on the findings page
    assert 'href="/findings#run-' in card
    assert ">details</a>" in card
    # no inline finding text any more — that is the Findings page's job
    assert 'class="headline"' not in card
    assert "Working set grew 18% over three days." not in card
    assert "Memory climbing on ubuntu-server" not in card


def test_overview_lists_up_to_ten_runs_newest_first(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "manyruns.sqlite3"
    cfg.settings.db_path = str(db)
    store = IncidentStore(db)
    for i in range(12):
        rid = store.insert_run(kind="daily", run_at=_iso(i), overall="healthy",
                               model_used="m", duration_s=1.0, counts_json="{}")
        if i == 11:  # newest run gets a warn finding
            store.insert_findings(rid, _iso(i), "daily",
                                  [{"severity": "warning", "host": "h", "metric": "M",
                                    "detail": "d"}], ["h|m|"])
    store.close()
    with TestClient(create_app(cfg)) as client:
        html = client.get("/").text
        card = html[html.index("latest runs"):html.index("recent investigations")]
        assert card.count("runline mono") == 10          # capped at 10
        assert card.count("runline mono dim") == 9       # only the newest is prominent
        first_row = card[:card.index("dim")]
        assert "1 finding (1 warn)" in first_row         # newest first carries its counts
        # findings page carries the anchor target
        fhtml = client.get("/findings").text
        assert 'id="run-' in fhtml


def test_overview_empty_run_state_unchanged(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "noruns.sqlite3"
    cfg.settings.db_path = str(db)
    store = IncidentStore(db)
    store.create_investigation(fingerprint="homelab|x|y", host="homelab",
                               trigger="manual", status="running", started_at=_iso(1))
    store.close()
    with TestClient(create_app(cfg)) as client:
        html = client.get("/").text
        assert "No daily run recorded yet." in html
        assert "DETAILS" not in html
