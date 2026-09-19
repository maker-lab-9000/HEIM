"""Dashboard tests: every route renders, filters filter, htmx partials are
fragments, auth gates everything but /healthz — driven through a seeded tmp
store and the example config (same fixture pattern as test_integration)."""
import json
import os
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

ROOT = Path(__file__).resolve().parent.parent

DUMMY_ENV = {
    "HEIM_SERVER_IP": "10.0.0.10",
    "HEIM_PROXMOX_IP": "10.0.0.2",
    "HEIM_HA_IP": "10.0.0.3",
    "HEIM_TELEGRAM_CHAT_ID": "111111111",
    "HEIM_EMAIL_TO": "test@example.com",
    "HEIM_EMAIL_FROM": "test@example.com",
}


def _iso(minutes_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat(
        timespec="milliseconds")


def _seed(db_path: Path) -> dict:
    """2 finished + 1 running investigation, a daily run with findings, and
    three incidents — enough to exercise every rendering branch."""
    store = IncidentStore(db_path)
    ids = {}

    # --- a running investigation with a transcript (incl. one blocked step)
    ids["running"] = store.create_investigation(
        fingerprint="ubuntu-server|mem_used|Memory climbing", host="ubuntu-server",
        host_role="guest", agent_name="investigator", model="claude-sonnet-4-6",
        trigger="poller", status="running", started_at=_iso(4),
        input_tokens=128_000, output_tokens=4_200, n_steps=3,
        # provenance, written when the row is created (pipelines/investigate)
        findings_json=json.dumps([
            {"severity": "critical", "host": "ubuntu-server", "metric": "Memory used + Swap",
             "trend": "up", "detail": "Working set grew 18% over three days.",
             "recommendation": "Cap the PhotoPrism container."},
            {"severity": "warning", "host": "ubuntu-server", "metric": "Load average",
             "trend": "up", "detail": "1.8x the three-day baseline."},
        ]),
        brief_md="Investigate the following alert(s) on host \"ubuntu-server\".\n\n"
                 "DETECTED FINDINGS:\n1. [critical] Memory used + Swap (up) — "
                 "Working set grew 18% over three days.\n")
    store.add_step(ids["running"], 1, "prometheus_query",
                   args_json=json.dumps({"promql": 'topk(10, container_memory_working_set_bytes{name!=""})'}),
                   result_preview="10 series · photoprism-photoprism-1 2.90 GiB",
                   result_bytes=2150, duration_ms=1200)
    store.add_step(ids["running"], 2, "ssh_diagnostic",
                   args_json=json.dumps({"command": "sudo agent-docker stats --no-stream"}),
                   result_preview="exit 0 · PhotoPrism 2.703GiB / 17.31%",
                   result_bytes=6800, duration_ms=3400)
    store.add_step(ids["running"], 3, "ssh_diagnostic",
                   args_json=json.dumps({"command": "docker restart photoprism"}),
                   result_preview="Command blocked by safety guard (mutating subcommand)",
                   result_bytes=60, blocked=True, duration_ms=100)

    # --- a finished investigation with a report and a resolved outcome
    ids["done"] = store.create_investigation(
        fingerprint="homelab|drive_temp|Drive temperature high", host="homelab",
        host_role="hypervisor", agent_name="investigator", model="claude-sonnet-4-6",
        trigger="daily", status="resolved", started_at=_iso(180),
        finished_at=_iso(176), input_tokens=96_000, output_tokens=3_100, n_steps=2,
        outcome="resolved",
        report_md="## Summary\n\nDrive **sdb** runs warm under rebuild load.\n\n"
                  "## Root cause\n\nFan curve too flat.\n")
    store.add_step(ids["done"], 1, "ha_api", args_json=json.dumps({"path": "/api/states"}),
                   result_preview="42 entities", result_bytes=1024, duration_ms=300)
    store.add_step(ids["done"], 2, "discover_metrics",
                   args_json=json.dumps({"pattern": "smartmon_.*"}),
                   result_preview="7 matching metrics", result_bytes=512, duration_ms=210)

    # --- a declined one (no steps, no report): started by hand, so no findings
    #     — but it still has the brief, which is stored at creation time
    ids["declined"] = store.create_investigation(
        fingerprint="ubuntu-server|cpu_load|CPU saturated", host="ubuntu-server",
        host_role="guest", agent_name="investigator", model="claude-sonnet-4-6",
        trigger="manual", status="declined", started_at=_iso(600),
        finished_at=_iso(599), n_steps=0,
        brief_md="Investigate the general health of host \"ubuntu-server\".\n\n"
                 "Do **not** stop at the symptom.\n")

    # --- a daily run + its findings
    run_at = _iso(5)
    ids["run"] = store.insert_run(run_at=run_at, kind="daily", overall="warning",
                                  model_used="claude-opus-4-6", duration_s=41.5,
                                  counts_json=json.dumps({"warn": 1, "crit": 1}))
    store.insert_findings(ids["run"], run_at, "daily", [
        {"host": "ubuntu-server", "metric": "mem_used", "severity": "critical",
         "trend": "up", "summary": "Memory climbing on ubuntu-server",
         "detail": "Working set grew 18% over three days.",
         "recommendation": "Cap the PhotoPrism container."},
        {"host": "homelab", "metric": "drive_temp", "severity": "warning",
         "trend": "up", "summary": "Drive temperature high",
         "detail": "sdb peaked at 48C.", "recommendation": "Raise the fan curve."},
    ], fingerprints=["ubuntu-server|mem_used|Memory climbing",
                     "homelab|drive_temp|Drive temperature high"])

    # --- incidents
    store.upsert([
        {"fingerprint": "ubuntu-server|mem_used|Memory climbing", "host": "ubuntu-server",
         "metric": "mem_used", "severity": "critical", "status": "open",
         "firstSeen": _iso(4000), "lastSeen": _iso(5), "timesSeen": 7, "missedRuns": 0,
         "description": "Working set grew 18% over three days.", "investigated": True},
        {"fingerprint": "homelab|drive_temp|Drive temperature high", "host": "homelab",
         "metric": "drive_temp", "severity": "warning", "status": "open",
         "firstSeen": _iso(2000), "lastSeen": _iso(5), "timesSeen": 3, "missedRuns": 1,
         "description": "sdb peaked at 48C."},
        {"fingerprint": "home-assistant|api_slow|API latency", "host": "home-assistant",
         "metric": "api_slow", "severity": "warning", "status": "resolved",
         "firstSeen": _iso(9000), "lastSeen": _iso(7000), "resolvedAt": _iso(6900),
         "timesSeen": 2, "missedRuns": 2, "description": "Recovered on its own."},
    ])
    store.close()
    return ids


def _config(tmp_path, monkeypatch):
    """The committed example config (the real settings.yaml is gitignored) with
    dummy identity vars, exactly like tests/test_integration.py."""
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("HEIM_DASHBOARD_TOKEN", raising=False)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    return load_config(croot)


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    ids = _seed(db)
    app = create_app(cfg)
    with TestClient(app) as client:
        yield client, ids, cfg


@pytest.fixture()
def client(seeded):
    return seeded[0]


@pytest.fixture()
def ids(seeded):
    return seeded[1]


# --------------------------------------------------------------- base shell

def test_healthz_is_plain_ok(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.text == "ok"


def test_static_assets_served(client):
    css = client.get("/static/heim.css")
    assert css.status_code == 200 and "--ember" in css.text
    js = client.get("/static/htmx.min.js")
    assert js.status_code == 200 and len(js.content) > 10_000


def test_overview_shell_and_kpis(client):
    r = client.get("/")
    assert r.status_code == 200
    html = r.text
    # wordmark, nav, daemon chip, topbar chrome
    assert 'class="spark"' in html and "HEIM" in html      # the house wordmark
    assert "/static/logo.svg" in html                       # favicon
    assert 'href="/investigations"' in html and 'href="/hosts"' in html
    assert "daemon" in html
    # KPI tiles: 2 open incidents, 1 running, 0 pending, tokens summed over 24h
    assert "open incidents" in html and "running invest." in html
    assert ">2</a>" in html            # open incidents
    assert "tokens 24h" in html
    assert fmt.tokens(128_000 + 4_200 + 96_000 + 3_100) in html   # 231k
    # latest daily headline + recent lists
    assert "claude-opus-4-6" in html
    assert "Memory climbing on ubuntu-server" in html
    assert "#%d" % 1 in html


def test_overview_empty_state(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    cfg.settings.db_path = str(tmp_path / "empty.sqlite3")
    with TestClient(create_app(cfg)) as client:
        r = client.get("/")
        assert r.status_code == 200
        assert "No activity yet." in r.text
        assert "check back after the next poll" in r.text
        assert client.get("/hosts").status_code == 200
        assert "No investigations match" in client.get("/investigations").text


# ------------------------------------------------------------ investigations

def test_investigations_list_rows(client):
    html = client.get("/investigations").text
    assert "ubuntu-server" in html and "homelab" in html
    assert "running" in html and "declined" in html and "resolved" in html
    assert "poller" in html and "daily" in html and "manual" in html
    assert "128k → 4.2k" in html          # humanized tokens, in → out
    assert "mem_used" in html             # fingerprint (middle-truncated)
    # a running row means the tbody polls
    assert 'hx-trigger="every 5s"' in html
    assert 'hx-get="/investigations/rows' in html


def test_running_row_shows_elapsed_not_a_dash(client, ids):
    # a running investigation has no finished_at; the honest duration is "so far"
    rows = client.get("/investigations?status=running").text
    # the duration cell is the one before "started"; an em dash there would be
    # the bug this test guards. (The cost cell legitimately dashes when the
    # model is unpriced — §5.6 — so the check is scoped to duration.)
    duration_cell = rows.split('class="num mono">')[-1]
    assert not duration_cell.startswith("—")
    detail = client.get(f"/investigations/{ids['running']}").text
    assert "so far" in detail
    # a finished one shows the closed interval instead
    assert "so far" not in client.get(f"/investigations/{ids['done']}").text


def test_investigations_filters(client, ids):
    only_running = client.get("/investigations?status=running").text
    assert f'/investigations/{ids["running"]}"' in only_running
    assert f'/investigations/{ids["done"]}"' not in only_running

    by_host = client.get("/investigations?host=homelab").text
    assert f'/investigations/{ids["done"]}"' in by_host
    assert f'/investigations/{ids["running"]}"' not in by_host

    by_trigger = client.get("/investigations?trigger=manual").text
    assert f'/investigations/{ids["declined"]}"' in by_trigger
    assert f'/investigations/{ids["running"]}"' not in by_trigger

    nothing = client.get("/investigations?status=running&host=homelab").text
    assert "No investigations match these filters." in nothing


def test_investigation_rows_partial_is_a_fragment(client, ids):
    r = client.get("/investigations/rows?status=running")
    assert r.status_code == 200
    body = r.text
    assert "<html" not in body and "<!doctype" not in body.lower()
    assert body.lstrip().startswith("<tbody")
    assert f'/investigations/{ids["running"]}"' in body
    assert f'/investigations/{ids["done"]}"' not in body


def test_investigation_detail_transcript(client, ids):
    r = client.get(f"/investigations/{ids['running']}")
    assert r.status_code == 200
    html = r.text
    # header block
    assert "ubuntu-server" in html and "claude-sonnet-4-6" in html
    assert "128k in → 4.2k out" in html
    assert "transcript · 3 steps" in html
    # gutter numbers + tool badges + $ command lines
    assert ">01<" in html and ">02<" in html and ">03<" in html
    assert "t-prometheus" in html and "t-ssh" in html
    assert "$ " in html
    assert "topk(10, container_memory_working_set_bytes{name!=&#34;&#34;})" in html \
        or "topk(10, container_memory_working_set_bytes" in html
    assert "sudo agent-docker stats --no-stream" in html
    # blocked step treatment
    assert "⛔ blocked" in html
    assert 'class="entry blocked"' in html
    # result previews are native <details>
    assert "<details" in html and "expand" in html
    # burn line: one segment per step, widths summing to ~100%
    assert html.count('class="seg t-') == 3
    assert "share of tool output" in html
    # live polling of the transcript partial
    assert f'hx-get="/investigations/{ids["running"]}/transcript"' in html
    # still running -> outcome line says so, no report yet
    assert "Still working…" in html
    assert "No report yet" in html


def test_investigation_detail_report_and_outcome(client, ids):
    html = client.get(f"/investigations/{ids['done']}").text
    assert "<h2>Summary</h2>" in html            # report_md through _md_to_html
    assert "<strong>sdb</strong>" in html
    assert "Resolved by operator" in html
    assert "t-ha" in html and "t-discover" in html
    assert "/api/states" in html and "smartmon_.*" in html
    assert 'hx-trigger="every 5s"' not in html   # finished: no polling


def test_investigation_detail_declined_has_no_steps(client, ids):
    html = client.get(f"/investigations/{ids['declined']}").text
    assert "No steps recorded for this investigation." in html
    assert "Declined — re-proposed next run" in html


def test_triggered_by_card_shows_findings_and_brief(client, ids):
    """The provenance card: what the agent was asked about, and the brief it got."""
    html = client.get(f"/investigations/{ids['running']}").text
    assert "triggered by" in html
    # one line per finding: severity icon + mono metric + detail, all in --ink-2
    assert "Memory used + Swap" in html and "Load average" in html
    assert "Working set grew 18% over three days." in html
    assert "1.8x the three-day baseline." in html
    assert 'class="sev st-crit"' in html and 'class="sev st-warn"' in html
    # the card sits between the header and the transcript
    assert html.index("triggered by") < html.index("transcript · 3 steps")
    assert html.index('class="card head"') < html.index("triggered by")
    # the brief is a native <details>, rendered through the markdown pipeline
    assert "Brief sent to the agent" in html
    assert "DETECTED FINDINGS" in html


def test_triggered_by_is_explicit_when_there_are_no_findings(client, ids):
    html = client.get(f"/investigations/{ids['declined']}").text
    assert "triggered by" in html
    assert "Manual investigation — no incident findings attached." in html


def test_declined_investigation_still_shows_its_brief(client, ids):
    """The brief is stored when the row is created, so a run that never got
    approved still says what it would have asked."""
    html = client.get(f"/investigations/{ids['declined']}").text
    assert "Brief sent to the agent" in html
    assert "Investigate the general health of host" in html
    assert "<strong>not</strong>" in html          # markdown-rendered, like the report


def _meta_table(html):
    """The header's meta table, sliced out of a detail page."""
    start = html.index('class="tbl dense imeta"')
    return html[start:html.index("</table>", start)]


def test_header_meta_is_a_table_with_one_row_of_values(client, ids):
    """The header metadata is a real dense table: a row of column labels and
    exactly one row of values, in the documented order."""
    html = client.get(f"/investigations/{ids['running']}").text
    meta = _meta_table(html)
    labels = re.findall(r'<th scope="col"[^>]*>([^<]+)</th>', meta)
    assert labels == ["trigger", "agent", "tokens", "cost",
                      "duration", "started", "fingerprint"]
    # one <tr> in the body, one <td> per column, values in header order
    body = meta[meta.index("<tbody"):]
    assert body.count("<tr") == 1
    assert body.count("<td") == len(labels)
    values = re.findall(r"<td[^>]*>(.*?)</td>", body, re.S)
    assert "poller" in values[0]
    assert "investigator · claude-sonnet-4-6" in values[1]
    assert "128k in → 4.2k out" in values[2]
    assert fmt.DASH in values[3]                 # unpriced model: a dash, not $0.00
    assert "so far" in values[4]                 # still running: an open interval
    assert "<time" in values[5] and "datetime=" in values[5]   # m.when(), not |rel
    # fingerprint: middle-truncated in the cell, in full on the title
    assert values[6].startswith("ubuntu-server|mem") and "…" in values[6]
    assert 'title="ubuntu-server|mem_used|Memory climbing"' in body
    # the host title and the actions stay outside the table
    assert html.index('class="ihost"') < html.index('class="tbl dense imeta"')
    assert html.index('class="tbl dense imeta"') < html.index('class="acts"')
    # fixed layout keeps a long model/fingerprint inside its column
    css = client.get("/static/heim.css").text
    assert ".imeta { table-layout: fixed; }" in css
    assert ".imeta td { overflow-wrap: anywhere; }" in css


def test_transcript_partial_is_a_fragment(client, ids):
    r = client.get(f"/investigations/{ids['running']}/transcript")
    assert r.status_code == 200
    assert "<html" not in r.text
    assert r.text.lstrip().startswith('<div id="transcript"')
    assert "⛔ blocked" in r.text


def test_unknown_investigation_is_404(client):
    r = client.get("/investigations/9999")
    assert r.status_code == 404
    assert "No investigation #9999." in r.text
    assert client.get("/investigations/9999/transcript").status_code == 404


def test_burn_segments_share_and_fallback():
    steps = [{"seq": 1, "tool": "ssh_diagnostic", "result_bytes": 750},
             {"seq": 2, "tool": "ha_api", "result_bytes": 250}]
    segs = fmt.burn_segments(steps)
    assert [s["pct"] for s in segs] == [75.0, 25.0]
    assert segs[0]["tool_key"] == "ssh"
    # no bytes recorded at all -> even split rather than a blank bar
    even = fmt.burn_segments([{"seq": 1, "tool": "x"}, {"seq": 2, "tool": "y"}])
    assert [s["pct"] for s in even] == [50.0, 50.0]
    assert fmt.burn_segments([]) == []


# ----------------------------------------------------------------- incidents

def test_incidents_page(client):
    html = client.get("/incidents").text
    assert "critical" in html and "warning" in html
    assert "open" in html and "resolved" in html
    assert "🔒" in html                                   # dispatch lock
    assert "×7" in html                                   # timesSeen
    assert "Working set grew 18% over three days." in html   # expansion body
    assert "linked investigations" in html
    assert "No investigation ran for this fingerprint yet." in html


# ------------------------------------------------------------------ findings

def test_findings_grouped_by_run(client):
    html = client.get("/findings").text
    assert "daily · " in html and "claude-opus-4-6" in html
    assert "overall" in html
    assert "Memory climbing on ubuntu-server" in html and "Drive temperature high" in html
    assert "sdb peaked at 48C." in html
    assert "Cap the PhotoPrism container." in html
    assert html.count("detail &amp; recommendation") == 2   # one per finding
    # the findings of a run are a real table (structure: test_findings_table.py)
    assert '<table class="tbl dense ftbl">' in html
    assert '<th scope="col" class="c-host">host</th>' in html
    # worst severity first inside a run
    assert html.index("Memory climbing on ubuntu-server") < html.index("Drive temperature high")


def test_unreadable_store_says_what_to_check(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    _seed(db)
    with TestClient(create_app(cfg), raise_server_exceptions=False) as client:
        assert client.get("/").status_code == 200
        db.write_bytes(b"not a database" * 800)      # e.g. the volume went away
        r = client.get("/")
        assert r.status_code == 500
        assert f"Store unreadable at {db}" in r.text
        assert "is the daemon running with the same volume?" in r.text


def test_weight_budget_and_no_cdn():
    """The spec's quality floor: one hand-written CSS file and a vendored htmx —
    no runtime CDN reference anywhere in the templates.

    The budget was ~12 KB through v1; the actions slice (spec §5: button
    language, feedback lines, ghost rows) deliberately grew it to 14 KB, and
    the findings table (column widths, host badges, the host color slots)
    grows it to 15.5 KB. §5.6 adds the full-transcript block, the metrics
    fixed-column geometry, the rail tagline, the health card and the
    tool-usage card, landing at ~17 KB. It is still one hand-written file with no build step, and still
    the only stylesheet the pages load.
    """
    static = Path(__file__).resolve().parent.parent / "src/heim/dashboard/static"
    # §11's token chart adds ~0.4 KB of SVG styling (7 rules), so 17.5 -> 20 KB
    # §9's recommendations table adds 6 column rules, so 20 -> 20.25 KB
    # §5.1's model picker adds one rule (5 declarations), so 20.25 -> 20.5 KB
    assert (static / "heim.css").stat().st_size <= 20_992
    assert (static / "htmx.min.js").stat().st_size > 10_000
    templates = (Path(__file__).resolve().parent.parent
                 / "src/heim/dashboard/templates")
    for path in templates.rglob("*.html"):
        text = path.read_text()
        assert "unpkg" not in text and "cdn." not in text, path
        assert "http://" not in text and "https://" not in text, path


# --------------------------------------------------------------------- hosts

def test_hosts_cards(client, cfg_hosts=("ubuntu-server", "homelab", "home-assistant")):
    html = client.get("/hosts").text
    for name in cfg_hosts:
        assert name in html
    assert "hypervisor" in html and "ha-guest" in html
    assert "open incident" in html
    assert "last finding" in html and "last investigation" in html
    assert "no open incidents" in html          # home-assistant has none open


# ---------------------------------------------------------------------- auth

def test_auth_required_when_token_set(seeded, monkeypatch):
    client, ids, _cfg = seeded
    monkeypatch.setenv("HEIM_DASHBOARD_TOKEN", "s3cret")

    assert client.get("/", follow_redirects=False).status_code == 401
    assert client.get("/investigations").status_code == 401
    r = client.get("/")
    assert "Basic" in r.headers.get("www-authenticate", "")

    ok = client.get("/", auth=("anyone", "s3cret"))
    assert ok.status_code == 200 and "HEIM" in ok.text
    assert client.get(f"/investigations/{ids['done']}", auth=("x", "s3cret")).status_code == 200
    assert client.get("/", auth=("anyone", "wrong")).status_code == 401

    # /healthz stays open for container health checks
    assert client.get("/healthz").status_code == 200


def test_auth_open_without_token(client):
    assert "HEIM_DASHBOARD_TOKEN" not in os.environ
    assert client.get("/").status_code == 200


# ------------------------------------------------------------------ helpers

def test_format_helpers():
    assert fmt.tokens(940) == "940"
    assert fmt.tokens(4200) == "4.2k"
    assert fmt.tokens(128_000) == "128k"
    assert fmt.tokens(1_400_000) == "1.4M"
    assert fmt.tokens(None) == "0"
    assert fmt.dur_s(252) == "4m 12s"
    assert fmt.dur_s(3.4) == "3.4s"
    assert fmt.dur_ms(100) == "100ms"
    assert fmt.dur_ms(3400) == "3.4s"
    assert fmt.size(2150) == "2.1 KB"
    assert fmt.rel_time(_iso(120)) == "2h ago"
    assert fmt.rel_time("") == fmt.DASH
    assert fmt.rel_time("not a date") == fmt.DASH
    assert fmt.duration(_iso(10), _iso(8)) == "2m 00s"
    assert fmt.duration(_iso(10), "") == fmt.DASH          # still running
    long_fp = "ubuntu-server|mem_used|Memory climbing on the media server"
    short = fmt.fingerprint(long_fp, 20)
    assert len(short) == 20 and short.startswith("ubuntu-") and "…" in short
    assert fmt.fingerprint("") == fmt.DASH
    assert fmt.status_pill("pending_approval")["label"] == "pending approval"
    assert fmt.status_pill("weird") == {"icon": "·", "cls": "st-muted",
                                        "label": "weird", "key": "weird"}


def test_command_of_per_tool():
    def step(tool, args):
        return {"tool": tool, "args_json": json.dumps(args)}

    assert fmt.command_of(step("ssh_diagnostic", {"command": "uptime"})) == "uptime"
    assert fmt.command_of(step("prometheus_query", {"promql": "up"})) == "up"
    assert fmt.command_of(step("ha_api", {"path": "/api/states"})) == "/api/states"
    assert fmt.command_of(step("proxmox_api", {"path": "/nodes"})) == "/nodes"
    assert fmt.command_of(step("discover_metrics", {"pattern": "node_.*"})) == "node_.*"
    # unknown tool / unknown args -> the raw JSON, never silently blank
    assert "hosts" in fmt.command_of(step("mystery", {"hosts": ["a"]}))
    assert fmt.command_of({"tool": "ssh_diagnostic", "args_json": "not json"}) == "not json"
    assert fmt.command_of({"tool": "x", "args_json": ""}) == fmt.DASH
