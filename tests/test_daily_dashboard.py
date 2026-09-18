"""Tests for heim.reports.daily_dashboard (port of the n8n PAM-10 nodes
"Build Dashboard HTML1" + "Add Incident Band").

Expected markup fragments are derived from the reference JS in
reference/pam-10-daily-analysis/.
"""
from __future__ import annotations

from heim.reports.daily_dashboard import build_daily_email

GEN_AT = "2026-09-18T06:30:00.000+00:00"

GREEN = "#16a34a"
AMBER = "#d97706"
RED = "#dc2626"
SLATE = "#64748b"

KPI_MARKER = '<tr><td style="background:#fff;padding:8px 10px;">'


def make_payload(**over) -> dict:
    p = {
        "generatedAt": GEN_AT,
        "windowDays": 3,
        "hosts": ["nas", "ubuntu-server"],
        "counts": {"crit": 0, "warn": 0, "naQueries": 0},
        "overall": "healthy",
        "categories": {},
        "topAlerts": [],
    }
    p.update(over)
    return p


def make_analysis(**over) -> dict:
    a = {
        "overallHealth": "healthy",
        "headline": "All systems nominal",
        "executiveSummary": "Nothing notable in the 3-day window.",
        "categories": {},
        "findings": [],
        "watchlist": [],
    }
    a.update(over)
    return a


def row(host="nas", label="CPU busy", name="", unit="%", qid="cpu_busy",
        category="CPU", current=10.0, avg=9.0, mn=5.0, mx=20.0,
        change=1.0, flag="ok") -> dict:
    return {
        "host": host, "label": label, "name": name, "unit": unit,
        "qid": qid, "category": category, "current": current, "avg": avg,
        "min": mn, "max": mx, "day3d": [None, None, current],
        "changePct": change, "flag": flag,
    }


def pill(text: str, color: str) -> str:
    """The exact pill markup the JS `pill()` helper emits."""
    return ('<span style="display:inline-block;padding:3px 10px;border-radius:999px;'
            'background:' + color + ';color:#fff;font-size:11px;font-weight:700;'
            'letter-spacing:.4px;text-transform:uppercase;">' + text + '</span>')


def kpi_value(val: str, color: str) -> str:
    """The value div inside a KPI tile."""
    return ('<div style="font-size:24px;font-weight:800;color:' + color +
            ';margin-top:4px;">' + val + '</div>')


# ---------------------------------------------------------------- overall chip

def test_overall_healthy_chip_and_subject():
    subject, html = build_daily_email(make_analysis(), make_payload(), None, GEN_AT)
    assert subject == "Homelab Health Report — 2026-09-18 — HEALTHY"
    assert pill("healthy", GREEN) in html
    assert "generated 2026-09-18 06:30" in html
    assert "hosts: nas, ubuntu-server" in html


def test_overall_warning_chip_and_subject():
    payload = make_payload(counts={"crit": 0, "warn": 2, "naQueries": 0},
                           overall="warning")
    subject, html = build_daily_email(make_analysis(), payload, None, GEN_AT)
    assert subject == "Homelab Health Report — 2026-09-18 — WARNING (2 warn)"
    assert pill("warning", AMBER) in html


def test_overall_critical_chip_and_subject():
    payload = make_payload(counts={"crit": 1, "warn": 3, "naQueries": 0},
                           overall="critical")
    subject, html = build_daily_email(make_analysis(), payload, None, GEN_AT)
    # crit suffix wins over warn suffix
    assert subject == "Homelab Health Report — 2026-09-18 — CRITICAL (1 crit)"
    assert pill("critical", RED) in html


def test_llm_overall_escalates_over_payload():
    # JS bumps overall with an.overallHealth even when payload says healthy.
    subject, html = build_daily_email(
        make_analysis(overallHealth="warning"), make_payload(), None, GEN_AT)
    assert subject.endswith("— WARNING")
    assert pill("warning", AMBER) in html


# ------------------------------------------------------------------- KPI tiles

def test_kpi_tiles_healthy():
    _, html = build_daily_email(make_analysis(), make_payload(), None, GEN_AT)
    assert kpi_value("HEALTHY", GREEN) in html
    assert kpi_value("0", GREEN) in html  # both Critical and Warnings tiles


def test_kpi_tiles_counts_and_colors():
    payload = make_payload(counts={"crit": 2, "warn": 5, "naQueries": 1},
                           overall="critical")
    _, html = build_daily_email(make_analysis(), payload, None, GEN_AT)
    assert kpi_value("CRITICAL", RED) in html
    assert kpi_value("2", RED) in html
    assert kpi_value("5", AMBER) in html


# ------------------------------------------------------------ storage band

def test_storage_band_hosts_mounts_percentages():
    disk = [
        row(host="nas", label="FS used", name="/", unit="%", qid="fs_used",
            category="Disk", current=72.4, flag="warn"),
        row(host="nas", label="FS used", name="/data", unit="%", qid="fs_used",
            category="Disk", current=30.0, flag="ok"),
        row(host="nas", label="FS used bytes", name="/", unit="B",
            qid="fs_used_bytes", category="Disk", current=500 * 1024 ** 3),
        row(host="nas", label="FS total bytes", name="/", unit="B",
            qid="fs_total_bytes", category="Disk", current=1000 * 1024 ** 3),
        row(host="ubuntu-server", label="FS used", name="/", unit="%",
            qid="fs_used", category="Disk", current=91.5, flag="crit"),
        row(host="homeassistant", label="HA disk", name="", unit="%",
            qid="ha_disk", category="Disk", current=0.5, flag="ok"),
    ]
    payload = make_payload(categories={"Disk": disk})
    _, html = build_daily_email(make_analysis(), payload, None, GEN_AT)

    assert "Filesystem usage per host" in html
    # host card headers
    assert ">nas</div>" in html
    assert ">ubuntu-server</div>" in html
    assert ">homeassistant</div>" in html
    # percentages (toFixed(1))
    assert ">72.4%</td>" in html
    assert ">30.0%</td>" in html
    assert ">91.5%</td>" in html
    # bar widths: toFixed(0), clamped to [2, 100]
    assert 'width="72%"' in html
    assert 'width="92%"' in html
    assert 'width="30%"' in html
    assert 'width="2%"' in html  # 0.5% clamps up to 2
    # capacity line only for the mount that has used+total bytes rows
    assert ">500 GB / 1000 GB</td>" in html
    # empty mount name renders as '/'
    assert ">/</td>" in html
    # within a host, mounts sort by usage descending
    assert html.index(">72.4%") < html.index(">30.0%")
    # card border reflects the worst flag on the host
    assert "border-left:4px solid " + AMBER in html  # nas (warn beats ok)
    assert "border-left:4px solid " + RED in html    # ubuntu-server (crit)


def test_storage_band_absent_without_disk_rows():
    _, html = build_daily_email(make_analysis(), make_payload(), None, GEN_AT)
    assert "Filesystem usage per host" not in html


# -------------------------------------------------------------------- findings

def test_findings_severity_pills_details_and_recommendations():
    analysis = make_analysis(findings=[
        {"severity": "info", "host": "all", "metric": "note", "detail": "fyi"},
        {"severity": "critical", "host": "nas", "metric": "Root FS",
         "trend": "rising", "summary": "Disk filling",
         "detail": "Root filesystem at 91% <script>alert(1)</script>",
         "recommendation": "Clean docker images"},
    ])
    _, html = build_daily_email(analysis, make_payload(), None, GEN_AT)
    assert pill("critical", RED) in html
    assert pill("info", "#0ea5e9") in html
    # critical sorts before info despite input order
    assert html.index(pill("critical", RED)) < html.index(pill("info", "#0ea5e9"))
    # trend annotation, bold summary, recommendation arrow
    assert '<span style="color:#64748b;font-weight:400;">(rising)</span>' in html
    assert ('<div style="font-weight:700;color:#1e293b;margin-bottom:3px;">'
            "Disk filling</div>") in html
    assert '<div style="color:#0f766e;margin-top:4px;">➜ Clean docker images</div>' in html
    # LLM text is HTML-escaped
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>" not in html


def test_no_findings_green_row():
    _, html = build_daily_email(make_analysis(), make_payload(), None, GEN_AT)
    assert ('<tr><td colspan="4" style="padding:16px;color:#16a34a;font-size:13px;">'
            "No degradation findings — all monitored signals within normal 3-day "
            "trend. ✅</td></tr>") in html


# -------------------------------------------------------------- category cards

def test_category_cards_status_and_insight():
    payload = make_payload(categories={"CPU": [row(flag="ok")]})
    analysis = make_analysis(categories={
        "CPU": {"status": "warning", "insight": "CPU trending up on nas"},
    })
    _, html = build_daily_email(analysis, payload, None, GEN_AT)
    # LLM status (warn) beats the data flag (ok) for the card
    assert "CPU trending up on nas" in html
    assert pill("warn", AMBER) in html
    # the other 7 categories have no analysis
    assert html.count("No analysis provided.") == 7
    assert pill("na", SLATE) in html


def test_category_card_data_flag_beats_milder_llm_status():
    payload = make_payload(categories={"Memory": [row(category="Memory",
                                                      qid="mem_used",
                                                      label="Mem used",
                                                      flag="crit")]},
                           counts={"crit": 1, "warn": 0, "naQueries": 0},
                           overall="critical")
    analysis = make_analysis(categories={
        "Memory": {"status": "ok", "insight": "Memory fine"}})
    _, html = build_daily_email(analysis, payload, None, GEN_AT)
    # worst-of wins: the Memory card must be crit despite the LLM saying ok
    assert ('border-left:4px solid ' + RED + ';"><tr>'
            '<td style="padding:14px 16px;"><table width="100%"><tr>'
            '<td style="font-size:14px;font-weight:800;color:#1e293b;">Memory</td>') in html


# ---------------------------------------------------------------- metric table

def test_metric_table_units_and_changepct():
    cpu = [
        row(host="nas", label="CPU busy", unit="%", current=55.123, avg=40.0,
            mx=90.0, change=12.3, flag="warn"),
        row(host="nas", label="Load per core", name="core", unit="ratio",
            qid="load_per_core", current=0.5, avg=0.4, mx=0.9, change=None,
            flag="ok"),
        row(host="ubuntu-server", label="CPU busy", unit="%", current=8.0,
            avg=7.0, mx=12.0, change=2.0, flag="ok"),
    ]
    net = [
        row(host="nas", label="RX", name="eth0", unit="B/s", qid="net_rx",
            category="Network", current=2.5 * 1024 * 1024, avg=1024.0,
            mx=3 * 1024 * 1024, change=-12.0, flag="ok"),
    ]
    host_cat = [
        row(host="nas", label="Node up", unit="online", qid="node_up",
            category="Host", current=1.0, avg=1.0, mx=1.0, change=None,
            flag="ok"),
    ]
    payload = make_payload(categories={"CPU": cpu, "Network": net,
                                       "Host": host_cat},
                           counts={"crit": 0, "warn": 1, "naQueries": 0},
                           overall="warning")
    _, html = build_daily_email(make_analysis(), payload, None, GEN_AT)

    # table headers
    for th in (">Host</th>", ">Metric</th>", ">Current</th>", ">3d avg</th>",
               ">3d max</th>", ">Trend</th>", ">Status</th>"):
        assert th in html
    # unit formatting
    assert ">55.1%</td>" in html
    assert ">0.500</td>" in html          # ratio -> toFixed(3)
    assert ">2.50 MB/s</td>" in html      # B/s scaling, <10 -> 2 decimals
    assert ">1.00 KB/s</td>" in html      # avg column
    assert ">online</td>" in html
    # name shown as a muted span next to the label
    assert 'Load per core <span style="color:#94a3b8;">core</span>' in html
    # changePct formatting and colors
    assert (';color:#dc2626;font-weight:600;">▲ 12%</td>') in html
    assert (';color:#16a34a;font-weight:600;">▼ 12%</td>') in html
    assert (';color:#64748b;font-weight:600;">▬</td>') in html   # |2| <= 5
    assert (';color:#64748b;font-weight:600;">—</td>') in html   # null changePct
    # row-flag pill in the status column
    assert pill("warn", AMBER) in html
    # sort: nas rows before ubuntu-server rows within the CPU table
    assert html.index(">55.1%") < html.index(">8.0%")


def test_row_status_escalated_by_matching_finding():
    payload = make_payload(categories={
        "CPU": [row(host="nas", label="CPU busy", flag="ok", change=1.0)]})
    analysis = make_analysis(findings=[
        {"severity": "warning", "host": "nas", "metric": "cpu busy sustained",
         "detail": "elevated"}])
    _, html = build_daily_email(analysis, payload, None, GEN_AT)
    # the ok-flagged row is escalated to warn by the overlapping finding
    assert pill("warn", AMBER) in html


# --------------------------------------------------------------- incident band

def test_incident_band_new_ongoing_resolved():
    summary = {
        "counts": {"open": 3, "new": 1, "ongoing": 1, "clearing": 1,
                   "resolved": 1},
        "new": [{"fingerprint": "nas|fs_used|/", "host": "nas",
                 "metric": "Root FS", "severity": "critical",
                 "status": "open", "firstSeen": GEN_AT, "lastSeen": GEN_AT,
                 "timesSeen": 1, "description": "root fs at 91%"}],
        "ongoing": [{"escalated": True, "fingerprint": "ubuntu-server|cpu_busy|",
                     "host": "ubuntu-server", "metric": "CPU busy",
                     "severity": "warning", "status": "open",
                     "timesSeen": 3, "description": "cpu elevated"}],
        "clearing": [{"fingerprint": "nas|swap_used|", "host": "nas",
                      "metric": "Swap used", "severity": "warning",
                      "status": "open", "timesSeen": 2,
                      "description": "swap high"}],
        "resolved": [{"fingerprint": "nas|host_temp_max|", "host": "nas",
                      "metric": "", "severity": "warning",
                      "status": "resolved", "timesSeen": 4,
                      "description": "temp <spike> over"}],
    }
    _, html = build_daily_email(make_analysis(), make_payload(), summary, GEN_AT)

    assert "(1 new · 1 ongoing · 1 resolved)" in html
    assert ('<span style="color:#dc2626;font-weight:700;">🆕 NEW</span> &nbsp;'
            "<b>nas</b> — Root FS</td>") in html
    assert ('<span style="color:#d97706;font-weight:700;">🔄 ONGOING ⬆ ESCALATED'
            "</span> &nbsp;<b>ubuntu-server</b> — CPU busy</td>") in html
    assert ('<span style="color:#d97706;font-weight:700;">➕ CLEARING</span>'
            " &nbsp;<b>nas</b> — Swap used</td>") in html
    # resolved is green regardless of severity; empty metric falls back to
    # the (escaped) description
    assert ('<span style="color:#16a34a;font-weight:700;">✅ RESOLVED</span>'
            " &nbsp;<b>nas</b> — temp &lt;spike&gt; over</td>") in html
    # order: new, ongoing, clearing, resolved
    assert (html.index("🆕 NEW") < html.index("🔄 ONGOING")
            < html.index("➕ CLEARING") < html.index("✅ RESOLVED"))
    # inserted immediately before the KPI row, after the dark header
    assert html.index("Incidents") < html.index(KPI_MARKER)
    assert html.index("🖥️ Homelab Health Report") < html.index("Incidents")


def test_incident_band_empty_summary_and_none():
    for summary in (None,
                    {"counts": {}, "new": [], "ongoing": [], "clearing": [],
                     "resolved": []}):
        _, html = build_daily_email(make_analysis(), make_payload(),
                                    summary, GEN_AT)
        # the band is still present, with zero counts and the green row
        assert "(0 new · 0 ongoing · 0 resolved)" in html
        assert ('<tr><td style="padding:8px 10px;font-size:12px;color:#16a34a;">'
                "No open incidents. ✅</td></tr>") in html
        assert html.index("No open incidents.") < html.index(KPI_MARKER)


# ------------------------------------------------------------- fallback / misc

def test_analysis_none_fallback():
    payload = make_payload(counts={"crit": 0, "warn": 1, "naQueries": 0},
                           overall="warning")
    subject, html = build_daily_email(None, payload, None, GEN_AT)
    assert "LLM analysis unavailable — showing metric data only." in html
    assert subject == "Homelab Health Report — 2026-09-18 — WARNING (1 warn)"
    # all category cards fall back to the placeholder insight
    assert html.count("No analysis provided.") == 8


def test_generated_at_fallback_when_payload_lacks_timestamp():
    payload = make_payload()
    del payload["generatedAt"]
    subject, html = build_daily_email(make_analysis(), payload, None, GEN_AT)
    assert subject.startswith("Homelab Health Report — 2026-09-18 —")
    assert "generated 2026-09-18 06:30" in html


def test_watchlist_rendering_and_absence():
    _, html = build_daily_email(
        make_analysis(watchlist=["nas swap creeping <up>"]),
        make_payload(), None, GEN_AT)
    assert "👁️ Watchlist" in html
    assert '<li style="margin:3px 0;">nas swap creeping &lt;up&gt;</li>' in html

    _, html2 = build_daily_email(make_analysis(), make_payload(), None, GEN_AT)
    assert "👁️ Watchlist" not in html2


def test_headline_and_summary_escaped():
    analysis = make_analysis(headline="Broken <b>tag</b> & stuff",
                             executiveSummary="a < b > c")
    _, html = build_daily_email(analysis, make_payload(), None, GEN_AT)
    assert "Broken &lt;b&gt;tag&lt;/b&gt; &amp; stuff" in html
    assert "a &lt; b &gt; c" in html
    assert "<b>tag</b>" not in html


def test_footer_and_frame():
    _, html = build_daily_email(make_analysis(), make_payload(), None, GEN_AT)
    assert html.startswith("<!doctype html><html><body")
    assert html.endswith("</table></td></tr></table></body></html>")
    assert "Prometheus 3-day window · analysis by Claude" in html
    assert "Category status" in html
    assert "Findings &amp; recommendations" in html
    assert "Metric detail (3-day window)" in html
