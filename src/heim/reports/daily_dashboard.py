"""Daily "Homelab Health Report" HTML email builder.

Port of two n8n Code nodes from workflow PAM-10 Daily Analysis:

* **"Build Dashboard HTML1"**
  (``reference/pam-10-daily-analysis/build-dashboard-html1.js``) — builds the
  full report: dark header with overall pill, KPI tiles, headline/executive
  summary, per-host filesystem-usage band, category-status grid, findings &
  recommendations table, per-category metric detail tables, watchlist, footer.
* **"Add Incident Band"**
  (``reference/pam-10-daily-analysis/add-incident-band.js``) — injects the
  incidents band (new/ongoing/clearing/resolved) immediately before the KPI
  row of the built HTML. Integrated here as a build step; the final HTML is
  byte-identical to running the two nodes in sequence.

Input-plumbing mapping (deliberate, documented deviations):

* The JS re-extracted the LLM chain's raw text and ``parseJSON()``-ed it.
  Here ``analysis`` arrives already parsed; ``analysis is None`` maps to the
  JS parse-failure fallback object (``overallHealth`` from ``payload.overall``,
  the "LLM analysis unavailable — showing metric data only." headline). The
  JS fallback set ``executiveSummary`` to the first 600 chars of the raw LLM
  text; the raw text does not exist in this API, so the fallback summary is
  empty.
* The JS read ``payload.generatedAt`` for the header timestamp and the
  subject. This port uses ``payload["generatedAt"]`` when present and falls
  back to the ``generated_at`` argument (the same run timestamp the aggregate
  step stamps into the payload) instead of the JS's empty string.
* The subject is built exactly as the JS does (line 63 of the build node):
  ``'Homelab Health Report — <date> — <OVERALL>'`` plus a ``(N crit)`` /
  ``(N warn)`` suffix. "Add Incident Band" passes the subject through
  unchanged.
* JS ``String#localeCompare`` sorts are mapped to ordinal string comparison
  (identical for the plain-ASCII host/label/name values the payload holds).

Everything is pure: no I/O, no clock reads.
"""
from __future__ import annotations

import math
import re
from decimal import ROUND_HALF_UP, Decimal

__all__ = ["build_daily_email"]

# ---------------------------------------------------------------------------
# Constants (verbatim from build-dashboard-html1.js)

_C: dict[str, str] = {
    "healthy": "#16a34a",
    "ok": "#16a34a",
    "warning": "#d97706",
    "warn": "#d97706",
    "critical": "#dc2626",
    "crit": "#dc2626",
    "na": "#64748b",
    "info": "#0ea5e9",
    "unknown": "#64748b",
}

_FLAG_SEV: dict[str, int] = {
    "crit": 3, "critical": 3, "warn": 2, "warning": 2,
    "ok": 1, "healthy": 1, "info": 0, "na": 0, "unknown": 0,
}

_CAT_ORDER = ["CPU", "Memory", "Disk", "Disk Health", "Temperature",
              "Network", "Proxmox", "Host"]

_HEALTH_RANK = {"healthy": 0, "ok": 0, "warning": 1, "warn": 1,
                "critical": 2, "crit": 2}
_HEALTH_NAME = ["healthy", "warning", "critical"]

#: findings sort rank (JS ``sevRank``). Quirk kept: bare 'crit' is absent and
#: therefore sorts last (rank 3), exactly like the JS.
_FINDING_SEV_RANK = {"critical": 0, "warn": 1, "warning": 1, "info": 2}

#: metric-table flag rank (JS ``flagRank``).
_FLAG_RANK = {"crit": 0, "warn": 1, "ok": 2, "na": 3}

_WORD_SPLIT_RE = re.compile(r"[^a-z0-9]+")


# ---------------------------------------------------------------------------
# Small helpers (ports of the JS one-liners)

def _norm(s: object) -> str:
    """JS ``norm``: ``String(s==null?'unknown':s).toLowerCase()``."""
    return ("unknown" if s is None else str(s)).lower()


def _col(s: object) -> str:
    """JS ``col``: status color, defaulting to slate."""
    return _C.get(_norm(s), "#64748b")


def _canon_flag(s: object) -> str:
    """JS ``canonFlag``: canonicalize a flag/severity string."""
    n = _norm(s)
    if n in ("crit", "critical"):
        return "crit"
    if n in ("warn", "warning"):
        return "warn"
    if n in ("ok", "healthy"):
        return "ok"
    if n == "info":
        return "info"
    return "na"


def _esc(s: object) -> str:
    """JS ``esc``: escape ``&``, ``<``, ``>`` only (no quote escaping)."""
    return ("" if s is None else str(s)) \
        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _as_number(v: object) -> float | None:
    """Coerce a row value like JS ``+v``; None for null/NaN/garbage."""
    if v is None:
        return None
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        f = float(v)
    else:
        try:
            f = float(str(v).strip())
        except ValueError:
            return None
    # NaN is rejected (JS isNaN); infinities pass through, also like JS.
    return None if math.isnan(f) else f


def _to_fixed(v: float, digits: int) -> str:
    """JS ``Number#toFixed``: fixed-decimal string, ties away from zero on
    the exact binary value."""
    quantum = Decimal(1).scaleb(-digits)
    d = Decimal(v).quantize(quantum, rounding=ROUND_HALF_UP)
    return f"{d:.{digits}f}"


def _human(v: object, unit: object) -> str:
    """JS ``human``: unit-aware value formatting."""
    n = _as_number(v)
    if n is None:
        return "—"
    if unit == "B/s":
        units = ["B/s", "KB/s", "MB/s", "GB/s"]
        a = abs(n)
        i = 0
        while a >= 1024 and i < 3:
            a /= 1024
            i += 1
        return _to_fixed(a, 2 if a < 10 else 0) + " " + units[i]
    if unit == "B":
        units = ["B", "KB", "MB", "GB", "TB"]
        a = abs(n)
        i = 0
        while a >= 1024 and i < 4:
            a /= 1024
            i += 1
        return _to_fixed(a, 2 if a < 10 else 0) + " " + units[i]
    if unit == "state":
        return "running" if n >= 1 else "stopped"
    if unit == "online":
        return "online" if n >= 1 else "offline"
    if unit == "%":
        return _to_fixed(n, 1) + "%"
    if unit == "°C":
        return _to_fixed(n, 1) + "°C"
    if unit == "days":
        return _to_fixed(n, 1) + "d"
    if unit in ("/s", "ratio"):
        return _to_fixed(n, 3)
    if abs(n) >= 1000:
        return _to_fixed(n, 0)
    return _to_fixed(n, 3 if abs(n) < 1 else 2)


def _arrow(p: object) -> str:
    """JS ``arrow``: trend arrow for a changePct value."""
    n = _as_number(p)
    if n is None:
        return "—"
    if n > 5:
        return "▲ " + _to_fixed(n, 0) + "%"
    if n < -5:
        return "▼ " + _to_fixed(abs(n), 0) + "%"
    return "▬"


def _arrow_color(p: object) -> str:
    """JS ``arrowColor``."""
    n = _as_number(p)
    if n is None:
        return "#64748b"
    if n > 5:
        return "#dc2626"
    if n < -5:
        return "#16a34a"
    return "#64748b"


def _pill(text: object, color: str) -> str:
    """JS ``pill``: rounded status chip."""
    return ('<span style="display:inline-block;padding:3px 10px;border-radius:999px;'
            'background:' + color + ';color:#fff;font-size:11px;font-weight:700;'
            'letter-spacing:.4px;text-transform:uppercase;">' + _esc(text) + '</span>')


def _kpi(label: str, val: str, color: str) -> str:
    """JS ``kpi``: one KPI tile cell (``val`` is inserted unescaped, as in JS)."""
    return ('<td width="33%" style="padding:6px;"><table width="100%" cellpadding="0" '
            'cellspacing="0" style="background:#ffffff;border:1px solid #e5e9f2;'
            'border-radius:12px;"><tr><td style="padding:16px 18px;">'
            '<div style="font-size:11px;color:#64748b;text-transform:uppercase;'
            'letter-spacing:.6px;font-weight:700;">' + _esc(label) + '</div>'
            '<div style="font-size:24px;font-weight:800;color:' + color +
            ';margin-top:4px;">' + val + '</div></td></tr></table></td>')


def _words(s: object) -> list[str]:
    """Lowercase word split, keeping words of length >= 3 (JS pattern)."""
    return [w for w in _WORD_SPLIT_RE.split(_norm(s)) if len(w) >= 3]


def _host_match(fh: str, rh: str) -> bool:
    """JS ``_hostMatch``: fuzzy host containment match."""
    if not fh or fh == "all":
        return True
    if not rh:
        return False
    return fh == rh or fh in rh or rh in fh


# ---------------------------------------------------------------------------
# Status derivation (ports of catStatus / rowStatus)

def _cat_status(cat: str, categories: dict, an: dict) -> str:
    """JS ``catStatus``: worst of the data flags and the LLM category status."""
    rows = categories.get(cat) or []
    dw: str | None = None
    for r in rows:
        s = _canon_flag(r.get("flag"))
        if dw is None or _FLAG_SEV.get(s, 0) > _FLAG_SEV.get(dw, 0):
            dw = s
    an_cats = an.get("categories")
    info = an_cats.get(cat) if isinstance(an_cats, dict) else None
    llm = _canon_flag(info["status"]) if info and info.get("status") else None
    st = dw
    if llm and (st is None or _FLAG_SEV.get(llm, 0) > _FLAG_SEV.get(st, 0)):
        st = llm
    return st if st is not None else "na"


def _prep_findings(an: dict) -> list[dict]:
    """JS ``_findings``: pre-normalized findings for row-status matching."""
    return [
        {"sev": _canon_flag(f.get("severity")),
         "host": _norm(f.get("host")),
         "words": _words(f.get("metric"))}
        for f in (an.get("findings") or [])
    ]


def _row_status(r: dict, findings: list[dict]) -> str:
    """JS ``rowStatus``: escalate a row's flag when a warn/crit finding
    overlaps it by host and metric words."""
    st = _canon_flag(r.get("flag"))
    rw = _words(_norm(r.get("label")) + " " + _norm(r.get("name")))
    for f in findings:
        if f["sev"] not in ("warn", "crit"):
            continue
        if _FLAG_SEV.get(f["sev"], 0) <= _FLAG_SEV.get(st, 0):
            continue
        if not _host_match(f["host"], _norm(r.get("host"))):
            continue
        if any(w in rw for w in f["words"]):
            st = f["sev"]
    return st


# ---------------------------------------------------------------------------
# Section builders

def _category_grid(categories: dict, an: dict) -> str:
    """Category-status cards, two per row (JS ``catGrid``)."""
    cells: list[str] = []
    for cat in _CAT_ORDER:
        an_cats = an.get("categories")
        info = an_cats.get(cat) if isinstance(an_cats, dict) else None
        st = _cat_status(cat, categories, an)
        insight = info["insight"] if info and info.get("insight") else "No analysis provided."
        cells.append(
            '<td width="50%" valign="top" style="padding:6px;"><table width="100%" '
            'cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid '
            '#e5e9f2;border-radius:12px;border-left:4px solid ' + _col(st) + ';"><tr>'
            '<td style="padding:14px 16px;"><table width="100%"><tr>'
            '<td style="font-size:14px;font-weight:800;color:#1e293b;">' + _esc(cat) +
            '</td><td align="right">' + _pill(st, _col(st)) + '</td></tr></table>'
            '<div style="font-size:12.5px;color:#475569;line-height:1.5;margin-top:8px;">'
            + _esc(insight) + '</div></td></tr></table></td>')
    grid = ""
    for i in range(0, len(cells), 2):
        second = cells[i + 1] if i + 1 < len(cells) else \
            '<td width="50%" style="padding:6px;"></td>'
        grid += "<tr>" + cells[i] + second + "</tr>"
    return grid


def _finding_rows(an: dict) -> str:
    """Findings & recommendations table body (JS ``findRows``)."""
    findings = sorted(
        an.get("findings") or [],
        key=lambda f: _FINDING_SEV_RANK.get(_norm(f.get("severity")), 3),
    )
    rows = ""
    for f in findings[:20]:
        trend = f.get("trend")
        summary = f.get("summary")
        rec = f.get("recommendation")
        rows += ('<tr style="border-top:1px solid #eef1f7;">'
                 '<td valign="top" style="padding:9px 10px;white-space:nowrap;">'
                 + _pill(f.get("severity"), _col(f.get("severity"))) + '</td>'
                 '<td valign="top" style="padding:9px 10px;font-size:12.5px;color:#1e293b;">'
                 + _esc(f.get("host") or "—") + '</td>'
                 '<td valign="top" style="padding:9px 10px;font-size:12.5px;color:#1e293b;'
                 'font-weight:600;">' + _esc(f.get("metric") or "")
                 + ((' <span style="color:#64748b;font-weight:400;">(' + _esc(trend) + ')</span>')
                    if trend else '') + '</td>'
                 '<td valign="top" style="padding:9px 10px;font-size:12.5px;color:#475569;'
                 'line-height:1.5;">'
                 + (('<div style="font-weight:700;color:#1e293b;margin-bottom:3px;">'
                     + _esc(summary) + '</div>') if summary else '')
                 + _esc(f.get("detail") or "")
                 + (('<div style="color:#0f766e;margin-top:4px;">➜ ' + _esc(rec) + '</div>')
                    if rec else '')
                 + '</td></tr>')
    if not rows:
        rows = ('<tr><td colspan="4" style="padding:16px;color:#16a34a;font-size:13px;">'
                'No degradation findings — all monitored signals within normal 3-day '
                'trend. ✅</td></tr>')
    return rows


def _data_tables(categories: dict, an: dict, findings: list[dict]) -> str:
    """Per-category metric detail tables (JS ``dataTables``)."""
    tables = ""
    for cat in _CAT_ORDER:
        rows = sorted(
            categories.get(cat) or [],
            key=lambda r: (str(r.get("host")),
                           _FLAG_RANK.get(r.get("flag"), 3),
                           str(r.get("label")),
                           str(r.get("name"))),
        )
        if not rows:
            continue
        st_color = _col(_cat_status(cat, categories, an))
        body = ""
        for r in rows:
            status = _row_status(r, findings)
            name = r.get("name")
            body += ('<tr style="border-top:1px solid #eef1f7;">'
                     '<td style="padding:7px 10px;font-size:12px;color:#475569;">'
                     + _esc(r.get("host")) + '</td>'
                     '<td style="padding:7px 10px;font-size:12px;color:#1e293b;">'
                     + _esc(r.get("label"))
                     + ((' <span style="color:#94a3b8;">' + _esc(name) + '</span>')
                        if name else '') + '</td>'
                     '<td align="right" style="padding:7px 10px;font-size:12px;'
                     'font-weight:700;color:#1e293b;">' + _human(r.get("current"), r.get("unit")) + '</td>'
                     '<td align="right" style="padding:7px 10px;font-size:12px;color:#475569;">'
                     + _human(r.get("avg"), r.get("unit")) + '</td>'
                     '<td align="right" style="padding:7px 10px;font-size:12px;color:#475569;">'
                     + _human(r.get("max"), r.get("unit")) + '</td>'
                     '<td align="right" style="padding:7px 10px;font-size:12px;color:'
                     + _arrow_color(r.get("changePct")) + ';font-weight:600;">'
                     + _arrow(r.get("changePct")) + '</td>'
                     '<td align="center" style="padding:7px 10px;">'
                     + _pill(status, _col(status)) + '</td></tr>')
        tables += ('<table width="100%" cellpadding="0" cellspacing="0" style="margin-top:16px;'
                   'background:#fff;border:1px solid #e5e9f2;border-radius:12px;overflow:hidden;">'
                   '<tr><td style="padding:12px 14px;background:#f8fafc;border-bottom:1px solid '
                   '#e5e9f2;font-size:13px;font-weight:800;color:#1e293b;border-left:4px solid '
                   + st_color + ';">' + _esc(cat) + '</td></tr>'
                   '<tr><td style="padding:0;"><table width="100%" cellpadding="0" cellspacing="0">'
                   '<tr style="background:#fbfcfe;">'
                   '<th align="left" style="padding:7px 10px;font-size:10.5px;color:#94a3b8;'
                   'text-transform:uppercase;letter-spacing:.5px;">Host</th>'
                   '<th align="left" style="padding:7px 10px;font-size:10.5px;color:#94a3b8;'
                   'text-transform:uppercase;">Metric</th>'
                   '<th align="right" style="padding:7px 10px;font-size:10.5px;color:#94a3b8;'
                   'text-transform:uppercase;">Current</th>'
                   '<th align="right" style="padding:7px 10px;font-size:10.5px;color:#94a3b8;'
                   'text-transform:uppercase;">3d avg</th>'
                   '<th align="right" style="padding:7px 10px;font-size:10.5px;color:#94a3b8;'
                   'text-transform:uppercase;">3d max</th>'
                   '<th align="right" style="padding:7px 10px;font-size:10.5px;color:#94a3b8;'
                   'text-transform:uppercase;">Trend</th>'
                   '<th align="center" style="padding:7px 10px;font-size:10.5px;color:#94a3b8;'
                   'text-transform:uppercase;">Status</th></tr>'
                   + body + '</table></td></tr></table>')
    return tables


def _watch_block(an: dict) -> str:
    """Watchlist card (JS ``watchBlock``); empty string when no items."""
    items = an.get("watchlist") or []
    if not items:
        return ""
    lis = "".join('<li style="margin:3px 0;">' + _esc(w) + "</li>" for w in items)
    return ('<tr><td style="background:#eef1f7;padding:6px 16px 16px;"><table width="100%" '
            'cellpadding="0" cellspacing="0" style="background:#fff;border:1px solid #e5e9f2;'
            'border-radius:12px;"><tr><td style="padding:14px 18px;">'
            '<div style="font-size:13px;font-weight:800;color:#1e293b;margin-bottom:6px;">'
            '👁️ Watchlist</div><ul style="margin:0;padding-left:18px;font-size:12.5px;'
            'color:#475569;">' + lis + '</ul></td></tr></table></td></tr>')


def _storage_band(categories: dict) -> str:
    """Per-host filesystem usage bars (JS ``storageBand``)."""
    disk = categories.get("Disk") or []
    used_b: dict[str, object] = {}
    total_b: dict[str, object] = {}
    for r in disk:
        key = str(r.get("host")) + "|" + str(r.get("name"))
        if r.get("qid") == "fs_used_bytes":
            used_b[key] = r.get("current")
        if r.get("qid") == "fs_total_bytes":
            total_b[key] = r.get("current")
    by_host: dict[str, list[dict]] = {}
    for r in disk:
        if r.get("qid") not in ("fs_used", "ha_disk"):
            continue
        by_host.setdefault(str(r.get("host")), []).append(r)

    rk = {"crit": 0, "warn": 1, "ok": 2, "na": 3}
    cells: list[str] = []
    for h in sorted(by_host):
        fs_list = sorted(by_host[h],
                         key=lambda r: -(_as_number(r.get("current")) or 0))
        worst = "na"
        rows_html = ""
        for r in fs_list:
            if rk.get(r.get("flag"), 3) < rk.get(worst, 3):
                worst = r.get("flag")
            key = str(r.get("host")) + "|" + str(r.get("name"))
            u, t = used_b.get(key), total_b.get(key)
            cap = (_human(u, "B") + " / " + _human(t, "B")) \
                if (u is not None and t is not None) else ""
            c = _col(r.get("flag"))
            cur = _as_number(r.get("current")) or 0.0
            pct = _to_fixed(cur, 1)
            bw = _to_fixed(max(2.0, min(100.0, cur)), 0)
            rows_html += ('<table width="100%" cellpadding="0" cellspacing="0" '
                          'style="margin-top:11px;"><tr>'
                          '<td style="font-size:12.5px;font-weight:700;color:#1e293b;">'
                          + _esc(r.get("name") or "/") + '</td>'
                          '<td align="right" style="font-size:14px;font-weight:800;color:'
                          + c + ';">' + pct + '%</td></tr>'
                          + (('<tr><td colspan="2" style="font-size:11px;color:#94a3b8;'
                              'padding-top:1px;">' + _esc(cap) + '</td></tr>') if cap else '')
                          + '<tr><td colspan="2" style="padding-top:5px;">'
                          '<table width="100%" cellpadding="0" cellspacing="0" '
                          'style="background:#eef1f7;border-radius:999px;"><tr>'
                          '<td style="padding:0;"><table width="' + bw + '%" cellpadding="0" '
                          'cellspacing="0" style="background:' + c + ';border-radius:999px;">'
                          '<tr><td style="font-size:0;line-height:0;height:7px;">&nbsp;</td>'
                          '</tr></table></td></tr></table></td></tr></table>')
        cells.append('<td width="50%" valign="top" style="padding:6px;"><table width="100%" '
                     'cellpadding="0" cellspacing="0" style="background:#fff;border:1px solid '
                     '#e5e9f2;border-radius:12px;border-left:4px solid ' + _col(worst) + ';">'
                     '<tr><td style="padding:14px 16px;"><div style="font-size:11px;'
                     'color:#64748b;text-transform:uppercase;letter-spacing:.5px;'
                     'font-weight:700;">' + _esc(h) + '</div>' + rows_html
                     + '</td></tr></table></td>')
    if not cells:
        return ""
    grid = ""
    for i in range(0, len(cells), 2):
        second = cells[i + 1] if i + 1 < len(cells) else \
            '<td width="50%" style="padding:6px;"></td>'
        grid += "<tr>" + cells[i] + second + "</tr>"
    return ('<tr><td style="background:#eef1f7;padding:16px 16px 4px;">'
            '<div style="font-size:12px;font-weight:800;color:#64748b;text-transform:uppercase;'
            'letter-spacing:.6px;padding-left:6px;">Filesystem usage per host</div></td></tr>'
            '<tr><td style="background:#eef1f7;padding:0 10px;"><table width="100%" '
            'cellpadding="0" cellspacing="0">' + grid + '</table></td></tr>')


# ---------------------------------------------------------------------------
# Incident band (port of add-incident-band.js)

def _sev_color(sev: object) -> str:
    """JS ``sevColor`` from add-incident-band.js."""
    n = str(sev or "").lower()
    if n == "critical":
        return "#dc2626"
    if n == "warning":
        return "#d97706"
    return "#64748b"


def _incident_line(kind: str, it: dict) -> str:
    """JS ``line``: one incident row with its kind tag."""
    color = "#16a34a" if kind == "resolved" else _sev_color(it.get("severity"))
    if kind == "new":
        tag = "🆕 NEW"
    elif kind == "ongoing":
        tag = "🔄 ONGOING" + (" ⬆ ESCALATED" if it.get("escalated") else "")
    elif kind == "clearing":
        tag = "➕ CLEARING"
    else:
        tag = "✅ RESOLVED"
    return ('<tr><td style="padding:6px 10px;font-size:12px;border-top:1px solid #eef1f7;">'
            '<span style="color:' + color + ';font-weight:700;">' + tag + '</span> &nbsp;<b>'
            + _esc(it.get("host")) + '</b> — '
            + _esc(it.get("metric") or it.get("description") or "") + '</td></tr>')


def _add_incident_band(html: str, summary: dict | None) -> str:
    """Inject the incidents band into the built HTML.

    Faithful to add-incident-band.js: a missing summary behaves like the
    empty default (the band is still rendered, showing "No open incidents").
    The band goes immediately before the KPI row; if that marker is missing,
    before ``</body>``.
    """
    s = summary or {"counts": {}, "new": [], "ongoing": [], "clearing": [], "resolved": []}
    rows = ""
    for it in s.get("new") or []:
        rows += _incident_line("new", it)
    for it in s.get("ongoing") or []:
        rows += _incident_line("ongoing", it)
    for it in s.get("clearing") or []:
        rows += _incident_line("clearing", it)
    for it in s.get("resolved") or []:
        rows += _incident_line("resolved", it)
    if not rows:
        rows = ('<tr><td style="padding:8px 10px;font-size:12px;color:#16a34a;">'
                'No open incidents. ✅</td></tr>')
    cts = s.get("counts") or {}
    band = ('<tr><td style="background:#eef1f7;padding:16px 16px 4px;">'
            '<div style="font-size:12px;font-weight:800;color:#64748b;'
            'text-transform:uppercase;letter-spacing:.6px;padding-left:6px;">Incidents '
            '&nbsp;<span style="color:#94a3b8;font-weight:600;">('
            + str(cts.get("new") or 0) + ' new · ' + str(cts.get("ongoing") or 0)
            + ' ongoing · ' + str(cts.get("resolved") or 0) + ' resolved)</span></div>'
            '</td></tr><tr><td style="background:#eef1f7;padding:0 10px 8px;">'
            '<table width="100%" cellpadding="0" cellspacing="0" style="background:#fff;'
            'border:1px solid #e5e9f2;border-radius:12px;overflow:hidden;">' + rows
            + '</table></td></tr>')
    marker = '<tr><td style="background:#fff;padding:8px 10px;">'
    if marker in html:
        return html.replace(marker, band + marker, 1)
    if "</body>" in html:
        return html.replace("</body>", band + "</body>", 1)
    return html


# ---------------------------------------------------------------------------
# Entry point

def build_daily_email(analysis: dict | None, payload: dict,
                      incident_summary: dict | None,
                      generated_at: str) -> tuple[str, str]:
    """Build the daily "Homelab Health Report" email (subject, html).

    Port of the n8n "Build Dashboard HTML1" + "Add Incident Band" Code
    nodes (PAM-10 Daily Analysis). ``analysis`` is the already-parsed LLM
    analysis dict (``None`` maps to the JS parse-failure fallback);
    ``payload`` is the aggregate payload; ``incident_summary`` is the
    reconcile summary (``None`` behaves like an empty summary);
    ``generated_at`` is the run's ISO timestamp, used as fallback when the
    payload carries no ``generatedAt``.
    """
    an = analysis if analysis is not None else {
        "overallHealth": payload.get("overall"),
        "headline": "LLM analysis unavailable — showing metric data only.",
        # JS: (String(raw)||'').slice(0,600) — raw LLM text is out of scope
        # in this API, so the fallback summary is empty.
        "executiveSummary": "",
        "categories": {},
        "findings": [],
        "watchlist": [],
    }
    categories = payload.get("categories") or {}

    gen_at = str(payload.get("generatedAt") or generated_at or "")
    dt = gen_at.replace("T", " ", 1)[:16] if gen_at else ""

    # ------------------------------------------------------------- counts
    an_findings = an.get("findings") or []
    f_crit = sum(1 for f in an_findings if _canon_flag(f.get("severity")) == "crit")
    f_warn = sum(1 for f in an_findings if _canon_flag(f.get("severity")) == "warn")
    pc = payload.get("counts") or {"crit": 0, "warn": 0}
    crit_count = max(f_crit, pc.get("crit") or 0)
    warn_count = max(f_warn, pc.get("warn") or 0)
    counts = {"crit": crit_count, "warn": warn_count, "naQueries": pc.get("naQueries")}

    # ------------------------------------------------------------- overall
    o_lvl = 0

    def bump(s: object) -> None:
        nonlocal o_lvl
        r = _HEALTH_RANK.get(_norm(s))
        if r is not None and r > o_lvl:
            o_lvl = r

    bump(an.get("overallHealth"))
    bump(payload.get("overall"))
    for cat in _CAT_ORDER:
        bump(_cat_status(cat, categories, an))
    if crit_count > 0:
        o_lvl = 2
    elif warn_count > 0 and o_lvl < 1:
        o_lvl = 1
    overall = _HEALTH_NAME[o_lvl]

    subject = ("Homelab Health Report — " + gen_at[:10] + " — " + overall.upper()
               + ((" (" + str(counts["crit"]) + " crit)") if counts["crit"]
                  else ((" (" + str(counts["warn"]) + " warn)") if counts["warn"] else "")))

    # ------------------------------------------------------------- sections
    findings_norm = _prep_findings(an)
    cat_grid = _category_grid(categories, an)
    find_rows = _finding_rows(an)
    data_tables = _data_tables(categories, an, findings_norm)
    watch_block = _watch_block(an)
    storage_band = _storage_band(categories)

    html = (
        '<!doctype html><html><body style="margin:0;padding:0;background:#eef1f7;">'
        '<table width="100%" cellpadding="0" cellspacing="0" style="background:#eef1f7;'
        'padding:18px 0;"><tr><td align="center">'
        '<table width="680" cellpadding="0" cellspacing="0" style="max-width:680px;width:100%;'
        'font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,'
        'sans-serif;color:#1e293b;">'
        '<tr><td style="background:linear-gradient(135deg,#0f172a,#1e293b);'
        'border-radius:16px 16px 0 0;padding:22px 24px;"><table width="100%"><tr>'
        '<td><div style="font-size:19px;font-weight:800;color:#fff;">🖥️ Homelab Health '
        'Report</div><div style="font-size:12px;color:#94a3b8;margin-top:3px;">3-day trend '
        '· generated ' + _esc(dt) + ' · hosts: '
        + _esc(", ".join(payload.get("hosts") or [])) + '</div></td>'
        '<td align="right" valign="top">' + _pill(overall, _col(overall))
        + '</td></tr></table></td></tr>'
        '<tr><td style="background:#fff;padding:8px 10px;"><table width="100%" '
        'cellpadding="0" cellspacing="0"><tr>'
        + _kpi("Overall", overall.upper(), _col(overall))
        + _kpi("Critical", str(counts["crit"] or 0),
               _C["critical"] if counts["crit"] else _C["ok"])
        + _kpi("Warnings", str(counts["warn"] or 0),
               _C["warning"] if counts["warn"] else _C["ok"])
        + '</tr></table></td></tr>'
        '<tr><td style="background:#fff;padding:6px 22px 20px;">'
        '<div style="font-size:15px;font-weight:800;color:#1e293b;line-height:1.4;">'
        + _esc(an.get("headline") or "") + '</div>'
        '<div style="font-size:13px;color:#475569;line-height:1.6;margin-top:6px;">'
        + _esc(an.get("executiveSummary") or "") + '</div></td></tr>'
        + storage_band
        + '<tr><td style="background:#eef1f7;padding:16px 16px 4px;">'
        '<div style="font-size:12px;font-weight:800;color:#64748b;text-transform:uppercase;'
        'letter-spacing:.6px;padding-left:6px;">Category status</div></td></tr>'
        '<tr><td style="background:#eef1f7;padding:0 10px;"><table width="100%" '
        'cellpadding="0" cellspacing="0">' + cat_grid + '</table></td></tr>'
        '<tr><td style="background:#eef1f7;padding:18px 16px 4px;">'
        '<div style="font-size:12px;font-weight:800;color:#64748b;text-transform:uppercase;'
        'letter-spacing:.6px;padding-left:6px;">Findings &amp; recommendations</div></td></tr>'
        '<tr><td style="background:#eef1f7;padding:6px 16px;"><table width="100%" '
        'cellpadding="0" cellspacing="0" style="background:#fff;border:1px solid #e5e9f2;'
        'border-radius:12px;overflow:hidden;"><tr style="background:#f8fafc;">'
        '<th align="left" style="padding:8px 10px;font-size:10.5px;color:#94a3b8;'
        'text-transform:uppercase;">Sev</th>'
        '<th align="left" style="padding:8px 10px;font-size:10.5px;color:#94a3b8;'
        'text-transform:uppercase;">Host</th>'
        '<th align="left" style="padding:8px 10px;font-size:10.5px;color:#94a3b8;'
        'text-transform:uppercase;">Metric</th>'
        '<th align="left" style="padding:8px 10px;font-size:10.5px;color:#94a3b8;'
        'text-transform:uppercase;">Detail &amp; action</th></tr>'
        + find_rows + '</table></td></tr>'
        '<tr><td style="background:#eef1f7;padding:18px 16px 4px;">'
        '<div style="font-size:12px;font-weight:800;color:#64748b;text-transform:uppercase;'
        'letter-spacing:.6px;padding-left:6px;">Metric detail (3-day window)</div></td></tr>'
        '<tr><td style="background:#eef1f7;padding:0 16px 16px;">' + data_tables + '</td></tr>'
        + watch_block
        + '<tr><td style="background:#0f172a;border-radius:0 0 16px 16px;padding:16px 24px;">'
        '<div style="font-size:11px;color:#64748b;line-height:1.6;">Automated report · '
        'Prometheus ' + _esc(payload.get("windowDays")) + '-day window · analysis by Claude '
        '· orchestrated by n8n. Thresholds are heuristic — verify critical findings before '
        'acting. Non-interactive snapshot.</div></td></tr>'
        '</table></td></tr></table></body></html>'
    )

    html = _add_incident_band(html, incident_summary)
    return subject, html
