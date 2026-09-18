"""Presentation helpers for the dashboard (registered as Jinja filters).

Pure functions — no I/O, no store access — so they are unit-testable and the
templates stay free of formatting logic. Every helper is tolerant of the empty
strings the store uses for "not set yet" and renders an em dash instead of
blowing up mid-page.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

#: The metrics page shows the daily email's numbers, so it humanizes them with
#: the daily email's own unit table rather than a second, subtly different one.
#: ``reports.daily_dashboard`` is pure (no I/O, no clock reads) and ``_human``
#: is written against exactly the units the aggregate rows carry — B, B/s, %,
#: °C, days, /s, ratio, state, online.
from heim.reports.daily_dashboard import _human as _human_value

DASH = "—"


# ------------------------------------------------------------------- time

def parse_dt(value: str | None) -> datetime | None:
    """Parse an ISO timestamp as written by ``Runtime.now_iso`` (tz-aware) or a
    naive ``datetime('now')`` SQLite default. Returns None for junk/empty."""
    if not value:
        return None
    text = str(value).strip().replace(" ", "T", 1)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:  # SQLite's datetime('now') is UTC
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def age_seconds(value: str | None, *, now: datetime | None = None) -> float | None:
    dt = parse_dt(value)
    if dt is None:
        return None
    now = now or datetime.now(timezone.utc)
    return (now - dt).total_seconds()


def rel_time(value: str | None, *, now: datetime | None = None) -> str:
    """"2h ago" / "just now" / "in 3m" (clock skew tolerated)."""
    secs = age_seconds(value, now=now)
    if secs is None:
        return DASH
    future = secs < 0
    secs = abs(secs)
    if secs < 45:
        return "just now" if not future else "in a moment"
    span = _coarse(secs)
    return f"in {span}" if future else f"{span} ago"


def _coarse(secs: float) -> str:
    if secs < 3600:
        return f"{int(secs // 60)}m"
    if secs < 86400:
        return f"{int(secs // 3600)}h"
    if secs < 86400 * 30:
        return f"{int(secs // 86400)}d"
    return f"{int(secs // (86400 * 30))}mo"


def iso(value: str | None) -> str:
    """Full timestamp for `title=` tooltips."""
    dt = parse_dt(value)
    return dt.isoformat(timespec="seconds") if dt else DASH


def clock(value: str | None) -> str:
    dt = parse_dt(value)
    return dt.strftime("%H:%M") if dt else DASH


def day(value: str | None) -> str:
    dt = parse_dt(value)
    return dt.strftime("%Y-%m-%d") if dt else DASH


def duration(start: str | None, end: str | None = None) -> str:
    """"4m 12s" between two stamps; blank end means "still running"."""
    a, b = parse_dt(start), parse_dt(end)
    if a is None:
        return DASH
    if b is None:
        return DASH
    return dur_s((b - a).total_seconds())


def elapsed(start: str | None) -> str:
    """Time since ``start`` — the honest "duration" of a still-running row."""
    secs = age_seconds(start)
    return dur_s(secs) if secs is not None else DASH


def dur_s(secs: float | int | None) -> str:
    if secs is None:
        return DASH
    secs = float(secs)
    if secs < 0:
        secs = 0.0
    if secs < 10:
        return f"{secs:.1f}s"
    if secs < 60:
        return f"{int(secs)}s"
    m, s = divmod(int(secs), 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m"


def dur_ms(ms: float | int | None) -> str:
    if not ms:
        return "0ms"
    ms = float(ms)
    return f"{int(ms)}ms" if ms < 1000 else dur_s(ms / 1000)


# ------------------------------------------------------------------ numbers

def tokens(n: int | float | None) -> str:
    """Humanized token count: 940 · 4.2k · 128k · 1.4M."""
    try:
        n = int(n or 0)
    except (TypeError, ValueError):
        return DASH
    if n < 1000:
        return str(n)
    if n < 10_000:
        return f"{n / 1000:.1f}k"
    if n < 1_000_000:
        return f"{round(n / 1000)}k"
    return f"{n / 1_000_000:.1f}M"


def money(amount: float | int | None, currency: str = "USD") -> str:
    """"$0.42" / "EUR 0.42" / "—" when there is nothing to show.

    Deliberately dumb: no conversion, no locale, no rounding to a currency's
    minor unit. A stored 0 means *unpriced* (the model has no entry in
    ``settings.model_prices``) and renders as an em dash — showing "$0.00"
    would claim a run was free. Sub-cent amounts keep four decimals, because
    "$0.00" for a real spend is the same lie in miniature.
    """
    try:
        value = float(amount or 0)
    except (TypeError, ValueError):
        return DASH
    if value == 0:
        return DASH
    code = str(currency or "USD").strip().upper() or "USD"
    prefix = "$" if code == "USD" else f"{code} "
    text = f"{value:.4f}" if abs(value) < 0.01 else f"{value:,.2f}"
    return prefix + text


def size(nbytes: int | float | None) -> str:
    """"2.1 KB" — result sizes in the transcript meta."""
    try:
        n = float(nbytes or 0)
    except (TypeError, ValueError):
        return DASH
    if n < 1024:
        return f"{int(n)} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


# ------------------------------------------------------------------ metrics

#: |Δ%| below this reads as flat — the row is not moving (spec §6: `▬`).
FLAT_PCT = 0.05

_NUM_RE = re.compile(r"^[-+]?[0-9][0-9.,]*")


def value(v: object, unit: object = None) -> str:
    """A metric value, humanized exactly as the daily email humanizes it."""
    return _human_value(v, unit)


def _split_unit(text: str) -> tuple[str, str]:
    """"2.90 GB" -> ("2.90", "GB"); "44.0°C" -> ("44.0", "°C")."""
    m = _NUM_RE.match(text)
    return (text[:m.end()], text[m.end():].strip()) if m else ("", text)


def trend(day3d: list | None, unit: object = None) -> str:
    """The three day averages as the spec's mono sparkline: `31.1 → 33.2 → 43.3`.

    Values are humanized like every other number on the page, then the unit is
    dropped when all of them share it — the current/avg columns right next door
    already carry it, and the column has to stay narrow. A mixed set (KB next
    to MB) keeps its units, because there the scale is the point.
    """
    vals = [v for v in (day3d or []) if v is not None]
    if not vals:
        return DASH
    parts = [value(v, unit) for v in vals]
    pairs = [_split_unit(p) for p in parts]
    if len({u for _n, u in pairs}) == 1 and all(n for n, _u in pairs):
        parts = [n for n, _u in pairs]
    return " → ".join(parts)


def delta(pct: object) -> str:
    """`▲ 12.4%` / `▼ 3.2%` / `▬` (flat) / `—` (no comparable value)."""
    if pct is None:
        return DASH
    try:
        n = float(pct)
    except (TypeError, ValueError):
        return DASH
    if abs(n) < FLAT_PCT:
        return "▬"
    return f"{'▲' if n > 0 else '▼'} {abs(n):.1f}%"


def fingerprint(fp: str | None, width: int = 34) -> str:
    """Middle-truncate a fingerprint (`host|qid|name`) keeping both ends."""
    text = (fp or "").strip()
    if not text:
        return DASH
    if len(text) <= width:
        return text
    keep = width - 1
    head = (keep + 1) // 2
    tail = keep - head
    return text[:head] + "…" + (text[-tail:] if tail else "")


# -------------------------------------------------------------- transcript

#: args key that carries the human-readable command per tool, in priority order
_COMMAND_KEYS = {
    "ssh_diagnostic": ("command",),
    "prometheus_query": ("promql", "query"),
    "ha_api": ("path",),
    "proxmox_api": ("path",),
    "discover_metrics": ("pattern",),
}


def command_of(step: dict) -> str:
    """The `$ …` line for a transcript entry.

    Per-tool the interesting argument differs (a shell command, a PromQL
    expression, an API path, a metric pattern); anything unknown falls back to
    the raw args JSON so nothing is ever silently hidden.
    """
    raw = (step or {}).get("args_json") or ""
    try:
        args = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        return str(raw).strip()
    if not isinstance(args, dict):
        return str(raw).strip()
    for key in _COMMAND_KEYS.get(str(step.get("tool") or ""), ()):
        val = args.get(key)
        if val:
            return str(val).strip()
    for key in ("command", "promql", "query", "path", "pattern"):
        if args.get(key):
            return str(args[key]).strip()
    return json.dumps(args, separators=(", ", ": ")) if args else DASH


#: tool name -> the CSS variable suffix of its badge color (spec §1)
_TOOL_KEY = {
    "ssh_diagnostic": "ssh",
    "prometheus_query": "prometheus",
    "ha_api": "ha",
    "discover_metrics": "discover",
    "proxmox_api": "proxmox",
}


def tool_key(tool: str | None) -> str:
    return _TOOL_KEY.get(str(tool or ""), "other")


#: how much of a model id a narrow column can carry
MODEL_WIDTH = 22


def short_model(name: str | None) -> str:
    """A model id trimmed to fit a table cell, without lying about which one.

    Drops the vendor prefix and any ``:free``/``:beta`` variant suffix — the
    parts that repeat down a column — and middle-truncates whatever is still
    too long, keeping both ends so ``…-4-6`` and ``…-4-5`` stay distinct.
    """
    text = str(name or "").strip()
    if not text:
        return DASH
    text = text.rsplit("/", 1)[-1].split(":", 1)[0]
    if len(text) <= MODEL_WIDTH:
        return text
    head = (MODEL_WIDTH - 1 + 1) // 2
    tail = MODEL_WIDTH - 1 - head
    return text[:head] + "…" + (text[-tail:] if tail else "")


# ----------------------------------------------------------------- hosts

#: How many hosts can carry a color. The host badges reuse the SAME validated
#: categorical palette as the tool badges (spec §1) — aliased in the stylesheet
#: as ``--host-1..--host-5`` — so there are exactly five slots. A sixth host, or
#: any host that is not configured (a Proxmox guest showing up under its own
#: name), renders with the muted ink instead of a recycled, misleading color.
HOST_SLOTS = 5

#: what an unslotted host gets: dot in faint ink, name still spelled out
HOST_MUTED = "--ink-3"


def host_color(host: str | None, hosts=()) -> str:
    """The CSS variable name for ``host``'s badge dot.

    Slots are handed out in *config order* so a host keeps the same color on
    every page for as long as the config is stable — color follows the entity,
    exactly like the tool badges. The color is never the only encoding: the
    badge always prints the host name next to the dot.
    """
    name = str(host or "").strip()
    order = [str(h) for h in (hosts or [])]
    if not name or name not in order:
        return HOST_MUTED
    slot = order.index(name)
    return f"--host-{slot + 1}" if slot < HOST_SLOTS else HOST_MUTED


# -------------------------------------------------------------- transcript


#: what the burn line is measuring, spelled out in the caption and tooltips
BURN_TOKENS = "input tokens"
BURN_BYTES = "tool output"


def burn_segments(steps: list[dict]) -> list[dict]:
    """Segment widths for the burn line.

    Since §5.6 the runner attributes each assistant turn's usage to the first
    tool call that turn requested, so the spec's "where did the budget go" bar
    can be drawn from **real input tokens** whenever the steps carry them.
    Rows written before that (or by a provider that reported no usage) have
    only ``result_bytes``, so they keep the original proxy — a step's share of
    total tool output, which is what gets fed back into the model's context —
    under its own, different, honest label. The caption and every tooltip name
    whichever basis was used; the two are never mixed in one bar.
    """
    steps = [s for s in (steps or [])]
    priced = any(int(s.get("input_tokens") or 0) > 0 for s in steps)
    basis = BURN_TOKENS if priced else BURN_BYTES
    key = "input_tokens" if priced else "result_bytes"
    total = sum(max(int(s.get(key) or 0), 0) for s in steps)
    out: list[dict] = []
    for s in steps:
        n = max(int(s.get(key) or 0), 0)
        pct = (n / total * 100) if total else (100 / len(steps) if steps else 0)
        amount = f"{tokens(n)} tok" if priced else size(n)
        share = f"{pct:.0f}% of {basis}" if priced else f"{pct:.0f}% share of {basis}"
        out.append({
            "seq": int(s.get("seq") or 0),
            "tool": s.get("tool") or "",
            "tool_key": tool_key(s.get("tool")),
            "blocked": bool(s.get("blocked")),
            "pct": round(pct, 3),
            "basis": basis,
            "title": (f"{int(s.get('seq') or 0):02d} {s.get('tool') or ''} · "
                      f"{amount} · {share}"),
        })
    return out


# ------------------------------------------------------------------ statuses

#: status -> (icon, css class, label) — meaning is never carried by color alone
_STATUS = {
    "running": ("●", "st-running", "running"),
    "pending_approval": ("◷", "st-warn", "pending approval"),
    "complete": ("✓", "st-ok", "complete"),
    "resolved": ("✓", "st-ok", "resolved"),
    "incomplete": ("⚠", "st-serious", "incomplete"),
    "needs_human": ("⚠", "st-serious", "needs human"),
    "failed": ("✕", "st-crit", "failed"),
    "declined": ("○", "st-muted", "declined"),
    "open": ("●", "st-crit", "open"),
    "clearing": ("◐", "st-warn", "clearing"),
    "suppressed": ("◌", "st-muted", "suppressed"),
    "queued": ("◌", "st-muted", "queued"),
    "critical": ("✕", "st-crit", "critical"),
    "warning": ("⚠", "st-warn", "warning"),
    "warn": ("⚠", "st-warn", "warning"),
    "info": ("·", "st-muted", "info"),
    "ok": ("✓", "st-ok", "ok"),
    "healthy": ("✓", "st-ok", "healthy"),
    # metric flags (spec §6): `crit` is the aggregate's own word for a breached
    # threshold — a reading, not a failed run, hence ✳ rather than ✕.
    "crit": ("✳", "st-crit", "crit"),
    "na": ("·", "st-muted", "n/a"),
    "timeout": ("◌", "st-muted", "timed out"),
}


def status_pill(value: str | None) -> dict:
    key = str(value or "").strip().lower()
    icon, cls, label = _STATUS.get(key, ("·", "st-muted", key or "unknown"))
    return {"icon": icon, "cls": cls, "label": label, "key": key}
