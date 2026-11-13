"""The daily Loki error digest: group, drop the expected noise, render.

Pure: the pipeline (``pipelines/log_digest.py``) fetches the lines and hands
them here as Loki ``streams`` results, one list per configured source.

Repeats collapse the way the ``loki_query`` tool collapses them (same host,
same unit or container, same text once numbers, ids and timestamps are masked),
so 300 copies of one error are one row with a count. Ignore rules come from
``config/log_digest.yaml``; what they dropped is counted in the email, never
silently gone.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml

from heim.tools.loki_query import _ANSI, _shape

LINE_CHARS = 400
MAX_GROUPS = 60


@dataclass(frozen=True)
class Source:
    name: str
    logql: str


@dataclass(frozen=True)
class IgnoreRule:
    pattern: str
    why: str = ""
    regex: re.Pattern = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        try:
            object.__setattr__(self, "regex", re.compile(self.pattern))
        except re.error as exc:
            raise ValueError(f"ignore pattern {self.pattern!r} is not a valid regex: {exc}") from exc


@dataclass(frozen=True)
class DigestCfg:
    lookback_hours: int
    sources: tuple[Source, ...]
    ignore: tuple[IgnoreRule, ...] = ()
    max_groups: int = MAX_GROUPS


def load_digest_cfg(path: Path) -> DigestCfg:
    raw = yaml.safe_load(Path(path).read_text()) or {}
    sources = tuple(Source(str(s["name"]), str(s["logql"])) for s in raw.get("sources") or [])
    if not sources:
        raise ValueError(f"{path}: no sources")
    for s in sources:
        if not s.logql.lstrip().startswith("{"):
            raise ValueError(f"{path}: source {s.name!r} must be a log query starting with {{…}}")
    ignore = tuple(IgnoreRule(str(r["pattern"]), str(r.get("why") or ""))
                   for r in raw.get("ignore") or [])
    hours = int(raw.get("lookback_hours", 24))
    if not 1 <= hours <= 168:
        raise ValueError(f"{path}: lookback_hours must be 1..168")
    return DigestCfg(hours, sources, ignore, int(raw.get("max_groups", MAX_GROUPS)))


@dataclass
class Group:
    host: str
    who: str
    count: int
    first_ns: int
    last_ns: int
    text: str


@dataclass
class Digest:
    groups: list[Group]
    lines: int
    ignored: dict[str, int]
    rules: tuple[IgnoreRule, ...] = ()
    truncated: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)
    max_groups: int = MAX_GROUPS

    @property
    def complete(self) -> bool:
        return not self.truncated and not self.failed


def _who(labels: dict) -> str:
    return labels.get("container_name") or labels.get("unit") or labels.get("job") or "?"


def summarise(results: dict[str, list[dict]], cfg: DigestCfg, truncated=(),
              failed: dict[str, str] | None = None) -> Digest:
    """Loki streams per source → groups, newest example kept, most frequent first."""
    groups: dict[tuple[str, str, str], Group] = {}
    ignored: dict[str, int] = {}
    seen: set[tuple[str, int, str]] = set()
    for streams in results.values():
        for s in streams:
            labels = s.get("stream") or {}
            host = labels.get("host") or labels.get("hostname") or "?"
            who = _who(labels)
            for ts, line in s.get("values") or []:
                ts = int(ts)
                text = " ".join(_ANSI.sub("", line).split())
                if (host, ts, text) in seen:   # the same line through two sources
                    continue
                seen.add((host, ts, text))
                rule = next((r for r in cfg.ignore if r.regex.search(text)), None)
                if rule is not None:
                    ignored[rule.pattern] = ignored.get(rule.pattern, 0) + 1
                    continue
                key = (host, who, _shape(text))
                g = groups.get(key)
                if g is None:
                    groups[key] = Group(host, who, 1, ts, ts, text)
                    continue
                g.count += 1
                if ts < g.first_ns:
                    g.first_ns = ts
                if ts > g.last_ns:
                    g.last_ns, g.text = ts, text
    ordered = sorted(groups.values(), key=lambda g: (-g.count, -g.last_ns))
    return Digest(ordered, sum(g.count for g in ordered), ignored, cfg.ignore,
                  list(truncated), dict(failed or {}), cfg.max_groups)


# ------------------------------------------------------------------ rendering

_INK, _INK3, _LINE, _CRIT = "#1f2328", "#6b6f76", "#e3e1dc", "#b3261e"


def _clock(ns: int, tz: ZoneInfo) -> str:
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).astimezone(tz).strftime("%m-%d %H:%M")


def subject_of(d: Digest, day: str) -> str:
    if not d.groups:
        head = "no errors"
    else:
        kinds = len(d.groups)
        head = f"{kinds} kind{'' if kinds == 1 else 's'} of error, {d.lines} line{'' if d.lines == 1 else 's'}"
    tail = " (incomplete)" if not d.complete else ""
    return f"HEIM logs · {head}{tail} · {day}"


def render_email(d: Digest, start: datetime, end: datetime, tz_name: str) -> tuple[str, str]:
    tz = ZoneInfo(tz_name)
    day = end.astimezone(tz).strftime("%Y-%m-%d")
    window = f"{start.astimezone(tz):%m-%d %H:%M} → {end.astimezone(tz):%m-%d %H:%M} ({tz_name})"
    base = f"padding:6px 8px;border-top:1px solid {_LINE};vertical-align:top"
    td = f'style="{base}"'
    td3 = f'style="{base};color:{_INK3}"'
    parts = [f'<div style="font-family:-apple-system,Segoe UI,sans-serif;color:{_INK};max-width:960px">',
             '<h2 style="margin:0 0 4px">Loki error digest</h2>',
             f'<p style="margin:0 0 16px;color:{_INK3}">{escape(window)}</p>']

    if not d.complete:
        items = [f"<li><b>{escape(n)}</b>: {escape(e)}</li>" for n, e in d.failed.items()]
        items += [f"<li><b>{escape(n)}</b>: line limit reached, only the newest lines were read</li>"
                  for n in d.truncated]
        parts.append(f'<p style="color:{_CRIT};margin:0 0 4px"><b>Incomplete.</b> '
                     f'Some sources could not be read in full:</p><ul>{"".join(items)}</ul>')

    if d.groups:
        shown = d.groups[:d.max_groups]
        rows = []
        for g in shown:
            when = _clock(g.last_ns, tz) if g.count == 1 else \
                f"{_clock(g.first_ns, tz)} → {_clock(g.last_ns, tz)}"
            text = g.text if len(g.text) <= LINE_CHARS else g.text[:LINE_CHARS] + "…"
            rows.append(
                f'<tr class="grp"><td {td}><b>{escape(g.host)}</b><br>'
                f'<span style="color:{_INK3}">{escape(g.who)}</span></td>'
                f'<td {td} align="right">×{g.count}</td>'
                f'<td style="{base};white-space:nowrap;color:{_INK3}">{escape(when)}</td>'
                f'<td {td}><code style="font-size:12px;word-break:break-word">{escape(text)}</code></td></tr>')
        parts.append('<table style="border-collapse:collapse;width:100%;font-size:13px">'
                     '<tr><th align="left">host · source</th><th align="right">count</th>'
                     '<th align="left">when</th><th align="left">latest line</th></tr>'
                     + "".join(rows) + "</table>")
        if len(d.groups) > len(shown):
            rest = d.groups[len(shown):]
            parts.append(f'<p style="color:{_INK3}">{len(rest)} more kinds '
                         f'({sum(g.count for g in rest)} lines) not shown.</p>')
    elif d.complete:
        parts.append("<p>No error lines in this window.</p>")

    if d.rules:
        why = {r.pattern: r.why for r in d.rules}
        rows = "".join(
            f'<tr><td {td}><code>{escape(r.pattern)}</code></td>'
            f'<td {td} align="right">{d.ignored.get(r.pattern, 0)}</td>'
            f'<td {td3}>{escape(why[r.pattern])}</td></tr>' for r in d.rules)
        parts.append(f'<h3 style="margin:24px 0 4px;font-size:14px">Ignored as expected</h3>'
                     f'<table style="border-collapse:collapse;font-size:12px">'
                     f'<tr><th align="left">pattern</th><th align="right">lines</th>'
                     f'<th align="left">why</th></tr>{rows}</table>'
                     f'<p style="color:{_INK3};font-size:12px">Edit config/log_digest.yaml to change these.</p>')
    parts.append("</div>")
    return subject_of(d, day), "".join(parts)
