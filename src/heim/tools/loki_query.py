"""Read-only LogQL tool over the homelab Loki (journal + container logs).

Two query shapes, told apart by the LogQL itself:

- a **log query** (``{selector} |= "…"``) returns lines from
  ``[end - lookback, end]``, newest first. Lines that repeat — the same
  message with only numbers, ids or timestamps changed — collapse into one
  entry with a count and first/last time, so 300 copies of one error cost
  one line of context, not 300.
- a **metric query** (``sum by (unit) (count_over_time({…}[1h]))``) is
  evaluated at ``end`` (instant) or, with ``step``, over the window; the
  answer has the same shape as the Prometheus tool's.

Loki's query API is GET-only, so the tool cannot change anything; the URL is
``settings.loki.url`` — the instance HEIM already pushes its own events to.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import httpx

from heim.metrics.promql import compact_result
from heim.tools.base import Tool

DEFAULT_LOOKBACK = "1h"
MAX_LOOKBACK = timedelta(days=7)
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
#: raw lines fetched per distinct line wanted: repeats collapse, so fetch more
RAW_FACTOR = 5
LINE_CHARS = 300

_DURATION = re.compile(r"^(\d+)\s*([mhd])$")
#: what varies between repeats of "the same" line: timestamps, hex ids, long
#: numbers (pids, ports, sizes) and decimals (durations). NOT kept variable, so
#: never merged: IPv4 addresses (logins from two addresses are two events) and
#: numbers under 4 digits (HTTP 200 vs 500, exit codes, md0 vs md1).
_VARIABLE = re.compile(
    r"(?P<ip>\b\d{1,3}(?:\.\d{1,3}){3}\b)"
    r"|\d{4}-\d\d-\d\d[T ][\d:.,]+Z?|\b[0-9a-f]{12,}\b|\b0x[0-9a-f]+\b|\d+\.\d+|\d{4,}", re.I)


#: terminal colour codes (HA core writes "\x1b[31m… \x1b[0m"; some shippers drop the ESC)
_ANSI = re.compile(r"\x1b?\[[0-9;]{1,8}m")


def _shape(text: str) -> str:
    return _VARIABLE.sub(lambda m: m.group("ip") or "#", text)


EMPTY_HINT = (
    "No lines matched. Before concluding 'nothing happened': (1) ubuntu-server docker logs carry NO "
    "level label — filter their text with |~ \"(?i)error|fatal|panic|exception\" instead "
    "of level=; (2) journal and docker collection started on 2026-10-08, so earlier "
    "windows are empty by construction; (3) list what exists with a metric query, e.g. "
    "sum by (unit) (count_over_time({job=\"systemd-journal\", host=\"homelab\"}[1h]))."
)
LIMIT_HINT = (
    "Line limit reached: only the newest lines are shown. Narrow with a line filter "
    "(|= / |~), a tighter selector or a shorter lookback — or count instead with "
    "sum by (…) (count_over_time({…}[<window>]))."
)


def parse_lookback(text: str) -> timedelta:
    m = _DURATION.match((text or DEFAULT_LOOKBACK).strip().lower())
    if not m:
        raise ValueError(f"lookback {text!r} is not like 15m, 6h or 2d")
    n, unit = int(m.group(1)), m.group(2)
    delta = {"m": timedelta(minutes=n), "h": timedelta(hours=n), "d": timedelta(days=n)}[unit]
    if delta <= timedelta(0) or delta > MAX_LOOKBACK:
        raise ValueError(f"lookback {text!r} must be between 1m and 7d")
    return delta


def parse_end(text: str, now: datetime) -> datetime:
    if not (text or "").strip():
        return now
    end = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    return end if end.tzinfo else end.replace(tzinfo=timezone.utc)


def is_metric_query(logql: str) -> bool:
    """A log query starts with its stream selector; anything else
    (``sum(…)``, ``rate(…)``, ``count_over_time(…)``) is a metric query."""
    return not logql.lstrip().startswith("{")


def _iso(ns: str | int) -> str:
    return datetime.fromtimestamp(int(ns) / 1e9, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _source(stream: dict) -> str:
    """``host/unit [level]`` or ``host/container (stderr)`` — who said it."""
    who = stream.get("container_name") or stream.get("unit") or stream.get("job") or "?"
    tag = f"{stream.get('host') or stream.get('hostname') or '?'}/{who}"
    if stream.get("level"):
        tag += f" [{stream['level']}]"
    elif stream.get("source") == "stderr":
        tag += " (stderr)"
    return tag


def compact_streams(result: list[dict], limit: int) -> tuple[list[str], int]:
    """Loki ``streams`` → newest-first display lines, repeats collapsed.

    Returns ``(lines, raw_count)``. A collapsed entry reads
    ``×N first→last  source  message`` with the newest example's text.
    """
    entries = [(int(ts), _source(s.get("stream") or {}), line)
               for s in result for ts, line in (s.get("values") or [])]
    entries.sort(key=lambda e: e[0], reverse=True)
    groups: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    seen: set[tuple[int, str]] = set()
    for ts, src, line in entries:
        text = " ".join(_ANSI.sub("", line).split())
        if (ts, text) in seen:   # the same line shipped twice (two pipelines, two label sets)
            continue
        seen.add((ts, text))
        key = (src, _shape(text))
        g = groups.get(key)
        if g is None:
            if len(order) >= limit:
                continue
            groups[key] = {"n": 1, "last": ts, "first": ts, "src": src, "text": text}
            order.append(key)
        else:
            g["n"] += 1
            g["first"] = ts
    lines = []
    for key in order:
        g = groups[key]
        text = g["text"] if len(g["text"]) <= LINE_CHARS else g["text"][:LINE_CHARS] + "…"
        when = _iso(g["last"]) if g["n"] == 1 else f"×{g['n']} {_iso(g['first'])}→{_iso(g['last'])}"
        lines.append(f"{when}  {g['src']}  {text}")
    return lines, len(seen)


class LokiQueryTool(Tool):
    async def run(self, args: dict) -> str:
        logql = str(args.get("logql") or "").strip()
        if not logql:
            return json.dumps({"ok": False, "error": "no logql provided"})
        loki = self.ctx.config.settings.loki
        if loki is None:
            return json.dumps({"ok": False, "error": "Loki is not configured (settings.loki) — logs unavailable; "
                                                      "do not retry, use the other tools"})
        try:
            span = parse_lookback(str(args.get("lookback") or ""))
            end = parse_end(str(args.get("end") or ""), datetime.now(timezone.utc))
            limit = max(1, min(int(args.get("limit") or DEFAULT_LIMIT), MAX_LIMIT))
        except (TypeError, ValueError) as exc:
            return json.dumps({"ok": False, "error": str(exc)})
        start = end - span
        step = str(args.get("step") or "").strip()
        base = loki.url.rstrip("/")
        metric = is_metric_query(logql)
        ns = lambda d: str(int(d.timestamp() * 1e9))  # noqa: E731

        if metric and not step:
            path, params = "/loki/api/v1/query", {"query": logql, "time": ns(end)}
        else:
            path = "/loki/api/v1/query_range"
            params = {"query": logql, "start": ns(start), "end": ns(end)}
            if metric:
                params["step"] = step
            else:
                params.update(direction="backward", limit=str(min(limit * RAW_FACTOR, 1000)))
        async with httpx.AsyncClient(timeout=45) as client:
            r = await client.get(base + path, params=params)

        window = {"start": start.strftime("%Y-%m-%dT%H:%M:%SZ"), "end": end.strftime("%Y-%m-%dT%H:%M:%SZ")}
        if r.status_code >= 400:
            # Loki explains a bad query in plain text ("parse error at line 1, col 7: …")
            out = {"ok": False, "status": r.status_code, "logql": logql, "error": r.text.strip()[:500],
                   "hint": "Fix the LogQL and retry once. A selector needs at least one label matcher "
                           "in {…}; line filters (|= |~ != !~) come after it; a metric query wraps a "
                           "log query with a range, e.g. count_over_time({…} |= \"x\" [1h])."}
            await self.ctx.emit(f"🪵 loki: {logql[:180]}\n→ HTTP {r.status_code}")
            self.ctx.record({"tool": self.name, "logql": logql, "status": r.status_code})
            return json.dumps(out)

        data = r.json()
        if metric:
            out = compact_result(data, logql)
            out["mode"] = "metric-range" if step else "metric-instant"
            out["window"] = window
            n = out.get("count", "?")
        else:
            lines, raw = compact_streams((data.get("data") or {}).get("result") or [], limit)
            out = {"ok": True, "logql": logql, "mode": "lines", "window": window,
                   "rawLines": raw, "shown": len(lines), "lines": lines}
            if not lines:
                out["hint"] = EMPTY_HINT
                if 'host="home-assistant"' in logql.replace(" ", ""):
                    out["hint"] = ('Loki labels this host host="homeassistant" (no hyphen) — HEIM\'s '
                                   '"home-assistant" only appears on HEIM\'s own events. ' + EMPTY_HINT)
            elif raw >= int(params["limit"]):
                out["hint"] = LIMIT_HINT
            n = f"{raw} lines → {len(lines)} distinct"
        clip = int(self.cfg.options.get("clip_bytes", 12000))
        text = json.dumps(out, ensure_ascii=False)
        while len(text) > clip and out.get("lines"):
            out["lines"] = out["lines"][:-1]   # drop the OLDEST shown entries first
            out["shown"] = len(out["lines"])
            out["hint"] = LIMIT_HINT
            text = json.dumps(out, ensure_ascii=False)
        await self.ctx.emit(f"🪵 loki ({out['mode']}, {args.get('lookback') or DEFAULT_LOOKBACK}): {logql[:180]}\n→ {n}")
        self.ctx.record({"tool": self.name, "logql": logql, "mode": out["mode"],
                         "lookback": str(args.get("lookback") or DEFAULT_LOOKBACK)})
        return text
