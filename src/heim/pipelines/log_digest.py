"""The daily Loki error digest (2026-11-13): fetch, summarise, email.

Reads each source in ``config/log_digest.yaml`` over the last
``lookback_hours`` (GET-only Loki query API), hands the lines to the pure
``reports.log_digest`` and emails the result, every day, clean or not, so a
missing email means a broken job. A source that cannot be read makes the
digest *incomplete* and says so; only when every source fails does the run
raise (the daemon then sends one Telegram line).
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import httpx

from heim.reports.log_digest import load_digest_cfg, render_email, summarise
from heim.runtime import Runtime

log = logging.getLogger(__name__)

#: lines read per source; Loki's own default ceiling is 5000
FETCH_LIMIT = 5000


def _ns(d: datetime) -> str:
    return str(int(d.timestamp()) * 1_000_000_000)


async def run_log_digest(rt: Runtime, now: datetime | None = None) -> dict:
    loki = rt.config.settings.loki
    if loki is None:
        raise RuntimeError("Loki is not configured (settings.loki)")
    cfg = load_digest_cfg(rt.config.root / "log_digest.yaml")
    end = now or datetime.now(timezone.utc)
    start = end - timedelta(hours=cfg.lookback_hours)
    base = loki.url.rstrip("/")

    results: dict[str, list[dict]] = {}
    failed: dict[str, str] = {}
    truncated: list[str] = []
    async with httpx.AsyncClient(timeout=60) as client:
        for src in cfg.sources:
            params = {"query": src.logql, "start": _ns(start), "end": _ns(end),
                      "limit": str(FETCH_LIMIT), "direction": "backward"}
            try:
                r = await client.get(base + "/loki/api/v1/query_range", params=params)
                r.raise_for_status()
                streams = (r.json().get("data") or {}).get("result") or []
            except Exception as exc:
                log.warning("log digest: source %s failed: %s", src.name, exc)
                failed[src.name] = f"{type(exc).__name__}: {exc}"[:300]
                continue
            results[src.name] = streams
            if sum(len(s.get("values") or []) for s in streams) >= FETCH_LIMIT:
                truncated.append(src.name)

    if len(failed) == len(cfg.sources):
        raise RuntimeError("every source failed: " + "; ".join(f"{k}: {v}" for k, v in failed.items()))

    digest = summarise(results, cfg, truncated=truncated, failed=failed)
    subject, html = render_email(digest, start, end, rt.config.settings.timezone)
    path = await rt.send_email(subject, html)
    return {"groups": len(digest.groups), "lines": digest.lines,
            "ignored": sum(digest.ignored.values()), "failed": failed,
            "truncated": truncated, "subject": subject, "email": str(path) if path else None}
