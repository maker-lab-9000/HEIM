"""The fast-path alert poller pipeline (port of n8n PAM 11).

Polls Prometheus /api/v1/alerts, diffs firing alerts against open incidents
(pure logic in heim.incidents.poller_logic), and applies the decision:
upserts, Telegram notifications, Loki events, state emit, and investigation
dispatches.
"""
from __future__ import annotations

import json
import logging
import time

import httpx

from heim.incidents.poller_logic import diff_and_decide
from heim.incidents.state import compute_state
from heim.pipelines.investigate import dispatch_all
from heim.runtime import Runtime

log = logging.getLogger(__name__)


async def _fetch_alerts(base_url: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(f"{base_url.rstrip('/')}/api/v1/alerts")
            return r.json()
    except Exception as exc:
        log.warning("alert fetch failed: %s", exc)
        return {"status": "error", "error": str(exc)}


async def run_poll(rt: Runtime, *, dispatch_concurrently: bool = True) -> dict:
    cfg = rt.config
    t0 = time.time()
    run_at = rt.now_iso()
    resp = await _fetch_alerts(cfg.settings.prometheus.url)
    open_rows = rt.store.open_rows()
    dec = diff_and_decide(resp, open_rows, rt.now_iso(), cfg.routing(), cfg.settings.instance_host_map)

    if dec.aborted:
        log.warning("poll aborted: %s (no writes, no resolves)", dec.aborted)
        return {"aborted": dec.aborted}

    if dec.rows_to_upsert:
        rt.store.upsert(dec.rows_to_upsert)
    for n in dec.notifications:
        text = n.get("text") if isinstance(n, dict) else str(n)
        if not text and isinstance(n, dict):
            text = (f"🚨 CRITICAL alert on {n.get('host')}: {n.get('metric')}\n\n"
                    f"{str(n.get('description') or '').replace('[alert] ', '')}\n\n"
                    "(Not auto-investigable — check manually.)")
        await rt.notify(text)
    if dec.loki_events:
        await rt.emit_loki(dec.loki_events)
    if dec.state_changed:
        await rt.emit_loki([compute_state(rt.store.open_rows(), routing=cfg.routing(), trigger="alert",
                                          last_run_ms=int(time.time() * 1000))])
    if dec.dispatches:
        log.info("poller dispatching %d investigation(s)", len(dec.dispatches))
        await dispatch_all(rt, dec.dispatches, concurrent=dispatch_concurrently, trigger="poller")

    summary = {
        "upserts": len(dec.rows_to_upsert),
        "dispatches": len(dec.dispatches),
        "notifications": len(dec.notifications),
        "loki_events": len(dec.loki_events),
        "state_changed": dec.state_changed,
    }
    if any(v for v in summary.values()):
        log.info("poll result: %s", summary)
    # Record the poll only when it actually changed something — a poll runs
    # every 5 minutes and silent no-ops would drown the runs table.
    if any(summary[k] for k in ("upserts", "dispatches", "notifications", "state_changed")):
        try:
            rt.store.insert_run(
                kind="poll", run_at=run_at, overall="", model_used="",
                duration_s=round(time.time() - t0, 3),
                counts_json=json.dumps(summary, ensure_ascii=False, default=str),
            )
        except Exception:
            log.exception("persisting poll run failed")
    return summary
