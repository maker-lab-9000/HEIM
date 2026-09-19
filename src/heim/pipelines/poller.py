"""The fast-path poll cycle (port of n8n PAM 11, plus threshold detection).

Two independent halves ride the same 5-minute cadence:

1. the **alert** half — polls Prometheus ``/api/v1/alerts``, diffs firing
   alerts against open incidents (pure logic in ``heim.incidents.poller_logic``)
   and applies the decision: upserts, Telegram notifications, Loki events,
   state emit, and investigation dispatches;
2. the **threshold** half — evaluates the metric catalog's own ``warn``/``crit``
   bounds (pure logic in ``heim.pipelines.thresholds``) so a metric sitting at
   crit can open an incident on its own, which until now only an
   ``alerts.yml`` rule or the daily LLM could do.

They share everything downstream — the store, ``rt.notify``, Loki, the
suppression filters and ``dispatch_all`` — so the approval gate, the
concurrency cap and the false-positive mutes apply to both unchanged. They are
deliberately *independent*: a failure in one half never aborts the other, and
the summary carries both sets of counters.
"""
from __future__ import annotations

import json
import logging
import time

import httpx

from heim.incidents.poller_logic import diff_and_decide
from heim.incidents.state import compute_state
from heim.metrics.queries import load_queries
from heim.pipelines import thresholds
from heim.pipelines.investigate import dispatch_all
from heim.pipelines.suppression import filter_decision, filter_threshold
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


async def _run_alerts(rt: Runtime, run_at: str, *, dispatch_concurrently: bool) -> dict:
    """The alert half. Returns its counters (or ``{"aborted": ...}``)."""
    cfg = rt.config
    resp = await _fetch_alerts(cfg.settings.prometheus.url)
    open_rows = rt.store.open_rows()
    dec = diff_and_decide(resp, open_rows, rt.now_iso(), cfg.routing(),
                          cfg.settings.instance_host_map)

    if dec.aborted:
        log.warning("poll aborted: %s (no writes, no resolves)", dec.aborted)
        return {"aborted": dec.aborted}

    # Muted fingerprints (§5.4) are dropped from everything the poller would
    # do with them — the golden diff logic above stays untouched.
    try:
        dec, dropped = filter_decision(dec, rt.store.active_suppressions(run_at))
        if dropped:
            log.info("suppression: poller dropped %s", dropped)
    except Exception:
        log.exception("applying suppressions failed — running unfiltered")

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

    return {
        "upserts": len(dec.rows_to_upsert),
        "dispatches": len(dec.dispatches),
        "notifications": len(dec.notifications),
        "loki_events": len(dec.loki_events),
        "state_changed": dec.state_changed,
    }


async def _run_thresholds(rt: Runtime, run_at: str, *,
                          dispatch_concurrently: bool) -> dict:
    """The threshold half. Returns its ``threshold_*`` counters."""
    cfg = rt.config
    qdefs = load_queries(cfg.queries_path)
    results = await thresholds.fetch_instants(cfg.settings.prometheus.url, qdefs)
    samples = thresholds.build_samples(results, cfg.settings.instance_host_map)
    if not samples:
        # Every instant query failed: Prometheus is unreachable, which is not
        # "everything is under threshold". Do nothing — above all, no resolves.
        log.warning("threshold detection: no usable samples (no writes, no resolves)")
        return {"threshold_samples": 0, "threshold_upserts": 0,
                "threshold_dispatches": 0, "threshold_notifications": 0,
                "threshold_streaks": 0, "threshold_state_changed": False}

    suppressed = set()
    try:
        suppressed = rt.store.active_suppressions(run_at)
    except Exception:
        log.exception("reading suppressions failed — running unfiltered")

    tcfg = thresholds.ThresholdConfig.from_settings(cfg.settings, suppressed)
    dec = thresholds.decide(samples, rt.store.open_rows(),
                            rt.store.threshold_streaks(), rt.now_iso(),
                            cfg.routing(), tcfg)
    dec, dropped = filter_threshold(dec, suppressed)
    if dropped:
        log.info("suppression: threshold detection dropped %s", dropped)

    # Hysteresis state first: if anything below blows up, a streak that was
    # already counted must not be counted twice on the next poll.
    rt.store.save_threshold_streaks(dec.streak_writes)
    rt.store.clear_threshold_streaks(dec.streak_clears)

    if dec.rows_to_upsert:
        rt.store.upsert(dec.rows_to_upsert)
    for n in dec.notifications:
        await rt.notify(
            f"🚨 CRITICAL metric on {n.get('host')}: {n.get('metric')}\n\n"
            f"{str(n.get('description') or '').replace(thresholds.PREFIX, '')}\n\n"
            "(Not auto-investigable — check manually.)")
    if dec.loki_events:
        await rt.emit_loki(dec.loki_events)
    if dec.state_changed:
        await rt.emit_loki([compute_state(rt.store.open_rows(), routing=cfg.routing(),
                                          trigger="threshold",
                                          last_run_ms=int(time.time() * 1000))])
    if dec.dispatches:
        log.info("threshold detection dispatching %d investigation(s): %s",
                 len(dec.dispatches),
                 ", ".join(str(d.get("fingerprint")) for d in dec.dispatches))
        await dispatch_all(rt, dec.dispatches, concurrent=dispatch_concurrently,
                           trigger="threshold")

    return {
        "threshold_samples": len(samples),
        "threshold_upserts": len(dec.rows_to_upsert),
        "threshold_dispatches": len(dec.dispatches),
        "threshold_notifications": len(dec.notifications),
        "threshold_streaks": len(dec.streak_writes),
        "threshold_state_changed": dec.state_changed,
    }


#: Summary keys that mean "this cycle actually did something" — the ones that
#: decide whether the poll is worth a row in ``runs``.
_RECORDABLE = ("upserts", "dispatches", "notifications", "state_changed",
               "threshold_upserts", "threshold_dispatches",
               "threshold_notifications", "threshold_state_changed")


async def run_poll(rt: Runtime, *, dispatch_concurrently: bool = True) -> dict:
    cfg = rt.config
    t0 = time.time()
    run_at = rt.now_iso()

    summary: dict = {}
    try:
        summary.update(await _run_alerts(
            rt, run_at, dispatch_concurrently=dispatch_concurrently))
    except Exception:
        # One half must never take the other down with it.
        log.exception("the alert half of the poll failed")
        summary["aborted"] = "alert half failed"

    if cfg.settings.threshold_detection:
        try:
            summary.update(await _run_thresholds(
                rt, run_at, dispatch_concurrently=dispatch_concurrently))
        except Exception:
            log.exception("the threshold half of the poll failed")

    if any(v for v in summary.values()):
        log.info("poll result: %s", summary)
    # Record the poll only when it actually changed something — a poll runs
    # every 5 minutes and silent no-ops would drown the runs table.
    if any(summary.get(k) for k in _RECORDABLE):
        try:
            rt.store.insert_run(
                kind="poll", run_at=run_at, overall="", model_used="",
                duration_s=round(time.time() - t0, 3),
                counts_json=json.dumps(summary, ensure_ascii=False, default=str),
            )
        except Exception:
            log.exception("persisting poll run failed")
    return summary
