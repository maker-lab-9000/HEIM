"""Long-running daemon: cron-scheduled daily runs + interval alert poller.

Replaces the two n8n schedule triggers. Investigations dispatched from either
pipeline run as fire-and-forget asyncio tasks (the n8n `waitForSubWorkflow:
false` equivalent), so a pending Telegram approval never blocks the next poll
or report.

A third task drains the ``jobs`` queue (roadmap §5.2): the dashboard and the
CLI only *insert* rows, the daemon stays the sole executor. On startup any job
or investigation left mid-flight by a crash is swept to
interrupted/failed, so the tables never lie about what is running.
"""
from __future__ import annotations

import asyncio
import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from heim.pipelines.daily import run_daily
from heim.pipelines.investigate import run_investigation
from heim.pipelines.poller import run_poll
from heim.pipelines.queue import request_from_payload
from heim.runtime import Runtime, build_runtime

log = logging.getLogger(__name__)

#: How often an idle queue worker re-checks for work.
QUEUE_POLL_SECONDS = 4.0


async def _daily_job(rt: Runtime) -> None:
    try:
        result = await run_daily(rt, dispatch_concurrently=True)
        log.info("daily run complete: %s", result)
    except Exception as exc:
        log.exception("daily run failed")
        await rt.notify(f"🔴 HEIM daily run FAILED: {type(exc).__name__}: {exc}")


async def _poll_job(rt: Runtime) -> None:
    try:
        await run_poll(rt, dispatch_concurrently=True)
    except Exception:
        log.exception("alert poll failed")  # next poll retries in a few minutes


async def run_job(rt: Runtime, job: dict) -> None:
    """Execute one claimed job and close it out (never raises)."""
    job_id = int(job.get("id") or 0)
    kind = str(job.get("kind") or "investigate")
    if kind != "investigate":
        log.warning("job #%d: unknown kind %r — marking failed", job_id, kind)
        rt.store.finish_job(job_id, "failed", error=f"unknown job kind: {kind}")
        return

    retry_of = int(job.get("retry_of") or 0)
    requested_by = str(job.get("requested_by") or "")
    trigger = "dashboard" if requested_by == "dashboard" else "manual"
    seen: dict[str, int] = {}
    try:
        req = request_from_payload(job.get("payload") or {}, rt, retry_of=retry_of)
        log.info("job #%d: investigating %s (%s%s)", job_id, req.host, trigger,
                 f", retry of #{retry_of}" if retry_of else "")
        await run_investigation(rt, req, trigger=trigger,
                                on_start=lambda inv_id: seen.__setitem__("id", inv_id))
    except Exception as exc:
        log.exception("job #%d failed", job_id)
        rt.store.finish_job(job_id, "failed", investigation_id=seen.get("id", 0),
                            error=f"{type(exc).__name__}: {exc}")
        return

    inv_id = seen.get("id", 0)
    row = rt.store.investigation(inv_id) if inv_id else None
    # The investigation itself records declined/needs_human/complete; only a
    # crashed run makes the *job* a failure.
    if row is not None and row.get("status") == "failed":
        rt.store.finish_job(job_id, "failed", investigation_id=inv_id,
                            error=str(row.get("incomplete_reason") or "investigation failed"))
    else:
        rt.store.finish_job(job_id, "done", investigation_id=inv_id)


async def _queue_worker(rt: Runtime, poll_seconds: float = QUEUE_POLL_SECONDS) -> None:
    """Drain the jobs queue forever. A worker exception must never kill it."""
    while True:
        try:
            job = rt.store.claim_next_job()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("claiming a job failed")
            job = None
        if job is None:
            await asyncio.sleep(poll_seconds)
            continue
        try:
            await run_job(rt, job)
        except asyncio.CancelledError:
            raise
        except Exception:  # run_job handles its own errors; this is belt & braces
            log.exception("queue worker: job #%s blew up", job.get("id"))


async def run_daemon() -> None:
    rt = build_runtime()
    tz = rt.config.settings.timezone
    scheduler = AsyncIOScheduler(timezone=tz)

    for hhmm in rt.config.settings.schedules.daily:
        hour, minute = hhmm.split(":")
        scheduler.add_job(_daily_job, CronTrigger(hour=int(hour), minute=int(minute), timezone=tz),
                          args=[rt], name=f"daily-{hhmm}", misfire_grace_time=3600)
    scheduler.add_job(_poll_job, IntervalTrigger(minutes=rt.config.settings.schedules.poll_minutes),
                      args=[rt], name="alert-poller", misfire_grace_time=120)

    try:
        swept = rt.store.sweep_interrupted()
        if swept:
            log.warning("crash recovery: %d job/investigation row(s) marked interrupted", swept)
    except Exception:
        log.exception("sweeping interrupted jobs failed")

    scheduler.start()
    worker = asyncio.create_task(_queue_worker(rt), name="queue-worker")
    log.info(
        "HEIM daemon up — daily at %s (%s), poller every %d min, %d hosts, telegram %s, "
        "%d job(s) queued",
        ", ".join(rt.config.settings.schedules.daily), tz,
        rt.config.settings.schedules.poll_minutes, len(rt.config.hosts),
        "on" if rt.telegram else "off", rt.store.queued_count(),
    )
    await rt.notify("🟢 HEIM daemon started")
    try:
        await asyncio.Event().wait()
    finally:
        worker.cancel()
        scheduler.shutdown(wait=False)
