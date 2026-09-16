"""Long-running daemon: cron-scheduled daily runs + interval alert poller.

Replaces the two n8n schedule triggers. Investigations dispatched from either
pipeline run as fire-and-forget asyncio tasks (the n8n `waitForSubWorkflow:
false` equivalent), so a pending Telegram approval never blocks the next poll
or report.
"""
from __future__ import annotations

import asyncio
import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from heim.pipelines.daily import run_daily
from heim.pipelines.poller import run_poll
from heim.runtime import Runtime, build_runtime

log = logging.getLogger(__name__)


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

    scheduler.start()
    log.info(
        "HEIM daemon up — daily at %s (%s), poller every %d min, %d hosts, telegram %s",
        ", ".join(rt.config.settings.schedules.daily), tz,
        rt.config.settings.schedules.poll_minutes, len(rt.config.hosts),
        "on" if rt.telegram else "off",
    )
    await rt.notify("🟢 HEIM daemon started")
    try:
        await asyncio.Event().wait()
    finally:
        scheduler.shutdown(wait=False)
