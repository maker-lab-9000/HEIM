"""Long-running daemon: cron-scheduled daily runs + interval alert poller.

Replaces the two n8n schedule triggers. Investigations dispatched from either
pipeline run as fire-and-forget asyncio tasks (the n8n `waitForSubWorkflow:
false` equivalent), so a pending Telegram approval never blocks the next poll
or report.

A third task drains the ``jobs`` queue (roadmap §5.2): the dashboard and the
CLI only *insert* rows, the daemon stays the sole executor. On startup any job
or investigation left mid-flight by a crash is swept to
interrupted/failed, so the tables never lie about what is running.

Ops hardening (roadmap §5.7) hangs off the same scheduler: every completed
poll pings the dead-man's switch, and a nightly job snapshots the SQLite store
into ``<data-dir>/backups/`` before pruning history past the retention window.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from heim.agents import BACKUP_TIME
from heim.channels import deadman
from heim.pipelines.daily import run_daily
from heim.pipelines.investigate import rearm_pending_approvals, run_investigation
from heim.pipelines.poller import run_poll
from heim.pipelines.queue import request_from_payload
from heim.pipelines.security_audit import run_security_audit
from heim.config import parse_weekly
from heim.metrics.queries import load_queries
from heim.security.catalogue import load_catalogue
from heim.runtime import Runtime, build_runtime

log = logging.getLogger(__name__)

#: How often an idle queue worker re-checks for work.
QUEUE_POLL_SECONDS = 4.0

#: When the nightly backup + retention job runs (configured timezone). Deep in
#: the quiet hours, far from both daily report slots.
BACKUP_HOUR, BACKUP_MINUTE = BACKUP_TIME

#: Grace for the weekly audit: a restart within the hour still runs it; later
#: than that the week is skipped (the next Monday is soon enough for hygiene).
AUDIT_MISFIRE_GRACE_S = 3600


def weekly_trigger(spec: str, tz: str) -> CronTrigger:
    """``"mon 06:00"`` → the APScheduler cron trigger for that weekly slot."""
    day, hour, minute = parse_weekly(spec)
    return CronTrigger(day_of_week=day, hour=hour, minute=minute, timezone=tz)


#: Backup filename pattern — one snapshot per day, so a re-run overwrites
#: rather than piling up, and plain name sort == chronological order.
BACKUP_STEM = "heim-%Y%m%d"


def _record_agent_run(rt: Runtime, agent: str, started_at: str, ok: bool,
                      error: str = "", detail: dict | None = None) -> None:
    """Heartbeat for the dashboard. A side channel: never breaks a job."""
    try:
        rt.store.record_agent_run(agent, started_at, rt.now_iso(), ok, error, detail)
    except Exception:
        log.exception("recording the %s heartbeat failed", agent)


def _exc_text(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:200]


def _query_count(rt: Runtime) -> int | None:
    try:
        return len(load_queries(rt.config.queries_path))
    except Exception:
        return None


async def _daily_job(rt: Runtime) -> None:
    started = rt.now_iso()
    try:
        result = await run_daily(rt, dispatch_concurrently=True)
        log.info("daily run complete: %s", result)
        _record_agent_run(rt, "daily", started, True, detail={
            "queries": _query_count(rt), "hosts": len(rt.config.hosts)})
    except Exception as exc:
        log.exception("daily run failed")
        _record_agent_run(rt, "daily", started, False, _exc_text(exc))
        await rt.notify(f"🔴 HEIM daily run FAILED: {type(exc).__name__}: {exc}")


def _record_poll_agents(rt: Runtime, started: str, summary: dict) -> None:
    """One heartbeat per poll half; a half that is switched off gets none."""
    cfg = rt.config
    aborted = summary.get("aborted")
    _record_agent_run(rt, "alert_poller", started, not aborted,
                      "Prometheus unreachable" if aborted else "",
                      {"hosts": len(cfg.hosts), **({"aborted": str(aborted)} if aborted else {})})
    if cfg.settings.threshold_detection:
        if summary.get("threshold_failed"):
            err = "threshold half raised"
        elif summary.get("threshold_samples") == 0:
            err = "no usable samples"
        else:
            err = ""
        _record_agent_run(rt, "thresholds", started, not err, err,
                          {"queries": _query_count(rt),
                           "samples": summary.get("threshold_samples")})
    if cfg.settings.uptime_kuma.url:
        if summary.get("uptime_failed"):
            err = "uptime half raised"
        elif summary.get("uptime_unreachable"):
            err = "Uptime Kuma unreachable"
        else:
            err = ""
        _record_agent_run(rt, "uptime", started, not err, err,
                          {"monitors": summary.get("uptime_monitors"),
                           "report_only": summary.get("uptime_report_only")})


async def _poll_job(rt: Runtime) -> None:
    started = rt.now_iso()
    try:
        summary = await run_poll(rt, dispatch_concurrently=True)
    except Exception as exc:
        log.exception("alert poll failed")  # next poll retries in a few minutes
        _record_agent_run(rt, "alert_poller", started, False, _exc_text(exc))
        return
    _record_poll_agents(rt, started, summary or {})
    # Every *completed* cycle pings, including the no-op ones: the switch
    # asserts "the scheduler is alive", not "an incident happened". A poll
    # that raised deliberately stays silent — that is the outage to report.
    await deadman.ping(rt.config.settings.deadman_url)


async def _security_audit_job(rt: Runtime) -> None:
    """Weekly read-only security audit. Same contract as _daily_job: never
    raise into the scheduler; a failure is one Telegram line. Success is
    silent here because the pipeline delivers its own digest."""
    started = rt.now_iso()
    try:
        result = await run_security_audit(rt)
        log.info("security audit complete: %s", result)
        _record_agent_run(rt, "security", started, True, detail={
            "checks": (result or {}).get("checks")})
    except Exception as exc:
        log.exception("security audit failed")
        _record_agent_run(rt, "security", started, False, _exc_text(exc))
        await rt.notify(f"🔴 HEIM weekly security audit FAILED: {type(exc).__name__}: {exc}")


async def _check_audit_catalogue(rt: Runtime) -> bool:
    """Validate config/security/checks.yaml at startup (Design §5: "at startup
    and in heim check"). A bad catalogue costs only the weekly audit, so it is
    logged and notified — never raised: like the other startup steps, it must
    not take the daily reports and the poller down with it."""
    try:
        load_catalogue(rt.config.security_checks_path)
        return True
    except Exception as exc:
        log.error("security audit catalogue %s is invalid: %s", rt.config.security_checks_path, exc)
        try:
            await rt.notify(f"🔴 HEIM security audit: checks.yaml is invalid — the weekly audit will fail "
                            f"until it is fixed: {type(exc).__name__}: {exc}")
        except Exception:
            log.exception("notifying the invalid security catalogue failed")
        return False


# ------------------------------------------------ nightly backup + retention


def backups_dir(db_path: str | Path) -> Path:
    """``<db file>/../backups`` — the store is the only state worth keeping."""
    return Path(db_path).expanduser().resolve().parent / "backups"


def prune_backups(directory: Path, keep: int) -> list[Path]:
    """Keep the newest ``keep`` snapshots; returns what was removed.

    Ordering is by filename (``heim-YYYYMMDD.sqlite3`` sorts chronologically),
    which survives mtime rewrites from a restore or an rsync. ``keep <= 0``
    disables pruning — never interpret it as "delete everything".
    """
    if keep <= 0:
        return []
    snapshots = sorted(Path(directory).glob("heim-*.sqlite3"), reverse=True)
    removed = []
    for path in snapshots[keep:]:
        try:
            path.unlink()
            removed.append(path)
        except OSError:
            log.exception("could not remove old backup %s", path)
    return removed


def run_backup(rt: Runtime) -> Path:
    """Write today's snapshot and rotate the backups dir. May raise."""
    settings = rt.config.settings
    dest = backups_dir(settings.db_path) / f"{rt.now().strftime(BACKUP_STEM)}.sqlite3"
    rt.store.backup_to(dest)
    removed = prune_backups(dest.parent, int(settings.backup_keep))
    log.info("backup written: %s (%d KiB)%s", dest, dest.stat().st_size // 1024,
             f", {len(removed)} old snapshot(s) removed" if removed else "")
    return dest


async def _backup_job(rt: Runtime) -> None:
    """Nightly housekeeping: snapshot first, prune second, never crash.

    Order matters — the backup is taken *before* the prune, so the snapshot
    still contains everything retention is about to delete. If the backup
    fails the prune is skipped entirely: deleting history we just failed to
    copy is the one way this job could do real damage.
    """
    started = rt.now_iso()
    try:
        dest = run_backup(rt)
    except Exception as exc:
        log.exception("nightly backup failed — skipping the retention prune")
        _record_agent_run(rt, "backup", started, False, _exc_text(exc))
        return
    _record_agent_run(rt, "backup", started, True, detail={"backup_file": dest.name})

    try:
        counts = rt.store.prune(rt.now_iso(), int(rt.config.settings.retention_days))
        if counts:
            log.info("retention prune deleted %s", counts)
    except Exception:
        log.exception("retention prune failed")


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
    scheduler.add_job(_backup_job,
                      CronTrigger(hour=BACKUP_HOUR, minute=BACKUP_MINUTE, timezone=tz),
                      args=[rt], name="nightly-backup", misfire_grace_time=3600)
    audit_spec = rt.config.settings.schedules.security_audit
    if audit_spec:
        await _check_audit_catalogue(rt)
        scheduler.add_job(_security_audit_job, weekly_trigger(audit_spec, tz), args=[rt],
                          name="security-audit", misfire_grace_time=AUDIT_MISFIRE_GRACE_S)

    try:
        swept = rt.store.sweep_interrupted()
        if swept:
            log.warning("crash recovery: %d job/investigation row(s) marked interrupted", swept)
    except Exception:
        log.exception("sweeping interrupted jobs failed")

    # The sweep deliberately leaves parked approvals alone; this picks them
    # back up. Order matters — re-arming before the sweep would race it.
    if rt.telegram is not None:
        rt.telegram.start_consumer()   # taps must land even with no ask outstanding
    try:
        rearmed = rearm_pending_approvals(rt)
    except Exception:
        log.exception("re-arming parked approvals failed")
        rearmed = 0

    scheduler.start()
    worker = asyncio.create_task(_queue_worker(rt), name="queue-worker")
    log.info(
        "HEIM daemon up — daily at %s (%s), poller every %d min, backup %02d:%02d, "
        "security audit %s, %d hosts, telegram %s, dead-man %s, %d job(s) queued, "
        "%d approval(s) re-armed",
        ", ".join(rt.config.settings.schedules.daily), tz,
        rt.config.settings.schedules.poll_minutes, BACKUP_HOUR, BACKUP_MINUTE,
        audit_spec or "off",
        len(rt.config.hosts), "on" if rt.telegram else "off",
        "on" if rt.config.settings.deadman_url else "off", rt.store.queued_count(), rearmed,
    )
    await rt.notify("🟢 HEIM daemon started")
    try:
        await asyncio.Event().wait()
    finally:
        worker.cancel()
        if rt.telegram is not None:
            rt.telegram.stop_consumer()
        scheduler.shutdown(wait=False)
