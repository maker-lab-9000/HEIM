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
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from heim.agents import AGENT_LABELS, BACKUP_TIME
from heim.jobs import announcements, pause_active
from heim.channels import deadman
from heim.llm import AnalystChainFailed
from heim.runctx import current_run, run_ids, set_runs
from heim.pipelines.daily import run_daily
from heim.pipelines.investigate import (model_label, notify_investigation_failed,
                                       rearm_pending_approvals, run_investigation)
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
    """Heartbeat for the dashboard. A side channel: never breaks a job.

    Closes the row :func:`_job_runs` opened for ``agent`` in this run, when
    there is one (spec 2026-11-04-activity-jobs-tools); otherwise writes a
    finished row, as before.
    """
    try:
        run_id = current_run(agent)
        if run_id:
            rt.store.finish_agent_run(run_id, rt.now_iso(), ok, error, detail)
        else:
            rt.store.record_agent_run(agent, started_at, rt.now_iso(), ok, error, detail)
    except Exception:
        log.exception("recording the %s heartbeat failed", agent)


def _active_pause(rt: Runtime, job: str) -> dict | None:
    """The dashboard pause in effect for ``job`` now, if any (never raises)."""
    try:
        row = rt.store.job_pauses().get(job)
    except Exception:
        log.exception("reading the pause of %s failed — running it", job)
        return None
    return row if pause_active(row, rt.now_iso()) else None


def _record_paused(rt: Runtime, job: str, started: str, row: dict) -> None:
    """A skipped run is still a heartbeat, so a paused job never reads Overdue."""
    _record_agent_run(rt, job, started, True, detail={"paused": True,
                                                     "until": str(row.get("until") or "")})


def _hhmm(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%H:%M")
    except (TypeError, ValueError):
        return iso


async def _announce_pauses(rt: Runtime) -> None:
    """Tell Telegram each pause start and end once (spec 2026-11-04-activity-
    jobs-tools). Run from every poll cycle, so a line arrives within one poll
    interval; one not sent is retried on the next cycle. Never raises."""
    try:
        pauses = rt.store.job_pauses()
        due = announcements(pauses, rt.now_iso())
    except Exception:
        log.exception("reading job pauses failed")
        return
    for job, which in due:
        row = pauses.get(job) or {}
        name = AGENT_LABELS.get(job, job)
        text = (f"⏸ HEIM: {name} paused until {_hhmm(str(row.get('until') or ''))} "
                f"({row.get('set_by') or 'dashboard'})" if which == "start"
                else f"▶ HEIM: {name} resumed")
        try:
            # Telegram.notify swallows its own errors; send() does not, so a
            # line Telegram did not take stays owed and is retried next cycle
            if rt.telegram is not None and not rt.dry_run:
                await rt.telegram.send(text)
            else:
                await rt.notify(text)
            rt.store.mark_pause_announced(job, which)
        except Exception:
            log.exception("announcing the %s of the %s pause failed", which, job)
            return


@contextmanager
def _job_runs(rt: Runtime, started_at: str, *agents: str):
    """Open one heartbeat per job when it starts and make the ids the run
    context, so everything the run creates records it (spec 2026-11-04-
    activity-jobs-tools). An id that cannot be opened is simply absent; the
    job then records its heartbeat at the end, as before."""
    ids: dict[str, int] = {}
    for agent in agents:
        try:
            ids[agent] = rt.store.start_agent_run(agent, started_at)
        except Exception:
            log.exception("opening the %s heartbeat failed", agent)
    token = set_runs(ids)
    try:
        yield ids
    finally:
        run_ids.reset(token)
        # a run that never reached its heartbeat (cancelled by a shutdown) is
        # a failure, never a success left open forever
        for rid in ids.values():
            try:
                rt.store.close_agent_run_if_open(rid, rt.now_iso(),
                                                 "cancelled before it finished")
            except Exception:
                log.exception("closing heartbeat #%s failed", rid)


def _exc_text(exc: BaseException) -> str:
    # A chain failure lists every model it tried; give it room to (spec 2026-11-04).
    # each attempt's error is already clipped to llm.ERROR_CLIP
    clip = 400 * len(exc.attempts) + 100 if isinstance(exc, AnalystChainFailed) else 200
    return f"{type(exc).__name__}: {exc}"[:clip]


def _query_count(rt: Runtime) -> int | None:
    try:
        return len(load_queries(rt.config.queries_path))
    except Exception:
        return None


async def _daily_job(rt: Runtime) -> None:
    started = rt.now_iso()
    with _job_runs(rt, started, "daily"):
        if (row := _active_pause(rt, "daily")) is not None:
            _record_paused(rt, "daily", started, row)
            return
        await _daily_job_body(rt, started)


async def _daily_job_body(rt: Runtime, started: str) -> None:
    try:
        result = await run_daily(rt, dispatch_concurrently=True)
        log.info("daily run complete: %s", result)
        _record_agent_run(rt, "daily", started, True, detail={
            "queries": _query_count(rt), "hosts": len(rt.config.hosts),
            "fallback": bool(result.get("fallback")),
            "model_used": str(result.get("model_used") or ""),
            "failed_models": list(result.get("failed_models") or [])})
    except Exception as exc:
        log.exception("daily run failed")
        _record_agent_run(rt, "daily", started, False, _exc_text(exc),
                          detail={"attempts": [a.as_dict() for a in exc.attempts]}
                          if isinstance(exc, AnalystChainFailed) else None)
        await rt.notify(f"🔴 HEIM daily run FAILED: {type(exc).__name__}: {exc}")


def _record_poll_agents(rt: Runtime, started: str, summary: dict,
                        skip: frozenset[str] = frozenset()) -> None:
    """One heartbeat per poll half; a half that is switched off gets none, and
    a paused one (``skip``) already has its "paused" heartbeat."""
    cfg = rt.config
    aborted = summary.get("aborted")
    # poller_logic aborts with "prometheus unreachable"; anything else (the
    # poller's own "alert half failed") is recorded as the reason it gave
    if not aborted:
        reason = ""
    elif str(aborted).strip().lower() == "prometheus unreachable":
        reason = "Prometheus unreachable"
    else:
        reason = str(aborted)
    if "alert_poller" not in skip:
        _record_agent_run(rt, "alert_poller", started, not aborted, reason,
                          {"hosts": len(cfg.hosts),
                           **({"aborted": str(aborted)} if aborted else {})})
    if cfg.settings.threshold_detection and "thresholds" not in skip:
        if summary.get("threshold_failed"):
            err = "threshold half raised"
        elif summary.get("threshold_samples") == 0:
            err = "no usable samples"
        else:
            err = ""
        _record_agent_run(rt, "thresholds", started, not err, err,
                          {"queries": _query_count(rt),
                           "samples": summary.get("threshold_samples")})
    if cfg.settings.uptime_kuma.url and "uptime" not in skip:
        if summary.get("uptime_failed"):
            err = "uptime half raised"
        elif summary.get("uptime_unreachable"):
            err = "Uptime Kuma unreachable"
        else:
            err = ""
        _record_agent_run(rt, "uptime", started, not err, err,
                          {"monitors": summary.get("uptime_monitors"),
                           "report_only": summary.get("uptime_report_only")})


def _poll_halves(rt: Runtime) -> list[str]:
    """The poll halves that run at all (a half switched off in config has none)."""
    st = rt.config.settings
    return (["alert_poller"] + (["thresholds"] if st.threshold_detection else [])
            + (["uptime"] if st.uptime_kuma.url else []))


async def _poll_job(rt: Runtime) -> None:
    started = rt.now_iso()
    await _announce_pauses(rt)
    halves = _poll_halves(rt)
    paused = {h: row for h in halves if (row := _active_pause(rt, h)) is not None}
    with _job_runs(rt, started, *halves) as opened:
        for half, row in paused.items():
            _record_paused(rt, half, started, row)
        try:
            # ``skip`` only when something is paused: the call is otherwise
            # exactly what it was
            summary = await (run_poll(rt, dispatch_concurrently=True, skip=frozenset(paused))
                             if paused else run_poll(rt, dispatch_concurrently=True))
        except Exception as exc:
            log.exception("alert poll failed")  # next poll retries in a few minutes
            # every half opened for this cycle is closed, none left "running"
            for half in opened:
                if half not in paused:
                    _record_agent_run(rt, half, started, False, _exc_text(exc))
            return
        try:
            _record_poll_agents(rt, started, summary or {}, skip=frozenset(paused))
        except Exception:  # a heartbeat must never cost the dead-man ping
            log.exception("recording the poll heartbeats failed")
    # Every *completed* cycle pings, including the no-op ones: the switch
    # asserts "the scheduler is alive", not "an incident happened". A poll
    # that raised deliberately stays silent — that is the outage to report.
    await deadman.ping(rt.config.settings.deadman_url)


async def _security_audit_job(rt: Runtime) -> None:
    """Weekly read-only security audit. Same contract as _daily_job: never
    raise into the scheduler; a failure is one Telegram line. Success is
    silent here because the pipeline delivers its own digest."""
    started = rt.now_iso()
    with _job_runs(rt, started, "security"):
        if (row := _active_pause(rt, "security")) is not None:
            _record_paused(rt, "security", started, row)
            return
        await _security_audit_body(rt, started)


async def _security_audit_body(rt: Runtime, started: str) -> None:
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

    One heartbeat, written last: a failed prune makes the run not ok (the
    store keeps growing), while ``backup_file`` still names the file written.
    """
    started = rt.now_iso()
    with _job_runs(rt, started, "backup"):
        if (row := _active_pause(rt, "backup")) is not None:
            _record_paused(rt, "backup", started, row)
            return
        _backup_body(rt, started)


def _backup_body(rt: Runtime, started: str) -> None:
    try:
        dest = run_backup(rt)
    except Exception as exc:
        log.exception("nightly backup failed — skipping the retention prune")
        _record_agent_run(rt, "backup", started, False, _exc_text(exc))
        return

    error = ""
    try:
        counts = rt.store.prune(rt.now_iso(), int(rt.config.settings.retention_days))
        if counts:
            log.info("retention prune deleted %s", counts)
    except Exception as exc:
        log.exception("retention prune failed")
        error = f"prune failed: {_exc_text(exc)}"[:200]
    _record_agent_run(rt, "backup", started, not error, error,
                      detail={"backup_file": dest.name})


async def _sweep_and_notify(rt: Runtime) -> int:
    """Crash recovery at startup, and one failure notice per investigation the
    restart cut short (spec 2026-11-04-investigator-openrouter). Never raises."""
    try:
        closed = rt.store.close_open_agent_runs(rt.now_iso(), "interrupted by daemon restart")
        if closed:
            log.warning("crash recovery: %d open heartbeat(s) closed as failed", closed)
    except Exception:
        log.exception("closing open heartbeats failed")
    try:
        cut_short = rt.store.running_investigations()
        swept = rt.store.sweep_interrupted()
    except Exception:
        log.exception("sweeping interrupted jobs failed")
        return 0
    if swept:
        log.warning("crash recovery: %d job/investigation row(s) marked interrupted", swept)
    for row in cut_short:
        # only the investigator's own runs: the notice points at its model page
        # (a security audit or an offline replay cut short is not one)
        if (row.get("agent_name") or "investigator") != "investigator" \
                or row.get("trigger") == "replay":
            continue
        await notify_investigation_failed(
            rt, inv_id=int(row["id"]), host=str(row.get("host") or "?"),
            model=str(row.get("model") or ""), error="interrupted by daemon restart")
    return int(swept)


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
        if not seen.get("id"):
            # no investigation row, so run_investigation never told anyone
            payload = job.get("payload") or {}
            await notify_investigation_failed(
                rt, inv_id=0, host=str(payload.get("host") or "?"),
                model=model_label(str(payload.get("model") or "")),
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

    await _sweep_and_notify(rt)

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
