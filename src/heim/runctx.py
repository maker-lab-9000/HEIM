"""The job run a piece of work belongs to (spec 2026-11-04-activity-jobs-tools).

The daemon opens a heartbeat (``agent_runs`` row) when a job starts and puts
its id here; the pipelines read it to stamp what the run creates — its
``runs`` row, its incident events, the investigations it dispatches. A
``ContextVar`` rather than a parameter, because the ids must reach code three
calls down (``dispatch_all`` → ``run_investigation``) and survive into the
tasks it starts: ``asyncio.create_task`` copies the context, so an
investigation that outlives its job still knows its parent. CLI one-offs
never set it, so what they create has no parent (0), exactly like a manual run.
"""
from __future__ import annotations

from contextvars import ContextVar, Token

#: job key (as in agent_runs.agent) -> the heartbeat id of the run in progress
run_ids: ContextVar[dict[str, int]] = ContextVar("heim_run_ids", default={})

#: an investigation trigger -> the job that dispatches with it
TRIGGER_JOB = {"daily": "daily", "poller": "alert_poller", "threshold": "thresholds",
               "uptime": "uptime"}


def set_runs(mapping: dict[str, int]) -> Token:
    return run_ids.set({k: int(v) for k, v in mapping.items() if int(v or 0)})


def current_run(job: str) -> int:
    return int(run_ids.get().get(job, 0))
