"""Jobs: the scheduled, model-free parts of HEIM, and their timed pauses.

Pure (spec 2026-11-04-activity-jobs-tools). A pause is a store row
``job_pauses(job, until, …)`` the dashboard writes and the daemon obeys: while
``now < until`` the job's work is skipped (the poll cycle and its dead-man ping
still run). Every pause ends by itself; ``announcements`` says which start or
end the daemon still owes Telegram.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

#: the jobs, keyed as their heartbeats (agent_runs.agent) are
JOB_KEYS = ("daily", "alert_poller", "thresholds", "uptime", "security", "backup")

#: the only pause lengths offered — a pause always ends by itself
PAUSE_CHOICES = {"1h": 3600, "4h": 14400, "24h": 86400}

#: incident Loki statuses that are a change worth recording ("open" is not)
_CHANGES = ("new", "escalated", "resolved")


def _parse(iso: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def pause_until(now_iso: str, choice: str) -> str:
    """``now`` plus a :data:`PAUSE_CHOICES` length, in ``now``'s offset."""
    if choice not in PAUSE_CHOICES:
        raise ValueError(f"pause length must be one of {', '.join(PAUSE_CHOICES)}")
    now = _parse(now_iso)
    if now is None:
        raise ValueError(f"unreadable time {now_iso!r}")
    return (now + timedelta(seconds=PAUSE_CHOICES[choice])).isoformat()


def pause_active(row: dict | None, now_iso: str) -> bool:
    if not row:
        return False
    until, now = _parse(row.get("until") or ""), _parse(now_iso)
    return bool(until and now and now < until)


def announcements(pauses: dict[str, dict], now_iso: str
                  ) -> list[tuple[str, Literal["start", "end"]]]:
    """The pause starts and ends not yet told to the operator, start first."""
    out: list[tuple[str, Literal["start", "end"]]] = []
    for job, row in sorted(pauses.items()):
        if int(row.get("pending_end") or 0):
            out.append((job, "end"))           # the previous pause's, still owed
        if not int(row.get("announced_start") or 0):
            out.append((job, "start"))
        if not pause_active(row, now_iso) and not int(row.get("announced_end") or 0):
            out.append((job, "end"))
    return out


def incident_changes(loki_events: list[dict]) -> list[dict]:
    """The incident changes inside a pipeline's Loki events, for incident_events."""
    out = []
    for e in loki_events or []:
        if (e or {}).get("event") != "incident":
            continue
        labels, fields = e.get("labels") or {}, e.get("fields") or {}
        status = str(labels.get("status") or "")
        if status not in _CHANGES or not fields.get("fingerprint"):
            continue
        out.append({"fingerprint": str(fields["fingerprint"]), "event": status,
                    "severity": str(labels.get("severity") or ""),
                    "host": str(labels.get("host") or "")})
    return out
