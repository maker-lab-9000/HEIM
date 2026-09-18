"""False-positive suppression (roadmap §5.4), applied in the pipelines only.

``reconcile.py`` and ``poller_logic.py`` are golden ports of the n8n Code
nodes and stay untouched: they keep deciding what *would* happen, and the
filters below drop whatever the human has muted before any of it reaches the
store, Telegram, Loki or the investigator. That keeps the suppression list a
pipeline-level policy rather than a fork of the ported logic.

A suppressed fingerprint is:
  * never upserted (so the stored, already-suppressed incident row is neither
    resurrected nor mutated),
  * never dispatched for investigation,
  * never notified or emitted as an incident event,
and is instead summarized for the analyst as a short "known false positives"
block appended to its *user* message.
"""
from __future__ import annotations

import logging
from dataclasses import replace
from datetime import datetime, timedelta

from heim.incidents.store import IncidentStore
from heim.incidents.types import PollerDecision, ReconcileResult

log = logging.getLogger(__name__)

__all__ = [
    "filter_rows",
    "filter_incident_events",
    "filter_reconcile",
    "filter_decision",
    "suppression_prompt_block",
    "suppress_fingerprint",
    "mark_false_positive",
    "PROMPT_HEADER",
    "PROMPT_MAX_ENTRIES",
]

PROMPT_HEADER = "Known false positives — do not report these unless materially changed:"
PROMPT_MAX_ENTRIES = 10


# ------------------------------------------------------------ pure filters


def filter_rows(rows: list[dict], suppressed: set[str]) -> list[dict]:
    """Drop dicts whose ``fingerprint`` is muted (non-dicts pass through)."""
    if not suppressed:
        return list(rows or [])
    return [
        r for r in (rows or [])
        if not (isinstance(r, dict) and str(r.get("fingerprint") or "") in suppressed)
    ]


def filter_incident_events(events: list[dict], suppressed: set[str]) -> list[dict]:
    """Drop ``incident`` Loki events for muted fingerprints (other event types
    — finding, category, state — are never fingerprinted and pass through)."""
    if not suppressed:
        return list(events or [])
    out = []
    for e in events or []:
        fp = str(((e or {}).get("fields") or {}).get("fingerprint") or "")
        if fp and fp in suppressed:
            continue
        out.append(e)
    return out


def filter_reconcile(rec: ReconcileResult, suppressed: set[str]) -> tuple[ReconcileResult, dict]:
    """Filtered copy of a reconcile result + what was dropped."""
    if not suppressed:
        return rec, {}
    rows = filter_rows(rec.rows_to_write, suppressed)
    invs = filter_rows(rec.to_investigate, suppressed)
    dropped = {
        "rows": len(rec.rows_to_write) - len(rows),
        "investigations": len(rec.to_investigate) - len(invs),
    }
    return replace(rec, rows_to_write=rows, to_investigate=invs), {k: v for k, v in dropped.items() if v}


def filter_decision(dec: PollerDecision, suppressed: set[str]) -> tuple[PollerDecision, dict]:
    """Filtered copy of a poller decision + what was dropped."""
    if not suppressed:
        return dec, {}
    rows = filter_rows(dec.rows_to_upsert, suppressed)
    disp = filter_rows(dec.dispatches, suppressed)
    notes = filter_rows(dec.notifications, suppressed)
    events = filter_incident_events(dec.loki_events, suppressed)
    dropped = {
        "upserts": len(dec.rows_to_upsert) - len(rows),
        "dispatches": len(dec.dispatches) - len(disp),
        "notifications": len(dec.notifications) - len(notes),
        "loki_events": len(dec.loki_events) - len(events),
    }
    return (
        replace(dec, rows_to_upsert=rows, dispatches=disp, notifications=notes,
                loki_events=events,
                # poller_logic derives state_changed from the rows it wrote; if
                # every one of them was muted, nothing changed after all.
                state_changed=bool(dec.state_changed and rows)),
        {k: v for k, v in dropped.items() if v},
    )


def _describe(row: dict) -> tuple[str, str]:
    """(host, what) for one suppression row — reason first, fingerprint else."""
    fp = str((row or {}).get("fingerprint") or "")
    parts = fp.split("|")
    host = parts[0] if parts and parts[0] else "unknown"
    reason = str((row or {}).get("reason") or "").strip()
    if reason:
        return host, reason
    rest = " · ".join(p for p in parts[1:] if p)
    return host, rest or fp or "(unspecified)"


def suppression_prompt_block(rows: list[dict], limit: int = PROMPT_MAX_ENTRIES) -> str:
    """The bounded block appended to the analyst's *user* message.

    Bounded on purpose (default 10 entries): the whole metrics payload already
    shares that prompt and the suppression list must never be the thing that
    blows the token budget.
    """
    entries = [r for r in (rows or []) if r]
    if not entries:
        return ""
    lines = [PROMPT_HEADER]
    for row in entries[:limit]:
        host, what = _describe(row)
        lines.append(f"- {host} · {what}")
    extra = len(entries) - limit
    if extra > 0:
        lines.append(f"- (+{extra} more suppressed)")
    return "\n".join(lines)


# ---------------------------------------------------------- store actions


def _until(days: int | None, now: datetime | None = None) -> str:
    """'' (forever) when days is None or <= 0, else now+days as ISO-8601.

    Written on the caller's clock — ``active_suppressions`` compares against
    the same ``Runtime.now_iso`` format.
    """
    if not days or int(days) <= 0:
        return ""
    base = now or datetime.now().astimezone()
    return (base + timedelta(days=int(days))).isoformat(timespec="milliseconds")


def suppress_fingerprint(
    store: IncidentStore,
    fingerprint: str,
    days: int | None = None,
    reason: str = "",
    now: datetime | None = None,
) -> dict:
    """Mute a fingerprint and mark its incident (if any) ``suppressed``."""
    until = _until(days, now)
    store.suppress(fingerprint, until=until, reason=reason,
                   created_at=(now or datetime.now().astimezone()).isoformat(timespec="milliseconds"))
    incident_updated = store.set_incident_status(fingerprint, "suppressed")
    log.info("suppressed %s until %s%s", fingerprint, until or "forever",
             "" if incident_updated else " (no incident row)")
    return {"fingerprint": fingerprint, "until": until, "reason": reason,
            "incident_updated": incident_updated}


def mark_false_positive(
    store: IncidentStore,
    finding_id: int,
    days: int | None = None,
    now: datetime | None = None,
) -> dict | None:
    """Verdict + suppression in one call (the dashboard/CLI action).

    Sets ``verdict=false_positive`` on the finding, mutes its fingerprint for
    ``days`` (None/0 = forever) and flips the matching incident row to
    ``suppressed``. Returns the finding row (with a ``suppression`` key), or
    None when there is no such finding.
    """
    finding = store.set_finding_verdict(finding_id, "false_positive")
    if finding is None:
        return None
    fingerprint = str(finding.get("fingerprint") or "")
    if not fingerprint:
        finding["suppression"] = None
        return finding
    reason = str(finding.get("summary") or finding.get("detail") or finding.get("metric") or "")
    finding["suppression"] = suppress_fingerprint(
        store, fingerprint, days=days, reason=reason, now=now
    )
    return finding
