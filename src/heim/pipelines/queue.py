"""The investigation job queue (roadmap §5.2 + §5.5).

Everything that wants an investigation to run but is *not* the daemon — the
dashboard, the CLI, a re-trigger button — inserts a row into ``jobs`` instead
of spawning a task. The daemon's queue worker (``heim.daemon._queue_worker``)
claims jobs one at a time and runs them through the normal
``run_investigation`` path, so the concurrency cap, the approval gate, the
tracking rows and the delivery channels all behave identically to a
daily/poller dispatch.

The payload is deliberately self-contained (``host``, ``host_role``,
``fingerprint``, ``findings``) so a job survives a restart and a re-run keeps
the *original* investigation's subject even if its incident has since changed.
"""
from __future__ import annotations

import logging

from heim.incidents.store import IncidentStore
from heim.pipelines.investigate import InvestigationRequest, request_from_dispatch

log = logging.getLogger(__name__)

__all__ = [
    "enqueue_investigation",
    "enqueue_retry",
    "request_from_payload",
    "payload_for",
]


def payload_for(host: str, host_role: str, fingerprint: str, findings: list[dict] | None,
                model: str = "") -> dict:
    return {
        "host": str(host or ""),
        "host_role": str(host_role or "guest"),
        "fingerprint": str(fingerprint or ""),
        "findings": list(findings or []),
        # §5.1: the model this trigger chose, "" for the configured default.
        # Always written so a payload says what it will run on, not what it
        # happened to omit.
        "model": str(model or ""),
    }


def enqueue_investigation(
    store: IncidentStore,
    *,
    host: str,
    host_role: str = "guest",
    fingerprint: str = "",
    findings: list[dict] | None = None,
    requested_by: str = "cli",
    retry_of: int = 0,
    model: str = "",
) -> int:
    """Queue an investigation; returns the job id.

    ``model`` overrides the investigator's model for this run only (§5.1); ""
    means the configured default. The caller validates it — the queue only
    carries what it was handed.
    """
    job_id = store.enqueue_job(
        kind="investigate",
        payload=payload_for(host, host_role, fingerprint, findings, model),
        requested_by=requested_by,
        retry_of=retry_of,
    )
    log.info("queued investigation job #%d for %s (by %s%s%s)", job_id, host, requested_by,
             f", retry of #{retry_of}" if retry_of else "",
             f", on {model}" if model else "")
    return job_id


def enqueue_retry(store: IncidentStore, investigation_id: int, requested_by: str = "cli") -> int | None:
    """Re-run a past investigation: same host/role/fingerprint, fresh evidence.

    The findings are re-synthesized from the incident row the original
    investigation was about (the faithful source — it is what
    ``request_from_dispatch`` would have produced); if the incident is gone,
    a single generic finding keeps the brief honest about what is being asked.
    Returns the new job id, or None when there is no such investigation.
    """
    original = store.investigation(investigation_id)
    if original is None:
        return None
    fingerprint = str(original.get("fingerprint") or "")
    incident = store.incident(fingerprint) if fingerprint else None
    if incident:
        findings = [{
            "severity": incident.get("severity", ""),
            "host": incident.get("host", ""),
            "metric": incident.get("metric", ""),
            "trend": "",
            "detail": incident.get("description", ""),
            "recommendation": "",
        }]
    else:
        findings = [{
            "severity": "warning",
            "host": str(original.get("host") or ""),
            "metric": "",
            "trend": "",
            "detail": f"re-run of investigation #{investigation_id}",
            "recommendation": "",
        }]
    return enqueue_investigation(
        store,
        host=str(original.get("host") or ""),
        host_role=str(original.get("host_role") or "guest"),
        fingerprint=fingerprint,
        findings=findings,
        requested_by=requested_by,
        retry_of=int(investigation_id),
    )


def request_from_payload(payload: dict, rt, retry_of: int = 0) -> InvestigationRequest:
    """Turn a job payload back into an :class:`InvestigationRequest`.

    Accepts both the queue's own shape (``findings`` list) and a raw
    reconcile/poller dispatch item, which ``request_from_dispatch`` already
    knows how to expand.
    """
    payload = payload or {}
    if "findings" not in payload and ("description" in payload or "metric" in payload):
        req = request_from_dispatch(payload, rt)
        req.retry_of = int(retry_of or 0)
        return req
    host = str(payload.get("host") or "")
    host_cfg = rt.config.hosts.get(host)
    role = str(payload.get("host_role") or payload.get("hostRole")
               or (host_cfg.role if host_cfg else "guest"))
    return InvestigationRequest(
        host=host,
        host_role=role,
        fingerprint=str(payload.get("fingerprint") or ""),
        findings=list(payload.get("findings") or []),
        retry_of=int(retry_of or 0),
        model_override=str(payload.get("model") or ""),
    )
