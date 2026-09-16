"""Loki AI-event push (port of n8n PAM 50 'Build Loki Payload' + HTTP push).

Event model and labels are IDENTICAL to the n8n stack (job=homelab-ai-monitor,
event=state|incident|investigation|action|finding|category), so the existing
Grafana "Homelab AI Operations" dashboard keeps working unchanged.

Each event: {"event": str, "labels": dict, "fields": dict, "tsMs": optional int}.
Batched events get unique timestamps (base_ms + i) — Loki silently drops
same-stream same-nanosecond duplicates.
"""
from __future__ import annotations

import json
import logging
import re
import time

import httpx

log = logging.getLogger(__name__)

_LABEL_KEY = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def _clean_stream(event: str, labels: dict | None) -> dict:
    stream = {"job": "homelab-ai-monitor", "event": str(event or "state"), **(labels or {})}
    clean = {}
    for k, v in stream.items():
        if not _LABEL_KEY.match(str(k)):
            continue
        if v is None or v == "":
            continue
        clean[str(k)] = str(v)
    return clean


def build_payload(events: list[dict], base_ms: int | None = None) -> dict:
    base_ms = base_ms if base_ms is not None else int(time.time() * 1000)
    streams = []
    for i, ev in enumerate(events):
        ms = int(ev.get("tsMs") or (base_ms + i))
        streams.append({
            "stream": _clean_stream(ev.get("event", "state"), ev.get("labels")),
            "values": [[f"{ms}000000", json.dumps(ev.get("fields") or {}, ensure_ascii=False)]],
        })
    return {"streams": streams}


async def push_events(loki_url: str, events: list[dict]) -> None:
    """Fire-and-forget semantics: failures are logged, never raised."""
    if not events:
        return
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(f"{loki_url.rstrip('/')}/loki/api/v1/push", json=build_payload(events))
            if r.status_code >= 300:
                log.warning("loki push HTTP %s: %s", r.status_code, r.text[:300])
    except Exception:
        log.exception("loki push failed")
