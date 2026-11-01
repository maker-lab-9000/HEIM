"""The uptime half of the poll: Uptime Kuma as an alert source (I/O edge).

The decision is pure (``heim.incidents.uptime_logic.decide``); this module
fetches ``/metrics``, feeds ``decide`` its inputs, and applies the result.
It shares the store, ``rt.notify``, Loki and ``dispatch_all`` with the other
poll halves, so the approval gate and the mutes apply unchanged.

Rules this edge owns:

* a failed fetch, a body that fails to parse AND a body with no monitors are
  all ``monitors=None`` — an empty list would count as a successful poll and
  could falsely close outages (``decide`` also treats ``[]`` as a failed poll);
* in dry-run nothing at all is written (no incidents, state or fail counter);
* rows and state are written first, so every later step (each host group,
  the messages, the Loki events, the dispatches) is isolated: one failing
  never drops the rest, and the dispatches go last.
"""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime
from urllib.parse import urlsplit

import httpx

from heim.config import Config
from heim.incidents.reconcile import host_role_for, ssh_host_for
from heim.incidents.state import compute_state
from heim.incidents.uptime_logic import (
    FLAP_WINDOW_S,
    UptimeContext,
    decide,
    down_headline,
    is_uptime_row,
    map_host,
    parse_metrics,
    unmapped_monitors,
)
from heim.pipelines.investigate import dispatch_all, extend_pending_investigation
from heim.runtime import Runtime

log = logging.getLogger(__name__)

TRIGGER = "uptime"
ENV_KEY = "UPTIME_KUMA"


async def fetch_metrics(url: str, api_key: str | None, *,
                        transport: httpx.AsyncBaseTransport | None = None) -> str | None:
    """GET ``{url}/metrics`` (basic auth ``("", key)`` when a key is set).

    The body on 200; ``None`` on anything else, with one warning line.
    """
    auth = httpx.BasicAuth("", api_key) if api_key else None
    try:
        async with httpx.AsyncClient(timeout=15, auth=auth, transport=transport) as client:
            r = await client.get(f"{url.rstrip('/')}/metrics")
        if r.status_code != 200:
            log.warning("Uptime Kuma /metrics returned HTTP %s", r.status_code)
            return None
        return r.text
    except Exception as exc:
        log.warning("Uptime Kuma fetch failed: %s", exc.__class__.__name__)
        return None


def check_lines(text: str | None, cfg: Config) -> list[tuple[bool | None, str, str]]:
    """``heim check`` lines for Uptime Kuma, from a fetched ``/metrics`` body."""
    monitors = parse_metrics(text) if text else []
    if not monitors:
        return [(False, "uptime kuma",
                 "unreachable, or no monitors in /metrics (check UPTIME_KUMA)")]
    out: list[tuple[bool | None, str, str]] = [
        (True, "uptime kuma", f"{len(monitors)} active monitors")]
    stray = unmapped_monitors(monitors, cfg.settings.instance_host_map, cfg.hosts)
    if stray:
        names = ", ".join(m.name for m in stray)
        out.append((None, "uptime kuma",
                    f"{len(stray)} monitor(s) map to no HEIM host (report only): {names}"))
    return out


def pending_uptime_investigations(store) -> dict[str, int]:
    """host -> id of the newest ``pending_approval`` investigation, trigger uptime."""
    out: dict[str, int] = {}
    for row in store.investigations(limit=500, status="pending_approval"):
        if row.get("trigger") != TRIGGER:
            continue
        host = str(row.get("host") or "")
        if host and host not in out:  # rows come newest first
            out[host] = int(row["id"])
    return out


def build_context(cfg: Config, suppressed: set[str],
                  pending: dict[str, int]) -> UptimeContext:
    names = frozenset(cfg.hosts)
    address = (urlsplit(cfg.settings.uptime_kuma.url).hostname or "").lower()
    kuma_host = map_host(address, cfg.settings.instance_host_map, names) or address
    return UptimeContext(
        instance_host_map=cfg.settings.instance_host_map,
        host_names=names,
        routing=cfg.routing(),
        kuma_host=kuma_host,
        timezone=cfg.settings.timezone,
        suppressed=frozenset(suppressed),
        pending_by_host=dict(pending),
    )


def _recent_rows(store, states: dict[str, dict], now_iso: str) -> list[dict]:
    """Resolved ``[uptime]`` rows whose monitor recovered inside the flap window."""
    try:
        now = datetime.fromisoformat(now_iso)
    except ValueError:
        return []
    out: list[dict] = []
    for fp, st in states.items():
        try:
            rec = datetime.fromisoformat(st.get("last_recovered_at") or "")
        except ValueError:
            continue
        try:
            if (now - rec).total_seconds() > FLAP_WINDOW_S:
                continue
        except TypeError:  # naive vs aware: unknown age, not recent
            continue
        row = store.incident(fp)
        if row and row.get("status") == "resolved" and is_uptime_row(row):
            out.append(row)
    return out


async def run_uptime(rt: Runtime, run_at: str, *, dispatch_concurrently: bool) -> dict:
    """The uptime half. Returns its ``uptime_*`` counters."""
    cfg = rt.config
    store = rt.store
    body = await fetch_metrics(cfg.settings.uptime_kuma.url, os.environ.get(ENV_KEY) or None)
    monitors: list | None = None
    if body is not None:
        try:
            monitors = parse_metrics(body)
        except Exception:
            # an unreadable export is no data, never "every monitor gone"
            log.exception("parsing Uptime Kuma /metrics failed: treated as a failed poll")
            monitors = None
    if monitors is not None and not monitors:
        log.warning("Uptime Kuma /metrics held no monitors: treated as a failed poll")
        monitors = None

    suppressed: set[str] = set()
    try:
        suppressed = store.active_suppressions(run_at)
    except Exception:
        log.exception("reading suppressions failed — running unfiltered")

    states = store.uptime_states()
    ctx = build_context(cfg, suppressed, pending_uptime_investigations(store))
    dec = decide(monitors, store.open_rows(), states, store.uptime_fail_polls(),
                 run_at, ctx, recent_rows=_recent_rows(store, states, run_at))

    counters = {
        "uptime_monitors": len(monitors or []),
        "uptime_upserts": len(dec.rows_to_upsert),
        "uptime_groups": len(dec.groups),
        # what WOULD be dispatched; a live poll recounts what actually was
        "uptime_dispatches": sum(1 for g in dec.groups
                                 if g.investigable and g.pending_investigation_id is None),
        "uptime_messages": len(dec.messages),
        "uptime_state_changed": dec.state_changed,
        "uptime_unreachable": monitors is None,
    }

    if rt.dry_run:
        for g in dec.groups:
            log.info("DRY-RUN uptime: %s", g.headline)
        for m in dec.messages:
            log.info("DRY-RUN uptime: %s", m)
        return counters

    # State first: a counted poll must not be counted twice if a later step fails.
    store.save_uptime_states(dec.state_writes)
    store.clear_uptime_states(dec.state_clears)
    store.set_uptime_fail_polls(dec.fail_polls)
    if dec.rows_to_upsert:
        store.upsert(dec.rows_to_upsert)

    # Rows and state are already written, so nothing below may be skipped by
    # one failing step: a group, message or event lost here is never re-sent.
    # Each group is isolated, and the dispatches go LAST — sequential dispatch
    # (CLI poll) waits on approvals, which must not hold back the messages.
    routing = cfg.routing()
    items: list[dict] = []
    for g in dec.groups:
        try:
            item = await _handle_group(rt, g, routing, run_at)
            if item is not None:
                items.append(item)
        except Exception:
            log.exception("uptime: handling the new outages on %s failed", g.host)

    for m in dec.messages:
        try:
            await rt.notify(m)
        except Exception:
            log.exception("uptime: notify failed")
    try:
        if dec.loki_events:
            await rt.emit_loki(dec.loki_events)
        if dec.state_changed:
            await rt.emit_loki([compute_state(store.open_rows(), routing=routing,
                                              trigger=TRIGGER,
                                              last_run_ms=int(time.time() * 1000))])
    except Exception:
        log.exception("uptime: Loki events failed")

    dispatched = 0
    if items:
        try:
            await dispatch_all(rt, items, concurrent=dispatch_concurrently,
                               trigger=TRIGGER)
            dispatched = len(items)
        except Exception:
            log.exception("uptime: dispatching %d investigation(s) failed", len(items))
    counters["uptime_dispatches"] = dispatched
    return counters


async def _handle_group(rt: Runtime, g, routing, run_at: str) -> dict | None:
    """Announce one host's new outages; returns its dispatch item, if any.

    A group that joins a pending investigation is announced here and needs no
    dispatch. If folding in fails (or the investigation left
    ``pending_approval``), the group is a fresh outage with its own prompt."""
    if g.pending_investigation_id is not None:
        try:
            joined = extend_pending_investigation(rt, g.pending_investigation_id,
                                                  g.findings)
        except Exception:
            log.exception("uptime: folding %s into pending investigation #%s "
                          "failed — dispatching fresh", g.host,
                          g.pending_investigation_id)
            joined = False
        if joined:
            await rt.notify(g.headline)
            return None
        g.headline = down_headline(g.host, g.items, True, True, None,
                                   run_at, rt.config.settings.timezone)
        g.pending_investigation_id = None
    if not g.investigable:
        await rt.notify(g.headline)
        return None
    return {**g.rows[0],
            "hostRole": host_role_for(g.host, routing),
            "sshHost": ssh_host_for(g.host, routing),
            "findings": g.findings, "headline": g.headline}
