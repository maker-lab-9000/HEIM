"""Dead-man's switch ping (roadmap §5.7).

Closes the "who watches the watcher" gap: HEIM cannot alert on the box it runs
on dying, so an *external* service (healthchecks.io, Uptime Kuma's push
monitor, an HA webhook — anything that accepts a bare GET) is told "still
alive" on a schedule and shouts when the pings stop.

The ping means **"HEIM is alive and polling"**, not "something happened": it
fires after *every* completed poll cycle, including the (normal) no-op ones.
A silent poller is exactly the failure this is here to catch.

Only the **daemon loop** pings — never a CLI one-off run. The switch monitors
the scheduler; an ad-hoc ``heim poll`` from a laptop would otherwise reset the
grace timer and hide a daemon that has been dead for hours.

Fire-and-forget like every other side channel (§2): a failure is one WARNING
line, never an exception and never a traceback.
"""
from __future__ import annotations

import logging

import httpx

log = logging.getLogger(__name__)

#: Generous enough for a slow WAN hop, short enough that a hung endpoint can
#: never stall the poll job for long.
PING_TIMEOUT_SECONDS = 10.0


async def ping(url: str, *, timeout: float = PING_TIMEOUT_SECONDS) -> bool:
    """GET ``url`` to signal liveness. Returns True when the ping landed.

    An empty URL means the switch is disabled (returns False without any I/O).
    """
    if not url:
        return False
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
        if r.status_code >= 300:
            log.warning("dead-man ping HTTP %s: %s", r.status_code, r.text[:200])
            return False
        return True
    except Exception as exc:
        # One line, no stack trace: a missed ping is the monitored service's
        # problem to report, not something the daemon can act on.
        log.warning("dead-man ping failed: %s: %s", type(exc).__name__, exc)
        return False
