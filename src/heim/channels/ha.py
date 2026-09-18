"""Home Assistant sensor push (port of the n8n 'Send to HA' HTTP nodes).

Creates/updates ``sensor.pam_*`` entities so reports show up on HA dashboards.
"""
from __future__ import annotations

import logging
import re

import httpx

log = logging.getLogger(__name__)


#: What a rejected push usually means. An HTTP error here is a configuration
#: problem, not a bug, so it gets one actionable WARNING line instead of a
#: stack trace nobody can act on.
_HTTP_HINTS = {
    401: "check HA_TOKEN (long-lived token from a non-admin user)",
    403: "check HA_TOKEN (long-lived token from a non-admin user)",
    404: "check HA_BASE_URL — the core API serves /api/states",
}
_HTTP_HINT_DEFAULT = "check HA_BASE_URL and HA_TOKEN"


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(s).lower()).strip("_")


async def post_sensor(base_url: str, token: str, entity_suffix: str, state: str, attributes: dict) -> None:
    url = f"{base_url.rstrip('/')}/api/states/sensor.pam_{entity_suffix}"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                url,
                headers={"Authorization": f"Bearer {token}"},
                json={"state": state, "attributes": attributes},
            )
            r.raise_for_status()
    except httpx.HTTPStatusError as exc:
        # HA answered, it just said no: one line, no traceback — the status code
        # and what to check are the whole diagnosis.
        code = exc.response.status_code
        log.warning("HA sensor push failed (%s): HTTP %s — %s", entity_suffix, code,
                    _HTTP_HINTS.get(code, _HTTP_HINT_DEFAULT))
    except Exception:  # HA push must never sink a pipeline
        log.exception("HA sensor push failed (%s)", entity_suffix)
