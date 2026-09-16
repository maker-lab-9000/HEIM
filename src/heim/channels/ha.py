"""Home Assistant sensor push (port of the n8n 'Send to HA' HTTP nodes).

Creates/updates ``sensor.pam_*`` entities so reports show up on HA dashboards.
"""
from __future__ import annotations

import logging
import re

import httpx

log = logging.getLogger(__name__)


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
    except Exception:  # HA push must never sink a pipeline
        log.exception("HA sensor push failed (%s)", entity_suffix)
