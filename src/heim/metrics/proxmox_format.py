"""Proxmox API response formatter.

Faithful port of the ``Format Output`` n8n Code node from the PAM-44 Proxmox
API tool workflow (``reference/pam-44-proxmox-api/format-output.js``).

Compacts the verbose ``/tasks`` LIST response (not ``/tasks/<upid>/log``):
drops node/pid/pstart noise, converts epoch times to UTC ISO and adds
``durationSec``, keeps ``user`` only when it differs from ``root@pam``, and
keeps ``upid`` only for backup-type (vzdump/migrate/restore/replicat/move/
resize) or non-OK tasks. Task-log endpoints and malformed JSON pass through
untouched. Finally clips the body to ``clip`` characters, appending
`` ...[truncated]``.

Note: the n8n node clipped at 8000 chars; here the limit is a parameter with
a mandated default of 8192.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

_TASKS_LIST = re.compile(r"/tasks(\?|$)")
_UPID_TYPES = re.compile(r"vzdump|migrate|restore|replicat|move|resize")


def _iso(ts: float) -> str:
    """Epoch seconds -> UTC ISO without milliseconds, matching the JS
    ``new Date(ts*1000).toISOString().slice(0,19)+'Z'``."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def _dumps(obj: Any) -> str:
    """JSON.stringify-equivalent: compact separators, no ASCII escaping."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def format_proxmox_output(path: str, body_text: str, clip: int = 8192) -> str:
    """Format a Proxmox API response body for the agent.

    ``path`` is the guarded request path (used only to detect the /tasks
    list endpoint); ``body_text`` is the raw response body as a string.
    """
    body = body_text

    # Compact the verbose /tasks LIST response (not /tasks/<upid>/log).
    if _TASKS_LIST.search(path or ""):
        try:
            p = json.loads(body)
            if isinstance(p, dict) and isinstance(p.get("data"), list):
                tasks: list[dict[str, Any]] = []
                for t in p["data"]:
                    if not isinstance(t, dict):
                        # JS property access on a primitive yields undefined;
                        # mirror that instead of raising.
                        t = {}
                    o: dict[str, Any] = {}
                    # JS assigns type/id/status unconditionally; undefined
                    # (missing) values are dropped by JSON.stringify.
                    if "type" in t:
                        o["type"] = t["type"]
                    if "id" in t:
                        o["id"] = t["id"]
                    if "status" in t:
                        o["status"] = t["status"]
                    starttime = t.get("starttime")
                    o["start"] = _iso(starttime) if starttime else None
                    endtime = t.get("endtime")
                    if endtime:
                        o["end"] = _iso(endtime)
                        if starttime:
                            o["durationSec"] = endtime - starttime
                    user = t.get("user")
                    if user and user != "root@pam":
                        o["user"] = user
                    upid = t.get("upid")
                    if upid and (
                        t.get("status") != "OK"
                        or _UPID_TYPES.search(str(t.get("type")))
                    ):
                        o["upid"] = upid
                    tasks.append(o)
                total = p.get("total")
                body = _dumps(
                    {
                        "total": total if total is not None else len(tasks),
                        "tasks": tasks,
                        "note": "epoch times converted to UTC ISO; upid included only for backup-type or failed tasks (needed for /tasks/<upid>/log)",
                    }
                )
        except Exception:
            pass  # malformed JSON (or bad timestamps): pass body through untouched

    if len(body) > clip:
        body = body[:clip] + " ...[truncated]"
    return body
