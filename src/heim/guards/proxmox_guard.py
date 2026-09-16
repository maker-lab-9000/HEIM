"""Proxmox API path guard.

Faithful port of the ``Guard Path`` n8n Code node from the PAM-44 Proxmox API
tool workflow (``reference/pam-44-proxmox-api/guard-path.js``).

GET-only read allowlist, default deny. Strips a full ``http(s)://host``
prefix, forces a leading slash, tolerates a missing ``/api2/json`` prefix on
``/nodes``, ``/cluster`` and ``/version`` paths (auto-prepends it), blocks
whitespace / backslash / ``..``, then matches against a fixed allowlist of
read-only endpoints on node ``homelab`` (the task-UPID charset includes ``@``).
"""

from __future__ import annotations

import re

from heim.guards import GuardResult

_URL_PREFIX = re.compile(r"^https?://[^/]+", re.IGNORECASE)
_MISSING_PREFIX = re.compile(r"^/(nodes|cluster|version)\b")
_BAD_CHARS = re.compile(r"\s|\\|\.\.")

# Query-string charset (same as the JS `Q`).
_Q = r"(\?[A-Za-z0-9_.,&=%:+/\-]*)?"
_N = "/api2/json/nodes/homelab"

_ALLOW: tuple[re.Pattern[str], ...] = (
    re.compile(r"^/api2/json/version$"),
    re.compile(r"^/api2/json/cluster/resources" + _Q + r"$"),
    re.compile("^" + _N + r"/status$"),
    re.compile("^" + _N + r"/qemu$"),
    re.compile("^" + _N + r"/qemu/\d+/(status/current|config)$"),
    re.compile("^" + _N + r"/tasks" + _Q + r"$"),
    re.compile("^" + _N + r"/tasks/[A-Za-z0-9:.@_%\-]+/(log|status)" + _Q + r"$"),
    re.compile("^" + _N + r"/(syslog|journal)" + _Q + r"$"),
    re.compile("^" + _N + r"/disks/list$"),
    re.compile("^" + _N + r"/disks/smart\?disk=(%2Fdev%2F|/dev/)[a-z0-9]+$"),
    re.compile("^" + _N + r"/storage(/[A-Za-z0-9_\-]+(/status|/content)?)?" + _Q + r"$"),
)


def guard_proxmox_path(path: str) -> GuardResult:
    """Check a Proxmox API path against the read-only allowlist.

    Returns ``GuardResult`` with ``normalized`` set to the full cleaned path
    including the ``/api2/json`` prefix.
    """
    cleaned = ("" if path is None else str(path)).strip()
    cleaned = _URL_PREFIX.sub("", cleaned, count=1)
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    if _MISSING_PREFIX.search(cleaned):
        cleaned = "/api2/json" + cleaned

    if _BAD_CHARS.search(cleaned):
        return GuardResult(
            allowed=False,
            reason='path contains whitespace, backslash or ".."',
            normalized=cleaned,
        )
    if not any(rx.search(cleaned) for rx in _ALLOW):
        return GuardResult(
            allowed=False,
            reason="endpoint not in the read-only allowlist",
            normalized=cleaned,
        )
    return GuardResult(allowed=True, normalized=cleaned)
