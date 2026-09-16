"""Home Assistant API path guard.

Faithful port of the ``Guard Path`` n8n Code node from the PAM-42 HA API
tool workflow (``reference/pam-42-ha-api/guard-path.js``).

GET-only read allowlist mirroring the SSH guard philosophy: default deny.
Strips a full ``http(s)://host`` prefix if the model passed one, forces a
leading slash, blocks whitespace / backslash / ``..``, then matches the
cleaned path against a fixed allowlist of read-only ``/api/`` endpoints.
"""

from __future__ import annotations

import re

from heim.guards import GuardResult

_URL_PREFIX = re.compile(r"^https?://[^/]+", re.IGNORECASE)
_BAD_CHARS = re.compile(r"\s|\\|\.\.")

_ALLOW: tuple[re.Pattern[str], ...] = (
    re.compile(r"^/api/$"),
    re.compile(r"^/api/config$"),
    re.compile(r"^/api/error_log$"),
    re.compile(r"^/api/states(/[A-Za-z0-9_.]+)?$"),
    re.compile(r"^/api/logbook(/[0-9TZz:.+\-]+)?(\?[A-Za-z0-9_.,&=%:+\-]*)?$"),
    re.compile(r"^/api/history/period(/[0-9TZz:.+\-]+)?(\?[A-Za-z0-9_.,&=%:+\-]*)?$"),
)


def guard_ha_path(path: str) -> GuardResult:
    """Check a Home Assistant API path against the read-only allowlist.

    Returns ``GuardResult`` with ``normalized`` set to the cleaned path
    (leading slash forced, full-URL prefix stripped) starting with ``/api/``
    when allowed.
    """
    cleaned = ("" if path is None else str(path)).strip()
    cleaned = _URL_PREFIX.sub("", cleaned, count=1)
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned

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
