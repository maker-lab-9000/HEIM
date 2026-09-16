"""Dashboard state snapshot derivation.

Port of the n8n Code node **"Compute State" (PAM 51)** —
``reference/pam-51-state-snapshot-loki/compute-state.js``.

Input/output adaptations from the JS (each documented, behavior otherwise
faithful):

* The JS pulled rows from the ``Get Open Incidents`` node and ``trigger``
  from its input item. Here ``open_rows`` is a plain parameter (filtered the
  same way: truthy rows with a ``fingerprint``), and ``trigger`` is an
  optional keyword defaulting to ``'run'`` — the JS default when the input
  carried no trigger.
* ``lastRunMs`` / ``lastRunTs`` came from ``Date.now()`` / ``new Date()``.
  To keep the function pure, ``last_run_ms`` can be injected; only when it is
  ``None`` does the function fall back to the wall clock (matching the JS).
  Both fields are derived from the same instant, as in the JS.
* The JS hardcoded ``agentOk: 1`` and ``agentStatus: 'Healthy'``. The
  ``agent_ok`` keyword parameterizes that: ``True`` (default) reproduces the
  JS output exactly; ``False`` emits ``agentOk: 0`` / ``agentStatus:
  'Unhealthy'``.
* The JS hardcoded ``SSH_HOSTS`` / ``HYPERVISOR_HOST`` / ``HOMELAB_CATS``.
  An optional ``routing`` keyword (:class:`~heim.incidents.types.HostRouting`)
  replaces them; when omitted, defaults identical to the JS constants are
  used. Note this node's ``investigable`` has **no** HA-host branch (unlike
  the reconciler's), so ``routing.ha_host`` is deliberately ignored here.

The returned dict is the full Loki event envelope the node emitted:
``{"event": "state", "labels": {}, "fields": {...}}``.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone

from heim.incidents.reconcile import to_bool
from heim.incidents.types import HostRouting

__all__ = ["category_of", "investigable", "compute_state"]

#: JS constants from compute-state.js, used when no routing is supplied.
_DEFAULT_ROUTING = HostRouting(
    ssh_hosts=frozenset({"ubuntu-server"}),
    hypervisor_host="homelab",
    hypervisor_categories=frozenset({"cpu", "memory", "temperature", "disk", "diskHealth"}),
    ha_host=None,
)

_CPU_RE = re.compile(r"cpu|load|processor")
_MEM_RE = re.compile(r"mem|swap|oom")
_TEMP_RE = re.compile(r"temp|thermal|celsius")
_DISK_HEALTH_RE = re.compile(r"smart|nvme|wear|spare|media err|crc")
_FS_RE = re.compile(r"fs|filesystem|disk|inode|pool|mount|/")
_NET_RE = re.compile(r"net|tcp|nic|rx|tx")


def category_of(metric: object) -> str:
    """Port of the JS ``categoryOf`` in compute-state.js (metric-only regex
    version — distinct from the reconciler's fingerprint-aware one; note it
    uses ``filesystem`` where the reconciler says ``disk``)."""
    q = str(metric or "").lower()
    if _CPU_RE.search(q):
        return "cpu"
    if _MEM_RE.search(q):
        return "memory"
    if _TEMP_RE.search(q):
        return "temperature"
    if _DISK_HEALTH_RE.search(q):
        return "diskHealth"
    if _FS_RE.search(q):
        return "filesystem"
    if _NET_RE.search(q):
        return "network"
    return "other"


def investigable(host: str, cat: str, routing: HostRouting) -> bool:
    """Port of the JS ``investigable`` in compute-state.js: SSH hosts always;
    the hypervisor for its category set (with the ``filesystem`` -> ``disk``
    mapping quirk); no HA-host branch in this node."""
    if host in routing.ssh_hosts:
        return True
    if routing.hypervisor_host is not None and host == routing.hypervisor_host:
        return ("disk" if cat == "filesystem" else cat) in routing.hypervisor_categories
    return False


def _iso_ms(ms: int) -> str:
    """JS ``Date(ms).toISOString()`` equivalent (millisecond precision, Z)."""
    dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def compute_state(open_rows: list[dict], *, agent_ok: bool = True,
                  last_run_ms: int | None = None, trigger: str = "run",
                  routing: HostRouting | None = None) -> dict:
    """Derive the dashboard state snapshot Loki event from open incident rows.

    Port of the PAM 51 "Compute State" Code node; see the module docstring
    for the documented input adaptations.
    """
    if routing is None:
        routing = _DEFAULT_ROUTING
    rows = [r for r in open_rows if r and r.get("fingerprint")]

    risk = {"filesystem": 0, "diskHealth": 0, "temperature": 0,
            "memory": 0, "cpu": 0, "network": 0}
    critical = 0
    warn = 0
    pending = 0
    for r in rows:
        sev = str(r.get("severity") or "").lower()
        cat = category_of(r.get("metric"))
        if cat in risk:
            risk[cat] += 1
        if sev in ("critical", "crit"):
            critical += 1
        elif sev in ("warning", "warn"):
            warn += 1
        if not to_bool(r.get("investigated")) and investigable(str(r.get("host") or ""), cat, routing):
            pending += 1

    active = len(rows)
    overall_health = "Critical" if critical > 0 else ("Warning" if warn > 0 else "Healthy")
    health_score = 2 if critical > 0 else (1 if warn > 0 else 0)
    now_ms = int(time.time() * 1000) if last_run_ms is None else last_run_ms

    fields = {
        "overallHealth": overall_health,
        "healthScore": health_score,
        "lastRunMs": now_ms,
        "agentOk": 1 if agent_ok else 0,
        "activeIncidents": active,
        "pendingApproval": pending,
        "criticalCount": critical,
        "warnCount": warn,
        "riskByCategory": risk,
        "lastRunTs": _iso_ms(now_ms),
        "lastRunStatus": "success",
        "agentStatus": "Healthy" if agent_ok else "Unhealthy",
        "trigger": str(trigger),
    }
    return {"event": "state", "labels": {}, "fields": fields}
