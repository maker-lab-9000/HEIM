"""Pure alert-poller diff logic.

Port of the n8n "PAM 11 - Alert Poller" **Diff & Decide** Code node
(``reference/pam-11-alert-poller/diff-decide.js``).

Fast-path alert diff over the Prometheus ``/api/v1/alerts`` response:

- only ``firing`` alerts are considered (``pending`` is flap-suppressed by
  the rules' ``for:`` durations);
- if the response status is not ``success`` the whole poll is aborted —
  no writes, and above all no false resolves;
- rows are written only on state change: new alert, warning->critical
  escalation, ``missedRuns`` reset, or resolve after 2 consecutive clear
  polls;
- the poller resolves ONLY incidents whose description starts with
  ``[alert] `` (poller-owned rows);
- declined incidents (``investigated=false``) are NOT re-dispatched here —
  the daily reconcile owns re-proposal.

Parameterization vs the JS (documented judgment calls):

- the hardcoded ``HOSTMAP`` IP-prefix table is replaced by
  ``instance_host_map`` (prefix -> host). Like the JS array, entries are
  matched in insertion order with ``str.startswith``, so put longer/more
  specific prefixes first;
- the JS hardcoded ``'homelab'`` for alerts carrying a PVE ``id`` label is
  replaced by ``routing.hypervisor_host`` (falling back to ``'unknown'``
  when unset);
- the JS hardcoded ``'ubuntu-server'`` for ``container_*`` /
  ``n8n_net_spike`` alerts ("all containers live on ubuntu-server") is
  replaced by the first SSH host from ``routing.ssh_hosts`` in sorted order
  (deterministic since frozensets are unordered), falling back to
  ``'unknown'`` when there is none. With a single SSH host — the original
  deployment — this is exactly the JS behavior.
"""
from __future__ import annotations

from heim.incidents.types import HostRouting, PollerDecision

_CPU_QIDS = ("cpu_busy", "load_per_core", "cpu_psi", "procs_blocked")
_MEMORY_QIDS = ("mem_used", "swap_used", "oom")
_TEMPERATURE_QIDS = ("drive_temp", "host_temp_max", "chip_temp")
_DISK_HEALTH_QIDS = (
    "smart_status",
    "nvme_wear",
    "spare",
    "media_err",
    "errlog",
    "sda_wear",
    "sdb_crc",
)
_DISK_QIDS = ("fs_used", "inodes_used", "pve_pool_used")
_NETWORK_QIDS = ("net_err", "n8n_net_spike")


def _category_of_qid(qid: str) -> str:
    """Port of the JS ``categoryOfQid``."""
    if qid in _CPU_QIDS:
        return "cpu"
    if qid in _MEMORY_QIDS:
        return "memory"
    if qid in _TEMPERATURE_QIDS:
        return "temperature"
    if qid in _DISK_HEALTH_QIDS:
        return "diskHealth"
    if qid in _DISK_QIDS:
        return "disk"
    if qid in _NETWORK_QIDS:
        return "network"
    if qid == "container_cpu_dev":
        return "cpu"
    if qid == "container_mem_dev":
        return "memory"
    if qid == "container_fs_growth":
        return "disk"
    if qid.startswith("container_"):
        return "container"
    return "other"


def _name_for(qid: str, labels: dict) -> str:
    """Port of the JS ``nameFor`` — per-qid fingerprint name rules."""
    if qid in ("fs_used", "inodes_used"):
        return (
            (labels.get("device") or "") + " " + (labels.get("mountpoint") or "")
        ).strip()
    if qid in ("drive_temp", "smart_status", "media_err", "sdb_crc", "net_err"):
        return labels.get("device") or ""
    if qid.startswith("pve_"):
        return labels.get("id") or ""
    if qid == "exporter_up":
        return labels.get("job") or ""
    if qid.startswith("container_"):
        return labels.get("name") or ""
    if qid == "n8n_net_spike":
        return "n8n"
    return ""


def _investigable(host: str, category: str, routing: HostRouting) -> bool:
    """Port of the JS ``investigable`` (SSH_HOSTS / HOMELAB_CATS lookup)."""
    if host in routing.ssh_hosts:
        return True
    if routing.hypervisor_host is not None and host == routing.hypervisor_host:
        return category in routing.hypervisor_categories
    return False


def _int(v: object) -> int:
    """JS ``Number(v) || 0`` for the integer counters."""
    if v is None or v == "":
        return 0
    try:
        return int(float(v))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _truthy(v: object) -> bool:
    """JS ``v === true || String(v) === 'true'``."""
    return v is True or str(v) == "true"


def diff_and_decide(
    alerts_resp: dict,
    open_rows: list[dict],
    now_iso: str,
    routing: HostRouting,
    instance_host_map: dict[str, str],
) -> PollerDecision:
    """Diff firing alerts against open incident rows and decide on writes.

    Port of the n8n "Diff & Decide" Code node (PAM 11 - Alert Poller).

    Args:
        alerts_resp: Prometheus ``/api/v1/alerts`` response body.
        open_rows: currently-open incident rows from the datatable.
        now_iso: current time as an ISO-8601 string (injected for purity).
        routing: host investigability routing (SSH hosts, hypervisor).
        instance_host_map: instance-label address prefix -> host name,
            matched in insertion order (replaces the JS hardcoded HOSTMAP).
    """
    if str(alerts_resp.get("status")) != "success":
        # Prometheus unreachable or errored — do NOTHING (especially no
        # false resolves).
        return PollerDecision(aborted="prometheus unreachable")

    data = alerts_resp.get("data") or {}
    alerts = data.get("alerts") or []
    open_ = [r for r in open_rows if r and r.get("fingerprint")]

    container_host = (
        sorted(routing.ssh_hosts)[0] if routing.ssh_hosts else "unknown"
    )
    hypervisor_host = routing.hypervisor_host or "unknown"

    def host_of(instance: object) -> str:
        s = str(instance or "")
        for prefix, host in instance_host_map.items():
            if s.startswith(prefix):
                return host
        return "unknown"

    # --- build the current firing set, deduped by fingerprint ---
    current: dict[str, dict] = {}
    for a in alerts:
        if not a or a.get("state") != "firing":
            # ignore pending — `for:` durations do the flap suppression
            continue
        labels = a.get("labels") or {}
        annotations = a.get("annotations") or {}
        qid = str(labels.get("qid") or "unknown")
        # all containers live on the SSH host; PVE-exporter metrics (id
        # label) belong to the hypervisor
        if qid.startswith("container_") or qid == "n8n_net_spike":
            host = container_host
        elif labels.get("id"):
            host = hypervisor_host
        else:
            host = host_of(labels.get("instance"))
        sev = (
            "critical"
            if str(labels.get("severity") or "warning").lower() == "critical"
            else "warning"
        )
        nm = _name_for(qid, labels)
        fp = f"{host}|{qid}|{nm}"
        rec = {
            "fingerprint": fp,
            "host": host,
            "qid": qid,
            "metric": str(labels.get("alertname") or qid) + (f" {nm}" if nm else ""),
            "severity": sev,
            "description": "[alert] "
            + str(
                annotations.get("description")
                or annotations.get("summary")
                or labels.get("alertname")
                or ""
            ),
            "category": _category_of_qid(qid),
        }
        if fp not in current or (
            sev == "critical" and current[fp]["severity"] != "critical"
        ):
            current[fp] = rec

    open_by_fp = {r["fingerprint"]: r for r in open_}
    rows: list[dict] = []
    dispatch: list[dict] = []
    notify: list[dict] = []
    loki: list[dict] = []

    # --- firing alerts: new / escalated / missedRuns-reset ---
    for fp, c in current.items():
        prev = open_by_fp.get(fp)
        will_inv = _investigable(c["host"], c["category"], routing)
        if prev is None:
            rows.append(
                {
                    "fingerprint": fp,
                    "host": c["host"],
                    "metric": c["metric"],
                    "severity": c["severity"],
                    "status": "open",
                    "firstSeen": now_iso,
                    "lastSeen": now_iso,
                    "resolvedAt": "",
                    "timesSeen": 1,
                    "missedRuns": 0,
                    "description": c["description"],
                    "investigated": will_inv,
                }
            )
            if will_inv:
                dispatch.append(c)
            elif c["severity"] == "critical":
                notify.append(c)
            loki.append(
                {
                    "event": "incident",
                    "labels": {
                        "host": c["host"],
                        "severity": c["severity"],
                        "status": "new",
                        "category": c["category"],
                    },
                    "fields": {
                        "fingerprint": fp,
                        "finding": c["description"],
                        "metric": c["metric"],
                        "sevScore": 3 if c["severity"] == "critical" else 2,
                        "detectedAt": now_iso,
                        "firstSeen": now_iso,
                        "lastSeen": now_iso,
                        "timesSeen": 1,
                    },
                }
            )
        else:
            was_crit = "crit" in str(prev.get("severity") or "").lower()
            if c["severity"] == "critical" and not was_crit:
                rows.append(
                    {
                        "fingerprint": fp,
                        "host": str(prev.get("host") or c["host"]),
                        "metric": c["metric"],
                        "severity": "critical",
                        "status": "open",
                        "firstSeen": str(prev.get("firstSeen") or now_iso),
                        "lastSeen": now_iso,
                        "resolvedAt": "",
                        "timesSeen": _int(prev.get("timesSeen")) + 1,
                        "missedRuns": 0,
                        "description": c["description"],
                        "investigated": True
                        if will_inv
                        else _truthy(prev.get("investigated")),
                    }
                )
                if will_inv:
                    dispatch.append(c)
                loki.append(
                    {
                        "event": "incident",
                        "labels": {
                            "host": c["host"],
                            "severity": "critical",
                            "status": "escalated",
                            "category": c["category"],
                        },
                        "fields": {
                            "fingerprint": fp,
                            "finding": c["description"],
                            "metric": c["metric"],
                            "sevScore": 3,
                            "detectedAt": str(prev.get("firstSeen") or now_iso),
                            "firstSeen": str(prev.get("firstSeen") or ""),
                            "lastSeen": now_iso,
                            "timesSeen": _int(prev.get("timesSeen")) + 1,
                        },
                    }
                )
            elif _int(prev.get("missedRuns")) > 0:
                rows.append(
                    {
                        "fingerprint": fp,
                        "host": str(prev.get("host") or ""),
                        "metric": str(prev.get("metric") or ""),
                        "severity": str(prev.get("severity") or ""),
                        "status": "open",
                        "firstSeen": str(prev.get("firstSeen") or ""),
                        "lastSeen": now_iso,
                        "resolvedAt": "",
                        "timesSeen": _int(prev.get("timesSeen")),
                        "missedRuns": 0,
                        "description": str(prev.get("description") or ""),
                        "investigated": _truthy(prev.get("investigated")),
                    }
                )
            # unchanged firing -> no write (no churn); declined
            # (investigated=false) -> NOT re-dispatched here (daily
            # reconcile owns re-proposal)

    # --- open rows no longer firing: count missed runs, resolve at 2 ---
    for r in open_:
        fp = str(r["fingerprint"])
        if fp in current:
            continue
        if not str(r.get("description") or "").startswith("[alert]"):
            continue  # only poller-owned incidents
        missed = _int(r.get("missedRuns")) + 1
        base = {
            "fingerprint": fp,
            "host": str(r.get("host") or ""),
            "metric": str(r.get("metric") or ""),
            "severity": str(r.get("severity") or ""),
            "firstSeen": str(r.get("firstSeen") or ""),
            "lastSeen": str(r.get("lastSeen") or ""),
            "timesSeen": _int(r.get("timesSeen")),
            "description": str(r.get("description") or ""),
            "investigated": _truthy(r.get("investigated")),
        }
        if missed >= 2:
            rows.append(
                dict(base, status="resolved", resolvedAt=now_iso, missedRuns=missed)
            )
            parts = fp.split("|")
            qid = parts[1] if len(parts) > 1 else ""
            loki.append(
                {
                    "event": "incident",
                    "labels": {
                        "host": base["host"],
                        "severity": base["severity"],
                        "status": "resolved",
                        "category": _category_of_qid(qid),
                    },
                    "fields": {
                        "fingerprint": fp,
                        "finding": base["description"],
                        "metric": base["metric"],
                        "sevScore": 1,
                        "resolvedAt": now_iso,
                    },
                }
            )
        else:
            rows.append(
                dict(
                    base,
                    status="open",
                    resolvedAt=str(r.get("resolvedAt") or ""),
                    missedRuns=missed,
                )
            )

    return PollerDecision(
        rows_to_upsert=rows,
        dispatches=dispatch,
        notifications=notify,
        loki_events=loki,
        state_changed=len(rows) > 0,
    )
