"""Pure half of the Uptime Kuma alert source (no I/O).

Parses Uptime Kuma's Prometheus-format ``/metrics`` text, derives each
monitor's target and address, maps an address to a HEIM host and decides which
hosts are investigable. The pipeline (fetch, store, notify) lives elsewhere;
see docs/superpowers/specs/2026-11-01-uptime-kuma-design.md.

Address mapping compares the WHOLE address, never a prefix: a k8s node at
10.0.0.24 must not resolve to the Proxmox host at 10.0.0.2.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from heim.incidents.types import HostRouting

PREFIX = "[uptime] "
QID = "uptime_down"
KUMA_QID = "uptime_kuma_up"
CATEGORY = "availability"

RESOLVE_AFTER = 2
ABSENT_AFTER = 2
UNREACHABLE_AFTER = 2
FLAP_WINDOW_S = 3600

DOWN, UP, PENDING, MAINTENANCE = 0, 1, 2, 3

_LINE_RE = re.compile(r"^monitor_status\{(.*)\}\s+(\S+)\s*$")
_LABEL_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
_ESCAPES = {"\\": "\\", '"': '"', "n": "\n"}
_UNESCAPE_RE = re.compile(r"\\(.)")


@dataclass(frozen=True)
class Monitor:
    monitor_id: str
    name: str
    type: str
    target: str
    address: str
    status: int


def _unescape(value: str) -> str:
    return _UNESCAPE_RE.sub(lambda m: _ESCAPES.get(m.group(1), m.group(0)), value)


def target_of(labels: dict[str, str]) -> tuple[str, str]:
    """Return ``(target, address)`` for a monitor's labels."""
    url = labels.get("monitor_url", "")
    if "://" in url:
        host = urlsplit(url).hostname
        if host:
            return url, host.lower()
    hostname = labels.get("monitor_hostname", "")
    if hostname == "null":
        hostname = ""
    port = labels.get("monitor_port", "")
    target = hostname if port in ("", "null") else f"{hostname}:{port}"
    return target, hostname.lower()


def parse_metrics(text: str) -> list[Monitor]:
    monitors: list[Monitor] = []
    for line in text.splitlines():
        m = _LINE_RE.match(line)
        if not m:
            continue
        try:
            status = int(float(m.group(2)))
        except ValueError:
            continue
        labels = {k: _unescape(v) for k, v in _LABEL_RE.findall(m.group(1))}
        target, address = target_of(labels)
        monitors.append(
            Monitor(
                monitor_id=labels.get("monitor_id", ""),
                name=labels.get("monitor_name", ""),
                type=labels.get("monitor_type", ""),
                target=target,
                address=address,
                status=status,
            )
        )
    return monitors


def map_host(
    address: str, instance_host_map: dict[str, str], host_names: Iterable[str]
) -> str | None:
    """Map an address to a HEIM host, or None when it is not one of ours."""
    try:
        ipaddress.ip_address(address)
    except ValueError:
        label = address.split(".")[0].lower()
        for name in host_names:
            if name.lower() == label:
                return name
        return None
    for key, host in instance_host_map.items():
        if key.split(":")[0] == address:
            return host
    return None


def is_investigable_host(host: str, routing: HostRouting) -> bool:
    if host in routing.ssh_hosts or host == routing.ha_host:
        return True
    return host == routing.hypervisor_host and CATEGORY in routing.hypervisor_categories


def unmapped_monitors(
    monitors: list[Monitor],
    instance_host_map: dict[str, str],
    host_names: Iterable[str],
) -> list[Monitor]:
    names = list(host_names)
    return [m for m in monitors if map_host(m.address, instance_host_map, names) is None]


def is_uptime_row(row: dict) -> bool:
    return str(row.get("description") or "").startswith(PREFIX)


# ------------------------------------------------------------ the decision


def fingerprint(host: str, monitor_name: str) -> str:
    """``host|uptime_down|name``; a ``|`` in the name becomes ``/`` (3 parts)."""
    return f"{host}|{QID}|{monitor_name.replace('|', '/')}"


def kuma_fingerprint(kuma_host: str) -> str:
    return f"{kuma_host}|{KUMA_QID}|"


@dataclass(frozen=True)
class UptimeContext:
    instance_host_map: dict[str, str]
    host_names: frozenset[str]
    routing: HostRouting
    kuma_host: str
    timezone: str
    suppressed: frozenset[str] = frozenset()
    pending_by_host: dict[str, int] = field(default_factory=dict)


@dataclass
class DownGroup:
    host: str
    rows: list[dict]
    investigable: bool
    pending_investigation_id: int | None
    headline: str
    findings: list[dict]


@dataclass
class UptimeDecision:
    rows_to_upsert: list[dict] = field(default_factory=list)
    state_writes: list[dict] = field(default_factory=list)
    state_clears: list[str] = field(default_factory=list)
    fail_polls: int = 0
    groups: list[DownGroup] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    loki_events: list[dict] = field(default_factory=list)
    state_changed: bool = False


MSG_UNREACHABLE = "⚠️ Can't reach Uptime Kuma: service outages are not being watched."
MSG_KUMA_BACK = "✅ Uptime Kuma is reachable again: watching service outages."


def _int(v: object) -> int:
    try:
        return int(float(v))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _truthy(v: object) -> bool:
    return v is True or str(v) == "true"


def _parse(iso: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return None


def _hhmm(iso: str, tz: str) -> str:
    dt = _parse(iso)
    return dt.astimezone(ZoneInfo(tz)).strftime("%H:%M") if dt else "?"


def _down_minutes(first_seen: str, now_iso: str) -> int:
    a, b = _parse(first_seen), _parse(now_iso)
    if a is None or b is None:
        return 1
    return max(1, round((b - a).total_seconds() / 60))


def _incident_event(fp: str, host: str, severity: str, status: str,
                    description: str, metric: str, now_iso: str,
                    first_seen: str = "", times_seen: int = 0) -> dict:
    """One Loki ``incident`` event; twin of
    ``heim.pipelines.thresholds._incident_event`` (copied, not imported: this
    module is pure). Statuses used here: ``new`` and ``resolved``."""
    fields: dict = {"fingerprint": fp, "finding": description, "metric": metric}
    if status == "resolved":
        fields.update({"sevScore": 1, "resolvedAt": now_iso})
    else:
        fields.update({
            "sevScore": 3 if severity == "critical" else 2,
            "detectedAt": first_seen or now_iso,
            "firstSeen": first_seen,
            "lastSeen": now_iso,
            "timesSeen": times_seen,
        })
    return {"event": "incident",
            "labels": {"host": host, "severity": severity, "status": status,
                       "category": CATEGORY},
            "fields": fields}


def _resolved_row(r: dict, now_iso: str) -> dict:
    return {
        "fingerprint": str(r.get("fingerprint") or ""),
        "host": str(r.get("host") or ""),
        "metric": str(r.get("metric") or ""),
        "severity": str(r.get("severity") or ""),
        "status": "resolved",
        "firstSeen": str(r.get("firstSeen") or ""),
        "lastSeen": str(r.get("lastSeen") or ""),
        "resolvedAt": now_iso,
        "timesSeen": _int(r.get("timesSeen")),
        "missedRuns": 0,
        "description": str(r.get("description") or ""),
        "investigated": _truthy(r.get("investigated")),
    }


def _group_for(host: str, rows: list[dict], mons: list[Monitor], mapped: bool,
               investigable: bool, pending_id: int | None, now_iso: str,
               tz: str) -> DownGroup:
    items = ", ".join(f"{m.name} ({m.target})" for m in mons)
    if pending_id is not None:
        head = (f"🔴 Also down on {host}: {items} · "
                f"added to pending investigation #{pending_id}")
    else:
        head = f"🔴 Down on {host}: {items} · first seen {_hhmm(now_iso, tz)}"
    if not mapped:
        head += "\n(report only: not a HEIM host)"
    elif not investigable:
        head += "\n(report only: no investigation for this host)"
    since = _hhmm(now_iso, tz)
    findings = [{
        "severity": "critical", "host": host, "metric": m.name, "trend": "",
        "fingerprint": r["fingerprint"], "recommendation": "",
        "detail": (f"Uptime Kuma check '{m.name}' ({m.type} {m.target}) has been "
                   f"failing since {since}. Find which container or process on "
                   f"{host} serves {m.target}, whether it is running, its recent "
                   f"logs, and why it stopped."),
    } for r, m in zip(rows, mons)]
    return DownGroup(host, rows, investigable, pending_id, head, findings)


def _unreachable(fail_polls: int, open_by_fp: dict[str, dict], now_iso: str,
                 ctx: UptimeContext) -> UptimeDecision:
    d = UptimeDecision(fail_polls=fail_polls + 1)
    fp = kuma_fingerprint(ctx.kuma_host)
    if d.fail_polls < UNREACHABLE_AFTER or fp in open_by_fp or fp in ctx.suppressed:
        return d
    desc = f"{PREFIX}Uptime Kuma is unreachable: service outages are not being watched"
    d.rows_to_upsert.append({
        "fingerprint": fp, "host": ctx.kuma_host, "metric": "Uptime Kuma",
        "severity": "warning", "status": "open", "firstSeen": now_iso,
        "lastSeen": now_iso, "resolvedAt": "", "timesSeen": 1, "missedRuns": 0,
        "description": desc, "investigated": False,
    })
    d.messages.append(MSG_UNREACHABLE)
    d.loki_events.append(_incident_event(fp, ctx.kuma_host, "warning", "new", desc,
                                         "Uptime Kuma", now_iso, now_iso, 1))
    d.state_changed = True
    return d


def decide(monitors: list[Monitor] | None, open_rows: list[dict],
           states: dict[str, dict], fail_polls: int, now_iso: str,
           ctx: UptimeContext) -> UptimeDecision:
    """Diff one Uptime Kuma poll against open ``[uptime] `` incidents. No I/O.

    ``monitors=None`` is a failed poll: nothing about monitors is written or
    resolved, only the failure counter moves.
    """
    open_by_fp = {str(r["fingerprint"]): r for r in open_rows
                  if r and r.get("fingerprint") and is_uptime_row(r)}
    foreign = {str(r["fingerprint"]) for r in open_rows
               if r and r.get("fingerprint") and not is_uptime_row(r)}
    if monitors is None:
        return _unreachable(fail_polls, open_by_fp, now_iso, ctx)

    d = UptimeDecision(fail_polls=0)
    kuma_fp = kuma_fingerprint(ctx.kuma_host)
    if kuma_fp in open_by_fp and kuma_fp not in ctx.suppressed:
        row = _resolved_row(open_by_fp[kuma_fp], now_iso)
        d.rows_to_upsert.append(row)
        d.messages.append(MSG_KUMA_BACK)
        d.loki_events.append(_incident_event(
            kuma_fp, row["host"], row["severity"], "resolved",
            row["description"], row["metric"], now_iso))
        d.state_changed = True

    names = list(ctx.host_names)
    seen: set[str] = set()
    new_by_host: dict[str, list[tuple[dict, Monitor]]] = {}
    hosts_mapped: dict[str, bool] = {}
    recoveries: dict[str, list[tuple[str, str]]] = {}
    writes: dict[str, dict] = {}
    clears: list[str] = []

    def put(fp: str, **kw) -> None:
        base = dict(states.get(fp) or {})
        cur = {"fingerprint": fp, "up_polls": 0, "absent_polls": 0,
               "last_recovered_at": "", "flap_outages": 0, "flap_msg_at": "",
               **base, **kw}
        if fp not in states or any(states[fp].get(k) != v for k, v in cur.items()):
            writes[fp] = cur

    def resolve(fp: str, r: dict) -> dict:
        row = _resolved_row(r, now_iso)
        d.rows_to_upsert.append(row)
        d.loki_events.append(_incident_event(
            fp, row["host"], row["severity"], "resolved", row["description"],
            row["metric"], now_iso))
        d.state_changed = True
        return row

    for m in monitors:
        mapped_host = map_host(m.address, ctx.instance_host_map, names)
        host = mapped_host or m.address
        fp = fingerprint(host, m.name)
        seen.add(fp)
        if fp in ctx.suppressed or fp in foreign:  # foreign row: never duplicate
            continue
        r = open_by_fp.get(fp)
        st = states.get(fp) or {}
        if m.status == DOWN:
            if r is not None:
                d.rows_to_upsert.append({
                    "fingerprint": fp, "host": str(r.get("host") or host),
                    "metric": str(r.get("metric") or m.name),
                    "severity": str(r.get("severity") or "critical"),
                    "status": "open",
                    "firstSeen": str(r.get("firstSeen") or now_iso),
                    "lastSeen": now_iso, "resolvedAt": "",
                    "timesSeen": _int(r.get("timesSeen")) + 1, "missedRuns": 0,
                    "description": str(r.get("description") or ""),
                    "investigated": _truthy(r.get("investigated")),
                })
                if st.get("up_polls") or st.get("absent_polls"):
                    put(fp, up_polls=0, absent_polls=0)
                continue
            investigable = mapped_host is not None and is_investigable_host(mapped_host, ctx.routing)
            pending = ctx.pending_by_host.get(host) if investigable else None
            row = {
                "fingerprint": fp, "host": host, "metric": m.name,
                "severity": "critical", "status": "open", "firstSeen": now_iso,
                "lastSeen": now_iso, "resolvedAt": "", "timesSeen": 1,
                "missedRuns": 0,
                "description": f"{PREFIX}{m.name} ({m.type} {m.target}) is down in Uptime Kuma",
                "investigated": investigable,
            }
            d.rows_to_upsert.append(row)
            d.loki_events.append(_incident_event(
                fp, host, "critical", "new", row["description"], m.name,
                now_iso, now_iso, 1))
            d.state_changed = True
            new_by_host.setdefault(host, []).append((row, m))
            hosts_mapped[host] = mapped_host is not None
            if st.get("up_polls") or st.get("absent_polls"):
                put(fp, up_polls=0, absent_polls=0)
        elif m.status == UP:
            if r is None:
                continue
            ups = _int(st.get("up_polls")) + 1
            if ups >= RESOLVE_AFTER:
                row = resolve(fp, r)
                put(fp, up_polls=0, absent_polls=0, last_recovered_at=now_iso)
                recoveries.setdefault(row["host"], []).append((
                    row["firstSeen"], f"{row['metric']} (down {_down_minutes(row['firstSeen'], now_iso)} min)"))
            else:
                put(fp, up_polls=ups, absent_polls=0)
        else:  # pending / maintenance: no change, but the monitor is present
            if st.get("absent_polls"):
                put(fp, absent_polls=0)

    for fp, r in open_by_fp.items():
        if fp == kuma_fp or fp in seen or fp in ctx.suppressed:
            continue
        absent = _int((states.get(fp) or {}).get("absent_polls")) + 1
        if absent >= ABSENT_AFTER:
            row = resolve(fp, r)
            clears.append(fp)
            writes.pop(fp, None)
            d.messages.append(
                f"⏸ {row['metric']} on {row['host']} is no longer monitored "
                f"(paused or removed): closing its outage")
        else:
            put(fp, absent_polls=absent)

    # drop state that has nothing left to remember
    now_dt = _parse(now_iso)
    for fp, st in states.items():
        if fp in clears or fp in writes or fp in open_by_fp:
            continue
        if any(fp == r["fingerprint"] for r, _ in
               (x for v in new_by_host.values() for x in v)):
            continue
        if _int(st.get("flap_outages")):
            continue
        rec = _parse(st.get("last_recovered_at") or "")
        if rec is None or now_dt is None or (now_dt - rec).total_seconds() > FLAP_WINDOW_S:
            clears.append(fp)

    for host, pairs in new_by_host.items():
        rows = [p[0] for p in pairs]
        mons = [p[1] for p in pairs]
        mapped = hosts_mapped[host]
        inv = mapped and is_investigable_host(host, ctx.routing)
        pending = ctx.pending_by_host.get(host) if inv else None
        d.groups.append(_group_for(host, rows, mons, mapped, inv, pending,
                                   now_iso, ctx.timezone))
    for host, parts in recoveries.items():
        d.messages.append(f"✅ Back up on {host}: " + ", ".join(p for _, p in sorted(parts, key=lambda x: x[0])))

    d.state_writes = list(writes.values())
    d.state_clears = clears
    return d
