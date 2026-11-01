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
from dataclasses import dataclass
from urllib.parse import urlsplit

from heim.incidents.types import HostRouting

PREFIX = "[uptime] "
QID = "uptime_down"
KUMA_QID = "uptime_kuma_up"
CATEGORY = "availability"

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
