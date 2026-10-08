"""Load and validate config/security/checks.yaml. Pure.

The catalogue is the ONLY place the audit's reads are defined; the model never
chooses one. So the loader is the gate: a line that is not provably read-only
makes the whole catalogue invalid (startup and `heim check` both fail loudly).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from heim.config import expand_env
from heim.guards import guard_command, guard_ha_path
from heim.security.types import SEVERITIES, CheckSpec, SourceSpec


class CatalogueError(ValueError):
    """The catalogue asks for something the audit must not do."""


_ID_RE = re.compile(r"^[a-z]+\.[a-z0-9_]+$")
_KINDS = ("pve", "ha", "prom", "ssh")
_BAD_CHARS = re.compile(r"\s|\\|\.\.")
_N = r"/api2/json/nodes/homelab"

#: The audit's own GET allowlist against the hypervisor — deliberately wider
#: than heim.guards.proxmox_guard (which bounds what the MODEL may call) and
#: never handed to the model. Every path here answered 200 to the auditor
#: token (PAMAuditor: *.Audit + Sys.Syslog) in the live probe, except
#: /journal, which the investigator uses routinely. Nothing here mutates.
PVE_AUDIT_ALLOW: tuple[re.Pattern[str], ...] = (
    re.compile(r"^/api2/json/version$"),
    re.compile(r"^/api2/json/cluster/resources(\?type=vm)?$"),
    re.compile(r"^/api2/json/cluster/(backup|options|status)$"),
    re.compile(r"^/api2/json/cluster/firewall/(options|rules)$"),
    re.compile(r"^/api2/json/access/(users|acl|roles|tfa|domains|groups)$"),
    re.compile("^" + _N + r"/(status|services|dns|time|apt/versions|apt/repositories|"
               r"certificates/info|firewall/options|firewall/rules)$"),
    re.compile("^" + _N + r"/qemu/\d+/(config|status/current|firewall/options)$"),
    re.compile("^" + _N + r"/tasks\?(typefilter=vzdump&limit=\d{1,3}|errors=1&limit=\d{1,3})$"),
    re.compile("^" + _N + r"/journal\?lastentries=\d{1,4}$"),
)

_SUDO_FILE_READ = re.compile(r"^sudo\s+(-[A-Za-z]+\s+)*(cat|grep)\b", re.IGNORECASE)
_SEGMENT_SPLIT = re.compile(r"&&|\|\||;|\||\n")


def validate_pve_path(path: str, *, key: str = "") -> str:
    p = str(path or "").strip()
    probe = p.replace("{vmid}", "100")
    where = f" ({key})" if key else ""
    if not p.startswith("/api2/json/") or _BAD_CHARS.search(probe):
        raise CatalogueError(f"PVE path must start with /api2/json/ and contain no whitespace/'..'{where}: {p!r}")
    if not any(rx.search(probe) for rx in PVE_AUDIT_ALLOW):
        raise CatalogueError(f"PVE path not on PVE_AUDIT_ALLOW{where}: {p!r}")
    return p


def validate_ha_path(path: str, *, key: str = "") -> str:
    g = guard_ha_path(str(path or ""))
    if not g.allowed:
        raise CatalogueError(f"HA path rejected by guard_ha_path ({key}): {path!r} — {g.reason}")
    return str(path)


def validate_ssh_line(line: str, *, key: str = "") -> str:
    raw = str(line or "").strip()
    probe = raw.replace("{container}", "x")
    g = guard_command(probe)
    where = f" ({key})" if key else ""
    if not g.allowed:
        raise CatalogueError(f"SSH line rejected by guard_command{where}: {raw!r} — {g.reason}")
    for seg in _SEGMENT_SPLIT.split(probe):
        if _SUDO_FILE_READ.match(seg.strip()):
            raise CatalogueError(
                f"SSH line uses sudo cat/grep{where}: {raw!r} — the sudoers scope deliberately "
                f"excludes them; read world-readable files without sudo instead")
    return raw


def validate_promql(expr: str, *, key: str = "") -> str:
    e = str(expr or "").strip()
    if not e or len(e) > 1000:
        raise CatalogueError(f"PromQL must be 1..1000 chars ({key})")
    return e


_VALIDATORS = {"pve": validate_pve_path, "ha": validate_ha_path, "ssh": validate_ssh_line, "prom": validate_promql}


@dataclass
class Catalogue:
    sources: dict[str, SourceSpec]
    checks: list[CheckSpec]
    params: dict = field(default_factory=dict)
    pve_node: str = "homelab"
    ssh_host: str = "ubuntu-server"
    ha_host: str = "home-assistant"

    def check(self, check_id: str) -> CheckSpec:
        for c in self.checks:
            if c.id == check_id:
                return c
        raise KeyError(check_id)

    def by_kind(self, kind: str) -> list[SourceSpec]:
        return [s for s in self.sources.values() if s.kind == kind]


#: Check params that are port → label maps. Either a YAML mapping, or — so a
#: deployment's port inventory can live in .env instead of git — a string
#: "port[:label],port[:label],..." (typically filled from ${HEIM_*}).
_PORT_MAP_PARAMS = ("expected_ports", "critical_ports")
_PORT_ITEM_RE = re.compile(r"^(\d{1,5})(?::([A-Za-z0-9_.+\- ]*))?$")


def parse_port_map(value, *, name: str) -> dict[str, str]:
    """``port[:label]`` items (string or mapping) → ``{"port": "label"}``.

    Validated here so a typo in .env fails at startup and in ``heim check``
    instead of silently allowing — or failing to allow — a port on Monday.
    An empty string is an empty map: with ``expected_ports`` that means every
    wildcard listener is flagged, the safe direction for an unset variable.
    """
    if isinstance(value, dict):
        items = [(str(k).strip(), "" if v is None else str(v).strip()) for k, v in value.items()]
    elif isinstance(value, str):
        items = []
        for token in re.split(r"[,\n]", value):
            token = token.strip()
            if not token:
                continue
            m = _PORT_ITEM_RE.match(token)
            if not m:
                raise CatalogueError(f"{name}: {token!r} is not 'port' or 'port:label'")
            items.append((m.group(1), (m.group(2) or "").strip()))
    else:
        raise CatalogueError(f"{name}: expected a mapping or a 'port[:label],...' string")
    out: dict[str, str] = {}
    for port, label in items:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise CatalogueError(f"{name}: {port!r} is not a TCP/UDP port (1-65535)")
        out[str(int(port))] = label
    return out


def load_catalogue(path: Path) -> Catalogue:
    # ${VAR} expansion, exactly like every other YAML under config/ — this is
    # how deployment inventories (e.g. HEIM_AUDIT_EXPECTED_PORTS) stay in .env.
    with open(path) as fh:
        data = yaml.safe_load(expand_env(fh.read(), source=str(path))) or {}
    sources: dict[str, SourceSpec] = {}
    for raw in data.get("sources") or []:
        key, kind = str(raw.get("key") or ""), str(raw.get("kind") or "")
        if not _ID_RE.match(key) or key in sources:
            raise CatalogueError(f"bad or duplicate source key {key!r}")
        if kind not in _KINDS:
            raise CatalogueError(f"source {key}: kind must be one of {_KINDS}, got {kind!r}")
        expand = str(raw.get("expand") or "")
        if expand not in ("", "vmid", "container"):
            raise CatalogueError(f"source {key}: expand must be '', 'vmid' or 'container'")
        target = _VALIDATORS[kind](str(raw.get("target") or ""), key=key)
        sources[key] = SourceSpec(key=key, kind=kind, target=target,
                                  control=str(raw.get("control") or ""), expand=expand)
    for s in sources.values():
        if s.control and s.control not in sources:
            raise CatalogueError(f"source {s.key}: control {s.control!r} is not a source")

    checks: list[CheckSpec] = []
    seen: set[str] = set()
    for raw in data.get("checks") or []:
        cid = str(raw.get("id") or "")
        if not _ID_RE.match(cid) or cid in seen:
            raise CatalogueError(f"bad or duplicate check id {cid!r}")
        seen.add(cid)
        sev = str(raw.get("severity") or "")
        if sev not in SEVERITIES:
            raise CatalogueError(f"check {cid}: severity must be one of {SEVERITIES}, got {sev!r}")
        srcs = tuple(str(s) for s in (raw.get("sources") or []))
        for s in srcs:
            if s not in sources:
                raise CatalogueError(f"check {cid}: unknown source {s!r}")
        params = dict(raw.get("params") or {})
        for key in _PORT_MAP_PARAMS:
            if key in params:
                params[key] = parse_port_map(params[key], name=f"check {cid}: {key}")
        checks.append(CheckSpec(
            id=cid, title=str(raw.get("title") or cid), severity=sev, sources=srcs,
            params=params, recommendation=str(raw.get("recommendation") or ""),
            compound=bool(raw.get("compound", False)),
        ))
    if not checks:
        raise CatalogueError(f"{path}: no checks defined")
    return Catalogue(
        sources=sources, checks=checks, params=dict(data.get("params") or {}),
        pve_node=str(data.get("pve_node") or "homelab"),
        ssh_host=str(data.get("ssh_host") or "ubuntu-server"),
        ha_host=str(data.get("ha_host") or "home-assistant"),
    )
