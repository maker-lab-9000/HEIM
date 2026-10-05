"""Pure parsers for the audit's raw evidence (ss, sshd_config, journald hints,
update-notifier, last, docker ps/images, PVE JSON). No I/O."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_WILDCARD = {"0.0.0.0", "*", "[::]", "::"}
_PROC_RE = re.compile(r'users:\(\("([^"]+)"')
_PRIVATE_SUFFIXES = (".local", ".lan", ".home", ".internal", ".ts.net", ".home.arpa", ".localdomain")


def parse_ss_listeners(text: str) -> list[dict]:
    """``sudo ss -tunlpH`` rows → proto/local/port/process/wildcard."""
    rows = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[4]
        addr, _, port = local.rpartition(":")
        addr = addr.split("%", 1)[0]            # 127.0.0.53%lo → 127.0.0.53
        m = _PROC_RE.search(line)
        rows.append({"proto": parts[0], "local": local, "port": port,
                     "process": m.group(1) if m else "?", "wildcard": addr in _WILDCARD})
    return rows


def parse_sshd_config(text: str) -> dict[str, str]:
    """sshd semantics: the FIRST value for a keyword wins; ``Match`` blocks end
    the global section. Keys lowercased. Callers concatenate drop-ins first
    (Ubuntu's stock sshd_config Includes sshd_config.d/*.conf at the top)."""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.lower().startswith("match "):
            break
        parts = s.replace("=", " ", 1).split(None, 1)
        if len(parts) != 2:
            continue
        out.setdefault(parts[0].lower(), parts[1].strip())
    return out


def unreadable_dropins(ls_text: str) -> list[str]:
    """``ls -la`` lines for ``*.conf`` whose mode lacks the other-read bit."""
    out = []
    for line in (ls_text or "").splitlines():
        parts = line.split()
        if len(parts) >= 9 and parts[-1].endswith(".conf") and len(parts[0]) >= 10 and parts[0][7] != "r":
            out.append(parts[-1])
    return out


_UPD_TOTAL = re.compile(r"(\d+) updates? can be applied")
_UPD_SEC = re.compile(r"(\d+) of these updates? (?:is|are) (?:a )?standard security")


def parse_updates_available(text: str) -> tuple[int, int]:
    t = _UPD_TOTAL.search(text or "")
    s = _UPD_SEC.search(text or "")
    return (int(t.group(1)) if t else 0, int(s.group(1)) if s else 0)


def parse_last_hosts(text: str) -> list[str]:
    """Host column of ``last -w -F``; skips reboot rows, tty-only rows and the trailer."""
    hosts = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] in ("reboot", "wtmp", "shutdown"):
            continue
        cand = parts[2]
        try:
            ipaddress.ip_address(cand)
        except ValueError:
            continue
        hosts.append(cand)
    return hosts


def docker_names(ps_text: str) -> list[str]:
    """NAMES (last column) of ``docker ps``, header skipped, names validated."""
    names = []
    for line in (ps_text or "").splitlines()[1:]:
        parts = line.split()
        if parts and NAME_RE.match(parts[-1]):
            names.append(parts[-1])
    return names


_AGE = re.compile(r"(\d+)\s+(second|minute|hour|day|week|month|year)s?\s+ago")
_MONTHS = {"second": 0, "minute": 0, "hour": 0, "day": 0, "week": 0, "month": 1, "year": 12}


def parse_docker_images(text: str) -> list[tuple[str, int]]:
    """``docker images`` → [(repo:tag, age in whole months)]."""
    out = []
    for line in (text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        m = _AGE.search(line)
        months = int(m.group(1)) * _MONTHS[m.group(2)] if m else 0
        out.append((f"{parts[0]}:{parts[1]}", months))
    return out


def apt_pending(body: object) -> list[dict]:
    """``/nodes/<n>/apt/versions`` rows whose installed (OldVersion) differs from the candidate (Version)."""
    rows = []
    for r in body if isinstance(body, list) else []:
        if not isinstance(r, dict):
            continue
        old, new = str(r.get("OldVersion") or ""), str(r.get("Version") or "")
        if old and new and old != new:
            rows.append({"Package": str(r.get("Package") or "?"), "OldVersion": old, "Version": new})
    return rows


def vmids_from_resources(body: object) -> dict[str, str]:
    """``/cluster/resources?type=vm`` → {vmid: guest name} (qemu only)."""
    out: dict[str, str] = {}
    for r in body if isinstance(body, list) else []:
        if isinstance(r, dict) and r.get("vmid") is not None and str(r.get("type") or "qemu") == "qemu":
            out[str(r["vmid"])] = str(r.get("name") or f"vm{r['vmid']}")
    return out


def is_public_host(url: str) -> bool:
    host = (urlparse(str(url or "")).hostname or "").lower()
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    return "." in host and not host.endswith(_PRIVATE_SUFFIXES)


def ip_in_cidrs(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs or []:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def unit_states(target: str, text: str) -> dict[str, str]:
    """``systemctl is-active a b c`` prints one state per unit, in argument order."""
    units = str(target or "").split()[2:]
    states = [l.strip() for l in (text or "").splitlines()]
    return {u: (states[i] if i < len(states) else "unknown") for i, u in enumerate(units)}
