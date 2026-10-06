"""Evidence fetchers for the weekly security audit — the I/O half.

Everything here is a READ: httpx GET against Proxmox / Home Assistant /
Prometheus, and guard-validated shell lines over one SSH connection. Targets
come from the validated catalogue only; expansions ({vmid}, {container}) are
re-validated after substitution. Every failure becomes an Evidence status the
evaluators turn into `unavailable`, never an exception up the pipeline.
"""
from __future__ import annotations

import asyncio
import json
import logging

import asyncssh
import httpx

from heim.config import Config, env
from heim.guards import guard_command
from heim.security.catalogue import Catalogue, CatalogueError, validate_pve_path
from heim.security.parsers import NAME_RE, docker_names, vmids_from_resources
from heim.security.types import Evidence, EvidenceBundle, SourceSpec
from heim.tools.base import clip
from heim.tools.ssh_diagnostic import COMMAND_TIMEOUT_S

log = logging.getLogger(__name__)

HTTP_TIMEOUT_S = 30
SSH_CONNECT_TIMEOUT_S = 20
SSH_CLIP_BYTES = 65536
KIND_TIMEOUT_S = 300
MAX_CONTAINERS = 40


# ------------------------------------------------------------------ pure bits

def classify_http(key: str, status_code: int, text: str, *, unwrap: str = "data", target: str = "") -> Evidence:
    """HTTP answer → Evidence. 401/403 = denied (the token lacks the privilege),
    404 = error (not on this version), 2xx = ok or EMPTY — the caller's control
    rule decides whether empty means anything."""
    if status_code in (401, 403):
        return Evidence(key, "denied", http_status=status_code, target=target,
                        detail=f"HTTP {status_code}: the token lacks the privilege for this path")
    if status_code == 404:
        return Evidence(key, "error", http_status=404, target=target, detail="HTTP 404: endpoint not available on this version")
    if status_code >= 400:
        return Evidence(key, "error", http_status=status_code, target=target, detail=f"HTTP {status_code}")
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return Evidence(key, "error", http_status=status_code, target=target, detail="response was not JSON")
    body = parsed.get(unwrap) if unwrap and isinstance(parsed, dict) and unwrap in parsed else parsed
    empty = body is None or body == [] or body == {} or body == ""
    return Evidence(key, "empty" if empty else "ok", body=body, http_status=status_code, target=target)


def prom_evidence(key: str, status_code: int, text: str, target: str) -> Evidence:
    if status_code >= 400:
        return Evidence(key, "error", http_status=status_code, target=target, detail=f"HTTP {status_code}")
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return Evidence(key, "error", http_status=status_code, target=target, detail="response was not JSON")
    if not isinstance(parsed, dict) or parsed.get("status") != "success":
        return Evidence(key, "error", http_status=status_code, target=target,
                        detail=f"prometheus: {str((parsed or {}).get('error') if isinstance(parsed, dict) else parsed)[:120]}")
    result = (parsed.get("data") or {}).get("result") or []
    return Evidence(key, "ok" if result else "empty", body=result, http_status=status_code, target=target)


def _all(sources: list[SourceSpec], status: str, detail: str) -> list[Evidence]:
    return [Evidence(s.key, status, detail=detail, target=s.target) for s in sources]


def _docker_ps_row_count(ps_text: str) -> int:
    """Container rows in ``docker ps`` output (header excluded), independent
    of ``docker_names``'s own NAME_RE filtering — the ground truth for how
    many containers SHOULD be inspected, so a name that fails validation (or
    is simply dropped by the cap) can still be counted as "not inspected"
    rather than disappearing."""
    return sum(1 for line in (ps_text or "").splitlines()[1:] if line.split())


# ---------------------------------------------------------------------- HTTP

async def fetch_pve(cfg: Config, sources: list[SourceSpec], *, node: str) -> list[Evidence]:
    host = cfg.hosts.get(node)
    if host is None or host.api is None:
        return _all(sources, "error", f"host {node} has no api config")
    token = env("PROXMOX_TOKEN")
    if not token:
        return _all(sources, "denied", "PROXMOX_TOKEN is not set — the Proxmox part of the audit is disabled")
    base = host.api.url.rstrip("/")
    headers = {"Authorization": f"PVEAPIToken={token}"}
    out: list[Evidence] = []

    async def get(key: str, path: str) -> Evidence:
        try:
            path = validate_pve_path(path, key=key)
        except CatalogueError as exc:
            return Evidence(key, "blocked", detail=str(exc), target=path)
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_S, verify=host.api.verify_ssl) as client:
                r = await client.get(base + path, headers=headers)
        except httpx.TimeoutException:
            return Evidence(key, "timeout", detail=f"no answer in {HTTP_TIMEOUT_S}s", target=path)
        except httpx.HTTPError as exc:
            return Evidence(key, "error", detail=f"{type(exc).__name__}: {exc}", target=path)
        return classify_http(key, r.status_code, r.text, target=path)

    plain = [s for s in sources if not s.expand]
    for e in await asyncio.gather(*(get(s.key, s.target) for s in plain)):
        out.append(e)
    vm_sources = [s for s in sources if s.expand == "vmid"]
    if vm_sources:
        res = next((e for e in out if e.key == "pve.resources_vm"), None)
        if res is None:
            res = await get("pve.resources_vm", "/api2/json/cluster/resources?type=vm")
            out.append(res)
        vmids = sorted(vmids_from_resources(res.body)) if res.status == "ok" else []
        if not vmids:
            out.extend(Evidence(s.key, "error", detail="VM list unavailable — per-VM sources not fetched", target=s.target) for s in vm_sources)
        else:
            jobs = [(f"{s.key}[{v}]", s.target.replace("{vmid}", v)) for s in vm_sources for v in vmids]
            out.extend(await asyncio.gather(*(get(k, p) for k, p in jobs)))
    return out


async def fetch_ha(cfg: Config, sources: list[SourceSpec], *, host: str) -> list[Evidence]:
    h = cfg.hosts.get(host)
    base_url = h.api.url if (h and h.api) else (cfg.settings.home_assistant.url if cfg.settings.home_assistant else "")
    if not base_url:
        return _all(sources, "error", f"host {host} has no api url")
    token = env("HA_TOKEN")
    if not token:
        return _all(sources, "denied", "HA_TOKEN is not set — the Home Assistant part of the audit is disabled")
    base = base_url.rstrip("/")
    verify = h.api.verify_ssl if (h and h.api) else True

    async def get(s: SourceSpec) -> Evidence:
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_S, verify=verify) as client:
                r = await client.get(base + s.target, headers={"Authorization": f"Bearer {token}"})
        except httpx.TimeoutException:
            return Evidence(s.key, "timeout", detail=f"no answer in {HTTP_TIMEOUT_S}s", target=s.target)
        except httpx.HTTPError as exc:
            return Evidence(s.key, "error", detail=f"{type(exc).__name__}: {exc}", target=s.target)
        return classify_http(s.key, r.status_code, r.text, unwrap="", target=s.target)

    return list(await asyncio.gather(*(get(s) for s in sources)))


async def fetch_prom(cfg: Config, sources: list[SourceSpec]) -> list[Evidence]:
    base = cfg.settings.prometheus.url.rstrip("/")

    async def get(s: SourceSpec) -> Evidence:
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_S) as client:
                r = await client.get(f"{base}/api/v1/query", params={"query": s.target})
        except httpx.TimeoutException:
            return Evidence(s.key, "timeout", detail=f"no answer in {HTTP_TIMEOUT_S}s", target=s.target)
        except httpx.HTTPError as exc:
            return Evidence(s.key, "error", detail=f"{type(exc).__name__}: {exc}", target=s.target)
        return prom_evidence(s.key, r.status_code, r.text, s.target)

    return list(await asyncio.gather(*(get(s) for s in sources)))


# ----------------------------------------------------------------------- SSH

async def fetch_ssh(cfg: Config, sources: list[SourceSpec], *, ssh_host: str) -> list[Evidence]:
    host = cfg.hosts.get(ssh_host)
    if host is None or host.ssh is None:
        return _all(sources, "error", f"host {ssh_host} has no ssh config — no shell for the audit")
    ssh = host.ssh
    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(ssh.host, port=ssh.port, username=ssh.user,
                             client_keys=[ssh.resolved_key_path()], known_hosts=None),
            SSH_CONNECT_TIMEOUT_S)
    except (OSError, asyncssh.Error, asyncio.TimeoutError) as exc:
        return _all(sources, "error", f"ssh unavailable: {type(exc).__name__}: {exc}")

    async def run(key: str, line: str) -> Evidence:
        g = guard_command(line)
        if not g.allowed:
            return Evidence(key, "blocked", detail=g.reason or "guard", target=line)
        try:
            r = await asyncio.wait_for(conn.run(g.normalized, check=False), COMMAND_TIMEOUT_S)
        except asyncio.TimeoutError:
            return Evidence(key, "timeout", detail=f"no answer in {COMMAND_TIMEOUT_S}s", target=line)
        except (OSError, asyncssh.Error) as exc:
            return Evidence(key, "error", detail=f"{type(exc).__name__}: {exc}", target=line)
        stdout = clip(str(r.stdout or ""), SSH_CLIP_BYTES)
        return Evidence(key, "ok" if stdout.strip() else "empty", body=stdout, exit_code=r.exit_status,
                        stderr=clip(str(r.stderr or ""), 2048), target=line)

    out: list[Evidence] = []
    try:
        for s in sources:
            if not s.expand:
                out.append(await run(s.key, s.target))
        for s in sources:
            if s.expand != "container":
                continue
            ps = next((e for e in out if e.key == "ssh.docker_ps"), None)
            if ps is None or ps.status != "ok":
                out.append(Evidence(s.key, "error", detail="container list unavailable — per-container sources not fetched", target=s.target))
                continue
            # Names come from remote `docker ps` output — untrusted. Re-validate
            # with fullmatch (not match): NAME_RE ends in `$`, and in Python `$`
            # also matches just before a trailing newline, so `.match` alone
            # could let a crafted "name\n<injected>" through this gate.
            ps_text = str(ps.body or "")
            total = _docker_ps_row_count(ps_text)
            inspected = 0
            for name in docker_names(ps_text)[:MAX_CONTAINERS]:
                if not NAME_RE.fullmatch(name):
                    continue
                out.append(await run(f"{s.key}[{name}]", s.target.replace("{container}", name)))
                inspected += 1
            # A container dropped by the cap, by NAME_RE (here or inside
            # docker_names), or by a malformed `ps` row must still surface as
            # evidence — never vanish silently, or a privileged/docker.sock
            # container could sit past the cap while the check still says ok.
            if total == 0 and ps.exit_code == 0:
                # a header-only `docker ps` is a genuine answer: nothing runs
                out.append(Evidence(f"{s.key}[_none]", "empty", body="", exit_code=0,
                                    detail="docker ps answered: no containers running", target=s.target))
                continue
            skipped = total - inspected
            if skipped > 0:
                out.append(Evidence(
                    f"{s.key}[_not_inspected]", "error",
                    detail=f"{skipped} container(s) not inspected (cap {MAX_CONTAINERS} or a name that failed validation)",
                    target=s.target))
    finally:
        conn.close()
    return out


# ---------------------------------------------------------------- orchestrate

async def _bounded(coro, sources: list[SourceSpec], kind: str) -> list[Evidence]:
    try:
        return await asyncio.wait_for(coro, KIND_TIMEOUT_S)
    except asyncio.TimeoutError:
        return _all(sources, "timeout", f"{kind} collection exceeded {KIND_TIMEOUT_S}s")
    except Exception as exc:  # a fetcher bug must degrade one kind, not the audit
        log.exception("%s collection failed", kind)
        return _all(sources, "error", f"{type(exc).__name__}: {exc}")


async def collect_evidence(cfg: Config, cat: Catalogue, *, now_iso: str) -> EvidenceBundle:
    pve, ha, prom, ssh = (cat.by_kind(k) for k in ("pve", "ha", "prom", "ssh"))
    gathered = await asyncio.gather(
        _bounded(fetch_pve(cfg, pve, node=cat.pve_node), pve, "pve"),
        _bounded(fetch_ha(cfg, ha, host=cat.ha_host), ha, "ha"),
        _bounded(fetch_prom(cfg, prom), prom, "prom"),
        _bounded(fetch_ssh(cfg, ssh, ssh_host=cat.ssh_host), ssh, "ssh"),
    )
    bundle = EvidenceBundle(collected_at=now_iso)
    for items in gathered:
        for e in items:
            bundle.items[e.key] = e
    log.info("security audit evidence: %d items (%s)", len(bundle.items),
             ", ".join(f"{k}={sum(1 for e in bundle.items.values() if e.key.startswith(k + '.') and e.usable)}"
                       for k in ("pve", "ha", "prom", "ssh")))
    return bundle
