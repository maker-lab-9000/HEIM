"""Read-only Proxmox VE API tool (port of n8n PAM 44).

GET-only path allowlist client-side; the real enforcement is the API token's
server-side role (a dedicated auditor user with only ``*.Audit`` + ``Sys.Syslog``).
Env PROXMOX_TOKEN holds the full value: ``user@pve!tokenid=secret``.

Token setup gotcha: a PVE token created with ``privsep=1`` (the default) has
NO permissions of its own regardless of the user's roles, and the failure is
quiet — list endpoints return 200 with an empty result rather than 403, so the
tool looks like it works while seeing nothing. Either give the token its own
ACL or create it with ``privsep=0`` to inherit the auditor user's roles.
"""
from __future__ import annotations

import json

import httpx

from heim.config import env
from heim.guards import guard_proxmox_path
from heim.metrics.proxmox_format import format_proxmox_output
from heim.tools.base import Tool


class ProxmoxApiTool(Tool):
    async def run(self, args: dict) -> str:
        path = str(args.get("path") or "").strip()
        limit = int(self.cfg.options.get("clip_bytes", 8192))
        g = guard_proxmox_path(path)
        if not g.allowed:
            await self.ctx.emit(f"⛔ BLOCKED Proxmox API: {path}\n({g.reason})")
            self.ctx.record({"tool": self.name, "path": path, "blocked": True, "reason": g.reason})
            return json.dumps({
                "ok": True, "blocked": True, "path": path,
                "message": f"Path blocked by safety guard ({g.reason}). Use one of the allowed endpoints.",
            })

        host = self.ctx.config.hosts[self.cfg.options["host"]]
        token = env("PROXMOX_TOKEN", required=True)
        base = host.api.url.rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=30, verify=host.api.verify_ssl) as client:
                r = await client.get(base + g.normalized,
                                     headers={"Authorization": f"PVEAPIToken={token}"})
        except httpx.TimeoutException:
            # /syslog does this on a journald-only host: pveproxy holds the
            # request for its full 30 s and we time out with it. Returning the
            # bare timeout would invite a retry that costs another 30 s.
            await self.ctx.emit(f"🖧 PVE GET {g.normalized}\n→ timed out after 30s")
            self.ctx.record({"tool": self.name, "path": g.normalized, "blocked": False, "status": 0})
            return json.dumps({"ok": False, "status": 0, "path": g.normalized, "body": "",
                               "hint": _hint(g.normalized, 0)})
        body = format_proxmox_output(g.normalized, r.text, clip=limit)

        await self.ctx.emit(f"🖧 PVE GET {g.normalized}\n→ HTTP {r.status_code}\n{body[:600]}")
        self.ctx.record({"tool": self.name, "path": g.normalized, "blocked": False, "status": r.status_code})
        out = {"ok": r.status_code < 400, "status": r.status_code, "path": g.normalized, "body": body}
        hint = _hint(g.normalized, r.status_code)
        if hint:
            out["hint"] = hint
        return json.dumps(out)


def _hint(path: str, status: int) -> str:
    """What to do next when the hypervisor answers with a dead end.

    Same rule as the SSH and HA tools: a call that cannot succeed says so,
    rather than handing back an empty body the agent will retry.
    """
    # 596 is pveproxy's own "the backend never answered"; 0 is our timeout.
    if path.startswith("/api2/json/nodes/") and "/syslog" in path and status in (0, 596):
        return (
            "/syslog does not work on this host and never will: PVE 8 ships journald "
            "only, with no rsyslog and no /var/log/syslog for that endpoint to read, so "
            "pveproxy holds the request until it times out. Use /journal instead — same "
            "host logs, answers in ~50ms. It takes ?lastentries=<n> for the newest N "
            "lines or ?since=<epoch seconds> for a window. Do not retry /syslog."
        )
    if status == 403:
        return (
            "The API token lacks the privilege for this path. Do not retry it or other "
            "paths needing the same privilege; note the gap in your report and use "
            "Prometheus plus the endpoints that do answer."
        )
    return ""
