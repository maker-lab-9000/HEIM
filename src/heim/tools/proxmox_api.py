"""Read-only Proxmox VE API tool (port of n8n PAM 44).

GET-only path allowlist client-side; the real enforcement is the API token's
server-side role (a dedicated auditor user — PVEAuditor + Sys.Syslog).
Env PROXMOX_TOKEN holds the full value: ``user@pve!tokenid=secret``.
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
        async with httpx.AsyncClient(timeout=30, verify=host.api.verify_ssl) as client:
            r = await client.get(base + g.normalized, headers={"Authorization": f"PVEAPIToken={token}"})
        body = format_proxmox_output(g.normalized, r.text, clip=limit)

        await self.ctx.emit(f"🖧 PVE GET {g.normalized}\n→ HTTP {r.status_code}\n{body[:600]}")
        self.ctx.record({"tool": self.name, "path": g.normalized, "blocked": False, "status": r.status_code})
        return json.dumps({"ok": r.status_code < 400, "status": r.status_code, "path": g.normalized, "body": body})
