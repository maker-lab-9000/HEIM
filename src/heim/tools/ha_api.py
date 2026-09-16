"""Read-only Home Assistant REST API tool (port of n8n PAM 42).

GET-only path allowlist enforced client-side by the guard; server-side, use a
Long-Lived Access Token from a dedicated NON-ADMIN HA user (env HA_TOKEN).
"""
from __future__ import annotations

import json

import httpx

from heim.config import env
from heim.guards import guard_ha_path
from heim.tools.base import Tool, clip


class HaApiTool(Tool):
    async def run(self, args: dict) -> str:
        path = str(args.get("path") or "").strip()
        limit = int(self.cfg.options.get("clip_bytes", 8192))
        g = guard_ha_path(path)
        if not g.allowed:
            await self.ctx.emit(f"⛔ BLOCKED HA API: {path}\n({g.reason})")
            self.ctx.record({"tool": self.name, "path": path, "blocked": True, "reason": g.reason})
            return json.dumps({
                "ok": True, "blocked": True, "path": path,
                "message": f"Path blocked by safety guard ({g.reason}). Use one of the allowed endpoints.",
            })

        host = self.ctx.config.hosts[self.cfg.options["host"]]
        token = env("HA_TOKEN", required=True)
        base = (host.api.url if host.api else self.ctx.config.settings.home_assistant.url).rstrip("/")
        async with httpx.AsyncClient(timeout=30, verify=host.api.verify_ssl if host.api else True) as client:
            r = await client.get(base + g.normalized, headers={"Authorization": f"Bearer {token}"})
        body = clip(r.text, limit)

        await self.ctx.emit(f"🏠 HA GET {g.normalized}\n→ HTTP {r.status_code}\n{body[:600]}")
        self.ctx.record({"tool": self.name, "path": g.normalized, "blocked": False, "status": r.status_code})
        return json.dumps({"ok": r.status_code < 400, "status": r.status_code, "path": g.normalized, "body": body})
