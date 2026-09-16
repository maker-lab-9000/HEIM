"""Prometheus metric-catalog discovery tool (port of n8n PAM 43)."""
from __future__ import annotations

import json

import httpx

from heim.metrics.discover import filter_names, format_discovery
from heim.tools.base import Tool


class DiscoverMetricsTool(Tool):
    async def run(self, args: dict) -> str:
        pattern = str(args.get("pattern") or "").strip()
        metric = str(args.get("metric") or "").strip() or None
        if not pattern and not metric:
            return json.dumps({"ok": False, "error": "provide a pattern and/or a metric"})

        base = self.ctx.config.settings.prometheus.url.rstrip("/")
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(f"{base}/api/v1/label/__name__/values")
            all_names = (r.json().get("data") or []) if r.status_code == 200 else []
            names = filter_names(all_names, pattern) if pattern else []
            series: list[dict] = []
            if metric:
                r2 = await client.get(f"{base}/api/v1/series", params={"match[]": metric})
                series = (r2.json().get("data") or []) if r2.status_code == 200 else []

        out = format_discovery(pattern, names, metric, series)
        await self.ctx.emit(f"🔎 discover: pattern={pattern!r} metric={metric!r} → {len(names)} names")
        self.ctx.record({"tool": self.name, "pattern": pattern, "metric": metric, "matches": len(names)})
        return json.dumps(out)
