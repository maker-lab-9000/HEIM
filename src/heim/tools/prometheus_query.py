"""PromQL query tool, instant + range, with token-compact results
(port of n8n PAM 41)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx

from heim.metrics.promql import build_range
from heim.metrics.promql import compact_result
from heim.tools.base import Tool


class PrometheusQueryTool(Tool):
    async def run(self, args: dict) -> str:
        promql = str(args.get("promql") or "").strip()
        lookback = str(args.get("lookback") or "").strip()
        step = str(args.get("step") or "").strip() or None
        if not promql:
            return json.dumps({"ok": False, "error": "no promql provided"})

        base = self.ctx.config.settings.prometheus.url.rstrip("/")
        rp = None
        if lookback:
            try:
                rp = build_range(lookback, step, datetime.now(timezone.utc))
            except ValueError:
                rp = None  # unparseable lookback -> instant query (n8n behavior)

        async with httpx.AsyncClient(timeout=30) as client:
            if rp is not None:
                r = await client.get(f"{base}/api/v1/query_range", params={
                    "query": promql, "start": rp.start, "end": rp.end, "step": rp.step_seconds,
                })
                mode = "range"
            else:
                r = await client.get(f"{base}/api/v1/query", params={"query": promql})
                mode = "instant"
        data = r.json()
        out = compact_result(data, promql)
        out["mode"] = mode

        n = out.get("count", "?")
        await self.ctx.emit(f"📈 promql ({mode}{', ' + lookback if rp else ''}): {promql[:180]}\n→ {n} series")
        self.ctx.record({"tool": self.name, "promql": promql, "mode": mode, "lookback": lookback})
        return json.dumps(out)
