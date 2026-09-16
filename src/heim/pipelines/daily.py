"""The daily LLM trend-analysis pipeline (port of n8n PAM 10).

Query Prometheus (3-day ranges) → aggregate → LLM analysis (primary model,
Anthropic fallback) → reconcile incidents → email + HA push + Loki emits →
dispatch investigations for new/escalated incidents.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import asdict

import httpx

from heim.incidents.loki_events import finding_and_category_events, incident_events
from heim.incidents.reconcile import reconcile
from heim.incidents.state import compute_state
from heim.llm import analyst_complete, parse_analysis
from heim.metrics.aggregate import aggregate
from heim.metrics.queries import build_window, load_queries
from heim.pipelines.investigate import dispatch_all
from heim.reports.render import daily_email
from heim.runtime import Runtime

log = logging.getLogger(__name__)

FETCH_CONCURRENCY = 8


async def _fetch_query_ranges(base_url: str, qdefs, window: dict) -> list[dict]:
    """One query_range per query def; failures degrade per-query (neverError)."""
    sem = asyncio.Semaphore(FETCH_CONCURRENCY)
    results: list[dict] = [None] * len(qdefs)  # type: ignore[list-item]

    async with httpx.AsyncClient(timeout=60) as client:
        async def one(i: int, q) -> None:
            item = {"query": asdict(q), "data": None, "error": None}
            try:
                async with sem:
                    r = await client.get(f"{base_url.rstrip('/')}/api/v1/query_range", params={
                        "query": q.promql, "start": window["start"], "end": window["end"], "step": window["step"],
                    })
                item["data"] = r.json()
            except Exception as exc:
                item["error"] = f"{type(exc).__name__}: {exc}"
            results[i] = item

        await asyncio.gather(*(one(i, q) for i, q in enumerate(qdefs)))
    return results


def _flatten_rows(payload: dict) -> list[dict]:
    return [row for rows in (payload.get("categories") or {}).values() for row in rows]


def _report_slot(hour: int) -> str:
    return "morning" if hour < 15 else "evening"


def _ha_report_md(analysis: dict) -> str:
    """Compact markdown for the HA sensor (port of 'Format report for HA')."""
    icon = {"healthy": "✅", "ok": "✅", "warning": "⚠️", "warn": "⚠️", "critical": "🔴", "crit": "🔴"}
    st = str(analysis.get("overallHealth") or "").lower()
    md = f"{icon.get(st, 'ℹ️')} **{st.upper()}** — {analysis.get('headline', '')}\n\n"
    if analysis.get("executiveSummary"):
        md += analysis["executiveSummary"] + "\n\n"
    cats = analysis.get("categories") or {}
    md += " · ".join(f"{icon.get(str((v or {}).get('status', '')).lower(), 'ℹ️')} {k}" for k, v in cats.items()) + "\n\n"
    not_ok = [k for k, v in cats.items() if v and v.get("status") and v["status"] != "ok"]
    for k in not_ok:
        md += f"- {icon.get(str(cats[k]['status']).lower(), 'ℹ️')} **{k}**: {cats[k].get('insight', '')}\n"
    findings = analysis.get("findings") or []
    if findings:
        md += f"\n**Findings ({len(findings)})**\n"
        for f in findings:
            md += f"- {icon.get(str(f.get('severity', '')).lower(), 'ℹ️')} **{f.get('host')}** — {f.get('summary', '')}\n"
    return md


async def run_daily(rt: Runtime, *, dispatch_concurrently: bool = True) -> dict:
    cfg = rt.config
    t0 = time.time()
    run_at = rt.now_iso()

    # 1. metrics
    qdefs = load_queries(cfg.queries_path)
    window = build_window(rt.now())
    log.info("daily run: fetching %d queries over %s → %s", len(qdefs), window["start"], window["end"])
    results = await _fetch_query_ranges(cfg.settings.prometheus.url, qdefs, window)
    agg = aggregate(results, now=rt.now())
    payload = agg["payload"]
    log.info("aggregated: overall=%s crit=%s warn=%s na=%s", payload["overall"],
             payload["counts"]["crit"], payload["counts"]["warn"], payload["counts"]["naQueries"])

    # 2. LLM analysis
    if cfg.analyst is None:
        raise RuntimeError("no analyst agent configured (config/agents/daily_analyst.yaml)")
    system = (cfg.prompts_dir / cfg.analyst.prompt).read_text()
    user = (
        "Here is the homelab 3-day Prometheus metrics summary as JSON. Analyze it for degradation "
        "TRENDS over the window (use the day3d per-day averages and changePct, not just current "
        "values). Respond with the strict JSON object defined in the system prompt and nothing else.\n\n"
        + json.dumps(payload, ensure_ascii=False)
    )
    text, model_used = await analyst_complete(cfg.analyst, system, user)
    analysis = parse_analysis(text)
    if analysis is None:
        await rt.notify(f"⚠️ HEIM daily run: analyst output unparseable (model {model_used}); no report sent.")
        raise RuntimeError(f"analyst returned unparseable output (model {model_used}): {text[:400]}")
    log.info("analysis by %s: %s — %s", model_used, analysis.get("overallHealth"), analysis.get("headline"))

    # 3. reconcile incidents
    open_rows = rt.store.open_rows()
    rec = reconcile(analysis, _flatten_rows(payload), open_rows, run_at, cfg.routing())
    rt.store.upsert(rec.rows_to_write)
    counts = (rec.summary or {}).get("counts") or {}
    log.info("reconcile: %s", counts)

    # 4. report email
    subject, html = daily_email(analysis=analysis, payload=payload, incident_summary=rec.summary, generated_at=run_at)
    await rt.send_email(subject, html)

    # 5. HA sensor push
    slot = _report_slot(rt.now().hour)
    await rt.push_ha(f"report_{slot}", rt.now().strftime("%Y-%m-%d %H:%M"), {
        "friendly_name": f"PAM {'Morning' if slot == 'morning' else 'Evening'} Report",
        "icon": "mdi:weather-sunset-up" if slot == "morning" else "mdi:weather-night",
        "slot": slot, "updated": rt.now_iso(), "report": _ha_report_md(analysis),
    })

    # 6. Loki emits (findings, categories, incidents, run state)
    events = finding_and_category_events(analysis, payload) + incident_events(rec.summary or {})
    events.append(compute_state(rt.store.open_rows(), routing=cfg.routing(), trigger="run",
                                last_run_ms=int(time.time() * 1000)))
    await rt.emit_loki(events)

    # 7. investigations (fire-and-forget in the daemon; sequential in the CLI)
    if rec.to_investigate:
        log.info("dispatching %d investigation(s): %s", len(rec.to_investigate),
                 ", ".join(x.get("fingerprint", "?") for x in rec.to_investigate))
        await dispatch_all(rt, rec.to_investigate, concurrent=dispatch_concurrently)

    return {
        "overall": analysis.get("overallHealth"),
        "model": model_used,
        "findings": len(analysis.get("findings") or []),
        "incidents": counts,
        "investigations": len(rec.to_investigate),
        "duration_s": round(time.time() - t0, 1),
        "subject": subject,
    }
