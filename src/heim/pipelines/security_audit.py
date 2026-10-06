"""The weekly read-only security audit pipeline.

Flow (run_security_audit, Task 11): catalogue → collect evidence (I/O) →
evaluate (pure) → drop suppressed → diff against the previous audit → persist
run + findings → deterministic report → ONE bounded model pass that explains
and prioritises (never detects) → deliver (email, Telegram digest, HA sensor,
Loki). A declined/failed model pass costs the report its '## AI assessment'
appendix and nothing else.

This module holds the prompt builders as well, so the prompt-hygiene test
can render exactly what the model will see.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime

from jinja2 import Environment, FileSystemLoader

from heim.agent.runner import AgentResult, run_agent
from heim.config import expand_env
from heim.costing import cost_of
from heim.pipelines.investigate import (
    _action, _step_recorder, _transcript_json, findings_text, record_tool_feedback,
)
from heim.pipelines.security_sources import collect_evidence
from heim.reports.render import salvage, security_audit_email
from heim.runtime import Runtime
from heim.security.catalogue import load_catalogue
from heim.security.diff import AuditDiff, diff_findings, finding_rows
from heim.security.evaluate import EvalContext, evaluate
from heim.security.report import (
    brief_sections, coverage_gaps, demote_headings, finding_events, ha_attributes, overall_of,
    render_audit_report, telegram_digest,
)
from heim.security.types import CheckResult
from heim.tools.base import ToolContext, load_tools

log = logging.getLogger(__name__)

AUDIT_KIND = "security_audit"          # runs.kind · findings.source · investigations.trigger
AGENT_NAME = "security_auditor"        # config/agents/security_auditor.yaml · investigations.agent_name
AUDIT_HOST = "all"                     # investigations.host for the run-level row

#: Words that make a defensive review read like an offensive one to a safety
#: classifier. tests/test_security_prompt.py fails if a rendered prompt
#: contains any of them; keep the templates in the vocabulary of hygiene.
ATTACK_TERMS = ("exploit", "attack", "brute", "penetration", "pentest", "payload", "intrusion", "crack", "bypass")


def build_audit_system_prompt(rt: Runtime, jenv: Environment) -> str:
    cfg = rt.config
    agent = cfg.agents[AGENT_NAME]
    facts = "\n".join(h.facts.strip() for h in sorted(cfg.hosts.values(), key=lambda h: h.name) if h.facts.strip())
    return expand_env(
        jenv.get_template(agent.prompt).render(now=rt.now_iso(), facts=facts,
                                               soft_step_budget=agent.soft_step_budget),
        source=agent.prompt,
    )


def build_audit_brief(rt: Runtime, jenv: Environment, results: list[CheckResult], diff: AuditDiff, *,
                      generated_at: str) -> str:
    sections = brief_sections(results, diff)
    return expand_env(
        jenv.get_template("briefs/security_audit.md.j2").render(
            generated_at=generated_at, n_new=len(diff.new), n_persisting=len(diff.persisting),
            n_resolved=len(diff.resolved), n_carried=len(diff.carried), **sections),
        source="briefs/security_audit.md.j2",
    )


async def run_security_audit(rt: Runtime, *, llm: bool = True) -> dict:
    """One weekly audit. Raises only when NO source answered; every other
    failure degrades one section of the report and is written into it."""
    cfg = rt.config
    t0 = time.time()
    generated_at = rt.now_iso()
    cat = load_catalogue(cfg.security_checks_path)

    # 1. collect (I/O, bounded) → 2. evaluate (pure)
    evidence = await collect_evidence(cfg, cat, now_iso=generated_at)
    ctx = EvalContext(now=rt.now(), instance_host_map=dict(cfg.settings.instance_host_map),
                      hosts=tuple(cfg.hosts), pve_node=cat.pve_node, ssh_host=cat.ssh_host, ha_host=cat.ha_host)
    if not any(e.usable for e in evidence.items.values()):
        raise RuntimeError("every source was unreachable — no audit possible this run")
    results = evaluate(cat, evidence, ctx)

    # 3. suppressions + week-over-week diff
    suppressed = rt.store.active_suppressions(generated_at)
    findings = [r for r in results if r.is_finding and r.fingerprint not in suppressed]
    unavailable_ids = {r.check_id for r in results if r.status == "unavailable"}
    prev_runs = rt.store.runs(limit=1, kind=AUDIT_KIND)
    previous = rt.store.findings_for_run(int(prev_runs[0]["id"])) if prev_runs else []
    previous = [p for p in previous if str(p.get("fingerprint") or "") not in suppressed]
    diff = diff_findings(findings, previous, unavailable_ids)
    rows = finding_rows(diff)
    weeks = {r["fingerprint"]: rt.store.finding_run_count(r["fingerprint"], AUDIT_KIND) + 1 for r in rows}

    # 4. deterministic report → 5. persist (tokens/cost live on the investigation row only)
    report_md = render_audit_report(results, diff, generated_at=generated_at, weeks=weeks)
    gaps = coverage_gaps(results)
    run_id = rt.store.insert_run(
        kind=AUDIT_KIND, run_at=generated_at, overall=overall_of(rows),
        model_used=cfg.agents[AGENT_NAME].model if (llm and AGENT_NAME in cfg.agents) else "",
        duration_s=round(time.time() - t0, 3),
        counts_json=json.dumps({"checks": len(results), "findings": len(rows), "new": len(diff.new),
                                "persisting": len(diff.persisting), "resolved": len(diff.resolved),
                                "carried": len(diff.carried), "unavailable": len(gaps),
                                "critical": sum(1 for r in rows if r["severity"] == "critical"),
                                "warning": sum(1 for r in rows if r["severity"] == "warning")}),
        headline=f"{len(rows)} findings · {len(diff.new)} new · {len(diff.resolved)} resolved",
        summary=report_md.split("\n\n", 2)[1] if "\n\n" in report_md else "",
    )
    rt.store.insert_findings(run_id, generated_at, AUDIT_KIND, rows, [r["fingerprint"] for r in rows])

    # 6. the model pass — explains, never detects; optional and degradable
    inv_id, assessment_md, agent_result, status, reason = 0, None, None, "skipped", ""
    if llm and AGENT_NAME in cfg.agents:
        inv_id, assessment_md, agent_result, status, reason = await _assessment(
            rt, run_id=run_id, results=results, diff=diff, rows=rows, generated_at=generated_at)
    if assessment_md:
        final_md = f"{report_md}\n\n## AI assessment\n\n{demote_headings(assessment_md)}"
    else:
        why = {"skipped": "skipped (--no-llm)", "failed": f"failed — {reason}"}.get(status, reason or "no assessment")
        final_md = f"{report_md}\n\n## AI assessment\n\n_Unavailable — {why}._"
    if inv_id:
        rt.store.update_investigation(inv_id, report_md=final_md)

    # 7. deliver
    subject = await _deliver(rt, run_id=run_id, final_md=final_md, diff=diff, results=results, rows=rows, inv_id=inv_id,
                             agent_result=agent_result, status=status, reason=reason, generated_at=generated_at)
    cost = cost_of(cfg.agents[AGENT_NAME].model, agent_result.input_tokens, agent_result.output_tokens,
                   cfg.settings.model_prices) if agent_result is not None else 0.0
    return {
        "run_id": run_id, "investigation_id": inv_id, "checks": len(results), "findings": len(rows),
        "new": len(diff.new), "persisting": len(diff.persisting), "resolved": len(diff.resolved),
        "carried": len(diff.carried), "unavailable": len(gaps), "assessment": status,
        "cost": float(cost or 0.0), "subject": subject, "duration_s": round(time.time() - t0, 1),
    }


async def _assessment(rt: Runtime, *, run_id: int, results: list[CheckResult], diff: AuditDiff,
                      rows: list[dict], generated_at: str) -> tuple[int, str | None, AgentResult | None, str, str]:
    cfg = rt.config
    agent_cfg = cfg.agents[AGENT_NAME]
    jenv = Environment(loader=FileSystemLoader(cfg.prompts_dir))
    brief = build_audit_brief(rt, jenv, results, diff, generated_at=generated_at)
    ftext = findings_text(rows)
    inv_id = rt.store.create_investigation(
        fingerprint=f"{AUDIT_HOST}|{AUDIT_KIND}|run-{run_id}", host=AUDIT_HOST, host_role="audit",
        agent_name=AGENT_NAME, model=agent_cfg.model, trigger=AUDIT_KIND, status="running",
        started_at=generated_at, brief_md=brief, findings_json=json.dumps(rows, ensure_ascii=False, default=str),
    )
    await rt.emit_loki([_action(AUDIT_HOST, "audit_started", f"run-{run_id}", "Weekly security audit assessment started", rt.now_iso())])
    try:
        async with rt.investigation_slot():
            system = build_audit_system_prompt(rt, jenv)
            ctx = ToolContext(config=cfg, tag="security-audit", feed=rt.feed, audit=rt.audit)
            tools = load_tools(agent_cfg.tools, cfg, ctx)
            result = await run_agent(agent_cfg, system=system, user_prompt=brief, tools=tools,
                                     on_step=_step_recorder(rt, inv_id),
                                     collect_transcript=cfg.settings.store_transcripts)
    except Exception as exc:
        log.exception("security audit assessment failed")
        reason = f"{type(exc).__name__}: {exc}"
        rt.store.update_investigation(inv_id, status="failed", finished_at=rt.now_iso(), incomplete_reason=reason)
        return inv_id, None, None, "failed", reason
    report = salvage(result.output_text, ftext, stop_reason=result.stop_reason)
    record_tool_feedback(rt, inv_id, report.report_md if not report.incomplete else result.output_text)
    cost = cost_of(agent_cfg.model, result.input_tokens, result.output_tokens, cfg.settings.model_prices)
    rt.store.update_investigation(
        inv_id, status="incomplete" if report.incomplete else "complete",
        incomplete_reason=(report.reason or "") if report.incomplete else "",
        report_md=report.report_md, input_tokens=result.input_tokens, output_tokens=result.output_tokens,
        n_steps=len(result.steps), cost=float(cost or 0.0),
        transcript_json=_transcript_json(result.transcript), finished_at=rt.now_iso(),
    )
    if report.incomplete:
        return inv_id, None, result, "incomplete", report.reason or "no '## Summary' in the model output"
    return inv_id, report.report_md, result, "complete", ""


async def _deliver(rt: Runtime, *, run_id: int, final_md: str, diff: AuditDiff, results: list[CheckResult], rows: list[dict],
                   inv_id: int, agent_result: AgentResult | None, status: str, reason: str, generated_at: str) -> str:
    incomplete = status in ("incomplete", "failed")
    n_steps = len(agent_result.steps) if agent_result else 0
    tok_in = agent_result.input_tokens if agent_result else 0
    tok_out = agent_result.output_tokens if agent_result else 0
    subject, html = security_audit_email(report_md=final_md, incomplete=incomplete, generated_at=generated_at,
                                         n_findings=len(rows), n_new=len(diff.new), n_resolved=len(diff.resolved),
                                         n_steps=n_steps, input_tokens=tok_in, output_tokens=tok_out)
    await rt.send_email(subject, html)
    await rt.notify(telegram_digest(diff, results, generated_at=generated_at, assessment=status, reason=reason))
    new_crit = [r for r in diff.new if r.severity == "critical"]
    if new_crit:
        await rt.notify("🔴 New critical security finding(s) this week:\n" +
                        "\n".join(f"• {r.host} · {r.check_id} · {r.summary[:160]}" for r in new_crit[:5]))
    state, attrs = ha_attributes(diff, results, generated_at=generated_at, report_md=final_md)
    await rt.push_ha("security_audit", state, attrs)
    events = finding_events(rows)
    if inv_id:
        events.append({"event": "investigation", "labels": {"host": AUDIT_HOST, "status": "incomplete" if incomplete else "complete"},
                       "fields": {"fingerprint": f"{AUDIT_HOST}|{AUDIT_KIND}|run-{run_id}", "rootCause": "", "confidence": "",
                                  "impact": f"{len(rows)} findings, {len(diff.new)} new", "remediation": [], "recommendedActions": [],
                                  "tokenEstimate": tok_in + tok_out, "nSteps": n_steps, "detectedAt": "", "resolvedAt": ""}})
    events.append(_action(AUDIT_HOST, "report", f"run-{run_id}", "Weekly security audit report generated", rt.now_iso()))
    await rt.emit_loki(events)
    return subject
