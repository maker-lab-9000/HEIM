"""The approval-gated investigation pipeline (port of n8n PAM 20).

Flow: build brief → Telegram approval → agent loop → salvage/render →
email + Telegram chunks + HA sensor + Loki events → outcome confirm.
Decline / timeout / needs-human all reset the incident's ``investigated``
flag so it is re-proposed on the next run.

Every investigation is also *persisted* (roadmap §5.1): a row is created before
the approval is asked — carrying its provenance (the triggering ``findings``
and the rendered brief) from the start, so a pending or declined run still
shows what it was about — and carries its status through the flow, while the
runner's ``on_step`` callback streams the agent's tool timeline into
``investigation_steps`` as it happens, now with the per-turn token
attribution and (optionally, ``settings.store_transcripts``) the agent's full
message history, capped at 512 KB; the finished row also carries the run's
cost in ``settings.currency`` (roadmap §5.6). The report's optional
``## Tooling feedback`` section — the agent's own notes on what would have
made a tool more useful — is indexed into ``tool_feedback`` on the way past
(``record_tool_feedback``, shared with the replay pipeline). The agent phase runs under a
process-wide semaphore (``settings.max_concurrent_investigations``) acquired
*after* approval, so a six-hour approval wait never occupies a slot.

The approval itself is *not* Telegram-only (roadmap §5.7 "web approvals"): the
Telegram button races a poll of ``investigations.approval_decision``, which any
other process (the dashboard) can write. With no Telegram configured the store
poll becomes the whole gate, so a dashboard-only deployment still gets a human
in the loop instead of silently skipping the approval.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from heim.agent.runner import run_agent
from heim.config import expand_env
from heim.costing import cost_of
from heim.channels.telegram import chunk_text
from heim.reports.render import (
    extract_sections,
    extract_tool_feedback,
    investigation_email,
    salvage,
)
from heim.runtime import Runtime
from heim.tools.base import ToolContext, load_tools

log = logging.getLogger(__name__)

_ROLE_TEMPLATE = {"guest": "guest", "hypervisor": "hypervisor", "ha-guest": "ha-guest"}
_TEMP_RE = re.compile(r"temp|thermal|°c", re.I)


@dataclass
class InvestigationRequest:
    host: str
    host_role: str = "guest"          # guest | hypervisor | ha-guest
    fingerprint: str = ""
    findings: list[dict] = field(default_factory=list)
    retry_of: int = 0                 # investigation id this one re-runs (§5.5)

    @property
    def tag(self) -> str:
        qid = self.fingerprint.split("|")[1] if "|" in self.fingerprint else ""
        return f"{self.host}|{qid}" if qid else self.host


def findings_text(findings: list[dict]) -> str:
    """Port of Build Brief's findings formatting."""
    if not findings:
        return "(no structured findings were passed; investigate the general health of the host)"
    lines = []
    for i, f in enumerate(findings):
        line = (
            f"{i + 1}. [{f.get('severity', '?')}] {f.get('metric') or f.get('label') or ''}"
            + (f" ({f['trend']})" if f.get("trend") else "")
            + f" — {f.get('detail', '')}"
            + (f" (suggested: {f['recommendation']})" if f.get("recommendation") else "")
        )
        lines.append(line)
    return "\n".join(lines)


def _approval_text(req: InvestigationRequest, ftext: str) -> str:
    """Port of the n8n 'Ask Approval (Telegram)' message."""
    note = ""
    if req.host_role == "hypervisor":
        note = (
            f"\n\n⚠️ {req.host} is the Proxmox hypervisor (no direct SSH). This investigates from "
            "the guest VM ubuntu-server + Prometheus per-guest metrics — correlation, not authority."
        )
    how = (
        "query Prometheus and SSH into ubuntu-server (read-only)"
        if req.host_role == "hypervisor"
        else "SSH in (read-only)" if req.host_role == "guest"
        else "query Prometheus and the HA API (read-only)"
    )
    return (
        f"🔍 Investigation approval needed for host \"{req.host}\".{note}\n\n"
        f"Findings that triggered it:\n{ftext}\n\n"
        f"Approve to let the monitoring agent {how} and find the root cause. If you decline or "
        f"don't respond, no investigation runs and it will be re-proposed on the next monitoring run."
    )


def build_system_prompt(rt: Runtime, jenv: Environment, host: str, *,
                        prompt_file: str | Path | None = None) -> str:
    """Render the investigator's system prompt for ``host``.

    Factored out of the pipeline so the replay harness (§5.6) can rebuild a
    *byte-identical* prompt for a stored investigation instead of an
    approximation of one — and, with ``prompt_file``, swap in a candidate
    prompt that still goes through the same jinja render + ``${VAR}``
    expansion, so a prompt experiment differs from the baseline in exactly the
    text being tested.
    """
    cfg = rt.config
    agent = cfg.agents["investigator"]
    ordered = sorted(cfg.hosts.values(), key=lambda h: (h.name != host, h.name))
    facts = "\n".join(h.facts.strip() for h in ordered if h.facts.strip())
    privileges = "\n".join(h.privileges.strip() for h in cfg.hosts.values() if h.privileges.strip())
    if prompt_file:
        source = str(prompt_file)
        template = jenv.from_string(Path(prompt_file).read_text())
    else:
        source = agent.prompt
        template = jenv.get_template(agent.prompt)
    return expand_env(
        template.render(
            now=rt.now_iso(),
            facts=facts,
            privileges=privileges or "(no SSH privileges configured)",
            soft_step_budget=agent.soft_step_budget,
        ),
        source=source,
    )


def _build_system_prompt(rt: Runtime, jenv: Environment, req: InvestigationRequest) -> str:
    return build_system_prompt(rt, jenv, req.host)


def _action(host: str, phase: str, fingerprint: str, message: str, ts: str) -> dict:
    return {"event": "action", "labels": {"host": host, "phase": phase},
            "fields": {"fingerprint": fingerprint, "message": message, "ts": ts}}


def _is_blocked(result_str: str) -> bool:
    """True when a tool result is a guard rejection (``{"blocked": true, ...}``)."""
    try:
        parsed = json.loads(result_str)
    except Exception:
        return False
    return isinstance(parsed, dict) and parsed.get("blocked") is True


def _step_recorder(rt: Runtime, investigation_id: int):
    """Build the runner's ``on_step`` callback: persist each executed step.

    ``turn_in``/``turn_out`` are the usage of the assistant turn that asked for
    this call, attributed to the turn's first executed step (see
    ``agent.runner.OnStep``) — so the column sums to the run total even though
    an individual sibling step reads 0.
    """
    def on_step(seq: int, tool: str, args: dict, result: str, duration_ms: float,
                turn_in: int = 0, turn_out: int = 0) -> None:
        text = result if isinstance(result, str) else str(result)
        rt.store.add_step(
            investigation_id,
            seq=seq,
            tool=tool,
            args_json=json.dumps(args, ensure_ascii=False, default=str),
            result_preview=text[:400],
            result_bytes=len(text),
            blocked=_is_blocked(text),
            duration_ms=int(round(duration_ms)),
            input_tokens=int(turn_in or 0),
            output_tokens=int(turn_out or 0),
        )
    return on_step


def record_tool_feedback(rt: Runtime, investigation_id: int, report_md: str) -> int:
    """Persist the report's optional ``## Tooling feedback`` lines.

    Called for complete *and* incomplete runs — an investigation that ran out
    of evidence is exactly the one with something to say about its tools — and
    from the replay pipeline through the same path, so a replayed model's
    opinion lands next to the original's. Never raises: a suggestion is a nice
    extra, not part of the report contract.
    """
    written = 0
    try:
        for tool, suggestion in extract_tool_feedback(report_md or ""):
            written += 1 if rt.store.add_tool_feedback(
                investigation_id, tool, suggestion, created_at=rt.now_iso()) else 0
    except Exception:
        log.exception("recording tool feedback for investigation #%s failed", investigation_id)
    return written


#: Hard ceiling on a stored transcript (roadmap §5.6). Transcripts exist for
#: post-morteming a wrong root cause, and the newest turns are the ones that
#: produced the conclusion — so the cap drops turns from the FRONT and leaves a
#: marker entry saying how many went, rather than truncating mid-JSON or
#: silently storing a prefix that stops before the reasoning.
TRANSCRIPT_MAX_BYTES = 512 * 1024


def _transcript_json(entries: list[dict] | None) -> str:
    """Serialize a transcript, capped at ``TRANSCRIPT_MAX_BYTES``.

    Returns '' for an empty transcript (the "not collected" value the column
    defaults to). A single oversized turn degenerates to the marker alone —
    honest about having kept nothing, rather than writing half a JSON array.
    """
    kept = list(entries or [])
    if not kept:
        return ""
    dropped = 0
    while True:
        marker = [{
            "role": "system",
            "truncated": dropped,
            "content": [{"type": "text", "text": (
                f"… {dropped} earlier turn(s) dropped — transcript capped at "
                f"{TRANSCRIPT_MAX_BYTES // 1024} KB, newest kept.")}],
        }] if dropped else []
        text = json.dumps(marker + kept, ensure_ascii=False, default=str)
        if len(text.encode("utf-8")) <= TRANSCRIPT_MAX_BYTES or not kept:
            return text
        kept.pop(0)
        dropped += 1


#: How often the approval wait re-reads ``investigations.approval_decision``.
APPROVAL_POLL_SECONDS = 5.0

_APPROVE = {"approve", "approved", "yes", "true"}
_DECLINE = {"decline", "declined", "no", "false"}


async def _store_decision(rt: Runtime, investigation_id: int, timeout_s: float,
                          poll_s: float | None = None) -> bool | None:
    """Poll the investigation row for a decision written by another process.

    Returns True/False once ``approval_decision`` says so, None on timeout.
    A read failure is logged and retried — a flaky read must not decline an
    investigation by accident.
    """
    # read at call time so the interval stays tunable (and testable)
    poll_s = APPROVAL_POLL_SECONDS if poll_s is None else poll_s
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, float(timeout_s))
    while True:
        try:
            decision = str(rt.store.approval_decision(investigation_id) or "").strip().lower()
        except Exception:
            log.exception("reading approval_decision for #%s failed", investigation_id)
            decision = ""
        if decision in _APPROVE:
            return True
        if decision in _DECLINE:
            return False
        remaining = deadline - loop.time()
        if remaining <= 0:
            return None
        await asyncio.sleep(min(poll_s, remaining))


async def _await_approval(rt: Runtime, investigation_id: int, text: str,
                          timeout_s: float) -> tuple[bool | None, str]:
    """Race the Telegram button against the store decision (dashboard/CLI).

    Whichever answers first wins; the loser is cancelled, so a Telegram reply
    that arrives after the dashboard already decided is ignored. Returns
    ``(answer, source)`` with answer None meaning "timed out".
    """
    tasks: dict[asyncio.Task, str] = {
        asyncio.create_task(_store_decision(rt, investigation_id, timeout_s)): "store",
    }
    if rt.telegram is not None:
        tasks[asyncio.create_task(rt.telegram.ask(text, timeout_s=timeout_s))] = "telegram"
    else:
        log.info("no Telegram configured — investigation #%s waits on a store decision "
                 "(dashboard) for up to %.1fh", investigation_id, timeout_s / 3600)
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)

    results: list[tuple[str, bool | None]] = []
    for t in done:
        try:
            results.append((tasks[t], t.result()))
        except Exception:
            log.exception("approval wait (%s) failed", tasks[t])
    for source, answer in results:
        if answer is not None:
            return answer, source
    return None, (results[0][0] if results else "")


async def run_investigation(
    rt: Runtime,
    req: InvestigationRequest,
    *,
    require_approval: bool | None = None,
    trigger: str = "manual",
    on_start=None,
) -> dict | None:
    """Returns a result summary dict, or None if declined/timed out/failed.

    ``on_start(investigation_id)`` is called as soon as the tracking row
    exists, so a caller that needs the id even on the declined/failed paths
    (the queue worker) can capture it.
    """
    cfg = rt.config
    agent_cfg = cfg.agents["investigator"]
    jenv = Environment(loader=FileSystemLoader(cfg.prompts_dir))
    ftext = findings_text(req.findings)
    generated_at = rt.now_iso()

    # The brief is pure template rendering with no side effects, so it is built
    # *before* the approval gate and stored with the row: the human deciding on
    # a pending investigation — and anyone reading a declined one later — can
    # see exactly what the agent was going to be asked. The same string is
    # handed to the agent below, unchanged.
    template = _ROLE_TEMPLATE.get(req.host_role, "guest")
    brief = expand_env(
        jenv.get_template(f"briefs/{template}.md.j2").render(
            host=req.host, findings_text=ftext, is_temperature=bool(_TEMP_RE.search(ftext)),
        ),
        source=f"briefs/{template}.md.j2",
    )

    # --------------------------------------------------- tracking row (§5.1)
    require = cfg.settings.approvals.require if require_approval is None else require_approval
    # A human gate is needed whenever approvals are required and this is not a
    # dry run — Telegram is one way to answer it, the store (dashboard/CLI) the
    # other. With neither channel the wait simply times out into "declined",
    # which is the safe direction.
    will_ask = bool(require and not rt.dry_run)
    inv_id = rt.store.create_investigation(
        fingerprint=req.fingerprint,
        host=req.host,
        host_role=req.host_role,
        agent_name="investigator",
        model=agent_cfg.model,
        trigger=trigger,
        status="pending_approval" if will_ask else "running",
        started_at=generated_at,
        retry_of=req.retry_of,
        brief_md=brief,
        findings_json=json.dumps(req.findings, ensure_ascii=False, default=str),
    )
    if on_start is not None:
        try:
            on_start(inv_id)
        except Exception:
            log.exception("on_start callback failed for investigation #%s", inv_id)

    # ------------------------------------------------------------- approval
    if will_ask:
        await rt.emit_loki([_action(req.host, "approval_requested", req.fingerprint,
                                    f"Approval requested for {req.host}", generated_at)])
        answer, source = await _await_approval(
            rt, inv_id, _approval_text(req, ftext),
            cfg.settings.approvals.approve_timeout_hours * 3600,
        )
        if answer is not True:
            log.info("investigation of %s declined/timed out (%s)", req.host, source or "no answer")
            rt.store.update_investigation(
                inv_id, status="declined", finished_at=rt.now_iso(),
                approval_decision="decline" if answer is False else "timeout",
            )
            if req.fingerprint:
                rt.store.set_investigated(req.fingerprint, False)
            await rt.emit_loki([_action(req.host, "declined", req.fingerprint,
                                        "Investigation declined", rt.now_iso())])
            return None
        log.info("investigation of %s approved via %s", req.host, source or "?")
        rt.store.update_investigation(inv_id, status="running", approval_decision="approve")
    await rt.emit_loki([_action(req.host, "started", req.fingerprint,
                                "Investigation started by AI agent", rt.now_iso())])

    # The concurrency cap (§5.7) covers the agent run and its delivery only —
    # the approval above and the outcome confirm below are human waits of up to
    # hours and must not hold a slot.
    try:
        async with rt.investigation_slot():
            # -------------------------------------------------------- the agent
            system = _build_system_prompt(rt, jenv, req)
            ctx = ToolContext(config=cfg, tag=req.tag, feed=rt.feed, audit=rt.audit)
            tools = load_tools(agent_cfg.tools, cfg, ctx)
            result = await run_agent(
                agent_cfg, system=system, user_prompt=brief, tools=tools,
                on_step=_step_recorder(rt, inv_id),
                collect_transcript=cfg.settings.store_transcripts,
            )

            # --------------------------------------------------------- rendering
            report = salvage(result.output_text, ftext)
            # the agent's own notes on its toolbox (optional section) — kept in
            # the report AND indexed per tool for the dashboard's usage card
            record_tool_feedback(rt, inv_id, report.report_md)
            # §5.6: price the run. An unpriced model stores 0 — the dashboard
            # renders that as an em dash, never as "$0.00".
            cost = cost_of(agent_cfg.model, result.input_tokens, result.output_tokens,
                           cfg.settings.model_prices)
            rt.store.update_investigation(
                inv_id,
                status="incomplete" if report.incomplete else "complete",
                incomplete_reason=(report.reason or "") if report.incomplete else "",
                report_md=report.report_md,
                input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
                n_steps=len(result.steps),
                cost=float(cost or 0.0),
                transcript_json=_transcript_json(getattr(result, "transcript", None)),
                finished_at=rt.now_iso(),
            )
            subject, html = investigation_email(
                host=req.host, report=report, generated_at=generated_at,
                n_steps=len(result.steps), input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
            )
            await rt.send_email(subject, html)

            # Telegram: full report, chunked (port of Split Report for Telegram)
            header = f"🔍 Investigation Report — {req.host}" + ("  ⚠️ incomplete" if report.incomplete else "")
            footer = (f"{result.input_tokens:,} in · {result.output_tokens:,} out tokens · "
                      f"{len(result.steps)} commands")
            if not rt.dry_run and rt.telegram is not None:
                try:
                    await rt.telegram.send_chunks(f"{header}\n\n{report.report_md}\n\n{footer}")
                except Exception:
                    log.exception("telegram report push failed")

            # Home Assistant sensor
            from heim.channels.ha import slug as ha_slug
            await rt.push_ha(
                f"investigation_{ha_slug(req.host)}",
                rt.now().strftime("%Y-%m-%d %H:%M"),
                {
                    "friendly_name": f"Investigation — {req.host}",
                    "icon": "mdi:magnify-scan",
                    "host": req.host,
                    "status": "incomplete" if report.incomplete else "complete",
                    "steps": len(result.steps),
                    "updated": rt.now_iso(),
                    "report": report.report_md.strip(),
                },
            )

            # Loki: investigation event + actions (port of Investigation To Loki)
            sections = extract_sections(report.report_md)
            status = "incomplete" if report.incomplete else "complete"
            events = [{
                "event": "investigation",
                "labels": {"host": req.host, "status": status},
                "fields": {
                    "fingerprint": req.fingerprint,
                    "rootCause": sections["root_cause"],
                    "confidence": sections["confidence"],
                    "impact": sections["summary"][:400],
                    "remediation": sections["remediation"],
                    "recommendedActions": sections["remediation"],
                    "tokenEstimate": result.input_tokens + result.output_tokens,
                    "nSteps": len(result.steps),
                    "detectedAt": "", "resolvedAt": "",
                },
            }]
            if not report.incomplete:
                events.append(_action(req.host, "rootcause", req.fingerprint, "Root cause identified", rt.now_iso()))
            events.append(_action(req.host, "report", req.fingerprint, "Report generated", rt.now_iso()))
            await rt.emit_loki(events)
    except Exception as exc:
        # An investigation crash must never take the daemon down: record it,
        # log it, and let the caller (dispatch task) continue.
        log.exception("investigation of %s failed", req.host)
        try:
            rt.store.update_investigation(
                inv_id, status="failed", finished_at=rt.now_iso(),
                incomplete_reason=f"{type(exc).__name__}: {exc}",
            )
        except Exception:
            log.exception("could not record investigation failure")
        return None

    # ------------------------------------------------------ outcome confirm
    if require and not rt.dry_run and rt.telegram is not None:
        outcome = await rt.telegram.ask(
            f"Investigation of \"{req.host}\" is complete (report delivered). Mark the outcome — "
            f"✅ Resolved = handled; ⚠️ Needs human = requires manual intervention (the incident "
            f"stays flagged and is re-proposed next run).",
            yes="✅ Resolved", no="⚠️ Needs human",
            timeout_s=cfg.settings.approvals.outcome_timeout_hours * 3600,
        )
        if outcome is True:
            rt.store.update_investigation(inv_id, status="resolved", outcome="resolved",
                                          finished_at=rt.now_iso())
            await rt.emit_loki([_action(req.host, "resolved", req.fingerprint, "Marked resolved", rt.now_iso())])
        else:  # needs human OR timeout -> re-surface next run
            rt.store.update_investigation(
                inv_id, status="needs_human",
                outcome="needs_human" if outcome is False else "timeout",
                finished_at=rt.now_iso(),
            )
            if req.fingerprint:
                rt.store.set_investigated(req.fingerprint, False)
            await rt.emit_loki([_action(req.host, "needs_human", req.fingerprint, "Flagged needs human", rt.now_iso())])

    return {
        "id": inv_id,
        "host": req.host,
        "incomplete": report.incomplete,
        "steps": len(result.steps),
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
        "cost": float(cost or 0.0),
        "subject": subject,
        "report_md": report.report_md,
    }


def request_from_dispatch(item: dict, rt: Runtime) -> InvestigationRequest:
    """Build a request from a reconcile/poller dispatch item.

    Port of 'Investigations To Items' / 'Dispatch Items': the findings list is
    synthesized from the incident row. host_role comes from the host's config
    file (the n8n poller hardcoded hypervisor-vs-guest; using the config role
    also routes ha-guest correctly)."""
    host = str(item.get("host") or "")
    host_cfg = rt.config.hosts.get(host)
    role = str(item.get("hostRole") or (host_cfg.role if host_cfg else "guest"))
    return InvestigationRequest(
        host=host,
        host_role=role,
        fingerprint=str(item.get("fingerprint") or ""),
        findings=[{
            "severity": item.get("severity", ""),
            "host": host,
            "metric": item.get("metric", ""),
            "trend": "",
            "detail": item.get("description", ""),
            "recommendation": "",
        }],
    )


async def dispatch_all(rt: Runtime, items: list[dict], *, concurrent: bool,
                       trigger: str = "manual") -> None:
    """Dispatch one investigation per item. ``concurrent`` fires them off as
    tasks (daemon); the concurrency *cap* is enforced inside
    ``run_investigation`` so it holds for every entry point."""
    reqs = [request_from_dispatch(i, rt) for i in items]
    if concurrent:
        for r in reqs:
            asyncio.create_task(run_investigation(rt, r, trigger=trigger))
    else:
        for r in reqs:
            await run_investigation(rt, r, trigger=trigger)
