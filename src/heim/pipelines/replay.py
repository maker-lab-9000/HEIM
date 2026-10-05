"""Offline replay of a stored investigation (roadmap §5.6, the eval harness).

One question, asked cheaply and repeatably: **would another model — or another
system prompt — have reached the same root cause on the same evidence?**

So the replay is deliberately hermetic. The brief and the system prompt are
rebuilt through the very code paths the original used; the tool *results* come
from the stored transcript via ``agent.cassette`` instead of from the hosts
(the disk that was full in March is not full now, and a "replay" against fresh
evidence compares nothing); and **the only outbound call is the LLM**. No SSH,
no Prometheus/HA/Proxmox, no approval gate, no email/Telegram/HA/Loki — a
replay is an experiment, not an incident response, and must never page anyone
or look like a second investigation happened.

The result is stored as a normal investigation row with ``trigger='replay'``
and ``replay_of`` pointing at the original, so it shows up in the dashboard
with its steps, tokens, cost and transcript, lineage-linked to its source.
"""
from __future__ import annotations

import json
import logging

from jinja2 import Environment, FileSystemLoader

from heim.agent.cassette import Cassette, cassette_tools
from heim.agent.runner import run_agent
from heim.costing import cost_of
from heim.pipelines.investigate import (
    _step_recorder,
    _transcript_json,
    build_system_prompt,
    findings_text,
    record_tool_feedback,
    with_model,
)
from heim.reports.render import salvage
from heim.runtime import Runtime
from heim.tools.base import ToolContext

log = logging.getLogger(__name__)


class ReplayError(ValueError):
    """A replay that cannot be set up (no such run, no transcript, no brief)."""


def _load_transcript(row: dict) -> list[dict]:
    raw = str(row.get("transcript_json") or "")
    if not raw:
        raise ReplayError(
            f"investigation #{row.get('id')} has no stored transcript, so there is "
            "nothing to replay against. Transcripts are the cassette: set "
            "`store_transcripts: true` in config/settings.yaml and replay a run "
            "recorded after that."
        )
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise ReplayError(
            f"investigation #{row.get('id')} has an unreadable transcript_json: {exc}"
        ) from exc
    if not isinstance(parsed, list):
        raise ReplayError(f"investigation #{row.get('id')} transcript_json is not a list")
    return parsed


async def run_replay(
    rt: Runtime,
    investigation_id: int,
    *,
    model: str | None = None,
    prompt_file: str | None = None,
) -> dict | None:
    """Replay investigation ``investigation_id`` offline. Summary dict, or None.

    ``model`` overrides the investigator's model; ``prompt_file`` swaps the
    system prompt for a candidate file (rendered and env-expanded exactly like
    the configured one). Both may be given; neither is required — replaying
    with the same model and prompt measures the run's own reproducibility.

    Raises ``ReplayError`` when the replay cannot be set up at all (unknown
    investigation, no stored transcript, no brief). Returns None when the
    replay *ran* and failed, mirroring ``run_investigation``.
    """
    cfg = rt.config
    original = rt.store.investigation(investigation_id)
    if original is None:
        raise ReplayError(f"no investigation #{investigation_id} in the store")
    brief = str(original.get("brief_md") or "")
    if not brief.strip():
        raise ReplayError(
            f"investigation #{investigation_id} has no stored brief_md — the replay "
            "would be asking a different question than the original did"
        )
    transcript = _load_transcript(original)
    cassette = Cassette.from_transcript(transcript)

    agent_cfg = with_model(cfg.agents["investigator"], model)
    jenv = Environment(loader=FileSystemLoader(cfg.prompts_dir))
    host = str(original.get("host") or "")
    system = build_system_prompt(rt, jenv, host, prompt_file=prompt_file)

    try:
        findings = json.loads(str(original.get("findings_json") or "[]"))
    except ValueError:
        log.warning("investigation #%s has unreadable findings_json", investigation_id)
        findings = []
    ftext = findings_text(findings if isinstance(findings, list) else [])

    inv_id = rt.store.create_investigation(
        fingerprint=str(original.get("fingerprint") or ""),
        host=host,
        host_role=str(original.get("host_role") or ""),
        agent_name=str(original.get("agent_name") or "investigator"),
        model=agent_cfg.model,
        trigger="replay",
        status="running",
        started_at=rt.now_iso(),
        replay_of=int(investigation_id),
        # provenance is copied verbatim: a replay is *the same question*, and
        # re-deriving the brief would let the two drift apart silently
        brief_md=brief,
        findings_json=str(original.get("findings_json") or ""),
    )
    log.info("replay #%s of investigation #%s on %s (%d recorded tool results)",
             inv_id, investigation_id, agent_cfg.model, len(cassette.entries))

    try:
        ctx = ToolContext(config=cfg, tag=f"replay#{inv_id}")   # no feed, no audit
        tools = cassette_tools(cassette, cfg, ctx)
        result = await run_agent(
            agent_cfg, system=system, user_prompt=brief, tools=tools,
            on_step=_step_recorder(rt, inv_id),
            collect_transcript=True,   # a replay without its own tape is not evidence
        )
    except Exception as exc:
        log.exception("replay #%s of investigation #%s failed", inv_id, investigation_id)
        try:
            rt.store.update_investigation(
                inv_id, status="failed", finished_at=rt.now_iso(),
                incomplete_reason=f"{type(exc).__name__}: {exc}",
            )
        except Exception:
            log.exception("could not record replay failure")
        return None

    report = salvage(result.output_text, ftext, stop_reason=getattr(result, "stop_reason", ""))
    record_tool_feedback(rt, inv_id, report.report_md)
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

    return {
        "id": inv_id,
        "replay_of": int(investigation_id),
        "host": host,
        "model": agent_cfg.model,
        "prompt_file": prompt_file or "",
        "status": "incomplete" if report.incomplete else "complete",
        "incomplete": report.incomplete,
        "steps": len(result.steps),
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
        "cost": float(cost or 0.0),
        "report_md": report.report_md,
        "cassette": cassette.stats(),
        "original": original,
    }
