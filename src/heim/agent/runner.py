"""The investigation agent loop (replaces n8n's LangChain Tools Agent).

Anthropic-native tool use: no scratchpad-text round-tripping, so the
"model emits its tool call as plain text" failure class the n8n stack hit
(exec 60136) cannot occur at this layer. Budget is enforced in the loop:
past ``hard_step_cap`` no more tools are executed and the model is told to
write the report. Token usage is REAL (from API usage), not estimated — both
the run total and the per-step attribution (roadmap §5.6), which credits each
assistant turn's usage to the first tool call that turn requested.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from anthropic import AsyncAnthropic, APIError, APIConnectionError

from heim.config import AgentCfg
from heim.tools.base import Tool

log = logging.getLogger(__name__)

RETRIES = 3
RETRY_WAIT_S = 3.0


#: Each stored tool_result is clipped to this many characters in the optional
#: transcript, bounded so one chatty command cannot dominate the 512 KB the
#: pipeline is willing to keep. 8192 = the 8 KB the tools themselves clip their
#: output at (``config/tools/*.yaml``: ``clip_bytes``), which makes a stored
#: transcript **lossless in practice** — that is what lets the replay harness
#: (§5.6) serve the stored results back to another model as a cassette instead
#: of feeding it a truncated version of the original's evidence.
TRANSCRIPT_RESULT_CHARS = 8192


@dataclass
class AgentStep:
    tool: str
    args: dict
    result_preview: str
    #: usage of the assistant turn that REQUESTED this call — see ``OnStep``
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class AgentResult:
    output_text: str
    steps: list[AgentStep] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    stop_reason: str = ""
    forced_final: bool = False
    #: the full message history as plain dicts — only when ``collect_transcript``
    transcript: list[dict] = field(default_factory=list)


async def _create_with_retry(client: AsyncAnthropic, **kwargs):
    last: Exception | None = None
    for attempt in range(RETRIES):
        try:
            return await client.messages.create(**kwargs)
        except (APIError, APIConnectionError) as exc:
            last = exc
            log.warning("anthropic call failed (attempt %d/%d): %s", attempt + 1, RETRIES, exc)
            await asyncio.sleep(RETRY_WAIT_S * (attempt + 1))
    raise last  # type: ignore[misc]


#: ``on_step(seq, tool_name, args, result_str, duration_ms, turn_in, turn_out)``
#: — fired right after every *executed* tool call (seq starts at 1). Used by the
#: investigation pipeline to persist the step timeline live, so a crash
#: mid-investigation still leaves the completed steps on disk.
#:
#: ``turn_in``/``turn_out`` are the token usage of the assistant turn that
#: REQUESTED this tool call. The API bills a turn, not a call: when one turn
#: issues several tool_use blocks there is no per-call split to be had, so the
#: **first executed step of the turn carries the whole delta and its siblings
#: carry 0**. Summing the column therefore still equals the run's real usage —
#: a per-step number is a lower bound on that step's share, never an estimate.
OnStep = Callable[[int, str, dict, str, float, int, int], None]


def _transcript_blocks(content) -> list[dict]:
    """An assistant turn's content blocks as plain, JSON-safe dicts."""
    out: list[dict] = []
    for b in content or []:
        kind = getattr(b, "type", "")
        if kind == "text":
            out.append({"type": "text", "text": getattr(b, "text", "")})
        elif kind == "tool_use":
            out.append({"type": "tool_use", "name": getattr(b, "name", ""),
                        "input": dict(getattr(b, "input", None) or {})})
    return out


async def run_agent(
    cfg: AgentCfg,
    *,
    system: str,
    user_prompt: str,
    tools: list[Tool],
    on_step: OnStep | None = None,
    collect_transcript: bool = False,
) -> AgentResult:
    client = AsyncAnthropic()
    schemas = [t.anthropic_schema() for t in tools]
    toolmap = {t.name: t for t in tools}
    messages: list[dict] = [{"role": "user", "content": user_prompt}]

    steps: list[AgentStep] = []
    in_tok = out_tok = 0
    forced = False
    # The SDK's message objects are not JSON-serializable and hold more than we
    # want on disk, so the transcript is built alongside `messages` rather than
    # converted from it afterwards (roadmap §5.6).
    transcript: list[dict] = (
        [{"role": "user", "content": [{"type": "text", "text": user_prompt}]}]
        if collect_transcript else []
    )

    try:
        # +3 turns of slack so a forced-final instruction can still be answered
        for _ in range(cfg.hard_step_cap + 3):
            resp = await _create_with_retry(
                client,
                model=cfg.model,
                max_tokens=cfg.max_tokens,
                system=system,
                messages=messages,
                tools=schemas,
                **({"temperature": cfg.temperature} if cfg.temperature is not None else {}),
            )
            in_tok += resp.usage.input_tokens
            out_tok += resp.usage.output_tokens
            # Credit for this turn, handed to its FIRST executed step and then
            # spent — siblings of a multi-tool turn record 0 (see ``OnStep``).
            credit = (int(resp.usage.input_tokens), int(resp.usage.output_tokens))

            tool_uses = [b for b in resp.content if b.type == "tool_use"]
            if resp.stop_reason == "tool_use" and tool_uses:
                messages.append({"role": "assistant", "content": resp.content})
                if collect_transcript:
                    transcript.append({"role": "assistant",
                                       "content": _transcript_blocks(resp.content)})
                results = []
                for tu in tool_uses:
                    if len(steps) >= cfg.hard_step_cap:
                        forced = True
                        out = (
                            "Step budget exhausted — no further tool calls will be executed. "
                            "Write the final report NOW, starting with '## Summary'."
                        )
                    else:
                        args = dict(tu.input or {})
                        tool = toolmap.get(tu.name)
                        t_start = time.monotonic()
                        if tool is None:
                            out = f"unknown tool: {tu.name}"
                        else:
                            out = await tool(args)
                        duration_ms = (time.monotonic() - t_start) * 1000.0
                        turn_in, turn_out = credit
                        credit = (0, 0)
                        steps.append(AgentStep(tu.name, args, str(out)[:400],
                                               turn_in, turn_out))
                        if on_step is not None:
                            try:
                                on_step(len(steps), tu.name, args, str(out), duration_ms,
                                        turn_in, turn_out)
                            except Exception:  # a tracking failure must never sink the loop
                                log.exception("on_step callback failed (step %d)", len(steps))
                    results.append({"type": "tool_result", "tool_use_id": tu.id, "content": str(out)})
                messages.append({"role": "user", "content": results})
                if collect_transcript:
                    transcript.append({"role": "user", "content": [
                        {"type": "tool_result",
                         "content": str(r["content"])[:TRANSCRIPT_RESULT_CHARS]}
                        for r in results
                    ]})
                continue

            text = "".join(b.text for b in resp.content if b.type == "text")
            if collect_transcript:
                transcript.append({"role": "assistant",
                                   "content": _transcript_blocks(resp.content)})
            return AgentResult(text, steps, in_tok, out_tok, resp.stop_reason or "", forced,
                               transcript)

        return AgentResult("", steps, in_tok, out_tok, "loop-cap", True, transcript)
    finally:
        for t in tools:
            try:
                await t.close()
            except Exception:
                pass
