"""The investigation agent loop (replaces n8n's LangChain Tools Agent).

Anthropic-native tool use: no scratchpad-text round-tripping, so the
"model emits its tool call as plain text" failure class the n8n stack hit
(exec 60136) cannot occur at this layer. Budget is enforced in the loop:
past ``hard_step_cap`` no more tools are executed and the model is told to
write the report. Token usage is REAL (from API usage), not estimated.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from anthropic import AsyncAnthropic, APIError, APIConnectionError

from heim.config import AgentCfg
from heim.tools.base import Tool

log = logging.getLogger(__name__)

RETRIES = 3
RETRY_WAIT_S = 3.0


@dataclass
class AgentStep:
    tool: str
    args: dict
    result_preview: str


@dataclass
class AgentResult:
    output_text: str
    steps: list[AgentStep] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    stop_reason: str = ""
    forced_final: bool = False


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


async def run_agent(
    cfg: AgentCfg,
    *,
    system: str,
    user_prompt: str,
    tools: list[Tool],
) -> AgentResult:
    client = AsyncAnthropic()
    schemas = [t.anthropic_schema() for t in tools]
    toolmap = {t.name: t for t in tools}
    messages: list[dict] = [{"role": "user", "content": user_prompt}]

    steps: list[AgentStep] = []
    in_tok = out_tok = 0
    forced = False

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

            tool_uses = [b for b in resp.content if b.type == "tool_use"]
            if resp.stop_reason == "tool_use" and tool_uses:
                messages.append({"role": "assistant", "content": resp.content})
                results = []
                for tu in tool_uses:
                    if len(steps) >= cfg.hard_step_cap:
                        forced = True
                        out = (
                            "Step budget exhausted — no further tool calls will be executed. "
                            "Write the final report NOW, starting with '## Summary'."
                        )
                    else:
                        tool = toolmap.get(tu.name)
                        if tool is None:
                            out = f"unknown tool: {tu.name}"
                        else:
                            out = await tool(dict(tu.input or {}))
                        steps.append(AgentStep(tu.name, dict(tu.input or {}), str(out)[:400]))
                    results.append({"type": "tool_result", "tool_use_id": tu.id, "content": str(out)})
                messages.append({"role": "user", "content": results})
                continue

            text = "".join(b.text for b in resp.content if b.type == "text")
            return AgentResult(text, steps, in_tok, out_tok, resp.stop_reason or "", forced)

        return AgentResult("", steps, in_tok, out_tok, "loop-cap", True)
    finally:
        for t in tools:
            try:
                await t.close()
            except Exception:
                pass
