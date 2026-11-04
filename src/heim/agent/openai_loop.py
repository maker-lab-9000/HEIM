"""The investigation agent loop over the OpenAI-compatible chat API.

Spec 2026-11-04-investigator-openrouter: the investigator may run on
OpenRouter or any OpenAI-compatible server (a LAN llama.cpp). This loop keeps
the Anthropic loop's contract exactly — same tools and guards, same
``hard_step_cap`` (+3 turns of slack) and forced-final text, the same
``on_step`` first-step-of-turn token attribution, and the same plain-dict
transcript shape, so tracking, the dashboard and the replay cassette read
both alike. Only the wire format differs.

Tool-call arguments arrive as a JSON *string*; one that does not parse to an
object is answered with an error and never executed with guessed arguments.
Retries cover what can heal by waiting (connection errors, 429, 5xx); any
other HTTP error — a usage limit, a bad key — fails at once.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

import httpx

from heim.agent.runner import (FORCED_FINAL_TEXT, TRANSCRIPT_RESULT_CHARS, AgentResult,
                               AgentStep, OnStep)
from heim.config import AgentCfg
from heim.llm import endpoint_for
from heim.tools.base import Tool

log = logging.getLogger(__name__)

RETRIES = 3
RETRY_WAIT_S = 3.0
TIMEOUT_S = 180.0

_STOP_REASONS = {"stop": "end_turn", "length": "max_tokens", "tool_calls": "tool_use"}


async def _post_with_retry(client: httpx.AsyncClient, url: str, headers: dict,
                           body: dict) -> dict:
    last = ""
    for attempt in range(RETRIES):
        try:
            r = await client.post(url, headers=headers, json=body)
        except httpx.TransportError as exc:
            last = f"{type(exc).__name__}: {exc}"
        else:
            if r.status_code < 400:
                return r.json()
            last = f"HTTP {r.status_code}: {str(r.text or '').strip()[:200]}"
            if r.status_code != 429 and r.status_code < 500:
                raise RuntimeError(last)
        log.warning("%s call failed (attempt %d/%d): %s", body.get("model"), attempt + 1,
                    RETRIES, last)
        if attempt + 1 < RETRIES:
            await asyncio.sleep(RETRY_WAIT_S * (attempt + 1))
    raise RuntimeError(last)


def _parse_args(raw) -> tuple[dict | None, str]:
    if isinstance(raw, dict):
        return raw, ""
    try:
        parsed = json.loads(raw or "{}")
    except (ValueError, TypeError) as exc:
        return None, str(exc)
    if not isinstance(parsed, dict):
        return None, f"expected a JSON object, got {type(parsed).__name__}"
    return parsed, ""


async def run_openai_agent(
    cfg: AgentCfg,
    *,
    system: str,
    user_prompt: str,
    tools: list[Tool],
    on_step: OnStep | None = None,
    collect_transcript: bool = False,
    transport: httpx.AsyncBaseTransport | None = None,
) -> AgentResult:
    """Run the tool loop on ``cfg.ref``. The caller closes the tools."""
    url, key = endpoint_for(cfg.ref)
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    schemas = [t.openai_schema() for t in tools]
    toolmap = {t.name: t for t in tools}
    messages: list[dict] = [{"role": "system", "content": system},
                            {"role": "user", "content": user_prompt}]
    steps: list[AgentStep] = []
    in_tok = out_tok = 0
    forced = False
    transcript: list[dict] = (
        [{"role": "user", "content": [{"type": "text", "text": user_prompt}]}]
        if collect_transcript else []
    )

    async with httpx.AsyncClient(timeout=TIMEOUT_S, transport=transport) as client:
        for _ in range(cfg.hard_step_cap + 3):
            body = {"model": cfg.model, "max_tokens": cfg.max_tokens, "messages": messages}
            if schemas:
                body["tools"] = schemas
                body["tool_choice"] = "auto"
            if cfg.temperature is not None:
                body["temperature"] = cfg.temperature
            data = await _post_with_retry(client, url, headers, body)
            usage = data.get("usage") or {}
            turn = (int(usage.get("prompt_tokens") or 0),
                    int(usage.get("completion_tokens") or 0))
            in_tok += turn[0]
            out_tok += turn[1]
            credit = turn

            choice = (data.get("choices") or [{}])[0]
            msg = choice.get("message") or {}
            text = msg.get("content") or ""
            calls = msg.get("tool_calls") or []
            finish = str(choice.get("finish_reason") or "")

            if calls:
                messages.append({"role": "assistant", "content": msg.get("content"),
                                 "tool_calls": calls})
                if collect_transcript:
                    blocks = [{"type": "text", "text": text}] if text else []
                    for c in calls:
                        fn = c.get("function") or {}
                        args, _ = _parse_args(fn.get("arguments"))
                        blocks.append({"type": "tool_use", "name": str(fn.get("name") or ""),
                                       "input": args or {}})
                    transcript.append({"role": "assistant", "content": blocks})
                results: list[str] = []
                for c in calls:
                    fn = c.get("function") or {}
                    name = str(fn.get("name") or "")
                    if len(steps) >= cfg.hard_step_cap:
                        forced = True
                        out = FORCED_FINAL_TEXT
                    else:
                        args, err = _parse_args(fn.get("arguments"))
                        if args is None:
                            out = f"invalid tool arguments: {err}"
                        else:
                            tool = toolmap.get(name)
                            t_start = time.monotonic()
                            out = f"unknown tool: {name}" if tool is None else await tool(args)
                            duration_ms = (time.monotonic() - t_start) * 1000.0
                            turn_in, turn_out = credit
                            credit = (0, 0)
                            steps.append(AgentStep(name, args, str(out)[:400], turn_in, turn_out))
                            if on_step is not None:
                                try:
                                    on_step(len(steps), name, args, str(out), duration_ms,
                                            turn_in, turn_out)
                                except Exception:  # tracking must never sink the loop
                                    log.exception("on_step callback failed (step %d)",
                                                  len(steps))
                    results.append(str(out))
                    messages.append({"role": "tool", "tool_call_id": str(c.get("id") or ""),
                                     "content": str(out)})
                if collect_transcript:
                    transcript.append({"role": "user", "content": [
                        {"type": "tool_result", "content": r[:TRANSCRIPT_RESULT_CHARS]}
                        for r in results]})
                continue

            if collect_transcript:
                transcript.append({"role": "assistant",
                                   "content": [{"type": "text", "text": text}] if text else []})
            return AgentResult(text, steps, in_tok, out_tok, _STOP_REASONS.get(finish, finish),
                               forced, transcript)

    return AgentResult("", steps, in_tok, out_tok, "loop-cap", True, transcript)
