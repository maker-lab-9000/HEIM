"""Single-completion LLM calls for the daily analyst
(port of n8n PAM 10's Basic LLM Chain: primary model + automatic fallback).

Primary is any OpenRouter model (OpenAI-compatible API, env OPENROUTER_API_KEY);
fallback is Anthropic (env ANTHROPIC_API_KEY).
"""
from __future__ import annotations

import json
import logging
import re

import httpx
from anthropic import AsyncAnthropic

from heim.config import AnalystCfg, ModelRef, env

log = logging.getLogger(__name__)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


async def _complete_openrouter(model: str, system: str, user: str,
                               max_tokens: int) -> tuple[str, dict]:
    key = env("OPENROUTER_API_KEY", required=True)
    async with httpx.AsyncClient(timeout=180) as client:
        r = await client.post(
            OPENROUTER_URL,
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        r.raise_for_status()
        data = r.json()
    content = data["choices"][0]["message"]["content"]
    if not (content or "").strip():
        raise RuntimeError("openrouter returned empty content")
    usage = data.get("usage") or {}
    return content, {"input": int(usage.get("prompt_tokens") or 0),
                     "output": int(usage.get("completion_tokens") or 0)}


async def _complete_anthropic(model: str, system: str, user: str,
                              max_tokens: int) -> tuple[str, dict]:
    client = AsyncAnthropic()
    resp = await client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = "".join(b.text for b in resp.content if b.type == "text")
    usage = getattr(resp, "usage", None)
    return text, {"input": int(getattr(usage, "input_tokens", 0) or 0),
                  "output": int(getattr(usage, "output_tokens", 0) or 0)}


async def _complete(ref: ModelRef, system: str, user: str, max_tokens: int) -> tuple[str, dict]:
    if ref.provider == "openrouter":
        return await _complete_openrouter(ref.model, system, user, max_tokens)
    return await _complete_anthropic(ref.model, system, user, max_tokens)


async def analyst_complete(cfg: AnalystCfg, system: str, user: str) -> tuple[str, str, dict]:
    """Returns (text, model_used, usage). Falls back on any primary failure.

    ``usage`` is ``{"input": int, "output": int}`` — the real token counts the
    provider reported, so the caller can price the run (roadmap §5.6). The
    *model actually used* is returned alongside it precisely because a fallback
    changes the price; never price a run against the primary model id.
    """
    try:
        text, usage = await _complete(cfg.primary, system, user, cfg.max_tokens)
        return text, cfg.primary.model, usage
    except Exception as exc:
        if cfg.fallback is None:
            raise
        log.warning("primary analyst model failed (%s); falling back to %s", exc, cfg.fallback.model)
        text, usage = await _complete(cfg.fallback, system, user, cfg.max_tokens)
        return text, cfg.fallback.model, usage


def parse_analysis(text: str) -> dict | None:
    """Parse the analyst's strict-JSON reply, tolerating code fences and
    surrounding prose (same cleanup the n8n Code nodes applied)."""
    raw = (text or "").strip()
    cleaned = re.sub(r"```json\n?", "", raw).replace("```", "").strip()
    for candidate in (cleaned,):
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict) and obj.get("overallHealth"):
                return obj
        except Exception:
            pass
    # last resort: first {...} block
    m = re.search(r"\{.*\}", cleaned, re.S)
    if m:
        try:
            obj = json.loads(m.group(0))
            if isinstance(obj, dict) and obj.get("overallHealth"):
                return obj
        except Exception:
            pass
    return None
