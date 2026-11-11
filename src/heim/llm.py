"""Single-completion LLM calls for the daily analyst
(port of n8n PAM 10's Basic LLM Chain: primary model + automatic fallback).

2026-11-04 — deliberate behaviour change (spec
docs/superpowers/specs/2026-11-04-analyst-provider-chain-design.md): the
primary + fallback pair became an ordered **chain** of any length, tried until
one entry answers. An Anthropic workspace usage limit had taken the daily report
down with only a two-step fallback. Two further changes ride with it: a reply
that ``accept`` rejects (unparseable analysis JSON) now counts as a failed
attempt and the next entry tries, and every attempt is recorded — with its
billed usage — so the run can be priced and the fallback surfaced.

Providers: ``anthropic`` (env ANTHROPIC_API_KEY), and two speakers of the
OpenAI-compatible chat API — ``openrouter`` (env OPENROUTER_API_KEY) and
``openai_compat`` (any ``base_url``, e.g. a LAN llama.cpp; a key only when
``api_key_env`` names one).
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Callable

import httpx
from anthropic import AsyncAnthropic

from heim.config import AnalystCfg, ModelRef, env

log = logging.getLogger(__name__)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
#: an attempt's error, as stored and shown — enough for an API message
ERROR_CLIP = 300


@dataclass
class Attempt:
    """One chain entry's try. Usage is kept whenever the provider answered,
    the successful attempt included, because every answer is billed."""
    provider: str
    model: str
    ok: bool
    error: str = ""
    input_tokens: int = 0
    output_tokens: int = 0

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class ChainResult:
    text: str
    analysis: dict | None
    model_used: str
    index: int                      # the answering entry's position in the chain
    usage: dict                     # the answering entry's {"input", "output"}
    attempts: list[Attempt] = field(default_factory=list)


class AnalystChainFailed(RuntimeError):
    """Every entry of the chain failed; ``attempts`` says how, in order."""

    def __init__(self, attempts: list[Attempt]):
        self.attempts = list(attempts)
        parts = "; ".join(f"{i}) {a.provider} {a.model} — {a.error}"
                          for i, a in enumerate(self.attempts, 1))
        super().__init__(f"all {len(self.attempts)} analyst models failed: {parts}")


class _Unusable(Exception):
    """The provider answered but the answer is not usable; it was still billed."""

    def __init__(self, reason: str, usage: dict):
        super().__init__(reason)
        self.usage = usage


async def _complete_openai_compat(url: str, key: str | None, model: str, system: str,
                                  user: str, max_tokens: int, *, timeout_s: float = 180.0,
                                  extra_body: dict | None = None) -> tuple[str, dict]:
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    body = {**(extra_body or {}),
            "model": model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ]}
    async with httpx.AsyncClient(timeout=timeout_s) as client:
        r = await client.post(url, headers=headers, json=body)
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            # keep the provider's own reason (e.g. "Insufficient credits"),
            # not httpx's boilerplate about where to read up on status codes
            body = str(getattr(r, "text", "") or "").strip()[:200]
            raise RuntimeError(f"HTTP {exc.response.status_code}: {body}") from None
        data = r.json()
    content = data["choices"][0]["message"]["content"]
    usage = data.get("usage") or {}
    usage = {"input": int(usage.get("prompt_tokens") or 0),
             "output": int(usage.get("completion_tokens") or 0)}
    if not (content or "").strip():
        raise _Unusable(f"{model} returned empty content", usage)
    return content, usage


async def _complete_anthropic(model: str, system: str, user: str,
                              max_tokens: int) -> tuple[str, dict]:
    client = AsyncAnthropic()
    resp = await client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    # Read text blocks only: models that think by default (Opus 5.5, Sonnet 5)
    # also return `thinking` blocks, empty unless display is requested.
    text = "".join(b.text for b in resp.content if b.type == "text")
    stop = str(getattr(resp, "stop_reason", "") or "")
    if stop in ("refusal", "max_tokens"):
        # Otherwise these surface only as "the analysis did not parse". A
        # refusal is a safety-classifier decline (HTTP 200); max_tokens on a
        # thinking model usually means thinking spent the budget first.
        details = getattr(resp, "stop_details", None)
        log.warning("analyst model %s stopped with %r%s — output is likely unusable "
                    "(%d chars of text)", model, stop,
                    f" ({getattr(details, 'category', '')})" if details else "", len(text))
    usage = getattr(resp, "usage", None)
    return text, {"input": int(getattr(usage, "input_tokens", 0) or 0),
                  "output": int(getattr(usage, "output_tokens", 0) or 0)}


def endpoint_for(ref: ModelRef) -> tuple[str, str | None]:
    """The chat-completions URL and API key of an OpenAI-compatible model
    (shared with the investigator's loop, ``agent/openai_loop.py``)."""
    if ref.provider == "openrouter":
        return OPENROUTER_URL, env("OPENROUTER_API_KEY", required=True)
    key = env(ref.api_key_env, required=True) if ref.api_key_env else None
    return ref.base_url.rstrip("/") + "/chat/completions", key


async def _complete(ref: ModelRef, system: str, user: str, max_tokens: int) -> tuple[str, dict]:
    if ref.provider == "anthropic":
        return await _complete_anthropic(ref.model, system, user, max_tokens)
    url, key = endpoint_for(ref)
    return await _complete_openai_compat(url, key, ref.model, system, user, max_tokens,
                                         timeout_s=ref.timeout_s, extra_body=ref.extra_body)


async def run_chain(chain: list[ModelRef], system: str, user: str, max_tokens: int,
                    accept: Callable[[str], dict | None] | None = None) -> ChainResult:
    """Try each entry in order; return the first usable answer.

    ``accept`` turns the text into the analysis (``None`` = unusable, try the
    next entry). Without it any non-empty text is an answer. Raises
    :class:`AnalystChainFailed` with every attempt when none answers.
    """
    attempts: list[Attempt] = []
    for i, ref in enumerate(chain):
        try:
            text, usage = await _complete(ref, system, user, max_tokens)
            analysis = accept(text) if accept is not None else None
            if accept is not None and analysis is None:
                raise _Unusable(f"unparseable output ({len(text)} chars)", usage)
        except Exception as exc:
            usage = getattr(exc, "usage", None) or {"input": 0, "output": 0}
            error = str(exc) if isinstance(exc, _Unusable) else f"{type(exc).__name__}: {exc}"
            attempts.append(Attempt(ref.provider, ref.model, False, error[:ERROR_CLIP],
                                    usage["input"], usage["output"]))
            log.warning("analyst model %s/%s failed (%s)%s", ref.provider, ref.model,
                        error[:ERROR_CLIP],
                        "; trying the next model" if i + 1 < len(chain) else "")
            continue
        attempts.append(Attempt(ref.provider, ref.model, True, "",
                                usage["input"], usage["output"]))
        return ChainResult(text=text, analysis=analysis, model_used=ref.model, index=i,
                           usage=usage, attempts=attempts)
    raise AnalystChainFailed(attempts)


async def analyst_complete(cfg: AnalystCfg, system: str, user: str) -> tuple[str, str, dict]:
    """Returns (text, model_used, usage) from the first entry of ``cfg.chain``
    that answers. The pre-chain interface, kept for its callers.

    ``usage`` is ``{"input": int, "output": int}`` — the real token counts the
    provider reported, so the caller can price the run (roadmap §5.6). The
    *model actually used* is returned alongside it precisely because a fallback
    changes the price; never price a run against the primary model id.
    """
    res = await run_chain(cfg.chain, system, user, cfg.max_tokens)
    return res.text, res.model_used, res.usage


def parse_analysis(text: str) -> dict | None:
    """Parse the analyst's strict-JSON reply, tolerating code fences and
    surrounding prose (same cleanup the n8n Code nodes applied)."""
    # a reasoning model (Qwen3 on llama-server) may lead with <think>…</think>,
    # whose braces would fool the first-{...} fallback below
    raw = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S).strip()
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
