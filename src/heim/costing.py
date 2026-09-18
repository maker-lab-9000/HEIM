"""Token cost arithmetic (roadmap §5.6).

Pure and deliberately dumb: prices are configuration
(``settings.model_prices``), never knowledge baked into the code — provider
pricing changes and a stale constant in a repo is a lie that compounds. A model
with no price entry is *unpriced*, which is a different thing from free:
``cost_of`` returns ``None`` so the caller can store 0 and the UI can render an
em dash instead of an authoritative-looking ``$0.00``.

Prices are quoted per MILLION tokens, the unit every provider's price page
uses, so a config value can be copied across without arithmetic.
"""
from __future__ import annotations

PER = 1_000_000.0


def cost_of(
    model: str | None,
    tokens_in: int | float | None,
    tokens_out: int | float | None,
    prices: dict | None,
) -> float | None:
    """Cost of one model call, or None when ``model`` has no price entry.

    ``prices`` maps a model id to ``{"input": <per-MTok>, "output": <per-MTok>}``;
    a missing side counts as 0 (some models only bill one direction), but a
    missing *model* is unpriced. Junk values (a string, None) are treated as an
    absent price rather than raising — a malformed price table must not take a
    pipeline down mid-investigation.
    """
    entry = (prices or {}).get(str(model or ""))
    if not isinstance(entry, dict):
        return None
    try:
        rate_in = float(entry.get("input") or 0)
        rate_out = float(entry.get("output") or 0)
    except (TypeError, ValueError):
        return None
    try:
        n_in = float(tokens_in or 0)
        n_out = float(tokens_out or 0)
    except (TypeError, ValueError):
        return None
    return (max(n_in, 0.0) * rate_in + max(n_out, 0.0) * rate_out) / PER
