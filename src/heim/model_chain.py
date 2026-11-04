"""Which model chain a run uses: the dashboard override or the YAML default.

Pure (spec 2026-11-04). The override lives in the store's ``model_overrides``
table and applies only while every entry is still in the settings allow-list
(``settings.analyst_models``); a stale override is ignored, not obeyed, so
taking a model off the list takes it out of production on the next run.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from heim.config import ModelRef

#: the ``model_overrides.agent`` key of the daily analyst's chain
OVERRIDE_AGENT = "daily_analyst"


@dataclass
class EffectiveChain:
    chain: list[ModelRef]
    source: Literal["yaml", "override"]
    stale: bool = False             # an override exists but was ignored
    updated_at: str = ""            # the override's time (applied or ignored)


def resolve_chain(yaml_chain: list[ModelRef], override: dict | None,
                  allowed: list[ModelRef]) -> EffectiveChain:
    if not override:
        return EffectiveChain(list(yaml_chain), "yaml")
    updated_at = str(override.get("updated_at") or "")
    allowed_keys = {a.key for a in allowed}
    try:
        chain = [ModelRef(**e) for e in override.get("chain") or []]
    except Exception:
        chain = []
    if chain and all(r.key in allowed_keys for r in chain):
        return EffectiveChain(chain, "override", False, updated_at)
    return EffectiveChain(list(yaml_chain), "yaml", True, updated_at)
