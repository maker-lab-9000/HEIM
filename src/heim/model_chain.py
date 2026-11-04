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
#: … and of the investigator's single model (a one-entry chain)
INVESTIGATOR_AGENT = "investigator"


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


def find_model(choice: str, allowed: list[ModelRef]) -> ModelRef:
    """The offered model a per-run choice names: a full key, or a bare model id
    that exactly one entry has. Anything else raises ``ValueError``."""
    choice = (choice or "").strip()
    for ref in allowed:
        if ref.key == choice:
            return ref
    same_id = [ref for ref in allowed if ref.model == choice]
    if len(same_id) == 1:
        return same_id[0]
    if same_id:
        raise ValueError(f"{choice} is offered under several providers; pick one of: "
                         + ", ".join(r.key for r in same_id))
    raise ValueError(f"{choice} is not offered (settings.investigator_models)")


def resolve_model(yaml: ModelRef, override: dict | None,
                  allowed: list[ModelRef]) -> EffectiveChain:
    """The investigator's model: a one-entry override, else the YAML model.
    An override of any other length counts as stale."""
    if override and len(override.get("chain") or []) != 1:
        return EffectiveChain([yaml], "yaml", True, str(override.get("updated_at") or ""))
    return resolve_chain([yaml], override, allowed)
