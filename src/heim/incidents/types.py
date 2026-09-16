"""Shared datatypes for incident logic (reconcile, poller, state).

These are defined centrally so the pure-logic modules (reconcile.py,
poller_logic.py, state.py) and the pipelines can share them without
circular imports.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class HostRouting:
    """Which hosts are investigable and how.

    Derived from config/hosts/*.yaml — replaces the SSH_HOSTS /
    HYPERVISOR_HOST / HOMELAB_INVESTIGATE_CATS / HA_HOST constants that were
    hardcoded in the n8n Reconcile Code node.
    """

    ssh_hosts: frozenset[str] = frozenset()
    hypervisor_host: str | None = None
    hypervisor_categories: frozenset[str] = frozenset()
    ha_host: str | None = None


@dataclass
class ReconcileResult:
    """Output of the pure reconcile step (port of PAM 30)."""

    rows_to_write: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    to_investigate: list[dict] = field(default_factory=list)


@dataclass
class PollerDecision:
    """Output of the pure alert-poller diff step (port of PAM 11 Diff & Decide)."""

    rows_to_upsert: list[dict] = field(default_factory=list)
    dispatches: list[dict] = field(default_factory=list)
    notifications: list[dict] = field(default_factory=list)
    loki_events: list[dict] = field(default_factory=list)
    state_changed: bool = False
    aborted: str | None = None
