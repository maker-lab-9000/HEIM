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
class ThresholdDecision:
    """Output of the pure threshold-detection step (``pipelines/thresholds``).

    The first four fields mirror :class:`PollerDecision` so the pipeline can
    apply them with exactly the same machinery (store upserts, Telegram,
    Loki, ``dispatch_all``). The two streak fields are the hysteresis state to
    persist: ``streak_writes`` are upserts into ``threshold_streaks``,
    ``streak_clears`` the fingerprints that came back under threshold.
    """

    rows_to_upsert: list[dict] = field(default_factory=list)
    dispatches: list[dict] = field(default_factory=list)
    notifications: list[dict] = field(default_factory=list)
    loki_events: list[dict] = field(default_factory=list)
    streak_writes: list[dict] = field(default_factory=list)
    streak_clears: list[str] = field(default_factory=list)
    #: True only for rows that change an incident's *state* (new, escalated,
    #: resolved) — a lastSeen refresh on a still-breaching series is not a
    #: state change and must not emit a state event every five minutes.
    state_changed: bool = False


@dataclass
class PollerDecision:
    """Output of the pure alert-poller diff step (port of PAM 11 Diff & Decide)."""

    rows_to_upsert: list[dict] = field(default_factory=list)
    dispatches: list[dict] = field(default_factory=list)
    notifications: list[dict] = field(default_factory=list)
    loki_events: list[dict] = field(default_factory=list)
    state_changed: bool = False
    aborted: str | None = None
