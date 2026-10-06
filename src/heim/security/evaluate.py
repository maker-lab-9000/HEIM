"""Evaluation core: context, result helpers, the empty-list control rule, and
the dispatcher that runs every catalogue check in isolation. Pure."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Callable

from heim.security.catalogue import Catalogue
from heim.security.parsers import vmids_from_resources
from heim.security.types import CheckResult, CheckSpec, EvidenceBundle, clean_subject

log = logging.getLogger(__name__)


@dataclass
class EvalContext:
    now: datetime
    instance_host_map: dict[str, str]
    hosts: tuple[str, ...]
    pve_node: str = "homelab"
    ssh_host: str = "ubuntu-server"
    ha_host: str = "home-assistant"
    vm_names: dict[str, str] = field(default_factory=dict)
    expected_offline_vms: tuple[str, ...] = ()

    def host_for_instance(self, instance: str) -> str:
        """``instance`` label → configured host via the settings prefix map."""
        inst = str(instance or "")
        for prefix, host in self.instance_host_map.items():
            if prefix and inst.startswith(str(prefix)):
                return host
        return inst.split(":")[0] or "unknown"

    def vm_name(self, vmid: object) -> str:
        return self.vm_names.get(str(vmid), f"vm{vmid}")


Evaluator = Callable[[CheckSpec, EvidenceBundle, EvalContext], list[CheckResult]]
Compound = Callable[[CheckSpec, list[CheckResult], EvalContext], list[CheckResult]]


def ok(spec: CheckSpec, host: str, subject: str) -> CheckResult:
    return CheckResult(spec.id, host, clean_subject(subject), "ok", spec.severity, "")


def fail(spec: CheckSpec, host: str, subject: str, summary: str, *,
         detail: str = "", severity: str | None = None) -> CheckResult:
    return CheckResult(spec.id, host, clean_subject(subject), "fail", severity or spec.severity,
                       summary, detail, spec.recommendation)


def note(spec: CheckSpec, host: str, subject: str, summary: str, detail: str = "") -> CheckResult:
    return CheckResult(spec.id, host, clean_subject(subject), "note", "info", summary, detail)


def unavailable(spec: CheckSpec, host: str, reason: str, subject: str = "-") -> CheckResult:
    return CheckResult(spec.id, host, clean_subject(subject), "unavailable", spec.severity,
                       f"not verified: {reason}", reason)


def default_host(spec: CheckSpec, ctx: EvalContext) -> str:
    kind = spec.id.split(".", 1)[0]
    return {"pve": ctx.pve_node, "ha": ctx.ha_host, "ssh": ctx.ssh_host, "net": ctx.ssh_host}.get(kind, "prometheus")


def gate_sources(spec: CheckSpec, cat: Catalogue, ev: EvidenceBundle) -> str:
    """'' when every non-expanding source is usable; else the reason.

    The privsep trap: a list endpoint answers 200 + [] both for "nothing
    there" and "you may not see it". An empty result therefore counts only
    when the source's declared control returned non-empty in the same run.

    A check whose sources are ALL expand sources (per-vmid/per-container)
    has no plain source to gate on; per-item availability is ordinarily the
    evaluator's job, but if literally zero items were collected/usable for
    any of them, there is nothing for the evaluator to look at — that must
    not silently become a passing `ok`, so it is gated here too.
    """
    has_plain = False
    any_expand = False
    any_expand_usable = False
    for key in spec.sources:
        src = cat.sources[key]
        if src.expand:
            any_expand = True
            if any(e.usable for e in ev.expanded(key).values()):
                any_expand_usable = True
            continue                      # per-item availability is the evaluator's job
        has_plain = True
        e = ev.get(key)
        if not e.usable:
            return f"{key}: {e.status} — {e.detail or 'no data'}"
        if e.status == "empty" and src.control:
            c = ev.get(src.control)
            if c.status != "ok":
                return (f"{key} returned an empty list and its control {src.control} is {c.status} — "
                        f"cannot tell 'nothing there' from 'not permitted'")
    if any_expand and not has_plain and not any_expand_usable:
        return "no items collected for an expand-only check — cannot verify any item"
    return ""


def _registry() -> tuple[dict[str, Evaluator], dict[str, Compound]]:
    plain: dict[str, Evaluator] = {}
    compound: dict[str, Compound] = {}

    from heim.security import evaluate_pve
    plain.update(evaluate_pve.EVALUATORS)

    # TODO(task 6): drop this try/except once evaluate_ha, evaluate_prom,
    # evaluate_ssh and evaluate_compound exist — Task 6's test asserts every
    # catalogue check has a registered evaluator.
    try:
        from heim.security import evaluate_ha
        plain.update(evaluate_ha.EVALUATORS)
    except ImportError:
        pass
    try:
        from heim.security import evaluate_prom
        plain.update(evaluate_prom.EVALUATORS)
    except ImportError:
        pass
    try:
        from heim.security import evaluate_ssh
        plain.update(evaluate_ssh.EVALUATORS)
    except ImportError:
        pass
    try:
        from heim.security import evaluate_compound
        compound.update(evaluate_compound.COMPOUND)
    except ImportError:
        pass

    return plain, compound


_STATUS_RANK = {"ok": 0, "note": 1, "unavailable": 2, "fail": 3}


def _collapse_by_fingerprint(results: list[CheckResult]) -> list[CheckResult]:
    """Collapse rows sharing a fingerprint into one: worst status wins
    (fail > unavailable > note > ok), order-independent; distinct details
    are joined, the winning row's summary/severity are kept.

    Two evaluator rows can legitimately share a fingerprint (same
    host|check_id|subject) when an evaluator emits one row per raw item
    keyed by a field that collides (e.g. two ACL entries for the same
    ugid). The week-over-week diff keys on the fingerprint, so a collision
    must never let an `ok` mask a `fail` depending on list order.
    """
    groups: dict[str, list[CheckResult]] = {}
    order: list[str] = []
    for r in results:
        fp = r.fingerprint
        if fp not in groups:
            order.append(fp)
            groups[fp] = []
        groups[fp].append(r)
    out: list[CheckResult] = []
    for fp in order:
        rows = groups[fp]
        if len(rows) == 1:
            out.append(rows[0])
            continue
        winner = max(rows, key=lambda r: _STATUS_RANK[r.status])
        details = [r.detail for r in rows if r.detail]
        seen: list[str] = []
        for d in details:
            if d not in seen:
                seen.append(d)
        merged_detail = "\n".join(seen) if seen else winner.detail
        out.append(replace(winner, detail=merged_detail))
    return out


def evaluate(cat: Catalogue, ev: EvidenceBundle, ctx: EvalContext) -> list[CheckResult]:
    """Run every catalogue check; a broken evaluator yields one `unavailable`
    row rather than taking the audit down."""
    plain, compound = _registry()
    res = ev.get("pve.resources_vm")
    if res.status == "ok":
        ctx.vm_names = vmids_from_resources(res.body)
    if not ctx.expected_offline_vms:
        ctx.expected_offline_vms = tuple(cat.params.get("expected_offline_vms") or ())
    results: list[CheckResult] = []
    for spec in cat.checks:
        if spec.compound:
            continue
        fn = plain.get(spec.id)
        if fn is None:
            results.append(unavailable(spec, default_host(spec, ctx), "no evaluator registered"))
            continue
        reason = gate_sources(spec, cat, ev)
        if reason:
            results.append(unavailable(spec, default_host(spec, ctx), reason))
            continue
        try:
            rows = fn(spec, ev, ctx)
        except Exception as exc:  # one bad payload must not sink the other 46 checks
            log.exception("evaluator %s failed", spec.id)
            rows = [unavailable(spec, default_host(spec, ctx), f"evaluator error: {type(exc).__name__}: {exc}")]
        results.extend(rows or [ok(spec, default_host(spec, ctx), "-")])
    for spec in cat.checks:
        if not spec.compound:
            continue
        fn = compound.get(spec.id)
        if fn is None:
            results.append(unavailable(spec, default_host(spec, ctx), "no compound evaluator registered"))
            continue
        try:
            results.extend(fn(spec, results, ctx))
        except Exception as exc:
            log.exception("compound evaluator %s failed", spec.id)
            results.append(unavailable(spec, default_host(spec, ctx), f"evaluator error: {type(exc).__name__}: {exc}"))
    return _collapse_by_fingerprint(results)
