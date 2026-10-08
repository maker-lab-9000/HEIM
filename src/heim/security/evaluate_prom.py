"""Prometheus evaluators (prom.*). Pure; consume /api/v1/query result vectors."""
from __future__ import annotations

from datetime import date

from heim.security.evaluate import EvalContext, fail, note, ok, unavailable
from heim.security.types import CheckSpec, EvidenceBundle


def _vec(ev: EvidenceBundle, key: str) -> list[dict]:
    b = ev.get(key).body
    if b is None:
        return []
    if not isinstance(b, list):
        raise TypeError(f"{key}: expected a list body, got {type(b).__name__}")
    return [s for s in b if isinstance(s, dict) and "metric" in s]


def _val(s: dict) -> float:
    try:
        return float((s.get("value") or [0, "nan"])[1])
    except (TypeError, ValueError):
        return float("nan")


def _host(ctx: EvalContext, s: dict) -> str:
    return ctx.host_for_instance(str(s["metric"].get("instance", "")))


def reboot_required(spec, ev, ctx):
    out = []
    for s in _vec(ev, "prom.reboot_required"):
        h = _host(ctx, s)
        out.append(fail(spec, h, h, f"{h} needs a reboot for an installed kernel/library update to take effect") if _val(s) >= 1 else ok(spec, h, h))
    return out or [unavailable(spec, "prometheus", "node_reboot_required has no series")]


def apt_pending(spec, ev, ctx):
    out, seen = [], set()
    for s in _vec(ev, "prom.apt_pending"):
        h = _host(ctx, s)
        seen.add(h)
        n = _val(s)
        out.append(fail(spec, h, h, f"{h}: {int(n)} pending apt upgrade rows (arch/origin cross-tab) reported by node_exporter") if n > 0 else ok(spec, h, h))
    for s in _vec(ev, "prom.apt_present"):
        h = _host(ctx, s)
        if h not in seen:
            out.append(note(spec, h, "collector-absent",
                            f"{h}: node_exporter has no apt_upgrades_pending series — the apt textfile collector is not installed, so pending updates are unobservable here"))
    return out or [unavailable(spec, "prometheus", "no node_exporter instances found")]


def failed_units(spec, ev, ctx):
    expected = set(spec.params.get("expected_failed") or [])
    out = []
    for s in _vec(ev, "prom.failed_units"):
        h, unit = _host(ctx, s), str(s["metric"].get("name") or "?")
        out.append(ok(spec, h, unit) if unit in expected else fail(spec, h, unit, f"{h}: systemd unit {unit} is in failed state"))
    # node_systemd_unit_state{state="failed"}==1 is a value-filtered query:
    # an empty vector is its designed healthy answer (no unit failed), not
    # missing evidence (R5(c), amended after Task 5's review). A Prometheus
    # that didn't answer is already `unavailable` via the dispatcher's
    # gate_sources (non-ok evidence status), and an unscraped node_exporter
    # is reported separately by prom.targets_down.
    return out or [ok(spec, "all", "none-failed")]


def time_sync(spec, ev, ctx):
    out = []
    for s in _vec(ev, "prom.timex"):
        h = _host(ctx, s)
        out.append(fail(spec, h, h, f"{h}: clock is not synchronised (node_timex_sync_status=0)") if _val(s) == 0 else ok(spec, h, h))
    return out or [unavailable(spec, "prometheus", "node_timex_sync_status has no series")]


def targets_down(spec, ev, ctx):
    out = []
    for s in _vec(ev, "prom.up"):
        job = str(s["metric"].get("job") or s["metric"].get("instance") or "?")
        out.append(fail(spec, _host(ctx, s), job, f"Prometheus target {job} ({s['metric'].get('instance', '')}) is down — a blind spot for this audit") if _val(s) == 0 else ok(spec, _host(ctx, s), job))
    return out or [unavailable(spec, "prometheus", "up has no series")]


def os_eol(spec, ev, ctx):
    table = {str(k).lower(): str(v) for k, v in (spec.params.get("os_eol") or {}).items()}
    warn_days = int(spec.params.get("warning_days", 180))
    review_by = str(spec.params.get("review_by") or "")
    out = []
    today = ctx.now.date()
    if review_by and today.isoformat() > review_by:
        out.append(note(spec, "all", "eol-table", f"the os_eol table in checks.yaml is past its review_by date ({review_by}) — verify the dates"))
    for s in _vec(ev, "prom.os_info"):
        m, h = s["metric"], _host(ctx, s)
        key = f"{m.get('id', '')} {m.get('version_id', '')}".strip().lower()
        pretty = str(m.get("pretty_name") or key)
        eol = table.get(key)
        if not eol:
            out.append(note(spec, h, key or "unknown", f"{h}: {pretty} has no EOL entry in checks.yaml"))
            continue
        days = (date.fromisoformat(eol) - today).days
        if days < 0:
            out.append(fail(spec, h, key, f"{h}: {pretty} reached end of life on {eol}", severity="critical"))
        elif days < warn_days:
            out.append(fail(spec, h, key, f"{h}: {pretty} reaches end of life in {days} days ({eol})"))
        else:
            out.append(ok(spec, h, key))
    return out or [unavailable(spec, "prometheus", "node_os_info has no series")]


EVALUATORS = {
    "prom.reboot_required": reboot_required, "prom.apt_pending": apt_pending, "prom.failed_units": failed_units,
    "prom.time_sync": time_sync, "prom.targets_down": targets_down, "prom.os_eol": os_eol,
}
