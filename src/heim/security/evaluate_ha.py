"""Home Assistant evaluators (ha.*). Pure; consume /api/config and /api/states JSON."""
from __future__ import annotations

import re

from heim.security.evaluate import EvalContext, fail, note, ok, unavailable
from heim.security.parsers import is_public_host
from heim.security.types import CheckSpec, EvidenceBundle

_LOGIN = re.compile(r"login|ip ban|banned", re.I)

#: Mirrors ha.pending_updates_sensitive's own `sensitive_patterns` param so
#: ha.pending_updates_other's count never depends on another check's params
#: (the two checks are independent catalogue rows, each evaluated alone).
_SENSITIVE_DEFAULT = ["core", "operating_system", "supervisor", "vaultwarden", "bitwarden", "letsencrypt",
                      "let_s_encrypt", "ssh", "adguard", "nginx", "proxy", "wireguard", "tailscale", "cloudflared"]


def _states(ev: EvidenceBundle) -> list[dict]:
    b = ev.get("ha.states").body
    if b is None:
        return []
    if not isinstance(b, list):
        raise TypeError(f"ha.states: expected a list body, got {type(b).__name__}")
    return [s for s in b if isinstance(s, dict)]


def _config(ev: EvidenceBundle) -> dict:
    b = ev.get("ha.config").body
    if b is None:
        return {}
    if not isinstance(b, dict):
        raise TypeError(f"ha.config: expected a dict body, got {type(b).__name__}")
    return b


def _guard_states(spec: CheckSpec, ev: EvidenceBundle, ctx: EvalContext) -> list | None:
    """/api/states on a live Home Assistant instance always returns every
    entity (typically hundreds) — a zero-length list means the audit could
    not verify anything from it, never that nothing is pending/failing.
    R5(c)/F2 pattern (pve.backup_coverage): a 200-with-[] must not become a
    silent `ok` when the endpoint is never legitimately empty."""
    if not _states(ev):
        return [unavailable(spec, ctx.ha_host, "ha.states returned no entities — cannot tell 'nothing to report' from 'not permitted'")]
    return None


def _guard_config(spec: CheckSpec, ev: EvidenceBundle, ctx: EvalContext) -> list | None:
    """/api/config always returns a populated object on a live instance; an
    empty object is the same "could not verify" trap as an empty states list."""
    if not _config(ev):
        return [unavailable(spec, ctx.ha_host, "ha.config returned an empty object — cannot verify configuration")]
    return None


def _updates_on(ev: EvidenceBundle) -> list[dict]:
    return [s for s in _states(ev) if str(s.get("entity_id", "")).startswith("update.") and str(s.get("state")) == "on"]


def _matches(spec: CheckSpec, s: dict) -> bool:
    pats = [str(p).lower() for p in spec.params.get("sensitive_patterns") or []]
    eid = str(s.get("entity_id", "")).lower()
    title = str((s.get("attributes") or {}).get("title") or "").lower()
    return any(p in eid or p in title for p in pats)


def _matches_any_sensitive(s: dict) -> bool:
    eid = str(s.get("entity_id", "")).lower()
    title = str((s.get("attributes") or {}).get("title") or "").lower()
    return any(p in eid or p in title for p in _SENSITIVE_DEFAULT)


def pending_updates_sensitive(spec, ev, ctx: EvalContext):
    guard = _guard_states(spec, ev, ctx)
    if guard is not None:
        return guard
    out = []
    for s in _updates_on(ev):
        if not _matches(spec, s):
            continue
        a = s.get("attributes") or {}
        out.append(fail(spec, ctx.ha_host, s["entity_id"],
                        f"{a.get('title') or s['entity_id']}: {a.get('installed_version')} → {a.get('latest_version')} available"))
    return out or [ok(spec, ctx.ha_host, "sensitive-updates")]


def pending_updates_other(spec, ev, ctx):
    guard = _guard_states(spec, ev, ctx)
    if guard is not None:
        return guard
    others = [s for s in _updates_on(ev) if not _matches_any_sensitive(s)]
    if not others:
        return [ok(spec, ctx.ha_host, "other")]
    names = ", ".join(str((s.get("attributes") or {}).get("title") or s["entity_id"]) for s in others[:10])
    return [note(spec, ctx.ha_host, "other", f"{len(others)} other update(s) pending", detail=names)]


def core_update_exposed(spec, ev, ctx):
    guard = _guard_states(spec, ev, ctx)
    if guard is None:
        guard = _guard_config(spec, ev, ctx)
    if guard is not None:
        return guard
    cfg = _config(ev)
    core_id = str(spec.params.get("core_entity") or "update.home_assistant_core_update")
    core = [s for s in _updates_on(ev) if s.get("entity_id") == core_id]
    if core and is_public_host(str(cfg.get("external_url") or "")):
        a = core[0].get("attributes") or {}
        return [fail(spec, ctx.ha_host, ctx.ha_host,
                     f"Home Assistant core {a.get('installed_version')} is reachable at a public URL while {a.get('latest_version')} is available")]
    return [ok(spec, ctx.ha_host, ctx.ha_host)]


def external_url(spec, ev, ctx):
    guard = _guard_config(spec, ev, ctx)
    if guard is not None:
        return guard
    url = str(_config(ev).get("external_url") or "")
    if is_public_host(url):
        return [note(spec, ctx.ha_host, "external_url", "Home Assistant is reachable from the internet via its external URL (DynDNS)")]
    return [ok(spec, ctx.ha_host, "external_url")]


def safe_mode(spec, ev, ctx):
    guard = _guard_config(spec, ev, ctx)
    if guard is not None:
        return guard
    cfg = _config(ev)
    modes = [m for m in ("safe_mode", "recovery_mode") if cfg.get(m)]
    if modes:
        return [fail(spec, ctx.ha_host, ctx.ha_host, f"Home Assistant is running in {' and '.join(modes)}")]
    return [ok(spec, ctx.ha_host, ctx.ha_host)]


def cert_expiry(spec, ev, ctx):
    guard = _guard_states(spec, ev, ctx)
    if guard is not None:
        return guard
    warn_d, crit_d = int(spec.params.get("warning_days", 30)), int(spec.params.get("critical_days", 14))
    out, unknown, total = [], 0, 0
    for s in _states(ev):
        eid = str(s.get("entity_id", ""))
        if "certificate_expiry" not in eid:
            continue
        total += 1
        try:
            days = float(s.get("state"))
        except (TypeError, ValueError):
            unknown += 1
            continue
        if days < crit_d:
            out.append(fail(spec, ctx.ha_host, eid, f"{eid}: certificate expires in {days:.0f} days", severity="critical"))
        elif days < warn_d:
            out.append(fail(spec, ctx.ha_host, eid, f"{eid}: certificate expires in {days:.0f} days"))
        else:
            out.append(ok(spec, ctx.ha_host, eid))
    if unknown:
        out.append(note(spec, ctx.ha_host, "unpopulated",
                        f"{unknown} of {total} certificate-expiry sensors report no value — certificate monitoring is configured but not working for them"))
    return out or [ok(spec, ctx.ha_host, "no-cert-sensors")]


def login_notifications(spec, ev, ctx):
    guard = _guard_states(spec, ev, ctx)
    if guard is not None:
        return guard
    out = []
    for s in _states(ev):
        eid = str(s.get("entity_id", ""))
        if not eid.startswith("persistent_notification."):
            continue
        a = s.get("attributes") or {}
        text = f"{a.get('title', '')} {a.get('message', '')}"
        if _LOGIN.search(text):
            out.append(fail(spec, ctx.ha_host, eid, f"{a.get('title') or eid}", detail=str(a.get("message") or "")[:300]))
    return out or [ok(spec, ctx.ha_host, "none")]


def external_dirs(spec, ev, ctx):
    guard = _guard_config(spec, ev, ctx)
    if guard is not None:
        return guard
    allowed = set(spec.params.get("allowed") or [])
    dirs = [str(d) for d in _config(ev).get("allowlist_external_dirs") or []]
    extra = sorted(d for d in dirs if d not in allowed)
    if extra:
        return [note(spec, ctx.ha_host, "external_dirs", f"allowlist_external_dirs includes {', '.join(extra)}")]
    return [ok(spec, ctx.ha_host, "external_dirs")]


EVALUATORS = {
    "ha.pending_updates_sensitive": pending_updates_sensitive, "ha.pending_updates_other": pending_updates_other,
    "ha.core_update_exposed": core_update_exposed, "ha.external_url": external_url, "ha.safe_mode": safe_mode,
    "ha.cert_expiry": cert_expiry, "ha.login_notifications": login_notifications, "ha.external_dirs": external_dirs,
}
