"""Proxmox evaluators (pve.*). Pure; consume parsed API JSON."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from heim.security.evaluate import EvalContext, fail, note, ok, unavailable
from heim.security.parsers import apt_pending
from heim.security.types import CheckSpec, EvidenceBundle

_MODIFY = re.compile(r"Modify|Allocate|Console|PowerMgmt|Permissions|Backup|Migrate|Snapshot|Clone|Config")
_SSHD_FAIL = re.compile(r"sshd\[\d+\]: (Failed password|Invalid user|error: maximum authentication attempts)")
_PVE_FAIL = re.compile(r"pvedaemon\[\d+\]: authentication failure")


def _list(ev: EvidenceBundle, key: str) -> list:
    b = ev.get(key).body
    return b if isinstance(b, list) else []


def _dict(ev: EvidenceBundle, key: str) -> dict:
    b = ev.get(key).body
    return b if isinstance(b, dict) else {}


def tfa_missing(spec: CheckSpec, ev: EvidenceBundle, ctx: EvalContext):
    with_tfa = {str(t.get("userid")) for t in _list(ev, "pve.access_tfa") if isinstance(t, dict) and t.get("entries")}
    interactive = set(spec.params.get("interactive_users") or ["root@pam"])
    out = []
    for u in _list(ev, "pve.access_users"):
        uid = str(u.get("userid") or "")
        if not uid or str(u.get("enable", 1)) == "0":
            continue
        if uid in with_tfa:
            out.append(ok(spec, ctx.pve_node, uid))
        elif uid in interactive:
            out.append(fail(spec, ctx.pve_node, uid, f"{uid} can log in to the Proxmox UI/API with a password alone (no second factor)"))
        else:
            out.append(note(spec, ctx.pve_node, uid, f"{uid} has no second factor (token/service account — informational)"))
    return out


def firewall_disabled(spec, ev, ctx):
    out = []
    cluster = _dict(ev, "pve.fw_cluster_options")
    if str(cluster.get("enable", 0)) != "1":
        out.append(fail(spec, ctx.pve_node, "cluster", "Proxmox firewall is not enabled at the datacenter level",
                        detail=f"cluster rules: {len(_list(ev, 'pve.fw_cluster_rules'))}, node rules: {len(_list(ev, 'pve.fw_node_rules'))}"))
    else:
        out.append(ok(spec, ctx.pve_node, "cluster"))
    vm_fw = ev.expanded("pve.fw_vm_options")
    for vmid, cfg_e in ev.expanded("pve.vm_config").items():
        if not cfg_e.usable or not isinstance(cfg_e.body, dict):
            continue
        flagged = sorted(k for k, v in cfg_e.body.items() if k.startswith("net") and "firewall=1" in str(v))
        fw = vm_fw.get(vmid)
        enabled = fw is not None and fw.usable and isinstance(fw.body, dict) and str(fw.body.get("enable", 0)) == "1"
        if flagged and not enabled:
            name = ctx.vm_name(vmid)
            out.append(note(spec, name, "nic-flag", f"{name}: {', '.join(flagged)} carry firewall=1 but the VM firewall is off — the flag has no effect"))
    return out


def pending_updates(spec, ev, ctx):
    rows = apt_pending(ev.get("pve.apt_versions").body)
    total = len(_list(ev, "pve.apt_versions"))
    if not rows:
        return [ok(spec, ctx.pve_node, ctx.pve_node)]
    names = sorted(r["Package"] for r in rows)
    return [fail(spec, ctx.pve_node, ctx.pve_node, f"{len(rows)} of {total} tracked packages have a newer version available",
                 detail=", ".join(names[:12]) + ("…" if len(names) > 12 else ""))]


def pending_updates_sensitive(spec, ev, ctx):
    rows = apt_pending(ev.get("pve.apt_versions").body)
    out = []
    for cls, prefixes in (spec.params.get("classes") or {}).items():
        hit = sorted({r["Package"]: f"{r['OldVersion']} → {r['Version']}" for r in rows
                      if any(r["Package"].startswith(p) for p in prefixes)}.items())
        if hit:
            out.append(fail(spec, ctx.pve_node, cls, f"{cls}: {len(hit)} security-relevant package(s) pending",
                            detail=", ".join(f"{p} {v}" for p, v in hit)))
        else:
            out.append(ok(spec, ctx.pve_node, cls))
    return out


def _enabled_repos(body: dict) -> list[dict]:
    return [r for f in body.get("files") or [] for r in (f.get("repositories") or []) if r.get("Enabled")]


def repo_security(spec, ev, ctx):
    body = _dict(ev, "pve.apt_repositories")
    has = any(any("security" in str(s) for s in r.get("Suites") or []) or
              any("security.debian.org" in str(u) for u in r.get("URIs") or []) for r in _enabled_repos(body))
    if has:
        return [ok(spec, ctx.pve_node, ctx.pve_node)]
    return [fail(spec, ctx.pve_node, ctx.pve_node, "no enabled Debian security repository on the hypervisor",
                 detail=f"{len(_enabled_repos(body))} enabled repositories, none with a *-security suite")]


def repo_risky(spec, ev, ctx):
    out = []
    for std in _dict(ev, "pve.apt_repositories").get("standard-repos") or []:
        h, st = str(std.get("handle")), std.get("status")
        if h == "test":
            out.append(fail(spec, ctx.pve_node, "pve-test", "pve-test repository is enabled on a production node") if st == 1 else ok(spec, ctx.pve_node, "pve-test"))
        elif h == "enterprise":
            out.append(note(spec, ctx.pve_node, "pve-enterprise", "enterprise repository enabled — needs a subscription or apt update fails") if st == 1 else ok(spec, ctx.pve_node, "pve-enterprise"))
    return out


def cert_expiry(spec, ev, ctx):
    warn_d, crit_d = int(spec.params.get("warning_days", 90)), int(spec.params.get("critical_days", 30))
    out = []
    now = ctx.now.astimezone(timezone.utc)
    for c in _list(ev, "pve.certificates"):
        fn = str(c.get("filename") or "?")
        na = c.get("notafter")
        if not isinstance(na, (int, float)):
            out.append(unavailable(spec, ctx.pve_node, f"{fn}: no notafter"))
            continue
        days = (datetime.fromtimestamp(na, tz=timezone.utc) - now).days
        if days < crit_d:
            out.append(fail(spec, ctx.pve_node, fn, f"{fn} expires in {days} days", severity="critical"))
        elif days < warn_d:
            out.append(fail(spec, ctx.pve_node, fn, f"{fn} expires in {days} days"))
        else:
            out.append(ok(spec, ctx.pve_node, fn))
        if fn == "pve-ssl.pem" and "Proxmox Virtual Environment" in str(c.get("issuer") or ""):
            out.append(note(spec, ctx.pve_node, f"{fn}:issuer", f"{fn} is signed by the internal PVE CA — browser warnings expected; valid {days} more days"))
    return out


def acl_privileged(spec, ev, ctx):
    roles = {str(r.get("roleid")): str(r.get("privs") or "") for r in _list(ev, "pve.access_roles")}
    out = []
    for a in _list(ev, "pve.access_acl"):
        ugid, role = str(a.get("ugid") or ""), str(a.get("roleid") or "")
        if ugid.startswith("root@pam"):
            continue
        strong = sorted(p for p in roles.get(role, "").split(",") if _MODIFY.search(p))
        if strong:
            out.append(fail(spec, ctx.pve_node, ugid, f"{ugid} holds {role} at {a.get('path')} with non-audit privileges", detail=", ".join(strong)))
        else:
            out.append(ok(spec, ctx.pve_node, ugid))
    return out


def backup_coverage(spec, ev, ctx):
    jobs = [j for j in _list(ev, "pve.backup_jobs") if str(j.get("enabled", 1)) != "0"]
    covered: set[str] = set()
    cover_all = False
    excluded: set[str] = set()
    for j in jobs:
        if str(j.get("all", 0)) == "1":
            cover_all = True
            excluded |= {v.strip() for v in str(j.get("exclude") or "").split(",") if v.strip()}
        covered |= {v.strip() for v in str(j.get("vmid") or "").split(",") if v.strip()}
    out = []
    for vm in _list(ev, "pve.resources_vm"):
        vmid, name, status = str(vm.get("vmid")), str(vm.get("name") or vm.get("vmid")), str(vm.get("status") or "")
        if vmid in covered or (cover_all and vmid not in excluded):
            out.append(ok(spec, name, "backup"))
        elif status == "running":
            out.append(fail(spec, name, "backup", f"{name} (vmid {vmid}) is running but no enabled backup job includes it"))
        else:
            out.append(note(spec, name, "backup", f"{name} (vmid {vmid}) is {status or 'not running'} and has no backup job"))
    return out


def backup_last_status(spec, ev, ctx):
    horizon = ctx.now.timestamp() - int(spec.params.get("max_age_days", 8)) * 86400
    recent = [t for t in _list(ev, "pve.tasks_vzdump") if float(t.get("starttime") or 0) >= horizon]
    if not recent:
        if _list(ev, "pve.backup_jobs"):
            return [fail(spec, ctx.pve_node, ctx.pve_node, f"no vzdump task ran in the last {spec.params.get('max_age_days', 8)} days although backup jobs exist")]
        return [note(spec, ctx.pve_node, ctx.pve_node, "no backup jobs configured and no vzdump tasks")]
    out = []
    for t in recent:
        st, ident = str(t.get("status") or ""), str(t.get("id") or "job")
        if st and st != "OK":
            out.append(fail(spec, ctx.vm_name(ident) if ident.isdigit() else ctx.pve_node, ident, f"backup task for {ident} ended with: {st[:80]}"))
    return out or [ok(spec, ctx.pve_node, "vzdump")]


def failed_tasks(spec, ev, ctx):
    horizon = ctx.now.timestamp() - 7 * 86400
    bad = [t for t in _list(ev, "pve.tasks_errors") if float(t.get("starttime") or 0) >= horizon]
    if not bad:
        return [ok(spec, ctx.pve_node, ctx.pve_node)]
    return [note(spec, ctx.pve_node, ctx.pve_node, f"{len(bad)} Proxmox task(s) failed in the last 7 days",
                 detail="\n".join(f"{t.get('type')} {t.get('id') or ''}: {str(t.get('status'))[:80]}" for t in bad[:8]))]


def services_dead(spec, ev, ctx):
    states = {str(s.get("name")): str(s.get("state") or "") for s in _list(ev, "pve.services")}
    out = []
    for name in spec.params.get("required_active") or []:
        st = states.get(name)
        if st is None:
            out.append(note(spec, ctx.pve_node, name, f"service {name} is not present on the hypervisor"))
        elif st == "running":
            out.append(ok(spec, ctx.pve_node, name))
        else:
            out.append(fail(spec, ctx.pve_node, name, f"security-relevant service {name} is {st}"))
    ts = spec.params.get("time_sync_any") or []
    if ts:
        if any(states.get(n) == "running" for n in ts):
            out.append(ok(spec, ctx.pve_node, "time-sync"))
        else:
            out.append(fail(spec, ctx.pve_node, "time-sync", f"no time-sync daemon running ({', '.join(ts)})"))
    return out


def auth_failures(spec, ev, ctx):
    body = ev.get("pve.journal").body
    lines = body.splitlines() if isinstance(body, str) else [str(l) for l in (body or [])]
    if not lines:
        return [unavailable(spec, ctx.pve_node, "journal returned no lines")]
    crit = int(spec.params.get("critical_count", 50))
    out = []
    for subject, rx in (("sshd", _SSHD_FAIL), ("pveproxy", _PVE_FAIL)):
        hits = [l for l in lines if rx.search(l)]
        if not hits:
            out.append(ok(spec, ctx.pve_node, subject))
            continue
        out.append(fail(spec, ctx.pve_node, subject,
                        f"{len(hits)} failed {subject} authentication attempts in the last {len(lines)} journal lines",
                        detail="\n".join(h[-160:] for h in hits[-5:]),
                        severity="critical" if len(hits) >= crit else None))
    return out


def vm_hardening(spec, ev, ctx):
    out = []
    for vmid, e in ev.expanded("pve.vm_config").items():
        if not e.usable or not isinstance(e.body, dict):
            continue
        name, cfg = ctx.vm_name(vmid), e.body
        if str(cfg.get("protection", 0)) != "1":
            out.append(note(spec, name, "protection", f"{name}: protection flag not set (accidental destroy/edit is possible)"))
        pt = sorted(k for k in cfg if k.startswith(("hostpci", "usb")))
        if pt:
            out.append(note(spec, name, "passthrough", f"{name}: device passthrough present ({', '.join(pt)})"))
        if "agent" not in cfg:
            out.append(note(spec, name, "agent", f"{name}: QEMU guest agent not configured"))
    return out


def stopped_vm_onboot(spec, ev, ctx):
    out = []
    status = ev.expanded("pve.vm_status")
    for vmid, e in ev.expanded("pve.vm_config").items():
        st = status.get(vmid)
        if not (e.usable and isinstance(e.body, dict) and st is not None and st.usable and isinstance(st.body, dict)):
            continue
        name = ctx.vm_name(vmid)
        if str(st.body.get("status")) == "stopped" and str(e.body.get("onboot", 0)) == "1":
            out.append(note(spec, name, "onboot", f"{name} is stopped but onboot=1 — it would start on the next host boot"))
        elif str(st.body.get("status")) == "running" and name in ctx.expected_offline_vms:
            out.append(note(spec, name, "running", f"{name} is running although it is expected to be powered off"))
    return out


def secureboot(spec, ev, ctx):
    info = _dict(ev, "pve.node_status").get("boot-info") or {}
    if str(info.get("secureboot", 0)) == "1":
        return [ok(spec, ctx.pve_node, "secureboot")]
    return [note(spec, ctx.pve_node, "secureboot", "Secure Boot is not enabled on the hypervisor")]


EVALUATORS = {
    "pve.tfa_missing": tfa_missing, "pve.firewall_disabled": firewall_disabled,
    "pve.pending_updates": pending_updates, "pve.pending_updates_sensitive": pending_updates_sensitive,
    "pve.repo_security": repo_security, "pve.repo_risky": repo_risky, "pve.cert_expiry": cert_expiry,
    "pve.acl_privileged": acl_privileged, "pve.backup_coverage": backup_coverage,
    "pve.backup_last_status": backup_last_status, "pve.failed_tasks": failed_tasks,
    "pve.services_dead": services_dead, "pve.auth_failures": auth_failures,
    "pve.vm_hardening": vm_hardening, "pve.stopped_vm_onboot": stopped_vm_onboot, "pve.secureboot": secureboot,
}
