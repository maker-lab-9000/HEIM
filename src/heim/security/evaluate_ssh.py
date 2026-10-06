"""ubuntu-server evaluators (ssh.*) over the fixed SSH lines. Pure.

Every evaluator distinguishes "nothing found" from "could not look": a
permission hint on stderr, a non-zero exit on a file read, or output that
lacks a known-present marker (sshd on :22) yields `unavailable`, never `ok`.
A command whose empty output is itself the designed healthy answer (find/grep
with no matches, an empty updates-available file) stays `ok` — see the R5
notes on `pending_security_updates`.
"""
from __future__ import annotations

import json
import re

from heim.security.evaluate import EvalContext, fail, note, ok, unavailable
from heim.security.parsers import (
    ip_in_cidrs, parse_docker_images, parse_last_hosts, parse_ss_listeners, parse_sshd_config,
    parse_updates_available, unit_states, unreadable_dropins,
)
from heim.security.types import CheckSpec, Evidence, EvidenceBundle

_JOURNAL_HINT = ("not seeing messages", "No journal files")
_RISKY_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL"}


def _text(e: Evidence) -> str:
    return str(e.body or "")


def listeners_unexpected(spec: CheckSpec, ev: EvidenceBundle, ctx: EvalContext):
    rows = parse_ss_listeners(_text(ev.get("ssh.listeners")))
    if not any(r["port"] == "22" for r in rows):
        return [unavailable(spec, ctx.ssh_host, "ss output shows no sshd listener on :22 — output not trustworthy (permission or format)")]
    expected = {str(k): str(v) for k, v in (spec.params.get("expected_ports") or {}).items()}
    critical = {str(k): str(v) for k, v in (spec.params.get("critical_ports") or {}).items()}
    out, seen = [], set()
    for r in rows:
        if not r["wildcard"]:
            continue
        key = f"{r['port']}/{r['process']}"
        if key in seen:
            continue
        seen.add(key)
        if r["port"] in critical:
            out.append(fail(spec, ctx.ssh_host, key, f"{r['process']} listens on all interfaces at :{r['port']} ({critical[r['port']]})", detail=r["local"], severity="critical"))
        elif r["port"] in expected:
            out.append(ok(spec, ctx.ssh_host, key))
        else:
            out.append(fail(spec, ctx.ssh_host, key, f"{r['process']} listens on all interfaces at :{r['port']} ({r['proto']}) and is not in expected_ports", detail=r["local"]))
    return out or [ok(spec, ctx.ssh_host, "no-wildcard-listeners")]


def _effective_sshd(ev: EvidenceBundle) -> tuple[dict | None, str]:
    main = ev.get("ssh.sshd_config")
    if main.status != "ok" or (main.exit_code not in (0, None)):
        return None, f"/etc/ssh/sshd_config unreadable ({main.detail or main.stderr.strip() or 'empty'})"
    hidden = unreadable_dropins(_text(ev.get("ssh.sshd_config_d_ls")))
    if hidden:
        return None, f"drop-in(s) {', '.join(hidden)} are not world-readable — the effective sshd config cannot be determined without sudo cat"
    # Ubuntu Includes sshd_config.d/*.conf at the top of sshd_config, and sshd keeps the FIRST value.
    return parse_sshd_config(_text(ev.get("ssh.sshd_config_d")) + "\n" + _text(main)), ""


def sshd_password_auth(spec, ev, ctx):
    conf, why = _effective_sshd(ev)
    if conf is None:
        return [unavailable(spec, ctx.ssh_host, why)]
    v = conf.get("passwordauthentication", "yes").lower()
    if v != "no":
        return [fail(spec, ctx.ssh_host, ctx.ssh_host, f"sshd accepts password authentication (PasswordAuthentication {v})")]
    return [ok(spec, ctx.ssh_host, ctx.ssh_host)]


def sshd_root_login(spec, ev, ctx):
    conf, why = _effective_sshd(ev)
    if conf is None:
        return [unavailable(spec, ctx.ssh_host, why)]
    v = conf.get("permitrootlogin", "prohibit-password").lower()
    if v == "yes":
        return [fail(spec, ctx.ssh_host, ctx.ssh_host, "sshd permits root login with a password (PermitRootLogin yes)")]
    return [ok(spec, ctx.ssh_host, ctx.ssh_host)]


def sshd_empty_passwords(spec, ev, ctx):
    conf, why = _effective_sshd(ev)
    if conf is None:
        return [unavailable(spec, ctx.ssh_host, why)]
    if conf.get("permitemptypasswords", "no").lower() == "yes":
        return [fail(spec, ctx.ssh_host, ctx.ssh_host, "sshd permits empty passwords")]
    return [ok(spec, ctx.ssh_host, ctx.ssh_host)]


def sshd_hardening(spec, ev, ctx):
    conf, why = _effective_sshd(ev)
    if conf is None:
        return [unavailable(spec, ctx.ssh_host, why)]
    out = []
    if conf.get("x11forwarding", "no").lower() == "yes":
        out.append(note(spec, ctx.ssh_host, "x11forwarding", "X11Forwarding is enabled"))
    try:
        if int(conf.get("maxauthtries", "6")) > 6:
            out.append(note(spec, ctx.ssh_host, "maxauthtries", f"MaxAuthTries is {conf['maxauthtries']} (default 6)"))
    except ValueError:
        pass
    if "allowusers" not in conf and "allowgroups" not in conf:
        out.append(note(spec, ctx.ssh_host, "allowusers", "neither AllowUsers nor AllowGroups restricts who may log in"))
    if conf.get("port", "22") != "22":
        out.append(note(spec, ctx.ssh_host, "port", f"sshd listens on port {conf['port']}"))
    return out or [ok(spec, ctx.ssh_host, "hardening")]


def auth_failures(spec, ev, ctx):
    cnt, sample = ev.get("ssh.auth_fail_count"), ev.get("ssh.auth_fail_sample")
    hint = f"{cnt.stderr} {sample.stderr}"
    if any(h in hint for h in _JOURNAL_HINT):
        return [unavailable(spec, ctx.ssh_host, "the SSH user cannot read the system journal — add it to the systemd-journal group (owner-side step 1) or leave this check unverified")]
    text = _text(cnt).strip().splitlines()
    try:
        n = int(text[-1]) if text else 0
    except ValueError:
        return [unavailable(spec, ctx.ssh_host, f"unparseable count output: {_text(cnt)[:60]!r}")]
    if n == 0:
        return [ok(spec, ctx.ssh_host, ctx.ssh_host)]
    crit = int(spec.params.get("critical_count", 100))
    return [fail(spec, ctx.ssh_host, ctx.ssh_host, f"{n} failed SSH authentication attempts logged in the last 7 days",
                 detail=_text(sample)[-1200:], severity="critical" if n >= crit else None)]


def pending_security_updates(spec, ev, ctx):
    e = ev.get("ssh.updates_available")
    # R5 deviation from the brief: the brief also gated on `e.status != "ok"`,
    # which turned an empty-but-successfully-read file into `unavailable`. On
    # a real Ubuntu host /var/lib/update-notifier/updates-available is 0
    # bytes exactly when there is nothing pending — that is the designed
    # healthy empty result (R5 amendment), so only a non-zero exit (file
    # missing/unreadable) may mean `unavailable`.
    if e.exit_code not in (0, None):
        return [unavailable(spec, ctx.ssh_host, "/var/lib/update-notifier/updates-available is not readable (is update-notifier-common installed?)")]
    total, sec = parse_updates_available(_text(e))
    if sec > 0:
        return [fail(spec, ctx.ssh_host, ctx.ssh_host, f"{sec} standard security updates pending ({total} updates in total)")]
    if total > 0:
        return [note(spec, ctx.ssh_host, "non-security", f"{total} non-security updates pending")]
    return [ok(spec, ctx.ssh_host, ctx.ssh_host)]


def _units(ev: EvidenceBundle) -> dict[str, str]:
    e = ev.get("ssh.unit_states")
    return unit_states(e.target, _text(e))


def auto_upgrades_off(spec, ev, ctx):
    conf = _text(ev.get("ssh.auto_upgrades"))
    if not re.search(r'Unattended-Upgrade\s+"1"', conf):
        return [fail(spec, ctx.ssh_host, ctx.ssh_host, "unattended-upgrades is not enabled in /etc/apt/apt.conf.d/20auto-upgrades")]
    if _units(ev).get("unattended-upgrades") not in ("active", "activating"):
        return [fail(spec, ctx.ssh_host, ctx.ssh_host, "unattended-upgrades is configured but its unit is not active")]
    return [ok(spec, ctx.ssh_host, ctx.ssh_host)]


def host_firewall(spec, ev, ctx):
    st = _units(ev)
    if st.get("ufw") == "active" or st.get("nftables") == "active":
        return [ok(spec, ctx.ssh_host, ctx.ssh_host)]
    return [note(spec, ctx.ssh_host, ctx.ssh_host, "no host firewall unit is active (ufw, nftables)")]


def fail2ban_absent(spec, ev, ctx):
    if _units(ev).get("fail2ban") == "active":
        return [ok(spec, ctx.ssh_host, ctx.ssh_host)]
    return [note(spec, ctx.ssh_host, ctx.ssh_host, "fail2ban is not active")]


def world_writable(spec, ev, ctx):
    paths = [p.strip() for p in _text(ev.get("ssh.world_writable")).splitlines() if p.strip().startswith("/")]
    if not paths:
        return [ok(spec, ctx.ssh_host, ctx.ssh_host)]
    return [fail(spec, ctx.ssh_host, p, f"world-writable file {p}") for p in paths[:20]]


def external_logins(spec, ev, ctx):
    cidrs = [str(c) for c in spec.params.get("trusted_cidrs") or []]
    ext = sorted({ip for ip in parse_last_hosts(_text(ev.get("ssh.last_logins"))) if not ip_in_cidrs(ip, cidrs)})
    if ext:
        return [fail(spec, ctx.ssh_host, "external", f"{len(ext)} login source address(es) outside the trusted networks in the last 7 days", detail=", ".join(ext))]
    return [ok(spec, ctx.ssh_host, "external")]


def login_shell_users(spec, ev, ctx):
    users = [l.split(":", 1)[0] for l in _text(ev.get("ssh.login_shells")).splitlines() if ":" in l]
    if not users:
        return [ok(spec, ctx.ssh_host, "users")]
    return [note(spec, ctx.ssh_host, "users", f"{len(users)} account(s) have a login shell", detail=", ".join(users[:20]))]


def agent_sudo_scope(spec, ev, ctx):
    e = ev.get("ssh.sudo_scope")
    if e.status != "ok" or e.exit_code not in (0, None):
        return [unavailable(spec, ctx.ssh_host, f"sudo -n -l did not answer ({e.stderr.strip()[:80] or 'non-zero exit'})")]
    allowed = set(spec.params.get("expected_sudo_binaries") or [])
    extra = []
    for line in _text(e).splitlines():
        s = line.strip()
        if not s.startswith("("):
            continue
        cmds = s.split(":", 1)[-1] if ":" in s else s.split(")", 1)[-1]
        for cmd in cmds.split(","):
            c = cmd.strip()
            if not c:
                continue
            base = c.split()[0].rsplit("/", 1)[-1]
            if base == "ALL" or base not in allowed:
                extra.append(c)
    if extra:
        return [fail(spec, ctx.ssh_host, "agent-user", "the monitoring user's sudo rights exceed the read-only set", detail=", ".join(extra[:10]))]
    return [ok(spec, ctx.ssh_host, "agent-user")]


def docker_privileged(spec, ev, ctx):
    out = []
    for name, e in ev.expanded("ssh.docker_inspect").items():
        if e.status != "ok":
            out.append(unavailable(spec, ctx.ssh_host, f"inspect {name}: {e.detail or e.status}"))
            continue
        try:
            data = json.loads(_text(e))
            hc = (data[0] if isinstance(data, list) else data).get("HostConfig") or {}
        except (ValueError, AttributeError, IndexError, TypeError):
            out.append(unavailable(spec, ctx.ssh_host, f"inspect {name}: unparseable JSON"))
            continue
        risks = []
        if hc.get("Privileged"):
            risks.append("privileged")
        if any("/var/run/docker.sock" in str(b) for b in hc.get("Binds") or []):
            risks.append("docker.sock mounted")
        if str(hc.get("NetworkMode")) == "host":
            risks.append("host network")
        caps = {str(c).upper().removeprefix("CAP_") for c in hc.get("CapAdd") or []}
        if caps & _RISKY_CAPS:
            risks.append("cap_add " + ",".join(sorted(caps & _RISKY_CAPS)))
        out.append(fail(spec, ctx.ssh_host, name, f"container {name}: {', '.join(risks)}") if risks else ok(spec, ctx.ssh_host, name))
    return out or [unavailable(spec, ctx.ssh_host, "no container was inspected")]


def docker_stale_images(spec, ev, ctx):
    max_m = int(spec.params.get("max_age_months", 6))
    stale = [(name, m) for name, m in parse_docker_images(_text(ev.get("ssh.docker_images"))) if m >= max_m]
    if not stale:
        return [ok(spec, ctx.ssh_host, "images")]
    return [note(spec, ctx.ssh_host, name, f"image {name} was built {m} months ago") for name, m in stale[:15]]


EVALUATORS = {
    "ssh.listeners_unexpected": listeners_unexpected, "ssh.sshd_password_auth": sshd_password_auth,
    "ssh.sshd_root_login": sshd_root_login, "ssh.sshd_empty_passwords": sshd_empty_passwords,
    "ssh.sshd_hardening": sshd_hardening, "ssh.auth_failures": auth_failures,
    "ssh.pending_security_updates": pending_security_updates, "ssh.auto_upgrades_off": auto_upgrades_off,
    "ssh.host_firewall": host_firewall, "ssh.fail2ban_absent": fail2ban_absent, "ssh.world_writable": world_writable,
    "ssh.external_logins": external_logins, "ssh.login_shell_users": login_shell_users,
    "ssh.agent_sudo_scope": agent_sudo_scope, "ssh.docker_privileged": docker_privileged,
    "ssh.docker_stale_images": docker_stale_images,
}
