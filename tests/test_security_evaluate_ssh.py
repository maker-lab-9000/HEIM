import json
from datetime import datetime, timezone
from pathlib import Path

from heim.security.catalogue import load_catalogue
from heim.security.evaluate import EvalContext, _registry, evaluate
from heim.security.types import Evidence, EvidenceBundle

CAT = load_catalogue(Path(__file__).resolve().parent.parent / "config" / "security" / "checks.yaml")
NOW = datetime(2026, 9, 28, 6, 0, tzinfo=timezone.utc)
CTX = dict(now=NOW, instance_host_map={}, hosts=("heim", "home-assistant", "homelab", "ubuntu-server"))
H = "ubuntu-server"


def ssh(key, text, exit_code=0, stderr=""):
    target = CAT.sources[key.split("[")[0]].target
    status = "ok" if str(text).strip() else "empty"
    return Evidence(key, status, body=text, exit_code=exit_code, stderr=stderr, target=target)


def rows_for(check_id, *items, ctx=None):
    b = EvidenceBundle(items={e.key: e for e in items})
    return [r for r in evaluate(CAT, b, ctx or EvalContext(**CTX)) if r.check_id == check_id]


def test_every_catalogue_check_has_an_evaluator():
    plain, compound = _registry()
    for c in CAT.checks:
        assert c.id in (compound if c.compound else plain), c.id


SS = ("tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"
      "tcp LISTEN 0 4096 *:8081 *:* users:((\"docker-proxy\",pid=2,fd=4))\n"
      "tcp LISTEN 0 4096 0.0.0.0:2375 0.0.0.0:* users:((\"dockerd\",pid=3,fd=4))\n"
      "tcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:((\"postgres\",pid=4,fd=4))\n"
      "tcp LISTEN 0 4096 [::]:8096 [::]:* users:((\"jellyfin\",pid=5,fd=4))\n")


def test_listeners_expected_unexpected_critical_and_control():
    rows = {r.subject: r for r in rows_for("ssh.listeners_unexpected", ssh("ssh.listeners", SS))}
    assert rows["22/sshd"].status == "ok" and rows["8081/docker-proxy"].status == "ok"
    assert rows["2375/dockerd"].severity == "critical"
    assert rows["8096/jellyfin"].status == "fail" and rows["8096/jellyfin"].severity == "warning"
    assert "5432/postgres" not in rows                              # loopback-bound
    no22 = rows_for("ssh.listeners_unexpected", ssh("ssh.listeners", "tcp LISTEN 0 1 *:80 *:* users:((\"x\",pid=1,fd=1))\n"))
    assert no22[0].status == "unavailable"


MAIN = "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\nX11Forwarding yes\n"
DROPIN = "PasswordAuthentication yes\n"
LS_OK = "total 4\n-rw-r--r-- 1 root root 30 Jan 1 00:00 50-cloud-init.conf\n"
LS_SECRET = "total 4\n-rw------- 1 root root 30 Jan 1 00:00 99-secret.conf\n"


def test_sshd_checks_dropins_win_and_unreadable_dropin_is_unavailable():
    b = [ssh("ssh.sshd_config", MAIN), ssh("ssh.sshd_config_d", DROPIN), ssh("ssh.sshd_config_d_ls", LS_OK)]
    assert rows_for("ssh.sshd_password_auth", *b)[0].status == "fail"
    assert rows_for("ssh.sshd_root_login", *b)[0].status == "ok"
    assert rows_for("ssh.sshd_empty_passwords", *b)[0].status == "ok"
    hard = rows_for("ssh.sshd_hardening", *b)
    assert any(r.subject == "x11forwarding" for r in hard) and any(r.subject == "allowusers" for r in hard)
    root = [ssh("ssh.sshd_config", "PermitRootLogin yes\n"), ssh("ssh.sshd_config_d", ""), ssh("ssh.sshd_config_d_ls", "total 0\n")]
    assert rows_for("ssh.sshd_root_login", *root)[0].severity == "critical"
    secret = [ssh("ssh.sshd_config", MAIN), ssh("ssh.sshd_config_d", ""), ssh("ssh.sshd_config_d_ls", LS_SECRET)]
    assert rows_for("ssh.sshd_password_auth", *secret)[0].status == "unavailable"


def test_auth_failures_count_sample_and_permission_hint():
    ok_rows = rows_for("ssh.auth_failures", ssh("ssh.auth_fail_count", "0\n", exit_code=1), ssh("ssh.auth_fail_sample", ""))
    assert ok_rows[0].status == "ok"
    hit = rows_for("ssh.auth_failures", ssh("ssh.auth_fail_count", "137\n"), ssh("ssh.auth_fail_sample", "Failed password for root from 203.0.113.9 port 1 ssh2\n"))
    assert hit[0].status == "fail" and hit[0].severity == "critical" and "203.0.113.9" in hit[0].detail
    hint = "Hint: You are currently not seeing messages from other users and the system.\n"
    denied = rows_for("ssh.auth_failures", ssh("ssh.auth_fail_count", "0\n", exit_code=1, stderr=hint), ssh("ssh.auth_fail_sample", "", stderr=hint))
    assert denied[0].status == "unavailable" and "systemd-journal" in denied[0].detail


def test_updates_auto_upgrades_and_units():
    upd = rows_for("ssh.pending_security_updates", ssh("ssh.updates_available", "12 updates can be applied immediately.\n5 of these updates are standard security updates.\n"))
    assert upd[0].status == "fail" and "5 standard security" in upd[0].summary
    assert rows_for("ssh.pending_security_updates", ssh("ssh.updates_available", "", exit_code=1))[0].status == "unavailable"
    units_on = ssh("ssh.unit_states", "inactive\ninactive\ninactive\nactive\nactive\n", exit_code=3)
    au = rows_for("ssh.auto_upgrades_off", ssh("ssh.auto_upgrades", 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'), units_on)
    assert au[0].status == "ok"
    au_off = rows_for("ssh.auto_upgrades_off", ssh("ssh.auto_upgrades", 'APT::Periodic::Unattended-Upgrade "0";\n'), units_on)
    assert au_off[0].status == "fail"
    assert rows_for("ssh.host_firewall", units_on)[0].status == "note"
    assert rows_for("ssh.fail2ban_absent", units_on)[0].status == "note"


def test_world_writable_external_logins_users_sudo():
    ww = rows_for("ssh.world_writable", ssh("ssh.world_writable", "/etc/cron.d/oops\n/opt/app/config.ini\n"))
    assert {r.subject for r in ww} == {"/etc/cron.d/oops", "/opt/app/config.ini"} and all(r.status == "fail" for r in ww)
    assert rows_for("ssh.world_writable", ssh("ssh.world_writable", ""))[0].status == "ok"
    last = ("alice pts/0 192.168.1.20 Mon Sep 21 08:00:00 2026 still logged in\n"
            "alice pts/1 203.0.113.9 Sat Sep 19 09:00:00 2026 - Sat Sep 19 09:30:00 2026 (00:30)\n")
    ext = rows_for("ssh.external_logins", ssh("ssh.last_logins", last))
    assert ext[0].status == "fail" and ext[0].subject == "external" and "203.0.113.9" in ext[0].detail
    users = rows_for("ssh.login_shell_users", ssh("ssh.login_shells", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/zsh\n"))
    assert users[0].status == "note" and "2 account" in users[0].summary
    sudo_ok = "User agent may run the following commands on host:\n    (root) NOPASSWD: /usr/bin/du, /usr/bin/df, /usr/bin/findmnt, /usr/bin/lsof, /usr/bin/ls, /usr/bin/ss, /usr/local/bin/agent-docker\n"
    assert rows_for("ssh.agent_sudo_scope", ssh("ssh.sudo_scope", sudo_ok))[0].status == "ok"
    sudo_bad = sudo_ok + "    (ALL) NOPASSWD: ALL\n"
    assert rows_for("ssh.agent_sudo_scope", ssh("ssh.sudo_scope", sudo_bad))[0].status == "fail"
    assert rows_for("ssh.agent_sudo_scope", ssh("ssh.sudo_scope", "", exit_code=1, stderr="sudo: a password is required"))[0].status == "unavailable"


def test_docker_inspect_and_images():
    cad = json.dumps([{"Name": "/cadvisor", "HostConfig": {"Privileged": True, "Binds": ["/var/run/docker.sock:/var/run/docker.sock:ro"], "NetworkMode": "bridge", "CapAdd": None}}])
    graf = json.dumps([{"Name": "/grafana", "HostConfig": {"Privileged": False, "Binds": ["grafana-data:/var/lib/grafana"], "NetworkMode": "bridge", "CapAdd": None}}])
    rows = {r.subject: r for r in rows_for("ssh.docker_privileged", ssh("ssh.docker_inspect[cadvisor]", cad), ssh("ssh.docker_inspect[grafana]", graf))}
    assert rows["cadvisor"].status == "fail" and "privileged" in rows["cadvisor"].summary and "docker.sock" in rows["cadvisor"].summary
    assert rows["grafana"].status == "ok"
    imgs = ("REPOSITORY TAG IMAGE ID CREATED SIZE\n"
            "grafana/grafana latest aaa 3 weeks ago 400MB\n"
            "old/thing v1 bbb 14 months ago 90MB\n")
    stale = rows_for("ssh.docker_stale_images", ssh("ssh.docker_images", imgs))
    assert [r.subject for r in stale if r.status == "note"] == ["old/thing:v1"]


def test_compound_no_firewall_any_layer():
    fw_off = [Evidence("pve.fw_cluster_options", "ok", body={"digest": "x"}), Evidence("pve.fw_cluster_rules", "empty", body=[]),
              Evidence("pve.fw_node_options", "ok", body={}), Evidence("pve.fw_node_rules", "empty", body=[])]
    units = ssh("ssh.unit_states", "inactive\ninactive\ninactive\nactive\nactive\n", exit_code=3)
    rows = rows_for("net.no_firewall_any_layer", *fw_off, units)
    assert rows[0].status == "fail" and rows[0].host == H
    fw_on = [Evidence("pve.fw_cluster_options", "ok", body={"enable": 1}), Evidence("pve.fw_cluster_rules", "ok", body=[{"a": 1}]),
             Evidence("pve.fw_node_options", "ok", body={}), Evidence("pve.fw_node_rules", "empty", body=[])]
    assert rows_for("net.no_firewall_any_layer", *fw_on, units)[0].status == "ok"


# ---------------------------------------------------------------- R5 deviations from the brief


def test_pending_security_updates_empty_file_means_no_updates_not_unavailable():
    """R5 amendment: `cat` on /var/lib/update-notifier/updates-available succeeding
    (exit 0) with zero bytes is the real-world "fully up to date" state, not a
    failure to read the file — it must evaluate to `ok`, not `unavailable`.
    Only a non-zero exit code (file missing/unreadable) is `unavailable`."""
    assert rows_for("ssh.pending_security_updates", ssh("ssh.updates_available", "", exit_code=0))[0].status == "ok"


def test_compound_no_firewall_any_layer_unavailable_when_pve_side_unverified():
    """R5: the compound check must not silently default to `ok` when one of
    its two inputs (pve.firewall_disabled) could not itself be verified —
    that would report "no finding" for a layer that was never actually
    checked. Omitting the pve.fw_* evidence makes pve.firewall_disabled's
    own gate_sources() turn it into `unavailable`; the compound must then
    also be `unavailable`, not `ok`."""
    units = ssh("ssh.unit_states", "inactive\ninactive\ninactive\nactive\nactive\n", exit_code=3)
    rows = rows_for("net.no_firewall_any_layer", units)
    assert rows[0].status == "unavailable"
