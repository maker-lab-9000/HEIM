"""Tests for the guard ports (command, HA path, Proxmox path).

Expectations are derived from the original n8n Code nodes in
``reference/pam-40-ssh-diagnostic/guard-command.js``,
``reference/pam-42-ha-api/guard-path.js`` and
``reference/pam-44-proxmox-api/guard-path.js`` — including their quirks.
"""

from __future__ import annotations

import pytest

from heim.guards import GuardResult, guard_command, guard_ha_path, guard_proxmox_path


# ---------------------------------------------------------------------------
# guard_command
# ---------------------------------------------------------------------------

ALLOWED_COMMANDS = [
    # plain reads
    "df -h",
    "free -m",
    "uptime",
    "cat /var/log/syslog",
    "journalctl --no-pager -n 50",
    # sudo prefix (with flags) is stripped and the inner command evaluated
    "sudo du -x -d1 /docker-data | sort -h",
    "sudo -n df -h",
    # leading env assignments are stripped
    "LANG=C df -h",
    # allowed stderr/null redirections are tolerated
    "ls -la /var/lib/docker 2>&1",
    "dmesg 2> /dev/null",
    "smartctl -a /dev/sda > /dev/null",
    # docker/podman read-only subcommands
    "docker ps",
    "docker logs mycontainer --tail 50",
    "docker inspect mycontainer",
    "docker stats --no-stream",
    "podman images",
    # the agent-docker wrapper is deliberately not gated at all
    "sudo agent-docker logs foo --tail 50",
    "sudo agent-docker restart pam-agent",
    # systemctl / service read-only forms
    "systemctl status nginx",
    "systemctl list-units --failed",
    "service nginx status",
    # journalctl quirk: only the exact bare flag is denied, '=' form slips by
    "journalctl --vacuum-time=2d",
    # swapon / sysctl read-only forms
    "swapon --show",
    "swapon -s",
    "sysctl vm.swappiness",
    # multi-segment: every segment read-only
    "df -h && free -m; uptime | head -n 1",
]


@pytest.mark.parametrize("command", ALLOWED_COMMANDS)
def test_guard_command_allowed(command: str) -> None:
    res = guard_command(command)
    assert res.allowed, f"{command!r} should be allowed, got: {res.reason}"
    assert res.reason == "ok"
    assert res.normalized == command.strip()


BLOCKED_COMMANDS = [
    # empties / limits
    ("", "Empty command."),
    ("   ", "Empty command."),
    ("df -h " + "x" * 2000, "Command too long (max 2000 chars)."),
    # shell escapes
    ("echo `id`", "Backtick command substitution is not allowed."),
    ("echo $(id)", "Command substitution is not allowed."),
    # redirection
    ("echo x > /tmp/f", "Writing to files via > or >> redirection is not allowed."),
    ("df -h >> /tmp/out", "Writing to files via > or >> redirection is not allowed."),
    # hard denies
    ("rm -rf /", 'Command "rm" is not permitted (read-only diagnostics only).'),
    ("sudo rm -rf /tmp/x", 'Command "rm" is not permitted (read-only diagnostics only).'),
    ("dd if=/dev/zero of=/dev/sda", 'Command "dd" is not permitted (read-only diagnostics only).'),
    ("reboot", 'Command "reboot" is not permitted (read-only diagnostics only).'),
    ("apt install htop", 'Command "apt" is not permitted (read-only diagnostics only).'),
    ("/usr/bin/rm -f x", 'Command "rm" is not permitted (read-only diagnostics only).'),
    # every pipe/and/or/semicolon/newline segment is checked
    ("df -h && rm -rf /", 'Command "rm" is not permitted (read-only diagnostics only).'),
    ("df -h; shutdown now", 'Command "shutdown" is not permitted (read-only diagnostics only).'),
    ("cat /etc/passwd | xargs rm", 'Command "xargs" is not permitted (read-only diagnostics only).'),
    ("df -h\nreboot", 'Command "reboot" is not permitted (read-only diagnostics only).'),
    # nested interpreters
    ('bash -c "rm -rf /"', 'Command "bash" is not permitted (read-only diagnostics only).'),
    ("python3 -c 'print(1)'", 'Command "python3" is not permitted (read-only diagnostics only).'),
    ("perl -e 'unlink shift'", 'Command "perl" is not permitted (read-only diagnostics only).'),
    # docker/podman mutation gating (sudo-stripped too)
    ("docker rm foo", "Only read-only docker subcommands (ps, logs, inspect, stats, images, df) are allowed."),
    ("docker restart app", "Only read-only docker subcommands (ps, logs, inspect, stats, images, df) are allowed."),
    ("sudo docker exec -it x sh", "Only read-only docker subcommands (ps, logs, inspect, stats, images, df) are allowed."),
    ("docker-compose up -d", "Only read-only docker subcommands (ps, logs, inspect, stats, images, df) are allowed."),
    ("podman stop web", "Only read-only docker subcommands (ps, logs, inspect, stats, images, df) are allowed."),
    # systemctl / service gating
    ("systemctl restart nginx", "Only read-only systemctl subcommands (status, show, list-*, is-active) are allowed."),
    ("sudo systemctl daemon-reload", "Only read-only systemctl subcommands (status, show, list-*, is-active) are allowed."),
    ("service nginx restart", 'Only "service <name> status" is allowed.'),
    ("service", 'Only "service <name> status" is allowed.'),
    # sed / find
    ("sed -i s/a/b/ /etc/hosts", "sed -i (in-place edit) is not allowed."),
    ('find /var -name "*.log" -delete', "find with -delete/-exec is not allowed."),
    ("find / -name core -exec rm {} +", "find with -delete/-exec is not allowed."),
    # journalctl / swapon / sysctl maintenance
    ("journalctl --vacuum-time 2d", "journalctl maintenance flags are not allowed."),
    ("journalctl --rotate", "journalctl maintenance flags are not allowed."),
    ("swapon /dev/sda1", "Only read-only swapon (--show / -s) is allowed."),
    ("sysctl -w vm.swappiness=10", "Only read-only sysctl (reading keys, e.g. sysctl vm.swappiness) is allowed."),
    ("sysctl vm.swappiness=10", "Only read-only sysctl (reading keys, e.g. sysctl vm.swappiness) is allowed."),
]


@pytest.mark.parametrize("command,reason", BLOCKED_COMMANDS)
def test_guard_command_blocked(command: str, reason: str) -> None:
    res = guard_command(command)
    assert not res.allowed, f"{command!r} should be blocked"
    assert res.reason == reason


def test_guard_command_normalized_is_trimmed_input() -> None:
    res = guard_command("  df -h  ")
    assert res == GuardResult(allowed=True, reason="ok", normalized="df -h")


# ---------------------------------------------------------------------------
# guard_ha_path
# ---------------------------------------------------------------------------

HA_ALLOWED = [
    ("/api/", "/api/"),
    ("/api/config", "/api/config"),
    ("/api/error_log", "/api/error_log"),
    ("/api/states", "/api/states"),
    ("/api/states/sensor.x", "/api/states/sensor.x"),
    # leading slash is added when missing
    ("api/config", "/api/config"),
    # full URL prefix is stripped
    ("http://homeassistant.local:8123/api/error_log", "/api/error_log"),
    ("https://ha.example.com/api/states/sensor.cpu_temp", "/api/states/sensor.cpu_temp"),
    ("/api/logbook/2026-01-01T00:00:00+00:00", "/api/logbook/2026-01-01T00:00:00+00:00"),
    (
        "/api/history/period/2026-01-01T00:00:00?filter_entity_id=sensor.x&end_time=2026-01-02T00:00:00",
        "/api/history/period/2026-01-01T00:00:00?filter_entity_id=sensor.x&end_time=2026-01-02T00:00:00",
    ),
]


@pytest.mark.parametrize("path,normalized", HA_ALLOWED)
def test_guard_ha_path_allowed(path: str, normalized: str) -> None:
    res = guard_ha_path(path)
    assert res.allowed, f"{path!r} should be allowed, got: {res.reason}"
    assert res.normalized == normalized


HA_BLOCKED = [
    # POST-style / non-allowlisted endpoints
    ("/api/services/light/turn_on", "endpoint not in the read-only allowlist"),
    ("/api/services", "endpoint not in the read-only allowlist"),
    ("/api/template", "endpoint not in the read-only allowlist"),
    ("/", "endpoint not in the read-only allowlist"),
    ("", "endpoint not in the read-only allowlist"),
    ("/api", "endpoint not in the read-only allowlist"),  # only /api/ (with slash) is allowed
    # bad characters
    ("/api/states/../config", 'path contains whitespace, backslash or ".."'),
    ("/api/error log", 'path contains whitespace, backslash or ".."'),
    ("/api\\states", 'path contains whitespace, backslash or ".."'),
    # states does not accept a query string
    ("/api/states/sensor.x?foo=1", "endpoint not in the read-only allowlist"),
]


@pytest.mark.parametrize("path,reason", HA_BLOCKED)
def test_guard_ha_path_blocked(path: str, reason: str) -> None:
    res = guard_ha_path(path)
    assert not res.allowed, f"{path!r} should be blocked"
    assert res.reason == reason


# ---------------------------------------------------------------------------
# guard_proxmox_path
# ---------------------------------------------------------------------------

UPID = "UPID:homelab:0004F1A2:000A3B7C:65F01234:vzdump:100:root@pam:"

PROXMOX_ALLOWED = [
    (
        "/api2/json/nodes/homelab/tasks?typefilter=vzdump&limit=20",
        "/api2/json/nodes/homelab/tasks?typefilter=vzdump&limit=20",
    ),
    # missing /api2/json prefix is auto-added for /nodes, /cluster, /version
    (
        "/nodes/homelab/tasks?typefilter=vzdump&limit=20",
        "/api2/json/nodes/homelab/tasks?typefilter=vzdump&limit=20",
    ),
    (
        "nodes/homelab/tasks?typefilter=vzdump&limit=20",
        "/api2/json/nodes/homelab/tasks?typefilter=vzdump&limit=20",
    ),
    ("/version", "/api2/json/version"),
    ("/cluster/resources?type=vm", "/api2/json/cluster/resources?type=vm"),
    ("/nodes/homelab/status", "/api2/json/nodes/homelab/status"),
    ("/api2/json/nodes/homelab/qemu", "/api2/json/nodes/homelab/qemu"),
    (
        "/api2/json/nodes/homelab/qemu/100/status/current",
        "/api2/json/nodes/homelab/qemu/100/status/current",
    ),
    # task log with '@' in the UPID
    (
        f"/api2/json/nodes/homelab/tasks/{UPID}/log",
        f"/api2/json/nodes/homelab/tasks/{UPID}/log",
    ),
    (
        f"/nodes/homelab/tasks/{UPID}/status?limit=10",
        f"/api2/json/nodes/homelab/tasks/{UPID}/status?limit=10",
    ),
    ("/api2/json/nodes/homelab/syslog?limit=100", "/api2/json/nodes/homelab/syslog?limit=100"),
    ("/api2/json/nodes/homelab/disks/list", "/api2/json/nodes/homelab/disks/list"),
    (
        "/api2/json/nodes/homelab/disks/smart?disk=/dev/sda",
        "/api2/json/nodes/homelab/disks/smart?disk=/dev/sda",
    ),
    (
        "/api2/json/nodes/homelab/storage/local/content",
        "/api2/json/nodes/homelab/storage/local/content",
    ),
    # full URL prefix stripped
    ("https://pve.local:8006/api2/json/version", "/api2/json/version"),
]


@pytest.mark.parametrize("path,normalized", PROXMOX_ALLOWED)
def test_guard_proxmox_path_allowed(path: str, normalized: str) -> None:
    res = guard_proxmox_path(path)
    assert res.allowed, f"{path!r} should be allowed, got: {res.reason}"
    assert res.normalized == normalized


PROXMOX_BLOCKED = [
    # non-allowlisted endpoints
    ("/access/users", "endpoint not in the read-only allowlist"),
    ("/api2/json/access/users", "endpoint not in the read-only allowlist"),
    ("/api2/json/nodes/homelab/qemu/100/snapshot", "endpoint not in the read-only allowlist"),
    # only node "homelab" is allowed
    ("/api2/json/nodes/otherhost/status", "endpoint not in the read-only allowlist"),
    ("", "endpoint not in the read-only allowlist"),
    # bad characters
    ("/api2/json/nodes/homelab/../pve/status", 'path contains whitespace, backslash or ".."'),
    ("/api2/json/nodes/homelab/tasks ?limit=1", 'path contains whitespace, backslash or ".."'),
    ("/api2\\json/version", 'path contains whitespace, backslash or ".."'),
]


@pytest.mark.parametrize("path,reason", PROXMOX_BLOCKED)
def test_guard_proxmox_path_blocked(path: str, reason: str) -> None:
    res = guard_proxmox_path(path)
    assert not res.allowed, f"{path!r} should be blocked"
    assert res.reason == reason
