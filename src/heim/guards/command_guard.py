"""SSH diagnostic command guard.

Faithful port of the ``Guard Command`` n8n Code node from the PAM-40 SSH
Diagnostic workflow (``reference/pam-40-ssh-diagnostic/guard-command.js``).

Default-deny read-only gate for agent-issued SSH commands: segment-aware
splitting on ``&& || ; | \\n``, env-assignment and ``sudo`` prefix stripping,
a hard-deny list of destructive/network/interpreter binaries, shell-escape
(backtick / ``$(``) and file-redirection blocking, and read-only sub-command
gating of dual-use tools (docker/podman, systemctl, service, journalctl,
swapon, sysctl, sed, find). Anything not explicitly denied is allowed —
including the ``agent-docker`` wrapper, which is deliberately not gated.
"""

from __future__ import annotations

import re

from heim.guards import GuardResult

_HARD_DENY: frozenset[str] = frozenset({
    "rm", "rmdir", "unlink", "shred", "mv", "dd", "mkfs", "fdisk", "parted",
    "wipefs", "blkdiscard", "reboot", "shutdown", "halt", "poweroff", "init",
    "telinit", "kill", "killall", "pkill", "chmod", "chown", "chgrp",
    "truncate", "tee", "mount", "umount", "crontab", "at", "atrm", "batch",
    "iptables", "nft", "ufw", "firewall-cmd", "passwd", "useradd", "userdel",
    "usermod", "groupadd", "groupdel", "visudo", "apt", "apt-get", "aptitude",
    "dpkg", "snap", "yum", "dnf", "rpm", "pip", "pip3", "npm", "pnpm", "yarn",
    "gem", "cargo", "make", "eval", "exec", "source", "nohup", "setfacl",
    "setcap", "chattr", "ln", "rmmod", "modprobe", "insmod", "swapoff",
    "fsck", "mkswap", "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh",
    "scp", "sftp", "ftp", "rsync", "xargs", "bash", "sh", "zsh", "dash",
    "ksh", "fish", "python", "python2", "python3", "perl", "ruby", "node",
    "php", "lua", "awk", "gawk",
})

_DOCKER_MUT: frozenset[str] = frozenset({
    "start", "stop", "restart", "rm", "rmi", "kill", "create", "run", "exec",
    "up", "down", "pull", "push", "build", "prune", "pause", "unpause",
    "commit", "cp", "export", "import", "save", "load", "tag", "login",
    "logout", "scale", "update", "rename", "attach", "wait",
})

_SYSCTL_MUT: frozenset[str] = frozenset({
    "start", "stop", "restart", "reload", "try-restart", "reload-or-restart",
    "enable", "disable", "mask", "unmask", "isolate", "set-property", "edit",
    "daemon-reload", "daemon-reexec", "reset-failed", "kill", "set-default",
    "halt", "poweroff", "reboot", "suspend", "hibernate",
})

_SWAPON_RO: frozenset[str] = frozenset({
    "-s", "--summary", "--show", "--noheadings", "--bytes", "--raw",
    "-h", "--help",
})

_ENV_ASSIGN_TEST = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_ENV_ASSIGN_STRIP = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*\s*")
_SUDO_PREFIX = re.compile(r"^sudo\s+(-[A-Za-z]+\s+)*", re.IGNORECASE)
_SEGMENT_SPLIT = re.compile(r"&&|\|\||;|\||\n")


def guard_command(command: str) -> GuardResult:
    """Check an SSH command against the read-only diagnostic policy.

    Returns ``GuardResult`` with ``normalized`` set to the trimmed command
    (the string that will be executed verbatim when allowed).
    """
    raw = ("" if command is None else str(command)).strip()

    def block(reason: str) -> GuardResult:
        return GuardResult(allowed=False, reason=reason, normalized=raw)

    if not raw:
        return block("Empty command.")
    if len(raw) > 2000:
        return block("Command too long (max 2000 chars).")
    if "`" in raw:
        return block("Backtick command substitution is not allowed.")
    if "$(" in raw:
        return block("Command substitution is not allowed.")

    redir = raw
    redir = re.sub(r"2>&1", " ", redir)
    redir = re.sub(r"&>\s*/dev/null", " ", redir)
    redir = re.sub(r"2>\s*/dev/null", " ", redir)
    redir = re.sub(r"1?>\s*/dev/null", " ", redir)
    if ">" in redir:
        return block("Writing to files via > or >> redirection is not allowed.")

    for seg in _SEGMENT_SPLIT.split(raw):
        seg = seg.strip()
        if not seg:
            continue
        while _ENV_ASSIGN_TEST.search(seg):
            seg = _ENV_ASSIGN_STRIP.sub("", seg, count=1)
        seg = _SUDO_PREFIX.sub("", seg, count=1)
        if not seg:
            continue
        tokens = re.split(r"\s+", seg)
        first = (tokens[0] if tokens else "").lower()
        if "/" in first:
            first = first[first.rfind("/") + 1 :]
        if not first:
            continue
        if first in _HARD_DENY:
            return block(
                'Command "' + first + '" is not permitted (read-only diagnostics only).'
            )
        rest = [t.lower() for t in tokens[1:]]
        if first == "sed" and any(t == "-i" or t.startswith("-i") for t in rest):
            return block("sed -i (in-place edit) is not allowed.")
        if first == "find" and any(
            t in ("-delete", "-exec", "-execdir", "-fprint", "-fprintf") for t in rest
        ):
            return block("find with -delete/-exec is not allowed.")
        if first in ("docker", "docker-compose", "podman") and any(
            t in _DOCKER_MUT for t in rest
        ):
            return block(
                "Only read-only docker subcommands (ps, logs, inspect, stats, images, df) are allowed."
            )
        if first == "systemctl" and any(t in _SYSCTL_MUT for t in rest):
            return block(
                "Only read-only systemctl subcommands (status, show, list-*, is-active) are allowed."
            )
        if first == "service" and not (rest and rest[-1] == "status"):
            return block('Only "service <name> status" is allowed.')
        if first == "journalctl" and any(
            t in ("--vacuum-size", "--vacuum-time", "--vacuum-files", "--rotate", "--flush")
            for t in rest
        ):
            return block("journalctl maintenance flags are not allowed.")
        if first == "swapon":
            if any(
                not (t in _SWAPON_RO or t.startswith("--show") or t.startswith("--output"))
                for t in rest
            ):
                return block("Only read-only swapon (--show / -s) is allowed.")
        if first == "sysctl" and any(
            ("=" in t) or t in ("-w", "--write", "-p", "--load", "--system") for t in rest
        ):
            return block(
                "Only read-only sysctl (reading keys, e.g. sysctl vm.swappiness) is allowed."
            )

    return GuardResult(allowed=True, reason="ok", normalized=raw)
