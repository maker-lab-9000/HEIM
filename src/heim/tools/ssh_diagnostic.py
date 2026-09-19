"""Read-only SSH diagnostic tool (port of n8n PAM 40).

Guard first (see heim.guards.command_guard), then execute over SSH; every
executed AND blocked command is streamed to the live feed and audit-logged.
The OS-level permissions of the SSH user remain the authoritative boundary —
the guard is defense-in-depth.
"""
from __future__ import annotations

import asyncio
import json

import asyncssh

from heim.guards import guard_command
from heim.tools.base import Tool, clip

COMMAND_TIMEOUT_S = 90


class SshUnavailable(RuntimeError):
    """Connection/auth failure carrying an operator-actionable explanation."""


class SshDiagnosticTool(Tool):
    _conn: asyncssh.SSHClientConnection | None = None

    def _host(self):
        host = self.ctx.config.hosts[self.cfg.options["host"]]
        if host.ssh is None:
            raise RuntimeError(f"host {host.name} has no ssh config")
        return host

    async def _connection(self) -> asyncssh.SSHClientConnection:
        if self._conn is None or self._conn.is_closed():
            ssh = self._host().ssh
            key = ssh.resolved_key_path()
            try:
                self._conn = await asyncssh.connect(
                    ssh.host,
                    port=ssh.port,
                    username=ssh.user,
                    client_keys=[key],
                    known_hosts=None,
                )
            except (OSError, asyncssh.Error) as exc:
                raise SshUnavailable(self._setup_hint(exc, ssh, key)) from exc
        return self._conn

    @staticmethod
    def _setup_hint(exc: Exception, ssh, key: str) -> str:
        """Turn a connection failure into something the agent can act on.

        The agent cannot fix the host, but it CAN stop retrying SSH and say in
        its report why the host was unreachable — which is far better than the
        bare "PermissionError: [Errno 13]" that sent one real investigation
        into three blind retries and a report that could not explain the gap.
        """
        import os

        who = f"uid {os.getuid()}"
        target = f"{ssh.user}@{ssh.host}:{ssh.port}"
        if isinstance(exc, PermissionError):
            return (
                f"SSH is unavailable: the private key {key!r} cannot be read by this "
                f"process ({who}). The key must be readable by the user HEIM runs as — "
                f"in Docker that means owned by uid 1000, e.g. "
                f"`install -o 1000 -g 1000 -m 600 <key> /opt/heim/secrets/agent_key` and "
                f"point HEIM_SSH_KEY_FILE at it. Do not retry SSH; use the Prometheus and "
                f"API tools, and say in your report that host access was unavailable."
            )
        if isinstance(exc, FileNotFoundError):
            return (
                f"SSH is unavailable: no private key at {key!r} ({who}). Set "
                f"HEIM_SSH_KEY_FILE to the key's host path so compose mounts it. Do not "
                f"retry SSH; use the other tools and note the gap in your report."
            )
        if isinstance(exc, asyncssh.PermissionDenied):
            return (
                f"SSH is unavailable: {target} rejected the key {key!r}. Its public half "
                f"is probably not in that user's authorized_keys. Do not retry SSH; use "
                f"the other tools and note the gap in your report."
            )
        return (
            f"SSH is unavailable: cannot connect to {target} using {key!r} "
            f"({type(exc).__name__}: {exc}). Do not retry SSH; use the other tools and "
            f"note the gap in your report."
        )

    async def run(self, args: dict) -> str:
        command = str(args.get("command") or "").strip()
        limit = int(self.cfg.options.get("clip_bytes", 8192))
        if not command:
            return json.dumps({"ok": False, "error": "no command provided"})

        g = guard_command(command)
        if not g.allowed:
            await self.ctx.emit(f"⛔ BLOCKED: $ {command}\n({g.reason})")
            self.ctx.record({"tool": self.name, "command": command, "blocked": True, "reason": g.reason})
            return json.dumps({
                "ok": True,
                "blocked": True,
                "command": command,
                "message": f"Command blocked by safety guard ({g.reason}). Rephrase as a single read-only command.",
            })

        try:
            conn = await self._connection()
        except SshUnavailable as exc:
            await self.ctx.emit(f"⛔ SSH unavailable\n{exc}")
            self.ctx.record({"tool": self.name, "command": command, "blocked": False,
                             "error": "ssh_unavailable", "detail": str(exc)})
            return json.dumps({"ok": False, "sshUnavailable": True, "error": str(exc)})
        result = await asyncio.wait_for(conn.run(command, check=False), COMMAND_TIMEOUT_S)
        stdout = clip(str(result.stdout or ""), limit)
        stderr = clip(str(result.stderr or ""), limit // 4)
        exit_code = result.exit_status

        preview = (stdout or stderr or "(no output)").strip()
        await self.ctx.emit(f"🖥️ $ {command}\n→ exit {exit_code}\n{preview[:700]}")
        self.ctx.record({
            "tool": self.name, "command": command, "blocked": False,
            "exitCode": exit_code, "stdoutBytes": len(result.stdout or ""),
        })
        return json.dumps({
            "ok": True, "blocked": False, "command": command,
            "exitCode": exit_code, "stdout": stdout, "stderr": stderr,
        })

    async def close(self) -> None:
        if self._conn is not None and not self._conn.is_closed():
            self._conn.close()
        self._conn = None
