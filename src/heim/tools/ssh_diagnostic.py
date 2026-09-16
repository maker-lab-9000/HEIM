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
            self._conn = await asyncssh.connect(
                ssh.host,
                port=ssh.port,
                username=ssh.user,
                client_keys=[ssh.resolved_key_path()],
                known_hosts=None,
            )
        return self._conn

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

        conn = await self._connection()
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
