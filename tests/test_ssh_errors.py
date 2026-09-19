"""SSH connection failures must explain themselves.

A real investigation (live, 2026-09-19) burned three tool calls on
`{"ok": false, "error": "PermissionError: [Errno 13] ... '/root/.ssh/crt'"}`
and produced a report that could not say why the host was unreachable. The
tool now returns the cause, the fix, and an instruction not to retry.
"""
from __future__ import annotations

import json

import asyncssh
import pytest

from heim.config import Host, SshCfg, ToolCfg
from heim.tools.base import ToolContext
from heim.tools.ssh_diagnostic import SshDiagnosticTool, SshUnavailable


class _Cfg:
    def __init__(self, host):
        self.hosts = {"ubuntu-server": host}


def _tool(monkeypatch, exc: Exception) -> SshDiagnosticTool:
    host = Host(name="ubuntu-server", role="guest",
                ssh=SshCfg(host="10.0.0.10", port=22, user="agent", key_path="/root/.ssh/crt"))
    cfg = ToolCfg(name="ssh_diagnostic", description="d",
                  module="heim.tools.ssh_diagnostic:SshDiagnosticTool",
                  args={}, required=[], options={"host": "ubuntu-server"})
    tool = SshDiagnosticTool(cfg, ToolContext(config=_Cfg(host)))

    async def _boom(*a, **k):
        raise exc
    monkeypatch.setattr("heim.tools.ssh_diagnostic.asyncssh.connect", _boom)
    return tool


async def test_unreadable_key_names_the_key_the_uid_and_the_fix(monkeypatch):
    out = json.loads(await _tool(monkeypatch, PermissionError(13, "Permission denied"))
                     .run({"command": "df -h"}))
    assert out["ok"] is False and out["sshUnavailable"] is True
    msg = out["error"]
    assert "/root/.ssh/crt" in msg            # WHICH key was tried
    assert "uid" in msg                        # who tried to read it
    assert "HEIM_SSH_KEY_FILE" in msg          # the actual fix
    assert "Do not retry SSH" in msg           # stop burning steps
    assert "PermissionError: [Errno 13]" not in msg   # not the bare stdlib error


async def test_missing_key_is_distinguished_from_an_unreadable_one(monkeypatch):
    out = json.loads(await _tool(monkeypatch, FileNotFoundError(2, "No such file"))
                     .run({"command": "df -h"}))
    assert "no private key at" in out["error"]
    assert "cannot be read" not in out["error"]


async def test_rejected_key_points_at_authorized_keys(monkeypatch):
    out = json.loads(await _tool(monkeypatch, asyncssh.PermissionDenied("auth failed"))
                     .run({"command": "df -h"}))
    assert "authorized_keys" in out["error"]
    assert "agent@10.0.0.10:22" in out["error"]


async def test_unexpected_failures_still_explain_and_stop_retries(monkeypatch):
    out = json.loads(await _tool(monkeypatch, OSError("no route to host"))
                     .run({"command": "df -h"}))
    assert "cannot connect to agent@10.0.0.10:22" in out["error"]
    assert "Do not retry SSH" in out["error"]


async def test_a_blocked_command_never_reaches_the_connection(monkeypatch):
    """The guard runs first — a mutating command must not even try to connect."""
    out = json.loads(await _tool(monkeypatch, PermissionError(13, "denied"))
                     .run({"command": "rm -rf /"}))
    assert out["blocked"] is True and "sshUnavailable" not in out


def test_hint_is_raised_as_SshUnavailable_not_a_bare_oserror():
    assert issubclass(SshUnavailable, RuntimeError)
