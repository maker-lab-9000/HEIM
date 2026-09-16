"""Agent-tool framework.

A tool = a YAML file under ``config/tools/`` (LLM-facing description + JSON-schema
args + options) bound to a Python class via its ``module`` field
(``heim.tools.ssh_diagnostic:SshDiagnosticTool``). Adding a tool to an agent is:
write the YAML, write the class, list the name in the agent's YAML.

Every tool call is streamed to the Telegram live feed and appended to the local
audit log (replaces the n8n per-tool "Notify Telegram" + session.log nodes).
"""
from __future__ import annotations

import importlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from heim.config import Config, ToolCfg

log = logging.getLogger(__name__)


@dataclass
class ToolContext:
    config: Config
    tag: str = ""                                               # e.g. "ubuntu-server|mem_used"
    feed: Callable[[str], Awaitable[None]] | None = None        # live Telegram feed
    audit: Callable[[dict], None] | None = None                 # audit-log writer

    async def emit(self, text: str) -> None:
        if self.feed is None:
            return
        try:
            await self.feed(f"[{self.tag}] {text}" if self.tag else text)
        except Exception:  # the feed must never sink a tool call
            log.exception("live feed emit failed")

    def record(self, entry: dict) -> None:
        if self.audit is None:
            return
        try:
            self.audit({"ts": time.time(), "tag": self.tag, **entry})
        except Exception:
            log.exception("audit write failed")


class Tool:
    def __init__(self, cfg: ToolCfg, ctx: ToolContext):
        self.cfg = cfg
        self.ctx = ctx

    @property
    def name(self) -> str:
        return self.cfg.name

    def anthropic_schema(self) -> dict:
        return {
            "name": self.cfg.name,
            "description": self.cfg.description,
            "input_schema": self.cfg.input_schema(),
        }

    async def run(self, args: dict) -> str:
        raise NotImplementedError

    async def close(self) -> None:  # override for tools holding connections
        return

    async def __call__(self, args: dict) -> str:
        try:
            return await self.run(dict(args or {}))
        except Exception as exc:  # tool errors go back to the model, not up the stack
            log.exception("tool %s failed", self.name)
            self.ctx.record({"tool": self.name, "args": args, "error": str(exc)})
            return json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


def clip(text: str | None, limit: int) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n… [truncated at {limit} bytes]"


def load_tools(names: list[str], config: Config, ctx: ToolContext) -> list[Tool]:
    tools: list[Tool] = []
    for name in names:
        cfg = config.tools.get(name)
        if cfg is None:
            raise KeyError(f"tool '{name}' not found in config/tools/")
        mod_name, _, cls_name = cfg.module.partition(":")
        cls = getattr(importlib.import_module(mod_name), cls_name)
        tools.append(cls(cfg, ctx))
    return tools
