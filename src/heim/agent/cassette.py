"""Replay cassettes: a stored transcript served back as tool results (§5.6).

The eval/replay harness answers one question — *would model X have reached the
same root cause on the same evidence?* — so the replayed agent must see the
ORIGINAL tool output, not fresh output from a host whose disk has since been
cleaned up. A ``Cassette`` is the ordered list of ``(tool, args, result)``
triples extracted from ``investigations.transcript_json``; a ``CassetteTool``
is a ``Tool`` that answers out of it instead of touching SSH/Prometheus/HA.

Matching is deliberately forgiving, in three tiers:

1. **exact** — same tool *and* the same arguments (canonical JSON), among the
   entries not yet served. The interesting case: a different model that runs
   the same commands gets byte-identical evidence.
2. **fuzzy** — the oldest unused entry for the same tool. A model that phrases
   ``df -h`` as ``df -hT`` still gets the filesystem table the original saw.
   This is the honest compromise of offline replay: it is *plausible* evidence,
   not the answer to the question actually asked, so it is counted separately
   and reported.
3. **miss** — nothing recorded for that tool any more: a clearly marked stub
   telling the model to reason from what it already has. Never a fabricated
   result — an invented ``df`` output would corrupt the very comparison the
   replay exists to make.

Every entry is served **once**, so a model looping on one command cannot mine
the same recording repeatedly and out-evidence the original.

Coupling note: ``from_transcript`` parses the §5.6 serialization written by
``agent.runner`` (``_transcript_blocks`` + the tool_result turn), which carries
no ``tool_use_id`` — results are therefore paired **positionally** with the
tool_use blocks of the preceding assistant turn. Changing that format means
changing this parser; ``tests/test_replay.py`` builds its fixtures by running
the real ``run_agent``, so the two cannot drift silently.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from heim.config import Config, ToolCfg
from heim.tools.base import Tool, ToolContext

log = logging.getLogger(__name__)

#: Served when the cassette has nothing left for a tool. JSON, and explicitly
#: labelled as a replay artifact, so the model cannot mistake it for evidence.
MISS_RESULT = ('{"replay": "no recorded result for this call — reason from the '
               'evidence you already have"}')


def canonical(args: dict | None) -> str:
    """Stable text form of a tool's arguments, for equality only."""
    try:
        return json.dumps(args or {}, sort_keys=True, ensure_ascii=False, default=str)
    except Exception:  # pragma: no cover - default=str makes this near-impossible
        return str(args)


@dataclass
class CassetteEntry:
    tool: str
    args: dict
    result: str
    used: bool = False

    @property
    def key(self) -> str:
        return canonical(self.args)


@dataclass
class Cassette:
    entries: list[CassetteEntry] = field(default_factory=list)
    exact: int = 0
    fuzzy: int = 0
    missed: int = 0

    # ------------------------------------------------------------- building

    @classmethod
    def from_transcript(cls, transcript: list[dict] | None) -> "Cassette":
        """Extract the ordered (tool, args, result) triples from a transcript.

        Tolerant by design: the stored transcript may have been front-truncated
        at 512 KB (orphan tool_result turns, a leading ``role: system`` marker)
        and a crashed run may end on a tool_use with no result. Anything that
        cannot be paired is skipped rather than raising — a slightly shorter
        cassette is a usable replay; an exception is not.
        """
        entries: list[CassetteEntry] = []
        pending: list[dict] = []          # tool_use blocks awaiting their results
        for turn in transcript or []:
            if not isinstance(turn, dict):
                continue
            blocks = turn.get("content")
            if not isinstance(blocks, list):
                continue
            uses = [b for b in blocks
                    if isinstance(b, dict) and b.get("type") == "tool_use"]
            results = [b for b in blocks
                       if isinstance(b, dict) and b.get("type") == "tool_result"]
            if uses:
                # a new assistant turn supersedes any unanswered calls
                pending = uses
                continue
            if not results:
                continue
            for use, res in zip(pending, results):
                entries.append(CassetteEntry(
                    tool=str(use.get("name") or ""),
                    args=dict(use.get("input") or {}),
                    result=str(res.get("content") if res.get("content") is not None else ""),
                ))
            pending = []
        return cls(entries=[e for e in entries if e.tool])

    # -------------------------------------------------------------- serving

    @property
    def tools(self) -> list[str]:
        """Distinct tool names, in first-recorded order."""
        seen: list[str] = []
        for e in self.entries:
            if e.tool not in seen:
                seen.append(e.tool)
        return seen

    def take(self, tool: str, args: dict | None) -> tuple[str, str]:
        """Serve one call: ``(result, kind)`` with kind exact|fuzzy|miss."""
        key = canonical(args)
        for entry in self.entries:
            if not entry.used and entry.tool == tool and entry.key == key:
                entry.used = True
                self.exact += 1
                return entry.result, "exact"
        for entry in self.entries:
            if not entry.used and entry.tool == tool:
                entry.used = True
                self.fuzzy += 1
                log.debug("cassette: fuzzy match for %s(%s)", tool, key[:120])
                return entry.result, "fuzzy"
        self.missed += 1
        return MISS_RESULT, "miss"

    def stats(self) -> dict:
        """Match accounting for the replay summary and the CLI comparison."""
        return {
            "recorded": len(self.entries),
            "exact": self.exact,
            "fuzzy": self.fuzzy,
            "missed": self.missed,
            "unused": sum(1 for e in self.entries if not e.used),
        }


class CassetteTool(Tool):
    """A ``Tool`` that answers from a cassette. No I/O, ever.

    It carries the *real* tool's ``ToolCfg``, so the replayed model is handed
    byte-identical tool definitions (name, description, input schema) — a
    difference in the conclusion then cannot be blamed on a different toolbox.
    """

    def __init__(self, cfg: ToolCfg, ctx: ToolContext, cassette: Cassette):
        super().__init__(cfg, ctx)
        self.cassette = cassette

    async def run(self, args: dict) -> str:
        result, kind = self.cassette.take(self.name, args)
        self.ctx.record({"tool": self.name, "args": args, "replay": kind})
        return result


#: Placeholder definition for a cassette tool that no longer exists in config
#: (renamed, or removed since the original ran). Replaying it is still better
#: than dropping the evidence, but the model is told what it is looking at.
def _synthetic_cfg(name: str) -> ToolCfg:
    return ToolCfg(
        name=name,
        module="heim.agent.cassette:CassetteTool",
        description=(f"Replay-only tool '{name}'. It is not in the current tool "
                     "configuration; results come from the recorded investigation."),
        args={}, required=[],
    )


def cassette_tools(cassette: Cassette, config: Config, ctx: ToolContext) -> list[CassetteTool]:
    """One ``CassetteTool`` per distinct tool in the cassette.

    Definitions come from ``config.tools`` — the YAML registry — so no live
    tool class is ever imported or instantiated: a replay cannot open an SSH
    connection even by accident.
    """
    tools: list[CassetteTool] = []
    for name in cassette.tools:
        cfg = config.tools.get(name)
        if cfg is None:
            log.warning("cassette tool %r is not in config/tools/ — replaying with a "
                        "synthetic definition", name)
            cfg = _synthetic_cfg(name)
        tools.append(CassetteTool(cfg, ctx, cassette))
    return tools
