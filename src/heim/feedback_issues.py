"""Tooling feedback → GitHub issues: the pure part (spec 2026-11-08).

Agents' ``tool: suggestion`` lines become comments on ONE open GitHub issue
per target — a tool name, ``security_audit`` (the audit's own feedback) or
``general`` (a name that matches no tool). The pipelines queue rows in
``feedback_outbox``; the daemon posts them (``pipelines/feedback_issues``).
Everything that leaves passes :func:`scrub` first, so a LAN address or a
``.env`` identity value never reaches GitHub.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Mapping

LABEL = "heim-feedback"
REDACTED = "‹redacted›"
#: an outbox row stops retrying after this many failed posts
MAX_ATTEMPTS = 10
#: rows posted per poll cycle
DRAIN_BATCH = 5
#: shorter identity values would redact ordinary words
_MIN_SECRET = 4

_COVERED = re.compile(r"^(already\s+)?covered by #\d+\.?$", re.I)
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
#: two or more colons with at least one hex letter or a '::' — never a clock time
_IPV6 = re.compile(r"(?<![\w:])(?=[0-9a-f:]*(?:::|[a-f]))[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![\w:])",
                   re.I)
_ENV_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=")


def target_for(tool: str, known: Iterable[str]) -> str:
    return tool if tool in set(known) else "general"


def is_covered_only(suggestion: str) -> bool:
    """``covered by #N`` and nothing else: stored, never posted (no "+1" comments)."""
    return bool(_COVERED.match((suggestion or "").strip()))


def identity_values(env_example: Path, environ: Mapping[str, str]) -> list[str]:
    """The current values of every variable ``.env.example`` names, longest first."""
    try:
        names = [m.group(1) for line in Path(env_example).read_text().splitlines()
                 if (m := _ENV_LINE.match(line))]
    except OSError:
        return []
    vals = {str(environ.get(n) or "").strip() for n in names}
    return sorted((v for v in vals if len(v) >= _MIN_SECRET), key=lambda v: (-len(v), v))


def scrub(text: str, secrets: list[str]) -> str:
    out = str(text or "")
    for s in sorted(secrets, key=len, reverse=True):
        if s:
            out = out.replace(s, REDACTED)
    out = _IPV4.sub(REDACTED, out)
    return _IPV6.sub(REDACTED, out)


def issue_title(target: str) -> str:
    return f"Tooling feedback: {target}"


def issue_labels(target: str) -> list[str]:
    return [LABEL, f"tool:{target}"]


def comment_body(suggestion: str, source: str) -> str:
    return f"{suggestion}\n\n_source: {source}_"
