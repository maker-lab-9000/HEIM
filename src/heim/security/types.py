"""Data types shared by the security-audit modules. Pure."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SEVERITIES = ("critical", "warning", "info")
RESULT_STATUSES = ("ok", "fail", "note", "unavailable")
EVIDENCE_STATUSES = ("ok", "empty", "error", "timeout", "denied", "blocked")

_SUBJECT_BAD = re.compile(r"[^A-Za-z0-9_.:/@=+-]+")
SUBJECT_MAX = 64


def clean_subject(s: object) -> str:
    """Fingerprint-safe subject: fixed charset, ≤ 64 chars, never empty.

    The subject is the third fingerprint segment (``host|check_id|subject``),
    so it must be a stable identifier (a user id, a port/process, a unit
    name) — never a count or a sentence.
    """
    t = _SUBJECT_BAD.sub("_", str(s if s is not None else "").strip()).strip("_")
    return (t or "-")[:SUBJECT_MAX]


@dataclass(frozen=True)
class SourceSpec:
    key: str
    kind: str            # pve | ha | prom | ssh
    target: str          # API path / PromQL / shell line (may contain {vmid} or {container})
    control: str = ""    # sibling source that must be non-empty for an empty result to count
    expand: str = ""     # "" | "vmid" | "container"


@dataclass(frozen=True)
class CheckSpec:
    id: str
    title: str
    severity: str
    sources: tuple[str, ...]
    params: dict = field(default_factory=dict)
    recommendation: str = ""
    compound: bool = False     # evaluated over other checks' results, not evidence


@dataclass
class Evidence:
    key: str
    status: str                 # one of EVIDENCE_STATUSES
    body: object = None         # parsed JSON (API) / text (SSH)
    http_status: int = 0
    exit_code: int | None = None
    stderr: str = ""
    detail: str = ""            # human reason for a non-ok status
    target: str = ""            # what was actually fetched/run

    @property
    def usable(self) -> bool:
        return self.status in ("ok", "empty")


@dataclass
class EvidenceBundle:
    items: dict[str, Evidence] = field(default_factory=dict)
    collected_at: str = ""

    def get(self, key: str) -> Evidence:
        return self.items.get(key) or Evidence(key, "error", detail="not collected")

    def expanded(self, prefix: str) -> dict[str, Evidence]:
        """``prefix[<x>]`` items → ``{x: evidence}`` (per-VM / per-container sources)."""
        out: dict[str, Evidence] = {}
        head = prefix + "["
        for k, e in self.items.items():
            if k.startswith(head) and k.endswith("]"):
                out[k[len(head):-1]] = e
        return out


@dataclass
class CheckResult:
    check_id: str
    host: str
    subject: str
    status: str                 # one of RESULT_STATUSES
    severity: str
    summary: str
    detail: str = ""
    recommendation: str = ""

    @property
    def fingerprint(self) -> str:
        return f"{self.host}|{self.check_id}|{self.subject}"

    @property
    def is_finding(self) -> bool:
        return self.status == "fail" and self.severity in ("critical", "warning")

    def as_finding(self, trend: str) -> dict:
        """The ``findings`` row shape (``store._FINDING_FIELDS`` + fingerprint)."""
        return {
            "host": self.host, "metric": self.check_id, "severity": self.severity,
            "trend": trend, "summary": self.summary, "detail": self.detail,
            "recommendation": self.recommendation, "fingerprint": self.fingerprint,
            "subject": self.subject,
        }
