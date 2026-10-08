"""Week-over-week diff of audit findings. Pure.

Fingerprints (host|check_id|subject) are the join key, so a finding whose
wording changed is still the same finding. A check that could not run this
week neither confirms nor resolves anything: its previous findings are
CARRIED (kept, marked unverified) rather than silently resolved.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from heim.security.types import CheckResult


@dataclass
class AuditDiff:
    new: list[CheckResult] = field(default_factory=list)
    persisting: list[CheckResult] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)     # previous finding rows no longer present
    carried: list[dict] = field(default_factory=list)      # previous rows whose check was unavailable

    @property
    def current(self) -> list[CheckResult]:
        return self.new + self.persisting


def diff_findings(current: list[CheckResult], previous: list[dict],
                  unavailable_check_ids: set[str]) -> AuditDiff:
    prev_by_fp = {str(p.get("fingerprint") or ""): p for p in previous if p.get("fingerprint")}
    cur_fps = {r.fingerprint for r in current}
    d = AuditDiff()
    for r in current:
        (d.persisting if r.fingerprint in prev_by_fp else d.new).append(r)
    for fp, p in prev_by_fp.items():
        if fp in cur_fps:
            continue
        if str(p.get("metric") or "") in unavailable_check_ids:
            d.carried.append(dict(p))
        else:
            d.resolved.append(dict(p))
    return d


def finding_rows(diff: AuditDiff) -> list[dict]:
    """The rows to persist for this run (``store.insert_findings`` shape)."""
    rows = [r.as_finding("new") for r in diff.new] + [r.as_finding("persisting") for r in diff.persisting]
    for p in diff.carried:
        row = {k: str(p.get(k) or "") for k in ("host", "metric", "severity", "summary", "recommendation", "fingerprint")}
        row["trend"] = "carried"
        row["detail"] = f"not re-verified this run (source unavailable). Last detail: {str(p.get('detail') or '')[:400]}"
        row["subject"] = row["fingerprint"].split("|")[-1]
        rows.append(row)
    return rows
