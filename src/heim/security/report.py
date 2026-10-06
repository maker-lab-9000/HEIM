"""The deterministic audit report and its derivatives (digest, HA sensor,
Loki events, brief sections for the model). Pure.

The report is complete without any model output: it starts with '## Summary'
(the same contract reports/render.salvage enforces), so a declined or failed
assessment costs the owner one appendix, not the audit.
"""
from __future__ import annotations

import re

from heim.security.diff import AuditDiff
from heim.security.types import CheckResult

_RANK = {"critical": 0, "warning": 1, "info": 2}
_LOKI_SEV = {"critical": "crit", "warning": "warn", "info": "info"}
_SEV_SCORE = {"critical": 3, "warning": 2, "info": 1}
TELEGRAM_MAX = 3500
HA_REPORT_MAX = 12000
EXCERPT_MAX = 3000


def _cell(s: object) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def _sorted(rows: list[CheckResult]) -> list[CheckResult]:
    return sorted(rows, key=lambda r: (_RANK.get(r.severity, 9), r.host, r.check_id, r.subject))


def coverage_gaps(results: list[CheckResult]) -> list[str]:
    seen: dict[str, str] = {}
    for r in results:
        if r.status == "unavailable" and r.check_id not in seen:
            seen[r.check_id] = r.detail or r.summary.removeprefix("not verified: ")
    return [f"{cid} — {why}" for cid, why in sorted(seen.items())]


def overall_of(rows: list[dict]) -> str:
    sevs = {str(r.get("severity") or "") for r in rows}
    return "critical" if "critical" in sevs else "warning" if "warning" in sevs else "ok"


def demote_headings(md: str) -> str:
    return re.sub(r"^(#{1,5}) ", r"#\1 ", md or "", flags=re.M)


def render_audit_report(results: list[CheckResult], diff: AuditDiff, *,
                        generated_at: str, weeks: dict[str, int]) -> str:
    findings = _sorted(diff.new) + _sorted(diff.persisting)
    new_fps = {r.fingerprint for r in diff.new}
    crit = sum(1 for r in findings if r.severity == "critical")
    warn = sum(1 for r in findings if r.severity == "warning")
    gaps = coverage_gaps(results)
    notes = _sorted([r for r in results if r.status == "note"])
    passed = sorted({r.check_id for r in results if r.status == "ok"} - {r.check_id for r in results if r.status == "fail"})

    L = ["## Summary", "",
         f"Weekly read-only security audit generated {generated_at}. {len(results)} check rows evaluated; "
         f"**{len(findings)} findings** ({crit} critical, {warn} warning): {len(diff.new)} new, "
         f"{len(diff.persisting)} persisting, {len(diff.resolved)} resolved since the previous audit, "
         f"{len(diff.carried)} carried forward unverified. {len(gaps)} check(s) could not run.", ""]
    if not findings and not diff.carried:
        L += ["No findings. Every check that ran passed.", ""]

    L += ["## Findings", "", "| # | Severity | Host | Check | Subject | Status | Seen | Summary |",
          "|---|---|---|---|---|---|---|---|"]
    n = 0
    for r in findings:
        n += 1
        trend = "new" if r.fingerprint in new_fps else "persisting"
        L.append(f"| {n} | {r.severity} | {r.host} | `{r.check_id}` | {_cell(r.subject)} | {trend} | "
                 f"{weeks.get(r.fingerprint, 1)}w | {_cell(r.summary)} |")
    for p in diff.carried:
        n += 1
        L.append(f"| {n} | {p.get('severity')} | {p.get('host')} | `{p.get('metric')}` | "
                 f"{_cell(str(p.get('fingerprint', '')).split('|')[-1])} | carried | "
                 f"{weeks.get(str(p.get('fingerprint')), 1)}w | {_cell(p.get('summary'))} (not re-verified) |")
    if n == 0:
        L.append("| – | – | – | – | – | – | – | none |")

    L += ["", "## Resolved since the previous audit", ""]
    L += [f"- ✅ `{p.get('metric')}` on {p.get('host')} — {_cell(str(p.get('fingerprint', '')).split('|')[-1])}"
          for p in diff.resolved] or ["- none"]

    L += ["", "## Details and recommendations", ""]
    for r in findings:
        L += [f"### {r.host} · `{r.check_id}` · {_cell(r.subject)}", "", r.summary, ""]
        if r.detail:
            L += ["```", r.detail[:1500], "```", ""]
        if r.recommendation:
            L += [f"**Recommended (human action — this audit is read-only):** {r.recommendation}", ""]
    if not findings:
        L += ["(no findings)", ""]

    L += ["## Notes (informational, not findings)", ""]
    L += [f"- {r.host} · `{r.check_id}` · {_cell(r.summary)}" for r in notes] or ["- none"]

    L += ["", "## Coverage gaps", ""]
    L += [f"- `{g.split(' — ')[0]}` — {g.split(' — ', 1)[1]}" for g in gaps] or ["- none — every check ran"]

    L += ["", "## Passed checks", "", f"{len(passed)} checks passed: " + (", ".join(f"`{c}`" for c in passed) or "none"), ""]
    return "\n".join(L)


def brief_sections(results: list[CheckResult], diff: AuditDiff) -> dict[str, str]:
    """The text blocks the model's brief is rendered from (bounded)."""
    new_fps = {r.fingerprint for r in diff.new}
    table = ["| severity | host | check | subject | status | summary |", "|---|---|---|---|---|---|"]
    for r in _sorted(diff.new) + _sorted(diff.persisting):
        table.append(f"| {r.severity} | {r.host} | {r.check_id} | {_cell(r.subject)} | "
                     f"{'new' if r.fingerprint in new_fps else 'persisting'} | {_cell(r.summary)} |")
    for p in diff.carried:
        table.append(f"| {p.get('severity')} | {p.get('host')} | {p.get('metric')} | "
                     f"{_cell(str(p.get('fingerprint', '')).split('|')[-1])} | carried (unverified) | {_cell(p.get('summary'))} |")
    if len(table) == 2:
        table.append("| – | – | – | – | – | no findings |")
    notes = [f"- {r.host} · {r.check_id} · {_cell(r.summary)}" for r in _sorted([r for r in results if r.status == "note"])] or ["- none"]
    coverage = [f"- {g}" for g in coverage_gaps(results)] or ["- none"]
    resolved = [f"- {p.get('metric')} on {p.get('host')} ({str(p.get('fingerprint', '')).split('|')[-1]})" for p in diff.resolved] or ["- none"]
    excerpts = []
    for r in _sorted(diff.new) + _sorted(diff.persisting):
        if r.detail:
            excerpts.append(f"[{r.check_id} · {r.subject}]\n{r.detail[:600]}")
    ex = "\n\n".join(excerpts)
    return {"table": "\n".join(table), "notes": "\n".join(notes), "coverage": "\n".join(coverage),
            "resolved": "\n".join(resolved), "excerpts": ex[:EXCERPT_MAX] + ("\n…" if len(ex) > EXCERPT_MAX else "") or "(none)"}


def telegram_digest(diff: AuditDiff, results: list[CheckResult], *, generated_at: str,
                    assessment: str, reason: str) -> str:
    cur = diff.current
    crit = sum(1 for r in cur if r.severity == "critical")
    gaps = len(coverage_gaps(results))
    L = [f"🛡️ Weekly security audit — {generated_at[:10]}",
         f"{len(cur)} findings · {crit} critical · {len(diff.new)} new · {len(diff.persisting)} persisting · "
         f"{len(diff.resolved)} resolved · {len(diff.carried)} carried · {gaps} checks unavailable", ""]
    for r in _sorted(diff.new)[:8]:
        L.append(f"🆕 [{r.severity}] {r.host} · {r.check_id} · {r.summary[:120]}")
    if len(diff.new) > 8:
        L.append(f"… +{len(diff.new) - 8} more new")
    for p in diff.resolved[:3]:
        L.append(f"✅ resolved: {p.get('host')} · {p.get('metric')}")
    if assessment == "incomplete":
        L += ["", f"⚠️ AI assessment unavailable — {reason}"]
    elif assessment == "failed":
        L += ["", f"⚠️ AI assessment failed — {reason}"]
    elif assessment == "skipped":
        L += ["", "ℹ️ AI assessment skipped (--no-llm)"]
    L += ["", "Full report by email · dashboard: /investigations?trigger=security_audit"]
    text = "\n".join(L)
    return text if len(text) <= TELEGRAM_MAX else text[:TELEGRAM_MAX - 2] + " …"


def ha_attributes(diff: AuditDiff, results: list[CheckResult], *, generated_at: str,
                  report_md: str) -> tuple[str, dict]:
    cur = diff.current
    state = f"{len(diff.new)} new · {len(diff.persisting)} persisting · {len(diff.resolved)} resolved · {len(diff.carried)} carried"
    attrs = {
        "friendly_name": "PAM Weekly Security Audit", "icon": "mdi:shield-search",
        "findings": len(cur), "new": len(diff.new), "persisting": len(diff.persisting),
        "resolved": len(diff.resolved), "carried": len(diff.carried),
        "critical": sum(1 for r in cur if r.severity == "critical"),
        "warning": sum(1 for r in cur if r.severity == "warning"),
        "unavailable_checks": len(coverage_gaps(results)),
        "updated": generated_at, "report": (report_md or "").strip()[:HA_REPORT_MAX],
    }
    return state, attrs


def finding_events(rows: list[dict]) -> list[dict]:
    """Loki ``finding`` events (existing event type) tagged category=security."""
    out = []
    for r in rows:
        sev = str(r.get("severity") or "info")
        out.append({
            "event": "finding",
            "labels": {"severity": _LOKI_SEV.get(sev, "info"), "host": str(r.get("host") or "all"), "category": "security"},
            "fields": {
                "metric": str(r.get("metric") or ""), "trend": str(r.get("trend") or ""),
                "summary": str(r.get("summary") or "")[:150], "action": str(r.get("recommendation") or "")[:120],
                "detail": str(r.get("detail") or ""), "recommendation": str(r.get("recommendation") or ""),
                "sevScore": _SEV_SCORE.get(sev, 0), "fingerprint": str(r.get("fingerprint") or ""),
                "source": "security_audit",
            },
        })
    return out
