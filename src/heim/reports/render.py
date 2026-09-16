"""Report rendering: markdown → styled HTML email, plus the output-salvage
logic ported from n8n PAM 20 'Render Report' (v2, 2026-08-21).

Salvage rules:
- if a '## Summary' heading exists anywhere, everything before it is trimmed
  and the report is complete;
- otherwise the run is INCOMPLETE with a per-cause reason (empty output /
  leaked tool-call text / malformed) and the raw output is preserved in a
  '## Raw agent output (untrusted)' block.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import markdown as md_lib
from jinja2 import Environment, PackageLoader, select_autoescape

_env = Environment(
    loader=PackageLoader("heim.reports", "templates"),
    autoescape=select_autoescape(enabled_extensions=()),
)

_SUMMARY_RE = re.compile(r"^##\s+Summary\b", re.M)
_LEAK_RE = re.compile(r"<parameter name=|</invoke>|<invoke |^Calling \S+", re.M)


@dataclass
class InvestigationReport:
    report_md: str
    incomplete: bool
    reason: str | None = None
    raw: str = ""


def salvage(agent_output: str, findings_text: str) -> InvestigationReport:
    """Port of the hardened Render Report incomplete/salvage block."""
    md = (agent_output or "").strip()
    m = _SUMMARY_RE.search(md)
    if m:
        return InvestigationReport(report_md=md[m.start():], incomplete=False)

    raw = md
    if not raw:
        reason = ("the agent returned no conclusion — most often a transient model/API error, "
                  "or (less often) the step budget")
    elif _LEAK_RE.search(raw):
        reason = ("the model emitted its next tool call as plain text instead of a structured "
                  "call, so the agent stopped without writing a report")
    else:
        reason = "the agent's final message contained no '## Summary' section, so it is treated as malformed"

    body = (
        "## Summary\n\nThe automated investigation did **not complete** — " + reason +
        ". No trusted root-cause analysis is available for this run.\n\n"
        "## Findings that triggered this investigation\n\n" + (findings_text or "(findings unavailable)") +
        "\n\n## Recommended next step\n\nRe-run the investigation, or investigate the host manually. "
        "If this recurs, raise the agent step budget or narrow the scope of the finding."
    )
    if raw:
        body += "\n\n## Raw agent output (untrusted)\n\n```\n" + raw[:2000].replace("```", "'''") + "\n```"
    return InvestigationReport(report_md=body, incomplete=True, reason=reason, raw=raw)


# ------------------------------------------------------------- section parsing
# Port of n8n 'Investigation To Loki' section()/confidence() helpers.

def _section(md: str, name: str) -> str:
    lower = md.lower()
    marker = "## " + name.lower()
    idx = lower.find(marker)
    if idx < 0:
        return ""
    rest = md[idx + len(marker):]
    nxt = rest.find("\n## ")
    return (rest if nxt < 0 else rest[:nxt]).strip()


def _confidence(md: str) -> str:
    lower = md.lower()
    i = lower.find("confidence")
    if i < 0:
        return ""
    seg = lower[i:i + 40]
    for level in ("high", "medium", "low"):
        if level in seg:
            return level
    return ""


def extract_sections(report_md: str) -> dict:
    rem = _section(report_md, "Recommended remediation")
    actions = []
    for line in rem.split("\n"):
        t = line.strip()
        while t and t[0] in "-*•().0123456789. ":
            t = t[1:]
        t = t.strip()
        if t:
            actions.append(t)
    summary = _section(report_md, "Summary")
    return {
        "summary": summary,
        "root_cause": _section(report_md, "Root cause") or summary,
        "remediation": actions[:8],
        "confidence": _confidence(report_md),
    }


# ---------------------------------------------------------------- html emails

def _md_to_html(md: str) -> str:
    return md_lib.markdown(md, extensions=["tables", "fenced_code", "sane_lists"])


def investigation_email(
    *,
    host: str,
    report: InvestigationReport,
    generated_at: str,
    n_steps: int,
    input_tokens: int,
    output_tokens: int,
) -> tuple[str, str]:
    subject = (
        ("⚠️ Investigation (incomplete) — " if report.incomplete else "🔍 Investigation Report — ")
        + host + " — " + generated_at[:10]
    )
    html = _env.get_template("investigation.html.j2").render(
        host=host,
        generated_at=generated_at.replace("T", " ")[:16],
        incomplete=report.incomplete,
        body=_md_to_html(report.report_md),
        n_steps=n_steps,
        input_tokens=f"{input_tokens:,}",
        output_tokens=f"{output_tokens:,}",
    )
    return subject, html


_STATUS_COLOR = {"healthy": "#16a34a", "warning": "#d97706", "critical": "#dc2626"}
_FLAG_ICON = {"ok": "✅", "warn": "⚠️", "crit": "🔴", "na": "ℹ️"}


def daily_email(
    *,
    analysis: dict,
    payload: dict,
    incident_summary: dict | None,
    generated_at: str,
) -> tuple[str, str]:
    overall = str(analysis.get("overallHealth") or payload.get("overall") or "healthy").lower()
    subject = f"🩺 Homelab Health Report — {overall.upper()} — {generated_at[:10]}"
    inc = incident_summary or {}
    counts = inc.get("counts") or {}
    html = _env.get_template("daily.html.j2").render(
        overall=overall,
        overall_color=_STATUS_COLOR.get(overall, "#64748b"),
        headline=analysis.get("headline", ""),
        executive=analysis.get("executiveSummary", ""),
        categories=analysis.get("categories", {}) or {},
        findings=analysis.get("findings", []) or [],
        watchlist=analysis.get("watchlist", []) or [],
        top_alerts=(payload.get("topAlerts") or [])[:10],
        flag_icon=_FLAG_ICON,
        incidents_new=inc.get("new", []) or [],
        incidents_resolved=inc.get("resolved", []) or [],
        counts={"new": counts.get("new", 0), "ongoing": counts.get("ongoing", 0),
                "resolved": counts.get("resolved", 0), "open": counts.get("open", 0)},
        generated_at=generated_at.replace("T", " ")[:16],
        hosts=payload.get("hosts", []),
        na_queries=(payload.get("counts") or {}).get("naQueries", 0),
    )
    return subject, html
