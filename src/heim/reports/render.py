"""Report rendering: markdown → styled HTML email, plus the output-salvage
logic ported from n8n PAM 20 'Render Report' (v2, 2026-08-21).

Salvage rules:
- if a '## Summary' heading exists anywhere, everything before it is trimmed
  and the report is complete;
- otherwise the run is INCOMPLETE with a per-cause reason (empty output /
  leaked tool-call text / malformed) and the raw output is preserved in a
  '## Raw agent output (untrusted)' block.

Also here: ``extract_sections`` (the Loki/dashboard section parser) and
``extract_tool_feedback``, which reads the optional '## Tooling feedback'
section — the agent's own notes on what would have made a tool more useful.
That section stays IN the report (email and Telegram show it too); the
pipelines merely also persist it.
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


#: A feedback line is ``tool_name: suggestion``. The name is matched loosely
#: (an identifier, optionally in backticks/bold) and validated by the caller,
#: not here — an unknown name is data about the prompt drifting, and silently
#: dropping it would hide that.
_FEEDBACK_RE = re.compile(r"^[`*_\s]*([A-Za-z][A-Za-z0-9_.-]*)[`*_\s]*:\s*(.+)$")

#: Cap on what one run may say. The prompt asks for 0–3 lines; a model that
#: ignores that must not be able to fill the card with essays.
MAX_TOOL_FEEDBACK = 3
MAX_SUGGESTION_CHARS = 300


def extract_tool_feedback(report_md: str) -> list[tuple[str, str]]:
    """``## Tooling feedback`` → ``[(tool, suggestion), …]`` (possibly empty).

    The section is optional (the agent adds it only when it has something
    concrete), so an absent section, an empty one, or prose that is not
    ``name: text`` all yield nothing rather than an error. Bullets and
    numbering are stripped the way ``extract_sections`` strips them, and the
    tool name is returned **as written** — resolving it against the configured
    toolbox is the caller's job.
    """
    body = _section(report_md or "", "Tooling feedback")
    out: list[tuple[str, str]] = []
    for line in body.split("\n"):
        t = line.strip()
        while t and t[0] in "-*•().0123456789. ":
            t = t[1:]
        m = _FEEDBACK_RE.match(t.strip())
        if not m:
            continue
        tool = m.group(1).strip()
        suggestion = m.group(2).strip().strip("`*_ ")
        if not tool or not suggestion:
            continue
        out.append((tool, suggestion[:MAX_SUGGESTION_CHARS]))
        if len(out) >= MAX_TOOL_FEEDBACK:
            break
    return out


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


def daily_email(
    *,
    analysis: dict | None,
    payload: dict,
    incident_summary: dict | None,
    generated_at: str,
) -> tuple[str, str]:
    """The daily report email — faithful port of the n8n dashboard
    (see heim.reports.daily_dashboard for the builder)."""
    from heim.reports.daily_dashboard import build_daily_email

    return build_daily_email(analysis, payload, incident_summary, generated_at)
