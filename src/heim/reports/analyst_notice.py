"""What the operator is told when the analyst chain falls back or fails.

Pure, and deliberately NOT part of the golden ``daily_dashboard`` renderer
(spec 2026-11-04): the fallback banner is prepended to that renderer's HTML by
the pipeline, and the failure email is its own small message.
"""
from __future__ import annotations

from html import escape

FAILURE_SUBJECT = "HEIM daily report NOT produced — all analyst models failed"

_BOX = ("font-family:system-ui,sans-serif;font-size:14px;line-height:1.45;"
        "border:1px solid #c98a00;background:#fff6e0;color:#3a2a00;"
        "padding:10px 14px;margin:0 0 12px;border-radius:4px")


def _failures(attempts) -> list:
    return [a for a in attempts if not a.ok]


def fallback_subject(subject: str, model_label: str) -> str:
    return f"{subject} [fallback: {model_label}]"


def fallback_banner_html(model_used: str, attempts) -> str:
    failed = "; ".join(f"{escape(a.provider)} {escape(a.model)} — {escape(a.error)}"
                       for a in _failures(attempts))
    return (f'<div style="{_BOX}"><strong>Answered by fallback model '
            f'{escape(model_used)}.</strong> Failed first: {failed}</div>')


def failure_email(attempts, run_at: str) -> tuple[str, str]:
    rows = "".join(
        f"<li><strong>{escape(a.provider)} {escape(a.model)}</strong> — {escape(a.error)}</li>"
        for a in attempts)
    html = (f'<div style="{_BOX}">'
            f"<p><strong>The daily report was not produced:</strong> every analyst model "
            f"failed (run at {escape(run_at)}).</p>"
            f"<ol>{rows}</ol>"
            f"<p>Metrics were collected; the next scheduled run will retry.</p></div>")
    return FAILURE_SUBJECT, html


def fallback_telegram(model_used: str, attempts) -> str:
    failed = "; ".join(f"{a.provider} {a.model} failed ({a.error})" for a in _failures(attempts))
    return f"⚠️ HEIM daily: {failed}; report by {model_used}"
