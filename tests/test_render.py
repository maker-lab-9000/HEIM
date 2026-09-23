"""Tests for report salvage/rendering (port of n8n Render Report v2) and
the Telegram chunker."""
from heim.channels.telegram import chunk_text
from heim.reports.render import daily_email, extract_sections, investigation_email, salvage

GOOD = """## Summary

PhotoPrism is leaking memory.

## Investigation steps

| # | Command | Result |
|---|---|---|
| 1 | free -m | 7 GiB used |

## Root cause

Confidence: High — unbounded indexing job.

## Recommended remediation

1. Set a memory limit.
2. Restart the container.
"""


def test_salvage_clean_report_passes():
    r = salvage(GOOD, "findings")
    assert not r.incomplete
    assert r.report_md.startswith("## Summary")


def test_salvage_trims_preamble():
    r = salvage("All the data is in hand. Let me write the report.\n\n" + GOOD, "findings")
    assert not r.incomplete
    assert r.report_md.startswith("## Summary")
    assert "data is in hand" not in r.report_md


def test_salvage_empty_output_incomplete():
    r = salvage("", "1. [warning] mem — climbing")
    assert r.incomplete
    assert "transient model/API error" in r.report_md
    assert "1. [warning] mem — climbing" in r.report_md


def test_salvage_leaked_tool_call_incomplete():
    leaked = 'Calling Run_diagnostic">\n<parameter name="command">free -m</parameter>\n</invoke>'
    r = salvage(leaked, "f")
    assert r.incomplete
    assert "plain text instead of a structured" in r.report_md
    assert "Raw agent output" in r.report_md
    assert "free -m" in r.report_md


def test_salvage_no_summary_incomplete_with_raw():
    r = salvage("I looked around but found nothing conclusive.", "f")
    assert r.incomplete
    assert "no '## Summary' section" in r.report_md
    assert "found nothing conclusive" in r.report_md


def test_extract_sections():
    s = extract_sections(GOOD)
    assert "PhotoPrism" in s["summary"]
    assert s["confidence"] == "high"
    assert s["remediation"][0].startswith("Set a memory limit")
    assert len(s["remediation"]) == 2


def test_investigation_email_renders():
    rep = salvage(GOOD, "f")
    subject, html = investigation_email(host="ubuntu-server", report=rep,
                                        generated_at="2026-09-16T07:00:00", n_steps=9,
                                        input_tokens=120000, output_tokens=4000)
    assert "ubuntu-server" in subject and "🔍" in subject
    assert "PhotoPrism" in html and "complete" in html and "120,000" in html


def test_daily_email_renders():
    analysis = {
        "overallHealth": "warning", "headline": "Memory climbing on ubuntu-server",
        "executiveSummary": "Steady 3-day climb.",
        "categories": {"Memory": {"status": "warn", "insight": "Used% rising."}},
        "findings": [{"severity": "warning", "host": "ubuntu-server", "metric": "Memory used",
                      "summary": "Mem 31→43%", "detail": "d", "recommendation": "r"}],
        "watchlist": ["swap"],
    }
    payload = {"overall": "warning", "hosts": ["ubuntu-server"], "counts": {"naQueries": 0},
               "topAlerts": [{"sev": "warn", "host": "ubuntu-server", "label": "Memory used",
                              "name": "", "current": 43.2, "unit": "%", "changePct": 39.5}]}
    summary = {"counts": {"new": 1, "ongoing": 0, "resolved": 0, "open": 1},
               "new": [{"host": "ubuntu-server", "metric": "Memory used", "severity": "warning"}],
               "resolved": []}
    subject, html = daily_email(analysis=analysis, payload=payload, incident_summary=summary,
                                generated_at="2026-09-16T07:00:00")
    assert subject.startswith("Homelab Health Report — 2026-09-16 — WARNING")
    assert "Memory climbing" in html          # headline
    assert "🆕" in html and "1 new" in html   # incident band
    assert "Category status" in html          # dashboard sections present


def test_chunk_text_short_single():
    assert chunk_text("hello") == ["hello"]


def test_chunk_text_splits_on_newlines():
    text = "\n".join(f"line {i} " + "x" * 80 for i in range(200))
    parts = chunk_text(text, limit=3900)
    assert len(parts) > 1
    assert all(len(p) <= 3900 for p in parts)
    assert "".join(p.replace("\n", "") for p in parts).count("line 199") == 1


def test_chunk_text_hard_cut_long_line():
    parts = chunk_text("y" * 9000, limit=3900)
    assert len(parts) == 3
    assert all(len(p) <= 3900 for p in parts)


# ------------------------------------------- new stop reasons (Sonnet 5 / Opus 5.5)
#
# Both models think by default, and the thinking counts toward max_tokens; both
# run safety classifiers that answer a declined request with HTTP 200 and
# stop_reason "refusal". Either way the agent returns no report — and the old
# message blamed "a transient model/API error", which sends the operator to
# re-run something that will fail the same way.


def test_salvage_names_a_refusal():
    r = salvage("", "1. [warning] mem", stop_reason="refusal")
    assert r.incomplete
    assert "declined" in r.reason and "safety" in r.reason
    assert "transient" not in r.reason            # not the generic blame
    assert "declined" in r.report_md               # and the report says so too


def test_salvage_names_running_out_of_tokens():
    r = salvage("", "1. [warning] mem", stop_reason="max_tokens")
    assert r.incomplete
    assert "max_tokens" in r.reason
    assert "thinking" in r.reason                  # the likely culprit on these models
    assert "transient" not in r.reason


def test_salvage_truncated_mid_report_is_still_named():
    """Cut off after some text but before '## Summary' — say why, keep the raw."""
    r = salvage("Checking memory first", "f", stop_reason="max_tokens")
    assert r.incomplete and "max_tokens" in r.reason
    assert "Checking memory first" in r.report_md  # raw output preserved


def test_salvage_ignores_stop_reason_when_the_report_is_there():
    """A report that made it wins, whatever the stop reason says."""
    r = salvage(GOOD, "f", stop_reason="max_tokens")
    assert not r.incomplete


def test_salvage_default_stop_reason_is_unchanged():
    """Callers that pass nothing get exactly the old wording."""
    assert "transient" in salvage("", "f").reason
