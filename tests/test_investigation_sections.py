"""The investigation page sorted by kind (spec: "AI output is labelled by
kind"): the transcript is the observations, the report's Summary / Root cause
/ Confidence the interpretation, its remediation the proposed actions, and the
operator's approval, outcome and mute the completed actions. The agent is
read-only, so it takes none.

`report_sections` is pure and drops nothing: every heading and the preamble
land in exactly one bucket, and the full text rides along as `raw` for the
folded full report.
"""
import json
import re

from test_overview_console import _client, _iso

from heim.dashboard import format as fmt
from heim.reports.render import salvage

KINDS = ("interpretation", "proposed", "other")
NO_ACTIONS = "No actions taken. The agent is read-only; decisions are yours."

REPORT = """\
A preamble the salvage would normally trim.

## Summary

Drive **sdb** runs warm under rebuild load.

### Detail

Only during the weekly scrub.

## Evidence

- `smartctl -a /dev/disk/by-id/raid1-a`: 48 C peak.

## Root cause (confidence: high)

Fan curve too flat.

## Remediation

1. Raise the fan curve to 40 % at 45 C.

## recommended next step

Re-check after the next scrub.

## Next steps

Watch the trend for a week.

## CONFIDENCE

High: the peaks line up with the scrub.

## Tooling feedback

ssh_diagnostic: allow smartctl -x.

## Something new

```
## Not a heading, it sits inside a fence
```
"""


def _headings(sections, kind):
    return [h for h, _ in sections[kind]]


def _section(html, key, nxt):
    """One kind panel of the detail page, sliced on its heading ids."""
    return html[html.index(f'id="h-{key}"'):html.index(f'id="h-{nxt}"')]


def test_report_sections_sorts_headings_and_drops_nothing():
    s = fmt.report_sections(REPORT)
    assert s["raw"] == REPORT
    # case-insensitive, matched on the heading's start, in document order
    assert _headings(s, "interpretation") == [
        "Summary", "Root cause (confidence: high)", "CONFIDENCE"]
    assert _headings(s, "proposed") == ["Remediation", "recommended next step", "Next steps"]
    # the preamble is "other" under an empty heading, like Evidence and feedback
    assert _headings(s, "other") == ["", "Evidence", "Tooling feedback", "Something new"]
    # a ### sub-heading belongs to the section above it
    summary = dict(s["interpretation"])["Summary"]
    assert summary.startswith("Drive **sdb**") and "### Detail" in summary
    assert summary.endswith("Only during the weekly scrub.")
    # a ## line inside a code fence is body text, not a section
    assert "## Not a heading, it sits inside a fence" in dict(s["other"])["Something new"]
    # nothing is dropped: every non-blank line of the report lands exactly once
    placed = []
    for kind in KINDS:
        for heading, body in s[kind]:
            placed += [f"## {heading}"] if heading else []
            placed += [line for line in body.splitlines() if line.strip()]
    assert sorted(placed) == sorted(line for line in REPORT.splitlines() if line.strip())

    empty = fmt.report_sections("")
    assert empty == {"interpretation": [], "proposed": [], "other": [], "raw": ""}
    assert fmt.report_sections(None)["raw"] == ""


def test_incomplete_report_keeps_raw_text(tmp_path, monkeypatch):
    # a malformed final message: no '## Summary', but a '## Root cause' line of
    # its own. Salvage fences it as untrusted raw output; that fence must not be
    # split, or the untrusted text would be promoted to the interpretation.
    output = "Let me check the fans.\n## Root cause\nprobably the fan curve, unverified"
    report = salvage(output, "1. [warning] Drive temperature high").report_md
    s = fmt.report_sections(report)
    assert s["raw"] == report
    assert _headings(s, "interpretation") == ["Summary"]
    assert _headings(s, "proposed") == ["Recommended next step"]
    assert _headings(s, "other") == ["Findings that triggered this investigation",
                                     "Raw agent output (untrusted)"]
    raw = dict(s["other"])["Raw agent output (untrusted)"]
    assert "## Root cause" in raw and "probably the fan curve, unverified" in raw

    # a stored report with no headings at all is all preamble, kept whole
    bare = fmt.report_sections("The agent ran out of budget mid-sentence and")
    assert bare["other"] == [("", "The agent ran out of budget mid-sentence and")]
    assert bare["interpretation"] == [] and bare["proposed"] == []

    def seed(s):
        s.create_investigation(host="homelab", status="incomplete", started_at=_iso(30),
                               finished_at=_iso(28), report_md=report,
                               incomplete_reason="malformed")
        s.create_investigation(host="homelab", status="incomplete", started_at=_iso(20),
                               finished_at=_iso(18),
                               report_md="The agent ran out of budget mid-sentence and")

    client = _client(tmp_path, monkeypatch, seed)
    html = client.get("/investigations/1").text
    interp = _section(html, "interpretation", "proposed")
    assert "did <strong>not complete</strong>" in interp
    assert "probably the fan curve" not in interp
    assert "Re-run the investigation" in _section(html, "proposed", "completed")
    # the raw text survives, in the folded full report
    full = html[html.index('<h2 class="eyebrow">report</h2>'):]
    assert "<details" in full and "probably the fan curve, unverified" in full

    bare_page = client.get("/investigations/2").text
    assert "The agent ran out of budget mid-sentence and" in bare_page[
        bare_page.index('<h2 class="eyebrow">report</h2>'):]
    assert "The report has no summary, root cause or confidence section." in _section(
        bare_page, "interpretation", "proposed")


def test_investigation_page_labels_observations_interpretation_proposed_completed(
        tmp_path, monkeypatch):
    fp = "homelab|drive_temp|Drive temperature high"

    def seed(s):
        iid = s.create_investigation(
            fingerprint=fp, host="homelab", host_role="hypervisor", agent_name="investigator",
            model="claude-sonnet-4-6", trigger="daily", status="resolved",
            started_at=_iso(180), finished_at=_iso(176), input_tokens=96_000,
            output_tokens=3_100, n_steps=1, outcome="resolved", approval_decision="approve",
            brief_md="Investigate the drive temperature on homelab.", report_md=REPORT,
            transcript_json=json.dumps([{"role": "user", "content": [
                {"type": "text", "text": "Investigate homelab."}]}]))
        s.add_step(iid, 1, "ssh_diagnostic", args_json=json.dumps({"command": "sensors"}),
                   result_preview="Package id 0: +48.0 C", result_bytes=900, duration_ms=800)
        s.suppress(fp, until="2026-12-24T00:00:00+00:00", reason="known scrub",
                   created_at=_iso(60))

    html = _client(tmp_path, monkeypatch, seed).get("/investigations/1").text
    # the page order: header facts, the four kinds, then the folded full
    # report, the brief, the stored transcript and the actions
    order = ['class="card head"', '<h2 id="h-observations">Observations</h2>',
             '<h2 id="h-interpretation">Interpretation</h2>',
             '<h2 id="h-proposed">Proposed actions</h2>',
             '<h2 id="h-completed">Completed actions</h2>',
             '<h2 class="eyebrow">report</h2>', "Brief sent to the agent",
             "Full transcript (1 turn)", 'class="acts"']
    positions = [html.index(marker) for marker in order]
    assert positions == sorted(positions)
    # each kind is a panel with a .label caption that says where it came from
    assert '<p class="label">transcript · 1 step</p>' in html
    assert '<p class="label">written by the agent</p>' in html
    assert '<p class="label">suggested by the agent · not carried out</p>' in html
    assert '<p class="label">taken by the operator</p>' in html
    assert html.count('<section class="panel kind"') == 4

    obs = _section(html, "observations", "interpretation")
    assert 'class="cmd mono"' in obs and "sensors" in obs and 'class="burn"' in obs

    interp = _section(html, "interpretation", "proposed")
    assert "<h3>Summary</h3>" in interp and "<strong>sdb</strong>" in interp
    assert "<h3>Root cause (confidence: high)</h3>" in interp and "<h3>CONFIDENCE</h3>" in interp
    assert "Raise the fan curve" not in interp and "smartctl" not in interp

    proposed = _section(html, "proposed", "completed")
    assert "<h3>Remediation</h3>" in proposed and "Raise the fan curve to 40 %" in proposed
    assert "Watch the trend for a week." in proposed
    assert "Fan curve too flat." not in proposed

    completed = html[html.index('id="h-completed"'):html.index('<h2 class="eyebrow">report</h2>')]
    # the row's own record: the approval (no time is stored for it), the
    # outcome and the mute, each with its time when there is one
    assert "Investigation approved" in completed
    assert re.search(r"Marked resolved\s*<time", completed)
    assert re.search(r"Fingerprint muted until 2026-12-24\s*<time", completed)
    assert NO_ACTIONS not in completed

    # Evidence and Tooling feedback are "other": in the full report only, folded
    full = html[html.index('<h2 class="eyebrow">report</h2>'):html.index("Brief sent to the agent")]
    assert "<details" in full and "<h2>Evidence</h2>" in full and "smartctl" in full
    assert "<h2>Tooling feedback</h2>" in full
    assert "Evidence, Tooling feedback" in full          # named on the fold


def test_no_actions_line_for_untouched_investigation(tmp_path, monkeypatch):
    def seed(s):
        s.create_investigation(host="ubuntu-server", status="complete", started_at=_iso(30),
                               finished_at=_iso(25), report_md="## Summary\n\nAll fine.\n")
        # an approval that timed out is not a decision anybody took
        s.create_investigation(host="ubuntu-server", status="declined", started_at=_iso(90),
                               finished_at=_iso(30), approval_decision="timeout")
        s.create_investigation(host="ubuntu-server", status="declined", started_at=_iso(90),
                               finished_at=_iso(30), approval_decision="decline")

    client = _client(tmp_path, monkeypatch, seed)
    for iid in (1, 2):
        html = client.get(f"/investigations/{iid}").text
        completed = html[html.index('id="h-completed"'):html.index('<h2 class="eyebrow">report</h2>')]
        assert f'<p class="empty">{NO_ACTIONS}</p>' in completed
    declined = client.get("/investigations/3").text
    completed = declined[declined.index('id="h-completed"'):]
    assert re.search(r"Investigation declined\s*<time", completed)
    assert NO_ACTIONS not in declined
    # no report: the interpretation and proposals say so, the fold stays
    assert "No report was written for this run." in _section(declined, "interpretation", "proposed")
    assert "<details" in declined[declined.index('<h2 class="eyebrow">report</h2>'):]


def test_waiting_age_and_replay_of_still_shown(tmp_path, monkeypatch):
    def seed(s):
        s.create_investigation(host="ubuntu-server", status="pending_approval",
                               started_at=_iso(125), brief_md="Investigate memory.")
        s.create_investigation(host="ubuntu-server", status="complete", trigger="daily",
                               started_at=_iso(300), finished_at=_iso(290),
                               report_md="## Summary\n\nOriginal.\n")
        s.create_investigation(host="ubuntu-server", status="complete", trigger="replay",
                               replay_of=2, started_at=_iso(60), finished_at=_iso(58),
                               report_md="## Summary\n\nReplayed.\n")

    client = _client(tmp_path, monkeypatch, seed)
    pending = client.get("/investigations/1").text
    meta = pending[pending.index('class="tbl dense imeta"'):pending.index("</table>")]
    # the age of a parked approval, lit orange: it needs the operator
    assert re.search(r'<span class="lamp orange" aria-hidden="true"></span>waiting 2h 0[45]m', meta)
    assert "No report yet" in _section(pending, "interpretation", "proposed")
    assert pending.count('<section class="panel kind"') == 4
    # ruling 18: a pending run puts the decision first, in the header card,
    # once; the brief follows further down
    assert pending.index('class="card head"') < pending.index('value="approve"') \
        < pending.index('id="h-observations"') < pending.index("Brief sent to the agent")
    assert pending.count('value="approve"') == 1 and pending.count('class="acts"') == 1
    assert '<h3 class="label">your decision</h3>' in pending

    # a finished run keeps its keys at the end, after the brief
    done = client.get("/investigations/2").text
    assert done.index('id="h-completed"') < done.index('class="acts"')
    assert done.count('class="acts"') == 1 and "your decision" not in done

    replay = client.get("/investigations/3").text
    assert 'href="/investigations/2">replay of #2</a>' in replay
    assert replay.index('href="/investigations/2">replay of #2</a>') < replay.index('id="h-observations"')
