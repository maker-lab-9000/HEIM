"""One colour code across the dashboard, grouped by who acts (the operator's
decision, 2026-11-02): orange waits on you, green is in progress or done well,
red is broken, amber is getting worse, ink/blue-grey is settled, grey is set
aside. ``format.FAMILIES`` / ``format._STATUS`` are the only place a state's
colour is decided."""
import re
from pathlib import Path

import pytest

from heim import agents
from heim.dashboard import format as fmt
from heim.security.types import SEVERITIES
from test_dashboard_actions import FP_TEMP, HX, app_store  # noqa: F401  (fixture)

CSS = (Path(__file__).resolve().parent.parent / "src/heim/dashboard/static/heim.css").read_text()

#: every state key the store and the agent model can produce
INVESTIGATION = ("pending_approval", "declined", "running", "complete", "incomplete",
                 "needs_human", "resolved", "failed")
INCIDENT = ("open", "clearing", "resolved", "suppressed")
JOB = ("queued", "running", "done", "failed", "interrupted")
SEVERITY = tuple(SEVERITIES) + ("crit", "warn", "ok", "na")
OVERALL = ("healthy", "warning", "critical", "normal", "degraded", "unknown")
VERDICT = ("confirmed", "false_positive")
RECOMMENDATION = ("done", "dismissed")
DECISION = ("approve", "decline")
AGENT = tuple(agents._STATES)
RUN = ("ok", "error", "missed")
DAEMON = ("connected", "stale", "unknown")

#: the operator's table
EXPECTED = {
    "you": {"pending_approval", "needs_human", "open", "queued"},
    "go": {"running", "done", "confirmed", "connected", "approve"},
    "crit": {"critical", "failed", "error", "dismissed", "decline", "crit"},
    "warn": {"warning", "degraded", "stale", "overdue", "incomplete", "missed", "warn"},
    "ok": {"resolved", "complete", "healthy", "ok", "idle", "normal"},
    "other": {"declined", "muted", "suppressed", "false_positive", "paused", "na", "unknown"},
}


def test_every_state_key_has_a_family():
    for group in (INVESTIGATION, INCIDENT, JOB, SEVERITY, OVERALL, VERDICT,
                  RECOMMENDATION, DECISION, AGENT, RUN, DAEMON):
        for key in group:
            assert key in fmt._STATUS, key
            assert fmt.family(key) in fmt.FAMILIES, key


@pytest.mark.parametrize("fam", sorted(EXPECTED))
def test_families_follow_the_operators_table(fam):
    for key in EXPECTED[fam]:
        assert fmt.family(key) == fam, key


def test_lamp_and_pill_class_come_from_the_family():
    assert [fmt.lamp(k) for k in ("open", "running", "failed", "warning", "resolved", "declined")] == [
        "orange", "green", "red", "amber", "blue", ""]
    assert fmt.status_pill("running")["cls"] == "st-go"
    assert fmt.status_pill("open")["cls"] == "st-you"
    assert fmt.family("no-such-state") == "other" and fmt.lamp(None) == ""


def _lum(h):
    c = [int(h.lstrip("#")[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]


def _ratio(a, b):
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _token(block_start, name):
    block = CSS[CSS.index(block_start):]
    return re.search(rf"{name}:\s*(#[0-9A-Fa-f]{{6}})", block[:block.index("}")]).group(1)


def test_green_lamp_is_mode_invariant_and_holds_3_to_1_on_both_panels():
    root, light = ":root {", '[data-theme="light"] {'
    assert "--go:" not in CSS[CSS.index(light):]
    go = _token(root, "--go")
    for panel in (_token(root, "--panel"), _token(light, "--panel")):
        assert _ratio(go, panel) >= 3, (go, panel)


def test_family_text_tokens_hold_4_5_to_1_on_both_panels():
    for block in (":root {", '[data-theme="light"] {'):
        panel = _token(block, "--panel")
        for tok in ("--t-you", "--t-open", "--t-crit", "--t-warn", "--ink", "--ink-3"):
            assert _ratio(_token(block, tok), panel) >= 4.5, (block, tok)


def test_open_incident_reads_orange_and_running_investigation_green(app_store):  # noqa: F811
    client, ids, _store, _cfg = app_store
    assert '<span class="word you">open</span>' in client.get("/incidents").text
    assert ":is(.word, .pressed).you { --tone: var(--t-you); }" in CSS
    listing = client.get("/investigations").text
    assert '<span class="pill st-go"><span class="dot green" aria-hidden="true"></span>running' in listing
    detail = client.get(f"/investigations/{ids['retry']}").text
    assert '<span class="lamp green" aria-hidden="true"></span>' in detail
    assert ":is(.lamp, .dot).green { --lit-hi: var(--go-hi); --lit: var(--go); }" in CSS


@pytest.mark.parametrize("decision, fam", [("approve", "go"), ("decline", "crit")])
def test_pressed_approve_is_green_and_decline_red(app_store, decision, fam):  # noqa: F811
    client, ids, _store, _cfg = app_store
    r = client.post("/actions/approval", data={"investigation_id": ids["pending"],
                                               "decision": decision}, headers=HX)
    assert f'class="btn pressed {fam}"' in r.text
    tok = {"go": "--t-open", "crit": "--t-crit"}[fam]
    assert f":is(.word, .pressed).{fam} {{ --tone: var({tok}); }}" in CSS


@pytest.mark.parametrize("verdict, fam", [("confirmed", "go"), ("false_positive", "other")])
def test_a_judged_finding_shows_its_pressed_verdict_key(app_store, verdict, fam):  # noqa: F811
    client, ids, _store, _cfg = app_store
    fid = ids["finding_temp"]
    r = client.post("/actions/verdict", data={"finding_id": fid, "verdict": verdict}, headers=HX)
    assert f'class="btn pressed {fam}" type="submit" aria-pressed="true"' in r.text
    html = client.get("/findings").text
    cells = re.findall(r'<td class="c-verdict">(.*?)</td>', html, re.S)
    judged = [c for c in cells if 'class="btn pressed' in c]
    assert len(judged) == 1
    assert f'class="btn pressed {fam}"' in judged[0]
    # both keys stay live: the pressed one clears, the other switches
    assert judged[0].count("<form") == 2 and 'name="verdict" value="clear"' in judged[0]
    if verdict == "false_positive":   # the dark lamp sits in front of the words
        assert '<span class="dot" aria-hidden="true"></span><span class="verdict">false positive' in judged[0]


def test_agents_panel_carries_the_colour_legend(app_store):  # noqa: F811
    client = app_store[0]
    for page in ("/", "/agents"):
        html = client.get(page).text
        legend = html[html.index('class="key legend"'):]
        legend = legend[:legend.index("</p>")]
        for colour, words in fmt.LEGEND:
            assert words in legend
            assert f'class="lamp sm{" " + colour if colour else ""}"' in legend
