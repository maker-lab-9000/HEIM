"""Operator follow-ups (2026-11-02): pressed keys show the outcome, the overview
cards span the container, the fold toggles are Details keys, and a needs-you
row does not say "Needs you" twice."""
import json
import re
from pathlib import Path

import pytest

from heim.dashboard import format as fmt
from test_dashboard import _iso
from test_dashboard_actions import app_store  # noqa: F401  (fixture)
from test_overview_console import PHYSICAL_REPORT, _client, _healthy_agents
from test_recommendations import seeded, seeded_client  # noqa: F401  (fixtures)

CSS = Path(__file__).resolve().parent.parent / "src/heim/dashboard/static/heim.css"
HX = {"HX-Request": "true"}


def _rec_key(client):
    return re.search(r'name="key" value="([0-9a-f]{40})"', client.get("/recommendations").text).group(1)


def test_done_recommendation_shows_a_pressed_green_done_key(seeded_client):
    key = _rec_key(seeded_client)
    r = seeded_client.post("/actions/recommendation", data={"key": key, "state": "done"}, headers=HX)
    assert 'class="btn pressed go" type="button" disabled aria-pressed="true"' in r.text
    assert ">Done</button>" in r.text and "Marked done." in r.text
    assert 'class="pill' not in r.text and 'class="dot"' not in r.text
    assert ">Dismiss<" not in r.text                      # no live keys on a handled row
    page = seeded_client.get("/recommendations").text.split("handled (1)", 1)[1]
    assert 'class="btn pressed go"' in page and ">Done</button>" in page


def test_dismissed_recommendation_shows_a_pressed_red_dismiss_key(seeded_client):
    key = _rec_key(seeded_client)
    r = seeded_client.post("/actions/recommendation", data={"key": key, "state": "dismissed"}, headers=HX)
    assert 'class="btn pressed crit" type="button" disabled aria-pressed="true"' in r.text
    assert ">Dismiss</button>" in r.text and "Dismissed." in r.text
    assert ">Done<" not in r.text
    page = seeded_client.get("/recommendations").text.split("handled (1)", 1)[1]
    assert 'class="btn pressed crit"' in page and ">Dismiss</button>" in page


@pytest.fixture()
def app(app_store):
    return app_store[0], app_store[1], app_store[2]


@pytest.mark.parametrize("decision, tone, label, other", [
    ("approve", "go", "Approve", "Decline"), ("decline", "crit", "Decline", "Approve")])
def test_a_decided_approval_shows_the_pressed_key(app, decision, tone, label, other):
    client, ids, _ = app
    inv = ids["pending"]
    live = client.get(f"/investigations/{inv}").text
    assert 'class="btn pressed' not in live and "Approve" in live and "Decline" in live
    r = client.post("/actions/approval", data={"investigation_id": inv, "decision": decision},
                    headers=HX)
    assert f'class="btn pressed {tone}" type="button" disabled aria-pressed="true"' in r.text
    assert f">{label}</button>" in r.text and other not in r.text
    page = client.get(f"/investigations/{inv}").text
    assert f'class="btn pressed {tone}"' in page and f">{label}</button>" in page
    assert f">{other}<" not in page and "Re-run" in page


def test_every_key_is_inset_while_pressed():
    css = CSS.read_text()
    assert re.search(r"\.btn:active[^{]*\{[^}]*inset 0 2px 3px var\(--shade\)", css)
    assert re.search(r"\.btn\.pressed[^{]*\{[^}]*inset 0 2px 3px var\(--shade\)[^}]*\}", css)
    # the key wears its family's --tone (the one colour code, 2026-11-02)
    assert re.search(r"\.btn\.pressed[^{]*\{[^}]*color: var\(--tone\)[^}]*"
                     r"color-mix\(in oklab, var\(--tone\) 14%, var\(--panel\)\)", css)
    for tone, tok in (("go", "--t-open"), ("crit", "--t-crit")):
        assert f":is(.word, .pressed).{tone} {{ --tone: var({tok}); }}" in css


def test_cards_span_the_container_in_four_two_one_columns():
    css = CSS.read_text()
    assert re.search(r"\.cards \{[^}]*repeat\(4, minmax\(0, 1fr\)\)", css)
    assert "auto-fill" not in css.split(".cards {", 1)[1].split("}", 1)[0]
    assert re.search(r"@media \(max-width: 70rem\)[^\n]*\.cards \{ grid-template-columns: repeat\(2,", css)
    assert re.search(r"@media \(max-width: 40rem\) \{ \.cards \{ grid-template-columns: minmax\(0, 1fr\)", css)
    assert re.search(r"\.cards \.card \{[^}]*min-width: 0[^}]*overflow-wrap: anywhere", css)


def test_incident_and_finding_folds_are_details_keys(app):
    client, _, _ = app
    for path in ("/incidents", "/findings"):
        html = client.get(path).text
        assert '<summary class="btn"' in html and ">Details</summary>" in html
        assert ">what this incident says<" not in html and ">detail &amp; recommendation<" not in html
        assert html.count("<details") == html.count("<summary class=\"btn\"") or path == "/findings"


def test_needs_you_workflow_title_is_empty():
    inv = {"id": 7, "status": "needs_human"}
    out = fmt.workflow_for({"host": "h", "description": ""}, [inv], {"h"})
    assert out == {"title": "", "sub": "investigation 7", "href": "/investigations/7"}


def test_needs_you_row_says_it_once_and_keeps_rerun(tmp_path, monkeypatch):
    def seed(s):
        _healthy_agents(s)
        s.create_investigation(fingerprint="homelab|drive_temp|jellymedia", host="homelab",
                               agent_name="investigator", status="needs_human",
                               outcome="needs_human", started_at=_iso(600),
                               finished_at=_iso(590), report_md=PHYSICAL_REPORT)

    with _client(tmp_path, monkeypatch, seed) as c:
        html = c.get("/").text
    att = html.split('aria-labelledby="h-att"', 1)[1].split("</section>", 1)[0]
    rows = re.findall(r"<tr>.*?</tr>", att.split("<tbody>", 1)[1], re.S)
    row = next(r for r in rows if "investigation " in r)
    assert row.count("Needs you") == 1                   # the left column's sub-line only
    assert '<span class="title"></span>' not in row
    wf = row.split("<td", 4)[4]
    assert "Needs you" not in wf and "Re-run" in wf and "/investigations/" in wf
