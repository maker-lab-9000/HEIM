"""§9 recommendations: the stable key, the collection logic, the state table,
and the page that turns all three into the operator's to-do list."""
import re
from collections import Counter
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.dashboard.app import create_app
from heim.dashboard.recommendations import collect, rec_key
from heim.incidents.store import IncidentStore
from test_dashboard import _config, _iso

FP_MEM = "ubuntu-server|mem_used|Memory climbing"
FP_TEMP = "homelab|drive_temp|Drive temperature high"

HX = {"HX-Request": "true"}


def test_rec_key_stable_and_normalized():
    a = rec_key("finding", 3, "Set a  memory LIMIT")
    b = rec_key("finding", 3, "set a memory limit")
    assert a == b and len(a) == 40
    assert rec_key("finding", 4, "set a memory limit") != a


def test_rec_key_distinguishes_kind_and_text():
    assert rec_key("finding", 3, "restart it") != rec_key("investigation", 3, "restart it")
    assert rec_key("finding", 3, "restart it") != rec_key("finding", 3, "restart them")


def test_collect_unions_open_incident_findings_and_remediations():
    incidents = [{"fingerprint": "u|mem|", "host": "u", "status": "open"}]
    findings = [
        {"fingerprint": "u|mem|", "host": "u", "metric": "Mem", "recommendation": "Cap it",
         "run_at": "2026-09-18T07:00:00"},
        {"fingerprint": "u|mem|", "host": "u", "metric": "Mem", "recommendation": "",
         "run_at": "2026-09-18T22:00:00"},           # empty rec -> ignored
        {"fingerprint": "x|gone|", "host": "x", "metric": "X", "recommendation": "Old",
         "run_at": "2026-09-17T07:00:00"},           # incident not open -> ignored
    ]
    invs = [{"id": 7, "host": "u", "status": "complete", "finished_at": "2026-09-18T08:00:00",
             "report_md": "## Summary\ns\n## Root cause\nrc\n"
                          "## Recommended remediation\n1. Restart it\n2. Add an alert\n"}]
    rows = collect(incidents, findings, invs)
    texts = [r["text"] for r in rows]
    assert "Cap it" in texts and "Restart it" in texts and "Add an alert" in texts
    assert "Old" not in texts
    inv_row = next(r for r in rows if r["text"] == "Restart it")
    assert inv_row["source"] == "investigation #7" and inv_row["source_href"] == "/investigations/7"
    fin_row = next(r for r in rows if r["text"] == "Cap it")
    assert fin_row["source"].startswith("finding") and "Mem" in fin_row["source"]


def test_collect_keeps_only_the_newest_finding_per_incident():
    incidents = [{"fingerprint": "u|mem|", "host": "u", "status": "open"}]
    findings = [
        {"fingerprint": "u|mem|", "host": "u", "metric": "Mem", "recommendation": "stale advice",
         "run_at": "2026-09-17T07:00:00"},
        {"fingerprint": "u|mem|", "host": "u", "metric": "Mem", "recommendation": "fresh advice",
         "run_at": "2026-09-18T07:00:00"},
    ]
    rows = collect(incidents, findings, [])
    assert [r["text"] for r in rows] == ["fresh advice"]
    assert rows[0]["at"] == "2026-09-18T07:00:00"
    assert rows[0]["host"] == "u" and rows[0]["source_href"] == "/findings"
    assert rows[0]["key"] == rec_key("finding", "u|mem|", "fresh advice")


def test_collect_sorts_newest_first_across_sources():
    incidents = [{"fingerprint": "a|cpu|", "host": "a", "status": "open"}]
    findings = [{"fingerprint": "a|cpu|", "host": "a", "metric": "CPU",
                 "recommendation": "middle", "run_at": "2026-09-18T12:00:00"}]
    invs = [
        {"id": 1, "host": "a", "status": "complete", "finished_at": "2026-09-19T09:00:00",
         "report_md": "## Recommended remediation\n- newest\n"},
        {"id": 2, "host": "a", "status": "complete", "finished_at": "2026-09-01T09:00:00",
         "report_md": "## Recommended remediation\n- oldest\n"},
    ]
    assert [r["text"] for r in collect(incidents, findings, invs)] == [
        "newest", "middle", "oldest",
    ]


def test_collect_skips_resolved_investigations_operator_already_handled_them():
    """Spec §9 lists *complete* runs only.

    ``resolved`` is the operator answering the outcome prompt with "handled",
    so its remediations are done work, not open to-dos.
    """
    invs = [
        {"id": 1, "host": "a", "status": "complete", "finished_at": "2026-09-18T00:00:00",
         "report_md": "## Recommended remediation\n- still to do\n"},
        {"id": 2, "host": "a", "status": "resolved", "finished_at": "2026-09-18T01:00:00",
         "report_md": "## Recommended remediation\n- already handled\n"},
        {"id": 3, "host": "a", "status": "needs_human", "finished_at": "2026-09-18T02:00:00",
         "report_md": "## Recommended remediation\n- needs a person\n"},
    ]
    assert [r["text"] for r in collect([], [], invs)] == ["still to do"]


def test_collect_skips_unfinished_investigations_and_empty_reports():
    invs = [
        {"id": 1, "host": "a", "status": "running", "finished_at": "",
         "report_md": "## Recommended remediation\n- not yet\n"},
        {"id": 2, "host": "a", "status": "failed", "finished_at": "2026-09-18T00:00:00",
         "report_md": "## Recommended remediation\n- failed run\n"},
        {"id": 3, "host": "a", "status": "complete", "finished_at": "2026-09-18T00:00:00",
         "report_md": None},
        {"id": 4, "host": "a", "status": "complete", "finished_at": "2026-09-18T00:00:00",
         "report_md": "## Summary\nnothing to do\n"},
    ]
    assert collect([], [], invs) == []


def test_collect_on_empty_inputs():
    assert collect([], [], []) == []


def test_store_state_roundtrip(tmp_path):
    s = IncidentStore(tmp_path / "r.sqlite3")
    s.set_recommendation_state("k1", "done")
    s.set_recommendation_state("k1", "dismissed")   # idempotent replace
    states = s.recommendation_states()
    assert states["k1"]["state"] == "dismissed" and states["k1"]["created_at"]
    s.close()


def test_store_states_start_empty_and_key_many(tmp_path):
    s = IncidentStore(tmp_path / "r.sqlite3")
    assert s.recommendation_states() == {}
    s.set_recommendation_state("a", "done")
    s.set_recommendation_state("b", "dismissed")
    states = s.recommendation_states()
    assert set(states) == {"a", "b"}
    assert states["a"]["state"] == "done" and states["b"]["state"] == "dismissed"
    s.close()


def test_store_rejects_unknown_state(tmp_path):
    s = IncidentStore(tmp_path / "r.sqlite3")
    with pytest.raises(ValueError):
        s.set_recommendation_state("k1", "snoozed")
    assert s.recommendation_states() == {}
    s.close()


# ------------------------------------------------------------------- the page


def _seed(db_path: Path) -> dict:
    """The three shapes the page has to render: an open incident's finding, a
    complete investigation whose report repeats a remediation line, and a
    complete investigation that never recorded a finish time."""
    store = IncidentStore(db_path)
    ids = {}
    run_at = _iso(30)
    ids["run"] = store.insert_run(run_at=run_at, kind="daily", overall="warning")
    store.insert_findings(ids["run"], run_at, "daily", [
        {"host": "ubuntu-server", "metric": "mem_used", "severity": "critical",
         "trend": "up", "summary": "Memory climbing on ubuntu-server",
         "detail": "Working set grew 18%.", "recommendation": "Cap it"},
    ], fingerprints=[FP_MEM])
    store.upsert([
        {"fingerprint": FP_MEM, "host": "ubuntu-server", "metric": "mem_used",
         "severity": "critical", "status": "open", "firstSeen": _iso(4000),
         "lastSeen": _iso(30), "timesSeen": 7, "missedRuns": 0,
         "description": "Working set grew 18% over three days."},
    ])
    ids["inv"] = store.create_investigation(
        fingerprint=FP_TEMP, host="homelab", host_role="hypervisor",
        agent_name="investigator", model="claude-sonnet-4-6", trigger="daily",
        status="complete", started_at=_iso(200), finished_at=_iso(190),
        report_md="## Summary\nHot drive.\n## Recommended remediation\n"
                  "1. Raise the fan curve\n2. Raise the fan curve\n"
                  "3. Add a temperature alert\n")
    # complete, but no finished_at: `at` is empty and must still render
    ids["unstamped"] = store.create_investigation(
        fingerprint=FP_TEMP, host="homelab", host_role="hypervisor",
        trigger="manual", status="complete", started_at=_iso(300),
        report_md="## Recommended remediation\n- Replace the drive\n")
    store.close()
    return ids


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    ids = _seed(db)
    with TestClient(create_app(cfg)) as client:
        yield client, ids, db


@pytest.fixture()
def seeded_client(seeded):
    return seeded[0]


@pytest.fixture()
def empty_client(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    cfg.settings.db_path = str(tmp_path / "empty.sqlite3")
    with TestClient(create_app(cfg)) as client:
        yield client


def test_recommendations_page_lists_and_acts(seeded_client):
    c = seeded_client
    html = c.get("/recommendations").text
    assert "Cap it" in html and "investigation #" in html
    assert "DONE" in html and "DISMISS" in html
    key = re.search(r'name="key" value="([0-9a-f]{40})"', html).group(1)
    r = c.post("/actions/recommendation",
               data={"key": key, "state": "done", "back": "/recommendations"},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/recommendations"
    html2 = c.get("/recommendations").text
    assert "handled (1)" in html2


def test_recommendations_page_sources_and_links(seeded_client):
    html = seeded_client.get("/recommendations").text
    assert 'href="/findings"' in html and 'href="/investigations/1"' in html
    assert "Raise the fan curve" in html and "Add a temperature alert" in html
    assert "ubuntu-server" in html and "homelab" in html


def test_recommendations_dedupes_a_repeated_remediation_line(seeded_client):
    """One report repeating itself is one to-do: same key, one row — otherwise
    ticking one of the twins would leave its identical sibling behind."""
    html = seeded_client.get("/recommendations").text
    assert html.count("Raise the fan curve") == 1
    keys = re.findall(r'name="key" value="([0-9a-f]{40})"', html)
    # two buttons per row, so every key appears exactly twice and no more
    assert set(Counter(keys).values()) == {2}


def test_recommendations_renders_a_missing_timestamp_as_a_dash(seeded_client):
    """A complete investigation with no finished_at still has advice to give;
    its age cell is the dash every other page uses, never an empty box.

    The cell goes through the same `when()` macro as every other table, so
    this pins that the macro's `iso`/`rel` pair keeps dashing on an empty
    value rather than emitting an empty <time>.
    """
    html = seeded_client.get("/recommendations").text
    assert "Replace the drive" in html
    row = html.split("Replace the drive", 1)[1].split("</tr>", 1)[0]
    assert "—" in row
    assert ">—</time>" in row and 'datetime="—"' in row


def test_recommendations_timestamps_are_time_elements(seeded_client):
    """Tabular timestamps use the `when()` macro, so they are machine-readable
    and carry the exact-time tooltip — the table convention, not the bare
    filter the inline lists use."""
    html = seeded_client.get("/recommendations").text
    row = html.split("Cap it", 1)[1].split("</tr>", 1)[0]
    assert re.search(r'<time class="mono" datetime="20\d\d-[^"]+" title="20\d\d-', row)
    key = re.search(r'name="key" value="([0-9a-f]{40})"', html).group(1)
    seeded_client.post("/actions/recommendation", data={"key": key, "state": "done"})
    handled = seeded_client.get("/recommendations").text.split("handled (1)", 1)[1]
    assert re.search(r'<time class="mono" datetime="20\d\d-[^"]+" title="20\d\d-', handled)


def test_recommendation_dismiss_moves_the_row_and_state_persists(seeded_client, seeded):
    html = seeded_client.get("/recommendations").text
    key = re.search(r'name="key" value="([0-9a-f]{40})"', html).group(1)
    seeded_client.post("/actions/recommendation",
                       data={"key": key, "state": "dismissed"})
    html2 = seeded_client.get("/recommendations").text
    assert "handled (1)" in html2 and "dismissed" in html2
    probe = IncidentStore(seeded[2])
    assert probe.recommendation_states()[key]["state"] == "dismissed"
    probe.close()


def test_recommendation_action_is_idempotent(seeded_client):
    html = seeded_client.get("/recommendations").text
    key = re.search(r'name="key" value="([0-9a-f]{40})"', html).group(1)
    for _ in range(3):
        seeded_client.post("/actions/recommendation", data={"key": key, "state": "done"})
    assert "handled (1)" in seeded_client.get("/recommendations").text


def test_recommendation_htmx_returns_a_fragment_with_the_flash(seeded_client):
    html = seeded_client.get("/recommendations").text
    key = re.search(r'name="key" value="([0-9a-f]{40})"', html).group(1)
    r = seeded_client.post("/actions/recommendation",
                           data={"key": key, "state": "done"}, headers=HX)
    assert r.status_code == 200
    assert "Marked done." in r.text and "<html" not in r.text


def test_recommendation_bad_state_400(seeded_client):
    assert seeded_client.post("/actions/recommendation",
                              data={"key": "x" * 40, "state": "nope"}).status_code == 400


def test_recommendation_bad_key_400(seeded_client):
    assert seeded_client.post("/actions/recommendation",
                              data={"key": "not a key", "state": "done"}).status_code == 400
    assert seeded_client.post("/actions/recommendation",
                              data={"state": "done"}).status_code == 400


def test_recommendation_state_of_a_vanished_source_is_ignored(seeded_client):
    """Spec §9: a state row whose recommendation no longer exists just sits
    there — it must not invent a handled row out of nothing."""
    seeded_client.post("/actions/recommendation",
                       data={"key": "a" * 40, "state": "done"})
    assert "handled (" not in seeded_client.get("/recommendations").text


def test_nav_has_recommendations(seeded_client):
    assert 'href="/recommendations"' in seeded_client.get("/").text


def test_recommendations_empty_state(empty_client):
    assert "Nothing to act on." in empty_client.get("/recommendations").text
