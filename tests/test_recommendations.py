"""§9 recommendations: the stable key, the collection logic, the state table."""
import pytest

from heim.dashboard.recommendations import collect, rec_key
from heim.incidents.store import IncidentStore


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
        {"id": 2, "host": "a", "status": "resolved", "finished_at": "2026-09-01T09:00:00",
         "report_md": "## Recommended remediation\n- oldest\n"},
    ]
    assert [r["text"] for r in collect(incidents, findings, invs)] == [
        "newest", "middle", "oldest",
    ]


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
