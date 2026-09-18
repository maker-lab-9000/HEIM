"""The agent's own notes on its toolbox: the optional '## Tooling feedback'
report section, its store table, and the tool-usage card line.

The loop this closes: the thing that uses the tools every day is the only
witness to what they are missing, and until now that observation died with the
report. Now the latest suggestion per tool sits on the dashboard next to that
tool's call count.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.agent.runner import AgentResult
from heim.config import load_config
from heim.dashboard.app import _general_feedback, _tool_usage, create_app
from heim.incidents.store import IncidentStore
from heim.pipelines.investigate import InvestigationRequest, run_investigation
from heim.reports.render import extract_sections, extract_tool_feedback
from heim.runtime import Runtime

ROOT = Path(__file__).resolve().parent.parent

DUMMY_ENV = {
    "HEIM_SERVER_IP": "10.0.0.10",
    "HEIM_PROXMOX_IP": "10.0.0.2",
    "HEIM_HA_IP": "10.0.0.3",
    "HEIM_TELEGRAM_CHAT_ID": "111111111",
    "HEIM_EMAIL_TO": "test@example.com",
    "HEIM_EMAIL_FROM": "test@example.com",
}

REPORT_WITH_FEEDBACK = (
    "## Summary\n\nPhotoPrism filled /var.\n\n"
    "## Root cause\n\nImport cache. Confidence: high\n\n"
    "## Recommended remediation\n\n- Cap the cache\n\n"
    "## Tooling feedback\n\n"
    "- ssh_diagnostic: allow `du --max-depth=2` without the interactive pager\n"
    "- prometheus_query: return the series count before the samples\n"
)


# ---------------------------------------------------------------- fixtures


def _config(tmp_path, monkeypatch):
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("HEIM_DASHBOARD_TOKEN", raising=False)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    return load_config(croot)


@pytest.fixture()
def store(tmp_path) -> IncidentStore:
    return IncidentStore(tmp_path / "t.sqlite3")


@pytest.fixture()
def rt(tmp_path, monkeypatch) -> Runtime:
    cfg = _config(tmp_path, monkeypatch)
    cfg.settings.loki = None
    cfg.settings.email = None
    cfg.settings.home_assistant = None
    cfg.settings.telegram = None
    return Runtime(config=cfg, store=IncidentStore(tmp_path / "rt.sqlite3"),
                   dry_run=True, out_dir=tmp_path / "out")


# ================================================== 1. the prompt contract


def test_the_prompt_asks_for_the_optional_section():
    text = (ROOT / "config/prompts/investigator.md.j2").read_text()
    assert "## Tooling feedback" in text
    assert "OPTIONAL" in text and "0-3 lines" in text
    for tool in ("ssh_diagnostic", "prometheus_query", "discover_metrics",
                 "ha_api", "proxmox_api"):
        assert tool in text
    # the salvage contract is untouched: the report still starts with Summary
    assert "MUST begin with the line '## Summary'" in text


# ====================================================== 2. the extractor


def test_extract_tool_feedback_reads_the_section():
    assert extract_tool_feedback(REPORT_WITH_FEEDBACK) == [
        ("ssh_diagnostic", "allow `du --max-depth=2` without the interactive pager"),
        ("prometheus_query", "return the series count before the samples"),
    ]
    # and the section stays in the report (email/telegram show it too)
    assert "## Tooling feedback" in REPORT_WITH_FEEDBACK
    # the other sections still parse as before
    assert extract_sections(REPORT_WITH_FEEDBACK)["confidence"] == "high"
    assert extract_sections(REPORT_WITH_FEEDBACK)["remediation"] == ["Cap the cache"]


def test_extract_tool_feedback_absent_or_empty():
    assert extract_tool_feedback("## Summary\n\nAll fine.\n") == []
    assert extract_tool_feedback("## Summary\n\nx\n\n## Tooling feedback\n\n") == []
    assert extract_tool_feedback("") == []
    assert extract_tool_feedback(None) == []


def test_extract_tool_feedback_tolerates_bullets_numbering_and_emphasis():
    md = ("## Tooling feedback\n"
          "1. ssh_diagnostic: add a --json flag\n"
          "* **prometheus_query**: support step=\n"
          "  • `ha_api`: expose /api/services\n")
    assert extract_tool_feedback(md) == [
        ("ssh_diagnostic", "add a --json flag"),
        ("prometheus_query", "support step="),
        ("ha_api", "expose /api/services"),
    ]


def test_extract_tool_feedback_keeps_unknown_names_and_skips_prose():
    md = ("## Tooling feedback\n"
          "Nothing structured to say here.\n"
          "logs: a Loki search tool would have saved four steps\n"
          "-: \n"
          "## Appendix\nignored: not in the section\n")
    assert extract_tool_feedback(md) == [
        ("logs", "a Loki search tool would have saved four steps")]


def test_extract_tool_feedback_is_capped_and_clipped():
    md = "## Tooling feedback\n" + "".join(
        f"ssh_diagnostic: suggestion {i}\n" for i in range(9))
    assert len(extract_tool_feedback(md)) == 3
    long_md = "## Tooling feedback\nha_api: " + "x" * 900
    assert len(extract_tool_feedback(long_md)[0][1]) == 300


# ========================================================== 3. the store


def test_tool_feedback_roundtrip_and_latest_per_tool(store):
    assert store.latest_tool_feedback() == {}

    first = store.create_investigation(host="ubuntu-server", status="complete")
    store.add_tool_feedback(first, "ssh_diagnostic", "add --json", created_at="t1")
    store.add_tool_feedback(first, "ha_api", "expose /api/services", created_at="t1")

    second = store.create_investigation(host="ubuntu-server", status="complete")
    store.add_tool_feedback(second, "ssh_diagnostic", "allow du --max-depth", created_at="t2")

    latest = store.latest_tool_feedback()
    assert set(latest) == {"ssh_diagnostic", "ha_api"}
    assert latest["ssh_diagnostic"] == {"tool": "ssh_diagnostic",
                                        "suggestion": "allow du --max-depth",
                                        "investigation_id": second, "created_at": "t2"}
    assert latest["ha_api"]["investigation_id"] == first
    # the history is kept, per investigation
    assert [r["suggestion"] for r in store.tool_feedback(first)] == [
        "add --json", "expose /api/services"]
    # empty input is a no-op, not a blank row
    assert store.add_tool_feedback(first, "", "x") == 0
    assert store.add_tool_feedback(first, "ha_api", "   ") == 0
    assert len(store.tool_feedback(first)) == 2


def test_tool_feedback_is_pruned_with_its_investigation(store):
    iid = store.create_investigation(host="h", status="complete",
                                     finished_at="2020-01-01T00:00:00+00:00")
    store.add_tool_feedback(iid, "ha_api", "old advice")
    counts = store.prune("2026-09-18T00:00:00+00:00", 30)
    assert counts.get("tool_feedback") == 1
    assert store.latest_tool_feedback() == {}


# ======================================================= 4. the pipelines


def _stub_agent(monkeypatch, output: str):
    async def fake_run_agent(cfg, *, system, user_prompt, tools, on_step=None,
                             collect_transcript=False):
        return AgentResult(output, [], 100, 20)

    monkeypatch.setattr("heim.pipelines.investigate.run_agent", fake_run_agent)


async def test_investigation_stores_the_feedback_it_reported(rt, monkeypatch):
    _stub_agent(monkeypatch, REPORT_WITH_FEEDBACK)
    res = await run_investigation(rt, InvestigationRequest(host="ubuntu-server"))
    assert res is not None

    latest = rt.store.latest_tool_feedback()
    assert latest["ssh_diagnostic"]["investigation_id"] == res["id"]
    assert latest["prometheus_query"]["suggestion"].startswith("return the series count")
    # the section is still in the delivered report — transparency over indexing
    assert "## Tooling feedback" in rt.store.investigation(res["id"])["report_md"]


async def test_an_incomplete_run_still_contributes_feedback(rt, monkeypatch):
    """Feedback is feedback: the run that ran out of evidence is exactly the
    one with something to say about its tools."""
    _stub_agent(monkeypatch, "I will now run df.\n\n## Tooling feedback\n"
                             "discover_metrics: return label values, not just names\n")
    res = await run_investigation(rt, InvestigationRequest(host="ubuntu-server"))
    assert rt.store.investigation(res["id"])["status"] == "incomplete"
    assert "discover_metrics" in rt.store.latest_tool_feedback()


async def test_a_report_without_the_section_writes_nothing(rt, monkeypatch):
    _stub_agent(monkeypatch, "## Summary\n\nAll fine.\n")
    await run_investigation(rt, InvestigationRequest(host="ubuntu-server"))
    assert rt.store.latest_tool_feedback() == {}


async def test_replay_stores_feedback_through_the_same_path(rt, monkeypatch, tmp_path):
    """The replay pipeline reuses ``record_tool_feedback`` — a replayed model's
    opinion lands next to the original's."""
    # tests/ is on sys.path (no package), so the replay fixtures are importable
    from test_replay import _FakeClient, _Resp, _Text, _record_transcript, _seed_original

    from heim.pipelines.replay import run_replay

    rt.config.settings.store_transcripts = True
    inv_id = _seed_original(rt, await _record_transcript(monkeypatch))

    client = _FakeClient([_Resp([_Text(REPORT_WITH_FEEDBACK)], "end_turn")])
    monkeypatch.setattr("heim.agent.runner.AsyncAnthropic", lambda *a, **k: client)
    res = await run_replay(rt, inv_id)
    assert rt.store.latest_tool_feedback()["ssh_diagnostic"]["investigation_id"] == res["id"]


# ==================================================== 5. the dashboard card


def test_tool_usage_attaches_feedback_to_the_busiest_row_only():
    rows = [{"tool": "ssh_diagnostic", "calls": 10, "agent_name": "investigator",
             "model": "claude-sonnet-4-6"},
            {"tool": "ssh_diagnostic", "calls": 4, "agent_name": "investigator",
             "model": "claude-haiku-4-6"},
            {"tool": "ha_api", "calls": 2, "agent_name": "investigator",
             "model": "claude-sonnet-4-6"}]
    feedback = {"ssh_diagnostic": {"tool": "ssh_diagnostic", "suggestion": "add --json",
                                   "investigation_id": 7, "created_at": "t"},
                "logs": {"tool": "logs", "suggestion": "a Loki tool would help",
                         "investigation_id": 8, "created_at": "t"}}
    out = _tool_usage(rows, feedback)
    assert out[0]["feedback"]["suggestion"] == "add --json"
    assert out[1]["feedback"] is None      # same tool, quieter row: said once
    assert out[2]["feedback"] is None
    assert [f["tool"] for f in _general_feedback(feedback, out)] == ["logs"]
    # no feedback at all is simply nothing
    assert all(r["feedback"] is None for r in _tool_usage(rows, {}))
    assert _general_feedback({}, out) == []


def test_overview_renders_the_feedback_line_and_the_general_footnote(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "dash.sqlite3"
    cfg.settings.db_path = str(db)

    store = IncidentStore(db)
    iid = store.create_investigation(host="ubuntu-server", status="complete",
                                     trigger="daily", started_at="2026-09-18T07:00:00+02:00",
                                     model="claude-sonnet-4-6", agent_name="investigator")
    store.add_step(iid, 1, "ssh_diagnostic", args_json=json.dumps({"command": "df -h"}),
                   result_preview="92%", result_bytes=10, duration_ms=200)
    store.add_tool_feedback(iid, "ssh_diagnostic", "allow du --max-depth=2",
                            created_at="2026-09-18T07:04:00+02:00")
    store.add_tool_feedback(iid, "logs", "a Loki search tool would save four steps",
                            created_at="2026-09-18T07:04:00+02:00")
    store.close()

    with TestClient(create_app(cfg)) as client:
        html = client.get("/").text
    assert "💡 allow du --max-depth=2" in html
    assert f'href="/investigations/{iid}"' in html
    assert "💡 general: logs: a Loki search tool would save four steps" in html


def test_overview_without_feedback_says_nothing(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "dash.sqlite3"
    cfg.settings.db_path = str(db)
    store = IncidentStore(db)
    iid = store.create_investigation(host="ubuntu-server", status="complete",
                                     trigger="daily", model="claude-sonnet-4-6")
    store.add_step(iid, 1, "ssh_diagnostic", args_json="{}", duration_ms=10)
    store.close()
    with TestClient(create_app(cfg)) as client:
        html = client.get("/").text
    assert "💡" not in html
