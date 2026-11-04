"""Which run started what — recorded when it happens, never inferred
(spec 2026-11-04-activity-jobs-tools)."""
from __future__ import annotations

import asyncio
import json

from test_tracking import _chain_result, _daily_payload, rt  # noqa: F401  (fixture)
from test_uptime_pipeline import Rig, _metrics  # noqa: F401

from heim import daemon
from heim.agent.runner import AgentResult, AgentStep
from heim.pipelines import daily
from heim.pipelines.investigate import dispatch_all
from heim.runctx import TRIGGER_JOB, current_run, run_ids, set_runs

REPORT = "## Summary\n\nok\n\n## Root cause\n\nx\n\n## Confidence\n\nhigh"


def test_current_run_defaults_and_trigger_map():
    assert current_run("daily") == 0
    token = set_runs({"daily": 4})
    try:
        assert current_run("daily") == 4 and current_run("uptime") == 0
    finally:
        run_ids.reset(token)
    assert TRIGGER_JOB == {"daily": "daily", "poller": "alert_poller",
                           "threshold": "thresholds", "uptime": "uptime"}


async def test_daily_job_opens_heartbeat_first(rt, monkeypatch):  # noqa: F811
    seen = {}

    async def fake_daily(rt_, dispatch_concurrently=True):
        rid = current_run("daily")
        seen["id"] = rid
        seen["row"] = rt_.store.agent_runs("daily")[0]
        return {"overall": "healthy"}

    monkeypatch.setattr(daemon, "run_daily", fake_daily)
    await daemon._daily_job(rt)
    assert seen["id"] and seen["row"]["id"] == seen["id"] and seen["row"]["finished_at"] == ""
    row = rt.store.agent_runs("daily")[0]
    assert row["id"] == seen["id"] and row["finished_at"] and row["ok"]
    assert len(rt.store.agent_runs("daily")) == 1


async def test_failed_daily_job_closes_its_heartbeat(rt, monkeypatch):  # noqa: F811
    async def boom(rt_, dispatch_concurrently=True):
        raise RuntimeError("nope")

    monkeypatch.setattr(daemon, "run_daily", boom)
    monkeypatch.setattr(rt, "notify", lambda text: asyncio.sleep(0))
    await daemon._daily_job(rt)
    rows = rt.store.agent_runs("daily")
    assert len(rows) == 1 and rows[0]["finished_at"] and not rows[0]["ok"]
    assert "nope" in rows[0]["error"]


def _stub_agent(monkeypatch):
    async def fake_run_agent(cfg, *, system, user_prompt, tools, on_step=None,
                             collect_transcript=False):
        await asyncio.sleep(0.01)
        return AgentResult(REPORT, [AgentStep("stub", {}, "")], 10, 5)

    monkeypatch.setattr("heim.pipelines.investigate.run_agent", fake_run_agent)


async def test_dispatched_investigation_records_parent(rt, monkeypatch):  # noqa: F811
    _stub_agent(monkeypatch)
    rt.config.settings.approvals.require = False
    token = set_runs({"daily": 7})
    try:
        await dispatch_all(rt, [{"host": "ubuntu-server", "hostRole": "guest",
                                 "fingerprint": "ubuntu-server|mem|m", "metric": "mem",
                                 "severity": "warning", "description": "d"}],
                           concurrent=True, trigger="daily")
    finally:
        run_ids.reset(token)
    # the task outlives the context it was started in
    for _ in range(200):
        rows = rt.store.investigations(limit=5)
        if rows and rows[0]["status"] not in ("running", "pending_approval"):
            break
        await asyncio.sleep(0.01)
    assert rows and rows[0]["parent_run_id"] == 7


async def test_manual_investigation_has_no_parent(rt, monkeypatch):  # noqa: F811
    from heim.pipelines.investigate import InvestigationRequest, run_investigation
    _stub_agent(monkeypatch)
    await run_investigation(rt, InvestigationRequest(host="ubuntu-server"),
                            require_approval=False, trigger="manual")
    assert rt.store.investigations(limit=1)[0]["parent_run_id"] == 0


async def test_daily_run_row_links_and_stores_input(rt, monkeypatch):  # noqa: F811
    row = {"host": "ubuntu-server", "label": "", "name": "Memory used", "unit": "%",
           "qid": "mem_used", "category": "Memory", "current": 91.0, "avg": 80.0,
           "min": 70.0, "max": 91.0, "day3d": [70.0, 80.0, 91.0], "changePct": 30.0,
           "flag": "warn"}
    analysis = {"overallHealth": "warning", "headline": "h", "executiveSummary": "s",
                "categories": {}, "watchlist": [],
                "findings": [{"severity": "warning", "host": "ubuntu-server",
                              "metric": "Memory used", "trend": "rising", "summary": "m",
                              "detail": "d", "recommendation": "r"}]}

    async def fake_fetch(base, qdefs, window):
        return []

    async def fake_analyst(chain, system, user, max_tokens, accept=None):
        return _chain_result(json.dumps(analysis), "model-x", 9, 9)

    async def fake_dispatch(rt_, items, *, concurrent, trigger="manual"):
        return None

    monkeypatch.setattr(daily, "_fetch_query_ranges", fake_fetch)
    monkeypatch.setattr(daily, "aggregate", lambda *a, **k: {"payload": _daily_payload([row])})
    monkeypatch.setattr(daily, "run_chain", fake_analyst)
    monkeypatch.setattr(daily, "dispatch_all", fake_dispatch)
    token = set_runs({"daily": 12})
    try:
        await daily.run_daily(rt, dispatch_concurrently=False)
    finally:
        run_ids.reset(token)
    run = rt.store.runs()[0]
    assert run["agent_run_id"] == 12
    assert "mem_used" in run["input_text"] or "Memory used" in run["input_text"]
    events = rt.store.incident_events_for([12])[12]
    assert [e["event"] for e in events] == ["new"]


async def test_poll_half_writes_incident_events(tmp_path, monkeypatch):
    from test_uptime_pipeline import _build
    rt_ = _build(tmp_path, monkeypatch)
    rig = Rig(rt_, monkeypatch)
    token = set_runs({"uptime": 11})
    try:
        await rig.poll(_metrics(("n8n", "10.0.0.10", 0), ("grafana", "10.0.0.10", 0)))
    finally:
        run_ids.reset(token)
    events = rt_.store.incident_events_for([11])[11]
    assert [e["event"] for e in events] == ["new", "new"]
    assert {e["host"] for e in events} == {"ubuntu-server"}


async def test_poll_job_opens_one_heartbeat_per_enabled_half(rt, monkeypatch):  # noqa: F811
    seen = {}

    async def fake_poll(rt_, dispatch_concurrently=True, skip=frozenset()):
        seen["alert"] = current_run("alert_poller")
        seen["thr"] = current_run("thresholds")
        return {}

    async def no_ping(url):
        return None

    monkeypatch.setattr(daemon, "run_poll", fake_poll)
    monkeypatch.setattr(daemon.deadman, "ping", no_ping)
    rt.config.settings.threshold_detection = True
    await daemon._poll_job(rt)
    assert seen["alert"] and seen["thr"] and seen["alert"] != seen["thr"]
    assert rt.store.agent_runs("alert_poller")[0]["id"] == seen["alert"]
    assert rt.store.agent_runs("alert_poller")[0]["finished_at"]
    assert len(rt.store.agent_runs("alert_poller")) == 1
