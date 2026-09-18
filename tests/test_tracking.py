"""Tracking tests (roadmap §5.1 + §5.7): the runs/findings/investigations/
investigation_steps store tables, the runner's live ``on_step`` callback, the
investigation status transitions, and the concurrency cap.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import time
from pathlib import Path

import pytest

from heim.agent.runner import AgentResult, run_agent
from heim.config import AgentCfg, load_config
from heim.incidents.store import IncidentStore
from heim.pipelines.investigate import (
    InvestigationRequest,
    _is_blocked,
    _step_recorder,
    run_investigation,
)
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

SUMMARY_OUTPUT = "## Summary\n\nDisk filled up.\n\n## Root cause\n\nlogs\n\n## Confidence\n\nhigh"


# ----------------------------------------------------------------- fixtures


@pytest.fixture()
def store(tmp_path) -> IncidentStore:
    return IncidentStore(tmp_path / "t.sqlite3")


@pytest.fixture()
def rt(tmp_path, monkeypatch) -> Runtime:
    """A Runtime on the committed example config, with every outbound channel
    disabled so the pipeline's delivery phase stays local."""
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    cfg.settings.loki = None
    cfg.settings.email = None
    cfg.settings.home_assistant = None
    return Runtime(
        config=cfg,
        store=IncidentStore(tmp_path / "rt.sqlite3"),
        dry_run=True,
        out_dir=tmp_path / "out",
    )


# --------------------------------------------------------------- fake agent API


class _Usage:
    def __init__(self, i: int, o: int):
        self.input_tokens, self.output_tokens = i, o


class _Text:
    type = "text"

    def __init__(self, text: str):
        self.text = text


class _ToolUse:
    type = "tool_use"

    def __init__(self, id_: str, name: str, input_: dict):
        self.id, self.name, self.input = id_, name, input_


class _Resp:
    def __init__(self, content: list, stop_reason: str, usage=(1, 1)):
        self.content = content
        self.stop_reason = stop_reason
        self.usage = _Usage(*usage)


class _FakeMessages:
    def __init__(self, script: list):
        self._script = list(script)
        self.calls = 0

    async def create(self, **kwargs):
        self.calls += 1
        return self._script.pop(0)


class _FakeClient:
    def __init__(self, script: list):
        self.messages = _FakeMessages(script)


class StubTool:
    """A minimal Tool-shaped stub (no ToolContext, no I/O)."""

    def __init__(self, name: str, result: str = "ok", delay: float = 0.0):
        self.name = name
        self._result = result
        self._delay = delay
        self.calls: list[dict] = []
        self.closed = False

    def anthropic_schema(self) -> dict:
        return {"name": self.name, "description": "stub", "input_schema": {"type": "object"}}

    async def __call__(self, args: dict) -> str:
        if self._delay:
            await asyncio.sleep(self._delay)
        self.calls.append(args)
        return self._result

    async def close(self) -> None:
        self.closed = True


def _agent_cfg(**kw) -> AgentCfg:
    return AgentCfg(name="investigator", model="claude-test", **kw)


def _patch_client(monkeypatch, script: list) -> _FakeClient:
    client = _FakeClient(script)
    monkeypatch.setattr("heim.agent.runner.AsyncAnthropic", lambda *a, **k: client)
    return client


# ============================================================ store: runs


def test_insert_run_and_list(store):
    rid = store.insert_run(kind="daily", run_at="2026-09-18T07:00:00", overall="warning",
                           model_used="model-x", duration_s=12.5,
                           counts_json=json.dumps({"new": 1}))
    assert rid > 0
    rows = store.runs()
    assert len(rows) == 1
    r = rows[0]
    assert (r["kind"], r["overall"], r["model_used"]) == ("daily", "warning", "model-x")
    assert r["duration_s"] == 12.5
    assert json.loads(r["counts_json"]) == {"new": 1}

    store.insert_run(kind="poll", run_at="t2", duration_s=0.4, counts_json="{}")
    assert [x["kind"] for x in store.runs()] == ["poll", "daily"]      # newest first
    assert [x["kind"] for x in store.runs(kind="daily")] == ["daily"]


def test_insert_run_rejects_unknown_field(store):
    with pytest.raises(ValueError, match="nope"):
        store.insert_run(kind="daily", nope=1)


# ========================================================= store: findings


def test_insert_and_read_findings(store):
    rid = store.insert_run(kind="daily", run_at="t0")
    findings = [
        {"host": "ubuntu-server", "metric": "Memory used", "severity": "warning",
         "trend": "rising", "summary": "mem climbing", "detail": "d1", "recommendation": "cap it"},
        {"host": "homelab", "metric": "Drive temp", "severity": "critical"},
    ]
    n = store.insert_findings(rid, "t0", "daily", findings, ["u|mem_used|", "h|drive_temp|sda"])
    assert n == 2

    rows = store.recent_findings()
    assert len(rows) == 2
    newest = rows[0]
    assert newest["host"] == "homelab" and newest["fingerprint"] == "h|drive_temp|sda"
    assert newest["trend"] == "" and newest["recommendation"] == ""   # missing keys -> ''
    oldest = rows[1]
    assert oldest["run_id"] == rid and oldest["source"] == "daily"
    assert oldest["summary"] == "mem climbing" and oldest["verdict"] is None  # verdict NULL for now


def test_insert_findings_pads_missing_fingerprints_and_skips_empty(store):
    rid = store.insert_run(kind="daily", run_at="t0")
    assert store.insert_findings(rid, "t0", "daily", [], []) == 0
    store.insert_findings(rid, "t0", "daily", [{"host": "h"}, {"host": "h2"}], ["only-one"])
    fps = [r["fingerprint"] for r in store.recent_findings()]
    assert fps == ["", "only-one"]


def test_daily_findings_fingerprints_use_the_reconcile_helper(store):
    """The finding rows must link to the same fingerprints reconcile computes."""
    from heim.incidents.reconcile import fingerprint_for

    payload_rows = [{"host": "ubuntu-server", "qid": "mem_used", "name": "Memory used",
                     "label": "", "flag": "warn"}]
    finding = {"host": "ubuntu-server", "metric": "Memory used", "severity": "warning",
               "summary": "s", "detail": "d", "recommendation": "r"}
    fp = fingerprint_for(finding, payload_rows)
    rid = store.insert_run(kind="daily", run_at="t0")
    store.insert_findings(rid, "t0", "daily", [finding], [fp])
    assert store.recent_findings()[0]["fingerprint"] == fp
    assert fp.startswith("ubuntu-server|mem_used|")


# =================================================== store: investigations


def test_investigation_roundtrip_with_steps(store):
    iid = store.create_investigation(
        fingerprint="u|fs_used|/", host="ubuntu-server", host_role="guest",
        agent_name="investigator", model="claude-test", trigger="daily",
        status="pending_approval", started_at="t0",
    )
    assert iid > 0
    assert store.investigations()[0]["status"] == "pending_approval"

    store.update_investigation(iid, status="running", brief_md="brief text")
    store.add_step(iid, 1, "ssh_diagnostic", args_json='{"command": "df -h"}',
                   result_preview="Filesystem...", result_bytes=1234, blocked=False,
                   duration_ms=250)
    store.add_step(iid, 2, "ssh_diagnostic", args_json='{"command": "rm -rf /"}',
                   result_preview='{"blocked": true}', result_bytes=20, blocked=True,
                   duration_ms=3)
    store.update_investigation(iid, status="complete", report_md="## Summary", n_steps=2,
                               input_tokens=1000, output_tokens=200, finished_at="t1")

    got = store.investigation(iid)
    assert got is not None
    assert got["status"] == "complete" and got["brief_md"] == "brief text"
    assert got["input_tokens"] == 1000 and got["output_tokens"] == 200 and got["n_steps"] == 2
    assert [s["seq"] for s in got["steps"]] == [1, 2]
    assert got["steps"][0]["blocked"] is False and got["steps"][1]["blocked"] is True
    assert json.loads(got["steps"][0]["args_json"])["command"] == "df -h"
    assert got["steps"][0]["duration_ms"] == 250 and got["steps"][0]["result_bytes"] == 1234

    assert store.investigation(9999) is None


def test_investigations_filter_limit_and_counts_by_status(store):
    for i, status in enumerate(["complete", "complete", "declined", "running"]):
        store.create_investigation(host=f"h{i}", status=status, trigger="daily", started_at=f"t{i}")
    assert store.counts_by_status() == {"complete": 2, "declined": 1, "running": 1}
    assert len(store.investigations(limit=2)) == 2
    assert [r["status"] for r in store.investigations(status="complete")] == ["complete"] * 2
    assert store.counts_by_status() == {"complete": 2, "declined": 1, "running": 1}


def test_update_investigation_rejects_unknown_field_and_ignores_empty(store):
    iid = store.create_investigation(host="h", status="running")
    with pytest.raises(ValueError, match="bogus"):
        store.update_investigation(iid, bogus="x")
    store.update_investigation(iid)  # no fields: a no-op, not an error
    assert store.investigation(iid)["status"] == "running"


def test_wal_enabled_and_incidents_untouched(tmp_path):
    s = IncidentStore(tmp_path / "wal.sqlite3")
    mode = s._db.execute("PRAGMA journal_mode").fetchone()[0]
    assert str(mode).lower() == "wal"
    # the pre-existing incident behaviour still works on the same file
    s.upsert([{"fingerprint": "u|mem_used|", "host": "u", "metric": "Mem", "severity": "warning",
               "status": "open", "firstSeen": "a", "lastSeen": "b", "resolvedAt": "",
               "timesSeen": 1, "missedRuns": 0, "description": "d", "investigated": True}])
    assert len(s.open_rows()) == 1
    # and the new tables are empty rather than missing
    assert s.investigations() == [] and s.recent_findings() == [] and s.runs() == []


# =========================================================== runner on_step


async def test_on_step_fires_with_seq_args_and_duration(monkeypatch):
    _patch_client(monkeypatch, [
        _Resp([_ToolUse("a", "stub", {"command": "uptime"})], "tool_use", (10, 5)),
        _Resp([_ToolUse("b", "stub", {"command": "df -h"}),
               _ToolUse("c", "stub", {"command": "free -m"})], "tool_use", (20, 7)),
        _Resp([_Text(SUMMARY_OUTPUT)], "end_turn", (3, 9)),
    ])
    tool = StubTool("stub", result="x" * 900, delay=0.02)
    seen: list[tuple] = []

    def on_step(seq, name, args, result, duration_ms):
        seen.append((seq, name, args, result, duration_ms))

    res = await run_agent(_agent_cfg(), system="s", user_prompt="u", tools=[tool], on_step=on_step)

    assert res.output_text == SUMMARY_OUTPUT and len(res.steps) == 3
    assert res.input_tokens == 33 and res.output_tokens == 21
    assert [s[0] for s in seen] == [1, 2, 3]                       # seq starts at 1
    assert [s[1] for s in seen] == ["stub"] * 3
    assert [s[2]["command"] for s in seen] == ["uptime", "df -h", "free -m"]
    assert all(s[3] == "x" * 900 for s in seen)                    # full result, not the preview
    assert all(s[4] >= 15 for s in seen), seen                     # ~20ms per call, measured
    assert tool.closed is True


async def test_on_step_optional_and_not_fired_for_unknown_tools(monkeypatch):
    """Omitting on_step keeps the old contract; unknown tools still count as steps."""
    _patch_client(monkeypatch, [
        _Resp([_ToolUse("a", "stub", {})], "tool_use"),
        _Resp([_Text(SUMMARY_OUTPUT)], "end_turn"),
    ])
    res = await run_agent(_agent_cfg(), system="s", user_prompt="u", tools=[StubTool("stub")])
    assert len(res.steps) == 1 and res.stop_reason == "end_turn"

    _patch_client(monkeypatch, [
        _Resp([_ToolUse("a", "ghost", {})], "tool_use"),
        _Resp([_Text(SUMMARY_OUTPUT)], "end_turn"),
    ])
    seen = []
    res = await run_agent(_agent_cfg(), system="s", user_prompt="u", tools=[StubTool("stub")],
                          on_step=lambda *a: seen.append(a))
    assert len(seen) == 1 and seen[0][1] == "ghost"
    assert "unknown tool" in seen[0][3]


async def test_on_step_exception_does_not_break_the_loop(monkeypatch):
    _patch_client(monkeypatch, [
        _Resp([_ToolUse("a", "stub", {})], "tool_use"),
        _Resp([_ToolUse("b", "stub", {})], "tool_use"),
        _Resp([_Text(SUMMARY_OUTPUT)], "end_turn"),
    ])
    calls = []

    def boom(seq, *rest):
        calls.append(seq)
        raise RuntimeError("tracking store exploded")

    res = await run_agent(_agent_cfg(), system="s", user_prompt="u",
                          tools=[StubTool("stub")], on_step=boom)
    assert calls == [1, 2]                       # kept being called
    assert res.output_text == SUMMARY_OUTPUT     # and the loop finished normally


async def test_on_step_not_fired_past_the_hard_step_cap(monkeypatch):
    _patch_client(monkeypatch, [
        _Resp([_ToolUse("a", "stub", {})], "tool_use"),
        _Resp([_ToolUse("b", "stub", {})], "tool_use"),
        _Resp([_Text(SUMMARY_OUTPUT)], "end_turn"),
    ])
    seen = []
    res = await run_agent(_agent_cfg(hard_step_cap=1), system="s", user_prompt="u",
                          tools=[StubTool("stub")], on_step=lambda *a: seen.append(a))
    assert [s[0] for s in seen] == [1]           # the budget-exhausted turn is not a step
    assert res.forced_final is True


# ==================================================== step recorder / blocked


def test_is_blocked_detection():
    assert _is_blocked(json.dumps({"ok": True, "blocked": True, "message": "nope"})) is True
    assert _is_blocked(json.dumps({"ok": True, "blocked": False})) is False
    assert _is_blocked("plain text output") is False
    assert _is_blocked("[1, 2, 3]") is False            # JSON, but not an object
    assert _is_blocked(json.dumps({"blocked": "true"})) is False  # string, not the bool


def test_step_recorder_persists_preview_bytes_and_blocked(rt):
    iid = rt.store.create_investigation(host="h", status="running")
    rec = _step_recorder(rt, iid)
    long_result = "y" * 1000
    rec(1, "ssh_diagnostic", {"command": "df -h"}, long_result, 12.7)
    rec(2, "ha_api", {"path": "/api/config"},
        json.dumps({"ok": True, "blocked": True, "path": "/x"}), 4.2)

    steps = rt.store.investigation(iid)["steps"]
    assert len(steps) == 2
    assert steps[0]["result_preview"] == "y" * 400 and steps[0]["result_bytes"] == 1000
    assert steps[0]["blocked"] is False and steps[0]["duration_ms"] == 13   # rounded
    assert steps[1]["blocked"] is True
    assert json.loads(steps[1]["args_json"]) == {"path": "/api/config"}


async def test_on_step_wired_into_the_pipeline(rt, monkeypatch):
    """End to end: a tool call made by the agent lands in investigation_steps."""
    async def fake_run_agent(cfg, *, system, user_prompt, tools, on_step=None):
        on_step(1, "ssh_diagnostic", {"command": "df -h"}, "Filesystem  Size", 11.0)
        on_step(2, "ssh_diagnostic", {"command": "cat /etc/shadow"},
                json.dumps({"ok": True, "blocked": True}), 2.0)
        return AgentResult(SUMMARY_OUTPUT, [], 100, 20)

    monkeypatch.setattr("heim.pipelines.investigate.run_agent", fake_run_agent)
    res = await run_investigation(rt, InvestigationRequest(host="ubuntu-server"))
    assert res is not None

    row = rt.store.investigation(res["id"])
    assert [s["tool"] for s in row["steps"]] == ["ssh_diagnostic"] * 2
    assert [s["blocked"] for s in row["steps"]] == [False, True]


# ==================================================== pipeline status flow


def _stub_agent(monkeypatch, *, output: str = SUMMARY_OUTPUT, steps: int = 2,
                delay: float = 0.0, raises: Exception | None = None, events: list | None = None):
    from heim.agent.runner import AgentStep

    async def fake_run_agent(cfg, *, system, user_prompt, tools, on_step=None):
        if events is not None:
            events.append(("enter", time.monotonic()))
        if delay:
            await asyncio.sleep(delay)
        if events is not None:
            events.append(("exit", time.monotonic()))
        if raises is not None:
            raise raises
        return AgentResult(output, [AgentStep("stub", {}, "") for _ in range(steps)], 1234, 567)

    monkeypatch.setattr("heim.pipelines.investigate.run_agent", fake_run_agent)


async def test_complete_investigation_is_recorded(rt, monkeypatch):
    _stub_agent(monkeypatch, steps=3)
    req = InvestigationRequest(host="ubuntu-server", fingerprint="u|fs_used|/",
                               findings=[{"severity": "warning", "metric": "Filesystem used",
                                          "detail": "92%"}])
    res = await run_investigation(rt, req, trigger="daily")
    assert res is not None

    row = rt.store.investigation(res["id"])
    assert row["status"] == "complete" and row["incomplete_reason"] == ""
    assert row["trigger"] == "daily" and row["agent_name"] == "investigator"
    assert row["model"] == rt.config.agents["investigator"].model
    assert row["host"] == "ubuntu-server" and row["host_role"] == "guest"
    assert row["fingerprint"] == "u|fs_used|/"
    assert (row["input_tokens"], row["output_tokens"], row["n_steps"]) == (1234, 567, 3)
    assert row["started_at"] and row["finished_at"]
    assert "Filesystem used" in row["brief_md"] and "ubuntu-server" in row["brief_md"]
    assert row["report_md"].startswith("## Summary")
    assert rt.store.counts_by_status() == {"complete": 1}


async def test_incomplete_investigation_records_reason(rt, monkeypatch):
    _stub_agent(monkeypatch, output="I will now run df -h to check.")
    res = await run_investigation(rt, InvestigationRequest(host="ubuntu-server"))
    row = rt.store.investigation(res["id"])
    assert row["status"] == "incomplete" and row["incomplete_reason"]
    assert res["incomplete"] is True


async def test_failed_investigation_is_recorded_and_swallowed(rt, monkeypatch):
    _stub_agent(monkeypatch, raises=RuntimeError("anthropic down"))
    res = await run_investigation(rt, InvestigationRequest(host="ubuntu-server"))
    assert res is None                                   # no crash propagated
    row = rt.store.investigations()[0]
    assert row["status"] == "failed"
    assert "RuntimeError: anthropic down" in row["incomplete_reason"]
    assert row["finished_at"]


class FakeTelegram:
    """Answers ``ask`` from a per-host script; records what it was asked."""

    def __init__(self, answers: dict):
        self.answers = answers      # host -> list of answers (or awaitables)
        self.asked: list[str] = []
        self.chunks: list[str] = []

    def _host(self, text: str) -> str:
        return next((h for h in self.answers if h in text), "")

    async def ask(self, text: str, **kw):
        self.asked.append(text)
        script = self.answers.get(self._host(text)) or [None]
        answer = script.pop(0) if script else None
        if callable(answer):
            answer = await answer()
        return answer

    async def send_chunks(self, text: str) -> None:
        self.chunks.append(text)

    async def notify(self, text: str) -> None:
        pass


async def test_declined_investigation_status_and_dispatch_lock(rt, monkeypatch):
    _stub_agent(monkeypatch)
    rt.dry_run = False
    rt.telegram = FakeTelegram({"ubuntu-server": [False]})
    rt.store.upsert([{"fingerprint": "u|fs_used|/", "host": "ubuntu-server", "metric": "fs",
                      "severity": "warning", "status": "open", "firstSeen": "a", "lastSeen": "b",
                      "resolvedAt": "", "timesSeen": 1, "missedRuns": 0, "description": "d",
                      "investigated": True}])

    res = await run_investigation(rt, InvestigationRequest(host="ubuntu-server",
                                                           fingerprint="u|fs_used|/"))
    assert res is None
    row = rt.store.investigations()[0]
    assert row["status"] == "declined" and row["finished_at"] and row["n_steps"] == 0
    assert rt.store.open_rows()[0]["investigated"] is False   # re-proposed next run


async def test_timed_out_approval_records_declined(rt, monkeypatch):
    _stub_agent(monkeypatch)
    rt.dry_run = False
    rt.telegram = FakeTelegram({"ubuntu-server": [None]})     # None = timeout
    assert await run_investigation(rt, InvestigationRequest(host="ubuntu-server")) is None
    assert rt.store.investigations()[0]["status"] == "declined"


async def test_outcome_resolved_and_needs_human(rt, monkeypatch):
    _stub_agent(monkeypatch)
    rt.dry_run = False

    rt.telegram = FakeTelegram({"ubuntu-server": [True, True]})   # approve, then resolved
    res = await run_investigation(rt, InvestigationRequest(host="ubuntu-server"))
    row = rt.store.investigation(res["id"])
    assert row["status"] == "resolved" and row["outcome"] == "resolved"

    rt.telegram = FakeTelegram({"ubuntu-server": [True, False]})  # approve, then needs human
    res = await run_investigation(rt, InvestigationRequest(host="ubuntu-server",
                                                           fingerprint="u|x|"))
    row = rt.store.investigation(res["id"])
    assert row["status"] == "needs_human" and row["outcome"] == "needs_human"

    rt.telegram = FakeTelegram({"ubuntu-server": [True, None]})   # approve, outcome times out
    res = await run_investigation(rt, InvestigationRequest(host="ubuntu-server"))
    row = rt.store.investigation(res["id"])
    assert row["status"] == "needs_human" and row["outcome"] == "timeout"


# ======================================================= the concurrency cap


async def test_investigations_serialize_under_the_cap(rt, monkeypatch):
    """max_concurrent_investigations=1 -> the agent phases must not overlap."""
    rt.config.settings.max_concurrent_investigations = 1
    events: list[tuple[str, float]] = []
    _stub_agent(monkeypatch, delay=0.05, events=events)

    await asyncio.gather(
        run_investigation(rt, InvestigationRequest(host="ubuntu-server")),
        run_investigation(rt, InvestigationRequest(host="home-assistant", host_role="ha-guest")),
    )
    assert [e[0] for e in events] == ["enter", "exit", "enter", "exit"]
    assert events[1][1] <= events[2][1]                     # first exits before second enters
    assert len(rt.store.investigations()) == 2
    assert rt.store.counts_by_status() == {"complete": 2}


async def test_cap_of_two_allows_overlap(rt, monkeypatch):
    """Control for the test above: the serialization comes from the cap, not
    from the code being accidentally sequential."""
    rt.config.settings.max_concurrent_investigations = 2
    events: list[tuple[str, float]] = []
    _stub_agent(monkeypatch, delay=0.05, events=events)

    await asyncio.gather(
        run_investigation(rt, InvestigationRequest(host="ubuntu-server")),
        run_investigation(rt, InvestigationRequest(host="home-assistant", host_role="ha-guest")),
    )
    assert [e[0] for e in events] == ["enter", "enter", "exit", "exit"]


async def test_semaphore_is_one_per_runtime_and_bounded(rt):
    sem = rt.investigation_slot()
    assert rt.investigation_slot() is sem                   # created once, lazily
    assert sem._value == rt.config.settings.max_concurrent_investigations == 2


async def test_approval_wait_does_not_hold_a_slot(rt, monkeypatch):
    """A six-hour approval wait must not occupy a concurrency slot."""
    rt.config.settings.max_concurrent_investigations = 1
    rt.dry_run = False
    in_agent = asyncio.Event()
    release_agent = asyncio.Event()

    async def fake_run_agent(cfg, *, system, user_prompt, tools, on_step=None):
        in_agent.set()
        await release_agent.wait()
        return AgentResult(SUMMARY_OUTPUT, [], 1, 1)

    monkeypatch.setattr("heim.pipelines.investigate.run_agent", fake_run_agent)

    answer_b = asyncio.Event()

    async def wait_then_decline():
        await answer_b.wait()                   # a human taking their time
        return False

    tg = FakeTelegram({
        "ubuntu-server": [True, True],          # approved at once, then resolved
        "home-assistant": [wait_then_decline],  # still being asked while A runs
    })
    rt.telegram = tg

    a = asyncio.create_task(run_investigation(rt, InvestigationRequest(host="ubuntu-server")))
    await asyncio.wait_for(in_agent.wait(), 2)              # A holds the only slot
    b = asyncio.create_task(run_investigation(
        rt, InvestigationRequest(host="home-assistant", host_role="ha-guest")))
    for _ in range(50):                                     # let B reach its approval ask
        await asyncio.sleep(0.005)
        if any("home-assistant" in t for t in tg.asked):
            break

    assert any("home-assistant" in t for t in tg.asked), "B never got to ask for approval"
    b_row = next(r for r in rt.store.investigations() if r["host"] == "home-assistant")
    assert b_row["status"] == "pending_approval"             # waiting on a human, not on the cap

    release_agent.set()
    answer_b.set()
    await asyncio.gather(a, b)
    statuses = {r["host"]: r["status"] for r in rt.store.investigations()}
    assert statuses == {"ubuntu-server": "resolved", "home-assistant": "declined"}


# ================================================ pipeline run-row insertion


async def test_poller_records_a_run_only_when_something_changed(rt, monkeypatch):
    from heim.incidents.types import PollerDecision
    from heim.pipelines import poller

    async def no_alerts(_url):
        return {"status": "success", "data": {"alerts": []}}

    monkeypatch.setattr(poller, "_fetch_alerts", no_alerts)

    monkeypatch.setattr(poller, "diff_and_decide", lambda *a, **k: PollerDecision())
    assert await poller.run_poll(rt, dispatch_concurrently=False) == {
        "upserts": 0, "dispatches": 0, "notifications": 0, "loki_events": 0, "state_changed": False}
    assert rt.store.runs() == []                             # silent no-op: nothing recorded

    monkeypatch.setattr(poller, "diff_and_decide",
                        lambda *a, **k: PollerDecision(state_changed=True))
    await poller.run_poll(rt, dispatch_concurrently=False)
    rows = rt.store.runs()
    assert len(rows) == 1 and rows[0]["kind"] == "poll"
    assert rows[0]["overall"] == "" and rows[0]["model_used"] == ""
    assert json.loads(rows[0]["counts_json"])["state_changed"] is True
    assert rows[0]["run_at"] and rows[0]["duration_s"] >= 0


def _daily_payload(rows: list[dict]) -> dict:
    return {
        "generatedAt": "2026-09-18T07:00:00.000+02:00",
        "windowDays": 3,
        "hosts": ["ubuntu-server"],
        "counts": {"crit": 0, "warn": 1, "naQueries": 0},
        "overall": "warning",
        "categories": {"Memory": rows},
        "topAlerts": [],
    }


async def test_daily_records_the_run_and_its_findings(rt, monkeypatch):
    from heim.incidents.reconcile import fingerprint_for
    from heim.pipelines import daily

    row = {"host": "ubuntu-server", "label": "", "name": "Memory used", "unit": "%",
           "qid": "mem_used", "category": "Memory", "current": 91.0, "avg": 80.0,
           "min": 70.0, "max": 91.0, "day3d": [70.0, 80.0, 91.0], "changePct": 30.0,
           "flag": "warn"}
    payload = _daily_payload([row])
    finding = {"severity": "warning", "host": "ubuntu-server", "metric": "Memory used",
               "trend": "rising", "summary": "memory climbing", "detail": "91% and rising",
               "recommendation": "cap the container"}
    analysis = {"overallHealth": "warning", "headline": "memory pressure",
                "executiveSummary": "mem up 30%", "categories": {},
                "findings": [finding], "watchlist": []}

    async def fake_fetch(base, qdefs, window):
        return []

    async def fake_analyst(cfg, system, user):
        return json.dumps(analysis), "model-x"

    dispatched: list = []

    async def fake_dispatch(rt_, items, *, concurrent, trigger="manual"):
        dispatched.append((len(items), trigger))

    monkeypatch.setattr(daily, "_fetch_query_ranges", fake_fetch)
    monkeypatch.setattr(daily, "aggregate", lambda *a, **k: {"payload": payload})
    monkeypatch.setattr(daily, "analyst_complete", fake_analyst)
    monkeypatch.setattr(daily, "dispatch_all", fake_dispatch)

    res = await daily.run_daily(rt, dispatch_concurrently=False)
    assert res["overall"] == "warning"

    runs = rt.store.runs()
    assert len(runs) == 1
    assert runs[0]["kind"] == "daily" and runs[0]["overall"] == "warning"
    assert runs[0]["model_used"] == "model-x" and runs[0]["duration_s"] >= 0
    assert "new" in json.loads(runs[0]["counts_json"])

    stored = rt.store.recent_findings()
    assert len(stored) == 1
    f = stored[0]
    assert f["run_id"] == runs[0]["id"] and f["source"] == "daily"
    assert (f["host"], f["metric"], f["severity"], f["trend"]) == (
        "ubuntu-server", "Memory used", "warning", "rising")
    assert f["summary"] == "memory climbing" and f["recommendation"] == "cap the container"
    assert f["fingerprint"] == fingerprint_for(finding, [row])
    assert f["fingerprint"].startswith("ubuntu-server|mem_used|")
    assert f["verdict"] is None

    # the trigger is threaded through to the investigations
    assert dispatched and dispatched[0][1] == "daily"


async def test_poller_threads_the_poller_trigger(rt, monkeypatch):
    from heim.incidents.types import PollerDecision
    from heim.pipelines import poller

    async def no_alerts(_url):
        return {"status": "success", "data": {"alerts": []}}

    dispatched: list = []

    async def fake_dispatch(rt_, items, *, concurrent, trigger="manual"):
        dispatched.append((len(items), trigger))

    monkeypatch.setattr(poller, "_fetch_alerts", no_alerts)
    monkeypatch.setattr(poller, "diff_and_decide",
                        lambda *a, **k: PollerDecision(dispatches=[{"host": "ubuntu-server"}]))
    monkeypatch.setattr(poller, "dispatch_all", fake_dispatch)

    await poller.run_poll(rt, dispatch_concurrently=False)
    assert dispatched == [(1, "poller")]
    assert [r["kind"] for r in rt.store.runs()] == ["poll"]


async def test_poller_aborted_records_nothing(rt, monkeypatch):
    from heim.pipelines import poller

    async def dead(_url):
        return {"status": "error", "error": "boom"}

    monkeypatch.setattr(poller, "_fetch_alerts", dead)
    assert await poller.run_poll(rt) == {"aborted": "prometheus unreachable"}
    assert rt.store.runs() == []
