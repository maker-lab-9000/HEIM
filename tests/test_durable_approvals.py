"""Durable approvals (roadmap §5.8): an approval waits until a human reacts.

Removing the timeout on its own would make things worse, so three mechanisms
are pinned here together — the indefinite wait, the crash sweep that now
spares parked rows, and buttons whose meaning survives the process that sent
them. Take away any one and an approval still dies quietly.
"""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest

from heim.agent.runner import AgentResult, AgentStep
from heim.config import load_config
from heim.incidents.store import IncidentStore
from heim.pipelines.investigate import (
    InvestigationRequest,
    rearm_pending_approvals,
    request_from_investigation,
    run_investigation,
)
from heim.runtime import Runtime, approval_sink

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


@pytest.fixture()
def store(tmp_path) -> IncidentStore:
    return IncidentStore(tmp_path / "t.sqlite3")


@pytest.fixture()
def rt(tmp_path, monkeypatch) -> Runtime:
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    cfg.settings.loki = None
    cfg.settings.email = None
    cfg.settings.home_assistant = None
    cfg.settings.threshold_detection = False
    return Runtime(config=cfg, store=IncidentStore(tmp_path / "rt.sqlite3"),
                   dry_run=True, out_dir=tmp_path / "out")


def _stub_agent(monkeypatch):
    async def fake_run_agent(cfg, *, system, user_prompt, tools, on_step=None,
                             collect_transcript=False):
        return AgentResult(SUMMARY_OUTPUT, [AgentStep("stub", {}, "")], 10, 5)

    monkeypatch.setattr("heim.pipelines.investigate.run_agent", fake_run_agent)


async def _wait_pending(rt, timeout: float = 3.0) -> dict:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        rows = rt.store.investigations(status="pending_approval")
        if rows:
            return rows[0]
        await asyncio.sleep(0.01)
    raise AssertionError("no investigation reached pending_approval")


# ================================================= A. indefinite is first-class


def test_zero_hours_means_no_deadline():
    """The config, not each caller, decides what 'no timeout' means."""
    from heim.config import ApprovalsCfg

    assert ApprovalsCfg(approve_timeout_hours=0).approve_timeout_s is None
    assert ApprovalsCfg(approve_timeout_hours=6).approve_timeout_s == 6 * 3600
    assert ApprovalsCfg(outcome_timeout_hours=0).outcome_timeout_s is None
    assert ApprovalsCfg(outcome_timeout_hours=8).outcome_timeout_s == 8 * 3600
    # shipped default: approvals park, outcome confirms still expire
    assert ApprovalsCfg().approve_timeout_s is None
    assert ApprovalsCfg().outcome_timeout_s == 8 * 3600


async def test_indefinite_approval_never_expires(rt, monkeypatch):
    """Drive well past the old 6h deadline: still pending, still waiting."""
    monkeypatch.setattr("heim.pipelines.investigate.APPROVAL_POLL_SECONDS", 0.01)
    _stub_agent(monkeypatch)
    rt.dry_run = False
    rt.telegram = None
    rt.config.settings.approvals.approve_timeout_hours = 0

    task = asyncio.create_task(run_investigation(rt, InvestigationRequest(host="ubuntu-server")))
    row = await _wait_pending(rt)

    # the wait is a real loop, so "past the deadline" means many poll cycles,
    # not a wall-clock sleep — 60 of them is 100x the old code's patience here
    for _ in range(60):
        await asyncio.sleep(0)
    assert not task.done()
    assert rt.store.investigation(row["id"])["status"] == "pending_approval"

    rt.store.set_approval_decision(row["id"], "approve")   # it still resolves
    res = await asyncio.wait_for(task, 5)
    assert res is not None and rt.store.investigation(row["id"])["status"] == "complete"


async def test_positive_timeout_still_expires(rt, monkeypatch):
    """The old behaviour must survive for anyone who wants a deadline."""
    monkeypatch.setattr("heim.pipelines.investigate.APPROVAL_POLL_SECONDS", 0.01)
    _stub_agent(monkeypatch)
    rt.dry_run = False
    rt.telegram = None
    rt.config.settings.approvals.approve_timeout_hours = 0.05 / 3600   # 50 ms

    assert await asyncio.wait_for(
        run_investigation(rt, InvestigationRequest(host="ubuntu-server")), 5) is None
    row = rt.store.investigations()[0]
    assert row["status"] == "declined" and row["approval_decision"] == "timeout"


# ==================================================== C. restart re-arms


def test_sweep_spares_parked_approvals_but_fails_running(store):
    """One test, because the whole point is the distinction between them."""
    running = store.create_investigation(host="a", status="running")
    parked = store.create_investigation(host="b", status="pending_approval")

    store.sweep_interrupted()

    by_id = {r["id"]: r for r in store.investigations()}
    assert by_id[running]["status"] == "failed"
    assert by_id[parked]["status"] == "pending_approval"


def test_request_from_investigation_round_trips(rt):
    inv_id = rt.store.create_investigation(
        host="homelab", host_role="hypervisor", fingerprint="homelab|pve_cpu|",
        model="claude-test", retry_of=7, status="pending_approval",
        findings_json='[{"metric": "CPU", "severity": "critical"}]')
    req = request_from_investigation(rt.store.investigation(inv_id))

    assert req.host == "homelab" and req.host_role == "hypervisor"
    assert req.fingerprint == "homelab|pve_cpu|" and req.retry_of == 7
    assert req.findings == [{"metric": "CPU", "severity": "critical"}]
    # the model is replayed as an override, so a re-armed run uses the model
    # the operator was told about even if the configured default moved
    assert req.model_override == "claude-test"


def test_request_from_investigation_survives_unreadable_findings(rt):
    inv_id = rt.store.create_investigation(host="a", status="pending_approval",
                                           findings_json="{not json")
    assert request_from_investigation(rt.store.investigation(inv_id)).findings == []


async def test_restart_rearms_and_a_later_decision_resolves_it(rt, monkeypatch):
    """A fresh runtime over the same store resumes the parked approval.

    This is the whole failure the plan is about: before, a deploy turned every
    parked approval into a silently failed investigation behind a Telegram
    message whose buttons no longer did anything.
    """
    monkeypatch.setattr("heim.pipelines.investigate.APPROVAL_POLL_SECONDS", 0.01)
    _stub_agent(monkeypatch)
    rt.dry_run = False
    rt.telegram = None

    inv_id = rt.store.create_investigation(
        host="ubuntu-server", status="pending_approval", brief_md="the original brief",
        started_at=rt.now_iso(), model="claude-test", trigger="dashboard")

    rt.store.sweep_interrupted()                     # the restart
    assert rearm_pending_approvals(rt) == 1

    await _wait_pending(rt)
    rt.store.set_approval_decision(inv_id, "approve")

    loop = asyncio.get_running_loop()
    deadline = loop.time() + 5
    while loop.time() < deadline:
        if rt.store.investigation(inv_id)["status"] == "complete":
            break
        await asyncio.sleep(0.01)

    row = rt.store.investigation(inv_id)
    assert row["status"] == "complete"
    assert row["trigger"] == "dashboard"             # re-arming is not a new trigger
    assert not rt.store.investigations(status="pending_approval")
    # exactly one investigation: re-arming resumes the row, never clones it
    assert len(rt.store.investigations()) == 1


def test_rearm_is_a_noop_with_nothing_parked(rt):
    assert rearm_pending_approvals(rt) == 0


# ============================== B. buttons carry the id, resolved via the store


def test_approval_sink_writes_the_decision(store):
    inv_id = store.create_investigation(host="a", status="pending_approval")
    sink = approval_sink(store)

    assert sink(f"inv:{inv_id}", True) is True
    assert store.approval_decision(inv_id) == "approve"


def test_approval_sink_declines(store):
    inv_id = store.create_investigation(host="a", status="pending_approval")
    assert approval_sink(store)(f"inv:{inv_id}", False) is True
    assert store.approval_decision(inv_id) == "decline"


def test_approval_sink_ignores_taps_that_no_longer_apply(store):
    """Already decided, gone, an outcome tap, or a legacy random uid."""
    decided = store.create_investigation(host="a", status="complete")
    sink = approval_sink(store)

    assert sink(f"inv:{decided}", True) is False
    assert store.approval_decision(decided) == ""     # unchanged
    assert sink("inv:999999", True) is False          # unknown investigation
    assert sink("out:1", True) is False               # outcome confirms are in-memory
    assert sink("a3f19c2b", True) is False            # pre-§5.8 random uid


async def test_a_tap_resolves_an_approval_in_another_process(rt, tmp_path, monkeypatch):
    """The tap writes the store, so a waiter that never made the button sees it.

    Two stores over one database file stand in for two daemon processes: the
    one whose Telegram consumer receives the tap, and the one actually waiting.
    """
    monkeypatch.setattr("heim.pipelines.investigate.APPROVAL_POLL_SECONDS", 0.01)
    _stub_agent(monkeypatch)
    rt.dry_run = False
    rt.telegram = None

    task = asyncio.create_task(run_investigation(rt, InvestigationRequest(host="ubuntu-server")))
    row = await _wait_pending(rt)

    other = IncidentStore(tmp_path / "rt.sqlite3")    # the consumer's own handle
    # exactly what Telegram._resolve() does with callback_data "heim:inv:<id>:y"
    assert approval_sink(other)(f"inv:{row['id']}", True) is True

    res = await asyncio.wait_for(task, 5)
    assert res is not None
    assert rt.store.investigation(row["id"])["approval_decision"] == "approve"


class _Recorder:
    """A Telegram stand-in that records the callback_data it would send."""

    def __init__(self):
        self.markups: list[dict] = []
        self.keys: list[str] = []

    async def ask(self, text, *, yes="y", no="n", timeout_s=0, key=""):
        self.keys.append(key)
        await asyncio.sleep(3600)        # never answers; the store decides

    async def send_chunks(self, text):
        pass

    async def notify(self, text):
        pass


async def test_approval_buttons_carry_the_investigation_id(rt, monkeypatch):
    monkeypatch.setattr("heim.pipelines.investigate.APPROVAL_POLL_SECONDS", 0.01)
    _stub_agent(monkeypatch)
    rt.dry_run = False
    rt.telegram = _Recorder()

    task = asyncio.create_task(run_investigation(rt, InvestigationRequest(host="ubuntu-server")))
    row = await _wait_pending(rt)
    rt.store.set_approval_decision(row["id"], "approve")
    await asyncio.wait_for(task, 5)

    assert rt.telegram.keys[0] == f"inv:{row['id']}"


async def test_a_rearmed_approval_does_not_resend_the_prompt(rt, monkeypatch):
    """The original message's buttons still work — a second copy is noise."""
    monkeypatch.setattr("heim.pipelines.investigate.APPROVAL_POLL_SECONDS", 0.01)
    _stub_agent(monkeypatch)
    rt.dry_run = False
    rt.telegram = _Recorder()

    inv_id = rt.store.create_investigation(host="ubuntu-server", status="pending_approval",
                                           brief_md="b", started_at=rt.now_iso())
    assert rearm_pending_approvals(rt) == 1
    for _ in range(10):
        await asyncio.sleep(0)

    assert rt.telegram.keys == []                     # nothing re-sent
    rt.store.set_approval_decision(inv_id, "approve")
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 5
    while loop.time() < deadline and rt.store.investigation(inv_id)["status"] != "complete":
        await asyncio.sleep(0.01)
    assert rt.store.investigation(inv_id)["status"] == "complete"


# ====================================================== telegram tap plumbing


def test_resolve_prefers_the_store_and_reports_a_stale_tap():
    from heim.channels.telegram import Telegram

    tg = Telegram("t", 1)
    recorded: list[tuple[str, bool]] = []
    tg.on_decision = lambda key, ok: (recorded.append((key, ok)), True)[1]

    assert tg._resolve("inv:4", True) == "Approved"
    assert tg._resolve("inv:4", False) == "Declined"
    assert recorded == [("inv:4", True), ("inv:4", False)]

    tg.on_decision = lambda key, ok: False            # nothing to record
    assert "No longer pending" in tg._resolve("inv:4", True)


def test_resolve_survives_a_raising_sink():
    """A broken store write must not kill the single update consumer."""
    from heim.channels.telegram import Telegram

    tg = Telegram("t", 1)

    def boom(key, ok):
        raise RuntimeError("db is gone")

    tg.on_decision = boom
    assert "No longer pending" in tg._resolve("inv:4", True)


def test_resolve_still_completes_an_in_memory_future():
    """Same-process asks answer instantly instead of after a poll interval."""
    from heim.channels.telegram import Telegram

    async def go():
        tg = Telegram("t", 1)
        fut = asyncio.get_running_loop().create_future()
        tg._pending["inv:9"] = fut
        assert tg._resolve("inv:9", True) == "Approved"
        assert await fut is True

    asyncio.run(go())
