"""Investigation plumbing for grouped (Uptime Kuma) outages.

One investigation per host group: findings carry fingerprints, a pending
investigation can absorb later outages, and a decline unlocks every incident
the group covered. Old single-finding callers must behave exactly as before.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from heim.agent.runner import AgentResult, AgentStep
from heim.config import load_config
from heim.incidents.store import IncidentStore
from heim.pipelines.investigate import (
    InvestigationRequest,
    _approval_text,
    _lock_fingerprints,
    extend_pending_investigation,
    recovered_note,
    request_from_dispatch,
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
HOST = "ubuntu-server"


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


def _stub_agent(monkeypatch) -> list[str]:
    prompts: list[str] = []

    async def fake_run_agent(cfg, *, system, user_prompt, tools, on_step=None,
                             collect_transcript=False):
        prompts.append(user_prompt)
        return AgentResult(SUMMARY_OUTPUT, [AgentStep("stub", {}, "")], 10, 5)

    monkeypatch.setattr("heim.pipelines.investigate.run_agent", fake_run_agent)
    return prompts


def _fp(name: str) -> str:
    return f"{HOST}|uptime_down|{name}"


def _finding(name: str) -> dict:
    return {"severity": "critical", "host": HOST, "metric": name, "trend": "",
            "fingerprint": _fp(name), "recommendation": "",
            "detail": f"Uptime Kuma check '{name}' is down. Find which container serves it."}


def _seed(rt, *names, status="open") -> None:
    rt.store.upsert([{
        "fingerprint": _fp(n), "host": HOST, "metric": n, "severity": "critical",
        "status": status, "firstSeen": "2026-11-01T10:00:00", "lastSeen": "2026-11-01T10:00:00",
        "resolvedAt": "", "timesSeen": 1, "missedRuns": 0,
        "description": f"[uptime] {n} down", "investigated": True,
    } for n in names])


def _req(*names) -> InvestigationRequest:
    return InvestigationRequest(host=HOST, fingerprint=_fp(names[0]),
                                findings=[_finding(n) for n in names])


def test_approval_text_leads_with_the_headline():
    req = InvestigationRequest(host=HOST, headline="🔴 Down on ubuntu-server: n8n (10.0.0.10:5678)")
    text = _approval_text(req, "1. finding")
    assert text.startswith("🔴 Down on ubuntu-server: n8n (10.0.0.10:5678)\n\n🔍 Investigation approval")
    plain = _approval_text(InvestigationRequest(host=HOST), "1. finding")
    assert plain.startswith("🔍 Investigation approval")


def test_request_from_dispatch_keeps_group_findings_and_headline(rt):
    item = {"host": HOST, "fingerprint": _fp("n8n"), "headline": "H",
            "findings": [_finding("n8n"), _finding("grafana")]}
    req = request_from_dispatch(item, rt)
    assert [f["metric"] for f in req.findings] == ["n8n", "grafana"]
    assert req.headline == "H"

    old = request_from_dispatch({"host": HOST, "fingerprint": "x|y|z", "metric": "m",
                                 "severity": "warning", "description": "d"}, rt)
    assert len(old.findings) == 1 and old.findings[0]["detail"] == "d"
    assert old.headline == ""


async def test_extend_pending_investigation_merges_and_rebuilds_the_brief(rt, monkeypatch):
    _stub_agent(monkeypatch)
    inv = rt.store.create_investigation(
        host=HOST, host_role="guest", fingerprint=_fp("n8n"), status="pending_approval",
        findings_json=json.dumps([_finding("n8n")]), brief_md="old")
    assert extend_pending_investigation(rt, inv, [_finding("n8n"), _finding("grafana")]) is True
    row = rt.store.investigation(inv)
    stored = json.loads(row["findings_json"])
    assert [f["metric"] for f in stored] == ["n8n", "grafana"]
    assert "n8n" in row["brief_md"] and "grafana" in row["brief_md"]

    running = rt.store.create_investigation(
        host=HOST, host_role="guest", fingerprint=_fp("n8n"), status="running",
        findings_json=json.dumps([_finding("n8n")]), brief_md="old")
    assert extend_pending_investigation(rt, running, [_finding("grafana")]) is False
    row = rt.store.investigation(running)
    assert row["brief_md"] == "old" and len(json.loads(row["findings_json"])) == 1


async def test_a_declined_group_unlocks_every_incident(rt, monkeypatch):
    _stub_agent(monkeypatch)
    _seed(rt, "a", "b", "c")
    rt.dry_run = False

    async def fake_await(rt_, inv_id, text, timeout_s, *, send_prompt=True):
        assert extend_pending_investigation(rt_, inv_id, [_finding("c")])
        return False, "test"

    monkeypatch.setattr("heim.pipelines.investigate._await_approval", fake_await)
    assert await run_investigation(rt, _req("a", "b"), require_approval=True) is None
    for n in "abc":
        assert rt.store.incident(_fp(n))["investigated"] is False


async def test_an_approved_run_sees_findings_folded_in_while_waiting(rt, monkeypatch):
    prompts = _stub_agent(monkeypatch)
    _seed(rt, "a", "b", "c")
    rt.dry_run = False

    async def fake_await(rt_, inv_id, text, timeout_s, *, send_prompt=True):
        extend_pending_investigation(rt_, inv_id, [_finding("c-service")])
        return True, "test"

    monkeypatch.setattr("heim.pipelines.investigate._await_approval", fake_await)
    assert await run_investigation(rt, _req("a", "b"), require_approval=True) is not None
    assert "c-service" in prompts[0]


async def test_the_brief_notes_checks_that_recovered_before_approval(rt, monkeypatch):
    prompts = _stub_agent(monkeypatch)
    _seed(rt, "n8n", "grafana")
    rt.dry_run = False

    async def fake_await(rt_, inv_id, text, timeout_s, *, send_prompt=True):
        rt_.store.set_incident_status(_fp("n8n"), "resolved")
        return True, "test"

    monkeypatch.setattr("heim.pipelines.investigate._await_approval", fake_await)
    await run_investigation(rt, _req("n8n", "grafana"), require_approval=True)
    assert "these checks have recovered: n8n. Find out why they went down." in prompts[0]
    assert "grafana." not in prompts[0].split("recovered:")[1]


def test_recovered_note_and_lock_fingerprints(rt):
    _seed(rt, "a", "b")
    assert recovered_note(rt.store, [_finding("a"), _finding("b")]) == ""
    rt.store.set_incident_status(_fp("b"), "resolved")
    rt.store.set_incident_status(_fp("a"), "resolved")
    assert recovered_note(rt.store, [_finding("a"), _finding("b"), {"metric": "x"}]) == (
        "\n\nNote: since this investigation was proposed, these checks have recovered: "
        "a, b. Find out why they went down.")
    req = _req("a", "b")
    assert _lock_fingerprints(req) == [_fp("a"), _fp("b")]
    assert _lock_fingerprints(InvestigationRequest(host=HOST, fingerprint="f",
                                                   findings=[{"metric": "m"}])) == ["f"]


async def test_old_investigations_behave_as_before(rt, monkeypatch):
    _stub_agent(monkeypatch)
    rt.dry_run = False
    calls: list[str] = []
    monkeypatch.setattr(rt.store, "set_investigated", lambda fp, v: calls.append(fp))

    async def fake_await(rt_, inv_id, text, timeout_s, *, send_prompt=True):
        assert text.startswith("🔍 Investigation approval")
        return False, "test"

    monkeypatch.setattr("heim.pipelines.investigate._await_approval", fake_await)
    req = InvestigationRequest(host=HOST, fingerprint="h|q|n",
                               findings=[{"severity": "warning", "metric": "m", "detail": "d"}])
    assert await run_investigation(rt, req, require_approval=True) is None
    assert calls == ["h|q|n"]
