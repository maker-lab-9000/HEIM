"""End-to-end pipeline with stubbed collectors and a stubbed model."""
import json
import shutil
from pathlib import Path

import pytest

from heim.agent.runner import AgentResult, AgentStep
from heim.config import load_config
from heim.incidents.store import IncidentStore
from heim.pipelines import security_audit as pipe
from heim.runtime import Runtime
from heim.security.types import Evidence, EvidenceBundle

ROOT = Path(__file__).resolve().parent.parent
USERS = [{"userid": "root@pam", "enable": 1}, {"userid": "auditor@pve", "enable": 1}]
GOOD = ("## Summary\n\nOne new critical item.\n\n## Priorities\n\n1. HA core\n\n## What changed\n\nnew: 1\n\n"
        "## Recommended remediation\n\n1. Update HA core.\n\n## Confidence\n\nhigh — the table is unambiguous.\n\n"
        "## Tooling feedback\n\nsecurity_audit: check PVE token expiry\n")


@pytest.fixture()
def rt(tmp_path, monkeypatch):
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    cfg.settings.loki = None
    cfg.settings.email = None
    cfg.settings.home_assistant = None
    return Runtime(config=cfg, store=IncidentStore(tmp_path / "rt.sqlite3"), dry_run=True, out_dir=tmp_path / "out")


def _bundle(*, tfa_empty=True, ha_public=True):
    items = [
        Evidence("pve.access_users", "ok", body=USERS),
        Evidence("pve.access_tfa", "empty" if tfa_empty else "ok", body=[] if tfa_empty else [{"userid": "root@pam", "entries": [{"type": "totp"}]}]),
        Evidence("ha.config", "ok", body={"safe_mode": False, "recovery_mode": False,
                                          "external_url": "https://x.example-dyndns.net:8123" if ha_public else "http://10.0.0.3:8123"}),
        Evidence("ha.states", "ok", body=[{"entity_id": "update.home_assistant_core_update", "state": "on",
                                           "attributes": {"title": "Home Assistant Core", "installed_version": "2026.9.1", "latest_version": "2026.9.3"}}]),
        Evidence("prom.reboot_required", "ok", body=[{"metric": {"instance": "10.0.0.10:9100"}, "value": [1, "0"]}]),
    ]
    return EvidenceBundle(items={e.key: e for e in items}, collected_at="t")


def _stub_collect(monkeypatch, bundle):
    async def fake(cfg, cat, *, now_iso):
        return bundle
    monkeypatch.setattr(pipe, "collect_evidence", fake)


def _stub_agent(monkeypatch, *, output=GOOD, stop_reason="end_turn", raises=None, steps=1):
    seen = {}

    async def fake_run_agent(cfg, *, system, user_prompt, tools, on_step=None, collect_transcript=False):
        seen.update(cfg=cfg, system=system, user_prompt=user_prompt, tools=[t.name for t in tools])
        if raises is not None:
            raise raises
        if on_step is not None:
            for i in range(steps):
                on_step(i + 1, "prometheus_query", {"promql": "up"}, '{"ok": true}', 12.0, 100, 20)
        return AgentResult(output, [AgentStep("prometheus_query", {}, "")] * steps, 5000, 900, stop_reason)
    monkeypatch.setattr(pipe, "run_agent", fake_run_agent)
    return seen


async def test_full_run_persists_reports_and_delivers(rt, monkeypatch, tmp_path):
    _stub_collect(monkeypatch, _bundle())
    seen = _stub_agent(monkeypatch)
    res = await pipe.run_security_audit(rt)
    assert res["assessment"] == "complete" and res["new"] == 3 and res["persisting"] == 0
    # store: run + findings + investigation, no double-counted tokens
    run = rt.store.runs(limit=1, kind="security_audit")[0]
    assert run["id"] == res["run_id"] and run["overall"] == "critical" and run["input_tokens"] == 0
    rows = rt.store.findings_for_run(run["id"])
    assert {r["fingerprint"] for r in rows} == {"homelab|pve.tfa_missing|root@pam", "home-assistant|ha.core_update_exposed|home-assistant",
                                             "home-assistant|ha.pending_updates_sensitive|update.home_assistant_core_update"}
    assert all(r["source"] == "security_audit" and r["trend"] == "new" for r in rows)
    inv = rt.store.investigation(res["investigation_id"])
    assert inv["agent_name"] == "security_auditor" and inv["trigger"] == "security_audit" and inv["host"] == "all"
    assert inv["status"] == "complete" and inv["input_tokens"] == 5000 and inv["cost"] > 0 and inv["n_steps"] == 1
    assert inv["report_md"].startswith("## Summary") and "## AI assessment" in inv["report_md"] and "### Priorities" in inv["report_md"]
    assert len(rt.store.steps(inv["id"])) == 1
    assert rt.store.tool_feedback(inv["id"])[0]["tool"] == "security_audit"
    # the model saw the diff and the table, and held no SSH tool
    assert "3 new" in seen["user_prompt"] and "0 resolved" in seen["user_prompt"]
    assert "ha.core_update_exposed" in seen["user_prompt"] and "ssh_diagnostic" not in seen["tools"]
    # delivery: dry-run email written, subject reflects counts
    assert res["subject"].startswith("🛡️ Weekly Security Audit — 3 findings, 3 new, 0 resolved")
    assert list((tmp_path / "out").glob("*.html"))
    assert res["unavailable"] > 30            # everything not in the stub bundle is a coverage gap, not a pass


async def test_second_run_diffs_and_resolves(rt, monkeypatch):
    _stub_collect(monkeypatch, _bundle())
    _stub_agent(monkeypatch)
    await pipe.run_security_audit(rt)
    _stub_collect(monkeypatch, _bundle(tfa_empty=False))            # root@pam now has TFA
    res = await pipe.run_security_audit(rt)
    assert res["resolved"] == 1 and res["persisting"] == 2 and res["new"] == 0
    rows = rt.store.findings_for_run(res["run_id"])
    assert [r["trend"] for r in rows] == ["persisting", "persisting"]
    assert rt.store.finding_run_count("home-assistant|ha.core_update_exposed|home-assistant", "security_audit") == 2


async def test_unavailable_check_carries_instead_of_resolving(rt, monkeypatch):
    _stub_collect(monkeypatch, _bundle())
    _stub_agent(monkeypatch)
    await pipe.run_security_audit(rt)
    b = _bundle()
    del b.items["pve.access_tfa"]                                    # source vanished this week
    _stub_collect(monkeypatch, b)
    res = await pipe.run_security_audit(rt)
    assert res["resolved"] == 0 and res["carried"] == 1
    carried = [r for r in rt.store.findings_for_run(res["run_id"]) if r["trend"] == "carried"]
    assert carried and carried[0]["fingerprint"] == "homelab|pve.tfa_missing|root@pam"


async def test_suppressed_fingerprint_is_dropped_everywhere(rt, monkeypatch):
    rt.store.suppress("homelab|pve.tfa_missing|root@pam", until="", reason="LAN only, accepted")
    _stub_collect(monkeypatch, _bundle())
    seen = _stub_agent(monkeypatch)
    res = await pipe.run_security_audit(rt)
    assert res["findings"] == 2
    # Suppression is fingerprint-scoped (§0.5): it hides the one suppressed
    # FINDING's own line from the model's brief...
    assert "root@pam can log in to the Proxmox UI/API with a password alone" not in seen["user_prompt"]
    # ...but the informational note row for a different account under the
    # same check id is a fact, not a finding, and legitimately stays visible.
    assert "auditor@pve has no second factor" in seen["user_prompt"]
    assert all(r["metric"] != "pve.tfa_missing" for r in rt.store.findings_for_run(res["run_id"]))


async def test_refusal_degrades_the_appendix_only(rt, monkeypatch):
    _stub_collect(monkeypatch, _bundle())
    _stub_agent(monkeypatch, output="", stop_reason="refusal", steps=0)
    res = await pipe.run_security_audit(rt)
    assert res["assessment"] == "incomplete"
    inv = rt.store.investigation(res["investigation_id"])
    assert inv["status"] == "incomplete" and "declined" in inv["incomplete_reason"]
    assert inv["report_md"].startswith("## Summary") and "root@pam" in inv["report_md"]
    assert "_Unavailable —" in inv["report_md"] and "declined" in inv["report_md"]
    assert res["subject"].endswith("(AI assessment unavailable)")
    assert len(rt.store.findings_for_run(res["run_id"])) == 3         # findings persisted regardless


async def test_model_exception_marks_investigation_failed_but_delivers(rt, monkeypatch):
    _stub_collect(monkeypatch, _bundle())
    _stub_agent(monkeypatch, raises=RuntimeError("api down"))
    res = await pipe.run_security_audit(rt)
    assert res["assessment"] == "failed"
    assert rt.store.investigation(res["investigation_id"])["status"] == "failed"
    assert res["subject"].startswith("🛡️")


async def test_no_llm_skips_the_model_entirely(rt, monkeypatch):
    _stub_collect(monkeypatch, _bundle())
    called = {"n": 0}

    async def boom(*a, **k):
        called["n"] += 1
        raise AssertionError("model must not be called")
    monkeypatch.setattr(pipe, "run_agent", boom)
    res = await pipe.run_security_audit(rt, llm=False)
    assert res["assessment"] == "skipped" and res["investigation_id"] == 0 and called["n"] == 0
    assert rt.store.runs(limit=1, kind="security_audit")[0]["model_used"] == ""
    assert not rt.store.investigations()


async def test_everything_unreachable_raises(rt, monkeypatch):
    _stub_collect(monkeypatch, EvidenceBundle(items={}, collected_at="t"))
    _stub_agent(monkeypatch)
    with pytest.raises(RuntimeError, match="unreachable"):
        await pipe.run_security_audit(rt)
    assert not rt.store.runs(limit=1, kind="security_audit")
