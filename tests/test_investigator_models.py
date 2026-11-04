"""The investigator's model choice (spec 2026-11-04-investigator-openrouter).

One model at a time, chosen by the operator: a per-run pick, else the
dashboard override, else config/agents/investigator.yaml.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from heim.config import AgentCfg, ModelRef, Settings, load_config
from heim.model_chain import INVESTIGATOR_AGENT, find_model, resolve_model

ROOT = Path(__file__).resolve().parent.parent

OPUS = ModelRef(provider="anthropic", model="claude-opus-5-5")
SONNET = ModelRef(provider="anthropic", model="claude-sonnet-5-5")
DEEPSEEK = ModelRef(provider="openrouter", model="deepseek/deepseek-v4.1-flash-1017")


def _repo_config(tmp_path):
    """The committed config, loaded from a copy — never the real .env."""
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    return load_config(croot)


# ================================================== 1. model identity


def test_agentcfg_defaults_to_anthropic_ref(tmp_path):
    cfg = _repo_config(tmp_path)
    assert cfg.agents["investigator"].ref.key == "anthropic|claude-sonnet-5-5"


def test_with_ref_copies_provider_and_url():
    agent = AgentCfg(name="investigator", model="claude-sonnet-5-5")
    local = ModelRef(provider="openai_compat", model="local", base_url="http://x/v1",
                     api_key_env="LLAMA_KEY")
    copy = agent.with_ref(local)
    assert (copy.provider, copy.model, copy.base_url, copy.api_key_env) == (
        "openai_compat", "local", "http://x/v1", "LLAMA_KEY")
    assert agent.provider == "anthropic" and agent.model == "claude-sonnet-5-5"
    assert copy.ref == local


def test_investigator_models_accepts_strings_and_dicts(tmp_path):
    cfg = _repo_config(tmp_path)
    data = cfg.settings.model_dump()
    data["investigator_models"] = [
        "claude-opus-5-5",
        {"provider": "openrouter", "model": "deepseek/deepseek-v4.1-flash-1017"},
    ]
    s = Settings(**data)
    assert [m.key for m in s.investigator_models] == [
        "anthropic|claude-opus-5-5", "openrouter|deepseek/deepseek-v4.1-flash-1017"]


def test_find_model_by_key_and_by_unique_id():
    allowed = [OPUS, DEEPSEEK]
    assert find_model(DEEPSEEK.key, allowed) == DEEPSEEK
    assert find_model("claude-opus-5-5", allowed) == OPUS


def test_find_model_rejects_ambiguous_and_unknown():
    twin = ModelRef(provider="openrouter", model="claude-opus-5-5")
    with pytest.raises(ValueError) as e:
        find_model("claude-opus-5-5", [OPUS, twin])
    assert OPUS.key in str(e.value) and twin.key in str(e.value)
    with pytest.raises(ValueError, match="not offered"):
        find_model("gpt-9", [OPUS])
    with pytest.raises(ValueError, match="not offered"):
        find_model("openrouter|evil/model", [OPUS])


def test_resolve_model_override_and_stale():
    allowed = [OPUS, DEEPSEEK]
    eff = resolve_model(SONNET, {"chain": [DEEPSEEK.model_dump()], "updated_at": "t"}, allowed)
    assert (eff.chain, eff.source, eff.stale) == ([DEEPSEEK], "override", False)
    eff = resolve_model(SONNET, {"chain": [{"provider": "openrouter", "model": "gone"}]},
                        allowed)
    assert (eff.chain, eff.source, eff.stale) == ([SONNET], "yaml", True)
    eff = resolve_model(SONNET, {"chain": [OPUS.model_dump(), DEEPSEEK.model_dump()]}, allowed)
    assert (eff.chain, eff.stale) == ([SONNET], True)
    assert resolve_model(SONNET, None, allowed).chain == [SONNET]
    assert INVESTIGATOR_AGENT == "investigator"


def test_from_key_round_trips():
    local = ModelRef(provider="openai_compat", model="local", base_url="http://x:8080/v1")
    for ref in (OPUS, DEEPSEEK, local):
        assert ModelRef.from_key(ref.key) == ref
    assert ModelRef.from_key("claude-opus-5-5") == OPUS     # a bare id is Anthropic


def test_with_model_understands_keys():
    from heim.pipelines.investigate import with_model
    agent = AgentCfg(name="investigator", model="claude-sonnet-5-5")
    assert with_model(agent, DEEPSEEK.key).ref == DEEPSEEK
    assert with_model(agent, "claude-opus-5-5").ref == OPUS
    assert with_model(agent, "") is agent


def test_dashboard_model_field_returns_the_key():
    from heim.dashboard.app import _model_field
    assert _model_field({"model": "deepseek/deepseek-v4.1-flash-1017"},
                        [OPUS, DEEPSEEK]) == DEEPSEEK.key
    assert _model_field({"model": OPUS.key}, [OPUS, DEEPSEEK]) == OPUS.key
    assert _model_field({}, [OPUS]) == ""


def test_cli_model_bare_id_still_works(tmp_path):
    from heim.cli import _cli_model_choice
    cfg = _repo_config(tmp_path)
    data = cfg.settings.model_dump()
    data["investigator_models"] = ["claude-opus-5-5"]           # a live, string-form setting
    cfg.settings = Settings(**data)
    assert _cli_model_choice(cfg, "claude-opus-5-5") == "anthropic|claude-opus-5-5"
    assert _cli_model_choice(cfg, "") == ""
    with pytest.raises(ValueError):
        _cli_model_choice(cfg, "gpt-9")


# ================================================== 3. store and queue


def _inv_row(s, **kw):
    base = dict(fingerprint="ubuntu-server|disk|Disk", host="ubuntu-server",
                host_role="guest", agent_name="investigator", model="claude-sonnet-5-5",
                trigger="daily", status="pending_approval", started_at="2026-11-04T10:00:00")
    base.update(kw)
    return s.create_investigation(**base)


def test_new_columns_migrate_on_old_db(tmp_path):
    from heim.incidents.store import IncidentStore
    db = tmp_path / "old.sqlite3"
    s = IncidentStore(db)
    s._db.execute("ALTER TABLE investigations DROP COLUMN provider")
    s._db.execute("ALTER TABLE investigations DROP COLUMN model_pinned")
    s._db.commit()
    s.close()
    s = IncidentStore(db)
    row = s.investigation(_inv_row(s))
    assert (row["provider"], row["model_pinned"]) == ("anthropic", 0)
    row = s.investigation(_inv_row(s, provider="openrouter", model_pinned=1,
                                   model=DEEPSEEK.model))
    assert (row["provider"], row["model_pinned"]) == ("openrouter", 1)


def test_rearm_request_pins_only_pinned_rows(tmp_path):
    from heim.incidents.store import IncidentStore
    from heim.pipelines.investigate import request_from_investigation
    s = IncidentStore(tmp_path / "s.sqlite3")
    unpinned = s.investigation(_inv_row(s))
    assert request_from_investigation(unpinned).model_override == ""
    pinned = s.investigation(_inv_row(s, provider="openrouter", model=DEEPSEEK.model,
                                      model_pinned=1))
    assert request_from_investigation(pinned).model_override == DEEPSEEK.key


def test_running_investigations_lists_only_running(tmp_path):
    from heim.incidents.store import IncidentStore
    s = IncidentStore(tmp_path / "s.sqlite3")
    running = _inv_row(s, status="running")
    _inv_row(s, status="pending_approval")
    _inv_row(s, status="complete")
    assert [r["id"] for r in s.running_investigations()] == [running]


def test_retry_payload_has_no_model(tmp_path):
    from heim.incidents.store import IncidentStore
    from heim.pipelines.queue import enqueue_retry
    s = IncidentStore(tmp_path / "s.sqlite3")
    original = _inv_row(s, status="failed", provider="openrouter", model=DEEPSEEK.model,
                        model_pinned=1)
    job_id = enqueue_retry(s, original)
    job = next(j for j in s.jobs(limit=5) if j["id"] == job_id)
    assert job["payload"]["model"] == ""


# ================================================== 4. resolve at start, notify on failure

import asyncio  # noqa: E402

from heim.agent.runner import AgentResult, AgentStep  # noqa: E402
from heim.incidents.store import IncidentStore  # noqa: E402
from heim.pipelines.investigate import (  # noqa: E402
    InvestigationRequest, _approval_text, request_from_investigation, run_investigation)
from heim.runtime import Runtime  # noqa: E402

DUMMY_ENV = {
    "HEIM_SERVER_IP": "10.0.0.10", "HEIM_PROXMOX_IP": "10.0.0.2", "HEIM_HA_IP": "10.0.0.3",
    "HEIM_TELEGRAM_CHAT_ID": "111111111", "HEIM_EMAIL_TO": "test@example.com",
    "HEIM_EMAIL_FROM": "test@example.com",
}
REPORT = "## Summary\n\nDisk filled up.\n\n## Root cause\n\nlogs\n\n## Confidence\n\nhigh"


class Rig:
    """A Runtime with every channel off, a recording notify and a fake agent."""

    def __init__(self, tmp_path, monkeypatch):
        for k, v in DUMMY_ENV.items():
            monkeypatch.setenv(k, v)
        monkeypatch.setattr("heim.pipelines.investigate.APPROVAL_POLL_SECONDS", 0.01)
        cfg = _repo_config(tmp_path)
        cfg.settings.loki = cfg.settings.email = cfg.settings.home_assistant = None
        cfg.settings.telegram = None
        cfg.settings.threshold_detection = False
        cfg.settings.investigator_models = [OPUS, DEEPSEEK]
        self.rt = Runtime(config=cfg, store=IncidentStore(tmp_path / "rt.sqlite3"),
                          dry_run=True, out_dir=tmp_path / "out")
        self.notes: list[str] = []
        self.ran_on: list[AgentCfg] = []
        self.fail_with: Exception | None = None

        async def notify(text):
            self.notes.append(text)
        self.rt.notify = notify

        async def fake_run_agent(cfg, *, system, user_prompt, tools, on_step=None,
                                 collect_transcript=False):
            self.ran_on.append(cfg)
            if self.fail_with is not None:
                raise self.fail_with
            return AgentResult(REPORT, [AgentStep("stub", {}, "")], 10, 5)
        monkeypatch.setattr("heim.pipelines.investigate.run_agent", fake_run_agent)

    def override(self, ref: ModelRef):
        self.rt.store.set_model_override(INVESTIGATOR_AGENT, [ref.model_dump()])

    async def run(self, model: str = ""):
        return await run_investigation(
            self.rt, InvestigationRequest(host="ubuntu-server", model_override=model),
            require_approval=False)

    def row(self) -> dict:
        return self.rt.store.investigations(limit=1)[0]


@pytest.fixture()
def rig(tmp_path, monkeypatch):
    return Rig(tmp_path, monkeypatch)


async def test_dashboard_override_used_when_no_pick(rig):
    rig.override(DEEPSEEK)
    await rig.run()
    assert rig.ran_on[-1].ref == DEEPSEEK
    row = rig.row()
    assert (row["provider"], row["model"], row["model_pinned"]) == (
        "openrouter", DEEPSEEK.model, 0)


async def test_yaml_default_without_override(rig):
    await rig.run()
    assert rig.ran_on[-1].ref == SONNET and rig.row()["model_pinned"] == 0


async def test_pick_beats_override_and_is_pinned(rig):
    rig.override(DEEPSEEK)
    await rig.run(OPUS.key)
    assert rig.ran_on[-1].ref == OPUS
    assert (rig.row()["model"], rig.row()["model_pinned"]) == ("claude-opus-5-5", 1)


async def test_stale_override_falls_back_to_yaml(rig, caplog):
    rig.rt.store.set_model_override(INVESTIGATOR_AGENT,
                                    [{"provider": "openrouter", "model": "gone/model"}])
    await rig.run()
    assert rig.ran_on[-1].ref == SONNET
    assert "override" in caplog.text and "ignored" in caplog.text


async def test_parked_approval_follows_switch(rig):
    rt = rig.rt
    inv_id = rt.store.create_investigation(
        host="ubuntu-server", host_role="guest", agent_name="investigator",
        model="claude-sonnet-5-5", status="pending_approval", started_at="t",
        brief_md="brief")
    rig.override(DEEPSEEK)                       # the operator switches while it waits
    task = asyncio.create_task(run_investigation(
        rt, request_from_investigation(rt.store.investigation(inv_id)), resume_id=inv_id))
    await asyncio.sleep(0.05)
    rt.store.set_approval_decision(inv_id, "approve")
    await asyncio.wait_for(task, 5)
    assert rig.ran_on[-1].ref == DEEPSEEK
    row = rt.store.investigation(inv_id)
    assert (row["provider"], row["model"], row["status"]) == (
        "openrouter", DEEPSEEK.model, "complete")


async def test_removed_compat_model_fails_and_notifies(rig):
    rt = rig.rt
    inv_id = rt.store.create_investigation(
        host="ubuntu-server", agent_name="investigator", model="local",
        provider="openai_compat", model_pinned=1, status="pending_approval", started_at="t")
    res = await run_investigation(
        rt, request_from_investigation(rt.store.investigation(inv_id)), resume_id=inv_id)
    assert res is None and rig.ran_on == []
    row = rt.store.investigation(inv_id)
    assert row["status"] == "failed" and "local" in row["incomplete_reason"]
    assert len(rig.notes) == 1 and rig.notes[0].startswith(f"❌ Investigation #{inv_id} ")


async def test_agent_exception_notifies_once(rig):
    rig.fail_with = RuntimeError("HTTP 400: usage limits")
    assert await rig.run() is None
    inv_id = rig.row()["id"]
    assert rig.notes == [
        f"❌ Investigation #{inv_id} (ubuntu-server) failed on claude-sonnet-5-5: "
        "RuntimeError: HTTP 400: usage limits — change the model on /agents/investigator"]


async def test_error_is_clipped_to_300(rig):
    rig.fail_with = RuntimeError("x" * 1000)
    await rig.run()
    err = rig.notes[0].split(": ", 1)[1].split(" — change")[0]
    assert len(err) <= 300


def test_approval_text_names_non_default_model():
    req = InvestigationRequest(host="ubuntu-server")
    assert "model:" not in _approval_text(req, "f")
    assert "· model: deepseek/deepseek-v4.1-flash-1017 (openrouter)" in _approval_text(
        req, "f", model=DEEPSEEK)
    opus = _approval_text(req, "f", model=OPUS)
    assert "· model: claude-opus-5-5" in opus and "(anthropic)" not in opus


async def test_job_failure_without_row_notifies(rig, monkeypatch):
    from heim import daemon

    def boom(*a, **k):
        raise ValueError("bad payload")
    monkeypatch.setattr(daemon, "request_from_payload", boom)
    await daemon.run_job(rig.rt, {"id": 9, "kind": "investigate",
                                  "payload": {"host": "homelab", "model": DEEPSEEK.key}})
    assert rig.notes == [
        "❌ Investigation of homelab failed on deepseek/deepseek-v4.1-flash-1017: "
        "ValueError: bad payload — change the model on /agents/investigator"]


async def test_restart_sweep_notifies_running_rows(rig):
    from heim import daemon
    rt = rig.rt
    a = rt.store.create_investigation(host="homelab", model="claude-sonnet-5-5",
                                      status="running", started_at="t")
    rt.store.create_investigation(host="homelab", status="pending_approval", started_at="t")
    assert await daemon._sweep_and_notify(rt) >= 1
    assert rig.notes == [
        f"❌ Investigation #{a} (homelab) failed on claude-sonnet-5-5: "
        "interrupted by daemon restart — change the model on /agents/investigator"]
    assert rt.store.investigation(a)["status"] == "failed"


async def test_dry_run_does_not_notify(tmp_path, monkeypatch):
    rig = Rig(tmp_path, monkeypatch)
    sent = []

    class FakeTelegram:
        async def notify(self, text):
            sent.append(text)
    del rig.rt.notify                                # the real Runtime.notify
    rig.rt.telegram = FakeTelegram()
    rig.fail_with = RuntimeError("boom")
    await rig.run()
    assert sent == []
