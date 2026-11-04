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
