"""llama-server in CT 111 as the analyst chain's last resort (2026-11-11).

Qwen3-8B on the iGPU reads ~70 tokens/s and writes ~7, behind a 32k context:
it needs a long timeout, its thinking turned off, and a parser that skips a
``<think>`` block. Unset, the entry must vanish rather than stop startup.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from test_analyst_chain import GOOD, _Http, _or_payload

from heim.config import AnalystCfg, ModelRef, load_config
from heim.llm import parse_analysis, run_chain
from heim.model_chain import resolve_chain

ROOT = Path(__file__).resolve().parent.parent
OPUS = {"provider": "anthropic", "model": "claude-opus-5-5"}
LOCAL = {"provider": "openai_compat", "model": "qwen3-8b",
         "base_url": "http://llm:8180/v1", "api_key_env": "HEIM_LLAMACPP_KEY",
         "timeout_s": 1800, "extra_body": {"chat_template_kwargs": {"enable_thinking": False}}}


def _repo_config(tmp_path):
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    return load_config(croot)


def test_an_unset_local_url_drops_the_entry_instead_of_stopping_startup():
    cfg = AnalystCfg(chain=[OPUS, {**LOCAL, "base_url": ""}])
    assert [r.provider for r in cfg.chain] == ["anthropic"]


def test_the_shipped_chain_ends_with_the_local_model_when_its_url_is_set(tmp_path, monkeypatch):
    monkeypatch.delenv("HEIM_LLAMACPP_URL", raising=False)
    assert [r.provider for r in _repo_config(tmp_path).analyst.chain] == ["anthropic", "openrouter"]
    monkeypatch.setenv("HEIM_LLAMACPP_URL", "http://llm:8180/v1")
    last = _repo_config(tmp_path / "b").analyst.chain[-1]
    assert (last.provider, last.base_url, last.api_key_env) == (
        "openai_compat", "http://llm:8180/v1", "HEIM_LLAMACPP_KEY")
    assert last.timeout_s >= 1200
    assert last.extra_body == {"chat_template_kwargs": {"enable_thinking": False}}


async def test_the_request_carries_the_extra_body_and_the_long_timeout(monkeypatch):
    seen = {}

    def client(*a, **k):
        seen.update(k)
        return _Http(_or_payload())
    _Http.calls = []
    monkeypatch.setattr("heim.llm.httpx.AsyncClient", client)
    monkeypatch.setenv("HEIM_LLAMACPP_KEY", "k")
    await run_chain([ModelRef(**LOCAL)], "sys", "user", 8192, accept=parse_analysis)
    assert seen["timeout"] == 1800
    body = _Http.calls[0]["json"]
    assert body["chat_template_kwargs"] == {"enable_thinking": False}
    assert body["messages"][1]["content"] == "user" and body["max_tokens"] == 8192


async def test_a_plain_entry_keeps_the_old_timeout_and_body(monkeypatch):
    seen = {}

    def client(*a, **k):
        seen.update(k)
        return _Http(_or_payload())
    _Http.calls = []
    monkeypatch.setattr("heim.llm.httpx.AsyncClient", client)
    await run_chain([ModelRef(provider="openai_compat", model="x", base_url="http://x/v1")],
                    "s", "u", 100)
    assert seen["timeout"] == 180
    assert set(_Http.calls[0]["json"]) == {"model", "max_tokens", "messages"}


def test_a_think_block_with_braces_is_skipped():
    text = "<think>the payload has {cpu: 3} and {mem}</think>\n" + GOOD
    assert parse_analysis(text) == json.loads(GOOD)


def test_an_override_takes_the_allow_list_entry_with_its_timeout():
    allowed = [ModelRef(**OPUS), ModelRef(**LOCAL)]
    # what an override saved before timeout_s existed looks like
    stored = {"chain": [OPUS, {k: LOCAL[k] for k in ("provider", "model", "base_url")}]}
    eff = resolve_chain([ModelRef(**OPUS)], stored, allowed)
    assert eff.source == "override"
    assert eff.chain[1].timeout_s == 1800 and eff.chain[1].api_key_env == "HEIM_LLAMACPP_KEY"
