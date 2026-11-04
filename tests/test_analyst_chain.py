"""The daily analyst's ordered provider chain (spec 2026-11-04).

Anthropic first, OpenRouter DeepSeek as fallback, llama.cpp later as an
``openai_compat`` entry — and the dashboard override layered over the YAML.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from heim.config import AnalystCfg, ModelRef, load_config

OPUS = {"provider": "anthropic", "model": "claude-opus-5-5"}
DEEPSEEK = {"provider": "openrouter", "model": "deepseek/deepseek-v4.1-flash-1017"}
ROOT = Path(__file__).resolve().parent.parent


def _repo_config(tmp_path):
    """The committed config, loaded from a copy — never the real .env."""
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    return load_config(croot)


# ================================================== 1. config


def test_chain_loads_in_order():
    cfg = AnalystCfg(chain=[OPUS, DEEPSEEK])
    assert [r.key for r in cfg.chain] == ["anthropic|claude-opus-5-5",
                                         "openrouter|deepseek/deepseek-v4.1-flash-1017"]


def test_primary_fallback_still_loads_as_a_chain():
    cfg = AnalystCfg(primary={"provider": "openrouter", "model": "a/b"}, fallback=OPUS)
    assert [r.model for r in cfg.chain] == ["a/b", "claude-opus-5-5"]


def test_primary_alone_is_a_one_entry_chain():
    cfg = AnalystCfg(primary=OPUS)
    assert [r.model for r in cfg.chain] == ["claude-opus-5-5"]


def test_chain_and_primary_together_is_an_error():
    with pytest.raises(ValidationError):
        AnalystCfg(chain=[OPUS], primary=DEEPSEEK)


def test_empty_chain_is_an_error():
    with pytest.raises(ValidationError):
        AnalystCfg(chain=[])
    with pytest.raises(ValidationError):
        AnalystCfg()


def test_openai_compat_needs_a_base_url():
    with pytest.raises(ValidationError):
        ModelRef(provider="openai_compat", model="local")


def test_key_includes_base_url_only_when_set():
    assert ModelRef(provider="openai_compat", model="local",
                    base_url="http://x:8080/v1").key == "openai_compat|local|http://x:8080/v1"
    assert ModelRef(**OPUS).key == "anthropic|claude-opus-5-5"
    assert ModelRef(**DEEPSEEK).label == "deepseek/deepseek-v4.1-flash-1017"


def test_shipped_daily_analyst_yaml_is_anthropic_then_deepseek(tmp_path):
    cfg = _repo_config(tmp_path)
    assert [r.key for r in cfg.analyst.chain] == ["anthropic|claude-opus-5-5",
                                                 "openrouter|deepseek/deepseek-v4.1-flash-1017"]


def test_settings_carry_an_analyst_allow_list(tmp_path):
    cfg = _repo_config(tmp_path)
    assert isinstance(cfg.settings.analyst_models, list)
