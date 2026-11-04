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


# ================================================== 2. run_chain

from heim.llm import AnalystChainFailed, Attempt, run_chain, parse_analysis  # noqa: E402

GOOD = '{"overallHealth": "healthy", "headline": "ok", "findings": []}'


class _Usage:
    def __init__(self, i: int, o: int):
        self.input_tokens, self.output_tokens = i, o


class _Text:
    type = "text"

    def __init__(self, text: str):
        self.text = text


class _Resp:
    def __init__(self, text: str, stop_reason: str = "end_turn", usage=(10, 5)):
        self.content = [_Text(text)]
        self.stop_reason = stop_reason
        self.usage = _Usage(*usage)


class _Anthropic:
    """Stands in for AsyncAnthropic: returns ``resp`` or raises ``exc``."""

    def __init__(self, resp=None, exc=None):
        async def create(**kw):
            if exc is not None:
                raise exc
            return resp
        self.messages = type("M", (), {"create": staticmethod(create)})()


class _HttpResp:
    def __init__(self, payload):
        self._p = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._p


class _Http:
    """Stands in for httpx.AsyncClient; records every POST."""
    calls: list = []

    def __init__(self, payload):
        self._p = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, headers=None, json=None):
        _Http.calls.append({"url": url, "headers": headers or {}, "json": json})
        return _HttpResp(self._p)


def _or_payload(text=GOOD, usage=(900, 40)):
    return {"choices": [{"message": {"content": text}}],
            "usage": {"prompt_tokens": usage[0], "completion_tokens": usage[1]}}


def _patch(monkeypatch, *, anthropic=None, http=None):
    if anthropic is not None:
        monkeypatch.setattr("heim.llm.AsyncAnthropic", lambda *a, **k: anthropic)
    if http is not None:
        _Http.calls = []
        monkeypatch.setattr("heim.llm.httpx.AsyncClient", lambda *a, **k: _Http(http))


CHAIN = [ModelRef(**OPUS), ModelRef(**DEEPSEEK)]


async def test_first_entry_answers(monkeypatch):
    _patch(monkeypatch, anthropic=_Anthropic(_Resp(GOOD, usage=(7000, 300))))
    res = await run_chain(CHAIN, "sys", "user", 8192, accept=parse_analysis)
    assert (res.index, res.model_used) == (0, "claude-opus-5-5")
    assert [a.ok for a in res.attempts] == [True]
    assert (res.attempts[0].input_tokens, res.attempts[0].output_tokens) == (7000, 300)
    assert res.analysis["overallHealth"] == "healthy"
    assert res.usage == {"input": 7000, "output": 300}


async def test_error_falls_through_to_next(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    _patch(monkeypatch,
           anthropic=_Anthropic(exc=RuntimeError("You have reached your specified workspace API usage limits")),
           http=_or_payload())
    res = await run_chain(CHAIN, "sys", "user", 8192, accept=parse_analysis)
    assert (res.index, res.model_used) == (1, "deepseek/deepseek-v4.1-flash-1017")
    assert [a.ok for a in res.attempts] == [False, True]
    assert "usage limits" in res.attempts[0].error
    assert res.usage == {"input": 900, "output": 40}


async def test_unparseable_falls_through_and_keeps_billed_tokens(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    _patch(monkeypatch,
           anthropic=_Anthropic(_Resp('{"overallHealth": "ok", ', "max_tokens", (5000, 8192))),
           http=_or_payload())
    res = await run_chain(CHAIN, "sys", "user", 8192, accept=parse_analysis)
    assert res.attempts[0].ok is False and "unparseable" in res.attempts[0].error
    assert (res.attempts[0].input_tokens, res.attempts[0].output_tokens) == (5000, 8192)
    assert res.index == 1 and res.analysis["overallHealth"] == "healthy"


async def test_missing_key_env_fails_that_entry_only(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    _patch(monkeypatch, anthropic=_Anthropic(_Resp(GOOD)), http=_or_payload())
    res = await run_chain(list(reversed(CHAIN)), "sys", "user", 8192, accept=parse_analysis)
    assert "OPENROUTER_API_KEY" in res.attempts[0].error
    assert res.index == 1 and res.model_used == "claude-opus-5-5"


async def test_all_fail_raises_with_every_attempt(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    _patch(monkeypatch, anthropic=_Anthropic(exc=RuntimeError("usage limits")),
           http=_or_payload(text="not json at all"))
    with pytest.raises(AnalystChainFailed) as ei:
        await run_chain(CHAIN, "sys", "user", 8192, accept=parse_analysis)
    assert len(ei.value.attempts) == 2
    assert all(isinstance(a, Attempt) and not a.ok for a in ei.value.attempts)
    msg = str(ei.value)
    assert msg.startswith("all 2 analyst models failed")
    assert "anthropic claude-opus-5-5" in msg and "deepseek/deepseek-v4.1-flash-1017" in msg


async def test_without_accept_any_text_is_an_answer(monkeypatch):
    _patch(monkeypatch, anthropic=_Anthropic(_Resp("plain words")))
    res = await run_chain(CHAIN, "sys", "user", 8192)
    assert res.text == "plain words" and res.analysis is None and res.index == 0


async def test_openai_compat_posts_to_its_base_url_without_auth_when_no_key_env(monkeypatch):
    _patch(monkeypatch, http=_or_payload())
    local = ModelRef(provider="openai_compat", model="local", base_url="http://llama:8080/v1/")
    res = await run_chain([local], "sys", "user", 8192, accept=parse_analysis)
    assert res.model_used == "local"
    assert _Http.calls[0]["url"] == "http://llama:8080/v1/chat/completions"
    assert "Authorization" not in _Http.calls[0]["headers"]


async def test_openai_compat_sends_its_named_key(monkeypatch):
    monkeypatch.setenv("LLAMA_KEY", "secret")
    _patch(monkeypatch, http=_or_payload())
    local = ModelRef(provider="openai_compat", model="local",
                     base_url="http://llama:8080/v1", api_key_env="LLAMA_KEY")
    await run_chain([local], "sys", "user", 8192)
    assert _Http.calls[0]["headers"]["Authorization"] == "Bearer secret"


async def test_errors_are_clipped_to_300_chars(monkeypatch):
    _patch(monkeypatch, anthropic=_Anthropic(exc=RuntimeError("x" * 2000)))
    with pytest.raises(AnalystChainFailed) as ei:
        await run_chain(CHAIN[:1], "sys", "user", 8192)
    assert len(ei.value.attempts[0].error) <= 300


async def test_attempt_as_dict_round_trips():
    a = Attempt(provider="anthropic", model="m", ok=False, error="e", input_tokens=1, output_tokens=2)
    assert a.as_dict() == {"provider": "anthropic", "model": "m", "ok": False, "error": "e",
                           "input_tokens": 1, "output_tokens": 2}


# ================================================== 3. store

import json  # noqa: E402

from heim.incidents.store import IncidentStore  # noqa: E402


def test_model_override_round_trip(tmp_path):
    s = IncidentStore(tmp_path / "s.sqlite3")
    assert s.model_override("daily_analyst") is None
    s.set_model_override("daily_analyst", [DEEPSEEK, OPUS])
    got = s.model_override("daily_analyst")
    assert [e["model"] for e in got["chain"]] == ["deepseek/deepseek-v4.1-flash-1017",
                                                  "claude-opus-5-5"]
    assert got["updated_by"] == "dashboard" and got["updated_at"]
    assert s.clear_model_override("daily_analyst") is True
    assert s.clear_model_override("daily_analyst") is False
    assert s.model_override("daily_analyst") is None


def test_set_model_override_replaces(tmp_path):
    s = IncidentStore(tmp_path / "s.sqlite3")
    s.set_model_override("daily_analyst", [OPUS])
    s.set_model_override("daily_analyst", [DEEPSEEK])
    assert [e["model"] for e in s.model_override("daily_analyst")["chain"]] == [
        "deepseek/deepseek-v4.1-flash-1017"]


def test_empty_override_is_refused(tmp_path):
    s = IncidentStore(tmp_path / "s.sqlite3")
    with pytest.raises(ValueError):
        s.set_model_override("daily_analyst", [])
    assert s.model_override("daily_analyst") is None


def test_corrupt_override_reads_as_none(tmp_path):
    s = IncidentStore(tmp_path / "s.sqlite3")
    s._db.execute("INSERT INTO model_overrides (agent, chain_json, updated_at) "
                  "VALUES ('daily_analyst', '{not json', 't')")
    s._db.commit()
    assert s.model_override("daily_analyst") is None


def test_runs_gain_attempts_json_on_an_old_db(tmp_path):
    db = tmp_path / "old.sqlite3"
    s = IncidentStore(db)
    s._db.execute("ALTER TABLE runs DROP COLUMN attempts_json")
    s._db.commit()
    s.close()
    s = IncidentStore(db)
    attempts = [{"provider": "anthropic", "model": "claude-opus-5-5", "ok": False}]
    rid = s.insert_run(kind="daily", run_at="t", attempts_json=json.dumps(attempts))
    run = [r for r in s.runs() if r["id"] == rid][0]
    assert json.loads(run["attempts_json"]) == attempts
    rid2 = s.insert_run(kind="daily", run_at="t2")
    assert [r for r in s.runs() if r["id"] == rid2][0]["attempts_json"] == "[]"
