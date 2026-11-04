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


# ================================================== 4. resolution + notices

from heim.model_chain import OVERRIDE_AGENT, resolve_chain  # noqa: E402
from heim.reports.analyst_notice import (  # noqa: E402
    failure_email, fallback_banner_html, fallback_subject, fallback_telegram)

ALLOWED = [ModelRef(**OPUS), ModelRef(**DEEPSEEK)]
FAILED_OPUS = Attempt("anthropic", "claude-opus-5-5", False, "BadRequestError: usage limits")
OK_DEEPSEEK = Attempt("openrouter", "deepseek/deepseek-v4.1-flash-1017", True, "", 900, 40)


def test_override_agent_is_the_daily_analyst():
    assert OVERRIDE_AGENT == "daily_analyst"


def test_no_override_runs_yaml():
    eff = resolve_chain(CHAIN, None, ALLOWED)
    assert eff.chain == CHAIN and eff.source == "yaml" and eff.stale is False


def test_valid_override_runs_in_its_order():
    eff = resolve_chain(CHAIN, {"chain": [DEEPSEEK], "updated_at": "2026-11-04T08:00:00+00:00",
                                "updated_by": "dashboard"}, ALLOWED)
    assert [r.model for r in eff.chain] == ["deepseek/deepseek-v4.1-flash-1017"]
    assert eff.source == "override" and eff.updated_at == "2026-11-04T08:00:00+00:00"


def test_override_with_an_unlisted_entry_is_stale():
    ov = {"chain": [DEEPSEEK, {"provider": "openrouter", "model": "evil/model"}],
          "updated_at": "t", "updated_by": "dashboard"}
    eff = resolve_chain(CHAIN, ov, ALLOWED)
    assert eff.chain == CHAIN and eff.source == "yaml" and eff.stale is True
    assert eff.updated_at == "t"


def test_any_override_is_stale_when_nothing_is_allowed():
    eff = resolve_chain(CHAIN, {"chain": [OPUS], "updated_at": "t", "updated_by": ""}, [])
    assert eff.source == "yaml" and eff.stale is True


def test_malformed_override_entry_is_stale():
    eff = resolve_chain(CHAIN, {"chain": [{"model": 3, "provider": "nope"}], "updated_at": "t",
                                "updated_by": ""}, ALLOWED)
    assert eff.source == "yaml" and eff.stale is True


def test_fallback_subject_tag():
    assert fallback_subject("PAM Morning Report", "deepseek/deepseek-v4.1-flash-1017") == \
        "PAM Morning Report [fallback: deepseek/deepseek-v4.1-flash-1017]"


def test_banner_names_the_answer_and_every_failure_escaped():
    bad = Attempt("anthropic", "claude-opus-5-5", False, "<script>x</script>")
    html = fallback_banner_html("deepseek/deepseek-v4.1-flash-1017", [bad, OK_DEEPSEEK])
    assert "deepseek/deepseek-v4.1-flash-1017" in html and "claude-opus-5-5" in html
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_failure_email_lists_every_attempt():
    second = Attempt("openrouter", "deepseek/deepseek-v4.1-flash-1017", False, "HTTPStatusError: 429")
    subject, html = failure_email([FAILED_OPUS, second], "2026-11-04T07:00:00+01:00")
    assert subject == "HEIM daily report NOT produced — all analyst models failed"
    for s in ("claude-opus-5-5", "usage limits", "deepseek/deepseek-v4.1-flash-1017", "429",
              "2026-11-04T07:00:00+01:00",
              "Metrics were collected; the next scheduled run will retry."):
        assert s in html
    assert html.index("claude-opus-5-5") < html.index("deepseek/deepseek-v4.1-flash-1017")


def test_failure_email_escapes():
    _s, html = failure_email([Attempt("anthropic", "m", False, "<b>x</b>")], "t")
    assert "<b>x</b>" not in html


def test_fallback_telegram_line():
    line = fallback_telegram("deepseek/deepseek-v4.1-flash-1017", [FAILED_OPUS, OK_DEEPSEEK])
    assert line.startswith("⚠️ HEIM daily:")
    assert "claude-opus-5-5" in line and "usage limits" in line
    assert line.endswith("report by deepseek/deepseek-v4.1-flash-1017")


# ================================================== 5. the daily pipeline

import logging  # noqa: E402

from heim.llm import ChainResult  # noqa: E402
from heim.pipelines import daily  # noqa: E402
from heim.reports.analyst_notice import FAILURE_SUBJECT  # noqa: E402
from heim.runtime import Runtime  # noqa: E402

ANALYSIS = {"overallHealth": "healthy", "headline": "All quiet", "executiveSummary": "ok",
            "categories": {}, "findings": [], "watchlist": []}
PAYLOAD = {"generatedAt": "2026-11-04T07:00:00.000+01:00", "windowDays": 3, "hosts": [],
           "counts": {"crit": 0, "warn": 0, "naQueries": 0}, "overall": "healthy",
           "categories": {}, "topAlerts": []}


class DailyRig:
    """``run_daily`` with Prometheus, aggregation and dispatch stubbed; the
    chain is whatever ``self.result`` says (a ChainResult or an exception)."""

    def __init__(self, rt, monkeypatch):
        self.rt = rt
        self.chains: list = []
        self.notes: list[str] = []
        self.result = None

        async def fetch(base, qdefs, window):
            return []

        async def fake_chain(chain, system, user, max_tokens, accept=None):
            self.chains.append(chain)
            if isinstance(self.result, Exception):
                raise self.result
            return self.result

        async def dispatch(rt_, items, *, concurrent, trigger="manual"):
            pass

        async def notify(text):
            self.notes.append(text)

        monkeypatch.setattr(daily, "_fetch_query_ranges", fetch)
        monkeypatch.setattr(daily, "aggregate", lambda *a, **k: {"payload": PAYLOAD})
        monkeypatch.setattr(daily, "run_chain", fake_chain)
        monkeypatch.setattr(daily, "dispatch_all", dispatch)
        monkeypatch.setattr(rt, "notify", notify)

    def emails(self) -> list:
        return sorted((self.rt.out_dir).glob("*.html")) if self.rt.out_dir.exists() else []


def _ok(index, attempts, model):
    return ChainResult(text=json.dumps(ANALYSIS), analysis=dict(ANALYSIS), model_used=model,
                       index=index, usage={"input": attempts[-1].input_tokens,
                                           "output": attempts[-1].output_tokens},
                       attempts=attempts)


@pytest.fixture()
def drt(tmp_path):
    cfg = _repo_config(tmp_path)
    cfg.settings.loki = None
    cfg.settings.email = None
    cfg.settings.home_assistant = None
    cfg.settings.telegram = None
    cfg.settings.analyst_models = list(ALLOWED)
    return Runtime(config=cfg, store=IncidentStore(tmp_path / "rt.sqlite3"),
                   dry_run=False, out_dir=tmp_path / "out")


@pytest.fixture()
def rig(drt, monkeypatch):
    return DailyRig(drt, monkeypatch)


OK_OPUS = Attempt("anthropic", "claude-opus-5-5", True, "", 7000, 300)


async def test_daily_runs_the_yaml_chain_by_default(drt, rig):
    rig.result = _ok(0, [OK_OPUS], "claude-opus-5-5")
    await daily.run_daily(drt, dispatch_concurrently=False)
    assert [r.key for r in rig.chains[0]] == [r.key for r in drt.config.analyst.chain]


async def test_daily_uses_the_override_chain(drt, rig):
    drt.store.set_model_override("daily_analyst", [DEEPSEEK])
    rig.result = _ok(0, [OK_DEEPSEEK], "deepseek/deepseek-v4.1-flash-1017")
    await daily.run_daily(drt, dispatch_concurrently=False)
    assert [r.model for r in rig.chains[0]] == ["deepseek/deepseek-v4.1-flash-1017"]


async def test_stale_override_runs_yaml_chain_and_warns(drt, rig, caplog):
    drt.store.set_model_override("daily_analyst", [{"provider": "openrouter", "model": "gone/x"}])
    rig.result = _ok(0, [OK_OPUS], "claude-opus-5-5")
    with caplog.at_level(logging.WARNING):
        await daily.run_daily(drt, dispatch_concurrently=False)
    assert [r.key for r in rig.chains[0]] == [r.key for r in drt.config.analyst.chain]
    assert "override" in caplog.text and "ignored" in caplog.text


async def test_fallback_run_tags_subject_and_prepends_banner(drt, rig):
    rig.result = _ok(1, [FAILED_OPUS, OK_DEEPSEEK], "deepseek/deepseek-v4.1-flash-1017")
    res = await daily.run_daily(drt, dispatch_concurrently=False)
    assert res["fallback"] is True
    assert res["model_used"] == "deepseek/deepseek-v4.1-flash-1017"
    assert res["failed_models"] == ["claude-opus-5-5"]
    assert res["subject"].endswith("[fallback: deepseek/deepseek-v4.1-flash-1017]")
    (email,) = rig.emails()
    html = email.read_text()
    assert html.startswith("<div") and "Answered by fallback model" in html
    assert "usage limits" in html
    (run,) = drt.store.runs()
    assert [a["ok"] for a in json.loads(run["attempts_json"])] == [False, True]
    assert any(n.startswith("⚠️ HEIM daily:") for n in rig.notes)


async def test_non_fallback_email_unchanged(drt, rig):
    rig.result = _ok(0, [OK_OPUS], "claude-opus-5-5")
    res = await daily.run_daily(drt, dispatch_concurrently=False)
    assert res["fallback"] is False and res["failed_models"] == []
    assert "[fallback" not in res["subject"]
    (email,) = rig.emails()
    assert "Answered by fallback model" not in email.read_text()
    assert rig.notes == []


async def test_failed_attempt_tokens_are_priced_into_the_run(drt, rig):
    drt.config.settings.model_prices = {
        "claude-opus-5-5": {"input": 4.0, "output": 20.0},
        "deepseek/deepseek-v4.1-flash-1017": {"input": 0.15, "output": 0.60}}
    billed = Attempt("anthropic", "claude-opus-5-5", False, "unparseable output", 1_000_000, 0)
    ok = Attempt("openrouter", "deepseek/deepseek-v4.1-flash-1017", True, "", 1_000_000, 1_000_000)
    rig.result = _ok(1, [billed, ok], "deepseek/deepseek-v4.1-flash-1017")
    await daily.run_daily(drt, dispatch_concurrently=False)
    (run,) = drt.store.runs()
    assert run["cost"] == pytest.approx(4.0 + 0.15 + 0.60)
    assert (run["input_tokens"], run["output_tokens"]) == (2_000_000, 1_000_000)


async def test_all_fail_sends_failure_email_and_reraises(drt, rig):
    from heim.llm import AnalystChainFailed
    second = Attempt("openrouter", "deepseek/deepseek-v4.1-flash-1017", False, "HTTPStatusError: 429")
    rig.result = AnalystChainFailed([FAILED_OPUS, second])
    with pytest.raises(AnalystChainFailed):
        await daily.run_daily(drt, dispatch_concurrently=False)
    (email,) = rig.emails()
    assert "NOT produced" in email.name
    html = email.read_text()
    assert "claude-opus-5-5" in html and "429" in html
    assert drt.store.runs() == []


async def test_all_fail_when_email_send_raises_still_raises_chain_failure(drt, rig, monkeypatch):
    from heim.llm import AnalystChainFailed

    async def smtp_down(subject, html):
        raise OSError("smtp down")

    monkeypatch.setattr(drt, "send_email", smtp_down)
    rig.result = AnalystChainFailed([FAILED_OPUS])
    with pytest.raises(AnalystChainFailed):
        await daily.run_daily(drt, dispatch_concurrently=False)


def test_failure_subject_constant():
    assert FAILURE_SUBJECT.startswith("HEIM daily report NOT produced")


async def test_openai_compat_http_error_keeps_the_response_body(monkeypatch):
    import httpx

    class _BadResp:
        status_code = 402
        text = '{"error": {"message": "Insufficient credits"}}'

        def raise_for_status(self):
            req = httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
            raise httpx.HTTPStatusError("402 Payment Required", request=req,
                                        response=httpx.Response(402, request=req))

    class _BadHttp(_Http):
        async def post(self, url, headers=None, json=None):
            return _BadResp()

    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    monkeypatch.setattr("heim.llm.httpx.AsyncClient", lambda *a, **k: _BadHttp({}))
    with pytest.raises(AnalystChainFailed) as ei:
        await run_chain([ModelRef(**DEEPSEEK)], "sys", "user", 8192)
    err = ei.value.attempts[0].error
    assert "402" in err and "Insufficient credits" in err
    assert "developer.mozilla.org" not in err
