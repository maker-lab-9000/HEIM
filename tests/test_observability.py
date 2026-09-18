"""Deeper agent observability (roadmap §5.6).

Four features, one file: per-step token attribution out of the runner, cost
accounting end to end (settings price table → llm/agent usage → store →
dashboard), the optional size-capped full transcript, and the ``/telemetry``
Prometheus exposition.
"""
from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.agent.runner import run_agent
from heim.config import AgentCfg, AnalystCfg, ModelRef, load_config
from heim.costing import cost_of
from heim.dashboard import format as fmt
from heim.dashboard.app import create_app, exposition
from heim.incidents.store import IncidentStore
from heim.llm import analyst_complete
from heim.pipelines.investigate import TRANSCRIPT_MAX_BYTES, _transcript_json

ROOT = Path(__file__).resolve().parent.parent

DUMMY_ENV = {
    "HEIM_SERVER_IP": "10.0.0.10",
    "HEIM_PROXMOX_IP": "10.0.0.2",
    "HEIM_HA_IP": "10.0.0.3",
    "HEIM_TELEGRAM_CHAT_ID": "111111111",
    "HEIM_EMAIL_TO": "test@example.com",
    "HEIM_EMAIL_FROM": "test@example.com",
}

PRICES = {"claude-sonnet-4-6": {"input": 3.0, "output": 15.0}}

SUMMARY_OUTPUT = "## Summary\n\nDisk filled up.\n"


# ------------------------------------------------- anthropic client stubs
#
# Same shape as tests/test_tracking.py's, kept local so the two files can
# drift independently.


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
        self.kwargs: list[dict] = []

    async def create(self, **kwargs):
        self.kwargs.append(kwargs)
        return self._script.pop(0)


class _FakeClient:
    def __init__(self, script: list):
        self.messages = _FakeMessages(script)


class StubTool:
    def __init__(self, name: str, result: str = "ok"):
        self.name = name
        self._result = result

    def anthropic_schema(self) -> dict:
        return {"name": self.name, "description": "stub", "input_schema": {"type": "object"}}

    async def __call__(self, args: dict) -> str:
        return self._result

    async def close(self) -> None:
        pass


def _agent_cfg(**kw) -> AgentCfg:
    return AgentCfg(name="investigator", model="claude-sonnet-4-6", **kw)


def _patch_client(monkeypatch, script: list) -> _FakeClient:
    client = _FakeClient(script)
    monkeypatch.setattr("heim.agent.runner.AsyncAnthropic", lambda *a, **k: client)
    return client


# ============================================ 1. per-step token attribution


async def test_turn_usage_lands_on_the_first_step_of_the_turn(monkeypatch):
    """One turn, three tool calls: the first carries the delta, the rest 0.

    The API bills a turn, not a call, so there is no honest per-call split.
    What must hold is that the column SUMS to the run's real usage.
    """
    _patch_client(monkeypatch, [
        _Resp([_ToolUse("a", "stub", {"n": 1}),
               _ToolUse("b", "stub", {"n": 2}),
               _ToolUse("c", "stub", {"n": 3})], "tool_use", (1000, 60)),
        _Resp([_ToolUse("d", "stub", {"n": 4})], "tool_use", (1400, 25)),
        _Resp([_Text(SUMMARY_OUTPUT)], "end_turn", (1600, 300)),
    ])
    seen: list[tuple] = []
    res = await run_agent(_agent_cfg(), system="s", user_prompt="u",
                          tools=[StubTool("stub")],
                          on_step=lambda *a: seen.append(a))

    assert [(s[5], s[6]) for s in seen] == [(1000, 60), (0, 0), (0, 0), (1400, 25)]
    # the steps the runner returns carry the same attribution
    assert [(s.input_tokens, s.output_tokens) for s in res.steps] == \
        [(1000, 60), (0, 0), (0, 0), (1400, 25)]
    # and the per-step column sums to the tool-requesting turns' real usage
    assert sum(s[5] for s in seen) == 2400
    assert sum(s[6] for s in seen) == 85
    # the run total additionally includes the final, tool-less turn
    assert (res.input_tokens, res.output_tokens) == (4000, 385)


async def test_turn_credit_goes_to_the_first_EXECUTED_step(monkeypatch):
    """Past the hard cap no step is recorded, so the credit waits for one.

    Otherwise a turn whose first block was refused by the budget would lose
    its usage from the per-step column while still counting in the total.
    """
    _patch_client(monkeypatch, [
        _Resp([_ToolUse("a", "stub", {})], "tool_use", (500, 10)),
        _Resp([_ToolUse("b", "stub", {})], "tool_use", (900, 20)),
        _Resp([_Text(SUMMARY_OUTPUT)], "end_turn", (100, 5)),
    ])
    seen: list[tuple] = []
    res = await run_agent(_agent_cfg(hard_step_cap=1), system="s", user_prompt="u",
                          tools=[StubTool("stub")], on_step=lambda *a: seen.append(a))
    assert [(s[0], s[5], s[6]) for s in seen] == [(1, 500, 10)]
    assert res.forced_final is True


def test_steps_persist_their_turn_usage(tmp_path):
    store = IncidentStore(tmp_path / "t.sqlite3")
    iid = store.create_investigation(host="h", status="running")
    store.add_step(iid, 1, "ssh_diagnostic", input_tokens=1000, output_tokens=60)
    store.add_step(iid, 2, "ssh_diagnostic")            # sibling of the same turn
    steps = store.steps(iid)
    assert [(s["input_tokens"], s["output_tokens"]) for s in steps] == [(1000, 60), (0, 0)]


# =========================================================== 2. cost_of


def test_cost_of_math():
    # 1M in at $3 + 200k out at $15 = 3.00 + 3.00
    assert cost_of("claude-sonnet-4-6", 1_000_000, 200_000, PRICES) == pytest.approx(6.0)
    assert cost_of("claude-sonnet-4-6", 0, 0, PRICES) == 0.0
    assert cost_of("claude-sonnet-4-6", 128_000, 4_200, PRICES) == pytest.approx(0.447)


def test_cost_of_is_none_when_unpriced():
    """Unpriced is NOT free: None so the caller stores 0 and renders a dash."""
    assert cost_of("some-other-model", 1_000_000, 1_000_000, PRICES) is None
    assert cost_of("claude-sonnet-4-6", 10, 10, {}) is None
    assert cost_of("", 10, 10, PRICES) is None
    assert cost_of(None, 10, 10, None) is None
    # a malformed table degrades to unpriced rather than raising mid-run
    assert cost_of("m", 10, 10, {"m": "3 dollars"}) is None
    assert cost_of("m", 10, 10, {"m": {"input": "free"}}) is None
    # a one-sided price is legal: the missing side is 0
    assert cost_of("m", 1_000_000, 1_000_000, {"m": {"input": 2.0}}) == pytest.approx(2.0)


def test_money_rendering():
    assert fmt.money(0.42) == "$0.42"
    assert fmt.money(0.42, "EUR") == "EUR 0.42"
    assert fmt.money(1234.5) == "$1,234.50"
    assert fmt.money(0.0004) == "$0.0004"       # sub-cent keeps its digits
    assert fmt.money(0) == fmt.DASH             # unpriced, not free
    assert fmt.money(None) == fmt.DASH
    assert fmt.money("junk") == fmt.DASH


# ================================================== 3. analyst usage


class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeHttpClient:
    """Stands in for httpx.AsyncClient in llm._complete_openrouter."""

    def __init__(self, payload: dict):
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, **kw):
        return _FakeResponse(self._payload)


async def test_analyst_usage_from_openrouter(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    payload = {"choices": [{"message": {"content": "{}"}}],
               "usage": {"prompt_tokens": 9100, "completion_tokens": 420}}
    monkeypatch.setattr("heim.llm.httpx.AsyncClient",
                        lambda *a, **k: _FakeHttpClient(payload))
    cfg = AnalystCfg(primary=ModelRef(provider="openrouter", model="vendor/model"))
    text, model, usage = await analyst_complete(cfg, "sys", "user")
    assert (text, model) == ("{}", "vendor/model")
    assert usage == {"input": 9100, "output": 420}


async def test_analyst_usage_from_anthropic_fallback(monkeypatch):
    """A fallback changes the price, so the *used* model is what comes back."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")

    def boom(*a, **k):
        raise RuntimeError("openrouter is down")

    monkeypatch.setattr("heim.llm.httpx.AsyncClient", boom)
    monkeypatch.setattr("heim.llm.AsyncAnthropic",
                        lambda *a, **k: _FakeClient([
                            _Resp([_Text("{}")], "end_turn", (7000, 350))]))
    cfg = AnalystCfg(primary=ModelRef(provider="openrouter", model="vendor/model"),
                     fallback=ModelRef(provider="anthropic", model="claude-opus-4-6"))
    text, model, usage = await analyst_complete(cfg, "sys", "user")
    assert (text, model) == ("{}", "claude-opus-4-6")
    assert usage == {"input": 7000, "output": 350}
    # priced against the model that actually answered
    assert cost_of(model, usage["input"], usage["output"],
                   {"claude-opus-4-6": {"input": 3.0, "output": 15.0}}) == pytest.approx(0.026250)


async def test_analyst_usage_is_zero_when_the_provider_reports_none(monkeypatch):
    """An unknown spend is zero, never a guess."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    monkeypatch.setattr("heim.llm.httpx.AsyncClient", lambda *a, **k: _FakeHttpClient(
        {"choices": [{"message": {"content": "{}"}}]}))
    cfg = AnalystCfg(primary=ModelRef(provider="openrouter", model="vendor/model"))
    _text, _model, usage = await analyst_complete(cfg, "sys", "user")
    assert usage == {"input": 0, "output": 0}


# ================================================ 4. store migrations


def test_migrations_add_the_observability_columns_to_an_old_db(tmp_path):
    """A database created before §5.6 gains the columns on the next connect."""
    db = tmp_path / "old.sqlite3"
    store = IncidentStore(db)
    for table, column in (("investigations", "cost"),
                          ("investigations", "transcript_json"),
                          ("investigation_steps", "input_tokens"),
                          ("runs", "cost"), ("runs", "headline")):
        store._db.execute(f"ALTER TABLE {table} DROP COLUMN {column}")
    store._db.commit()
    store.close()

    reopened = IncidentStore(db)                     # the migration runs here
    iid = reopened.create_investigation(host="h", status="complete", cost=0.42,
                                        transcript_json='[{"role": "user"}]')
    rid = reopened.insert_run(kind="daily", run_at="t", input_tokens=9100,
                              output_tokens=420, cost=0.05, headline="All quiet",
                              summary="Nothing to report.")
    reopened.add_step(iid, 1, "ha_api", input_tokens=7, output_tokens=3)

    row = reopened.investigation(iid)
    assert row["cost"] == 0.42 and json.loads(row["transcript_json"]) == [{"role": "user"}]
    assert row["steps"][0]["input_tokens"] == 7
    run = [r for r in reopened.runs() if r["id"] == rid][0]
    assert (run["input_tokens"], run["output_tokens"], run["cost"]) == (9100, 420, 0.05)
    assert run["headline"] == "All quiet" and run["summary"] == "Nothing to report."


def test_usage_totals_sums_both_tables(tmp_path):
    store = IncidentStore(tmp_path / "t.sqlite3")
    assert store.usage_totals() == {"input_tokens": 0, "output_tokens": 0, "cost": 0.0}
    store.create_investigation(host="a", input_tokens=100, output_tokens=10, cost=0.25)
    store.create_investigation(host="b", input_tokens=200, output_tokens=20, cost=0.0)
    store.insert_run(kind="daily", input_tokens=50, output_tokens=5, cost=0.1)
    assert store.usage_totals() == {"input_tokens": 350, "output_tokens": 35, "cost": 0.35}


# =============================================== 5. optional transcripts


async def test_transcript_is_collected_only_when_asked(monkeypatch):
    script = [_Resp([_ToolUse("a", "stub", {"command": "uptime"})], "tool_use"),
              _Resp([_Text(SUMMARY_OUTPUT)], "end_turn")]
    _patch_client(monkeypatch, list(script))
    off = await run_agent(_agent_cfg(), system="s", user_prompt="u",
                          tools=[StubTool("stub")])
    assert off.transcript == []

    _patch_client(monkeypatch, list(script))
    on = await run_agent(_agent_cfg(), system="s", user_prompt="the brief",
                         tools=[StubTool("stub", result="load average: 0.4")],
                         collect_transcript=True)
    assert [t["role"] for t in on.transcript] == ["user", "assistant", "user", "assistant"]
    assert on.transcript[0]["content"] == [{"type": "text", "text": "the brief"}]
    assert on.transcript[1]["content"] == [
        {"type": "tool_use", "name": "stub", "input": {"command": "uptime"}}]
    assert on.transcript[2]["content"] == [
        {"type": "tool_result", "content": "load average: 0.4"}]
    assert on.transcript[3]["content"] == [{"type": "text", "text": SUMMARY_OUTPUT}]
    # plain dicts all the way down: it has to survive json.dumps
    assert json.loads(json.dumps(on.transcript)) == on.transcript


async def test_transcript_tool_results_are_clipped(monkeypatch):
    """The clip is 8 KB — the same ceiling the tools themselves apply to their
    output (``clip_bytes``), so a stored transcript is lossless in practice
    and can be served back as a replay cassette (§5.6 eval harness)."""
    from heim.agent.runner import TRANSCRIPT_RESULT_CHARS

    assert TRANSCRIPT_RESULT_CHARS == 8192
    _patch_client(monkeypatch, [
        _Resp([_ToolUse("a", "stub", {})], "tool_use"),
        _Resp([_Text(SUMMARY_OUTPUT)], "end_turn"),
    ])
    res = await run_agent(_agent_cfg(), system="s", user_prompt="u",
                          tools=[StubTool("stub", result="z" * 50_000)],
                          collect_transcript=True)
    assert res.transcript[2]["content"][0]["content"] == "z" * 8192
    # a realistic (already tool-clipped) result survives whole
    _patch_client(monkeypatch, [
        _Resp([_ToolUse("a", "stub", {})], "tool_use"),
        _Resp([_Text(SUMMARY_OUTPUT)], "end_turn"),
    ])
    whole = await run_agent(_agent_cfg(), system="s", user_prompt="u",
                            tools=[StubTool("stub", result="q" * 8192)],
                            collect_transcript=True)
    assert whole.transcript[2]["content"][0]["content"] == "q" * 8192


def test_transcript_cap_keeps_the_newest_turns():
    """Truncation drops from the FRONT: the turns that produced the conclusion
    are the ones a post-mortem needs."""
    entries = [{"role": "assistant", "seq": i,
                "content": [{"type": "text", "text": "x" * 20_000}]}
               for i in range(60)]
    text = _transcript_json(entries)
    assert len(text.encode("utf-8")) <= TRANSCRIPT_MAX_BYTES
    parsed = json.loads(text)
    marker, kept = parsed[0], parsed[1:]
    assert marker["role"] == "system" and marker["truncated"] > 0
    assert "512 KB" in marker["content"][0]["text"]
    # the tail survived, in order, and the head is what went
    assert [e["seq"] for e in kept] == list(range(60 - len(kept), 60))
    assert kept[-1]["seq"] == 59
    assert marker["truncated"] == 60 - len(kept)


def test_transcript_under_the_cap_is_untouched_and_empty_stays_empty():
    entries = [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]
    assert json.loads(_transcript_json(entries)) == entries
    assert _transcript_json([]) == ""
    assert _transcript_json(None) == ""
    # one turn that alone blows the cap: the marker alone, not half a JSON array
    huge = json.loads(_transcript_json(
        [{"role": "assistant", "content": [{"type": "text", "text": "y" * (600 * 1024)}]}]))
    assert len(huge) == 1 and huge[0]["truncated"] == 1


# ============================================ 6/7/8. the dashboard slice


def _iso(minutes_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat(
        timespec="milliseconds")


TRANSCRIPT = json.dumps([
    {"role": "system", "truncated": 4,
     "content": [{"type": "text", "text": "… 4 earlier turn(s) dropped — capped."}]},
    {"role": "user", "content": [{"type": "text", "text": "Investigate ubuntu-server."}]},
    {"role": "assistant", "content": [
        {"type": "text", "text": "Checking the container memory first."},
        {"type": "tool_use", "name": "prometheus_query", "input": {"promql": "up"}}]},
    {"role": "user", "content": [{"type": "tool_result", "content": "10 series"}]},
])


def _seed(db_path: Path) -> dict:
    store = IncidentStore(db_path)
    ids = {}
    ids["priced"] = store.create_investigation(
        fingerprint="ubuntu-server|mem_used|Memory climbing", host="ubuntu-server",
        host_role="guest", agent_name="investigator", model="claude-sonnet-4-6",
        trigger="poller", status="complete", started_at=_iso(30),
        finished_at=_iso(25), input_tokens=128_000, output_tokens=4_200, n_steps=3,
        cost=0.447, transcript_json=TRANSCRIPT,
        report_md="## Summary\n\nPhotoPrism grew.\n")
    # steps WITH per-turn attribution: a two-call turn, then a single-call turn
    store.add_step(ids["priced"], 1, "prometheus_query",
                   args_json=json.dumps({"promql": "up"}), result_preview="10 series",
                   result_bytes=2150, duration_ms=1200,
                   input_tokens=9000, output_tokens=60)
    store.add_step(ids["priced"], 2, "ssh_diagnostic",
                   args_json=json.dumps({"command": "free -m"}), result_preview="ok",
                   result_bytes=6800, duration_ms=3400)
    store.add_step(ids["priced"], 3, "ssh_diagnostic",
                   args_json=json.dumps({"command": "df -h"}), result_preview="ok",
                   result_bytes=1050, duration_ms=300,
                   input_tokens=3000, output_tokens=40)

    # a legacy row: no cost, no transcript, no per-step tokens
    ids["legacy"] = store.create_investigation(
        fingerprint="homelab|drive_temp|Drive temperature high", host="homelab",
        host_role="hypervisor", agent_name="investigator", model="older-model",
        trigger="daily", status="resolved", started_at=_iso(180),
        finished_at=_iso(176), input_tokens=96_000, output_tokens=3_100, n_steps=2)
    store.add_step(ids["legacy"], 1, "ha_api", args_json=json.dumps({"path": "/x"}),
                   result_preview="42 entities", result_bytes=750, duration_ms=300)
    store.add_step(ids["legacy"], 2, "discover_metrics",
                   args_json=json.dumps({"pattern": "smartmon_.*"}),
                   result_preview="7 metrics", result_bytes=250, duration_ms=210)

    run_at = _iso(5)
    ids["run"] = store.insert_run(run_at=run_at, kind="daily", overall="warning",
                                  model_used="claude-opus-4-6", duration_s=41.5,
                                  counts_json=json.dumps({"warn": 1}),
                                  input_tokens=9100, output_tokens=420, cost=0.0336,
                                  headline="Memory is climbing on ubuntu-server",
                                  summary="One container accounts for the growth.")
    store.insert_findings(ids["run"], run_at, "daily", [
        {"host": "ubuntu-server", "metric": "mem_used", "severity": "critical",
         "summary": "Memory climbing on ubuntu-server", "detail": "18% in 3 days."},
    ], fingerprints=["ubuntu-server|mem_used|Memory climbing"])

    store.upsert([
        {"fingerprint": "ubuntu-server|mem_used|Memory climbing", "host": "ubuntu-server",
         "metric": "mem_used", "severity": "critical", "status": "open",
         "firstSeen": _iso(4000), "lastSeen": _iso(5), "timesSeen": 7, "missedRuns": 0,
         "description": "Working set grew 18%.", "investigated": True},
    ])
    store.suppress("homelab|drive_temp|Drive temperature high", until="",
                   reason="known false positive", created_at=_iso(60))
    store.enqueue_job("investigate", {"host": "ubuntu-server"}, requested_by="dashboard")
    store.close()
    return ids


def _config(tmp_path, monkeypatch):
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("HEIM_DASHBOARD_TOKEN", raising=False)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    return load_config(croot)


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    cfg.settings.db_path = str(tmp_path / "heim.sqlite3")
    # the committed example leaves model_prices empty (no price is asserted in
    # the repo); a deployment fills it in, so the tests do too
    cfg.settings.model_prices = dict(PRICES)
    ids = _seed(Path(cfg.settings.db_path))
    app = create_app(cfg)
    with TestClient(app) as client:
        yield client, ids, cfg


@pytest.fixture()
def client(seeded):
    return seeded[0]


@pytest.fixture()
def ids(seeded):
    return seeded[1]


# ------------------------------------------------------------ burn line


def test_burn_line_uses_tokens_when_present():
    steps = [{"seq": 1, "tool": "prometheus_query", "input_tokens": 9000, "result_bytes": 10},
             {"seq": 2, "tool": "ssh_diagnostic", "input_tokens": 0, "result_bytes": 9999},
             {"seq": 3, "tool": "ssh_diagnostic", "input_tokens": 3000, "result_bytes": 10}]
    segs = fmt.burn_segments(steps)
    assert [s["pct"] for s in segs] == [75.0, 0.0, 25.0]
    assert all(s["basis"] == fmt.BURN_TOKENS for s in segs)
    assert "9.0k tok" in segs[0]["title"] and "75% of input tokens" in segs[0]["title"]


def test_burn_line_falls_back_to_bytes_for_legacy_rows():
    """Rows written before §5.6 keep the honest byte proxy and its own label."""
    segs = fmt.burn_segments([{"seq": 1, "tool": "ha_api", "result_bytes": 750},
                              {"seq": 2, "tool": "discover_metrics", "result_bytes": 250}])
    assert [s["pct"] for s in segs] == [75.0, 25.0]
    assert all(s["basis"] == fmt.BURN_BYTES for s in segs)
    assert "share of tool output" in segs[0]["title"]
    assert "tok" not in segs[0]["title"]


def test_burn_line_bases_are_never_mixed_in_one_bar(client, ids):
    tokens_page = client.get(f"/investigations/{ids['priced']}").text
    assert "share of input tokens per step" in tokens_page
    assert "share of tool output" not in tokens_page
    legacy_page = client.get(f"/investigations/{ids['legacy']}").text
    assert "share of tool output per step" in legacy_page
    assert "of input tokens" not in legacy_page


def test_step_meta_shows_attributed_tokens(client, ids):
    html = client.get(f"/investigations/{ids['priced']}").text
    # the tilde is the honesty marker: a turn's delta on its first call
    assert "~9.0k tok" in html and "~3.0k tok" in html
    # the sibling step of the first turn claims nothing: two of three steps
    assert html.count(" · ~") == 2


# ---------------------------------------------------------------- cost


def test_investigation_detail_shows_cost(client, ids):
    html = client.get(f"/investigations/{ids['priced']}").text
    assert "cost" in html and "$0.45" in html


def test_unpriced_investigation_shows_a_dash_not_zero(client, ids):
    html = client.get(f"/investigations/{ids['legacy']}").text
    meta = html[html.index('<dl class="imeta">'):html.index("</dl>")]
    assert "cost" in meta and "$0.00" not in meta
    assert fmt.DASH in meta


def test_investigations_list_has_a_cost_column(client):
    html = client.get("/investigations").text
    assert '<th scope="col" class="num">cost</th>' in html
    assert "$0.45" in html
    # the header, the ghost row and both data rows all carry the same cell count
    body = html[html.index("<tbody"):]
    for row in body.split("<tr")[1:]:
        if "colspan" not in row:
            assert row.count("<td") == 10


def test_findings_run_header_shows_cost(client):
    html = client.get("/findings").text
    assert "claude-opus-4-6" in html and "$0.03" in html


def test_overview_token_tile_shows_the_24h_cost(client):
    html = client.get("/").text
    assert "tokens 24h" in html
    assert "$0.45" in html


def test_currency_other_than_usd_uses_the_code(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    cfg.settings.db_path = str(tmp_path / "eur.sqlite3")
    cfg.settings.currency = "EUR"
    ids = _seed(Path(cfg.settings.db_path))
    with TestClient(create_app(cfg)) as client:
        html = client.get(f"/investigations/{ids['priced']}").text
        meta = html[html.index('<dl class="imeta">'):html.index("</dl>")]
        assert "EUR 0.45" in meta and "$" not in meta


# ---------------------------------------------------------- transcript


def test_detail_page_renders_the_full_transcript(client, ids):
    html = client.get(f"/investigations/{ids['priced']}").text
    assert "Full transcript (3 turns)" in html          # the marker is not a turn
    assert "… 4 earlier turn(s) dropped" in html        # …it is the note above them
    assert "Investigate ubuntu-server." in html
    assert "Checking the container memory first." in html
    assert "prometheus_query" in html and "promql" in html
    assert 'class="mono wrap"' in html
    # it sits after the report, folded away
    assert html.index("<h2 class=\"eyebrow\">report</h2>") < html.index("Full transcript")


def test_no_transcript_no_section(client, ids):
    html = client.get(f"/investigations/{ids['legacy']}").text
    assert "Full transcript" not in html


def test_unreadable_transcript_does_not_break_the_page(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    cfg.settings.db_path = str(tmp_path / "bad.sqlite3")
    store = IncidentStore(Path(cfg.settings.db_path))
    iid = store.create_investigation(host="ubuntu-server", status="complete",
                                     started_at=_iso(5), transcript_json="{not json")
    store.close()
    with TestClient(create_app(cfg)) as client:
        r = client.get(f"/investigations/{iid}")
        assert r.status_code == 200
        assert "Full transcript" not in r.text


# ----------------------------------------------------------- /telemetry


def test_telemetry_exposition_lines(client):
    r = client.get("/telemetry")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert "version=0.0.4" in r.headers["content-type"]
    body = r.text
    assert "heim_open_incidents 1" in body
    assert "heim_suppressions_active 1" in body
    assert "heim_jobs_queued 1" in body
    assert 'heim_investigations_total{status="complete"} 1' in body
    assert 'heim_investigations_total{status="resolved"} 1' in body
    assert "heim_tokens_in_total 233100" in body        # 128k + 96k + the run's 9.1k
    assert "heim_tokens_out_total 7720" in body
    assert "heim_cost_total 0.4806" in body
    # every metric declares itself, exactly once
    for name in ("heim_open_incidents", "heim_suppressions_active", "heim_jobs_queued",
                 "heim_investigations_total", "heim_tokens_in_total",
                 "heim_tokens_out_total", "heim_cost_total",
                 "heim_last_daily_run_age_seconds"):
        assert body.count(f"# HELP {name} ") == 1, name
        assert body.count(f"# TYPE {name} gauge") == 1, name
    assert body.endswith("\n")
    # HELP/TYPE always precede their samples, and nothing is HTML
    assert body.index("# TYPE heim_open_incidents") < body.index("heim_open_incidents 1")
    assert "<" not in body


def test_telemetry_omits_the_age_gauge_with_no_run(tmp_path, monkeypatch):
    """Absence, not zero: a fresh install must not read as "just ran"."""
    cfg = _config(tmp_path, monkeypatch)
    cfg.settings.db_path = str(tmp_path / "empty.sqlite3")
    with TestClient(create_app(cfg)) as client:
        body = client.get("/telemetry").text
        assert "heim_last_daily_run_age_seconds" not in body
        assert "NaN" not in body
        assert "heim_open_incidents 0" in body
        # no investigations at all: the family still declares itself, no samples
        assert "# TYPE heim_investigations_total gauge" in body
        assert "heim_investigations_total{" not in body


def test_telemetry_age_gauge_tracks_the_last_daily_run(client):
    body = client.get("/telemetry").text
    line = [x for x in body.splitlines()
            if x.startswith("heim_last_daily_run_age_seconds ")][0]
    age = float(line.split()[1])
    assert 250 < age < 400            # seeded 5 minutes ago


def test_telemetry_is_auth_exempt_like_healthz(seeded, monkeypatch):
    """Prometheus cannot carry the basic-auth password, and the endpoint holds
    only aggregates — so it is exempt, and the pages are not."""
    client, _ids, _cfg = seeded
    monkeypatch.setenv("HEIM_DASHBOARD_TOKEN", "s3cret")
    assert client.get("/").status_code == 401
    assert client.get("/investigations").status_code == 401
    assert client.get("/healthz").status_code == 200
    r = client.get("/telemetry")
    assert r.status_code == 200 and "heim_open_incidents" in r.text


def test_exposition_escapes_label_values():
    text = exposition({"open_incidents": 0, "suppressions_active": 0, "jobs_queued": 0,
                       "by_status": {'we"ird\\': 2, "plain": 1},
                       "usage": {"input_tokens": 1, "output_tokens": 2, "cost": 0},
                       "last_daily_age_s": None, "currency": "EUR"})
    assert 'heim_investigations_total{status="we\\"ird\\\\"} 2' in text
    assert 'heim_investigations_total{status="plain"} 1' in text
    # the cost HELP names the deployment's currency
    assert "# HELP heim_cost_total Money spent across investigations and runs, in EUR." in text
    assert "heim_cost_total 0" in text


def test_exposition_never_uses_exponent_notation():
    text = exposition({"open_incidents": 0, "suppressions_active": 0, "jobs_queued": 0,
                       "by_status": {}, "last_daily_age_s": 0,
                       "usage": {"input_tokens": 12_000_000, "output_tokens": 0,
                                 "cost": 1234.5},
                       "currency": "USD"})
    assert "heim_tokens_in_total 12000000" in text
    assert "heim_cost_total 1234.5" in text
    assert "e+" not in text and "e-" not in text


def test_prometheus_config_documents_the_scrape_job():
    text = (ROOT / "prometheus/prometheus.yml").read_text()
    assert "# - job_name: 'heim'" in text
    assert "#   metrics_path: /telemetry" in text
    # commented out: enabling it is the operator's decision, and the target is
    # a placeholder rather than somebody's real address
    assert "\n  - job_name: 'heim'" not in text
    assert "<heim-host>:8300" in text


# --------------------------------------------------------- config surface


def test_settings_defaults_are_the_safe_ones(tmp_path, monkeypatch):
    """The CODE default is still priceless — an unpriced model renders '—'.

    The shipped settings file now carries real, sourced prices (see
    test_shipped_prices_are_real_sourced_and_dated), but Settings itself must
    keep defaulting to {} so a deployment that deletes the block degrades to
    '—' rather than to a fabricated zero.
    """
    from heim.config import Settings
    bare = Settings(prometheus={"url": "http://x:9090"})
    assert bare.model_prices == {}
    assert bare.currency == "USD"
    assert bare.store_transcripts is False
    cfg = _config(tmp_path, monkeypatch)
    assert cfg.settings.currency == "USD"
    assert cfg.settings.store_transcripts is False


def test_both_settings_yamls_document_the_new_knobs():
    example = (ROOT / "config/settings.example.yaml").read_text()
    live = (ROOT / "config/settings.yaml").read_text()
    for text in (example, live):
        assert "\nmodel_prices:" in text
        assert "currency: USD" in text
        assert "store_transcripts: false" in text


def test_shipped_prices_are_real_sourced_and_dated():
    """Prices are allowed in the repo ONLY when they are sourced and dated.

    Supersedes the earlier "never ship a price" rule: the operator asked for
    current rates, so the guard moved from "no prices" to "no UNSOURCED
    prices" — a reader must be able to see where a number came from and when
    it was checked, because provider rates drift.
    """
    import re
    import yaml
    example = (ROOT / "config/settings.example.yaml").read_text()
    assert "verified 2026-" in example, "price block must carry a verification date"
    assert re.search(r"Anthropic|provider", example), "price block must name its source"
    prices = yaml.safe_load(example)["model_prices"]
    assert prices, "model_prices must not be empty once shipped"
    for model, rate in prices.items():
        assert set(rate) == {"input", "output"}, model
        assert rate["output"] >= rate["input"] >= 0, model  # output always costs more


def test_price_keys_cover_the_configured_agent_models(tmp_path, monkeypatch):
    """Every model the agents are configured to use must be priced, or its
    cost silently renders '—' on the dashboard."""
    cfg = _config(tmp_path, monkeypatch)
    priced = set(cfg.settings.model_prices)
    assert cfg.agents["investigator"].model in priced
    assert cfg.analyst.fallback.model in priced
    assert cfg.analyst.primary.model in priced


def test_no_dashboard_token_leaks_into_the_environment():
    assert "HEIM_DASHBOARD_TOKEN" not in os.environ


# ----------------------------------------------------------- health card


def test_health_card_shows_the_analysis_and_every_host(client):
    html = client.get("/").text
    card = html[html.index('class="card health"'):html.index("latest runs")]
    # the analyst's words, not counters
    assert "Memory is climbing on ubuntu-server" in card
    assert "One container accounts for the growth." in card
    assert 'href="/findings#run-1"' in card
    # …and one chip per configured host, including the ones that are fine
    for host in ("ubuntu-server", "homelab", "home-assistant"):
        assert host in card
    assert "1 critical" in card and card.count("clear") == 2


def test_health_card_survives_a_run_with_no_headline(tmp_path, monkeypatch):
    """Runs written before §5.6 have no headline: the host strip still shows."""
    cfg = _config(tmp_path, monkeypatch)
    cfg.settings.db_path = str(tmp_path / "old.sqlite3")
    store = IncidentStore(Path(cfg.settings.db_path))
    store.insert_run(kind="daily", run_at=_iso(5), overall="healthy")
    store.close()
    with TestClient(create_app(cfg)) as client:
        card = client.get("/").text
        assert 'class="card health"' in card
        assert "ubuntu-server" in card and card.count("clear") == 3


# ------------------------------------------------------------ tool usage


def test_tool_usage_groups_by_tool_agent_and_model(tmp_path):
    """Two agents on two models: the same tool name is not one row."""
    store = IncidentStore(tmp_path / "t.sqlite3")
    a = store.create_investigation(host="h1", agent_name="investigator",
                                   model="claude-sonnet-4-6", status="complete")
    b = store.create_investigation(host="h2", agent_name="triager",
                                   model="claude-haiku-4-6", status="complete")
    store.add_step(a, 1, "ssh_diagnostic", duration_ms=1000, input_tokens=900,
                   output_tokens=100)
    store.add_step(a, 2, "ssh_diagnostic", duration_ms=3000, blocked=True)
    store.add_step(a, 3, "ssh_diagnostic", duration_ms=2000)
    store.add_step(a, 4, "prometheus_query", duration_ms=500)
    store.add_step(b, 1, "ssh_diagnostic", duration_ms=100)
    store.add_step(b, 2, "ha_api", duration_ms=200, blocked=True)

    rows = store.tool_usage()
    # busiest first
    assert [(r["tool"], r["agent_name"], r["calls"]) for r in rows][0] == \
        ("ssh_diagnostic", "investigator", 3)
    by_key = {(r["tool"], r["model"]): r for r in rows}
    ssh = by_key[("ssh_diagnostic", "claude-sonnet-4-6")]
    assert ssh["blocked"] == 1
    assert ssh["avg_ms"] == pytest.approx(2000.0)         # (1000+3000+2000)/3
    assert ssh["tokens"] == 1000                          # in + out, attributed
    # the same tool under the other agent stays its own row
    other = by_key[("ssh_diagnostic", "claude-haiku-4-6")]
    assert (other["calls"], other["agent_name"], other["tokens"]) == (1, "triager", 0)
    assert by_key[("ha_api", "claude-haiku-4-6")]["blocked"] == 1
    assert len(store.tool_usage(limit=2)) == 2


def test_tool_usage_is_empty_without_steps(tmp_path):
    store = IncidentStore(tmp_path / "t.sqlite3")
    store.create_investigation(host="h", status="declined")   # no steps
    assert store.tool_usage() == []


def test_short_model():
    assert fmt.short_model("claude-sonnet-4-6") == "claude-sonnet-4-6"
    assert fmt.short_model("google/gemma-4-31b-it:free") == "gemma-4-31b-it"
    assert fmt.short_model("") == fmt.DASH
    long = fmt.short_model("an-extremely-long-model-identifier-v4-6")
    assert len(long) == fmt.MODEL_WIDTH and "…" in long
    # both ends survive, so neighbouring versions stay distinguishable
    assert long.endswith("4-6")


def test_overview_tool_usage_card(client):
    html = client.get("/").text
    assert "tool usage" in html
    table = html[html.index("tool usage"):html.index("recent investigations")]
    # tool badges carry identity; the bar is only magnitude
    assert 'class="tool t-ssh"' in table and 'class="tool t-prometheus"' in table
    assert "investigator · claude-sonnet-4-6" in table
    assert 'class="tubar"' in table and "width:100.0%" in table
    # busiest first: ssh_diagnostic (2 calls) above the 1-call rows
    assert table.index("t-ssh") < table.index("t-prometheus")
    # per-step tokens where they exist, an em dash for the legacy investigation
    assert "3.0k" in table                     # ssh_diagnostic: 0 + (3000+40)
    assert "9.1k" in table                     # prometheus_query: 9000+60
    assert fmt.DASH in table
    # the card sits between the runs and the investigations list
    assert html.index("latest runs") < html.index("tool usage")


def test_overview_tool_usage_empty_state(tmp_path, monkeypatch):
    cfg = _config(tmp_path, monkeypatch)
    cfg.settings.db_path = str(tmp_path / "empty.sqlite3")
    with TestClient(create_app(cfg)) as client:
        # the page's global empty state hides the cards, so seed one row that
        # is not a step: the card must then render its own empty state
        store = IncidentStore(Path(cfg.settings.db_path))
        store.create_investigation(host="ubuntu-server", status="declined",
                                   started_at=_iso(5))
        store.close()
        html = client.get("/").text
        assert "No tool calls recorded yet — the first investigation fills this in." in html
