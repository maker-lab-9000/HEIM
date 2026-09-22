"""The eval/replay harness (roadmap §5.6, the last open item).

Three layers, one file: the cassette (transcript → recorded tool results),
the offline replay pipeline (a second investigation row, no channels, no
network beyond the LLM), and the CLI comparison the whole thing exists for.

The cassette fixtures are produced by running the REAL ``run_agent`` against a
stubbed Anthropic client — never by hand-writing the §5.6 transcript format.
The cassette parser is coupled to that format, and a hand-written fixture
would let the two drift apart while the tests stayed green.
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.agent.cassette import MISS_RESULT, Cassette, CassetteTool, cassette_tools
from heim.agent.runner import run_agent
from heim.config import AgentCfg, load_config
from heim.dashboard.app import create_app
from heim.incidents.store import IncidentStore
from heim.pipelines.investigate import _transcript_json
from heim.pipelines.replay import ReplayError, run_replay
from heim.runtime import Runtime
from heim.tools.base import ToolContext

ROOT = Path(__file__).resolve().parent.parent

DUMMY_ENV = {
    "HEIM_SERVER_IP": "10.0.0.10",
    "HEIM_PROXMOX_IP": "10.0.0.2",
    "HEIM_HA_IP": "10.0.0.3",
    "HEIM_TELEGRAM_CHAT_ID": "111111111",
    "HEIM_EMAIL_TO": "test@example.com",
    "HEIM_EMAIL_FROM": "test@example.com",
}

ORIGINAL_REPORT = (
    "## Summary\n\nPhotoPrism filled /var.\n\n"
    "## Root cause\n\nThe PhotoPrism import cache grew to 40 GB.\nConfidence: high\n\n"
    "## Recommended remediation\n\n- Cap the cache\n"
)
REPLAY_REPORT = (
    "## Summary\n\nDisk pressure on /var.\n\n"
    "## Root cause\n\nThe PhotoPrism thumbnail cache grew to 40 GB.\nConfidence: medium\n\n"
    "## Recommended remediation\n\n- Cap the cache\n"
)


# ---------------------------------------------------------------- fixtures


@pytest.fixture()
def rt(tmp_path, monkeypatch) -> Runtime:
    """A Runtime on the committed example config, every channel disabled."""
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    cfg.settings.loki = None
    cfg.settings.email = None
    cfg.settings.home_assistant = None
    cfg.settings.telegram = None
    cfg.settings.store_transcripts = True
    # keyed on the configured investigator model, so a replay with no override
    # is priced whatever model config/agents/investigator.yaml names
    cfg.settings.model_prices = {cfg.agents["investigator"].model: {"input": 3.0, "output": 15.0},
                                 "claude-haiku-4-6": {"input": 0.8, "output": 4.0}}
    cfg.settings.db_path = str(tmp_path / "rt.sqlite3")
    return Runtime(config=cfg, store=IncidentStore(tmp_path / "rt.sqlite3"),
                   dry_run=True, out_dir=tmp_path / "out")


# ------------------------------------------------------ anthropic stubs


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
    def __init__(self, content: list, stop_reason: str, usage=(100, 20)):
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


def _patch_client(monkeypatch, script: list) -> _FakeClient:
    client = _FakeClient(script)
    monkeypatch.setattr("heim.agent.runner.AsyncAnthropic", lambda *a, **k: client)
    return client


async def _record_transcript(monkeypatch) -> list[dict]:
    """A real transcript from a real ``run_agent``: three tool calls (one turn
    with two of them), two different tools, then the report."""
    _patch_client(monkeypatch, [
        _Resp([_ToolUse("a", "ssh_diagnostic", {"command": "df -h"})], "tool_use"),
        _Resp([_ToolUse("b", "ssh_diagnostic", {"command": "sudo du -shx /var/*"}),
               _ToolUse("c", "prometheus_query", {"promql": "node_filesystem_avail_bytes"})],
              "tool_use"),
        _Resp([_Text(ORIGINAL_REPORT)], "end_turn"),
    ])
    result = await run_agent(
        AgentCfg(name="investigator", model="claude-sonnet-4-6"),
        system="s", user_prompt="Investigate ubuntu-server.",
        tools=[StubTool("ssh_diagnostic", result="/dev/sda1  92% /"),
               StubTool("prometheus_query", result="2.1e9")],
        collect_transcript=True,
    )
    return result.transcript


def _seed_original(rt: Runtime, transcript: list[dict], **overrides) -> int:
    fields = dict(
        fingerprint="ubuntu-server|fs_used|/", host="ubuntu-server", host_role="guest",
        agent_name="investigator", model="claude-sonnet-4-6", trigger="daily",
        status="complete", started_at="2026-09-01T07:00:00.000+02:00",
        finished_at="2026-09-01T07:04:00.000+02:00",
        input_tokens=120_000, output_tokens=3_000, n_steps=3, cost=0.405,
        brief_md='Investigate the following alert(s) on host "ubuntu-server".\n\n'
                 "DETECTED FINDINGS:\n1. [warning] Filesystem used — 92%\n",
        findings_json=json.dumps([{"severity": "warning", "host": "ubuntu-server",
                                   "metric": "Filesystem used", "detail": "92%"}]),
        report_md=ORIGINAL_REPORT,
        transcript_json=_transcript_json(transcript),
    )
    fields.update(overrides)
    return rt.store.create_investigation(**fields)


# ========================================================== 1. the cassette


async def test_from_transcript_extracts_the_ordered_triples(monkeypatch):
    """Against the real §5.6 serialization, not a hand-written imitation."""
    cassette = Cassette.from_transcript(await _record_transcript(monkeypatch))
    assert [(e.tool, e.args, e.result) for e in cassette.entries] == [
        ("ssh_diagnostic", {"command": "df -h"}, "/dev/sda1  92% /"),
        ("ssh_diagnostic", {"command": "sudo du -shx /var/*"}, "/dev/sda1  92% /"),
        ("prometheus_query", {"promql": "node_filesystem_avail_bytes"}, "2.1e9"),
    ]
    # multi-call turns pair positionally: the 2nd tool_use of turn 2 got the
    # 2nd tool_result of the following user turn
    assert cassette.tools == ["ssh_diagnostic", "prometheus_query"]
    assert cassette.stats() == {"recorded": 3, "exact": 0, "fuzzy": 0,
                                "missed": 0, "unused": 3}


async def test_cassette_survives_a_json_roundtrip_through_the_store(rt, monkeypatch):
    """What actually feeds a replay is the stored *string*, not the live list."""
    transcript = await _record_transcript(monkeypatch)
    inv_id = _seed_original(rt, transcript)
    stored = json.loads(rt.store.investigation(inv_id)["transcript_json"])
    assert len(Cassette.from_transcript(stored).entries) == 3


async def test_exact_match_wins_over_order(monkeypatch):
    cassette = Cassette.from_transcript(await _record_transcript(monkeypatch))
    # the du call is the SECOND ssh entry; asking for it by args must not
    # serve the df recording that happens to be first
    result, kind = cassette.take("ssh_diagnostic", {"command": "sudo du -shx /var/*"})
    assert kind == "exact" and result == "/dev/sda1  92% /"
    assert cassette.entries[1].used is True and cassette.entries[0].used is False
    # argument order must not matter
    c2 = Cassette.from_transcript([
        {"role": "assistant", "content": [
            {"type": "tool_use", "name": "ha_api", "input": {"path": "/api/states", "q": 1}}]},
        {"role": "user", "content": [{"type": "tool_result", "content": "42 entities"}]},
    ])
    assert c2.take("ha_api", {"q": 1, "path": "/api/states"}) == ("42 entities", "exact")


async def test_fuzzy_falls_back_to_the_oldest_unused_entry_of_the_same_tool(monkeypatch):
    cassette = Cassette.from_transcript(await _record_transcript(monkeypatch))
    result, kind = cassette.take("ssh_diagnostic", {"command": "df -hT --total"})
    assert kind == "fuzzy" and result == "/dev/sda1  92% /"
    assert cassette.entries[0].used is True          # the oldest, not a later one


async def test_each_entry_is_served_once_then_it_is_a_miss(monkeypatch):
    cassette = Cassette.from_transcript(await _record_transcript(monkeypatch))
    assert cassette.take("ssh_diagnostic", {"command": "df -h"})[1] == "exact"
    assert cassette.take("ssh_diagnostic", {"command": "df -h"})[1] == "fuzzy"   # the du tape
    third = cassette.take("ssh_diagnostic", {"command": "df -h"})
    assert third == (MISS_RESULT, "miss")
    assert "no recorded result" in third[0] and json.loads(third[0])["replay"]
    assert cassette.stats() == {"recorded": 3, "exact": 1, "fuzzy": 1,
                                "missed": 1, "unused": 1}


async def test_miss_for_a_tool_that_was_never_recorded(monkeypatch):
    cassette = Cassette.from_transcript(await _record_transcript(monkeypatch))
    assert cassette.take("proxmox_api", {"path": "/nodes"}) == (MISS_RESULT, "miss")


def test_from_transcript_tolerates_truncation_and_dangling_calls():
    """A front-truncated transcript starts mid-conversation; a crashed run ends
    on an unanswered tool_use. Both must yield a usable cassette."""
    cassette = Cassette.from_transcript([
        {"role": "system", "truncated": 4,
         "content": [{"type": "text", "text": "… 4 earlier turn(s) dropped"}]},
        # orphan result: its tool_use was dropped by the cap
        {"role": "user", "content": [{"type": "tool_result", "content": "orphan"}]},
        {"role": "assistant", "content": [
            {"type": "text", "text": "checking"},
            {"type": "tool_use", "name": "ha_api", "input": {"path": "/api/config"}}]},
        {"role": "user", "content": [{"type": "tool_result", "content": "2026.8.1"}]},
        # a call that never got its result (the run died here)
        {"role": "assistant", "content": [
            {"type": "tool_use", "name": "ha_api", "input": {"path": "/api/error_log"}}]},
    ])
    assert [(e.tool, e.result) for e in cassette.entries] == [("ha_api", "2026.8.1")]
    assert Cassette.from_transcript([]).entries == []
    assert Cassette.from_transcript(None).entries == []
    assert Cassette.from_transcript(["junk", {"role": "user"}]).entries == []


# ---------------------------------------------------------- cassette tools


async def test_cassette_tools_carry_the_real_tool_definitions(rt, monkeypatch):
    cassette = Cassette.from_transcript(await _record_transcript(monkeypatch))
    tools = cassette_tools(cassette, rt.config, ToolContext(config=rt.config))
    assert [t.name for t in tools] == ["ssh_diagnostic", "prometheus_query"]
    assert all(isinstance(t, CassetteTool) for t in tools)
    ssh = tools[0]
    real = rt.config.tools["ssh_diagnostic"]
    assert ssh.anthropic_schema() == {
        "name": "ssh_diagnostic", "description": real.description,
        "input_schema": real.input_schema(),
    }
    # and it answers from the tape, with no I/O of any kind
    assert await ssh({"command": "df -h"}) == "/dev/sda1  92% /"
    assert cassette.exact == 1


async def test_cassette_tool_for_an_unknown_tool_gets_a_synthetic_definition(rt):
    cassette = Cassette.from_transcript([
        {"role": "assistant", "content": [
            {"type": "tool_use", "name": "retired_tool", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "content": "old evidence"}]},
    ])
    tools = cassette_tools(cassette, rt.config, ToolContext(config=rt.config))
    assert [t.name for t in tools] == ["retired_tool"]
    assert "Replay-only tool" in tools[0].anthropic_schema()["description"]
    assert await tools[0]({}) == "old evidence"


# ===================================================== 2. the replay pipeline


def _replay_script(report: str = REPLAY_REPORT) -> list:
    """The replayed model: one ssh call it also made, one it did not."""
    return [
        _Resp([_ToolUse("r1", "ssh_diagnostic", {"command": "df -h"})], "tool_use", (900, 40)),
        _Resp([_ToolUse("r2", "ssh_diagnostic", {"command": "ls -la /var/tmp"})],
              "tool_use", (300, 10)),
        _Resp([_Text(report)], "end_turn", (200, 60)),
    ]


async def test_run_replay_stores_a_second_investigation(rt, monkeypatch):
    inv_id = _seed_original(rt, await _record_transcript(monkeypatch))
    _patch_client(monkeypatch, _replay_script())

    res = await run_replay(rt, inv_id)
    assert res is not None and res["replay_of"] == inv_id

    row = rt.store.investigation(res["id"])
    assert row["trigger"] == "replay" and row["replay_of"] == inv_id
    assert row["status"] == "complete" and row["incomplete_reason"] == ""
    assert row["host"] == "ubuntu-server" and row["host_role"] == "guest"
    assert row["model"] == rt.config.agents["investigator"].model
    # provenance copied verbatim from the original — same question, same brief
    assert row["brief_md"] == rt.store.investigation(inv_id)["brief_md"]
    assert json.loads(row["findings_json"])[0]["metric"] == "Filesystem used"
    assert row["report_md"] == REPLAY_REPORT.strip()   # salvage trims
    assert (row["input_tokens"], row["output_tokens"], row["n_steps"]) == (1400, 110, 2)
    assert row["cost"] == pytest.approx((1400 * 3.0 + 110 * 15.0) / 1e6)
    assert row["started_at"] and row["finished_at"]

    # the standard step recorder ran: the tape's evidence is on the steps
    steps = row["steps"]
    assert [s["seq"] for s in steps] == [1, 2]
    assert steps[0]["result_preview"] == "/dev/sda1  92% /"          # exact match
    assert steps[1]["result_preview"] == "/dev/sda1  92% /"          # fuzzy: the du tape
    assert res["cassette"] == {"recorded": 3, "exact": 1, "fuzzy": 1,
                               "missed": 0, "unused": 1}
    # the replay records its own transcript, so it can itself be replayed
    assert json.loads(row["transcript_json"])[0]["content"][0]["text"].startswith(
        "Investigate the following alert(s)")
    # and the original is untouched
    assert rt.store.investigation(inv_id)["report_md"] == ORIGINAL_REPORT


async def test_replay_serves_the_miss_stub_and_still_completes(rt, monkeypatch):
    inv_id = _seed_original(rt, await _record_transcript(monkeypatch))
    _patch_client(monkeypatch, [
        _Resp([_ToolUse("r1", "prometheus_query", {"promql": "up"})], "tool_use"),
        _Resp([_ToolUse("r2", "prometheus_query", {"promql": "up"})], "tool_use"),
        _Resp([_Text(REPLAY_REPORT)], "end_turn"),
    ])
    res = await run_replay(rt, inv_id)
    assert res["cassette"]["missed"] == 1
    steps = rt.store.investigation(res["id"])["steps"]
    assert "no recorded result" in steps[1]["result_preview"]


async def test_replay_of_an_investigation_without_a_transcript_says_what_to_set(rt):
    inv_id = rt.store.create_investigation(host="ubuntu-server", status="complete",
                                           brief_md="b", report_md=ORIGINAL_REPORT)
    with pytest.raises(ReplayError) as exc:
        await run_replay(rt, inv_id)
    assert "store_transcripts: true" in str(exc.value)
    assert f"#{inv_id}" in str(exc.value)


async def test_replay_rejects_unknown_id_broken_transcript_and_missing_brief(rt, monkeypatch):
    with pytest.raises(ReplayError, match="no investigation #4242"):
        await run_replay(rt, 4242)

    transcript = await _record_transcript(monkeypatch)
    no_brief = _seed_original(rt, transcript, brief_md="")
    with pytest.raises(ReplayError, match="no stored brief_md"):
        await run_replay(rt, no_brief)

    broken = _seed_original(rt, transcript)
    rt.store.update_investigation(broken, transcript_json="{not json")
    with pytest.raises(ReplayError, match="unreadable transcript_json"):
        await run_replay(rt, broken)


async def test_model_override_reaches_the_api_call_and_the_row(rt, monkeypatch):
    configured = rt.config.agents["investigator"].model   # captured BEFORE the run
    inv_id = _seed_original(rt, await _record_transcript(monkeypatch))
    client = _patch_client(monkeypatch, _replay_script())

    res = await run_replay(rt, inv_id, model="claude-haiku-4-6")
    assert {k["model"] for k in client.messages.kwargs} == {"claude-haiku-4-6"}
    assert res["model"] == "claude-haiku-4-6"
    assert rt.store.investigation(res["id"])["model"] == "claude-haiku-4-6"
    # priced against the model that actually answered
    assert res["cost"] == pytest.approx((1400 * 0.8 + 110 * 4.0) / 1e6)
    # the configured agent is not mutated for the next caller
    assert rt.config.agents["investigator"].model == configured


async def test_default_system_prompt_is_the_investigators(rt, monkeypatch):
    inv_id = _seed_original(rt, await _record_transcript(monkeypatch))
    client = _patch_client(monkeypatch, _replay_script())
    await run_replay(rt, inv_id)
    system = client.messages.kwargs[0]["system"]
    assert system.startswith("You are a senior SRE")
    assert "${" not in system                     # env-expanded, like the real run
    assert "ubuntu-server" in system


async def test_prompt_file_override_is_rendered_and_env_expanded(rt, tmp_path, monkeypatch):
    monkeypatch.setenv("HEIM_SERVER_IP", "10.0.0.10")
    candidate = tmp_path / "candidate.md.j2"
    candidate.write_text("CANDIDATE PROMPT. budget={{ soft_step_budget }} "
                         "ip=${HEIM_SERVER_IP}\n{{ facts }}")
    inv_id = _seed_original(rt, await _record_transcript(monkeypatch))
    client = _patch_client(monkeypatch, _replay_script())

    res = await run_replay(rt, inv_id, prompt_file=str(candidate))
    system = client.messages.kwargs[0]["system"]
    assert system.startswith("CANDIDATE PROMPT.")
    assert "budget=15" in system and "ip=10.0.0.10" in system     # jinja + ${VAR}
    assert res["prompt_file"] == str(candidate)


async def test_replay_opens_no_channels_and_no_live_tools(rt, monkeypatch):
    """The only outbound call a replay may make is the LLM one."""
    def boom(*a, **k):                     # pragma: no cover - must never run
        raise AssertionError("a replay must not build live tools")

    monkeypatch.setattr("heim.tools.base.load_tools", boom)
    for name in ("send_email", "push_ha", "emit_loki", "notify"):
        monkeypatch.setattr(Runtime, name, boom)

    inv_id = _seed_original(rt, await _record_transcript(monkeypatch))
    _patch_client(monkeypatch, _replay_script())
    assert (await run_replay(rt, inv_id)) is not None


async def test_a_crashing_replay_is_recorded_not_raised(rt, monkeypatch):
    inv_id = _seed_original(rt, await _record_transcript(monkeypatch))

    async def boom(*a, **k):
        raise RuntimeError("model exploded")

    monkeypatch.setattr("heim.pipelines.replay.run_agent", boom)
    assert (await run_replay(rt, inv_id)) is None
    replay_row = [r for r in rt.store.investigations() if r["trigger"] == "replay"][0]
    assert replay_row["status"] == "failed"
    assert "model exploded" in replay_row["incomplete_reason"]


async def test_replay_output_without_a_summary_is_incomplete(rt, monkeypatch):
    inv_id = _seed_original(rt, await _record_transcript(monkeypatch))
    _patch_client(monkeypatch, _replay_script(report="I will now run df -h."))
    res = await run_replay(rt, inv_id)
    assert res["status"] == "incomplete" and res["incomplete"] is True
    row = rt.store.investigation(res["id"])
    assert row["status"] == "incomplete" and row["incomplete_reason"]
    # the salvaged report still carries the ORIGINAL findings as provenance
    assert "Filesystem used" in row["report_md"]


# ================================================================ 3. the CLI


async def test_cli_replay_prints_the_comparison(rt, monkeypatch, capsys):
    from heim import cli

    inv_id = _seed_original(rt, await _record_transcript(monkeypatch))
    _patch_client(monkeypatch, _replay_script())
    monkeypatch.setattr("heim.runtime.build_runtime", lambda *a, **k: rt)

    args = argparse.Namespace(id=inv_id, model="claude-haiku-4-6", prompt_file=None)
    assert await cli._cmd_replay(args) == 0

    out = capsys.readouterr().out
    assert f"replay #{inv_id + 1} of investigation #{inv_id}" in out
    assert "original" in out and "replay" in out
    assert "claude-sonnet-4-6" in out and "claude-haiku-4-6" in out
    # cassette accounting
    assert "3 recorded · 1 exact · 1 fuzzy · 0 missed" in out
    # confidence side by side, both root causes in full, then the diff
    assert "high" in out and "medium" in out
    assert "ROOT CAUSE — original" in out and "ROOT CAUSE — replay" in out
    assert "The PhotoPrism import cache grew to 40 GB." in out
    assert "The PhotoPrism thumbnail cache grew to 40 GB." in out
    assert "--- original" in out and "+++ replay" in out
    assert "-The PhotoPrism import cache grew to 40 GB." in out
    assert "+The PhotoPrism thumbnail cache grew to 40 GB." in out


async def test_cli_replay_reports_setup_errors_without_a_traceback(rt, monkeypatch, capsys):
    from heim import cli

    monkeypatch.setattr("heim.runtime.build_runtime", lambda *a, **k: rt)
    args = argparse.Namespace(id=777, model=None, prompt_file=None)
    assert await cli._cmd_replay(args) == 2
    assert "error: no investigation #777" in capsys.readouterr().out


def test_cli_parser_wires_the_replay_command():
    args = cli_parse(["replay", "12", "--model", "m", "--prompt-file", "p.md"])
    assert (args.cmd, args.id, args.model, args.prompt_file) == ("replay", 12, "m", "p.md")
    assert cli_parse(["replay", "3"]).model is None


def cli_parse(argv: list[str]):
    from heim.cli import _build_parser

    return _build_parser().parse_args(argv)


def test_replay_comparison_is_readable_with_identical_reports():
    from heim.cli import replay_comparison

    text = replay_comparison({
        "id": 9, "replay_of": 8, "host": "ubuntu-server", "model": "claude-sonnet-4-6",
        "status": "complete", "steps": 2, "input_tokens": 10, "output_tokens": 2,
        "cost": 0.0, "report_md": ORIGINAL_REPORT, "prompt_file": "",
        "cassette": {"recorded": 3, "exact": 3, "fuzzy": 0, "missed": 0, "unused": 0},
        "original": {"model": "claude-sonnet-4-6", "status": "complete", "n_steps": 3,
                     "input_tokens": 120_000, "output_tokens": 3_000, "cost": 0.405,
                     "report_md": ORIGINAL_REPORT},
    })
    assert "(identical root-cause text)" in text
    assert "0.4050" in text and "—" in text          # unpriced replay renders an em dash


# ========================================================== 4. the dashboard


def test_dashboard_renders_replay_lineage(tmp_path, monkeypatch):
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("HEIM_DASHBOARD_TOKEN", raising=False)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    db = tmp_path / "dash.sqlite3"
    cfg.settings.db_path = str(db)

    store = IncidentStore(db)
    original = store.create_investigation(host="ubuntu-server", status="complete",
                                          trigger="daily", started_at="2026-09-01T07:00:00",
                                          report_md=ORIGINAL_REPORT)
    replay = store.create_investigation(host="ubuntu-server", status="complete",
                                        trigger="replay", replay_of=original,
                                        model="claude-haiku-4-6",
                                        started_at="2026-09-02T07:00:00",
                                        report_md=REPLAY_REPORT)
    store.close()

    with TestClient(create_app(cfg)) as client:
        html = client.get(f"/investigations/{replay}").text
        assert f'href="/investigations/{original}">replay of #{original}</a>' in html
        assert "REPLAY" in html.upper()
        # the original page is unchanged — no back-link, nothing to maintain
        assert "replay of #" not in client.get(f"/investigations/{original}").text
