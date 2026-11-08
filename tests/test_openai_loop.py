"""The investigator's OpenAI-compatible tool loop (spec
2026-11-04-investigator-openrouter): same contract as the Anthropic loop —
step cap, forced final, on_step attribution, transcript shape — over the chat
completions API. Offline: every request goes to an httpx.MockTransport.
"""
from __future__ import annotations

import json

import httpx
import pytest

from heim.agent import openai_loop
from heim.agent.cassette import Cassette
from heim.agent.openai_loop import run_openai_agent
from heim.agent.runner import FORCED_FINAL_TEXT, run_agent
from heim.config import AgentCfg
from heim.llm import OPENROUTER_URL

REPORT = "## Summary\n\nDisk full.\n\n## Root cause\n\nlogs\n"


class StubTool:
    def __init__(self, name: str, result: str = "ok"):
        self.name = name
        self._result = result
        self.calls: list[dict] = []

    def openai_schema(self) -> dict:
        return {"type": "function", "function": {
            "name": self.name, "description": "stub", "parameters": {"type": "object"}}}

    async def __call__(self, args: dict) -> str:
        self.calls.append(args)
        return self._result

    async def close(self) -> None:
        pass


def _call(i: int, name: str, args) -> dict:
    raw = args if isinstance(args, str) else json.dumps(args)
    return {"id": f"call_{i}", "type": "function", "function": {"name": name, "arguments": raw}}


def _reply(content=None, calls=None, finish="stop", usage=(100, 20)) -> dict:
    msg = {"role": "assistant", "content": content}
    if calls:
        msg["tool_calls"] = calls
        finish = "tool_calls"
    return {"choices": [{"message": msg, "finish_reason": finish}],
            "usage": {"prompt_tokens": usage[0], "completion_tokens": usage[1]}}


class Script:
    """Serves scripted responses in order and records every request."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        r = self.responses.pop(0)
        return r if isinstance(r, httpx.Response) else httpx.Response(200, json=r)

    def body(self, i: int) -> dict:
        return json.loads(self.requests[i].content)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    monkeypatch.setattr(openai_loop, "RETRY_WAIT_S", 0)


def _cfg(**kw) -> AgentCfg:
    base = dict(name="investigator", provider="openrouter",
                model="deepseek/deepseek-v4.1-flash-1017", hard_step_cap=5, max_tokens=1000)
    base.update(kw)
    return AgentCfg(**base)


async def _run(script: Script, tools, cfg=None, **kw):
    return await run_openai_agent(cfg or _cfg(), system="sys", user_prompt="brief",
                                  tools=tools, transport=httpx.MockTransport(script), **kw)


async def test_tool_round_trip_then_answer():
    df = StubTool("ssh_diagnostic", "Filesystem 100%")
    script = Script(_reply(calls=[_call(1, "ssh_diagnostic", {"command": "df -h"})]),
                    _reply(REPORT, usage=(300, 50)))
    res = await _run(script, [df])
    assert df.calls == [{"command": "df -h"}]
    second = script.body(1)["messages"]
    assert second[-1] == {"role": "tool", "tool_call_id": "call_1", "content": "Filesystem 100%"}
    assert res.output_text.startswith("## Summary")
    assert (res.input_tokens, res.output_tokens) == (400, 70)
    assert res.stop_reason == "end_turn" and len(res.steps) == 1
    body = script.body(0)
    assert body["tools"][0]["function"]["name"] == "ssh_diagnostic"
    assert body["tool_choice"] == "auto" and body["max_tokens"] == 1000
    assert body["messages"][:2] == [{"role": "system", "content": "sys"},
                                    {"role": "user", "content": "brief"}]


async def test_bearer_header_and_url():
    script = Script(_reply(REPORT))
    await _run(script, [])
    assert str(script.requests[0].url) == OPENROUTER_URL
    assert script.requests[0].headers["authorization"] == "Bearer sk-test"

    script = Script(_reply(REPORT))
    await _run(script, [], cfg=_cfg(provider="openai_compat", model="local",
                                   base_url="http://llama:8080/v1/"))
    assert str(script.requests[0].url) == "http://llama:8080/v1/chat/completions"
    assert "authorization" not in script.requests[0].headers


async def test_invalid_json_arguments_answered_not_run():
    tool = StubTool("prometheus_query")
    script = Script(_reply(calls=[_call(1, "prometheus_query", "{not json"),
                                  _call(2, "prometheus_query", "[1, 2]")]),
                    _reply(REPORT))
    res = await _run(script, [tool])
    assert tool.calls == []
    answers = [m for m in script.body(1)["messages"] if m["role"] == "tool"]
    assert [a["tool_call_id"] for a in answers] == ["call_1", "call_2"]
    assert all(a["content"].startswith("invalid tool arguments") for a in answers)
    assert res.steps == [] and res.output_text.startswith("## Summary")


async def test_cap_answers_every_call_in_a_turn():
    tool = StubTool("ssh_diagnostic")
    script = Script(_reply(calls=[_call(i, "ssh_diagnostic", {"command": f"c{i}"})
                                  for i in (1, 2, 3)]),
                    _reply(REPORT))
    res = await _run(script, [tool], cfg=_cfg(hard_step_cap=1))
    assert len(tool.calls) == 1
    answers = [m for m in script.body(1)["messages"] if m["role"] == "tool"]
    assert [a["tool_call_id"] for a in answers] == ["call_1", "call_2", "call_3"]
    assert answers[1]["content"] == FORCED_FINAL_TEXT
    assert res.forced_final is True


async def test_first_step_carries_turn_usage():
    seen = []
    tool = StubTool("ssh_diagnostic")
    script = Script(_reply(calls=[_call(1, "ssh_diagnostic", {"command": "a"}),
                                  _call(2, "ssh_diagnostic", {"command": "b"})]),
                    _reply(REPORT))
    await _run(script, [tool],
               on_step=lambda seq, name, args, out, ms, i, o: seen.append((seq, i, o)))
    assert seen == [(1, 100, 20), (2, 0, 0)]


async def test_unknown_tool_is_a_step_with_an_error_answer():
    script = Script(_reply(calls=[_call(1, "rm_rf", {})]), _reply(REPORT))
    res = await _run(script, [StubTool("ssh_diagnostic")])
    assert [s.tool for s in res.steps] == ["rm_rf"]
    assert script.body(1)["messages"][-1]["content"] == "unknown tool: rm_rf"


async def test_empty_length_reply():
    res = await _run(Script(_reply(None, finish="length")), [])
    assert res.output_text == "" and res.stop_reason == "max_tokens"


async def test_retries_5xx_but_not_400():
    script = Script(httpx.Response(503, text="busy"), _reply(REPORT))
    res = await _run(script, [])
    assert len(script.requests) == 2 and res.output_text.startswith("## Summary")

    script = Script(httpx.Response(400, text="usage limits reached"), _reply(REPORT))
    with pytest.raises(RuntimeError, match="HTTP 400: usage limits reached"):
        await _run(script, [])
    assert len(script.requests) == 1


async def test_retries_give_up_after_three():
    script = Script(*[httpx.Response(502, text="bad gateway")] * 3)
    with pytest.raises(RuntimeError, match="HTTP 502"):
        await _run(script, [])
    assert len(script.requests) == 3


async def test_transcript_shape_matches_anthropic_loop():
    tool = StubTool("ssh_diagnostic", "Filesystem 100%")
    script = Script(_reply("checking", calls=[_call(1, "ssh_diagnostic", {"command": "df"})]),
                    _reply(REPORT))
    res = await _run(script, [tool], collect_transcript=True)
    assert [t["role"] for t in res.transcript] == ["user", "assistant", "user", "assistant"]
    assert res.transcript[1]["content"] == [
        {"type": "text", "text": "checking"},
        {"type": "tool_use", "name": "ssh_diagnostic", "input": {"command": "df"}}]
    cassette = Cassette.from_transcript(res.transcript)
    assert cassette.take("ssh_diagnostic", {"command": "df"})[0] == "Filesystem 100%"


async def test_loop_cap_returns_forced_empty():
    tool = StubTool("ssh_diagnostic")
    script = Script(*[_reply(calls=[_call(i, "ssh_diagnostic", {"command": str(i)})])
                      for i in range(5)])
    res = await _run(script, [tool], cfg=_cfg(hard_step_cap=1))
    assert res.stop_reason == "loop-cap" and res.forced_final is True
    assert len(script.requests) == 4                      # cap + 3 turns of slack


async def test_run_agent_dispatches_on_provider(monkeypatch):
    called = {}

    async def fake(cfg, **kw):
        called["provider"] = cfg.provider
        from heim.agent.runner import AgentResult
        return AgentResult(REPORT)

    def no_anthropic(*a, **k):
        raise AssertionError("AsyncAnthropic must not be built for openrouter")

    monkeypatch.setattr("heim.agent.openai_loop.run_openai_agent", fake)
    monkeypatch.setattr("heim.agent.runner.AsyncAnthropic", no_anthropic)
    res = await run_agent(_cfg(), system="s", user_prompt="u", tools=[StubTool("x")])
    assert called == {"provider": "openrouter"} and res.output_text == REPORT


def test_tool_openai_schema_matches_its_yaml():
    from heim.config import ToolCfg
    from heim.tools.base import Tool, ToolContext
    cfg = ToolCfg(name="ssh_diagnostic", description="read-only ssh", module="x",
                  args={"command": {"type": "string"}}, required=["command"])
    t = Tool(cfg, ToolContext(config=None))
    assert t.openai_schema() == {"type": "function", "function": {
        "name": "ssh_diagnostic", "description": "read-only ssh",
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}},
                       "required": ["command"]}}}
    assert t.anthropic_schema()["input_schema"] == t.openai_schema()["function"]["parameters"]


# ------------------------------------------------ final review fixes


async def test_error_object_in_a_200_raises_with_the_reason():
    script = Script({"error": {"code": 400, "message": "Provider returned error"}})
    with pytest.raises(RuntimeError, match="provider error.*Provider returned error"):
        await _run(script, [])
    assert len(script.requests) == 1


async def test_retryable_error_object_in_a_200_is_retried():
    script = Script({"error": {"code": 502, "message": "upstream down"}}, _reply(REPORT))
    res = await _run(script, [])
    assert len(script.requests) == 2 and res.output_text.startswith("## Summary")


async def test_finish_reason_error_raises():
    with pytest.raises(RuntimeError, match="provider error"):
        await _run(Script(_reply(None, finish="error")), [])


async def test_non_json_200_raises_clearly():
    with pytest.raises(RuntimeError, match="not JSON"):
        await _run(Script(httpx.Response(200, text="<html>gateway</html>")), [])


async def test_assistant_turn_echoed_back_as_returned():
    reply = _reply(None, calls=[_call(1, "ssh_diagnostic", {"command": "df"})])
    reply["choices"][0]["message"]["reasoning"] = "think"
    reply["choices"][0]["message"]["reasoning_details"] = [{"type": "reasoning.text",
                                                            "text": "think"}]
    script = Script(reply, _reply(REPORT))
    await _run(script, [StubTool("ssh_diagnostic")])
    echoed = script.body(1)["messages"][2]
    assert echoed["role"] == "assistant"
    assert echoed["reasoning"] == "think" and echoed["reasoning_details"][0]["text"] == "think"
    assert echoed["tool_calls"][0]["id"] == "call_1"
