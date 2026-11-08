"""The agents' read-only github_issues tool (spec 2026-11-08)."""
from __future__ import annotations

import json

import httpx
import pytest
from jinja2 import Environment, FileSystemLoader
from test_tracking import rt  # noqa: F401  (fixture)

from heim.pipelines.investigate import build_system_prompt
from heim.pipelines.security_audit import build_audit_system_prompt
from heim.tools.base import ToolContext, load_tools
from heim.tools.github_issues import GitHubIssuesTool


@pytest.fixture
def readable(rt, monkeypatch):  # noqa: F811
    monkeypatch.setenv("HEIM_GITHUB_READ_TOKEN", "r")
    monkeypatch.setenv("HEIM_GITHUB_TOKEN", "w")
    rt.config.settings.github.repo = "o/r"
    return rt


def _tool(rt_, monkeypatch, handler):
    monkeypatch.setattr(GitHubIssuesTool, "transport", httpx.MockTransport(handler))
    (tool,) = load_tools(["github_issues"], rt_.config, ToolContext(config=rt_.config))
    return tool


ISSUE = {"number": 42, "title": "Tooling feedback: loki_query", "state": "open",
         "labels": [{"name": "heim-feedback"}, {"name": "tool:loki_query"}],
         "updated_at": "2026-11-08T09:00:00Z", "body": "add X", "comments": 7}


async def test_lists_feedback_issues_for_a_tool(readable, monkeypatch):
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(200, json=[ISSUE, {**ISSUE, "number": 9, "pull_request": {}}])

    out = json.loads(await _tool(readable, monkeypatch, handler)({"tool": "loki_query"}))
    req = seen[0]
    assert req.method == "GET" and req.url.path == "/repos/o/r/issues"
    assert req.url.params["labels"] == "heim-feedback,tool:loki_query"
    assert req.url.params["state"] == "open"
    assert req.headers["authorization"] == "Bearer r"
    assert [i["number"] for i in out["issues"]] == [42]
    assert out["issues"][0]["labels"] == ["heim-feedback", "tool:loki_query"]


async def test_reads_one_issue_with_last_comments(readable, monkeypatch):
    comments = [{"body": f"c{i}" + "x" * 2000, "created_at": "t"} for i in range(8)]

    def handler(req):
        if req.url.path.endswith("/comments"):
            return httpx.Response(200, json=comments)
        return httpx.Response(200, json=ISSUE)

    out = json.loads(await _tool(readable, monkeypatch, handler)({"number": 42}))
    assert out["number"] == 42 and out["body"] == "add X"
    assert [c["body"][:2] for c in out["comments"]] == ["c3", "c4", "c5", "c6", "c7"]
    assert all(len(c["body"]) <= 1000 for c in out["comments"])


async def test_rejects_bad_state(readable, monkeypatch):
    seen = []
    tool = _tool(readable, monkeypatch, lambda r: seen.append(r) or httpx.Response(200, json=[]))
    out = json.loads(await tool({"state": "all"}))
    assert out["ok"] is False and seen == []


def test_not_offered_without_read_config(rt, monkeypatch):  # noqa: F811
    monkeypatch.delenv("HEIM_GITHUB_READ_TOKEN", raising=False)
    rt.config.settings.github.repo = "o/r"
    names = [t.name for t in load_tools(["loki_query", "github_issues"], rt.config,
                                        ToolContext(config=rt.config))]
    assert names == ["loki_query"]


def test_prompt_mentions_tool_only_when_configured(rt, monkeypatch):  # noqa: F811
    jenv = Environment(loader=FileSystemLoader(str(rt.config.prompts_dir)))
    monkeypatch.delenv("HEIM_GITHUB_READ_TOKEN", raising=False)
    assert "github_issues" not in build_system_prompt(rt, jenv, "ubuntu-server")
    assert "github_issues" not in build_audit_system_prompt(rt, jenv)
    monkeypatch.setenv("HEIM_GITHUB_READ_TOKEN", "r")
    rt.config.settings.github.repo = "o/r"
    assert "call github_issues" in build_system_prompt(rt, jenv, "ubuntu-server")
    assert "call github_issues" in build_audit_system_prompt(rt, jenv)
