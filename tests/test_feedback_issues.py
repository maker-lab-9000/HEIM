"""Pure helpers and the GitHub channel (spec 2026-11-08)."""
from __future__ import annotations

import json

import httpx

from heim.channels.github import GitHub
from heim.feedback_issues import (REDACTED, comment_body, identity_values, is_covered_only,
                                  issue_labels, issue_title, scrub, target_for)


def test_scrub_ipv4_ipv6_and_identity():
    out = scrub("ssh 192.168.1.20 as svcuser fe80::1 failed", ["svcuser"])
    assert "192.168" not in out and "svcuser" not in out and "fe80::1" not in out
    assert out.count(REDACTED) == 3


def test_scrub_keeps_tool_text():
    for text in ("add --since flag to journalctl", "window 12:30 to 13:00", "use rate()[5m]"):
        assert scrub(text, []) == text


def test_scrub_longest_secret_first():
    assert scrub("host-a.lan and host", ["host", "host-a.lan"]) == f"{REDACTED} and {REDACTED}"


def test_identity_values_from_env_example(tmp_path):
    ex = tmp_path / ".env.example"
    ex.write_text("# c\nHEIM_SSH_USER=you\nHEIM_SERVER_IP=\nSHORT=\nEMPTY=\n")
    env = {"HEIM_SSH_USER": "svcuser", "HEIM_SERVER_IP": "10.1.2.3", "SHORT": "abc",
           "OTHER": "notlisted"}
    assert identity_values(ex, env) == ["10.1.2.3", "svcuser"]
    assert identity_values(tmp_path / "missing", env) == []


def test_covered_only():
    assert is_covered_only("covered by #42")
    assert is_covered_only("Already covered by #7.")
    assert not is_covered_only("covered by #42, plus add X")
    assert not is_covered_only("add X")


def test_target_for():
    assert target_for("loki_query", ["loki_query"]) == "loki_query"
    assert target_for("ssh", ["loki_query"]) == "general"


def test_issue_shape():
    assert issue_title("loki_query") == "Tooling feedback: loki_query"
    assert issue_labels("loki_query") == ["heim-feedback", "tool:loki_query"]
    assert comment_body("add X", "investigation #3") == "add X\n\n_source: investigation #3_"


async def test_github_client_paths():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path, req.headers.get("authorization"),
                     json.loads(req.content) if req.content else None))
        if req.url.path.endswith("/comments"):
            return httpx.Response(201, json={"id": 1})
        return httpx.Response(201 if req.method == "POST" else 200,
                              json={"number": 42, "state": "open", "html_url": "u", "comments": 0})

    gh = GitHub("o/r", "tok", transport=httpx.MockTransport(handler))
    assert (await gh.create_issue("t", "b", ["heim-feedback"]))["number"] == 42
    await gh.comment(42, "c")
    await gh.get_issue(42)
    assert [(m, p) for m, p, _, _ in seen] == [("POST", "/repos/o/r/issues"),
                                               ("POST", "/repos/o/r/issues/42/comments"),
                                               ("GET", "/repos/o/r/issues/42")]
    assert all(a == "Bearer tok" for _, _, a, _ in seen)
    assert seen[0][3] == {"title": "t", "body": "b", "labels": ["heim-feedback"]}


async def test_github_client_raises_on_error():
    gh = GitHub("o/r", "bad", transport=httpx.MockTransport(lambda r: httpx.Response(401)))
    try:
        await gh.get_issue(1)
    except httpx.HTTPStatusError:
        return
    raise AssertionError("expected HTTPStatusError")
