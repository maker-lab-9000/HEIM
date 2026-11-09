"""The daemon posts queued tooling feedback to GitHub (spec 2026-11-08)."""
from __future__ import annotations

import json

import httpx
import pytest
from test_jobs_pause import _quiet
from test_tracking import rt  # noqa: F401  (fixture)

from heim import daemon
from heim.channels.github import GitHub
from heim.pipelines import feedback_issues as fi

T0 = "2026-11-08T10:00:00+01:00"


class FakeGitHub:
    """A tiny GitHub: issues by number, every request recorded."""

    def __init__(self, fail_first: int = 0):
        self.issues: dict[int, dict] = {}
        self.requests: list[tuple[str, str, dict | None]] = []
        self.fail_first = fail_first

    def handler(self, req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content) if req.content else None
        self.requests.append((req.method, req.url.path, body))
        if self.fail_first:
            self.fail_first -= 1
            return httpx.Response(401, json={"message": "Bad credentials"})
        parts = req.url.path.split("/")
        if req.method == "POST" and parts[-1] == "issues":
            n = 40 + len(self.issues) + 1
            self.issues[n] = {"number": n, "state": "open", "html_url": f"https://gh.invalid/{n}",
                              "comments": 0}
            return httpx.Response(201, json=self.issues[n])
        if req.method == "POST" and parts[-1] == "comments":
            self.issues[int(parts[-2])]["comments"] += 1
            return httpx.Response(201, json={"id": 1})
        return httpx.Response(200, json=self.issues[int(parts[-1])])

    def client(self) -> GitHub:
        return GitHub("o/r", "w", transport=httpx.MockTransport(self.handler))


@pytest.fixture
def live(rt, monkeypatch):  # noqa: F811
    monkeypatch.setenv("HEIM_GITHUB_TOKEN", "w")
    rt.config.settings.github.repo = "o/r"
    rt.dry_run = False
    return rt


def _posts(gh):
    return [(m, p) for m, p, _ in gh.requests if m == "POST"]


async def test_first_row_opens_issue_then_comments(live):
    live.store.queue_feedback("loki_query", 1, "add X", created_at=T0)
    live.store.queue_feedback("loki_query", 2, "add Y", created_at=T0)
    gh = FakeGitHub()
    assert await fi.drain_outbox(live, gh.client()) == {"posted": 2, "failed": 0}
    assert _posts(gh) == [("POST", "/repos/o/r/issues"), ("POST", "/repos/o/r/issues/41/comments")]
    created = gh.requests[0][2]
    assert created["title"] == "Tooling feedback: loki_query"
    assert created["labels"] == ["heim-feedback", "tool:loki_query"]
    assert created["body"].startswith("add X")
    row = live.store.feedback_issue("loki_query")
    assert row["number"] == 41 and row["url"] == "https://gh.invalid/41" and row["comments"] == 1
    assert live.store.outbox_rows() == []


async def test_closed_issue_opens_a_new_one(live):
    gh = FakeGitHub()
    live.store.queue_feedback("loki_query", 1, "add X", created_at=T0)
    await fi.drain_outbox(live, gh.client())
    gh.issues[41]["state"] = "closed"
    live.store.queue_feedback("loki_query", 2, "add Y", created_at=T0)
    await fi.drain_outbox(live, gh.client())
    assert _posts(gh)[-1] == ("POST", "/repos/o/r/issues")
    assert live.store.feedback_issue("loki_query")["number"] == 42


async def test_failure_is_recorded_and_retried(live):
    a = live.store.queue_feedback("loki_query", 1, "add X", created_at=T0)
    live.store.queue_feedback("ha_api", 2, "add Y", created_at=T0)
    gh = FakeGitHub(fail_first=1)
    assert await fi.drain_outbox(live, gh.client()) == {"posted": 1, "failed": 1}
    (row,) = live.store.outbox_rows()
    assert row["id"] == a and row["attempts"] == 1 and "401" in row["error"]
    assert await fi.drain_outbox(live, gh.client()) == {"posted": 1, "failed": 0}
    assert live.store.outbox_rows() == []


async def test_poster_scrubs_at_send_time(live, monkeypatch):
    live.store.queue_feedback("ssh_diagnostic", 1, "run as svcuser on 192.168.1.20", created_at=T0)
    (live.config.root.parent / ".env.example").write_text("HEIM_SSH_USER=you\n")
    monkeypatch.setenv("HEIM_SSH_USER", "svcuser")
    gh = FakeGitHub()
    await fi.drain_outbox(live, gh.client())
    sent = gh.requests[0][2]["body"]
    assert "svcuser" not in sent and "192.168" not in sent and "‹redacted›" in sent


async def test_drain_off_without_token_or_in_dry_run(live, monkeypatch):
    live.store.queue_feedback("loki_query", 1, "add X", created_at=T0)
    gh = FakeGitHub()
    live.dry_run = True
    assert await fi.drain_outbox(live, gh.client()) == {}
    live.dry_run = False
    monkeypatch.delenv("HEIM_GITHUB_TOKEN")
    assert await fi.drain_outbox(live, gh.client()) == {}
    assert gh.requests == []


async def test_poll_job_drains_after_the_ping(live, monkeypatch):
    order = []
    _quiet(live, monkeypatch)

    async def ping(url):
        order.append("ping")

    async def drain(r, client=None):
        order.append("drain")
        raise RuntimeError("github down")

    monkeypatch.setattr(daemon.deadman, "ping", ping)
    monkeypatch.setattr(daemon, "drain_outbox", drain)
    await daemon._poll_job(live)
    assert order == ["ping", "drain"]


@pytest.mark.parametrize("status", [404, 410, 301])
async def test_gone_issue_opens_a_new_one(live, status):
    gh = FakeGitHub()
    live.store.set_feedback_issue("loki_query", 7, "open", "u", 0, T0)
    live.store.queue_feedback("loki_query", 1, "add X", created_at=T0)
    real = gh.handler

    def handler(req):
        if req.method == "GET":
            gh.requests.append((req.method, req.url.path, None))
            return httpx.Response(status, json={"message": "gone"})
        return real(req)

    client = GitHub("o/r", "w", transport=httpx.MockTransport(handler))
    assert await fi.drain_outbox(live, client) == {"posted": 1, "failed": 0}
    assert live.store.feedback_issue("loki_query")["number"] == 41


async def test_network_outage_neither_counts_nor_continues(live):
    for i in range(3):
        live.store.queue_feedback("loki_query", i, f"s{i}", created_at=T0)
    calls = []

    def handler(req):
        calls.append(req)
        raise httpx.ConnectError("Name or service not known")

    client = GitHub("o/r", "w", transport=httpx.MockTransport(handler))
    for _ in range(20):
        assert await fi.drain_outbox(live, client) == {"posted": 0, "failed": 1}
    assert len(calls) == 20                                  # one try per cycle, batch stops
    rows = live.store.outbox_rows()
    assert len(rows) == 3 and all(r["attempts"] == 0 for r in rows)
    assert "ConnectError" in rows[0]["error"]
