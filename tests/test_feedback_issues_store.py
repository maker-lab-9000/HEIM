"""Tooling feedback → GitHub issues: settings and store (spec 2026-11-08)."""
from __future__ import annotations

from heim.config import GitHubCfg
from heim.incidents.store import IncidentStore

T0 = "2026-11-08T10:00:00+01:00"


def test_github_cfg_reads_env(monkeypatch):
    for k in ("HEIM_GITHUB_REPO", "HEIM_GITHUB_READ_TOKEN", "HEIM_GITHUB_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    assert not GitHubCfg().can_read and not GitHubCfg().can_write
    monkeypatch.setenv("HEIM_GITHUB_REPO", "owner/repo")
    assert GitHubCfg().repo == "owner/repo"
    assert not GitHubCfg().can_read and not GitHubCfg().can_write
    monkeypatch.setenv("HEIM_GITHUB_READ_TOKEN", "r")
    assert GitHubCfg().can_read and not GitHubCfg().can_write
    monkeypatch.setenv("HEIM_GITHUB_TOKEN", "w")
    cfg = GitHubCfg()
    assert cfg.can_write and cfg.read_token() == "r" and cfg.write_token() == "w"
    assert not GitHubCfg(repo="").can_write


def test_outbox_roundtrip(tmp_path):
    s = IncidentStore(tmp_path / "s.sqlite3")
    a = s.queue_feedback("loki_query", 7, "first", created_at=T0)
    b = s.queue_feedback("ssh_diagnostic", 8, "second", created_at="2026-11-08T10:01:00+01:00")
    assert [r["id"] for r in s.pending_feedback(5, 10)] == [a, b]
    s.mark_feedback_posted(a, T0, 42)
    s.mark_feedback_failed(b, "HTTPStatusError: 401")
    rows = s.pending_feedback(5, 10)
    assert [r["id"] for r in rows] == [b]
    assert rows[0]["attempts"] == 1 and "401" in rows[0]["error"]
    for _ in range(9):
        s.mark_feedback_failed(b, "again")
    assert s.pending_feedback(5, 10) == []
    assert [r["id"] for r in s.outbox_rows("ssh_diagnostic")] == [b]
    assert s.outbox_rows("loki_query") == []


def test_feedback_issue_upsert(tmp_path):
    s = IncidentStore(tmp_path / "s.sqlite3")
    assert s.feedback_issue("loki_query") is None
    s.set_feedback_issue("loki_query", 42, "open", "https://example.invalid/42", 1, T0)
    s.set_feedback_issue("loki_query", 43, "open", "https://example.invalid/43", 0, T0)
    row = s.feedback_issue("loki_query")
    assert row["number"] == 43 and row["state"] == "open" and row["comments"] == 0
    assert set(s.feedback_issues()) == {"loki_query"}


def test_prune_drops_posted_outbox_rows_only(tmp_path):
    s = IncidentStore(tmp_path / "s.sqlite3")
    old = "2026-01-01T10:00:00+01:00"
    posted = s.queue_feedback("loki_query", 1, "old posted", created_at=old)
    s.mark_feedback_posted(posted, old, 42)
    waiting = s.queue_feedback("loki_query", 1, "old waiting", created_at=old)
    counts = s.prune(T0, 120)
    assert counts.get("feedback_outbox") == 1
    assert [r["id"] for r in s.pending_feedback(5, 10)] == [waiting]
