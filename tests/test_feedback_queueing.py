"""Pipelines queue tooling and audit feedback for GitHub (spec 2026-11-08)."""
from __future__ import annotations

import pytest
from test_tracking import rt  # noqa: F401  (fixture)

from heim.pipelines.investigate import record_tool_feedback
from heim.pipelines.security_audit import queue_audit_feedback

REPORT = """## Summary
x

## Tooling feedback
- loki_query: add a since flag
- loki_query: covered by #42
- ssh: allow journalctl
"""


@pytest.fixture
def live(rt, monkeypatch):  # noqa: F811
    monkeypatch.setenv("HEIM_GITHUB_TOKEN", "w")
    rt.config.settings.github.repo = "o/r"
    rt.dry_run = False
    return rt


def _inv(rt_, agent="investigator"):
    return rt_.store.create_investigation(host="ubuntu-server", agent_name=agent, trigger="manual",
                                          status="running", model="claude-sonnet-5-5")


def test_suggestions_are_queued_per_target(live):
    i = _inv(live)
    assert record_tool_feedback(live, i, REPORT) == 3
    rows = live.store.outbox_rows()
    assert [r["target"] for r in rows] == ["loki_query", "general"]
    assert rows[0]["body"].startswith("add a since flag")
    assert f"investigation #{i}" in rows[0]["body"] and "claude-sonnet-5-5" in rows[0]["body"]


def test_covered_line_is_stored_not_queued(live):
    record_tool_feedback(live, _inv(live), REPORT)
    stored = [f["suggestion"] for f in live.store.tool_feedback_rows(limit=None)]
    assert "covered by #42" in stored
    assert not any("covered by" in r["body"] for r in live.store.outbox_rows())


def test_unknown_tool_goes_to_general(live):
    record_tool_feedback(live, _inv(live), "## Tooling feedback\n- ssh: allow journalctl\n")
    (row,) = live.store.outbox_rows()
    assert row["target"] == "general" and row["body"].startswith("ssh: allow journalctl")


def test_nothing_queued_without_write_config(live, monkeypatch):
    monkeypatch.delenv("HEIM_GITHUB_TOKEN")
    assert record_tool_feedback(live, _inv(live), REPORT) == 3
    assert live.store.outbox_rows() == []


def test_dry_run_and_replay_queue_nothing(live):
    live.dry_run = True
    record_tool_feedback(live, _inv(live), REPORT)
    live.dry_run = False
    record_tool_feedback(live, _inv(live), REPORT, file_issues=False)
    assert live.store.outbox_rows() == []


AUDIT = """## Summary
x

## Audit feedback
### Improve the audit
- ssh_port — noisy — group rows
### What else to check
- nothing this week
"""


def test_audit_feedback_becomes_one_row(live):
    i = _inv(live, agent="security_auditor")
    assert queue_audit_feedback(live, i, AUDIT) == 1
    (row,) = live.store.outbox_rows()
    assert row["target"] == "security_audit"
    assert "### Improve the audit" in row["body"] and "group rows" in row["body"]
    assert "What else to check" not in row["body"]


def test_empty_audit_feedback_is_not_queued(live):
    i = _inv(live, agent="security_auditor")
    empty = "## Audit feedback\n### Improve the audit\n\n### What else to check\n- nothing this week\n"
    assert queue_audit_feedback(live, i, empty) == 0
    live.dry_run = True
    assert queue_audit_feedback(live, i, AUDIT) == 0
    assert live.store.outbox_rows() == []
