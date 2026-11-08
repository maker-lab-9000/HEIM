"""Drain the tooling-feedback outbox into GitHub issues (spec 2026-11-08).

Run by the daemon's poll cycle, after the dead-man ping. One open issue per
target: a stored issue that is still open gets a comment; none, or a closed
one (closed = done), gets a fresh issue. A failed row keeps its error and is
retried next cycle, up to ``MAX_ATTEMPTS``. Bodies are scrubbed here, at send
time, so a row queued before a ``.env`` change is scrubbed with today's values.
"""
from __future__ import annotations

import logging
import os

import httpx

from heim.channels.github import GitHub
from heim.feedback_issues import (DRAIN_BATCH, MAX_ATTEMPTS, identity_values, issue_labels,
                                  issue_title, scrub)
from heim.runtime import Runtime

log = logging.getLogger(__name__)
ERROR_CLIP = 300
#: a stored issue that answers with one of these is gone: open a new one
GONE = frozenset({301, 404, 410})


async def _post(rt: Runtime, gh: GitHub, row: dict, secrets: list[str]) -> int:
    target, body = row["target"], scrub(row["body"], secrets)
    known = rt.store.feedback_issue(target)
    issue = None
    if known:
        try:
            issue = await gh.get_issue(known["number"])
        except httpx.HTTPStatusError as exc:
            # deleted (404/410) or transferred / repo renamed (301): treat it
            # as no issue at all, or the target would fail for good
            if exc.response.status_code not in GONE:
                raise
    if issue is not None and issue.get("state") == "open":
        await gh.comment(issue["number"], body)
        issue = {**issue, "comments": int(issue.get("comments") or 0) + 1}
    else:
        issue = await gh.create_issue(issue_title(target), body, issue_labels(target))
    rt.store.set_feedback_issue(target, int(issue["number"]), str(issue.get("state") or "open"),
                                str(issue.get("html_url") or ""),
                                int(issue.get("comments") or 0), rt.now_iso())
    return int(issue["number"])


async def drain_outbox(rt: Runtime, client: GitHub | None = None) -> dict:
    gh_cfg = rt.config.settings.github
    if rt.dry_run or not gh_cfg.can_write:
        return {}
    rows = rt.store.pending_feedback(DRAIN_BATCH, MAX_ATTEMPTS)
    if not rows:
        return {"posted": 0, "failed": 0}
    gh = client or GitHub(gh_cfg.repo, gh_cfg.write_token())
    secrets = identity_values(rt.config.root.parent / ".env.example", os.environ)
    posted = failed = 0
    for row in rows:
        try:
            number = await _post(rt, gh, row, secrets)
        except httpx.TransportError as exc:
            # the network, not this row: no attempt is spent (a reboot's DNS
            # race or a GitHub outage must not use up the rows' tries), and the
            # rest of the batch would only wait out the same timeout
            failed += 1
            log.warning("GitHub unreachable, feedback stays queued: %s", exc)
            rt.store.note_feedback_error(row["id"], f"{type(exc).__name__}: {exc}"[:ERROR_CLIP])
            break
        except Exception as exc:
            failed += 1
            log.warning("posting tooling feedback #%s to GitHub failed: %s", row["id"], exc)
            rt.store.mark_feedback_failed(row["id"], f"{type(exc).__name__}: {exc}"[:ERROR_CLIP])
            continue
        posted += 1
        rt.store.mark_feedback_posted(row["id"], rt.now_iso(), number)
    return {"posted": posted, "failed": failed}
