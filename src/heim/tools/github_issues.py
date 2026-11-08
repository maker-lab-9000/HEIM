"""Read-only view of the tooling-feedback GitHub issues (spec 2026-11-08).

GET-only and hard-scoped: the URL is built here from ``settings.github.repo``
and fixed paths (``/issues`` filtered to the ``heim-feedback`` label, or
``/issues/<int>`` and its comments) — the model passes no path or URL. The
token is ``HEIM_GITHUB_READ_TOKEN`` (Issues: read), so the tool is read-only
by guard and by privilege (AGENTS.md invariant 4). Without a repo and that
token the tool is not offered at all (:meth:`available`).
"""
from __future__ import annotations

import json

import httpx

from heim.feedback_issues import LABEL
from heim.tools.base import Tool, clip

API = "https://api.github.com"
LIST_LIMIT = 20
LAST_COMMENTS = 5
COMMENT_CHARS = 1000
STATES = ("open", "closed")


class GitHubIssuesTool(Tool):
    #: tests swap in an httpx.MockTransport
    transport: httpx.AsyncBaseTransport | None = None

    @classmethod
    def available(cls, config) -> bool:
        return config.settings.github.can_read

    async def _get(self, client: httpx.AsyncClient, path: str, **params):
        r = await client.get(f"{API}/repos/{self.ctx.config.settings.github.repo}{path}",
                             params=params)
        r.raise_for_status()
        return r.json()

    async def run(self, args: dict) -> str:
        gh = self.ctx.config.settings.github
        state = str(args.get("state") or "open")
        if state not in STATES:
            return json.dumps({"ok": False, "error": f"state must be one of {', '.join(STATES)}"})
        number = args.get("number")
        tool = str(args.get("tool") or "").strip()
        headers = {"Authorization": f"Bearer {gh.read_token()}",
                   "Accept": "application/vnd.github+json", "User-Agent": "heim"}
        async with httpx.AsyncClient(timeout=15, headers=headers, transport=self.transport) as c:
            if number not in (None, ""):
                issue = await self._get(c, f"/issues/{int(number)}")
                comments = await self._get(c, f"/issues/{int(number)}/comments", per_page=100)
                out = {**_summary(issue), "body": str(issue.get("body") or "")[:COMMENT_CHARS],
                       "comments": [{"at": cm.get("created_at"),
                                     "body": str(cm.get("body") or "")[:COMMENT_CHARS]}
                                    for cm in comments[-LAST_COMMENTS:]]}
                await self.ctx.emit(f"🐙 GitHub issue #{int(number)}")
            else:
                labels = LABEL + (f",tool:{tool}" if tool else "")
                issues = await self._get(c, "/issues", labels=labels, state=state,
                                         per_page=LIST_LIMIT)
                out = {"issues": [_summary(i) for i in issues if "pull_request" not in i]}
                await self.ctx.emit(f"🐙 GitHub issues {labels} ({state}): {len(out['issues'])}")
        self.ctx.record({"tool": self.name, "args": args, "blocked": False})
        return clip(json.dumps(out, ensure_ascii=False), int(self.cfg.options.get("clip_bytes", 8192)))


def _summary(issue: dict) -> dict:
    return {"number": issue.get("number"), "title": issue.get("title"),
            "state": issue.get("state"), "comments": issue.get("comments"),
            "updated_at": issue.get("updated_at"),
            "labels": [lb.get("name") if isinstance(lb, dict) else lb
                       for lb in issue.get("labels") or []]}
