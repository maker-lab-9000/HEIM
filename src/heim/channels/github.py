"""GitHub issues, write side (spec 2026-11-08) — used ONLY by the daemon's
feedback outbox drain, with ``HEIM_GITHUB_TOKEN``. The agents never get this
client; their ``github_issues`` tool is GET-only with a read token.

Unlike the other channels this one raises (``httpx.HTTPStatusError`` or a
transport error): the drain records the failure on the outbox row and retries.
"""
from __future__ import annotations

import httpx

API = "https://api.github.com"
TIMEOUT_S = 15.0


class GitHub:
    def __init__(self, repo: str, token: str,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.base = f"{API}/repos/{repo}"
        self.headers = {"Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                        "User-Agent": "heim"}
        self.transport = transport

    async def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        async with httpx.AsyncClient(timeout=TIMEOUT_S, headers=self.headers,
                                     transport=self.transport) as c:
            r = await c.request(method, f"{self.base}{path}", json=body)
            r.raise_for_status()
            return r.json()

    async def get_issue(self, number: int) -> dict:
        return await self._call("GET", f"/issues/{int(number)}")

    async def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
        return await self._call("POST", "/issues",
                                {"title": title, "body": body, "labels": labels})

    async def comment(self, number: int, body: str) -> dict:
        return await self._call("POST", f"/issues/{int(number)}/comments", {"body": body})
