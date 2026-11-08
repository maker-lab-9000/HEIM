"""Telegram getUpdates really long-polls, over one reused connection.

Regression: the 40 s meant for Telegram's long poll was consumed as the HTTP
timeout, so getUpdates went out with no ``timeout`` and Telegram answered at
once — a tight loop, a fresh client and DNS lookup per call (~650k a day).
"""
from __future__ import annotations

import json

import httpx

from heim.channels import telegram as tgmod
from heim.channels.telegram import Telegram


def _ok(result):
    return httpx.Response(200, json={"ok": True, "result": result})


async def test_get_updates_asks_telegram_to_long_poll():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((json.loads(req.content), req.extensions["timeout"]["read"]))
        tg.stop_consumer()                       # one round is enough
        return _ok([])

    tg = Telegram("t", 1, transport=httpx.MockTransport(handler))
    tg._persistent = True
    await tg._updates_loop()
    body, read_timeout = seen[0]
    assert body["timeout"] == tgmod.LONG_POLL_S >= 30
    assert read_timeout > tgmod.LONG_POLL_S


async def test_calls_share_one_http_client(monkeypatch):
    made = []
    real = httpx.AsyncClient

    def counting(*a, **kw):
        made.append(1)
        return real(*a, **kw)

    monkeypatch.setattr(tgmod.httpx, "AsyncClient", counting)
    tg = Telegram("t", 1, transport=httpx.MockTransport(lambda r: _ok({"message_id": 5})))
    for _ in range(3):
        await tg.send("hi")
    assert len(made) == 1


async def test_failures_back_off(monkeypatch):
    sleeps = []

    async def fake_sleep(s):
        sleeps.append(s)
        if len(sleeps) == 6:
            tg.stop_consumer()

    monkeypatch.setattr(tgmod.asyncio, "sleep", fake_sleep)
    tg = Telegram("t", 1, transport=httpx.MockTransport(
        lambda r: (_ for _ in ()).throw(httpx.ConnectError("no dns"))))
    tg._persistent = True
    await tg._updates_loop()
    assert sleeps == [5, 10, 20, 40, 60, 60]
