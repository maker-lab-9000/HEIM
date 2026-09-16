"""Telegram channel: notifications, live command feed, chunked reports, and
inline-button approvals.

Replaces the n8n Telegram sendAndWait construction (URL buttons hitting
``/webhook-waiting`` through a tunnel) with real callback buttons consumed via
``getUpdates`` long-polling — no inbound exposure needed at all.

The report chunker ports the n8n "Split Report for Telegram" Code node:
<= 3900-char chunks split on newline boundaries, ``(part i/N)`` prefixes.
"""
from __future__ import annotations

import asyncio
import logging
import uuid

import httpx

log = logging.getLogger(__name__)

CHUNK_LIMIT = 3900  # Telegram hard cap is 4096; leave room for the part prefix


def chunk_text(text: str, limit: int = CHUNK_LIMIT) -> list[str]:
    """Port of n8n PAM 20 'Split Report for Telegram'."""
    out: list[str] = []
    rest = text
    while len(rest) > limit:
        cut = rest.rfind("\n", 0, limit)
        if cut < limit // 2:  # no sensible newline near the edge -> hard cut
            cut = limit
        out.append(rest[:cut])
        rest = rest[cut:].lstrip("\n")
    if rest.strip():
        out.append(rest)
    return out if out else [text[:limit]]


class Telegram:
    def __init__(self, token: str, chat_id: int):
        self._base = f"https://api.telegram.org/bot{token}"
        self.chat_id = chat_id
        self._offset: int | None = None
        self._pending: dict[str, asyncio.Future] = {}
        self._loop_task: asyncio.Task | None = None

    async def _api(self, method: str, *, timeout: float = 35.0, **params) -> dict | list:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(f"{self._base}/{method}", json=params)
            data = r.json()
            if not data.get("ok"):
                raise RuntimeError(f"telegram {method} failed: {data}")
            return data["result"]

    # ------------------------------------------------------------- sending

    async def send(self, text: str, *, reply_markup: dict | None = None) -> int:
        params: dict = {"chat_id": self.chat_id, "text": text[:4096], "disable_web_page_preview": True}
        if reply_markup is not None:
            params["reply_markup"] = reply_markup
        result = await self._api("sendMessage", **params)
        return result["message_id"]

    async def notify(self, text: str) -> None:
        try:
            await self.send(text)
        except Exception:  # notifications must never sink a pipeline
            log.exception("telegram notify failed")

    async def send_chunks(self, full_text: str) -> None:
        parts = chunk_text(full_text)
        n = len(parts)
        for i, p in enumerate(parts):
            label = f"(part {i + 1}/{n})\n" if n > 1 else ""
            await self.send(label + p)

    # ------------------------------------------------------------ approvals

    async def ask(
        self,
        text: str,
        *,
        yes: str = "✅ Approve",
        no: str = "❌ Decline",
        timeout_s: float = 6 * 3600,
    ) -> bool | None:
        """Send an approval prompt with inline buttons; return True/False, or
        None on timeout. Multiple concurrent asks are supported (one shared
        getUpdates consumer)."""
        uid = uuid.uuid4().hex[:12]
        markup = {
            "inline_keyboard": [[
                {"text": no, "callback_data": f"heim:{uid}:n"},
                {"text": yes, "callback_data": f"heim:{uid}:y"},
            ]]
        }
        message_id = await self.send(text, reply_markup=markup)
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[uid] = fut
        self._ensure_updates_loop()
        try:
            answer: bool | None = await asyncio.wait_for(fut, timeout_s)
        except (TimeoutError, asyncio.TimeoutError):
            answer = None
        finally:
            self._pending.pop(uid, None)
        # best-effort: strip the buttons and show the outcome
        outcome = {True: yes, False: no, None: "⏰ timed out"}[answer]
        try:
            await self._api(
                "editMessageText",
                chat_id=self.chat_id,
                message_id=message_id,
                text=text[:4000] + f"\n\n→ {outcome}",
            )
        except Exception:
            pass
        return answer

    def _ensure_updates_loop(self) -> None:
        if self._loop_task is None or self._loop_task.done():
            self._loop_task = asyncio.get_running_loop().create_task(self._updates_loop())

    async def _updates_loop(self) -> None:
        """Single consumer of getUpdates; resolves pending approval futures.
        Exits when nothing is pending (restarted lazily by the next ask)."""
        while self._pending:
            try:
                updates = await self._api(
                    "getUpdates",
                    timeout=40.0,
                    offset=self._offset,
                    allowed_updates=["callback_query"],
                    **{"timeout": 25} if False else {},
                )
            except Exception:
                log.exception("telegram getUpdates failed; retrying in 5s")
                await asyncio.sleep(5)
                continue
            for u in updates:
                self._offset = u["update_id"] + 1
                cq = u.get("callback_query")
                if not cq:
                    continue
                data = str(cq.get("data") or "")
                try:
                    await self._api("answerCallbackQuery", callback_query_id=cq["id"])
                except Exception:
                    pass
                # only honor buttons pressed in our chat
                chat = ((cq.get("message") or {}).get("chat") or {}).get("id")
                if chat != self.chat_id:
                    continue
                parts = data.split(":")
                if len(parts) == 3 and parts[0] == "heim":
                    fut = self._pending.get(parts[1])
                    if fut and not fut.done():
                        fut.set_result(parts[2] == "y")
