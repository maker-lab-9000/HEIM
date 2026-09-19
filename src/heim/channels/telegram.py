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
from collections.abc import Callable

import httpx

log = logging.getLogger(__name__)

CHUNK_LIMIT = 3900  # Telegram hard cap is 4096; leave room for the part prefix


def _deadline(timeout_s: float | None) -> float | None:
    """``None`` (wait forever) for any non-positive timeout.

    One place decides what "no timeout" means, so the Telegram wait and the
    store poll cannot disagree about it.
    """
    return None if not timeout_s or float(timeout_s) <= 0 else float(timeout_s)


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
        self._persistent = False
        #: Called with ``(key, approved)`` for every button tap in our chat;
        #: returns True if it recorded something. The runtime points this at
        #: the store, which is what makes a tap outlive the process that sent
        #: the buttons. Left None, approvals are in-memory only.
        self.on_decision: Callable[[str, bool], bool] | None = None

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
        key: str = "",
    ) -> bool | None:
        """Send an approval prompt with inline buttons; return True/False, or
        None on timeout. Multiple concurrent asks are supported (one shared
        getUpdates consumer).

        ``key`` is what the buttons carry. Pass a durable one — ``inv:<id>`` —
        and a tap still means something after a restart, because
        ``on_decision`` can resolve it against the store instead of against
        this process's memory. Omitted, it falls back to a random uid, which
        only the process that created it can resolve.

        ``timeout_s <= 0`` waits indefinitely: an approval nobody answers stays
        parked rather than expiring into a decline.
        """
        key = key or uuid.uuid4().hex[:12]
        markup = {
            "inline_keyboard": [[
                {"text": no, "callback_data": f"heim:{key}:n"},
                {"text": yes, "callback_data": f"heim:{key}:y"},
            ]]
        }
        message_id = await self.send(text, reply_markup=markup)
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[key] = fut
        self._ensure_updates_loop()
        try:
            answer: bool | None = await asyncio.wait_for(fut, _deadline(timeout_s))
        except (TimeoutError, asyncio.TimeoutError):
            answer = None
        finally:
            self._pending.pop(key, None)
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

    def start_consumer(self) -> None:
        """Consume button taps for as long as this process lives.

        The lazy loop below stops once nothing is pending, which is fine while
        every button belongs to an outstanding ``ask``. Durable approvals break
        that: a tap can arrive for a prompt sent before the last restart, with
        no ``ask`` outstanding to start the loop. The daemon calls this at
        startup so the window where a tap is silently dropped is closed.
        """
        self._persistent = True
        self._ensure_updates_loop()

    def stop_consumer(self) -> None:
        self._persistent = False
        if self._loop_task is not None:
            self._loop_task.cancel()
            self._loop_task = None

    def _ensure_updates_loop(self) -> None:
        if self._loop_task is None or self._loop_task.done():
            self._loop_task = asyncio.get_running_loop().create_task(self._updates_loop())

    async def _updates_loop(self) -> None:
        """Single consumer of getUpdates; resolves button taps.

        Runs while something is pending, or forever once ``start_consumer``
        has been called.
        """
        while self._persistent or self._pending:
            try:
                updates = await self._api(
                    "getUpdates",
                    timeout=40.0,
                    offset=self._offset,
                    allowed_updates=["callback_query"],
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
                # only honor buttons pressed in our chat
                chat = ((cq.get("message") or {}).get("chat") or {}).get("id")
                if chat != self.chat_id or not data.startswith("heim:"):
                    await self._ack(cq)
                    continue
                # key may itself contain ':' (``inv:41``), so split off the
                # verdict from the right, never with a fixed field count.
                key, _, verdict = data[len("heim:"):].rpartition(":")
                if not key or verdict not in ("y", "n"):
                    await self._ack(cq)
                    continue
                await self._ack(cq, self._resolve(key, verdict == "y"))

    async def _ack(self, cq: dict, text: str = "") -> None:
        """Acknowledge a tap so Telegram stops spinning on the button."""
        try:
            await self._api("answerCallbackQuery", callback_query_id=cq["id"],
                            **({"text": text} if text else {}))
        except Exception:
            log.debug("answerCallbackQuery failed", exc_info=True)

    def _resolve(self, key: str, approved: bool) -> str:
        """Apply one tap; returns the toast to show the operator.

        Two resolutions, deliberately both: the durable one (``on_decision``
        writes the store, which is what a waiter in a *later* process polls)
        and the in-memory future (which makes the same-process case answer
        instantly instead of after a poll interval). They write the same
        verdict, so the order between them does not matter.
        """
        recorded = False
        if self.on_decision is not None:
            try:
                recorded = bool(self.on_decision(key, approved))
            except Exception:
                log.exception("recording telegram decision for %r failed", key)
        fut = self._pending.get(key)
        if fut is not None and not fut.done():
            fut.set_result(approved)
            recorded = True
        if recorded:
            return "Approved" if approved else "Declined"
        # A tap on a prompt that was already answered elsewhere — the
        # dashboard, or an earlier tap. Say so; silence reads as a bug.
        return "No longer pending — nothing changed."
