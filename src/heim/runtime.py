"""Runtime wiring: config + incident store + channels, with dry-run support.

``--dry-run`` keeps every outward side effect local: emails become HTML files
under ``out/``, Telegram/Loki/HA sends become log lines, and approvals are
auto-granted. Prometheus reads and SSH/API tool calls still happen (they are
read-only by design).
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from heim.channels import loki as loki_ch
from heim.channels.email import send_html
from heim.channels.ha import post_sensor
from heim.channels.telegram import Telegram
from heim.config import Config, env, load_config
from heim.incidents.store import IncidentStore

log = logging.getLogger(__name__)


@dataclass
class Runtime:
    config: Config
    store: IncidentStore
    telegram: Telegram | None = None
    dry_run: bool = False
    out_dir: Path = field(default_factory=lambda: Path("out"))
    _inv_sem: asyncio.Semaphore | None = field(default=None, repr=False)

    # ------------------------------------------------------- concurrency

    def investigation_slot(self) -> asyncio.Semaphore:
        """The process-wide investigation concurrency cap.

        Created lazily (and once) so it binds to the running loop rather than
        to import time; every caller of ``run_investigation`` shares it, which
        makes the cap global across daily dispatch, poller dispatch and the CLI.
        """
        if self._inv_sem is None:
            self._inv_sem = asyncio.Semaphore(
                max(1, int(self.config.settings.max_concurrent_investigations))
            )
        return self._inv_sem

    # ------------------------------------------------------------- time

    def now(self) -> datetime:
        return datetime.now(ZoneInfo(self.config.settings.timezone))

    def now_iso(self) -> str:
        return self.now().isoformat(timespec="milliseconds")

    # ------------------------------------------------------------ channels

    async def feed(self, text: str) -> None:
        """Live command feed (used as the tools' feed callback)."""
        if self.dry_run or self.telegram is None:
            log.info("FEED %s", text.replace("\n", " ⏎ ")[:300])
            return
        await self.telegram.notify(text[:3500])

    async def notify(self, text: str) -> None:
        if self.dry_run or self.telegram is None:
            log.info("NOTIFY %s", text.replace("\n", " ⏎ ")[:300])
            return
        await self.telegram.notify(text)

    def audit(self, entry: dict) -> None:
        try:
            with open(self.config.settings.audit_log, "a") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        except Exception:
            log.exception("audit append failed")

    async def emit_loki(self, events: list[dict]) -> None:
        if not events:
            return
        if self.dry_run or self.config.settings.loki is None:
            log.info("LOKI (%d events suppressed: %s)", len(events),
                     ", ".join(sorted({e.get("event", "?") for e in events})))
            return
        await loki_ch.push_events(self.config.settings.loki.url, events)

    async def send_email(self, subject: str, html: str) -> Path | None:
        if self.dry_run or self.config.settings.email is None:
            self.out_dir.mkdir(exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            safe = "".join(c if c.isalnum() or c in "-_ " else "_" for c in subject)[:60].strip()
            path = self.out_dir / f"{stamp} {safe}.html"
            path.write_text(html)
            log.info("EMAIL written to %s (subject: %s)", path, subject)
            return path
        await send_html(self.config.settings.email, subject, html)
        log.info("email sent: %s", subject)
        return None

    async def push_ha(self, entity_suffix: str, state: str, attributes: dict) -> None:
        # State writes via the HA REST API require an ADMIN user; the agent tool's
        # HA_TOKEN is deliberately non-admin, so pushes prefer HA_PUSH_TOKEN.
        ha = self.config.settings.home_assistant
        token = env("HA_PUSH_TOKEN") or env("HA_TOKEN")
        if self.dry_run or ha is None or not token:
            log.info("HA push suppressed (sensor.pam_%s)", entity_suffix)
            return
        await post_sensor(ha.url, token, entity_suffix, state, attributes)


def build_runtime(config: Config | None = None, *, dry_run: bool = False) -> Runtime:
    cfg = config or load_config()
    store = IncidentStore(cfg.settings.db_path)
    telegram = None
    token = env("TELEGRAM_BOT_TOKEN")
    if cfg.settings.telegram is not None and token:
        telegram = Telegram(token, cfg.settings.telegram.chat_id)
    return Runtime(config=cfg, store=store, telegram=telegram, dry_run=dry_run)
