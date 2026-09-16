"""Email delivery over SMTP (replaces the n8n Gmail OAuth nodes).

For Gmail, use an app password (Google account → Security → App passwords)
via env SMTP_USER / SMTP_PASSWORD.
"""
from __future__ import annotations

import asyncio
import logging
import smtplib
from email.mime.text import MIMEText

from heim.config import EmailCfg, env

log = logging.getLogger(__name__)


def _send_sync(cfg: EmailCfg, subject: str, html: str) -> None:
    user = env("SMTP_USER", required=True)
    password = env("SMTP_PASSWORD", required=True)
    msg = MIMEText(html, "html", "utf-8")
    msg["Subject"] = subject
    msg["From"] = cfg.from_addr
    msg["To"] = cfg.to
    with smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, timeout=30) as smtp:
        smtp.login(user, password)
        smtp.sendmail(cfg.from_addr, [cfg.to], msg.as_string())


async def send_html(cfg: EmailCfg, subject: str, html: str) -> None:
    await asyncio.to_thread(_send_sync, cfg, subject, html)
