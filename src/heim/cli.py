"""HEIM command-line interface.

    heim check                         validate config + connectivity
    heim daily [--dry-run]             run the daily analysis pipeline once
    heim poll [--dry-run]              run one alert-poller cycle
    heim investigate --host H ...      run one investigation
    heim incidents [--all]             show the incident store
    heim daemon                        run scheduler + poller + approvals

--dry-run keeps side effects local: emails become HTML files under out/,
Telegram/Loki/HA writes become log lines, approvals auto-granted.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from heim import config as config_mod
from heim.config import env, load_config


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("asyncssh").setLevel(logging.WARNING)


# ---------------------------------------------------------------- commands


async def _cmd_check(args) -> int:
    import httpx

    cfg = load_config()
    ok = True

    def line(status: bool | None, label: str, detail: str = "") -> None:
        nonlocal ok
        icon = "✅" if status else ("⚠️ " if status is None else "❌")
        if status is False:
            ok = False
        print(f"{icon} {label}" + (f" — {detail}" if detail else ""))

    print(f"config root: {cfg.root}")
    line(True, f"config: {len(cfg.hosts)} hosts, {len(cfg.tools)} tools, "
               f"{len(cfg.agents)} agents{' + analyst' if cfg.analyst else ''}")
    from heim.metrics.queries import load_queries
    line(True, f"queries: {len(load_queries(cfg.queries_path))} in {cfg.queries_path.name}")

    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        try:
            r = await client.get(f"{cfg.settings.prometheus.url.rstrip('/')}/-/healthy")
            line(r.status_code == 200, f"prometheus {cfg.settings.prometheus.url}", r.text.strip()[:60])
        except Exception as exc:
            line(False, f"prometheus {cfg.settings.prometheus.url}", str(exc))
        if cfg.settings.loki:
            try:
                r = await client.get(f"{cfg.settings.loki.url.rstrip('/')}/ready")
                line(r.status_code == 200, f"loki {cfg.settings.loki.url}", r.text.strip()[:60])
            except Exception as exc:
                line(False, f"loki {cfg.settings.loki.url}", str(exc))
        if cfg.settings.home_assistant:
            token = env("HA_TOKEN")
            if token:
                try:
                    r = await client.get(f"{cfg.settings.home_assistant.url.rstrip('/')}/api/",
                                         headers={"Authorization": f"Bearer {token}"})
                    line(r.status_code == 200, "home assistant API", f"HTTP {r.status_code}")
                except Exception as exc:
                    line(False, "home assistant API", str(exc))
            else:
                line(None, "home assistant API", "HA_TOKEN not set — pushes will be skipped")
        if cfg.settings.telegram:
            token = env("TELEGRAM_BOT_TOKEN")
            if token:
                try:
                    r = await client.get(f"https://api.telegram.org/bot{token}/getMe")
                    name = (r.json().get("result") or {}).get("username", "?")
                    line(r.json().get("ok", False), "telegram bot", f"@{name}, chat {cfg.settings.telegram.chat_id}")
                except Exception as exc:
                    line(False, "telegram bot", str(exc))
            else:
                line(None, "telegram", "TELEGRAM_BOT_TOKEN not set — approvals/feed disabled")

    line(bool(env("ANTHROPIC_API_KEY")), "ANTHROPIC_API_KEY", "" if env("ANTHROPIC_API_KEY") else "required for the investigator + analyst fallback")
    line(None if not env("OPENROUTER_API_KEY") else True, "OPENROUTER_API_KEY",
         "" if env("OPENROUTER_API_KEY") else "not set — analyst will use the Anthropic fallback only")
    if cfg.settings.email:
        line(bool(env("SMTP_USER") and env("SMTP_PASSWORD")), "SMTP credentials",
             "" if env("SMTP_PASSWORD") else "SMTP_USER/SMTP_PASSWORD not set — emails will fail")
    import os
    for h in cfg.hosts.values():
        if h.ssh:
            key = h.ssh.resolved_key_path()
            line(os.path.exists(key), f"ssh key for {h.name}", key)
    return 0 if ok else 1


async def _cmd_daily(args) -> int:
    from heim.pipelines.daily import run_daily
    from heim.runtime import build_runtime

    rt = build_runtime(dry_run=args.dry_run)
    result = await run_daily(rt, dispatch_concurrently=False)
    print(json.dumps(result, indent=2))
    return 0


async def _cmd_poll(args) -> int:
    from heim.pipelines.poller import run_poll
    from heim.runtime import build_runtime

    rt = build_runtime(dry_run=args.dry_run)
    result = await run_poll(rt, dispatch_concurrently=False)
    print(json.dumps(result, indent=2))
    return 0


async def _cmd_investigate(args) -> int:
    from heim.pipelines.investigate import InvestigationRequest, run_investigation
    from heim.runtime import build_runtime

    rt = build_runtime(dry_run=args.dry_run)
    host_cfg = rt.config.hosts.get(args.host)
    role = args.role or (host_cfg.role if host_cfg else "guest")
    findings = []
    if args.finding:
        findings = [{"severity": args.severity, "host": args.host, "metric": args.metric or "",
                     "trend": "", "detail": args.finding, "recommendation": ""}]
    req = InvestigationRequest(host=args.host, host_role=role,
                               fingerprint=args.fingerprint or "", findings=findings)
    result = await run_investigation(rt, req, require_approval=False if args.no_approval else None)
    if result is None:
        print("declined / timed out — nothing ran")
        return 1
    print(f"\n{'⚠️ INCOMPLETE' if result['incomplete'] else '✅ complete'} — {result['steps']} steps, "
          f"{result['input_tokens']:,} in / {result['output_tokens']:,} out tokens\n")
    print(result["report_md"])
    return 0


async def _cmd_incidents(args) -> int:
    from heim.runtime import build_runtime

    rt = build_runtime(dry_run=True)
    rows = rt.store.all_rows() if args.all else rt.store.open_rows()
    if not rows:
        print("no incidents" if args.all else "no open incidents")
        return 0
    for r in rows:
        inv = "🔒" if r["investigated"] else "  "
        print(f"{inv} [{r['status']:8s}] {r['severity']:8s} {r['fingerprint']:55s} "
              f"seen×{r['timesSeen']} missed:{r['missedRuns']} last:{str(r['lastSeen'])[:16]}")
    return 0


async def _cmd_daemon(args) -> int:
    from heim.daemon import run_daemon

    await run_daemon()
    return 0


def main() -> None:
    p = argparse.ArgumentParser(prog="heim", description="HEIM — Homelab Event & Incident Monitor")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("check", help="validate config and connectivity")

    d = sub.add_parser("daily", help="run the daily analysis pipeline once")
    d.add_argument("--dry-run", action="store_true")

    pl = sub.add_parser("poll", help="run one alert-poller cycle")
    pl.add_argument("--dry-run", action="store_true")

    inv = sub.add_parser("investigate", help="run one investigation")
    inv.add_argument("--host", required=True)
    inv.add_argument("--role", choices=["guest", "hypervisor", "ha-guest"])
    inv.add_argument("--finding", help="free-text finding to investigate")
    inv.add_argument("--metric", default="")
    inv.add_argument("--severity", default="warning")
    inv.add_argument("--fingerprint", default="")
    inv.add_argument("--no-approval", action="store_true")
    inv.add_argument("--dry-run", action="store_true")

    ic = sub.add_parser("incidents", help="show the incident store")
    ic.add_argument("--all", action="store_true", help="include resolved")

    sub.add_parser("daemon", help="run scheduler + poller + approval listener")

    args = p.parse_args()
    _setup_logging(args.verbose)
    handler = {
        "check": _cmd_check, "daily": _cmd_daily, "poll": _cmd_poll,
        "investigate": _cmd_investigate, "incidents": _cmd_incidents, "daemon": _cmd_daemon,
    }[args.cmd]
    try:
        sys.exit(asyncio.run(handler(args)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
