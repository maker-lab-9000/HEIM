"""HEIM command-line interface.

    heim check                         validate config + connectivity
    heim daily [--dry-run]             run the daily analysis pipeline once
    heim poll [--dry-run]              run one poll cycle (alerts + thresholds)
    heim thresholds [--all]            current value, flag and streak per query
    heim investigate --host H ...      run one investigation
    heim investigate --fingerprint FP  ... rebuilt from the stored incident
    heim incidents [--all]             show the incident store
    heim incidents mute FP [--days N]  suppress a false-positive fingerprint
    heim incidents unmute FP           lift a suppression
    heim investigations [--show ID]    list / inspect tracked investigations
    heim replay ID [--model M]         re-run a stored investigation offline
                 [--prompt-file F]     against its recorded tool results
    heim jobs [--limit N]              show the investigation job queue
    heim dashboard [--host] [--port]   serve the read-only web dashboard
    heim daemon                        run scheduler + poller + approvals

--dry-run keeps side effects local: emails become HTML files under out/,
Telegram/Loki/HA writes become log lines, approvals auto-granted.
"""
from __future__ import annotations

import argparse
import asyncio
import difflib
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


async def _cmd_thresholds(args) -> int:
    """What threshold detection sees right now: value, flag and streak.

    The operator's way to see what is *about* to open an incident — a series
    at ``crit`` with a streak one short of ``threshold_consecutive`` is one
    poll away from a dispatch.
    """
    from heim.metrics.queries import load_queries
    from heim.pipelines import thresholds
    from heim.runtime import build_runtime

    rt = build_runtime()
    settings = rt.config.settings
    qdefs = load_queries(rt.config.queries_path)
    results = await thresholds.fetch_instants(settings.prometheus.url, qdefs)
    samples = thresholds.build_samples(results, settings.instance_host_map)
    streaks = rt.store.threshold_streaks()
    tcfg = thresholds.ThresholdConfig.from_settings(settings)

    if not samples:
        print("no samples — is Prometheus reachable?")
        return 1
    rank = {"crit": 0, "warn": 1, "ok": 2, "na": 3}
    rows = sorted(samples, key=lambda s: (rank.get(str(s.get("flag")), 3),
                                          str(s.get("host")), str(s.get("qid"))))
    if not args.all:
        rows = [s for s in rows if s.get("flag") in ("crit", "warn")]
    print(f"threshold_detection={'on' if settings.threshold_detection else 'OFF'} "
          f"severity={tcfg.severity} consecutive={tcfg.consecutive}")
    print(f"{'flag':<5} {'host':<18} {'metric':<28} {'current':>10}  streak")
    for s in rows:
        streak = int((streaks.get(str(s['fingerprint'])) or {}).get("count") or 0)
        cur = s.get("current")
        value = "—" if cur is None else f"{cur:g}{s.get('unit') or ''}"
        armed = " ← opens next poll" if (
            s.get("flag") in tcfg.over_flags and streak + 1 >= tcfg.consecutive) else ""
        print(f"{str(s['flag']):<5} {str(s['host'])[:18]:<18} "
              f"{str(s['metric'])[:28]:<28} {value:>10}  {streak}{armed}")
    if not rows:
        print("(everything under threshold)")
    return 0


def _request_from_incident(rt, incident: dict, role: str | None) -> "object":
    """Build an InvestigationRequest out of a stored incident row (§5.5)."""
    from heim.pipelines.investigate import InvestigationRequest

    host = str(incident.get("host") or "")
    host_cfg = rt.config.hosts.get(host)
    return InvestigationRequest(
        host=host,
        host_role=role or (host_cfg.role if host_cfg else "guest"),
        fingerprint=str(incident.get("fingerprint") or ""),
        findings=[{
            "severity": incident.get("severity", ""),
            "host": host,
            "metric": incident.get("metric", ""),
            "trend": "",
            "detail": incident.get("description", ""),
            "recommendation": "",
        }],
    )


async def _cmd_investigate(args) -> int:
    from heim.pipelines.investigate import InvestigationRequest, run_investigation
    from heim.runtime import build_runtime

    if not args.host and not args.fingerprint:
        print("error: one of --host or --fingerprint is required")
        return 2

    rt = build_runtime(dry_run=args.dry_run)
    # §5.1: the CLI offers the same list the dashboard's dropdown does — the
    # config is only readable once the runtime is built, so this is checked
    # here rather than by argparse's `choices`.
    model = str(getattr(args, "model", "") or "").strip()
    offered = list(rt.config.settings.investigator_models)
    if model and model not in offered:
        print(f"error: {model} is not in settings.investigator_models "
              f"({', '.join(offered) if offered else 'empty'})")
        return 2
    if not args.host:
        # --fingerprint alone: pull the subject out of the incident store
        incident = rt.store.incident(args.fingerprint)
        if incident is None:
            print(f"no incident with fingerprint {args.fingerprint!r}")
            return 1
        req = _request_from_incident(rt, incident, args.role)
        print(f"investigating {req.host} from incident {args.fingerprint} "
              f"[{incident.get('severity')}] {incident.get('metric')}")
    else:
        host_cfg = rt.config.hosts.get(args.host)
        role = args.role or (host_cfg.role if host_cfg else "guest")
        findings = []
        if args.finding:
            findings = [{"severity": args.severity, "host": args.host, "metric": args.metric or "",
                         "trend": "", "detail": args.finding, "recommendation": ""}]
        req = InvestigationRequest(host=args.host, host_role=role,
                                   fingerprint=args.fingerprint or "", findings=findings)
    req.model_override = model
    if model:
        print(f"model: {model} (this run only)")
    result = await run_investigation(rt, req, require_approval=False if args.no_approval else None)
    if result is None:
        print("declined / timed out — nothing ran")
        return 1
    print(f"\n{'⚠️ INCOMPLETE' if result['incomplete'] else '✅ complete'} — {result['steps']} steps, "
          f"{result['input_tokens']:,} in / {result['output_tokens']:,} out tokens\n")
    print(result["report_md"])
    return 0


def _money(value: float | int | None) -> str:
    """0 means the model has no price entry — unpriced, not free (§5.6)."""
    return f"{float(value):.4f}" if value else "—"


def replay_comparison(result: dict) -> str:
    """Original vs replay, as the CLI prints it (pure, so it is testable).

    The interesting output is the bottom half: the two root-cause sections in
    full, then a unified diff of them. Everything above is the context needed
    to read that diff honestly — which model, how many steps, and *how much of
    the replay's evidence was really the original's* (the cassette line).
    """
    from heim.reports.render import extract_sections

    orig = result.get("original") or {}
    stats = result.get("cassette") or {}
    o_sections = extract_sections(str(orig.get("report_md") or ""))
    r_sections = extract_sections(str(result.get("report_md") or ""))

    def row(label: str, left: str, right: str) -> str:
        return f"{label:<12s} {left:<30s} {right}"

    lines = [
        f"replay #{result['id']} of investigation #{result['replay_of']} — {result['host']}",
        "",
        row("", "original", "replay"),
        row("model", str(orig.get("model") or "—"), str(result.get("model") or "—")),
        row("status", str(orig.get("status") or "—"), str(result.get("status") or "—")),
        row("steps", str(orig.get("n_steps") or 0), str(result.get("steps") or 0)),
        row("tokens",
            f"{int(orig.get('input_tokens') or 0):,} in / {int(orig.get('output_tokens') or 0):,} out",
            f"{result.get('input_tokens', 0):,} in / {result.get('output_tokens', 0):,} out"),
        row("cost", _money(orig.get("cost")), _money(result.get("cost"))),
        row("confidence", o_sections["confidence"] or "—", r_sections["confidence"] or "—"),
        "",
        f"cassette     {stats.get('recorded', 0)} recorded · {stats.get('exact', 0)} exact · "
        f"{stats.get('fuzzy', 0)} fuzzy · {stats.get('missed', 0)} missed · "
        f"{stats.get('unused', 0)} unused",
    ]
    if result.get("prompt_file"):
        lines.append(f"prompt       {result['prompt_file']}")
    if stats.get("fuzzy"):
        lines.append("             (fuzzy = same tool, different arguments — the replay saw "
                     "plausible evidence, not the answer to the call it made)")

    o_rc = str(o_sections["root_cause"] or "").strip()
    r_rc = str(r_sections["root_cause"] or "").strip()
    lines += [
        "",
        "─" * 70,
        "ROOT CAUSE — original",
        "─" * 70,
        o_rc or "(none)",
        "",
        "─" * 70,
        f"ROOT CAUSE — replay ({result.get('model') or '?'})",
        "─" * 70,
        r_rc or "(none)",
        "",
        "─" * 70,
        "DIFF (original → replay)",
        "─" * 70,
    ]
    diff = list(difflib.unified_diff(
        o_rc.splitlines(), r_rc.splitlines(),
        fromfile="original", tofile="replay", lineterm="",
    ))
    lines += diff if diff else ["(identical root-cause text)"]
    return "\n".join(lines)


async def _cmd_replay(args) -> int:
    from heim.pipelines.replay import ReplayError, run_replay
    from heim.runtime import build_runtime

    # dry_run: a replay opens no channels by construction, but this also keeps
    # any incidental write (out/) local and matches operator expectations.
    rt = build_runtime(dry_run=True)
    try:
        result = await run_replay(rt, args.id, model=args.model,
                                  prompt_file=args.prompt_file)
    except ReplayError as exc:
        print(f"error: {exc}")
        return 2
    if result is None:
        print("replay failed — see the log")
        return 1
    print(replay_comparison(result))
    return 0


async def _cmd_incidents(args) -> int:
    from heim.runtime import build_runtime

    rt = build_runtime(dry_run=True)
    action = getattr(args, "action", None)
    if action in ("mute", "unmute"):
        return _incidents_mute(rt, action, args)

    rows = rt.store.all_rows() if args.all else rt.store.open_rows()
    if not rows:
        print("no incidents" if args.all else "no open incidents")
        return 0
    for r in rows:
        inv = "🔒" if r["investigated"] else "  "
        print(f"{inv} [{r['status']:8s}] {r['severity']:8s} {r['fingerprint']:55s} "
              f"seen×{r['timesSeen']} missed:{r['missedRuns']} last:{str(r['lastSeen'])[:16]}")
    return 0


def _incidents_mute(rt, action: str, args) -> int:
    """``heim incidents mute|unmute <fingerprint>`` — the CLI half of §5.4.

    Same suppression semantics as marking a finding a false positive, minus
    the finding verdict (there is no finding here, just a fingerprint)."""
    from heim.pipelines.suppression import suppress_fingerprint

    fingerprint = args.fingerprint
    if not fingerprint:
        print(f"error: `heim incidents {action}` needs a fingerprint")
        return 2
    if action == "unmute":
        if not rt.store.unsuppress(fingerprint):
            print(f"{fingerprint} was not suppressed")
            return 1
        incident = rt.store.incident(fingerprint)
        if incident and incident.get("status") == "suppressed":
            rt.store.set_incident_status(fingerprint, "open")
        print(f"unmuted {fingerprint}")
        return 0

    days = args.days if args.days is not None else rt.config.settings.suppression_days
    res = suppress_fingerprint(rt.store, fingerprint, days=days,
                               reason=args.reason or "", now=rt.now())
    print(f"muted {fingerprint} until {res['until'] or 'forever'}"
          + ("" if res["incident_updated"] else " (no incident row yet)"))
    return 0


async def _cmd_jobs(args) -> int:
    from heim.runtime import build_runtime

    rt = build_runtime(dry_run=True)
    rows = rt.store.jobs(limit=args.limit, status=args.status)
    if not rows:
        print("no jobs queued or recorded")
        return 0
    for r in rows:
        payload = r.get("payload") or {}
        inv = f"inv:#{r['investigation_id']}" if r["investigation_id"] else ""
        retry = f"retry-of:#{r['retry_of']}" if r["retry_of"] else ""
        print(f"#{r['id']:<5d} [{r['status']:11s}] {r['kind']:11s} "
              f"{str(payload.get('host') or '-'):16s} by:{(r['requested_by'] or '-'):9s} "
              f"{inv:10s} {retry:14s} {str(r['created_at'])[:19]}"
              + (f"  ⚠️ {r['error']}" if r["error"] else ""))
    print(f"\n{rt.store.queued_count()} queued")
    return 0


def _print_investigation(row: dict) -> None:
    """The --show detail block: metadata, the step table, then the report."""
    print(f"investigation #{row['id']} — {row['status']}")
    for label, key in (
        ("host", "host"), ("role", "host_role"), ("fingerprint", "fingerprint"),
        ("trigger", "trigger"), ("agent", "agent_name"), ("model", "model"),
        ("started", "started_at"), ("finished", "finished_at"),
        ("outcome", "outcome"), ("incomplete", "incomplete_reason"),
    ):
        if row.get(key):
            print(f"  {label:11s} {row[key]}")
    print(f"  {'tokens':11s} {row.get('input_tokens', 0):,} in / {row.get('output_tokens', 0):,} out")
    # 0 means the model has no entry in settings.model_prices — unpriced, not free
    if row.get("cost"):
        print(f"  {'cost':11s} {float(row['cost']):.4f}")
    steps = row.get("steps") or []
    print(f"  {'steps':11s} {len(steps)}")
    if steps:
        print("\nsteps:")
        for s in steps:
            flag = "🚫" if s.get("blocked") else "  "
            args_preview = str(s.get("args_json") or "").replace("\n", " ")[:80]
            # ~Nk: the turn's usage, credited to the first call that turn made
            tok = f" ~{s.get('input_tokens') or 0:>6,}tok" if s.get("input_tokens") else " " * 11
            print(f"  {flag} {s['seq']:3d} {s['tool']:18s} {s.get('duration_ms', 0):7d}ms"
                  f"{tok}  {args_preview}")
    if row.get("report_md"):
        print("\n" + "-" * 70 + "\n")
        print(row["report_md"])


async def _cmd_investigations(args) -> int:
    from heim.runtime import build_runtime

    rt = build_runtime(dry_run=True)
    if args.show:
        row = rt.store.investigation(args.show)
        if row is None:
            print(f"no investigation with id {args.show}")
            return 1
        _print_investigation(row)
        return 0

    rows = rt.store.investigations(limit=args.limit)
    if not rows:
        print("no investigations recorded yet")
        return 0
    for r in rows:
        print(f"#{r['id']:<5d} [{r['status']:16s}] {r['trigger']:7s} {r['host']:16s} "
              f"{(r['fingerprint'] or '-'):40s} steps:{r['n_steps']:<3d} "
              f"{r['input_tokens']:>7,} in / {r['output_tokens']:>6,} out  {str(r['started_at'])[:19]}")
    counts = rt.store.counts_by_status()
    if counts:
        print("\n" + " · ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    return 0


async def _cmd_dashboard(args) -> int:
    import uvicorn  # heavy + optional at import time; keep it in the handler

    from heim.dashboard.app import create_app

    app = create_app(load_config())
    print(f"dashboard on http://{args.host}:{args.port} "
          f"({'basic auth on' if env('HEIM_DASHBOARD_TOKEN') else 'no auth — keep it LAN-only'})",
          flush=True)
    server = uvicorn.Server(uvicorn.Config(app, host=args.host, port=args.port, log_level="info"))
    await server.serve()
    return 0


async def _cmd_daemon(args) -> int:
    from heim.daemon import run_daemon

    await run_daemon()
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="heim", description="HEIM — Homelab Event & Incident Monitor")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("check", help="validate config and connectivity")

    d = sub.add_parser("daily", help="run the daily analysis pipeline once")
    d.add_argument("--dry-run", action="store_true")

    pl = sub.add_parser("poll", help="run one alert-poller cycle")
    pl.add_argument("--dry-run", action="store_true")

    th = sub.add_parser("thresholds",
                        help="show each catalog entry's value, flag and streak")
    th.add_argument("--all", action="store_true",
                    help="include ok/na series (default: only warn and crit)")

    inv = sub.add_parser("investigate", help="run one investigation")
    inv.add_argument("--host", help="host to investigate (or use --fingerprint alone)")
    inv.add_argument("--role", choices=["guest", "hypervisor", "ha-guest"])
    inv.add_argument("--finding", help="free-text finding to investigate")
    inv.add_argument("--metric", default="")
    inv.add_argument("--severity", default="warning")
    inv.add_argument("--fingerprint", default="")
    inv.add_argument("--no-approval", action="store_true")
    inv.add_argument("--model", default="",
                     help="run on one of settings.investigator_models "
                          "(default: the investigator's own model)")
    inv.add_argument("--dry-run", action="store_true")

    ic = sub.add_parser("incidents", help="show the incident store / mute fingerprints")
    # Optional positionals keep `heim incidents` and `heim incidents --all`
    # working exactly as before while adding the mute/unmute verbs.
    ic.add_argument("action", nargs="?", choices=["mute", "unmute"],
                    help="mute / unmute a fingerprint (omit to list incidents)")
    ic.add_argument("fingerprint", nargs="?", help="fingerprint for mute/unmute")
    ic.add_argument("--all", action="store_true", help="include resolved")
    ic.add_argument("--days", type=int, default=None,
                    help="mute window in days (0 = forever; default: settings.suppression_days)")
    ic.add_argument("--reason", default="", help="why it is a false positive (shown to the analyst)")

    jb = sub.add_parser("jobs", help="show the investigation job queue")
    jb.add_argument("--limit", type=int, default=20)
    jb.add_argument("--status", choices=["queued", "running", "done", "failed", "interrupted"])

    iv = sub.add_parser("investigations", help="list / inspect tracked investigations")
    iv.add_argument("--limit", type=int, default=20)
    iv.add_argument("--show", type=int, metavar="ID",
                    help="print one investigation with its step timeline and report")

    rp = sub.add_parser("replay", help="replay a stored investigation offline (eval harness)")
    rp.add_argument("id", type=int, help="investigation id to replay")
    rp.add_argument("--model", help="model to replay on (default: the investigator's)")
    rp.add_argument("--prompt-file", help="candidate system prompt to replay with")

    db = sub.add_parser("dashboard", help="serve the read-only web dashboard")
    db.add_argument("--host", default="0.0.0.0")
    db.add_argument("--port", type=int, default=8300)

    sub.add_parser("daemon", help="run scheduler + poller + approval listener")
    return p


def main() -> None:
    args = _build_parser().parse_args()
    _setup_logging(args.verbose)
    handler = {
        "check": _cmd_check, "daily": _cmd_daily, "poll": _cmd_poll,
        "thresholds": _cmd_thresholds,
        "investigate": _cmd_investigate, "incidents": _cmd_incidents,
        "investigations": _cmd_investigations, "jobs": _cmd_jobs, "replay": _cmd_replay,
        "dashboard": _cmd_dashboard, "daemon": _cmd_daemon,
    }[args.cmd]
    try:
        sys.exit(asyncio.run(handler(args)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
