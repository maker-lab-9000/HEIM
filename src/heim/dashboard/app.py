"""The HEIM dashboard — a read-only web view of the pipeline's own records.

Stack per AGENTS.md §5.3: FastAPI + Jinja + vendored htmx, no build step. The
UI is specified in ``docs/design/dashboard-ui.md``; this module only assembles
the data each page needs.

**Read-only in v1.** The daemon is the sole writer of the pipeline tables
(AGENTS.md §2 invariants); this process opens exactly one SQLite connection and
never issues a write. WAL (enabled by ``IncidentStore``) is what makes a second
reader safe alongside the running daemon.

Run it with ``heim dashboard`` (uvicorn), or mount ``create_app()`` yourself.
"""
from __future__ import annotations

import base64
import binascii
import logging
import os
import secrets
import sqlite3
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from heim.config import Config, load_config
from heim.dashboard import format as fmt
from heim.incidents.store import IncidentStore
from heim.reports.render import _md_to_html

log = logging.getLogger(__name__)

_HERE = Path(__file__).resolve().parent
TEMPLATES_DIR = _HERE / "templates"
STATIC_DIR = _HERE / "static"

#: env var holding the shared password for HTTP basic auth (unset = open)
TOKEN_ENV = "HEIM_DASHBOARD_TOKEN"

#: a daemon that has not recorded a run in this long is "quiet"
DAEMON_FRESH_S = 20 * 60

STORE_ERROR = ("Store unreadable at {path} — is the daemon running with the "
               "same volume?")


# --------------------------------------------------------------- data access


class StoreReader:
    """Serialized read access to the one store connection.

    Routes are ``async def`` (they run on the event loop) but Starlette may
    still touch us from a portal thread in tests, so every read takes a lock
    and the connection is opened with ``check_same_thread=False``.

    The only statements this process ever issues beyond SELECTs are the
    idempotent ``CREATE TABLE IF NOT EXISTS`` in ``IncidentStore.__init__``
    (so a dashboard started before the first daemon run still has a schema to
    read). No pipeline row is ever written here — the daemon stays the sole
    writer (AGENTS.md §2).
    """

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.Lock()
        self._store = IncidentStore(self.path, check_same_thread=False)

    def read(self, fn: Callable[[IncidentStore], object]):
        with self._lock:
            return fn(self._store)

    def close(self) -> None:
        with self._lock:
            self._store.close()


# ------------------------------------------------------------------ auth


def _auth_ok(header: str | None, token: str) -> bool:
    """HTTP basic: any username, password must equal the token."""
    if not header or not header.lower().startswith("basic "):
        return False
    try:
        raw = base64.b64decode(header.split(" ", 1)[1].strip(), validate=True)
        _user, _, password = raw.decode("utf-8", "replace").partition(":")
    except (binascii.Error, ValueError, IndexError):
        return False
    return secrets.compare_digest(password, token)


# ------------------------------------------------------------------- app


def create_app(config: Config | None = None) -> FastAPI:
    cfg = config or load_config()
    reader = StoreReader(cfg.settings.db_path)

    try:
        tz = ZoneInfo(cfg.settings.timezone)
    except (ZoneInfoNotFoundError, ValueError):
        tz = timezone.utc

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        reader.close()

    app = FastAPI(title="HEIM", docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
    app.state.config = cfg
    app.state.reader = reader
    app.state.tz = tz

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.filters.update(
        rel=fmt.rel_time, iso=fmt.iso, clock=fmt.clock, day=fmt.day,
        dur_s=fmt.dur_s, dur_ms=fmt.dur_ms, tokens=fmt.tokens, size=fmt.size,
        fp=fmt.fingerprint, pill=fmt.status_pill, tool_key=fmt.tool_key,
        command=fmt.command_of,
    )
    templates.env.globals.update(duration=fmt.duration, elapsed=fmt.elapsed,
                                 DASH=fmt.DASH)
    app.state.templates = templates

    # ---------------------------------------------------------- middleware

    @app.middleware("http")
    async def basic_auth(request: Request, call_next):
        # read the env per request so a token can be added without a restart
        token = os.environ.get(TOKEN_ENV) or ""
        if token and request.url.path != "/healthz":
            if not _auth_ok(request.headers.get("authorization"), token):
                return Response(
                    "Authentication required.", status_code=401,
                    headers={"WWW-Authenticate": 'Basic realm="heim"'},
                    media_type="text/plain",
                )
        return await call_next(request)

    # -------------------------------------------------------------- render

    def page(request: Request, template: str, status: int = 200, **ctx) -> HTMLResponse:
        now = datetime.now(tz)
        base = {
            "now": now,
            "clock": now.strftime("%H:%M"),
            "env_chip": _env_chip(cfg, now),
            "daemon": _daemon_chip(reader),
            "nav": NAV,
        }
        base.update(ctx)
        return templates.TemplateResponse(request, template, base, status_code=status)

    def partial(request: Request, template: str, **ctx) -> HTMLResponse:
        return templates.TemplateResponse(request, template, ctx)

    @app.exception_handler(sqlite3.Error)
    async def _store_error(request: Request, exc: sqlite3.Error):
        log.warning("store read failed: %s", exc)
        return templates.TemplateResponse(
            request, "error.html",
            {"message": STORE_ERROR.format(path=reader.path), "detail": str(exc),
             "nav": NAV, "clock": "", "env_chip": _env_chip(cfg, datetime.now(tz)),
             "daemon": {"ok": False, "label": "daemon unreachable", "when": ""},
             "page_title": "error"},
            status_code=500,
        )

    # -------------------------------------------------------------- routes

    @app.get("/healthz", response_class=PlainTextResponse)
    async def healthz() -> str:
        return "ok"

    @app.get("/", response_class=HTMLResponse)
    async def overview(request: Request):
        open_incidents = reader.read(lambda s: s.open_rows())
        counts = reader.read(lambda s: s.counts_by_status())
        invs = reader.read(lambda s: s.investigations(limit=60))
        findings = reader.read(lambda s: s.recent_findings(limit=60))
        daily = reader.read(lambda s: s.runs(limit=1, kind="daily"))
        latest = daily[0] if daily else None
        headline_findings = _findings_of_run(findings, latest)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        tok_in = tok_out = 0
        for row in invs:
            started = fmt.parse_dt(row.get("started_at"))
            if started and started >= cutoff:
                tok_in += int(row.get("input_tokens") or 0)
                tok_out += int(row.get("output_tokens") or 0)
        kpis = [
            {"label": "open incidents", "value": str(len(open_incidents)),
             "meta": _incident_meta(open_incidents), "href": "/incidents"},
            {"label": "running invest.", "value": str(counts.get("running", 0)),
             "meta": "agents working now", "href": "/investigations?status=running",
             "running": counts.get("running", 0) > 0},
            {"label": "pending approval", "value": str(counts.get("pending_approval", 0)),
             "meta": "waiting on a 👍 in Telegram",
             "href": "/investigations?status=pending_approval"},
            {"label": "tokens 24h", "value": fmt.tokens(tok_in + tok_out),
             "meta": f"{fmt.tokens(tok_in)} in → {fmt.tokens(tok_out)} out"},
        ]
        return page(
            request, "overview.html", page_title="overview", kpis=kpis,
            latest_run=latest, headline=_headline(headline_findings),
            investigations=invs[:8], findings=findings[:6],
            empty=not invs and not findings and not open_incidents,
        )

    @app.get("/investigations", response_class=HTMLResponse)
    async def investigations(request: Request, status: str = "", host: str = "",
                             trigger: str = ""):
        rows, filters = _investigation_rows(reader, cfg, status, host, trigger)
        return page(request, "investigations.html", page_title="investigations",
                    rows=rows, filters=filters,
                    live=any(r["status"] == "running" for r in rows))

    @app.get("/investigations/rows", response_class=HTMLResponse)
    async def investigation_rows(request: Request, status: str = "", host: str = "",
                                 trigger: str = ""):
        rows, _ = _investigation_rows(reader, cfg, status, host, trigger)
        return partial(request, "partials/_inv_rows.html", rows=rows,
                       live=any(r["status"] == "running" for r in rows),
                       query=_query(status=status, host=host, trigger=trigger))

    @app.get("/investigations/{inv_id}", response_class=HTMLResponse)
    async def investigation_detail(request: Request, inv_id: int):
        row = reader.read(lambda s: s.investigation(inv_id))
        if row is None:
            return page(request, "error.html", status=404, page_title="not found",
                        message=f"No investigation #{inv_id}.",
                        detail="It may have been pruned, or the id is wrong — "
                               "the list shows everything the store has.")
        steps = row.get("steps") or []
        return page(
            request, "investigation.html", page_title=f"investigations / #{inv_id}",
            inv=row, steps=steps, burn=fmt.burn_segments(steps),
            report_html=_md_to_html(row.get("report_md") or "") if row.get("report_md") else "",
            outcome=_outcome_line(row),
        )

    @app.get("/investigations/{inv_id}/transcript", response_class=HTMLResponse)
    async def investigation_transcript(request: Request, inv_id: int):
        row = reader.read(lambda s: s.investigation(inv_id))
        if row is None:
            return PlainTextResponse(f"No investigation #{inv_id}.", status_code=404)
        steps = row.get("steps") or []
        return partial(request, "partials/_transcript.html", inv=row, steps=steps,
                       burn=fmt.burn_segments(steps))

    @app.get("/incidents", response_class=HTMLResponse)
    async def incidents(request: Request):
        rows = reader.read(lambda s: s.all_rows(limit=200))
        invs = reader.read(lambda s: s.investigations(limit=200))
        by_fp: dict[str, list[dict]] = {}
        for inv in invs:
            by_fp.setdefault(str(inv.get("fingerprint") or ""), []).append(inv)
        for row in rows:
            row["investigations"] = by_fp.get(row["fingerprint"], [])
        return page(request, "incidents.html", page_title="incidents", rows=rows)

    @app.get("/findings", response_class=HTMLResponse)
    async def findings_page(request: Request):
        rows = reader.read(lambda s: s.recent_findings(limit=200))
        runs = {int(r["id"]): r for r in reader.read(lambda s: s.runs(limit=200))}
        groups: list[dict] = []
        index: dict[object, dict] = {}
        for row in rows:
            key = row.get("run_id")
            group = index.get(key)
            if group is None:
                run = runs.get(int(key)) if key is not None else None
                group = {"run": run, "run_at": row.get("run_at") or (run or {}).get("run_at", ""),
                         "source": row.get("source") or (run or {}).get("kind", ""),
                         "findings": []}
                index[key] = group
                groups.append(group)
            group["findings"].append(row)
        for group in groups:  # worst first inside a run, like the daily email
            group["findings"].sort(key=lambda f: _SEV_RANK.get(
                str(f.get("severity") or "").lower(), 3))
        return page(request, "findings.html", page_title="findings", groups=groups,
                    total=len(rows))

    @app.get("/hosts", response_class=HTMLResponse)
    async def hosts_page(request: Request):
        open_incidents = reader.read(lambda s: s.open_rows())
        findings = reader.read(lambda s: s.recent_findings(limit=200))
        invs = reader.read(lambda s: s.investigations(limit=200))
        cards = []
        for host in cfg.hosts.values():
            cards.append({
                "name": host.name,
                "role": host.role,
                "open": [i for i in open_incidents if i["host"] == host.name],
                "finding": next((f for f in findings if f.get("host") == host.name), None),
                "investigation": next((i for i in invs if i.get("host") == host.name), None),
            })
        return page(request, "hosts.html", page_title="hosts", cards=cards)

    return app


# ---------------------------------------------------------------- helpers

NAV = [
    {"href": "/", "label": "overview", "icon": "◆"},
    {"href": "/investigations", "label": "investigations", "icon": "▣"},
    {"href": "/incidents", "label": "incidents", "icon": "▲"},
    {"href": "/findings", "label": "findings", "icon": "▤"},
    {"href": "/hosts", "label": "hosts", "icon": "▢"},
]

_TRIGGERS = ["daily", "poller", "manual"]


def _query(**params) -> str:
    parts = [f"{k}={v}" for k, v in params.items() if v]
    return ("?" + "&".join(parts)) if parts else ""


def _env_chip(cfg: Config, now: datetime) -> str:
    n = len(cfg.hosts)
    return f"{n} host{'s' if n != 1 else ''} · {now.tzname() or cfg.settings.timezone}"


def _daemon_chip(reader: StoreReader) -> dict:
    """Liveness derived from the freshest `runs` row (the daemon writes one per
    cycle that did something) — the dashboard never probes the daemon itself."""
    try:
        rows = reader.read(lambda s: s.runs(limit=1))
    except sqlite3.Error:  # pragma: no cover - surfaced by the error page
        return {"ok": False, "label": "daemon unreachable", "when": ""}
    if not rows:
        return {"ok": False, "label": "daemon quiet", "when": "no runs yet"}
    age = fmt.age_seconds(rows[0].get("run_at"))
    when = fmt.rel_time(rows[0].get("run_at"))
    if age is not None and age < DAEMON_FRESH_S:
        return {"ok": True, "label": "daemon", "when": f"last run {when}"}
    return {"ok": False, "label": "daemon quiet", "when": when}


def _incident_meta(rows: list[dict]) -> str:
    crit = sum(1 for r in rows if str(r.get("severity", "")).lower().startswith("crit"))
    if not rows:
        return "nothing open"
    return f"{crit} critical · {len(rows) - crit} warning"


def _findings_of_run(findings: list[dict], run: dict | None) -> list[dict]:
    if not run:
        return []
    return [f for f in findings if f.get("run_id") == run.get("id")]


_SEV_RANK = {"critical": 0, "crit": 0, "warning": 1, "warn": 1, "info": 2, "": 3}


def _headline(findings: list[dict]) -> dict | None:
    if not findings:
        return None
    return sorted(findings, key=lambda f: _SEV_RANK.get(
        str(f.get("severity") or "").lower(), 3))[0]


def _investigation_rows(reader: StoreReader, cfg: Config, status: str, host: str,
                        trigger: str) -> tuple[list[dict], dict]:
    """Filtered rows + the option lists the filter row renders.

    Status filtering happens in SQL (the store supports it); host/trigger are
    low-cardinality so they are filtered here rather than widening the store's
    read API.
    """
    rows = reader.read(lambda s: s.investigations(limit=200, status=status or None))
    all_rows = reader.read(lambda s: s.investigations(limit=200))
    if host:
        rows = [r for r in rows if r.get("host") == host]
    if trigger:
        rows = [r for r in rows if r.get("trigger") == trigger]
    statuses = sorted({str(r.get("status") or "") for r in all_rows if r.get("status")})
    hosts = sorted({str(r.get("host") or "") for r in all_rows if r.get("host")}
                   | set(cfg.hosts))
    triggers = sorted({str(r.get("trigger") or "") for r in all_rows if r.get("trigger")}
                      | set(_TRIGGERS))
    filters = {
        "status": status, "host": host, "trigger": trigger,
        "statuses": statuses, "hosts": hosts, "triggers": triggers,
        "query": _query(status=status, host=host, trigger=trigger),
    }
    return rows, filters


def _outcome_line(row: dict) -> dict | None:
    """The closing line of the detail page (read-only in v1; actions land with
    the jobs queue, AGENTS.md §5.2)."""
    status = str(row.get("status") or "")
    outcome = str(row.get("outcome") or "")
    when = fmt.clock(row.get("finished_at"))
    if outcome == "resolved" or status == "resolved":
        return {"icon": "✓", "cls": "st-ok", "text": f"Resolved by operator · {when}"}
    if outcome == "needs_human" or status == "needs_human":
        return {"icon": "⚠", "cls": "st-serious",
                "text": "Needs human — re-proposed next run"}
    if outcome == "timeout":
        return {"icon": "◌", "cls": "st-muted",
                "text": "No outcome confirmed — the ask timed out"}
    if status == "declined":
        return {"icon": "○", "cls": "st-muted",
                "text": "Declined — re-proposed next run"}
    if status == "failed":
        return {"icon": "✕", "cls": "st-crit",
                "text": row.get("incomplete_reason") or "Failed before writing a report"}
    if status == "incomplete":
        return {"icon": "⚠", "cls": "st-serious",
                "text": row.get("incomplete_reason") or "Incomplete run"}
    if status == "running":
        return {"icon": "●", "cls": "st-running", "text": "Still working…"}
    if status == "pending_approval":
        return {"icon": "◷", "cls": "st-warn", "text": "Waiting for approval in Telegram"}
    return None
