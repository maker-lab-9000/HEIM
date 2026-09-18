"""The HEIM dashboard — a web view of the pipeline's own records, plus actions.

Stack per AGENTS.md §5.3: FastAPI + Jinja + vendored htmx, no build step. The
UI is specified in ``docs/design/dashboard-ui.md``; this module only assembles
the data each page needs.

**Reads everything, writes action rows only** (design spec §5). The daemon
remains the sole executor and the sole writer of the pipeline tables
(AGENTS.md §2 invariants); the dashboard's entire write surface is the
allow-list in ``_ACTION_HELPERS``: queue a job, decide an approval, judge a
finding, mute/unmute a fingerprint. No route ever touches ``incidents``,
``investigations``, ``runs`` or ``jobs`` outside those helpers. WAL (enabled by
``IncidentStore``) is what makes this second connection safe alongside the
running daemon.

The one page that looks outside the store is ``/metrics`` (spec §6): it reads
Prometheus through the daily pipeline's own fetch + aggregate, behind a
~10-minute in-process cache, so its numbers are the daily email's numbers.

Run it with ``heim dashboard`` (uvicorn), or mount ``create_app()`` yourself.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import os
import secrets
import sqlite3
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qsl, urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from heim.config import Config, load_config
from heim.dashboard import format as fmt
from heim.incidents.store import IncidentStore
from heim.metrics.aggregate import aggregate
from heim.metrics.queries import build_window, load_queries
# the daily pipeline's own fetcher: the metrics page must read Prometheus
# through the exact code path the email did, or the numbers would drift
from heim.pipelines.daily import _fetch_query_ranges
from heim.pipelines.queue import enqueue_investigation, enqueue_retry
from heim.pipelines.suppression import mark_false_positive, suppress_fingerprint
from heim.reports.render import _md_to_html

log = logging.getLogger(__name__)

_HERE = Path(__file__).resolve().parent
TEMPLATES_DIR = _HERE / "templates"
STATIC_DIR = _HERE / "static"

#: env var holding the shared password for HTTP basic auth (unset = open)
TOKEN_ENV = "HEIM_DASHBOARD_TOKEN"

#: a daemon that has not recorded a run in this long is "quiet"
DAEMON_FRESH_S = 20 * 60

#: how long a fetched metrics payload is served without touching Prometheus
#: (spec §6: "a ~10-minute in-process cache")
METRICS_TTL_S = 600

STORE_ERROR = ("Store unreadable at {path} — is the daemon running with the "
               "same volume?")

PROM_ERROR = ("Prometheus unreachable at {url} — the numbers here come "
              "straight from it. Check `heim check`.")

#: The dashboard's complete write surface (design spec §5). Anything else —
#: incident lifecycle, investigation rows, run/finding inserts, job claiming —
#: belongs to the daemon alone, so no route may call it.
_ACTION_HELPERS = (
    "enqueue_investigation", "enqueue_retry", "set_approval_decision",
    "set_finding_verdict", "mark_false_positive", "suppress", "unsuppress",
    "set_incident_status",   # only via suppress/unsuppress, mirroring the CLI
)


# --------------------------------------------------------------- data access


class StoreReader:
    """Serialized access to the one store connection.

    Routes are ``async def`` (they run on the event loop) but Starlette may
    still touch us from a portal thread in tests, so every call takes a lock
    and the connection is opened with ``check_same_thread=False``.

    ``read`` issues SELECTs (plus the idempotent ``CREATE TABLE IF NOT EXISTS``
    in ``IncidentStore.__init__``, so a dashboard started before the first
    daemon run still has a schema to read). ``write`` exists for the action
    slice only and is passed nothing but the ``_ACTION_HELPERS`` allow-list.
    """

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.Lock()
        self._store = IncidentStore(self.path, check_same_thread=False)

    def read(self, fn: Callable[[IncidentStore], object]):
        with self._lock:
            return fn(self._store)

    def write(self, fn: Callable[[IncidentStore], object]):
        """Run one action helper against the store (serialized like reads).

        Separate from ``read`` on purpose: grepping for ``reader.write`` shows
        the dashboard's whole write surface in one screen.
        """
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


# ---------------------------------------------------------------- actions
#
# Security posture for the write path (accepted risk, design spec §5): the
# dashboard is a LAN-only page behind optional HTTP basic auth, so these
# same-origin forms carry **no CSRF token**. A token would need minting,
# storing and rotating for a surface whose worst forged POST queues a
# read-only investigation or mutes a fingerprint an operator can unmute in one
# click — not worth the machinery here. If the dashboard is ever published
# beyond the LAN, adding a per-session token to `_ACTION_HELPERS`' forms is the
# first thing to do.


class ActionError(Exception):
    """A rejected action: rendered through the standard error template.

    Bad input is a 400 ("the form said something impossible"), a missing row a
    404 ("there is nothing to act on") — htmx ignores non-2xx bodies, so the
    page the operator is looking at simply stays put.
    """

    def __init__(self, message: str, detail: str = "", status: int = 400):
        super().__init__(message)
        self.message = message
        self.detail = detail
        self.status = status


async def _fields(request: Request) -> dict:
    """Form fields as plain strings.

    Parsed here rather than through FastAPI's ``Form(...)`` /
    ``request.form()``: both pull in python-multipart, and the dashboard only
    ever posts ``application/x-www-form-urlencoded`` — what a plain
    ``<form method="post">`` and htmx both send by default. One less runtime
    dependency for the same three lines, and a file upload or JSON body is
    refused instead of silently half-parsed.

    Fingerprints contain ``|`` and ``/`` (mountpoints), so they travel as form
    fields and never as path segments — nothing here is put into a URL either.
    """
    ctype = (request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if ctype != "application/x-www-form-urlencoded":
        raise ActionError(
            "That action did not arrive as a form.",
            f"Expected application/x-www-form-urlencoded, got {ctype or '(nothing)'}.")
    body = (await request.body()).decode("utf-8", "replace")
    return {k: v for k, v in parse_qsl(body, keep_blank_values=True)}


def _int_field(fields: dict, name: str) -> int:
    raw = str(fields.get(name) or "").strip()
    try:
        value = int(raw)
    except ValueError:
        raise ActionError(f"That action needs a numeric {name.replace('_', ' ')}.",
                          f"The form posted {name}={raw!r}.", 400) from None
    if value <= 0:
        raise ActionError(f"That action needs a real {name.replace('_', ' ')}.",
                          f"The form posted {name}={raw!r}.", 400)
    return value


def _choice_field(fields: dict, name: str, allowed: tuple[str, ...]) -> str:
    value = str(fields.get(name) or "").strip().lower()
    if value not in allowed:
        raise ActionError(
            f"{value or '(nothing)'} is not a valid {name}.",
            f"Expected one of {', '.join(allowed)} — check the form markup.", 400)
    return value


def _text_field(fields: dict, name: str, what: str) -> str:
    value = str(fields.get(name) or "").strip()
    if not value:
        raise ActionError(f"{what} needs a {name.replace('_', ' ')}.",
                          "The form posted an empty value.", 400)
    return value


def _back_to(request: Request, fields: dict) -> str:
    """Where a plain (non-htmx) form POST returns to.

    The ``back`` field first, then the Referer; both are accepted only as
    same-site paths so the redirect can never be pointed off the box.
    """
    for candidate in (fields.get("back"), request.headers.get("referer")):
        text = str(candidate or "").strip()
        if text.startswith("/") and not text.startswith("//"):
            return text
        if text:
            try:
                url = urlsplit(text)
            except ValueError:  # pragma: no cover - urlsplit is very forgiving
                continue
            if url.netloc == request.url.netloc and url.path.startswith("/"):
                return url.path + (f"?{url.query}" if url.query else "")
    return "/"


#: the inline feedback lines (spec §5: mono, --ink-2, no toasts)
QUEUED = "Queued as job #{job} — the daemon picks it up within a few seconds."
APPROVED = "Approved — the daemon starts the investigation within a few seconds."
DECLINED = "Declined — nothing runs; it is re-proposed next run."
CONFIRMED = "Confirmed — kept in the findings history."
UNMUTED = "Unmuted — the pipelines report this fingerprint again."


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
    templates.env.filters.update(mval=fmt.value, mtrend=fmt.trend,
                                 mdelta=fmt.delta)
    # host badge colors are handed out in config order, so the filter is bound
    # to this app's config rather than being a free function on fmt
    host_order = tuple(cfg.hosts)
    templates.env.filters["host_var"] = lambda h: fmt.host_color(h, host_order)
    templates.env.globals.update(duration=fmt.duration, elapsed=fmt.elapsed,
                                 DASH=fmt.DASH)
    app.state.templates = templates

    # ------------------------------------------------------- metrics cache
    #
    # The one piece of state this app owns. Everything else it renders is read
    # from the store on demand; the metrics page instead talks to Prometheus,
    # which is ~90 range queries a page load — so the payload is cached for
    # METRICS_TTL_S and a lock makes concurrent requests share one fetch
    # instead of stampeding. A failed fetch never evicts: the previous payload
    # keeps rendering under its own honest "as of" stamp (spec §6).

    cache: dict = {"payload": None, "fetched_at": None, "error": None}
    cache_lock = asyncio.Lock()

    async def _get_metrics_payload(
        force: bool = False,
    ) -> tuple[dict | None, datetime | None, str | None]:
        async with cache_lock:
            now = datetime.now(tz)
            at = cache["fetched_at"]
            fresh = at is not None and (now - at).total_seconds() < METRICS_TTL_S
            if cache["payload"] is not None and fresh and not force:
                return cache["payload"], at, cache["error"]
            try:
                payload = await _fetch_metrics(cfg, now)
            except Exception as exc:  # network, catalog, aggregate — all fatal
                error = f"{type(exc).__name__}: {exc}"
                log.warning("metrics fetch failed: %s", error)
                cache["error"] = error
                return cache["payload"], cache["fetched_at"], error
            cache.update(payload=payload, fetched_at=now, error=None)
            return payload, now, None

    app.state.get_metrics_payload = _get_metrics_payload

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
        query = request.url.query
        base = {
            "now": now,
            "clock": now.strftime("%H:%M"),
            "env_chip": _env_chip(cfg, now),
            "daemon": _daemon_chip(reader),
            "nav": NAV,
            # where action forms send a no-JS operator back to (spec §5)
            "back": request.url.path + (f"?{query}" if query else ""),
        }
        base.update(ctx)
        return templates.TemplateResponse(request, template, base, status_code=status)

    def partial(request: Request, template: str, **ctx) -> HTMLResponse:
        return templates.TemplateResponse(request, template, ctx)

    def respond(request: Request, fields: dict, template: str, flash: dict, **ctx):
        """The two faces of every action (spec §5).

        Plain form POST → 303 back to the page it came from, so a browser with
        no JS lands on fresh server-rendered HTML. htmx POST → just the
        affected panel, re-rendered with the inline feedback line.
        """
        if request.headers.get("hx-request"):
            return partial(request, template, flash=flash,
                           back=_back_to(request, fields), **ctx)
        return RedirectResponse(_back_to(request, fields), status_code=303)

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

    @app.exception_handler(ActionError)
    async def _action_error(request: Request, exc: ActionError):
        log.info("action refused (%d): %s", exc.status, exc.message)
        return page(request, "error.html", status=exc.status,
                    page_title="not found" if exc.status == 404 else "bad request",
                    message=exc.message, detail=exc.detail)

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
        daily = reader.read(lambda s: s.runs(limit=10, kind="daily"))
        queued = reader.read(lambda s: s.queued_count())
        latest = daily[0] if daily else None
        sev_counts = reader.read(
            lambda s: s.finding_severity_counts([r["id"] for r in daily]))
        run_list = [
            {"run": r, "line": _counts_line(sev_counts.get(r["id"], {}))}
            for r in daily
        ]
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
            {"label": "queued", "value": str(queued),
             "meta": "waiting for the daemon" if queued else "queue empty",
             "href": "/investigations"},
        ]
        return page(
            request, "overview.html", page_title="overview", kpis=kpis,
            latest_run=latest, run_list=run_list,
            investigations=invs[:8], findings=findings[:6],
            empty=not invs and not findings and not open_incidents and not queued,
        )

    @app.get("/investigations", response_class=HTMLResponse)
    async def investigations(request: Request, status: str = "", host: str = "",
                             trigger: str = ""):
        rows, ghosts, filters = _investigation_rows(reader, cfg, status, host, trigger)
        return page(request, "investigations.html", page_title="investigations",
                    rows=rows, ghosts=ghosts, filters=filters,
                    live=_live(rows, ghosts))

    @app.get("/investigations/rows", response_class=HTMLResponse)
    async def investigation_rows(request: Request, status: str = "", host: str = "",
                                 trigger: str = ""):
        rows, ghosts, _ = _investigation_rows(reader, cfg, status, host, trigger)
        return partial(request, "partials/_inv_rows.html", rows=rows, ghosts=ghosts,
                       live=_live(rows, ghosts),
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
            findings=_trigger_findings(row),
            brief_html=_md_to_html(row.get("brief_md") or "") if row.get("brief_md") else "",
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
        # all_rows() is status-blind, so suppressed incidents are listed too —
        # they are exactly the rows an operator needs in order to unmute.
        rows = reader.read(lambda s: s.all_rows(limit=200))
        invs = reader.read(lambda s: s.investigations(limit=200))
        sups = _suppressions(reader)
        by_fp: dict[str, list[dict]] = {}
        for inv in invs:
            by_fp.setdefault(str(inv.get("fingerprint") or ""), []).append(inv)
        for row in rows:
            row["investigations"] = by_fp.get(row["fingerprint"], [])
            row["suppression"] = sups.get(row["fingerprint"])
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

    @app.get("/metrics", response_class=HTMLResponse)
    async def metrics_page(request: Request, host: str = "", category: str = "",
                           refresh: str = ""):
        """The daily email's metric detail, live (spec §6).

        ``refresh=1`` is a GET on purpose: it changes nothing an operator could
        lose — it only skips the TTL — so the quiet REFRESH button is a plain
        form GET that a browser may repeat, bookmark or reload at will.
        """
        payload, fetched_at, error = await _get_metrics_payload(
            force=str(refresh).strip() == "1")
        now = datetime.now(tz)
        return page(
            request, "metrics.html", page_title="metrics",
            metrics=_metrics_view(payload, cfg, host, category, fetched_at, now),
            filters=_metrics_filters(payload, cfg, host, category),
            error=error, prom_error=PROM_ERROR.format(url=cfg.settings.prometheus.url),
        )

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

    # ------------------------------------------------------- action routes
    #
    # Everything below inserts an action row and nothing else: the daemon
    # still decides, runs and records. All of them sit behind the same auth
    # middleware as the pages (it is method-agnostic) and take their subject
    # from form fields only — never from the URL, because a fingerprint
    # carries `|` and `/`.

    @app.post("/actions/investigate")
    async def action_investigate(request: Request):
        fields = await _fields(request)
        fingerprint = str(fields.get("fingerprint") or "").strip()
        incident = reader.read(lambda s: s.incident(fingerprint)) if fingerprint else None
        host = str((incident or {}).get("host") or fields.get("host") or "").strip()
        if not host:
            raise ActionError(
                "An investigation needs a host.",
                "The form posted no host and no known fingerprint to take one from.")
        host_cfg = cfg.hosts.get(host)
        if host_cfg is None:
            raise ActionError(
                f"No host named {host} is configured.",
                "Add a file under config/hosts/ and restart the daemon — it only "
                "investigates hosts it has a profile for.")
        # From an incident: the same subject reconcile would have dispatched.
        # Otherwise a bare manual run — the agent starts from the host itself.
        findings = [_finding_from_incident(incident)] if incident else []
        job_id = reader.write(lambda s: enqueue_investigation(
            s, host=host, host_role=host_cfg.role, fingerprint=fingerprint,
            findings=findings, requested_by="dashboard"))
        flash = {"text": QUEUED.format(job=job_id)}
        if incident:
            return respond(request, fields, "partials/_incident_acts.html", flash,
                           **_incident_ctx(reader, fingerprint))
        return respond(request, fields, "partials/_host_acts.html", flash,
                       host=host)

    @app.post("/actions/retrigger")
    async def action_retrigger(request: Request):
        fields = await _fields(request)
        inv_id = _int_field(fields, "investigation_id")
        job_id = reader.write(lambda s: enqueue_retry(s, inv_id, requested_by="dashboard"))
        if job_id is None:
            raise ActionError(f"No investigation #{inv_id}.",
                              "Nothing to re-run — the list shows everything the "
                              "store has.", 404)
        return respond(request, fields, "partials/_inv_acts.html",
                       {"text": QUEUED.format(job=job_id)},
                       inv=reader.read(lambda s: s.investigation(inv_id)))

    @app.post("/actions/approval")
    async def action_approval(request: Request):
        fields = await _fields(request)
        inv_id = _int_field(fields, "investigation_id")
        decision = _choice_field(fields, "decision", ("approve", "decline"))
        if reader.read(lambda s: s.investigation(inv_id)) is None:
            raise ActionError(f"No investigation #{inv_id}.",
                              "There is nothing waiting for a decision under that "
                              "id.", 404)
        # The daemon's approval wait polls this column and races it against the
        # Telegram button; writing it is the whole of "approve from the web".
        reader.write(lambda s: s.set_approval_decision(inv_id, decision))
        flash = {"text": APPROVED if decision == "approve" else DECLINED}
        return respond(request, fields, "partials/_inv_acts.html", flash,
                       inv=reader.read(lambda s: s.investigation(inv_id)))

    @app.post("/actions/verdict")
    async def action_verdict(request: Request):
        fields = await _fields(request)
        finding_id = _int_field(fields, "finding_id")
        verdict = _choice_field(fields, "verdict", ("confirmed", "false_positive"))
        days = cfg.settings.suppression_days
        if verdict == "false_positive":
            # one call: verdict + suppression + the incident status flip
            row = reader.write(lambda s: mark_false_positive(
                s, finding_id, days=days, now=datetime.now(tz)))
            flash = {"text": _muted_text((row or {}).get("suppression"))}
        else:
            row = reader.write(lambda s: s.set_finding_verdict(finding_id, "confirmed"))
            flash = {"text": CONFIRMED}
        if row is None:
            raise ActionError(f"No finding #{finding_id}.",
                              "Findings are pruned with their run — the history "
                              "page shows what is left.", 404)
        return respond(request, fields, "partials/_verdict.html", flash, f=row)

    @app.post("/actions/mute")
    async def action_mute(request: Request):
        fields = await _fields(request)
        fingerprint = _text_field(fields, "fingerprint", "Muting")
        days = cfg.settings.suppression_days
        if str(fields.get("days") or "").strip():
            days = _int_field(fields, "days")
        res = reader.write(lambda s: suppress_fingerprint(
            s, fingerprint, days=days, reason="marked a false positive from the dashboard",
            now=datetime.now(tz)))
        return respond(request, fields, "partials/_incident_acts.html",
                       {"text": _muted_text(res)},
                       **_incident_ctx(reader, fingerprint))

    @app.post("/actions/unmute")
    async def action_unmute(request: Request):
        fields = await _fields(request)
        fingerprint = _text_field(fields, "fingerprint", "Unmuting")
        if not reader.write(lambda s: s.unsuppress(fingerprint)):
            raise ActionError(f"{fingerprint} is not muted.",
                              "Nothing to lift — the muted rows are the ones with a "
                              "muted pill.", 404)
        # same as `heim incidents unmute`: only a suppressed row goes back to open
        incident = reader.read(lambda s: s.incident(fingerprint))
        if incident and incident.get("status") == "suppressed":
            reader.write(lambda s: s.set_incident_status(fingerprint, "open"))
        return respond(
            request, fields, "partials/_incident_acts.html",
            {"text": UNMUTED},
            **_incident_ctx(reader, fingerprint))

    return app


# ---------------------------------------------------------------- helpers

NAV = [
    {"href": "/", "label": "overview", "icon": "◆"},
    {"href": "/investigations", "label": "investigations", "icon": "▣"},
    {"href": "/incidents", "label": "incidents", "icon": "▲"},
    {"href": "/findings", "label": "findings", "icon": "▤"},
    {"href": "/metrics", "label": "metrics", "icon": "▥"},
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


_SEV_RANK = {"critical": 0, "crit": 0, "warning": 1, "warn": 1, "info": 2, "": 3}


def _counts_line(sev_counts: dict[str, int]) -> str:
    """"4 findings (1 crit · 2 warn)" from grouped severity counts."""
    total = sum(sev_counts.values())
    if not total:
        return ""
    crit = sum(n for s, n in sev_counts.items()
               if _SEV_RANK.get(str(s or "").lower(), 3) == 0)
    warn = sum(n for s, n in sev_counts.items()
               if _SEV_RANK.get(str(s or "").lower(), 3) == 1)
    line = f"{total} finding{'' if total == 1 else 's'}"
    parts = ([f"{crit} crit"] if crit else []) + ([f"{warn} warn"] if warn else [])
    return f"{line} ({' · '.join(parts)})" if parts else line


def _findings_line(findings: list[dict]) -> str:
    """"4 findings (1 crit · 2 warn)" — the run's findings at a glance.

    The overview card is a header line, not a reader: it says how much the run
    found and how bad the worst of it is, and the Findings page says the rest.
    The parenthetical only appears when something needs attention; a run of
    pure info findings is just a count, and a clean run adds nothing at all.
    """
    total = len(findings)
    if not total:
        return ""
    ranks = [_SEV_RANK.get(str(f.get("severity") or "").lower(), 3)
             for f in findings]
    crit, warn = ranks.count(0), ranks.count(1)
    line = f"{total} finding{'' if total == 1 else 's'}"
    parts = ([f"{crit} crit"] if crit else []) + ([f"{warn} warn"] if warn else [])
    return f"{line} ({' · '.join(parts)})" if parts else line


def _live(rows: list[dict], ghosts: list[dict]) -> bool:
    """Poll the table while anything can change under it — a running agent
    appends steps, and a queued job turns into a row of its own."""
    return bool(ghosts) or any(r.get("status") == "running" for r in rows)


def _ghost_rows(reader: StoreReader, host: str) -> list[dict]:
    """Queued jobs, as the ghost rows that sit above the real ones (spec §5).

    Oldest first — that is the order the daemon claims them in.
    """
    jobs = reader.read(lambda s: s.jobs(limit=50, status="queued"))
    ghosts = []
    for job in reversed(list(jobs)):
        payload = job.get("payload") or {}
        ghosts.append({
            "id": int(job.get("id") or 0),
            "host": str(payload.get("host") or ""),
            "fingerprint": str(payload.get("fingerprint") or ""),
            "requested_by": str(job.get("requested_by") or ""),
            "retry_of": int(job.get("retry_of") or 0),
            "created_at": job.get("created_at") or "",
        })
    if host:
        ghosts = [g for g in ghosts if g["host"] == host]
    return ghosts


def _investigation_rows(reader: StoreReader, cfg: Config, status: str, host: str,
                        trigger: str) -> tuple[list[dict], list[dict], dict]:
    """Filtered rows + queued ghost rows + the option lists the filter row renders.

    Status filtering happens in SQL (the store supports it); host/trigger are
    low-cardinality so they are filtered here rather than widening the store's
    read API. Ghost rows are jobs, not investigations, so they only show when
    the status filter would not contradict them (any status, or "queued").
    """
    rows = reader.read(lambda s: s.investigations(limit=200, status=status or None))
    all_rows = reader.read(lambda s: s.investigations(limit=200))
    if host:
        rows = [r for r in rows if r.get("host") == host]
    if trigger:
        rows = [r for r in rows if r.get("trigger") == trigger]
    ghosts = [] if (status and status != "queued") or trigger else _ghost_rows(reader, host)
    statuses = sorted({str(r.get("status") or "") for r in all_rows if r.get("status")})
    hosts = sorted({str(r.get("host") or "") for r in all_rows if r.get("host")}
                   | set(cfg.hosts))
    triggers = sorted({str(r.get("trigger") or "") for r in all_rows if r.get("trigger")}
                      | set(_TRIGGERS))
    if ghosts and "queued" not in statuses:
        statuses = sorted(statuses + ["queued"])
    filters = {
        "status": status, "host": host, "trigger": trigger,
        "statuses": statuses, "hosts": hosts, "triggers": triggers,
        "query": _query(status=status, host=host, trigger=trigger),
    }
    return rows, ghosts, filters


# ------------------------------------------------------------------ metrics
#
# Everything below is the page's presentation of an aggregate payload — the
# same dict the daily email renders. Pure functions: the only I/O is the one
# fetch, and it is the daily pipeline's own helper.

#: flag -> sort rank and back (spec §6: crit, warn, ok, na)
_FLAG_RANK = {"crit": 0, "warn": 1, "ok": 2, "na": 3}
_FLAG_BY_RANK = ["crit", "warn", "ok", "na"]


class MetricsUnavailable(RuntimeError):
    """Every query in the catalog failed — there is nothing to render."""


async def _fetch_metrics(cfg: Config, now: datetime) -> dict:
    """Catalog → Prometheus → aggregate, exactly as ``run_daily`` step 1 does."""
    qdefs = load_queries(cfg.queries_path)
    window = build_window(now)
    results = await _fetch_query_ranges(cfg.settings.prometheus.url, qdefs, window)
    payload = aggregate(results, now=now,
                        instance_host_map=cfg.settings.instance_host_map)["payload"]
    # _fetch_query_ranges degrades per query rather than raising, so a
    # Prometheus that is simply down comes back as a payload of nothing. That
    # is not "everything is fine" — it is the unreachable state, and the page
    # has to say so instead of drawing an empty healthy table.
    if not payload.get("categories"):
        errs = [str(r.get("error")) for r in results if r.get("error")]
        raise MetricsUnavailable(errs[0] if errs else "no series returned")
    return payload


def _host_order(cfg: Config, names) -> list[str]:
    """Configured hosts in config order first, then whatever else reported."""
    known = [h for h in cfg.hosts if h in names]
    return known + sorted(n for n in names if n not in cfg.hosts)


def _row_key(row: dict) -> tuple:
    """Worst flag first, then the biggest mover (spec §6)."""
    return (_FLAG_RANK.get(str(row.get("flag") or ""), 3),
            -abs(row.get("changePct") or 0))


def _cached_for(fetched_at: datetime | None, now: datetime) -> str:
    if fetched_at is None:
        return ""
    mins = int(max((now - fetched_at).total_seconds(), 0) // 60)
    return f"cached {mins}m" if mins else "just fetched"


def _metrics_view(payload: dict | None, cfg: Config, host: str, category: str,
                  fetched_at: datetime | None, now: datetime) -> dict:
    """The header numbers plus per-host, per-category row tables."""
    if not payload:
        return {"hosts": [], "rows": 0, "has_data": False, "as_of": "",
                "cached": "", "overall": "",
                "counts": {"crit": 0, "warn": 0, "na": 0}}
    cats: dict[str, list] = payload.get("categories") or {}
    order = list(cats)  # catalog order — the order the email prints them in
    by_host: dict[str, dict[str, list]] = {}
    for cat in order:
        if category and cat != category:
            continue
        for row in cats[cat]:
            if host and row.get("host") != host:
                continue
            by_host.setdefault(str(row.get("host") or ""), {}) \
                   .setdefault(cat, []).append(row)

    sections, total = [], 0
    for name in _host_order(cfg, by_host):
        groups = by_host[name]
        flat = [r for rows in groups.values() for r in rows]
        total += len(flat)
        worst = min((_FLAG_RANK.get(str(r.get("flag") or ""), 3) for r in flat),
                    default=3)
        sections.append({
            "name": name,
            "flag": _FLAG_BY_RANK[worst],
            "cats": [{"name": c, "rows": sorted(groups[c], key=_row_key)}
                     for c in order if c in groups],
        })
    counts = payload.get("counts") or {}
    return {
        "hosts": sections,
        "rows": total,
        # the header describes the whole payload, so it stays put even when a
        # filter narrows the tables to nothing
        "has_data": True,
        "overall": payload.get("overall") or "",
        "counts": {"crit": int(counts.get("crit") or 0),
                   "warn": int(counts.get("warn") or 0),
                   "na": int(counts.get("naQueries") or 0)},
        "as_of": fetched_at.strftime("%H:%M") if fetched_at else "",
        "cached": _cached_for(fetched_at, now),
    }


def _metrics_filters(payload: dict | None, cfg: Config, host: str,
                     category: str) -> dict:
    """Option lists come from the whole payload, never from the filtered view —
    a filter must always be able to undo itself."""
    cats = (payload or {}).get("categories") or {}
    hosts = set((payload or {}).get("hosts") or [])
    return {
        "host": host, "category": category,
        "hosts": _host_order(cfg, hosts), "categories": list(cats),
        "query": _query(host=host, category=category),
    }


def _finding_from_incident(incident: dict) -> dict:
    """The one-finding brief a stored incident becomes when it is investigated.

    Same shape ``heim investigate --fingerprint`` and ``enqueue_retry`` build,
    so a dashboard-queued job reads exactly like a daily/poller dispatch.
    """
    return {
        "severity": incident.get("severity", ""),
        "host": incident.get("host", ""),
        "metric": incident.get("metric", ""),
        "trend": "",
        "detail": incident.get("description", ""),
        "recommendation": "",
    }


def _suppressions(reader: StoreReader) -> dict:
    return {str(r.get("fingerprint") or ""): r for r in reader.read(lambda s: s.suppressed())}


def _incident_ctx(reader: StoreReader, fingerprint: str) -> dict:
    """Context for the incident action cell after a mute/unmute/queue.

    The incident row may not exist (a fingerprint can be muted before it ever
    opens), so the fingerprint itself is the fallback subject.
    """
    row = reader.read(lambda s: s.incident(fingerprint))
    return {"r": row or {"fingerprint": fingerprint, "host": "", "status": ""},
            "sup": _suppressions(reader).get(fingerprint)}


def _muted_text(suppression: dict | None) -> str:
    """The feedback line for a mute — the verdict half is implied by the pill."""
    until = str((suppression or {}).get("until") or "")
    if not suppression:
        return "Marked false positive — no fingerprint to mute."
    if not until:
        return "Marked false positive — muted for good; unmute it from incidents."
    return f"Marked false positive — muted until {fmt.day(until)}."


def _trigger_findings(row: dict) -> list[dict]:
    """The findings that triggered an investigation, as the card renders them.

    ``findings_json`` is written when the row is created (pipelines/investigate),
    so it is there for a pending or declined run too — an empty list is the
    honest answer for a manual run, not a missing value.
    """
    try:
        parsed = json.loads(row.get("findings_json") or "[]")
    except (TypeError, ValueError):
        log.warning("investigation #%s has unreadable findings_json", row.get("id"))
        return []
    if not isinstance(parsed, list):
        return []
    out = []
    for f in parsed:
        if not isinstance(f, dict):
            continue
        out.append({
            "severity": str(f.get("severity") or ""),
            "metric": str(f.get("metric") or f.get("label") or ""),
            "detail": str(f.get("detail") or f.get("summary") or ""),
        })
    return out


def _outcome_line(row: dict) -> dict | None:
    """The closing line of the detail page (the actions sit in the header)."""
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
        return {"icon": "◷", "cls": "st-warn",
                "text": "Waiting for approval — approve or decline above, or "
                        "answer in Telegram."}
    return None
