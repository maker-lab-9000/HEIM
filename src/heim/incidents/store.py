"""SQLite incident store (replaces the n8n `monitor_incidents` Data Table).

Row schema matches the n8n table so the reconcile/poller ports read and write
the same dict shape: fingerprint, host, metric, severity, status, firstSeen,
lastSeen, resolvedAt, timesSeen, missedRuns, description, investigated.

Beyond incidents the same file holds the *tracking* tables (roadmap §5.1):
``runs`` (one row per daily/poll cycle that did something), ``findings`` (the
analyst's per-host findings, which previously survived only in the email),
``investigations`` and ``investigation_steps`` (per-investigation metadata and
the agent's full tool timeline). WAL is enabled so a second *reader* (CLI,
dashboard) can query while the daemon writes; the daemon stays the sole writer
of these tables.

Roadmap §5.2/§5.4/§5.5 add two *action* tables — ``jobs`` (the crash-safe
investigation queue the dashboard and the CLI insert into and the daemon
drains) and ``suppressions`` (muted fingerprints) — plus the
``investigations.approval_decision`` column used for approvals that arrive
from outside Telegram. These are the one place where a second process writes,
so the connection also sets ``busy_timeout``.

Roadmap §5.6 adds the observability columns — per-step token attribution
(``investigation_steps.input_tokens/output_tokens``), money
(``investigations.cost``, ``runs.input_tokens/output_tokens/cost``) and the
optional full agent transcript (``investigations.transcript_json``) — all
through the same ``_ADDED_COLUMNS`` migration map, plus ``usage_totals()`` for
the ``/telemetry`` exposition. Its eval/replay harness adds
``investigations.replay_of`` (the run this one replays offline) and the
``tool_feedback`` table — the agent's own "this tool would be more useful if…"
lines, latest-per-tool on the dashboard's tool-usage card.

Roadmap §5.7 adds the two housekeeping operations the daemon runs nightly:
``backup_to`` (SQLite's online backup API — WAL-safe, unlike copying the file)
and ``prune`` (retention: finished history out, everything still live in).
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

#: Closed jobs are receipts for the queue UI, not history — they are pruned on
#: the shorter of the retention window and this many days.
JOB_RETENTION_MAX_DAYS = 30

#: Reclaiming space costs a full file rewrite, so only do it when a prune
#: actually freed something worth rewriting for.
VACUUM_AFTER_DELETIONS = 500


def _shift_iso(now_iso: str, days: int) -> str:
    """``now_iso`` minus ``days``, rendered for lexical comparison.

    Keeps the offset of the input (an unparseable value falls back to UTC now,
    so a retention job can never crash on a malformed clock string).
    """
    try:
        base = datetime.fromisoformat(str(now_iso))
    except (TypeError, ValueError):
        base = datetime.now(timezone.utc)
    return (base - timedelta(days=int(days))).isoformat(timespec="milliseconds")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    fingerprint  TEXT PRIMARY KEY,
    host         TEXT NOT NULL DEFAULT '',
    metric       TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'open',
    firstSeen    TEXT NOT NULL DEFAULT '',
    lastSeen     TEXT NOT NULL DEFAULT '',
    resolvedAt   TEXT NOT NULL DEFAULT '',
    timesSeen    INTEGER NOT NULL DEFAULT 0,
    missedRuns   INTEGER NOT NULL DEFAULT 0,
    description  TEXT NOT NULL DEFAULT '',
    investigated INTEGER NOT NULL DEFAULT 0,
    updatedAt    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at      TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL DEFAULT '',        -- 'daily' | 'poll'
    overall     TEXT NOT NULL DEFAULT '',
    model_used  TEXT NOT NULL DEFAULT '',
    duration_s  REAL NOT NULL DEFAULT 0,
    counts_json TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         INTEGER,
    run_at         TEXT NOT NULL DEFAULT '',
    source         TEXT NOT NULL DEFAULT '',     -- 'daily'
    host           TEXT NOT NULL DEFAULT '',
    metric         TEXT NOT NULL DEFAULT '',
    severity       TEXT NOT NULL DEFAULT '',
    trend          TEXT NOT NULL DEFAULT '',
    summary        TEXT NOT NULL DEFAULT '',
    detail         TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    fingerprint    TEXT NOT NULL DEFAULT '',
    verdict        TEXT                          -- NULL | confirmed | false_positive
);

CREATE TABLE IF NOT EXISTS investigations (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint       TEXT NOT NULL DEFAULT '',
    host              TEXT NOT NULL DEFAULT '',
    host_role         TEXT NOT NULL DEFAULT '',
    agent_name        TEXT NOT NULL DEFAULT '',
    model             TEXT NOT NULL DEFAULT '',
    trigger           TEXT NOT NULL DEFAULT '',  -- 'daily' | 'poller' | 'manual'
    status            TEXT NOT NULL DEFAULT '',
    started_at        TEXT NOT NULL DEFAULT '',
    finished_at       TEXT NOT NULL DEFAULT '',
    input_tokens      INTEGER NOT NULL DEFAULT 0,
    output_tokens     INTEGER NOT NULL DEFAULT 0,
    n_steps           INTEGER NOT NULL DEFAULT 0,
    brief_md          TEXT NOT NULL DEFAULT '',
    report_md         TEXT NOT NULL DEFAULT '',
    incomplete_reason TEXT NOT NULL DEFAULT '',
    outcome           TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS investigation_steps (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id INTEGER,
    seq              INTEGER NOT NULL DEFAULT 0,
    tool             TEXT NOT NULL DEFAULT '',
    args_json        TEXT NOT NULL DEFAULT '',
    result_preview   TEXT NOT NULL DEFAULT '',
    result_bytes     INTEGER NOT NULL DEFAULT 0,
    blocked          INTEGER NOT NULL DEFAULT 0,
    duration_ms      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS jobs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    kind             TEXT NOT NULL DEFAULT 'investigate',
    payload_json     TEXT NOT NULL DEFAULT '{}',
    status           TEXT NOT NULL DEFAULT 'queued',  -- queued|running|done|failed|interrupted
    requested_by     TEXT NOT NULL DEFAULT '',        -- 'dashboard' | 'cli'
    retry_of         INTEGER NOT NULL DEFAULT 0,      -- investigation re-run, 0 = none
    investigation_id INTEGER NOT NULL DEFAULT 0,      -- filled when executed
    error            TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT '',
    started_at       TEXT NOT NULL DEFAULT '',
    finished_at      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS tool_feedback (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id INTEGER,
    tool             TEXT NOT NULL DEFAULT '',
    suggestion       TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS suppressions (
    fingerprint TEXT PRIMARY KEY,
    until       TEXT NOT NULL DEFAULT '',   -- '' = forever
    reason      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_steps_investigation ON investigation_steps (investigation_id, seq);
CREATE INDEX IF NOT EXISTS idx_tool_feedback_tool ON tool_feedback (tool, id);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings (run_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs (status, id);
"""

#: Columns added to tables that already exist in deployed databases. Applied
#: idempotently on every connect (PRAGMA table_info → ALTER TABLE ADD COLUMN),
#: which keeps adding a column a one-line change here. SQLite's ADD COLUMN
#: needs a constant default, which every entry below has.
_ADDED_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "investigations": [
        ("retry_of", "INTEGER NOT NULL DEFAULT 0"),
        ("approval_decision", "TEXT NOT NULL DEFAULT ''"),
        # the findings that triggered the run, as the pipeline received them —
        # the provenance the dashboard's "triggered by" card reads
        ("findings_json", "TEXT NOT NULL DEFAULT ''"),
        # §5.6: money spent, in settings.currency. 0 means "not priced" (the
        # model has no entry in settings.model_prices), never "free".
        ("cost", "REAL NOT NULL DEFAULT 0"),
        # §5.6: the agent's full message history, JSON, capped — only written
        # when settings.store_transcripts is on. '' = not collected.
        ("transcript_json", "TEXT NOT NULL DEFAULT ''"),
        # §5.6 eval harness: the investigation this row REPLAYS offline
        # (same brief, same recorded tool results, different model/prompt).
        # 0 = not a replay. Distinct from retry_of, which re-runs for real.
        ("replay_of", "INTEGER NOT NULL DEFAULT 0"),
    ],
    "investigation_steps": [
        # §5.6: usage of the assistant turn that requested this call. When one
        # turn issued several calls the first carries the whole delta and its
        # siblings carry 0, so the column SUMs to the run's real usage.
        ("input_tokens", "INTEGER NOT NULL DEFAULT 0"),
        ("output_tokens", "INTEGER NOT NULL DEFAULT 0"),
    ],
    "runs": [
        # §5.6: the analyst completion's usage and cost, same semantics as
        # the investigations columns above.
        ("input_tokens", "INTEGER NOT NULL DEFAULT 0"),
        ("output_tokens", "INTEGER NOT NULL DEFAULT 0"),
        ("cost", "REAL NOT NULL DEFAULT 0"),
        # The analyst's verdict in words. `overall` alone is a status word;
        # these two are what the run actually said, and until now they lived
        # only in the email. The dashboard's health card reads them.
        ("headline", "TEXT NOT NULL DEFAULT ''"),
        ("summary", "TEXT NOT NULL DEFAULT ''"),
    ],
}

_COLS = [
    "fingerprint", "host", "metric", "severity", "status", "firstSeen",
    "lastSeen", "resolvedAt", "timesSeen", "missedRuns", "description", "investigated",
]

#: Writable columns of ``investigations`` (create/update accept these only —
#: an unknown field is a programming error, not a silent no-op).
_INVESTIGATION_COLS = [
    "fingerprint", "host", "host_role", "agent_name", "model", "trigger", "status",
    "started_at", "finished_at", "input_tokens", "output_tokens", "n_steps",
    "brief_md", "report_md", "incomplete_reason", "outcome", "retry_of",
    "approval_decision", "findings_json", "cost", "transcript_json", "replay_of",
]

_RUN_COLS = ["run_at", "kind", "overall", "model_used", "duration_s", "counts_json",
             "input_tokens", "output_tokens", "cost", "headline", "summary"]

_FINDING_FIELDS = ["host", "metric", "severity", "trend", "summary", "detail", "recommendation"]


class IncidentStore:
    def __init__(self, path: str | Path, *, check_same_thread: bool = True):
        # ``check_same_thread=False`` is used by the read-only dashboard, whose
        # connection is created at startup and read from the server's event
        # loop thread; it serializes its own access (see dashboard/app.py).
        self._db = sqlite3.connect(str(path), check_same_thread=check_same_thread)
        self._db.row_factory = sqlite3.Row
        try:
            self._db.execute("PRAGMA journal_mode=WAL")
            # The dashboard/CLI now *write* (jobs, verdicts, suppressions), so a
            # writer can meet a locked db: wait instead of failing immediately.
            self._db.execute("PRAGMA busy_timeout=5000")
        except sqlite3.Error:  # e.g. an in-memory or read-only FS db — not fatal
            pass
        self._db.executescript(_SCHEMA)
        self._migrate()
        self._db.commit()

    def _migrate(self) -> None:
        """Add any column in ``_ADDED_COLUMNS`` missing from a deployed db."""
        for table, columns in _ADDED_COLUMNS.items():
            have = {r["name"] for r in self._db.execute(f"PRAGMA table_info({table})")}
            for name, decl in columns:
                if name not in have:
                    self._db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

    @staticmethod
    def _to_dict(row: sqlite3.Row) -> dict:
        d = {k: row[k] for k in _COLS}
        d["investigated"] = bool(d["investigated"])
        return d

    def open_rows(self) -> list[dict]:
        cur = self._db.execute("SELECT * FROM incidents WHERE status = 'open' ORDER BY firstSeen")
        return [self._to_dict(r) for r in cur.fetchall()]

    def all_rows(self, limit: int = 200, offset: int = 0) -> list[dict]:
        # fingerprint is the primary key, so it is the tiebreak that makes this
        # order total: a poll batch upserts many incidents with one identical
        # lastSeen, and LIMIT/OFFSET over a tie can repeat or skip a row
        # between windows when the sort has nothing left to decide with.
        cur = self._db.execute(
            "SELECT * FROM incidents ORDER BY lastSeen DESC, fingerprint DESC "
            "LIMIT ? OFFSET ?",
            (limit, offset))
        return [self._to_dict(r) for r in cur.fetchall()]

    def upsert(self, rows: list[dict]) -> None:
        for row in rows:
            values = {k: row.get(k, "") for k in _COLS}
            values["timesSeen"] = int(values.get("timesSeen") or 0)
            values["missedRuns"] = int(values.get("missedRuns") or 0)
            values["investigated"] = 1 if values.get("investigated") in (True, 1, "true") else 0
            self._db.execute(
                f"""INSERT INTO incidents ({', '.join(_COLS)}, updatedAt)
                    VALUES ({', '.join(':' + c for c in _COLS)}, datetime('now'))
                    ON CONFLICT(fingerprint) DO UPDATE SET
                    {', '.join(f'{c} = excluded.{c}' for c in _COLS[1:])},
                    updatedAt = datetime('now')""",
                values,
            )
        self._db.commit()

    def incident(self, fingerprint: str) -> dict | None:
        row = self._db.execute(
            "SELECT * FROM incidents WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return self._to_dict(row) if row is not None else None

    def set_incident_status(self, fingerprint: str, status: str) -> bool:
        """Direct status write (used by the suppression path, which must not go
        through reconcile). Returns True when a row was touched."""
        cur = self._db.execute(
            "UPDATE incidents SET status = ?, updatedAt = datetime('now') WHERE fingerprint = ?",
            (str(status), fingerprint),
        )
        self._db.commit()
        return cur.rowcount > 0

    def set_investigated(self, fingerprint: str, value: bool) -> None:
        self._db.execute(
            "UPDATE incidents SET investigated = ?, updatedAt = datetime('now') WHERE fingerprint = ?",
            (1 if value else 0, fingerprint),
        )
        self._db.commit()

    # ------------------------------------------------------- investigations

    def create_investigation(self, **fields) -> int:
        """Insert an investigation row up front; returns its id."""
        vals = self._pick(fields, _INVESTIGATION_COLS, "investigation")
        cols = list(vals) or ["status"]
        vals.setdefault("status", "")
        cur = self._db.execute(
            f"INSERT INTO investigations ({', '.join(cols)}) "
            f"VALUES ({', '.join(':' + c for c in cols)})",
            vals,
        )
        self._db.commit()
        return int(cur.lastrowid or 0)

    def update_investigation(self, investigation_id: int, **fields) -> None:
        vals = self._pick(fields, _INVESTIGATION_COLS, "investigation")
        if not vals:
            return
        vals["_id"] = investigation_id
        self._db.execute(
            f"UPDATE investigations SET {', '.join(f'{c} = :{c}' for c in vals if c != '_id')} "
            f"WHERE id = :_id",
            vals,
        )
        self._db.commit()

    def add_step(
        self,
        investigation_id: int,
        seq: int,
        tool: str,
        args_json: str = "",
        result_preview: str = "",
        result_bytes: int = 0,
        blocked: bool = False,
        duration_ms: int = 0,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> int:
        cur = self._db.execute(
            """INSERT INTO investigation_steps
               (investigation_id, seq, tool, args_json, result_preview, result_bytes,
                blocked, duration_ms, input_tokens, output_tokens)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (investigation_id, int(seq), str(tool), str(args_json), str(result_preview),
             int(result_bytes or 0), 1 if blocked else 0, int(duration_ms or 0),
             int(input_tokens or 0), int(output_tokens or 0)),
        )
        self._db.commit()
        return int(cur.lastrowid or 0)

    def investigations(self, limit: int = 50, status: str | None = None,
                       offset: int = 0) -> list[dict]:
        sql = "SELECT * FROM investigations"
        params: list = []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        return [dict(r) for r in self._db.execute(sql, params).fetchall()]

    def investigation(self, investigation_id: int) -> dict | None:
        row = self._db.execute(
            "SELECT * FROM investigations WHERE id = ?", (investigation_id,)
        ).fetchone()
        if row is None:
            return None
        out = dict(row)
        out["steps"] = self.steps(investigation_id)
        return out

    def steps(self, investigation_id: int) -> list[dict]:
        cur = self._db.execute(
            "SELECT * FROM investigation_steps WHERE investigation_id = ? ORDER BY seq, id",
            (investigation_id,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            r["blocked"] = bool(r["blocked"])
        return rows

    def usage_totals(self) -> dict:
        """Lifetime tokens and cost across investigations *and* runs (§5.6).

        The two tables are the only places HEIM spends money: the agent loop
        and the daily analyst completion. Summed here rather than in the
        caller so ``/telemetry`` stays one read. Retention pruning means these
        are "what the store still remembers", which is the honest scope for a
        gauge — the docstring of the exposition says so too.
        """
        totals = {"input_tokens": 0, "output_tokens": 0, "cost": 0.0}
        for table in ("investigations", "runs"):
            row = self._db.execute(
                f"SELECT COALESCE(SUM(input_tokens), 0) AS i, "
                f"COALESCE(SUM(output_tokens), 0) AS o, "
                f"COALESCE(SUM(cost), 0) AS c FROM {table}"
            ).fetchone()
            totals["input_tokens"] += int(row["i"] or 0)
            totals["output_tokens"] += int(row["o"] or 0)
            totals["cost"] += float(row["c"] or 0.0)
        return totals

    def tool_usage(self, limit: int = 12) -> list[dict]:
        """Which tools get used, by which agent — one grouped query.

        Grouped by (tool, agent_name, model) rather than by tool alone: the
        same tool behaves differently under a different model, and once there
        is more than one agent (or a model upgrade) "ssh_diagnostic: 412 calls"
        stops being a fact about anything. Busiest first.

        ``tokens`` is the summed per-step attribution (§5.6), so it is 0 for
        rows written before that — the card renders those as an em dash rather
        than as "no tokens used".
        """
        cur = self._db.execute(
            """SELECT s.tool AS tool,
                      i.agent_name AS agent_name,
                      i.model AS model,
                      COUNT(*) AS calls,
                      COALESCE(SUM(s.blocked), 0) AS blocked,
                      COALESCE(AVG(s.duration_ms), 0) AS avg_ms,
                      COALESCE(SUM(s.input_tokens + s.output_tokens), 0) AS tokens
               FROM investigation_steps s
               JOIN investigations i ON i.id = s.investigation_id
               GROUP BY s.tool, i.agent_name, i.model
               ORDER BY calls DESC, s.tool
               LIMIT ?""",
            (int(limit),),
        )
        return [{"tool": str(r["tool"] or ""),
                 "agent_name": str(r["agent_name"] or ""),
                 "model": str(r["model"] or ""),
                 "calls": int(r["calls"] or 0),
                 "blocked": int(r["blocked"] or 0),
                 "avg_ms": float(r["avg_ms"] or 0.0),
                 "tokens": int(r["tokens"] or 0)}
                for r in cur.fetchall()]

    # ------------------------------------------------------- tool feedback

    def add_tool_feedback(self, investigation_id: int, tool: str, suggestion: str,
                          created_at: str = "") -> int:
        """Record one ``tool: suggestion`` line the agent wrote about its toolbox.

        Append-only: the point is the agent's *latest* opinion per tool, and
        keeping the history means a suggestion can be traced to the run that
        produced it. Empty tool or suggestion is a no-op (returns 0).
        """
        tool = str(tool or "").strip()
        suggestion = str(suggestion or "").strip()
        if not tool or not suggestion:
            return 0
        cur = self._db.execute(
            """INSERT INTO tool_feedback (investigation_id, tool, suggestion, created_at)
               VALUES (?, ?, ?, ?)""",
            (int(investigation_id or 0), tool, suggestion, created_at or self._now()),
        )
        self._db.commit()
        return int(cur.lastrowid or 0)

    def latest_tool_feedback(self) -> dict[str, dict]:
        """The newest suggestion per tool, as ``{tool: row}`` — one query.

        Newest by row id (the insert order is the run order), so a tool whose
        feedback the agent stopped repeating keeps showing its last opinion
        until something newer is written.
        """
        cur = self._db.execute(
            """SELECT f.tool AS tool, f.suggestion AS suggestion,
                      f.investigation_id AS investigation_id, f.created_at AS created_at
               FROM tool_feedback f
               JOIN (SELECT tool, MAX(id) AS id FROM tool_feedback GROUP BY tool) last
                 ON last.id = f.id
               ORDER BY f.tool"""
        )
        return {str(r["tool"]): {"tool": str(r["tool"]),
                                 "suggestion": str(r["suggestion"] or ""),
                                 "investigation_id": int(r["investigation_id"] or 0),
                                 "created_at": str(r["created_at"] or "")}
                for r in cur.fetchall()}

    def tool_feedback(self, investigation_id: int) -> list[dict]:
        cur = self._db.execute(
            "SELECT * FROM tool_feedback WHERE investigation_id = ? ORDER BY id",
            (int(investigation_id),),
        )
        return [dict(r) for r in cur.fetchall()]

    def counts_by_status(self) -> dict:
        cur = self._db.execute(
            "SELECT status, COUNT(*) AS n FROM investigations GROUP BY status"
        )
        return {str(r["status"]): int(r["n"]) for r in cur.fetchall()}

    # --------------------------------------------------------- runs/findings

    def insert_run(self, **fields) -> int:
        vals = self._pick(fields, _RUN_COLS, "run")
        cols = list(vals) or ["kind"]
        vals.setdefault("kind", "")
        cur = self._db.execute(
            f"INSERT INTO runs ({', '.join(cols)}) VALUES ({', '.join(':' + c for c in cols)})",
            vals,
        )
        self._db.commit()
        return int(cur.lastrowid or 0)

    def runs(self, limit: int = 50, kind: str | None = None,
             offset: int = 0) -> list[dict]:
        sql = "SELECT * FROM runs"
        params: list = []
        if kind:
            sql += " WHERE kind = ?"
            params.append(kind)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        return [dict(r) for r in self._db.execute(sql, params).fetchall()]

    def insert_findings(
        self,
        run_id: int,
        run_at: str,
        source: str,
        findings: list[dict],
        fingerprints: list[str] | None = None,
    ) -> int:
        """Store the analyst's findings. ``fingerprints[i]`` is the incident
        fingerprint finding ``i`` reconciled into (computed by the caller with
        the pure ``reconcile.fingerprint_for`` helper); a short list is padded
        with ''. Returns the number of rows written."""
        fps = list(fingerprints or [])
        rows = []
        for i, f in enumerate(findings or []):
            vals = {k: str((f or {}).get(k) or "") for k in _FINDING_FIELDS}
            vals["run_id"] = run_id
            vals["run_at"] = run_at
            vals["source"] = source
            vals["fingerprint"] = fps[i] if i < len(fps) else ""
            rows.append(vals)
        if not rows:
            return 0
        cols = ["run_id", "run_at", "source", *_FINDING_FIELDS, "fingerprint"]
        self._db.executemany(
            f"INSERT INTO findings ({', '.join(cols)}) "
            f"VALUES ({', '.join(':' + c for c in cols)})",
            rows,
        )
        self._db.commit()
        return len(rows)

    def finding_severity_counts(self, run_ids: list[int]) -> dict[int, dict[str, int]]:
        """Per-run finding counts by severity, one grouped query (overview run list)."""
        if not run_ids:
            return {}
        marks = ",".join("?" for _ in run_ids)
        cur = self._db.execute(
            f"SELECT run_id, severity, COUNT(*) AS n FROM findings "
            f"WHERE run_id IN ({marks}) GROUP BY run_id, severity",
            [int(r) for r in run_ids],
        )
        out: dict[int, dict[str, int]] = {}
        for row in cur.fetchall():
            out.setdefault(row["run_id"], {})[str(row["severity"] or "")] = row["n"]
        return out

    def recent_findings(self, limit: int = 100, offset: int = 0) -> list[dict]:
        cur = self._db.execute(
            "SELECT * FROM findings ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
        return [dict(r) for r in cur.fetchall()]

    def finding(self, finding_id: int) -> dict | None:
        row = self._db.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return dict(row) if row is not None else None

    def set_finding_verdict(self, finding_id: int, verdict: str) -> dict | None:
        """Set a finding's verdict (confirmed | false_positive | NULL-ish).
        Returns the updated row, or None when there is no such finding."""
        cur = self._db.execute(
            "UPDATE findings SET verdict = ? WHERE id = ?",
            (str(verdict) if verdict else None, int(finding_id)),
        )
        self._db.commit()
        if cur.rowcount == 0:
            return None
        return self.finding(finding_id)

    # ---------------------------------------------------------- jobs (§5.2)

    def enqueue_job(
        self,
        kind: str = "investigate",
        payload: dict | None = None,
        requested_by: str = "",
        retry_of: int = 0,
        created_at: str = "",
    ) -> int:
        cur = self._db.execute(
            """INSERT INTO jobs (kind, payload_json, status, requested_by, retry_of, created_at)
               VALUES (?, ?, 'queued', ?, ?, ?)""",
            (str(kind), json.dumps(payload or {}, ensure_ascii=False, default=str),
             str(requested_by), int(retry_of or 0), created_at or self._now()),
        )
        self._db.commit()
        return int(cur.lastrowid or 0)

    def claim_next_job(self, now: str = "") -> dict | None:
        """Atomically take the oldest queued job (queued → running).

        ``BEGIN IMMEDIATE`` grabs SQLite's write lock before the SELECT, so two
        claimers — even in different processes — can never read the same row as
        queued; the loser waits out ``busy_timeout`` and then sees the row as
        running. Returns the claimed row (with ``payload`` parsed) or None.
        """
        if self._db.in_transaction:
            self._db.commit()
        self._db.execute("BEGIN IMMEDIATE")
        try:
            row = self._db.execute(
                "SELECT * FROM jobs WHERE status = 'queued' ORDER BY id LIMIT 1"
            ).fetchone()
            if row is None:
                self._db.execute("ROLLBACK")
                return None
            job_id = int(row["id"])
            started = now or self._now()
            self._db.execute(
                "UPDATE jobs SET status = 'running', started_at = ? WHERE id = ?",
                (started, job_id),
            )
            self._db.execute("COMMIT")
        except BaseException:
            try:
                self._db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        out = self._job_dict(row)
        out["status"] = "running"
        out["started_at"] = started
        return out

    def finish_job(
        self,
        job_id: int,
        status: str,
        investigation_id: int = 0,
        error: str = "",
        now: str = "",
    ) -> None:
        self._db.execute(
            """UPDATE jobs SET status = ?, investigation_id = ?, error = ?, finished_at = ?
               WHERE id = ?""",
            (str(status), int(investigation_id or 0), str(error or ""),
             now or self._now(), int(job_id)),
        )
        self._db.commit()

    def job(self, job_id: int) -> dict | None:
        row = self._db.execute("SELECT * FROM jobs WHERE id = ?", (int(job_id),)).fetchone()
        return self._job_dict(row) if row is not None else None

    def jobs(self, limit: int = 50, status: str | None = None) -> list[dict]:
        sql = "SELECT * FROM jobs"
        params: list = []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [self._job_dict(r) for r in self._db.execute(sql, params).fetchall()]

    def queued_count(self) -> int:
        row = self._db.execute("SELECT COUNT(*) AS n FROM jobs WHERE status = 'queued'").fetchone()
        return int(row["n"]) if row else 0

    def sweep_interrupted(self, now: str = "") -> int:
        """Crash recovery: nothing can still be running right after a restart.

        Marks ``running`` jobs as ``interrupted`` and the investigations that
        were mid-flight (running / pending_approval) as failed. Returns the
        number of rows touched across both tables.
        """
        stamp = now or self._now()
        touched = self._db.execute(
            "UPDATE jobs SET status = 'interrupted', finished_at = ?, "
            "error = 'interrupted by daemon restart' WHERE status = 'running'",
            (stamp,),
        ).rowcount
        touched += self._db.execute(
            "UPDATE investigations SET status = 'failed', finished_at = ?, "
            "incomplete_reason = 'interrupted by daemon restart' "
            "WHERE status IN ('running', 'pending_approval')",
            (stamp,),
        ).rowcount
        self._db.commit()
        return int(touched)

    # -------------------------------------------------- suppressions (§5.4)

    def suppress(self, fingerprint: str, until: str = "", reason: str = "",
                 created_at: str = "") -> None:
        """Mute a fingerprint. ``until`` == '' means forever; it must be written
        on the same clock that ``active_suppressions`` is later queried with
        (the pipelines use ``Runtime.now_iso``)."""
        self._db.execute(
            """INSERT INTO suppressions (fingerprint, until, reason, created_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(fingerprint) DO UPDATE SET
                 until = excluded.until, reason = excluded.reason,
                 created_at = excluded.created_at""",
            (str(fingerprint), str(until or ""), str(reason or ""),
             created_at or self._now()),
        )
        self._db.commit()

    def unsuppress(self, fingerprint: str) -> bool:
        cur = self._db.execute("DELETE FROM suppressions WHERE fingerprint = ?", (fingerprint,))
        self._db.commit()
        return cur.rowcount > 0

    def suppressed(self) -> list[dict]:
        cur = self._db.execute("SELECT * FROM suppressions ORDER BY created_at DESC, fingerprint")
        return [dict(r) for r in cur.fetchall()]

    def active_suppressions(self, now_iso: str) -> set[str]:
        """Fingerprints muted *right now* — ``until`` empty (forever) or in the
        future relative to ``now_iso`` (ISO-8601 strings compare lexically)."""
        cur = self._db.execute(
            "SELECT fingerprint FROM suppressions WHERE until = '' OR until > ?", (str(now_iso),)
        )
        return {str(r["fingerprint"]) for r in cur.fetchall()}

    # -------------------------------------------- backup & retention (§5.7)

    def backup_to(self, dest_path: str | Path) -> Path:
        """Snapshot the live database to ``dest_path`` (returns the path).

        Uses SQLite's online backup API rather than copying the file: with WAL
        enabled the ``.sqlite3`` file alone is *not* a consistent database
        (committed pages may still live in the ``-wal`` sidecar), so a plain
        ``cp`` of a running store can restore to a stale or torn state.
        ``Connection.backup`` reads through the same connection, so the daemon
        may keep writing while it runs.
        """
        dest = Path(dest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if self._db.in_transaction:      # never snapshot a half-written cycle
            self._db.commit()
        target = sqlite3.connect(str(dest))
        try:
            self._db.backup(target)
        finally:
            target.close()
        return dest

    def prune(self, now_iso: str, retention_days: int) -> dict:
        """Delete history older than ``retention_days``; per-table counts back.

        Deletes **only** what is provably finished:

        - ``incidents`` with ``status='resolved'`` whose ``lastSeen`` is older
        - ``findings`` / ``runs`` by ``run_at``
        - ``investigations`` that actually finished (``finished_at`` non-empty)
          and their ``investigation_steps``
        - ``jobs`` in a terminal state (done/failed/interrupted), on the
          shorter of the retention window and ``JOB_RETENTION_MAX_DAYS`` —
          a closed job is a receipt, not history worth months of disk

        Never touched: suppressions, open/clearing/suppressed incidents,
        unfinished investigations, queued/running jobs. ``retention_days <= 0``
        means "keep forever" and is a no-op. Only non-zero counts are returned,
        so an idle night logs nothing.

        Timestamps are compared lexically (the store's convention, cf.
        ``active_suppressions``): the cutoff is rendered with the same UTC
        offset as ``now_iso``, so mixed-offset rows can be off by the offset
        difference — hours at the edge of a 120-day window, which is fine.
        """
        days = int(retention_days or 0)
        if days <= 0:
            return {}
        cutoff = _shift_iso(now_iso, days)
        job_cutoff = _shift_iso(now_iso, min(days, JOB_RETENTION_MAX_DAYS))

        counts: dict[str, int] = {}

        def _delete(table: str, where: str, params: tuple) -> None:
            n = self._db.execute(f"DELETE FROM {table} WHERE {where}", params).rowcount
            if n > 0:
                counts[table] = counts.get(table, 0) + int(n)

        # children first, while their parents are still selectable
        _delete("investigation_steps",
                "investigation_id IN (SELECT id FROM investigations "
                "WHERE finished_at != '' AND finished_at < ?)", (cutoff,))
        # tool feedback follows its investigation: the card links back to the
        # run that produced the suggestion, and a link into deleted history is
        # worse than an empty line.
        _delete("tool_feedback",
                "investigation_id IN (SELECT id FROM investigations "
                "WHERE finished_at != '' AND finished_at < ?)", (cutoff,))
        _delete("investigations", "finished_at != '' AND finished_at < ?", (cutoff,))
        _delete("incidents", "status = 'resolved' AND lastSeen != '' AND lastSeen < ?", (cutoff,))
        _delete("findings", "run_at != '' AND run_at < ?", (cutoff,))
        _delete("runs", "run_at != '' AND run_at < ?", (cutoff,))
        _delete("jobs",
                "status IN ('done', 'failed', 'interrupted') "
                "AND COALESCE(NULLIF(finished_at, ''), created_at) != '' "
                "AND COALESCE(NULLIF(finished_at, ''), created_at) < ?", (job_cutoff,))
        self._db.commit()

        if sum(counts.values()) > VACUUM_AFTER_DELETIONS:
            # VACUUM cannot run inside a transaction (hence the commit above,
            # and no implicit one after it — sqlite3 only auto-opens for DML).
            # It rebuilds the file, which also checkpoints and truncates the
            # WAL, so the freed pages actually leave the disk.
            self._db.execute("VACUUM")
        return counts

    # ------------------------------------------- approvals from outside TG

    def set_approval_decision(self, investigation_id: int, decision: str) -> None:
        self._db.execute(
            "UPDATE investigations SET approval_decision = ? WHERE id = ?",
            (str(decision or ""), int(investigation_id)),
        )
        self._db.commit()

    def approval_decision(self, investigation_id: int) -> str:
        row = self._db.execute(
            "SELECT approval_decision FROM investigations WHERE id = ?", (int(investigation_id),)
        ).fetchone()
        return str(row["approval_decision"] or "") if row is not None else ""

    # ------------------------------------------------------------- internals

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @staticmethod
    def _job_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        try:
            d["payload"] = json.loads(d.get("payload_json") or "{}")
        except (TypeError, ValueError):
            d["payload"] = {}
        return d

    @staticmethod
    def _pick(fields: dict, allowed: list[str], what: str) -> dict:
        unknown = set(fields) - set(allowed)
        if unknown:
            raise ValueError(f"unknown {what} field(s): {', '.join(sorted(unknown))}")
        return {k: v for k, v in fields.items() if k in allowed}

    def close(self) -> None:
        self._db.close()
