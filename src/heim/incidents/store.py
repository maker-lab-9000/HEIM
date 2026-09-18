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
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

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

CREATE INDEX IF NOT EXISTS idx_steps_investigation ON investigation_steps (investigation_id, seq);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings (run_id);
"""

_COLS = [
    "fingerprint", "host", "metric", "severity", "status", "firstSeen",
    "lastSeen", "resolvedAt", "timesSeen", "missedRuns", "description", "investigated",
]

#: Writable columns of ``investigations`` (create/update accept these only —
#: an unknown field is a programming error, not a silent no-op).
_INVESTIGATION_COLS = [
    "fingerprint", "host", "host_role", "agent_name", "model", "trigger", "status",
    "started_at", "finished_at", "input_tokens", "output_tokens", "n_steps",
    "brief_md", "report_md", "incomplete_reason", "outcome",
]

_RUN_COLS = ["run_at", "kind", "overall", "model_used", "duration_s", "counts_json"]

_FINDING_FIELDS = ["host", "metric", "severity", "trend", "summary", "detail", "recommendation"]


class IncidentStore:
    def __init__(self, path: str | Path):
        self._db = sqlite3.connect(str(path))
        self._db.row_factory = sqlite3.Row
        try:
            self._db.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error:  # e.g. an in-memory or read-only FS db — not fatal
            pass
        self._db.executescript(_SCHEMA)
        self._db.commit()

    @staticmethod
    def _to_dict(row: sqlite3.Row) -> dict:
        d = {k: row[k] for k in _COLS}
        d["investigated"] = bool(d["investigated"])
        return d

    def open_rows(self) -> list[dict]:
        cur = self._db.execute("SELECT * FROM incidents WHERE status = 'open' ORDER BY firstSeen")
        return [self._to_dict(r) for r in cur.fetchall()]

    def all_rows(self, limit: int = 200) -> list[dict]:
        cur = self._db.execute("SELECT * FROM incidents ORDER BY lastSeen DESC LIMIT ?", (limit,))
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
    ) -> int:
        cur = self._db.execute(
            """INSERT INTO investigation_steps
               (investigation_id, seq, tool, args_json, result_preview, result_bytes, blocked, duration_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (investigation_id, int(seq), str(tool), str(args_json), str(result_preview),
             int(result_bytes or 0), 1 if blocked else 0, int(duration_ms or 0)),
        )
        self._db.commit()
        return int(cur.lastrowid or 0)

    def investigations(self, limit: int = 50, status: str | None = None) -> list[dict]:
        sql = "SELECT * FROM investigations"
        params: list = []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
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

    def runs(self, limit: int = 50, kind: str | None = None) -> list[dict]:
        sql = "SELECT * FROM runs"
        params: list = []
        if kind:
            sql += " WHERE kind = ?"
            params.append(kind)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
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

    def recent_findings(self, limit: int = 100) -> list[dict]:
        cur = self._db.execute("SELECT * FROM findings ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]

    # ------------------------------------------------------------- internals

    @staticmethod
    def _pick(fields: dict, allowed: list[str], what: str) -> dict:
        unknown = set(fields) - set(allowed)
        if unknown:
            raise ValueError(f"unknown {what} field(s): {', '.join(sorted(unknown))}")
        return {k: v for k, v in fields.items() if k in allowed}

    def close(self) -> None:
        self._db.close()
