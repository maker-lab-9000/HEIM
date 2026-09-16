"""SQLite incident store (replaces the n8n `monitor_incidents` Data Table).

Row schema matches the n8n table so the reconcile/poller ports read and write
the same dict shape: fingerprint, host, metric, severity, status, firstSeen,
lastSeen, resolvedAt, timesSeen, missedRuns, description, investigated.
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
"""

_COLS = [
    "fingerprint", "host", "metric", "severity", "status", "firstSeen",
    "lastSeen", "resolvedAt", "timesSeen", "missedRuns", "description", "investigated",
]


class IncidentStore:
    def __init__(self, path: str | Path):
        self._db = sqlite3.connect(str(path))
        self._db.row_factory = sqlite3.Row
        self._db.execute(_SCHEMA)
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

    def close(self) -> None:
        self._db.close()
