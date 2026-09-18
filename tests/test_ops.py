"""Ops hardening: dead-man's switch, nightly backups, retention (roadmap §5.7).

Three independent safety nets, tested at the level they can actually fail:

- the **switch** must ping after a *completed* poll (including no-op polls),
  stay silent when unconfigured or when the poll raised, and turn any network
  problem into one log line rather than a dead scheduler;
- the **backup** must produce a genuinely openable database (WAL included) and
  rotate to the newest N;
- the **prune** must delete only finished history and never touch anything the
  pipelines still depend on.

Network I/O is faked by monkeypatching ``httpx.AsyncClient`` (respx is not a
dependency of this repo; the same pattern is used for the other channels).
"""
from __future__ import annotations

import logging
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from heim import daemon
from heim.channels import deadman
from heim.config import load_config
from heim.incidents import store as store_mod
from heim.incidents.store import IncidentStore
from heim.runtime import Runtime

ROOT = Path(__file__).resolve().parent.parent

DUMMY_ENV = {
    "HEIM_SERVER_IP": "10.0.0.10",
    "HEIM_PROXMOX_IP": "10.0.0.2",
    "HEIM_HA_IP": "10.0.0.3",
    "HEIM_TELEGRAM_CHAT_ID": "111111111",
    "HEIM_EMAIL_TO": "test@example.com",
    "HEIM_EMAIL_FROM": "test@example.com",
}

NOW = "2026-09-18T12:00:00.000+02:00"


# ----------------------------------------------------------------- fixtures


@pytest.fixture()
def store(tmp_path) -> IncidentStore:
    return IncidentStore(tmp_path / "t.sqlite3")


@pytest.fixture()
def rt(tmp_path, monkeypatch) -> Runtime:
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    cfg.settings.loki = None
    cfg.settings.email = None
    cfg.settings.home_assistant = None
    (tmp_path / "data").mkdir(exist_ok=True)       # the compose ./data volume
    cfg.settings.db_path = str(tmp_path / "data" / "heim.sqlite3")
    return Runtime(
        config=cfg,
        store=IncidentStore(cfg.settings.db_path),
        dry_run=True,
        out_dir=tmp_path / "out",
    )


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "OK"):
        self.status_code = status_code
        self.text = text


def fake_httpx(monkeypatch, *, calls: list, status: int = 200, raises: Exception | None = None):
    """Replace ``httpx.AsyncClient`` for the deadman module."""

    class FakeClient:
        def __init__(self, **kw):
            self.kw = kw

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url):
            calls.append({"url": url, "timeout": self.kw.get("timeout")})
            if raises is not None:
                raise raises
            return FakeResponse(status)

    monkeypatch.setattr(deadman.httpx, "AsyncClient", FakeClient)


def _incident(fingerprint: str, **kw) -> dict:
    row = {"fingerprint": fingerprint, "host": fingerprint.split("|")[0], "metric": "Memory used",
           "severity": "warning", "status": "open", "firstSeen": "2026-01-01T00:00:00.000+02:00",
           "lastSeen": "2026-09-01T00:00:00.000+02:00", "resolvedAt": "", "timesSeen": 3,
           "missedRuns": 0, "description": "mem at 91%", "investigated": False}
    row.update(kw)
    return row


def _iso(days_ago: float) -> str:
    base = datetime.fromisoformat(NOW) - timedelta(days=days_ago)
    return base.isoformat(timespec="milliseconds")


# ============================================================ dead-man switch


async def test_ping_gets_the_url_with_a_timeout(monkeypatch):
    calls: list = []
    fake_httpx(monkeypatch, calls=calls)

    assert await deadman.ping("https://hc-ping.example/uuid") is True
    assert calls == [{"url": "https://hc-ping.example/uuid",
                      "timeout": deadman.PING_TIMEOUT_SECONDS}]
    assert deadman.PING_TIMEOUT_SECONDS == 10.0


async def test_ping_is_disabled_by_an_empty_url(monkeypatch):
    calls: list = []
    fake_httpx(monkeypatch, calls=calls)

    assert await deadman.ping("") is False
    assert calls == []                      # not configured == no I/O at all


async def test_ping_failure_warns_without_raising(monkeypatch, caplog):
    calls: list = []
    fake_httpx(monkeypatch, calls=calls, raises=RuntimeError("connection refused"))

    with caplog.at_level(logging.WARNING, logger="heim.channels.deadman"):
        assert await deadman.ping("https://hc-ping.example/uuid") is False

    assert len(calls) == 1
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.levelno == logging.WARNING
    assert record.exc_info is None          # a warning line, never a traceback
    assert "connection refused" in record.getMessage()


async def test_ping_http_error_warns(monkeypatch, caplog):
    calls: list = []
    fake_httpx(monkeypatch, calls=calls, status=503)

    with caplog.at_level(logging.WARNING, logger="heim.channels.deadman"):
        assert await deadman.ping("https://hc-ping.example/uuid") is False
    assert "503" in caplog.text


# ------------------------------------------------------- the daemon's wiring


async def test_poll_job_pings_after_a_noop_poll(rt, monkeypatch):
    """The switch says "HEIM is polling", so a poll that found nothing pings."""
    rt.config.settings.deadman_url = "https://hc-ping.example/uuid"
    pinged: list[str] = []

    async def empty_poll(rt_, dispatch_concurrently=True):
        return {"upserts": 0, "dispatches": 0}

    async def fake_ping(url, **kw):
        pinged.append(url)
        return True

    monkeypatch.setattr(daemon, "run_poll", empty_poll)
    monkeypatch.setattr(daemon.deadman, "ping", fake_ping)

    await daemon._poll_job(rt)
    assert pinged == ["https://hc-ping.example/uuid"]


async def test_poll_job_does_not_ping_when_the_poll_raised(rt, monkeypatch, caplog):
    rt.config.settings.deadman_url = "https://hc-ping.example/uuid"
    pinged: list[str] = []

    async def broken_poll(rt_, dispatch_concurrently=True):
        raise RuntimeError("prometheus unreachable")

    async def fake_ping(url, **kw):
        pinged.append(url)
        return True

    monkeypatch.setattr(daemon, "run_poll", broken_poll)
    monkeypatch.setattr(daemon.deadman, "ping", fake_ping)

    with caplog.at_level(logging.ERROR, logger="heim.daemon"):
        await daemon._poll_job(rt)          # a failed poll must not kill the job

    assert pinged == []                     # silence IS the signal
    assert "alert poll failed" in caplog.text


async def test_poll_job_ping_failure_never_propagates(rt, monkeypatch):
    rt.config.settings.deadman_url = "https://hc-ping.example/uuid"
    calls: list = []
    fake_httpx(monkeypatch, calls=calls, raises=RuntimeError("dns"))

    async def empty_poll(rt_, dispatch_concurrently=True):
        return {}

    monkeypatch.setattr(daemon, "run_poll", empty_poll)
    await daemon._poll_job(rt)              # would raise if the helper leaked
    assert len(calls) == 1


def test_deadman_url_defaults_to_disabled(rt):
    assert rt.config.settings.deadman_url == ""


# ================================================================== backups


def test_backup_to_produces_an_openable_copy(store, tmp_path):
    store.upsert([_incident("ubuntu-server|mem_used|"), _incident("homelab|cpu|")])
    store.create_investigation(host="ubuntu-server", status="complete")

    dest = store.backup_to(tmp_path / "backups" / "heim-20260918.sqlite3")
    assert dest.exists() and dest.stat().st_size > 0

    copy = sqlite3.connect(dest)
    copy.row_factory = sqlite3.Row
    rows = [dict(r) for r in copy.execute("SELECT * FROM incidents ORDER BY fingerprint")]
    assert [r["fingerprint"] for r in rows] == ["homelab|cpu|", "ubuntu-server|mem_used|"]
    assert rows[1]["description"] == "mem at 91%"
    assert copy.execute("SELECT COUNT(*) FROM investigations").fetchone()[0] == 1
    copy.close()

    # and the snapshot is a real store, not just a file
    reopened = IncidentStore(dest)
    assert len(reopened.all_rows()) == 2
    reopened.close()


def test_backup_captures_writes_still_in_the_wal(tmp_path):
    """A plain file copy could miss these — the backup API must not."""
    path = tmp_path / "live.sqlite3"
    store = IncidentStore(path)
    assert store._db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    store.upsert([_incident("ubuntu-server|mem_used|")])

    dest = store.backup_to(tmp_path / "snap.sqlite3")
    copy = sqlite3.connect(dest)
    assert copy.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1
    copy.close()
    store.close()


def test_backup_to_creates_the_directory(store, tmp_path):
    dest = store.backup_to(tmp_path / "deep" / "nested" / "b.sqlite3")
    assert dest.parent.is_dir()


def test_prune_backups_keeps_the_newest_n(tmp_path):
    for day in range(1, 8):
        (tmp_path / f"heim-202609{day:02d}.sqlite3").write_text("x")
    (tmp_path / "notes.txt").write_text("unrelated")

    removed = daemon.prune_backups(tmp_path, keep=3)

    kept = sorted(p.name for p in tmp_path.glob("heim-*.sqlite3"))
    assert kept == ["heim-20260905.sqlite3", "heim-20260906.sqlite3", "heim-20260907.sqlite3"]
    assert sorted(p.name for p in removed) == [
        "heim-20260901.sqlite3", "heim-20260902.sqlite3", "heim-20260903.sqlite3",
        "heim-20260904.sqlite3"]
    assert (tmp_path / "notes.txt").exists()          # only our own files rotate


def test_prune_backups_is_a_noop_below_the_limit_and_when_disabled(tmp_path):
    for day in (1, 2):
        (tmp_path / f"heim-202609{day:02d}.sqlite3").write_text("x")
    assert daemon.prune_backups(tmp_path, keep=14) == []
    assert daemon.prune_backups(tmp_path, keep=0) == []     # 0 = never rotate, not "wipe"
    assert len(list(tmp_path.glob("heim-*.sqlite3"))) == 2


def test_backups_dir_is_a_sibling_of_the_db(tmp_path):
    assert daemon.backups_dir(tmp_path / "data" / "heim.sqlite3") == tmp_path / "data" / "backups"


def test_run_backup_names_by_date_and_rotates(rt):
    rt.config.settings.backup_keep = 2
    rt.store.upsert([_incident("ubuntu-server|mem_used|")])
    bdir = daemon.backups_dir(rt.config.settings.db_path)
    bdir.mkdir(parents=True, exist_ok=True)
    for day in (1, 2, 3):
        (bdir / f"heim-202601{day:02d}.sqlite3").write_text("old")

    dest = daemon.run_backup(rt)

    assert dest.name == f"heim-{rt.now():%Y%m%d}.sqlite3"
    assert dest.parent == bdir
    names = sorted(p.name for p in bdir.glob("heim-*.sqlite3"))
    assert names == ["heim-20260103.sqlite3", dest.name]     # newest 2, today included
    assert sqlite3.connect(dest).execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1


async def test_backup_job_runs_backup_then_prune(rt, monkeypatch):
    order: list[str] = []
    rt.store.upsert([_incident("ubuntu-server|mem_used|", status="resolved",
                               lastSeen=_iso(400))])

    real_backup = daemon.run_backup

    def spy_backup(rt_):
        order.append("backup")
        return real_backup(rt_)

    real_prune = rt.store.prune

    def spy_prune(now_iso, retention_days):
        order.append("prune")
        return real_prune(now_iso, retention_days)

    monkeypatch.setattr(daemon, "run_backup", spy_backup)
    monkeypatch.setattr(rt.store, "prune", spy_prune)

    await daemon._backup_job(rt)

    assert order == ["backup", "prune"]           # the snapshot predates the deletion
    assert rt.store.all_rows() == []              # the old resolved incident is gone
    snapshot = next(daemon.backups_dir(rt.config.settings.db_path).glob("heim-*.sqlite3"))
    assert sqlite3.connect(snapshot).execute(
        "SELECT COUNT(*) FROM incidents").fetchone()[0] == 1   # ...but survives in the backup


async def test_backup_job_skips_the_prune_when_the_backup_failed(rt, monkeypatch, caplog):
    rt.store.upsert([_incident("ubuntu-server|mem_used|", status="resolved",
                               lastSeen=_iso(400))])
    pruned: list = []

    def boom(rt_):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(daemon, "run_backup", boom)
    monkeypatch.setattr(rt.store, "prune", lambda *a, **k: pruned.append(a) or {})

    with caplog.at_level(logging.ERROR, logger="heim.daemon"):
        await daemon._backup_job(rt)              # never raises into the scheduler

    assert pruned == []                           # never delete what we failed to copy
    assert len(rt.store.all_rows()) == 1
    assert "skipping the retention prune" in caplog.text


async def test_backup_job_survives_a_failing_prune(rt, monkeypatch, caplog):
    def boom(*a, **k):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(rt.store, "prune", boom)
    with caplog.at_level(logging.ERROR, logger="heim.daemon"):
        await daemon._backup_job(rt)
    assert "retention prune failed" in caplog.text
    assert list(daemon.backups_dir(rt.config.settings.db_path).glob("heim-*.sqlite3"))


def test_backup_keep_default(rt):
    assert rt.config.settings.backup_keep == 14


# ================================================================ retention


def _aged_db(store: IncidentStore) -> None:
    """One old + one recent row in every prunable table."""
    old, recent = _iso(400), _iso(3)

    store.upsert([
        _incident("old|resolved|", status="resolved", lastSeen=old),
        _incident("old|open|", status="open", lastSeen=old),
        _incident("old|suppressed|", status="suppressed", lastSeen=old),
        _incident("recent|resolved|", status="resolved", lastSeen=recent),
    ])
    store.suppress("old|suppressed|", until="", reason="known noise", created_at=old)

    for run_at in (old, recent):
        run_id = store.insert_run(kind="daily", run_at=run_at)
        store.insert_findings(run_id, run_at, "daily", [{"host": "h", "metric": "m"}], ["fp"])

    finished_old = store.create_investigation(host="h", status="complete",
                                              started_at=old, finished_at=old)
    store.add_step(finished_old, 1, "ssh_diagnostic", result_preview="df -h")
    store.add_step(finished_old, 2, "prometheus_query", result_preview="up")
    unfinished = store.create_investigation(host="h", status="pending_approval",
                                            started_at=old, finished_at="")
    store.add_step(unfinished, 1, "ssh_diagnostic", result_preview="pending")
    finished_recent = store.create_investigation(host="h", status="complete",
                                                 started_at=recent, finished_at=recent)
    store.add_step(finished_recent, 1, "ha_api", result_preview="{}")

    done = store.enqueue_job(payload={"host": "h"}, created_at=old)
    store.finish_job(done, "done", now=old)
    failed = store.enqueue_job(payload={"host": "h"}, created_at=old)
    store.finish_job(failed, "failed", now=_iso(31))
    store.enqueue_job(payload={"host": "h"}, created_at=old)          # still queued
    running = store.enqueue_job(payload={"host": "h"}, created_at=old)
    store._db.execute("UPDATE jobs SET status = 'running' WHERE id = ?", (running,))
    store._db.commit()
    recent_done = store.enqueue_job(payload={"host": "h"}, created_at=recent)
    store.finish_job(recent_done, "done", now=recent)


def test_prune_deletes_only_finished_history(store):
    _aged_db(store)

    counts = store.prune(NOW, 120)

    # --- incidents: resolved + old only
    assert {r["fingerprint"] for r in store.all_rows()} == {
        "old|open|", "old|suppressed|", "recent|resolved|"}
    # --- suppressions are never touched, even for a deleted incident
    assert [r["fingerprint"] for r in store.suppressed()] == ["old|suppressed|"]
    # --- findings/runs by run_at
    assert len(store.runs()) == 1 and len(store.recent_findings()) == 1
    # --- investigations: finished + old only, with their steps
    kept = store.investigations()
    assert {r["status"] for r in kept} == {"pending_approval", "complete"}
    assert len(kept) == 2
    assert store._db.execute("SELECT COUNT(*) FROM investigation_steps").fetchone()[0] == 2
    # --- jobs: terminal states only, on the 30-day window
    left = store.jobs(limit=50)
    assert sorted(j["status"] for j in left) == ["done", "queued", "running"]

    assert counts == {"incidents": 1, "runs": 1, "findings": 1,
                      "investigations": 1, "investigation_steps": 2, "jobs": 2}


def test_prune_keeps_an_open_incident_of_the_same_age(store):
    store.upsert([_incident("h|resolved|", status="resolved", lastSeen=_iso(400)),
                  _incident("h|open|", status="open", lastSeen=_iso(400)),
                  _incident("h|clearing|", status="clearing", lastSeen=_iso(400))])

    assert store.prune(NOW, 120) == {"incidents": 1}
    assert {r["fingerprint"] for r in store.all_rows()} == {"h|open|", "h|clearing|"}


def test_prune_keeps_an_unfinished_investigation_and_its_steps(store):
    old = _iso(400)
    running = store.create_investigation(host="h", status="running", started_at=old)
    store.add_step(running, 1, "ssh_diagnostic")
    finished = store.create_investigation(host="h", status="complete",
                                          started_at=old, finished_at=old)
    store.add_step(finished, 1, "ssh_diagnostic")

    assert store.prune(NOW, 120) == {"investigations": 1, "investigation_steps": 1}
    assert [r["id"] for r in store.investigations()] == [running]
    assert len(store.steps(running)) == 1


def test_prune_keeps_queued_and_running_jobs(store):
    old = _iso(400)
    store.enqueue_job(payload={}, created_at=old)
    running = store.enqueue_job(payload={}, created_at=old)
    store._db.execute("UPDATE jobs SET status = 'running' WHERE id = ?", (running,))
    interrupted = store.enqueue_job(payload={}, created_at=old)
    store.finish_job(interrupted, "interrupted", now=old)
    store._db.commit()

    assert store.prune(NOW, 120) == {"jobs": 1}
    assert sorted(j["status"] for j in store.jobs()) == ["queued", "running"]


def test_prune_uses_the_shorter_job_window(store):
    """A 120-day retention still reaps a job closed 45 days ago."""
    job = store.enqueue_job(payload={}, created_at=_iso(60))
    store.finish_job(job, "done", now=_iso(45))
    inv = store.create_investigation(host="h", status="complete",
                                     started_at=_iso(60), finished_at=_iso(45))

    assert store.prune(NOW, 120) == {"jobs": 1}          # the investigation is young yet
    assert store.jobs() == []
    assert [r["id"] for r in store.investigations()] == [inv]
    assert store_mod.JOB_RETENTION_MAX_DAYS == 30


def test_prune_job_window_never_exceeds_retention(store):
    """retention_days=7 must not keep jobs for 30 days."""
    job = store.enqueue_job(payload={}, created_at=_iso(20))
    store.finish_job(job, "done", now=_iso(20))
    assert store.prune(NOW, 7) == {"jobs": 1}


def test_prune_with_retention_zero_is_a_noop(store):
    _aged_db(store)
    before = (len(store.all_rows()), len(store.runs()), len(store.investigations()),
              len(store.jobs(limit=50)))

    assert store.prune(NOW, 0) == {}
    assert store.prune(NOW, -1) == {}

    assert (len(store.all_rows()), len(store.runs()), len(store.investigations()),
            len(store.jobs(limit=50))) == before


def test_prune_with_a_ten_year_window_still_reaps_closed_jobs(store):
    """Nothing else is old enough — closed jobs are always on the 30-day cap."""
    _aged_db(store)
    assert store.prune(NOW, 3650) == {"jobs": 2}


def test_prune_tolerates_a_malformed_now(store):
    store.upsert([_incident("h|resolved|", status="resolved", lastSeen=_iso(400))])
    assert store.prune("not-a-timestamp", 120) == {"incidents": 1}


def _trace(store: IncidentStore) -> list[str]:
    """Record the SQL the store actually executes (Connection.execute itself
    is read-only, so the trace callback is the way in)."""
    executed: list[str] = []
    store._db.set_trace_callback(executed.append)
    return executed


def test_prune_vacuums_past_the_threshold(store, monkeypatch):
    monkeypatch.setattr(store_mod, "VACUUM_AFTER_DELETIONS", 10)
    old = _iso(400)
    store.upsert([_incident(f"h|q{i}|", status="resolved", lastSeen=old) for i in range(12)])

    executed = _trace(store)
    assert store.prune(NOW, 120) == {"incidents": 12}
    assert "VACUUM" in executed
    assert store.all_rows() == []


def test_prune_below_the_threshold_does_not_vacuum(store):
    store.upsert([_incident("h|q|", status="resolved", lastSeen=_iso(400))])
    executed = _trace(store)
    store.prune(NOW, 120)
    assert "VACUUM" not in executed
    assert store_mod.VACUUM_AFTER_DELETIONS == 500


def test_prune_of_a_large_batch_vacuums_for_real(store):
    """>500 deletions: the real VACUUM path runs against a WAL db, no raising."""
    old = _iso(400)
    store.upsert([_incident(f"h|q{i}|", status="resolved", lastSeen=old) for i in range(600)])
    counts = store.prune(NOW, 120)
    assert counts == {"incidents": 600}
    assert store.all_rows() == []
    # the store is still usable (and still WAL) after the rewrite
    store.upsert([_incident("h|after|")])
    assert store._db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert len(store.all_rows()) == 1


def test_retention_days_default(rt):
    assert rt.config.settings.retention_days == 120


def test_prune_leaves_rows_without_timestamps_alone(store):
    """A row with an empty timestamp is unknown-age, not infinitely old."""
    store.upsert([_incident("h|noTs|", status="resolved", lastSeen="")])
    store.insert_run(kind="daily", run_at="")
    inv = store.create_investigation(host="h", status="complete", finished_at="")

    assert store.prune(NOW, 120) == {}
    assert len(store.all_rows()) == 1 and len(store.runs()) == 1
    assert [r["id"] for r in store.investigations()] == [inv]


# ------------------------------------------------------------ utc timestamps


def test_prune_matches_utc_stamps_written_by_the_store(store):
    """Store-side ``created_at`` is UTC while ``now_iso`` is local — the
    lexical comparison still has to land on the right side of the window."""
    utc_old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat(timespec="seconds")
    job = store.enqueue_job(payload={}, created_at=utc_old)
    store.finish_job(job, "done", now=utc_old)

    now_local = datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")
    assert store.prune(now_local, 120) == {"jobs": 1}
