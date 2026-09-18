"""Jobs queue, suppression and re-trigger tests (roadmap §5.2 / §5.4 / §5.5).

Covers the store's action tables (jobs, suppressions, verdicts, the idempotent
column migration), the daemon's queue worker, the pipeline-level suppression
filters (the golden reconcile/poller modules stay untouched, so the filtering
must be provably in the pipelines), the store-side approval decision that lets
a dashboard approve without Telegram, and the CLI mute/unmute handlers.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import sqlite3
import threading
from argparse import Namespace
from datetime import timedelta
from pathlib import Path

import pytest

from heim.agent.runner import AgentResult
from heim.config import load_config
from heim.incidents.store import IncidentStore
from heim.incidents.types import PollerDecision, ReconcileResult
from heim.pipelines.investigate import InvestigationRequest, run_investigation
from heim.pipelines.queue import (
    enqueue_investigation,
    enqueue_retry,
    request_from_payload,
)
from heim.pipelines.suppression import (
    filter_decision,
    filter_incident_events,
    filter_reconcile,
    mark_false_positive,
    suppress_fingerprint,
    suppression_prompt_block,
)
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

SUMMARY_OUTPUT = "## Summary\n\nDisk filled up.\n\n## Root cause\n\nlogs\n\n## Confidence\n\nhigh"


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
    return Runtime(
        config=cfg,
        store=IncidentStore(tmp_path / "rt.sqlite3"),
        dry_run=True,
        out_dir=tmp_path / "out",
    )


def _incident(fingerprint: str, **kw) -> dict:
    row = {"fingerprint": fingerprint, "host": fingerprint.split("|")[0], "metric": "Memory used",
           "severity": "warning", "status": "open", "firstSeen": "2026-09-01T00:00:00",
           "lastSeen": "2026-09-02T00:00:00", "resolvedAt": "", "timesSeen": 3,
           "missedRuns": 0, "description": "mem at 91%", "investigated": False}
    row.update(kw)
    return row


def _stub_agent(monkeypatch, *, output: str = SUMMARY_OUTPUT, raises: Exception | None = None):
    from heim.agent.runner import AgentStep

    async def fake_run_agent(cfg, *, system, user_prompt, tools, on_step=None):
        if raises is not None:
            raise raises
        return AgentResult(output, [AgentStep("stub", {}, "")], 10, 5)

    monkeypatch.setattr("heim.pipelines.investigate.run_agent", fake_run_agent)


# ============================================================ schema/migration


def test_new_tables_and_columns_exist(store):
    names = {r[0] for r in store._db.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"jobs", "suppressions", "incidents", "investigations"} <= names
    cols = {r["name"] for r in store._db.execute("PRAGMA table_info(investigations)")}
    assert {"retry_of", "approval_decision"} <= cols


def test_migration_adds_columns_to_a_legacy_db_and_is_idempotent(tmp_path):
    """A deployed db predates retry_of/approval_decision: ALTER, don't recreate."""
    path = tmp_path / "legacy.sqlite3"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE investigations (id INTEGER PRIMARY KEY AUTOINCREMENT, "
               "host TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '')")
    db.execute("INSERT INTO investigations (host, status) VALUES ('ubuntu-server', 'complete')")
    db.commit()
    db.close()

    s1 = IncidentStore(path)
    cols = {r["name"] for r in s1._db.execute("PRAGMA table_info(investigations)")}
    assert {"retry_of", "approval_decision"} <= cols
    row = s1.investigations()[0]
    assert row["host"] == "ubuntu-server" and row["retry_of"] == 0   # data preserved
    assert row["approval_decision"] == ""
    s1.close()

    s2 = IncidentStore(path)                      # second connect must be a no-op
    assert len(s2.investigations()) == 1
    s2.close()


def test_busy_timeout_is_set(store):
    assert store._db.execute("PRAGMA busy_timeout").fetchone()[0] == 5000


# ================================================================ jobs (§5.2)


def test_enqueue_claim_finish_lifecycle(store):
    job_id = store.enqueue_job("investigate", {"host": "ubuntu-server", "findings": []},
                               requested_by="dashboard", retry_of=7)
    assert job_id > 0 and store.queued_count() == 1

    queued = store.job(job_id)
    assert queued["status"] == "queued" and queued["requested_by"] == "dashboard"
    assert queued["retry_of"] == 7 and queued["created_at"]
    assert queued["payload"] == {"host": "ubuntu-server", "findings": []}
    assert queued["started_at"] == "" and queued["finished_at"] == ""

    claimed = store.claim_next_job()
    assert claimed["id"] == job_id and claimed["status"] == "running" and claimed["started_at"]
    assert claimed["payload"]["host"] == "ubuntu-server"
    assert store.queued_count() == 0
    assert store.claim_next_job() is None            # nothing left to claim

    store.finish_job(job_id, "done", investigation_id=42)
    done = store.job(job_id)
    assert done["status"] == "done" and done["investigation_id"] == 42
    assert done["finished_at"] and done["error"] == ""


def test_claim_is_fifo_and_jobs_listing_filters(store):
    first = store.enqueue_job(payload={"host": "a"}, requested_by="cli")
    second = store.enqueue_job(payload={"host": "b"}, requested_by="cli")
    assert store.claim_next_job()["id"] == first
    assert store.claim_next_job()["id"] == second

    store.finish_job(first, "done")
    assert [j["id"] for j in store.jobs()] == [second, first]       # newest first
    assert [j["id"] for j in store.jobs(status="running")] == [second]
    assert [j["id"] for j in store.jobs(status="done")] == [first]
    assert store.jobs(limit=1)[0]["id"] == second


def test_finish_job_records_the_error(store):
    job_id = store.enqueue_job(payload={"host": "a"})
    store.claim_next_job()
    store.finish_job(job_id, "failed", error="RuntimeError: boom")
    row = store.job(job_id)
    assert row["status"] == "failed" and row["error"] == "RuntimeError: boom"


def test_claim_is_atomic_across_concurrent_claimers(tmp_path):
    """Two connections racing for one job: exactly one wins, the other gets None.

    Separate ``IncidentStore`` objects = separate SQLite connections, i.e. the
    real dashboard-vs-daemon shape rather than a same-connection illusion.
    """
    path = tmp_path / "race.sqlite3"
    writer = IncidentStore(path)
    writer.enqueue_job(payload={"host": "only-one"})

    n = 6
    results: list = []
    lock = threading.Lock()
    start = threading.Barrier(n)

    def claim() -> None:
        s = IncidentStore(path)          # a connection of its own, per thread
        start.wait()
        try:
            got = s.claim_next_job()
        except Exception as exc:                       # pragma: no cover - diagnostic
            got = exc
        with lock:
            results.append(got)
        s.close()

    threads = [threading.Thread(target=claim) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert not any(isinstance(r, Exception) for r in results), results
    winners = [r for r in results if r is not None]
    assert len(winners) == 1, f"{len(winners)} claimers got the same job"
    assert writer.jobs()[0]["status"] == "running"
    writer.close()


def test_many_jobs_are_each_claimed_exactly_once(tmp_path):
    path = tmp_path / "race2.sqlite3"
    writer = IncidentStore(path)
    for i in range(12):
        writer.enqueue_job(payload={"host": f"h{i}"})

    claimed: list[int] = []
    lock = threading.Lock()

    def drain() -> None:
        s = IncidentStore(path)
        while True:
            job = s.claim_next_job()
            if job is None:
                break
            with lock:
                claimed.append(job["id"])
        s.close()

    threads = [threading.Thread(target=drain) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    assert sorted(claimed) == sorted(j["id"] for j in writer.jobs(limit=100))
    assert len(claimed) == len(set(claimed)) == 12
    writer.close()


async def test_claim_next_job_is_safe_from_concurrent_workers(tmp_path):
    """Two async workers (daemon + a second process) racing from the loop."""
    path = tmp_path / "async-race.sqlite3"
    writer = IncidentStore(path)
    writer.enqueue_job(payload={"host": "a"})
    workers = [IncidentStore(path, check_same_thread=False) for _ in range(2)]

    a, b = await asyncio.gather(*(asyncio.to_thread(w.claim_next_job) for w in workers))
    assert [bool(a), bool(b)].count(True) == 1
    for w in workers:
        w.close()
    writer.close()


def test_sweep_interrupted(store):
    done = store.enqueue_job(payload={"host": "done"})
    running = store.enqueue_job(payload={"host": "running"})
    queued = store.enqueue_job(payload={"host": "queued"})
    store.claim_next_job()
    store.finish_job(done, "done")
    store.claim_next_job()                                   # `running` stays running

    inv_running = store.create_investigation(host="a", status="running")
    inv_pending = store.create_investigation(host="b", status="pending_approval")
    inv_complete = store.create_investigation(host="c", status="complete")

    assert store.sweep_interrupted() == 3                    # 1 job + 2 investigations

    assert store.job(running)["status"] == "interrupted"
    assert store.job(running)["error"] == "interrupted by daemon restart"
    assert store.job(running)["finished_at"]
    assert store.job(done)["status"] == "done"
    assert store.job(queued)["status"] == "queued"           # still claimable after a restart

    by_id = {r["id"]: r for r in store.investigations()}
    assert by_id[inv_running]["status"] == "failed"
    assert by_id[inv_running]["incomplete_reason"] == "interrupted by daemon restart"
    assert by_id[inv_pending]["status"] == "failed"
    assert by_id[inv_complete]["status"] == "complete"
    assert store.sweep_interrupted() == 0                    # idempotent


# ================================================= enqueue helpers (§5.2/5.5)


def test_enqueue_investigation_payload(store):
    job_id = enqueue_investigation(
        store, host="ubuntu-server", host_role="guest", fingerprint="u|mem_used|",
        findings=[{"severity": "warning", "detail": "mem"}], requested_by="dashboard",
    )
    job = store.job(job_id)
    assert job["kind"] == "investigate" and job["requested_by"] == "dashboard"
    assert job["retry_of"] == 0
    assert job["payload"] == {
        "host": "ubuntu-server", "host_role": "guest", "fingerprint": "u|mem_used|",
        "findings": [{"severity": "warning", "detail": "mem"}],
    }


def test_enqueue_retry_reuses_the_incident_and_sets_retry_of(store):
    store.upsert([_incident("ubuntu-server|mem_used|", severity="critical")])
    original = store.create_investigation(
        host="ubuntu-server", host_role="guest", fingerprint="ubuntu-server|mem_used|",
        status="complete", trigger="daily",
    )

    job_id = enqueue_retry(store, original, requested_by="dashboard")
    job = store.job(job_id)
    assert job["retry_of"] == original and job["requested_by"] == "dashboard"
    payload = job["payload"]
    assert payload["host"] == "ubuntu-server" and payload["host_role"] == "guest"
    assert payload["fingerprint"] == "ubuntu-server|mem_used|"
    assert payload["findings"][0]["detail"] == "mem at 91%"
    assert payload["findings"][0]["severity"] == "critical"     # from the incident row


def test_enqueue_retry_without_an_incident_row_synthesizes_a_finding(store):
    original = store.create_investigation(host="homelab", host_role="hypervisor", status="complete")
    job = store.job(enqueue_retry(store, original, requested_by="cli"))
    assert job["payload"]["host_role"] == "hypervisor"
    assert job["payload"]["findings"][0]["detail"] == f"re-run of investigation #{original}"


def test_enqueue_retry_of_unknown_investigation_is_none(store):
    assert enqueue_retry(store, 999, requested_by="cli") is None


def test_request_from_payload_shapes(rt):
    req = request_from_payload(
        {"host": "ubuntu-server", "host_role": "guest", "fingerprint": "fp",
         "findings": [{"detail": "x"}]}, rt, retry_of=3)
    assert (req.host, req.host_role, req.fingerprint, req.retry_of) == (
        "ubuntu-server", "guest", "fp", 3)
    assert req.findings == [{"detail": "x"}]

    # a raw reconcile/poller dispatch item goes through request_from_dispatch
    dispatch = request_from_payload(
        {"host": "ubuntu-server", "fingerprint": "fp2", "severity": "critical",
         "metric": "Memory used", "description": "[alert] mem"}, rt, retry_of=5)
    assert dispatch.fingerprint == "fp2" and dispatch.retry_of == 5
    assert dispatch.findings[0]["detail"] == "[alert] mem"
    assert dispatch.host_role == "guest"                       # from the host config


async def test_retry_of_is_persisted_on_the_investigation(rt, monkeypatch):
    _stub_agent(monkeypatch)
    res = await run_investigation(rt, InvestigationRequest(host="ubuntu-server", retry_of=11))
    assert rt.store.investigation(res["id"])["retry_of"] == 11


# ================================================== the daemon queue worker


async def test_queue_worker_runs_a_job_and_links_the_investigation(rt, monkeypatch):
    from heim import daemon

    _stub_agent(monkeypatch)
    job_id = enqueue_investigation(rt.store, host="ubuntu-server", fingerprint="u|mem_used|",
                                   findings=[{"severity": "warning", "detail": "mem"}],
                                   requested_by="dashboard")
    job = rt.store.claim_next_job()
    await daemon.run_job(rt, job)

    row = rt.store.job(job_id)
    assert row["status"] == "done" and row["investigation_id"] > 0
    inv = rt.store.investigation(row["investigation_id"])
    assert inv["status"] == "complete" and inv["host"] == "ubuntu-server"
    assert inv["trigger"] == "dashboard"                 # requested_by=dashboard
    assert inv["fingerprint"] == "u|mem_used|"


async def test_queue_worker_marks_a_retry_and_links_predecessor(rt, monkeypatch):
    from heim import daemon

    _stub_agent(monkeypatch)
    rt.store.upsert([_incident("ubuntu-server|mem_used|")])
    original = rt.store.create_investigation(
        host="ubuntu-server", host_role="guest", fingerprint="ubuntu-server|mem_used|",
        status="complete")
    job_id = enqueue_retry(rt.store, original, requested_by="dashboard")

    await daemon.run_job(rt, rt.store.claim_next_job())

    row = rt.store.job(job_id)
    new_inv = rt.store.investigation(row["investigation_id"])
    assert row["status"] == "done"
    assert new_inv["retry_of"] == original and new_inv["id"] != original
    assert new_inv["fingerprint"] == "ubuntu-server|mem_used|"


async def test_queue_worker_marks_a_crashed_investigation_failed(rt, monkeypatch):
    from heim import daemon

    _stub_agent(monkeypatch, raises=RuntimeError("anthropic down"))
    job_id = enqueue_investigation(rt.store, host="ubuntu-server", requested_by="cli")
    await daemon.run_job(rt, rt.store.claim_next_job())

    row = rt.store.job(job_id)
    assert row["status"] == "failed" and "anthropic down" in row["error"]
    assert row["investigation_id"] > 0                    # still linked for the post-mortem
    assert rt.store.investigation(row["investigation_id"])["status"] == "failed"


async def test_queue_worker_rejects_unknown_kinds(rt):
    from heim import daemon

    job_id = rt.store.enqueue_job(kind="reboot-everything", payload={}, requested_by="cli")
    await daemon.run_job(rt, rt.store.claim_next_job())
    row = rt.store.job(job_id)
    assert row["status"] == "failed" and "unknown job kind" in row["error"]


async def test_queue_worker_loop_drains_and_survives_errors(rt, monkeypatch):
    from heim import daemon

    _stub_agent(monkeypatch)
    calls: list[int] = []
    real_run_job = daemon.run_job

    async def flaky(rt_, job):
        calls.append(job["id"])
        if len(calls) == 1:
            raise RuntimeError("worker blew up")
        await real_run_job(rt_, job)

    monkeypatch.setattr(daemon, "run_job", flaky)
    a = enqueue_investigation(rt.store, host="ubuntu-server", requested_by="cli")
    b = enqueue_investigation(rt.store, host="ubuntu-server", requested_by="cli")

    worker = asyncio.create_task(daemon._queue_worker(rt, poll_seconds=0.01))
    for _ in range(200):
        await asyncio.sleep(0.01)
        if len(calls) >= 2 and rt.store.job(b)["status"] == "done":
            break
    worker.cancel()
    await asyncio.gather(worker, return_exceptions=True)

    assert calls == [a, b]                        # the crash did not kill the loop
    assert rt.store.job(b)["status"] == "done"


# ============================================================ suppressions


def test_active_suppressions_past_future_forever(store):
    now = "2026-09-18T12:00:00.000+02:00"
    store.suppress("h|forever|", until="")
    store.suppress("h|future|", until="2026-10-01T00:00:00.000+02:00")
    store.suppress("h|past|", until="2026-09-01T00:00:00.000+02:00")

    assert store.active_suppressions(now) == {"h|forever|", "h|future|"}
    assert {r["fingerprint"] for r in store.suppressed()} == {
        "h|forever|", "h|future|", "h|past|"}

    assert store.unsuppress("h|forever|") is True
    assert store.unsuppress("h|forever|") is False           # already gone
    assert store.active_suppressions(now) == {"h|future|"}


def test_suppress_upserts_the_reason(store):
    store.suppress("h|x|", until="", reason="first")
    store.suppress("h|x|", until="2030-01-01", reason="second")
    rows = store.suppressed()
    assert len(rows) == 1 and rows[0]["reason"] == "second" and rows[0]["until"] == "2030-01-01"


def test_suppress_fingerprint_sets_the_incident_status(store):
    store.upsert([_incident("ubuntu-server|mem_used|")])
    res = suppress_fingerprint(store, "ubuntu-server|mem_used|", days=7, reason="known noise")
    assert res["incident_updated"] is True and res["until"]
    assert store.incident("ubuntu-server|mem_used|")["status"] == "suppressed"
    assert store.open_rows() == []                  # gone from the open set
    assert res["fingerprint"] in store.active_suppressions(res["until"][:4] + "-01-01")


def test_suppress_fingerprint_forever_and_without_an_incident(store):
    res = suppress_fingerprint(store, "ghost|qid|name", days=0)
    assert res["until"] == "" and res["incident_updated"] is False
    assert store.active_suppressions("2099-01-01") == {"ghost|qid|name"}


def test_mark_false_positive_end_to_end(store):
    store.upsert([_incident("ubuntu-server|mem_used|")])
    run_id = store.insert_run(kind="daily", run_at="2026-09-18T07:00:00")
    store.insert_findings(run_id, "2026-09-18T07:00:00", "daily",
                          [{"host": "ubuntu-server", "metric": "Memory used",
                            "severity": "warning", "summary": "memory climbing"}],
                          ["ubuntu-server|mem_used|"])
    finding_id = store.recent_findings()[0]["id"]

    out = mark_false_positive(store, finding_id, days=30)
    assert out["verdict"] == "false_positive"
    assert store.finding(finding_id)["verdict"] == "false_positive"
    assert store.incident("ubuntu-server|mem_used|")["status"] == "suppressed"
    rows = store.suppressed()
    assert len(rows) == 1 and rows[0]["fingerprint"] == "ubuntu-server|mem_used|"
    assert rows[0]["reason"] == "memory climbing" and rows[0]["until"]
    assert out["suppression"]["until"] == rows[0]["until"]


def test_mark_false_positive_unknown_finding_and_empty_fingerprint(store):
    assert mark_false_positive(store, 404, days=1) is None

    run_id = store.insert_run(kind="daily", run_at="x")
    store.insert_findings(run_id, "x", "daily", [{"host": "h", "summary": "s"}], [])
    fid = store.recent_findings()[0]["id"]
    out = mark_false_positive(store, fid, days=1)
    assert out["verdict"] == "false_positive" and out["suppression"] is None
    assert store.suppressed() == []                  # nothing to mute without a fingerprint


def test_set_finding_verdict_returns_the_row(store):
    run_id = store.insert_run(kind="daily", run_at="x")
    store.insert_findings(run_id, "x", "daily", [{"host": "h", "metric": "m"}], ["fp"])
    fid = store.recent_findings()[0]["id"]
    assert store.set_finding_verdict(fid, "confirmed")["verdict"] == "confirmed"
    assert store.set_finding_verdict(999, "confirmed") is None


def test_mark_false_positive_default_window_is_days_from_now(store, rt):
    store.upsert([_incident("ubuntu-server|mem_used|")])
    run_id = store.insert_run(kind="daily", run_at="x")
    store.insert_findings(run_id, "x", "daily", [{"host": "ubuntu-server"}],
                          ["ubuntu-server|mem_used|"])
    fid = store.recent_findings()[0]["id"]

    now = rt.now()
    mark_false_positive(store, fid, days=rt.config.settings.suppression_days, now=now)
    until = store.suppressed()[0]["until"]
    assert until == (now + timedelta(days=90)).isoformat(timespec="milliseconds")
    assert store.active_suppressions(now.isoformat(timespec="milliseconds")) == {
        "ubuntu-server|mem_used|"}
    assert store.active_suppressions(
        (now + timedelta(days=91)).isoformat(timespec="milliseconds")) == set()


def test_suppression_days_default_in_settings(rt):
    assert rt.config.settings.suppression_days == 90


# -------------------------------------------------------- the pure filters


def test_filter_reconcile_drops_suppressed_rows_and_dispatches():
    rec = ReconcileResult(
        rows_to_write=[{"fingerprint": "a|x|", "host": "a"}, {"fingerprint": "b|y|", "host": "b"}],
        to_investigate=[{"fingerprint": "a|x|", "host": "a"}, {"fingerprint": "b|y|", "host": "b"}],
        summary={"counts": {"new": 2}},
    )
    out, dropped = filter_reconcile(rec, {"a|x|"})
    assert [r["fingerprint"] for r in out.rows_to_write] == ["b|y|"]
    assert [r["fingerprint"] for r in out.to_investigate] == ["b|y|"]
    assert dropped == {"rows": 1, "investigations": 1}
    # the input is left alone (no accidental mutation of the golden output)
    assert len(rec.rows_to_write) == 2
    assert out.summary == rec.summary


def test_filter_reconcile_without_suppressions_is_a_no_op():
    rec = ReconcileResult(rows_to_write=[{"fingerprint": "a|x|"}])
    out, dropped = filter_reconcile(rec, set())
    assert out is rec and dropped == {}


def test_filter_decision_drops_every_channel():
    dec = PollerDecision(
        rows_to_upsert=[{"fingerprint": "a|x|"}, {"fingerprint": "b|y|"}],
        dispatches=[{"fingerprint": "a|x|"}],
        notifications=[{"fingerprint": "a|x|", "text": "boom"}, {"fingerprint": "b|y|"}],
        loki_events=[
            {"event": "incident", "fields": {"fingerprint": "a|x|"}},
            {"event": "incident", "fields": {"fingerprint": "b|y|"}},
        ],
        state_changed=True,
    )
    out, dropped = filter_decision(dec, {"a|x|"})
    assert [r["fingerprint"] for r in out.rows_to_upsert] == ["b|y|"]
    assert out.dispatches == []
    assert [n["fingerprint"] for n in out.notifications] == ["b|y|"]
    assert [e["fields"]["fingerprint"] for e in out.loki_events] == ["b|y|"]
    assert out.state_changed is True
    assert dropped == {"upserts": 1, "dispatches": 1, "notifications": 1, "loki_events": 1}


def test_filter_decision_clears_state_changed_when_everything_was_muted():
    dec = PollerDecision(rows_to_upsert=[{"fingerprint": "a|x|"}], state_changed=True)
    out, _ = filter_decision(dec, {"a|x|"})
    assert out.rows_to_upsert == [] and out.state_changed is False


def test_filter_incident_events_keeps_unfingerprinted_events():
    events = [
        {"event": "finding", "labels": {"host": "a"}, "fields": {"metric": "m"}},
        {"event": "incident", "fields": {"fingerprint": "a|x|"}},
        {"event": "state", "fields": {}},
    ]
    out = filter_incident_events(events, {"a|x|"})
    assert [e["event"] for e in out] == ["finding", "state"]


def test_filter_rows_tolerates_non_dicts():
    from heim.pipelines.suppression import filter_rows

    assert filter_rows(["plain text", {"fingerprint": "a|x|"}], {"a|x|"}) == ["plain text"]
    assert filter_rows(None, {"a|x|"}) == []


def test_suppression_prompt_block_is_bounded_and_readable():
    rows = [{"fingerprint": "ubuntu-server|mem_used|", "reason": "container cache, by design"},
            {"fingerprint": "homelab|drive_temp|sda", "reason": ""}]
    block = suppression_prompt_block(rows)
    lines = block.splitlines()
    assert lines[0].startswith("Known false positives")
    assert lines[1] == "- ubuntu-server · container cache, by design"
    assert lines[2] == "- homelab · drive_temp · sda"        # falls back to the fingerprint

    many = [{"fingerprint": f"h{i}|q|", "reason": f"r{i}"} for i in range(14)]
    capped = suppression_prompt_block(many)
    assert len(capped.splitlines()) == 1 + 10 + 1            # header + 10 + "+4 more"
    assert capped.splitlines()[-1] == "- (+4 more suppressed)"
    assert suppression_prompt_block([]) == ""


# ------------------------------------------------------- pipeline wiring


def _daily_payload(rows: list[dict]) -> dict:
    return {"generatedAt": "2026-09-18T07:00:00.000+02:00", "windowDays": 3,
            "hosts": ["ubuntu-server"], "counts": {"crit": 0, "warn": 1, "naQueries": 0},
            "overall": "warning", "categories": {"Memory": rows}, "topAlerts": []}


async def test_daily_filters_suppressed_and_hints_the_analyst(rt, monkeypatch):
    from heim.incidents.reconcile import fingerprint_for
    from heim.pipelines import daily

    row = {"host": "ubuntu-server", "label": "", "name": "Memory used", "unit": "%",
           "qid": "mem_used", "category": "Memory", "current": 91.0, "avg": 80.0,
           "min": 70.0, "max": 91.0, "day3d": [70.0, 80.0, 91.0], "changePct": 30.0,
           "flag": "warn"}
    payload = _daily_payload([row])
    finding = {"severity": "warning", "host": "ubuntu-server", "metric": "Memory used",
               "trend": "rising", "summary": "memory climbing", "detail": "91%",
               "recommendation": "cap it"}
    analysis = {"overallHealth": "warning", "headline": "h", "executiveSummary": "s",
                "categories": {}, "findings": [finding], "watchlist": []}
    fingerprint = fingerprint_for(finding, [row])

    # the same finding is a known false positive
    rt.store.suppress(fingerprint, until="", reason="container cache, by design")

    prompts: list[str] = []
    emitted: list[dict] = []
    dispatched: list = []

    async def fake_fetch(base, qdefs, window):
        return []

    async def fake_analyst(cfg, system, user):
        prompts.append(user)
        return json.dumps(analysis), "model-x"

    async def fake_dispatch(rt_, items, *, concurrent, trigger="manual"):
        dispatched.append(items)

    async def fake_emit(events):
        emitted.extend(events)

    monkeypatch.setattr(daily, "_fetch_query_ranges", fake_fetch)
    monkeypatch.setattr(daily, "aggregate", lambda *a, **k: {"payload": payload})
    monkeypatch.setattr(daily, "analyst_complete", fake_analyst)
    monkeypatch.setattr(daily, "dispatch_all", fake_dispatch)
    monkeypatch.setattr(rt, "emit_loki", fake_emit)

    res = await daily.run_daily(rt, dispatch_concurrently=False)

    # 1. the incident was never written and never investigated
    assert rt.store.all_rows() == []
    assert dispatched == [] and res["investigations"] == 0
    # 2. no incident Loki event leaked for it (other event types survive)
    assert [e for e in emitted if e.get("event") == "incident"] == []
    assert any(e.get("event") == "finding" for e in emitted)
    # 3. the analyst got the bounded hint on its *user* message
    assert "Known false positives" in prompts[0]
    assert "- ubuntu-server · container cache, by design" in prompts[0]
    # 4. the findings history still records it (verdicts live there)
    assert len(rt.store.recent_findings()) == 1


async def test_daily_does_not_resurrect_a_suppressed_incident_row(rt, monkeypatch):
    """An already-suppressed incident row must not be re-opened or mutated."""
    from heim.incidents.reconcile import fingerprint_for
    from heim.pipelines import daily

    row = {"host": "ubuntu-server", "label": "", "name": "Memory used", "unit": "%",
           "qid": "mem_used", "category": "Memory", "current": 91.0, "avg": 80.0,
           "min": 70.0, "max": 91.0, "day3d": [70.0, 80.0, 91.0], "changePct": 30.0,
           "flag": "warn"}
    payload = _daily_payload([row])
    finding = {"severity": "critical", "host": "ubuntu-server", "metric": "Memory used",
               "trend": "rising", "summary": "memory climbing", "detail": "91%"}
    analysis = {"overallHealth": "warning", "headline": "h", "executiveSummary": "s",
                "categories": {}, "findings": [finding], "watchlist": []}
    fingerprint = fingerprint_for(finding, [row])
    rt.store.upsert([_incident(fingerprint, status="suppressed", severity="warning",
                               description="mem at 91%")])
    rt.store.suppress(fingerprint, until="")

    async def fake_fetch(base, qdefs, window):
        return []

    async def fake_analyst(cfg, system, user):
        return json.dumps(analysis), "model-x"

    async def fake_dispatch(rt_, items, *, concurrent, trigger="manual"):
        pass

    monkeypatch.setattr(daily, "_fetch_query_ranges", fake_fetch)
    monkeypatch.setattr(daily, "aggregate", lambda *a, **k: {"payload": payload})
    monkeypatch.setattr(daily, "analyst_complete", fake_analyst)
    monkeypatch.setattr(daily, "dispatch_all", fake_dispatch)

    await daily.run_daily(rt, dispatch_concurrently=False)

    stored = rt.store.incident(fingerprint)
    assert stored["status"] == "suppressed"          # not re-opened
    assert stored["severity"] == "warning"           # not escalated to critical


async def test_poller_filters_suppressed_fingerprints(rt, monkeypatch):
    from heim.pipelines import poller

    dec = PollerDecision(
        rows_to_upsert=[{"fingerprint": "muted|x|", "host": "a", "metric": "m", "severity": "warning",
                         "status": "open", "firstSeen": "", "lastSeen": "", "resolvedAt": "",
                         "timesSeen": 1, "missedRuns": 0, "description": "[alert] x",
                         "investigated": False},
                        {"fingerprint": "live|y|", "host": "b", "metric": "m", "severity": "warning",
                         "status": "open", "firstSeen": "", "lastSeen": "", "resolvedAt": "",
                         "timesSeen": 1, "missedRuns": 0, "description": "[alert] y",
                         "investigated": False}],
        dispatches=[{"fingerprint": "muted|x|", "host": "a"}],
        notifications=[{"fingerprint": "muted|x|", "text": "🚨"}],
        loki_events=[{"event": "incident", "fields": {"fingerprint": "muted|x|"}}],
        state_changed=True,
    )
    notified: list[str] = []
    emitted: list[dict] = []
    dispatched: list = []

    async def no_alerts(_url):
        return {"status": "success", "data": {"alerts": []}}

    async def fake_dispatch(rt_, items, *, concurrent, trigger="manual"):
        dispatched.append(items)

    async def fake_notify(text):
        notified.append(text)

    async def fake_emit(events):
        emitted.extend(events)

    rt.store.suppress("muted|x|", until="")
    monkeypatch.setattr(poller, "_fetch_alerts", no_alerts)
    monkeypatch.setattr(poller, "diff_and_decide", lambda *a, **k: dec)
    monkeypatch.setattr(poller, "dispatch_all", fake_dispatch)
    monkeypatch.setattr(rt, "notify", fake_notify)
    monkeypatch.setattr(rt, "emit_loki", fake_emit)

    summary = await poller.run_poll(rt, dispatch_concurrently=False)

    assert summary["upserts"] == 1 and summary["dispatches"] == 0
    assert summary["notifications"] == 0 and summary["loki_events"] == 0
    assert [r["fingerprint"] for r in rt.store.all_rows()] == ["live|y|"]
    assert notified == [] and dispatched == []
    assert [e for e in emitted if e.get("event") == "incident"] == []


# ==================================== approvals from outside Telegram (§5.7)


async def _decide_when_pending(rt, decision: str, timeout: float = 3.0) -> int:
    """Wait for a pending_approval row to appear, then write a decision."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        rows = rt.store.investigations(status="pending_approval")
        if rows:
            rt.store.set_approval_decision(rows[0]["id"], decision)
            return int(rows[0]["id"])
        await asyncio.sleep(0.01)
    raise AssertionError("no investigation reached pending_approval")


async def test_store_decision_approves_without_telegram(rt, monkeypatch):
    """Dashboard-only deployment: approvals still gate, the store resolves them."""
    monkeypatch.setattr("heim.pipelines.investigate.APPROVAL_POLL_SECONDS", 0.01)
    _stub_agent(monkeypatch)
    rt.dry_run = False
    rt.telegram = None                                     # no Telegram at all

    task = asyncio.create_task(run_investigation(
        rt, InvestigationRequest(host="ubuntu-server", fingerprint="u|mem_used|")))
    inv_id = await _decide_when_pending(rt, "approve")
    res = await asyncio.wait_for(task, 5)

    assert res is not None and res["id"] == inv_id
    row = rt.store.investigation(inv_id)
    assert row["status"] == "complete" and row["approval_decision"] == "approve"


async def test_store_decision_declines_and_resets_the_dispatch_lock(rt, monkeypatch):
    monkeypatch.setattr("heim.pipelines.investigate.APPROVAL_POLL_SECONDS", 0.01)
    _stub_agent(monkeypatch)
    rt.dry_run = False
    rt.telegram = None
    rt.store.upsert([_incident("ubuntu-server|mem_used|", investigated=True)])

    task = asyncio.create_task(run_investigation(
        rt, InvestigationRequest(host="ubuntu-server", fingerprint="ubuntu-server|mem_used|")))
    inv_id = await _decide_when_pending(rt, "decline")
    assert await asyncio.wait_for(task, 5) is None

    row = rt.store.investigation(inv_id)
    assert row["status"] == "declined" and row["approval_decision"] == "decline"
    assert rt.store.open_rows()[0]["investigated"] is False     # re-proposed next run


async def test_store_decision_beats_a_silent_telegram(rt, monkeypatch):
    """The dashboard answers while Telegram is still long-polling."""
    monkeypatch.setattr("heim.pipelines.investigate.APPROVAL_POLL_SECONDS", 0.01)
    _stub_agent(monkeypatch)
    rt.dry_run = False
    cancelled = asyncio.Event()

    class SilentTelegram:
        """Never answers the approval; answers the later outcome question."""

        def __init__(self):
            self.asked: list[str] = []

        async def ask(self, text, **kw):
            self.asked.append(text)
            if len(self.asked) > 1:                      # the outcome confirm
                return True
            try:
                await asyncio.sleep(3600)                # a human who never taps
            except asyncio.CancelledError:
                cancelled.set()
                raise

    tg = SilentTelegram()
    rt.telegram = tg
    task = asyncio.create_task(run_investigation(rt, InvestigationRequest(host="ubuntu-server")))
    inv_id = await _decide_when_pending(rt, "approve")
    res = await asyncio.wait_for(task, 5)

    assert res is not None
    assert tg.asked, "Telegram was still asked (push stays)"
    assert cancelled.is_set(), "the Telegram wait must be cancelled once the store decided"
    assert rt.store.investigation(inv_id)["status"] == "resolved"


async def test_dry_run_still_auto_approves(rt, monkeypatch):
    _stub_agent(monkeypatch)
    rt.telegram = None
    assert rt.dry_run is True
    res = await asyncio.wait_for(
        run_investigation(rt, InvestigationRequest(host="ubuntu-server")), 5)
    assert res is not None
    assert rt.store.investigation(res["id"])["status"] == "complete"


async def test_approvals_disabled_skips_the_gate(rt, monkeypatch):
    _stub_agent(monkeypatch)
    rt.dry_run = False
    rt.telegram = None
    res = await asyncio.wait_for(
        run_investigation(rt, InvestigationRequest(host="ubuntu-server"),
                          require_approval=False), 5)
    assert res is not None and rt.store.investigation(res["id"])["status"] == "complete"


async def test_approval_wait_times_out_into_declined(rt, monkeypatch):
    monkeypatch.setattr("heim.pipelines.investigate.APPROVAL_POLL_SECONDS", 0.01)
    _stub_agent(monkeypatch)
    rt.dry_run = False
    rt.telegram = None
    rt.config.settings.approvals.approve_timeout_hours = 0.00002   # ~70 ms

    assert await asyncio.wait_for(
        run_investigation(rt, InvestigationRequest(host="ubuntu-server")), 5) is None
    row = rt.store.investigations()[0]
    assert row["status"] == "declined" and row["approval_decision"] == "timeout"


# ==================================================================== CLI


def test_cli_mute_and_unmute(rt, monkeypatch, capsys):
    from heim import cli

    rt.store.upsert([_incident("ubuntu-server|mem_used|")])
    args = Namespace(action="mute", fingerprint="ubuntu-server|mem_used|", all=False,
                     days=5, reason="known noise")
    assert cli._incidents_mute(rt, "mute", args) == 0
    assert "muted ubuntu-server|mem_used|" in capsys.readouterr().out
    assert rt.store.incident("ubuntu-server|mem_used|")["status"] == "suppressed"
    assert rt.store.suppressed()[0]["reason"] == "known noise"

    args = Namespace(action="unmute", fingerprint="ubuntu-server|mem_used|", all=False,
                     days=None, reason="")
    assert cli._incidents_mute(rt, "unmute", args) == 0
    assert rt.store.suppressed() == []
    assert rt.store.incident("ubuntu-server|mem_used|")["status"] == "open"   # restored


def test_cli_mute_uses_the_configured_default_window(rt):
    from heim import cli

    args = Namespace(action="mute", fingerprint="h|q|n", all=False, days=None, reason="")
    assert cli._incidents_mute(rt, "mute", args) == 0
    until = rt.store.suppressed()[0]["until"]
    assert until and until > rt.now_iso()


def test_cli_mute_requires_a_fingerprint_and_unmute_reports_misses(rt, capsys):
    from heim import cli

    args = Namespace(action="mute", fingerprint=None, all=False, days=None, reason="")
    assert cli._incidents_mute(rt, "mute", args) == 2

    args = Namespace(action="unmute", fingerprint="nope", all=False, days=None, reason="")
    assert cli._incidents_mute(rt, "unmute", args) == 1
    assert "was not suppressed" in capsys.readouterr().out


def test_cli_incidents_parsing_stays_backward_compatible():
    """`heim incidents` / `--all` must keep working next to the new verbs."""
    from heim import cli

    parser = cli._build_parser()
    plain = parser.parse_args(["incidents"])
    assert plain.action is None and plain.all is False

    all_ = parser.parse_args(["incidents", "--all"])
    assert all_.action is None and all_.all is True

    mute = parser.parse_args(["incidents", "mute", "h|q|n", "--days", "7"])
    assert (mute.action, mute.fingerprint, mute.days) == ("mute", "h|q|n", 7)

    unmute = parser.parse_args(["incidents", "unmute", "h|q|n"])
    assert (unmute.action, unmute.fingerprint) == ("unmute", "h|q|n")

    jobs = parser.parse_args(["jobs", "--limit", "5"])
    assert jobs.cmd == "jobs" and jobs.limit == 5

    fp_only = parser.parse_args(["investigate", "--fingerprint", "h|q|n"])
    assert fp_only.host is None and fp_only.fingerprint == "h|q|n"


async def test_cli_jobs_listing(rt, monkeypatch, capsys):
    from heim import cli

    enqueue_investigation(rt.store, host="ubuntu-server", requested_by="dashboard")
    monkeypatch.setattr(cli, "build_runtime", lambda **kw: rt, raising=False)
    monkeypatch.setattr("heim.runtime.build_runtime", lambda **kw: rt)

    assert await cli._cmd_jobs(Namespace(limit=10, status=None)) == 0
    out = capsys.readouterr().out
    assert "ubuntu-server" in out and "queued" in out and "dashboard" in out


async def test_cli_investigate_by_fingerprint_builds_from_the_incident(rt, monkeypatch, capsys):
    from heim import cli

    _stub_agent(monkeypatch)
    rt.store.upsert([_incident("ubuntu-server|mem_used|", severity="critical")])
    monkeypatch.setattr("heim.runtime.build_runtime", lambda **kw: rt)

    rc = await cli._cmd_investigate(Namespace(
        host=None, role=None, finding=None, metric="", severity="warning",
        fingerprint="ubuntu-server|mem_used|", no_approval=False, dry_run=True))
    assert rc == 0
    inv = rt.store.investigations()[0]
    assert inv["host"] == "ubuntu-server" and inv["fingerprint"] == "ubuntu-server|mem_used|"
    assert "mem at 91%" in inv["brief_md"]
    assert "investigating ubuntu-server from incident" in capsys.readouterr().out


async def test_cli_investigate_by_unknown_fingerprint(rt, monkeypatch):
    from heim import cli

    monkeypatch.setattr("heim.runtime.build_runtime", lambda **kw: rt)
    rc = await cli._cmd_investigate(Namespace(
        host=None, role=None, finding=None, metric="", severity="warning",
        fingerprint="nope", no_approval=False, dry_run=True))
    assert rc == 1


async def test_cli_investigate_needs_host_or_fingerprint():
    from heim import cli

    rc = await cli._cmd_investigate(Namespace(
        host=None, role=None, finding=None, metric="", severity="warning",
        fingerprint="", no_approval=False, dry_run=True))
    assert rc == 2
