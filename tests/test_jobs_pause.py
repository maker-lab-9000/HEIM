"""Run links, incident events and timed job pauses
(spec 2026-11-04-activity-jobs-tools)."""
from __future__ import annotations

import pytest

from heim.incidents.store import IncidentStore
from heim.jobs import (JOB_KEYS, PAUSE_CHOICES, announcements, incident_changes, pause_active,
                       pause_until)

T0 = "2026-11-04T10:00:00+01:00"


@pytest.fixture()
def store(tmp_path):
    return IncidentStore(tmp_path / "s.sqlite3")


# ================================================== store


def test_start_and_finish_agent_run(store):
    rid = store.start_agent_run("daily", T0)
    row = store.agent_runs("daily")[0]
    assert row["id"] == rid and row["finished_at"] == ""
    store.finish_agent_run(rid, "2026-11-04T10:03:00+01:00", False, "boom", {"x": 1})
    row = store.agent_runs("daily")[0]
    assert (row["finished_at"], row["ok"], row["error"], row["detail"]) == (
        "2026-11-04T10:03:00+01:00", False, "boom", {"x": 1})


def test_new_columns_and_tables_migrate_on_old_db(tmp_path):
    db = tmp_path / "old.sqlite3"
    s = IncidentStore(db)
    s._db.execute("ALTER TABLE investigations DROP COLUMN parent_run_id")
    s._db.execute("ALTER TABLE runs DROP COLUMN agent_run_id")
    s._db.execute("ALTER TABLE runs DROP COLUMN input_text")
    s._db.execute("DROP TABLE incident_events")
    s._db.execute("DROP TABLE job_pauses")
    s._db.commit()
    s.close()
    s = IncidentStore(db)
    inv = s.create_investigation(host="h", parent_run_id=7, started_at=T0)
    assert s.investigation(inv)["parent_run_id"] == 7
    rid = s.insert_run(kind="daily", run_at=T0, agent_run_id=3, input_text="payload")
    run = [r for r in s.runs() if r["id"] == rid][0]
    assert (run["agent_run_id"], run["input_text"]) == (3, "payload")
    s.pause_job("backup", "2026-11-04T11:00:00+01:00", set_at=T0)
    assert "backup" in s.job_pauses()
    assert s.add_incident_events(3, T0, [{"fingerprint": "f", "event": "new"}]) == 1


def test_incident_events_round_trip_and_prune(store):
    store.add_incident_events(5, T0, [
        {"fingerprint": "h|q|n", "event": "new", "severity": "warning", "host": "h"},
        {"fingerprint": "h|q|m", "event": "escalated", "severity": "critical", "host": "h"}])
    store.add_incident_events(6, T0, [])
    got = store.incident_events_for([5, 6, 9])
    assert [e["event"] for e in got[5]] == ["new", "escalated"]
    assert got.get(6, []) == [] and got.get(9, []) == []
    assert got[5][1]["severity"] == "critical" and got[5][0]["at"] == T0
    counts = store.prune("2026-12-30T10:00:00+01:00", 0)
    assert counts.get("incident_events") == 2
    assert store.incident_events_for([5]) == {}


def test_pause_resume_rows(store):
    store.pause_job("alert_poller", "2026-11-04T14:00:00+01:00", set_by="dashboard", set_at=T0)
    row = store.job_pauses()["alert_poller"]
    assert (row["until"], row["set_by"], row["announced_start"], row["announced_end"]) == (
        "2026-11-04T14:00:00+01:00", "dashboard", 0, 0)
    store.mark_pause_announced("alert_poller", "start")
    assert store.resume_job("alert_poller", "2026-11-04T11:00:00+01:00") is True
    row = store.job_pauses()["alert_poller"]
    assert row["until"] == "2026-11-04T11:00:00+01:00" and row["announced_start"] == 1
    store.pause_job("alert_poller", "2026-11-04T15:00:00+01:00", set_at=T0)
    row = store.job_pauses()["alert_poller"]
    assert (row["announced_start"], row["announced_end"]) == (0, 0)
    assert store.resume_job("nope", T0) is False


def test_announced_pauses_are_pruned(store):
    store.pause_job("backup", "2026-11-04T11:00:00+01:00", set_at=T0)
    store.mark_pause_announced("backup", "start")
    store.mark_pause_announced("backup", "end")
    store.pause_job("daily", "2026-11-04T11:00:00+01:00", set_at=T0)   # end not announced
    store.prune("2026-11-05T10:00:00+01:00", 0)
    assert set(store.job_pauses()) == {"daily"}


# ================================================== pure


def test_job_keys_and_choices():
    assert JOB_KEYS == ("daily", "alert_poller", "thresholds", "uptime", "security", "backup")
    assert PAUSE_CHOICES == {"1h": 3600, "4h": 14400, "24h": 86400}


def test_pause_active_and_until():
    assert pause_until(T0, "4h") == "2026-11-04T14:00:00+01:00"
    with pytest.raises(ValueError):
        pause_until(T0, "2h")
    row = {"until": "2026-11-04T14:00:00+01:00"}
    assert pause_active(row, T0) is True
    assert pause_active(row, "2026-11-04T14:00:00+01:00") is False
    assert pause_active(None, T0) is False
    # a different offset for the same instant still compares correctly
    assert pause_active(row, "2026-11-04T12:59:00+00:00") is True


def test_announcements():
    later = "2026-11-04T15:00:00+01:00"
    active = {"until": "2026-11-04T14:00:00+01:00", "announced_start": 0, "announced_end": 0}
    assert announcements({"a": active}, T0) == [("a", "start")]
    started = {**active, "announced_start": 1}
    assert announcements({"a": started}, T0) == []
    assert announcements({"a": started}, later) == [("a", "end")]
    assert announcements({"a": active}, later) == [("a", "start"), ("a", "end")]
    done = {**started, "announced_end": 1}
    assert announcements({"a": done}, later) == []


def test_incident_changes_filters_statuses():
    def ev(status, fp="h|q|n"):
        return {"event": "incident", "labels": {"host": "h", "severity": "warning",
                                                "status": status},
                "fields": {"fingerprint": fp}}
    loki = [ev("new"), ev("open"), ev("escalated", "x"), ev("resolved", "y"),
            {"event": "finding", "labels": {"status": "new"}, "fields": {}}]
    assert incident_changes(loki) == [
        {"fingerprint": "h|q|n", "event": "new", "severity": "warning", "host": "h"},
        {"fingerprint": "x", "event": "escalated", "severity": "warning", "host": "h"},
        {"fingerprint": "y", "event": "resolved", "severity": "warning", "host": "h"}]


# ================================================== the daemon obeys (Task 3)

from test_tracking import rt  # noqa: E402,F401  (fixture)

from heim import agents, daemon  # noqa: E402


class Clock:
    def __init__(self, rt_, monkeypatch, iso):
        self.iso = iso
        monkeypatch.setattr(rt_, "now_iso", lambda: self.iso)


def _quiet(rt_, monkeypatch):
    notes, pings, polls = [], [], []

    async def notify(text):
        notes.append(text)

    async def ping(url):
        pings.append(url)

    async def fake_poll(r, dispatch_concurrently=True, skip=frozenset()):
        polls.append(set(skip))
        return {}

    monkeypatch.setattr(rt_, "notify", notify)
    monkeypatch.setattr(daemon.deadman, "ping", ping)
    monkeypatch.setattr(daemon, "run_poll", fake_poll)
    return notes, pings, polls


async def test_paused_half_skips_work_but_ping_still_runs(rt, monkeypatch):  # noqa: F811
    Clock(rt, monkeypatch, T0)
    notes, pings, polls = _quiet(rt, monkeypatch)
    rt.store.pause_job("alert_poller", "2026-11-04T11:00:00+01:00", set_at=T0)
    await daemon._poll_job(rt)
    assert polls == [{"alert_poller"}] and len(pings) == 1
    beat = rt.store.agent_runs("alert_poller")[0]
    assert beat["ok"] and beat["detail"]["paused"] is True
    assert beat["detail"]["until"] == "2026-11-04T11:00:00+01:00"


async def test_poller_skip_really_skips_the_half(rt, monkeypatch):  # noqa: F811
    from heim.pipelines import poller
    called = []

    async def alerts(*a, **k):
        called.append("alerts")
        return {}
    monkeypatch.setattr(poller, "_run_alerts", alerts)
    await poller.run_poll(rt, dispatch_concurrently=False, skip=frozenset({"alert_poller"}))
    assert called == []
    await poller.run_poll(rt, dispatch_concurrently=False)
    assert called == ["alerts"]


async def test_paused_daily_does_not_run(rt, monkeypatch):  # noqa: F811
    Clock(rt, monkeypatch, T0)
    ran = []

    async def fake_daily(r, dispatch_concurrently=True):
        ran.append(1)
        return {}
    monkeypatch.setattr(daemon, "run_daily", fake_daily)
    rt.store.pause_job("daily", "2026-11-04T11:00:00+01:00", set_at=T0)
    await daemon._daily_job(rt)
    assert ran == [] and rt.store.agent_runs("daily")[0]["detail"]["paused"] is True


async def test_announce_start_then_end_once(rt, monkeypatch):  # noqa: F811
    clock = Clock(rt, monkeypatch, T0)
    notes, _pings, _polls = _quiet(rt, monkeypatch)
    rt.store.pause_job("backup", "2026-11-04T11:00:00+01:00", set_at=T0)
    await daemon._poll_job(rt)
    assert notes == ["⏸ HEIM: Backup verifier paused until 11:00 (dashboard)"]
    await daemon._poll_job(rt)
    assert len(notes) == 1
    clock.iso = "2026-11-04T11:05:00+01:00"
    await daemon._poll_job(rt)
    assert notes[-1] == "▶ HEIM: Backup verifier resumed" and len(notes) == 2
    await daemon._poll_job(rt)
    assert len(notes) == 2


async def test_resume_now_and_repause(rt, monkeypatch):  # noqa: F811
    clock = Clock(rt, monkeypatch, T0)
    notes, _p, _q = _quiet(rt, monkeypatch)
    rt.store.pause_job("uptime", "2026-11-04T14:00:00+01:00", set_at=T0)
    await daemon._poll_job(rt)
    clock.iso = "2026-11-04T10:10:00+01:00"
    rt.store.resume_job("uptime", clock.iso)
    await daemon._poll_job(rt)
    rt.store.pause_job("uptime", "2026-11-04T11:10:00+01:00", set_at=clock.iso)
    await daemon._poll_job(rt)
    assert [n.split(" ")[0] for n in notes] == ["⏸", "▶", "⏸"]


async def test_an_announce_failure_never_breaks_the_poll(rt, monkeypatch):  # noqa: F811
    Clock(rt, monkeypatch, T0)
    _notes, pings, _polls = _quiet(rt, monkeypatch)

    async def broken(text):
        raise RuntimeError("telegram down")
    monkeypatch.setattr(rt, "notify", broken)
    rt.store.pause_job("backup", "2026-11-04T11:00:00+01:00", set_at=T0)
    await daemon._poll_job(rt)
    assert len(pings) == 1


def test_off_vs_paused_status(tmp_path):
    spec = agents.AgentSpec(key="uptime", name="Uptime monitor", cadence_s=300,
                            stale_after_s=900, paused=True, scope="")
    st = agents.status_of(spec, [], T0)
    assert (st.state, st.word) == ("off", "Off")
    live = agents.AgentSpec(key="uptime", name="Uptime monitor", cadence_s=300,
                            stale_after_s=900, paused=False, scope="")
    beat = {"started_at": T0, "finished_at": T0, "ok": True,
            "detail": {"paused": True, "until": "2026-11-04T11:00:00+01:00"}}
    # "Paused" follows the pause row in effect, not a skipped run's heartbeat
    st = agents.status_of(live, [beat], T0, paused_until="2026-11-04T11:00:00+01:00")
    assert (st.state, st.word) == ("paused", "Paused")
