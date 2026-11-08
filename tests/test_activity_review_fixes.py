"""Final-review fixes for Activity, Jobs and Tools (spec 2026-11-04-activity-jobs-tools)."""
from __future__ import annotations

import asyncio

import pytest
from test_jobs_pause import T0, Clock, _quiet
from test_tracking import rt  # noqa: F401  (fixture)

from heim import agents, daemon
from heim.activity import timeline
from heim.jobs import announcements

WEEKLY = agents.AgentSpec(key="security", name="Security audit", cadence_s=604800,
                          stale_after_s=691200, paused=False, scope="")


def beat(at, ok=True, finished=True, **detail):
    return {"id": 1, "agent": "security", "started_at": at, "finished_at": at if finished else "",
            "ok": ok, "error": "", "detail": detail}


# ---------------------------------------------- 1. status follows the pause rows


def test_an_ended_pause_no_longer_reads_paused():
    runs = [beat("2026-11-02T06:00:00+01:00", paused=True, until="2026-11-02T10:00:00+01:00"),
            beat("2026-10-26T06:00:00+01:00")]
    st = agents.status_of(WEEKLY, runs, "2026-11-04T10:00:00+01:00")
    assert st.state == "healthy"


def test_an_active_pause_reads_paused_before_the_slot():
    runs = [beat("2026-11-02T06:00:00+01:00")]
    st = agents.status_of(WEEKLY, runs, T0, paused_until="2026-11-04T14:00:00+01:00")
    assert (st.state, st.word) == ("paused", "Paused")


def test_paused_beats_do_not_hide_staleness():
    daily = agents.AgentSpec(key="daily", name="Daily analysis", cadence_s=43200,
                             stale_after_s=46800, paused=False, scope="")
    runs = [{**beat("2026-11-01T07:00:00+01:00", paused=True), "agent": "daily"}]
    st = agents.status_of(daily, runs, "2026-11-04T10:00:00+01:00")
    assert st.state == "stale"


def test_jobs_page_and_overview_overlay_an_active_pause(tmp_path, monkeypatch):
    from test_overview_console import _cards, _client, _healthy_agents

    def seed(s):
        _healthy_agents(s)
        s.pause_job("backup", "2099-01-01T00:00:00+00:00")
    with _client(tmp_path, monkeypatch, seed) as c:
        assert "1 paused: Backup verifier" in _cards(c.get("/").text)["Agent coverage"]
        row = c.get("/jobs").text.split("Backup verifier", 1)[1].split("</tr>", 1)[0]
        assert "</span>Paused</span>" in row


# ------------------------------------- 2. open heartbeats: running, then closed


def test_an_open_heartbeat_reads_running():
    st = agents.status_of(WEEKLY, [beat(T0, finished=False)], T0)
    assert (st.state, st.word) == ("running", "Running")
    assert [n["word"] for n in timeline([beat(T0, finished=False)], {}, [], {}, {})] == ["Running"]
    assert agents.run_strip([beat(T0, finished=False)], 604800, T0) == []


def test_startup_sweep_closes_open_heartbeats(rt, monkeypatch):  # noqa: F811
    rid = rt.store.start_agent_run("daily", T0)
    monkeypatch.setattr(rt, "notify", lambda text: asyncio.sleep(0))
    asyncio.run(daemon._sweep_and_notify(rt))
    row = rt.store.agent_runs("daily")[0]
    assert row["id"] == rid and row["finished_at"] and not row["ok"]
    assert "restart" in row["error"]


async def test_a_cancelled_job_closes_its_heartbeat(rt, monkeypatch):  # noqa: F811
    async def cancelled(r, dispatch_concurrently=True):
        raise asyncio.CancelledError()
    monkeypatch.setattr(daemon, "run_daily", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await daemon._daily_job(rt)
    row = rt.store.agent_runs("daily")[0]
    assert row["finished_at"] and not row["ok"] and "cancel" in row["error"]


# ------------------------------------------------ 3. paused runs merge on the timeline


def test_paused_runs_merge():
    beats = [{"id": i, "agent": "alert_poller", "ok": True, "error": "",
              "started_at": f"2026-11-04T07:{55 - 5 * i:02d}:00+01:00",
              "finished_at": f"2026-11-04T07:{55 - 5 * i:02d}:00+01:00",
              "detail": {"paused": True, "until": "2026-11-04T09:00:00+01:00"}}
             for i in range(1, 8)]
    nodes = timeline(beats, {}, [], {}, {})
    assert len(nodes) == 1 and nodes[0]["count"] == 7 and nodes[0]["word"] == "Paused"
    assert "paused" in nodes[0]["text"] and "7 runs" in nodes[0]["text"]


# ----------------------------------- 4. resume then re-pause within one poll interval


def test_resume_then_repause_before_a_cycle_still_owes_the_end(rt):  # noqa: F811
    s = rt.store
    s.pause_job("daily", "2026-11-04T11:00:00+01:00", set_at=T0)
    s.mark_pause_announced("daily", "start")
    s.resume_job("daily", "2026-11-04T10:05:00+01:00")
    s.pause_job("daily", "2026-11-04T14:07:00+01:00", set_at="2026-11-04T10:07:00+01:00")
    due = announcements(s.job_pauses(), "2026-11-04T10:08:00+01:00")
    assert due == [("daily", "end"), ("daily", "start")]
    s.mark_pause_announced("daily", "end")
    s.mark_pause_announced("daily", "start")
    assert announcements(s.job_pauses(), "2026-11-04T10:09:00+01:00") == []


async def test_daemon_sends_resumed_then_paused(rt, monkeypatch):  # noqa: F811
    clock = Clock(rt, monkeypatch, T0)
    notes, _p, _q = _quiet(rt, monkeypatch)
    rt.store.pause_job("uptime", "2026-11-04T11:00:00+01:00", set_at=T0)
    await daemon._poll_job(rt)
    clock.iso = "2026-11-04T10:05:00+01:00"
    rt.store.resume_job("uptime", clock.iso)
    rt.store.pause_job("uptime", "2026-11-04T12:05:00+01:00", set_at=clock.iso)
    await daemon._poll_job(rt)
    assert [n.split(" ")[0] for n in notes] == ["⏸", "▶", "⏸"]


# ------------------------------------ 5. a failed Telegram send is retried


async def test_a_failed_telegram_send_is_retried_next_cycle(rt, monkeypatch):  # noqa: F811
    Clock(rt, monkeypatch, T0)
    _notes, _p, _q = _quiet(rt, monkeypatch)
    sent, fail = [], {"on": True}

    class FlakyTelegram:
        async def send(self, text, **kw):
            if fail["on"]:
                raise RuntimeError("telegram down")
            sent.append(text)
            return 1

        async def notify(self, text):          # the real one swallows errors
            try:
                await self.send(text)
            except Exception:
                pass

    rt.telegram = FlakyTelegram()
    rt.dry_run = False
    rt.store.pause_job("backup", "2026-11-04T11:00:00+01:00", set_at=T0)
    await daemon._poll_job(rt)
    assert sent == [] and rt.store.job_pauses()["backup"]["announced_start"] == 0
    fail["on"] = False
    await daemon._poll_job(rt)
    assert len(sent) == 1 and sent[0].startswith("⏸")
