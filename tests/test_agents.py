"""Heartbeats: the agent_runs table, the pure agent model, daemon recording."""
from __future__ import annotations

import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from heim import agents, daemon
from heim.agents import AgentSpec, AgentStatus
from heim.config import load_config
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

NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
NOW_ISO = NOW.isoformat()


def ago(seconds: float) -> str:
    return (NOW - timedelta(seconds=seconds)).isoformat()


def run(seconds_ago: float, ok: bool = True, error: str = "") -> dict:
    return {"agent": "alert_poller", "started_at": ago(seconds_ago),
            "finished_at": ago(seconds_ago), "ok": ok, "error": error, "detail": {}}


def spec(**kw) -> AgentSpec:
    base = dict(key="alert_poller", name="Alert poller", cadence_s=300, stale_after_s=900,
                paused=False, scope="")
    base.update(kw)
    return AgentSpec(**base)


def status(key: str, state: str) -> AgentStatus:
    return AgentStatus(key=key, state=state, word="", lamp="", last_run_at="", last_ok_at="",
                       last_error="", last_error_at="", current="")


# ------------------------------------------------------------------ store


def test_record_and_read_agent_runs_newest_first(tmp_path):
    s = IncidentStore(tmp_path / "t.sqlite3")
    s.record_agent_run("daily", ago(300), ago(290), True, detail={"hosts": 3})
    s.record_agent_run("daily", ago(100), ago(90), False, error="boom")
    rows = s.agent_runs("daily")
    assert [r["started_at"] for r in rows] == [ago(100), ago(300)]
    assert rows[0]["ok"] is False and rows[0]["error"] == "boom"
    assert rows[1]["ok"] is True and rows[1]["detail"] == {"hosts": 3}
    assert s.agent_runs("backup") == []


def test_agent_runs_since_bound_is_inclusive(tmp_path):
    s = IncidentStore(tmp_path / "t.sqlite3")
    for secs in (300, 200, 100):
        s.record_agent_run("daily", ago(secs), ago(secs), True)
    assert [r["started_at"] for r in s.agent_runs("daily", since=ago(200))] == [ago(100), ago(200)]


def test_agent_runs_by_agent_caps_per_agent(tmp_path):
    s = IncidentStore(tmp_path / "t.sqlite3")
    for secs in (300, 200, 100):
        s.record_agent_run("daily", ago(secs), ago(secs), True)
    s.record_agent_run("backup", ago(50), ago(50), True)
    by = s.agent_runs_by_agent(limit_per_agent=2)
    assert set(by) == {"daily", "backup"}
    assert [r["started_at"] for r in by["daily"]] == [ago(100), ago(200)]
    assert len(by["backup"]) == 1


def test_prune_drops_agent_runs_older_than_14_days_only(tmp_path):
    s = IncidentStore(tmp_path / "t.sqlite3")
    day = 86400
    s.record_agent_run("daily", ago(15 * day), ago(15 * day), True)
    s.record_agent_run("daily", ago(13 * day), ago(13 * day), True)
    counts = s.prune(NOW_ISO, 120)
    assert counts == {"agent_runs": 1}
    assert [r["started_at"] for r in s.agent_runs("daily")] == [ago(13 * day)]


def test_prune_agent_runs_even_when_retention_is_keep_forever(tmp_path):
    s = IncidentStore(tmp_path / "t.sqlite3")
    day = 86400
    s.record_agent_run("daily", ago(15 * day), ago(15 * day), True)
    s.record_agent_run("daily", ago(1 * day), ago(1 * day), True)
    s.upsert([{"fingerprint": "h|q|", "host": "h", "status": "resolved", "lastSeen": ago(400 * day),
               "firstSeen": ago(400 * day), "description": "[metric] x", "severity": "warning"}])
    assert s.prune(NOW_ISO, 0) == {"agent_runs": 1}
    assert len(s.agent_runs("daily")) == 1
    assert len(s.all_rows()) == 1          # incident history untouched


# ------------------------------------------------------------------ status


def test_no_runs_is_unknown_not_healthy():
    st = agents.status_of(spec(), [], NOW_ISO)
    assert (st.state, st.word, st.lamp) == ("unknown", "No data yet", "")


def test_fresh_ok_run_is_healthy():
    st = agents.status_of(spec(), [run(60)], NOW_ISO)
    assert (st.state, st.word, st.lamp) == ("healthy", "Healthy", "blue")
    assert st.last_run_at == ago(60) and st.last_ok_at == ago(60)


def test_ok_after_error_is_degraded():
    st = agents.status_of(spec(), [run(60), run(360, ok=False, error="x")], NOW_ISO)
    assert (st.state, st.word, st.lamp) == ("degraded", "Degraded", "amber")
    assert st.last_error == "x"


def test_last_error_is_failed_with_message():
    st = agents.status_of(spec(), [run(60, ok=False, error="Prometheus unreachable"), run(360)], NOW_ISO)
    assert (st.state, st.word, st.lamp) == ("failed", "Failed", "red")
    assert st.last_error == "Prometheus unreachable" and st.last_error_at == ago(60)
    assert st.last_ok_at == ago(360)


def test_old_ok_run_is_overdue():
    st = agents.status_of(spec(), [run(901)], NOW_ISO)
    assert (st.state, st.word, st.lamp) == ("stale", "Overdue", "amber")
    assert agents.status_of(spec(), [run(900)], NOW_ISO).state == "healthy"


def test_paused_spec_is_paused_whatever_the_runs():
    st = agents.status_of(spec(paused=True), [run(60, ok=False, error="x")], NOW_ISO)
    assert (st.state, st.word, st.lamp) == ("paused", "Paused", "")


def test_run_strip_marks_misses_and_the_open_slot():
    runs = [run(120), run(420), run(720), run(1920)]
    ticks = agents.run_strip(runs, 300, NOW_ISO)
    assert [t.state for t in ticks] == ["ok", "miss", "ok", "ok", "ok"]
    ticks = agents.run_strip([run(540), run(840)], 300, NOW_ISO)
    assert [t.state for t in ticks] == ["ok", "ok", "open"]
    assert [t.state for t in agents.run_strip([run(60, ok=False)], 300, NOW_ISO)] == ["fail"]
    assert [t.state for t in agents.run_strip([run(99999), run(999999)], None, NOW_ISO)] == ["ok", "ok"]
    assert len(agents.run_strip([run(i * 60) for i in range(40)], 300, NOW_ISO, n=24)) == 24


def test_investigator_running_idle_and_failed():
    done = {"id": 3, "host": "ubuntu-server", "status": "complete", "started_at": ago(900),
            "finished_at": ago(800), "incomplete_reason": ""}
    running = {"id": 4, "host": "homelab", "status": "running", "started_at": ago(30),
               "finished_at": "", "incomplete_reason": ""}
    failed = {"id": 5, "host": "homelab", "status": "failed", "started_at": ago(30),
              "finished_at": ago(20), "incomplete_reason": "model refused"}
    st = agents.investigator_status([running, done], NOW_ISO)
    assert (st.state, st.word, st.lamp) == ("running", "Running", "ring")
    assert st.current == "homelab · investigation 4"
    st = agents.investigator_status([done], NOW_ISO)
    assert (st.state, st.word, st.lamp) == ("idle", "Idle", "blue")
    st = agents.investigator_status([failed, done], NOW_ISO)
    assert (st.state, st.lamp, st.last_error) == ("failed", "red", "model refused")
    assert agents.investigator_status([], NOW_ISO).state == "unknown"


def test_overall_condition_unknown_when_a_watcher_is_overdue():
    inc = [{"severity": "critical"}]
    c = agents.overall_condition(inc, [status("alert_poller", "stale"), status("thresholds", "healthy")])
    assert (c["state"], c["word"], c["lamp"]) == ("unknown", "Unknown", "")
    # a paused watcher is not a blind one
    c = agents.overall_condition([], [status("uptime", "paused"), status("alert_poller", "healthy")])
    assert c["state"] == "normal"


def test_overall_condition_critical_degraded_normal_with_counts():
    ok = [status("alert_poller", "healthy")]
    c = agents.overall_condition([{"severity": "critical"}, {"severity": "warning"}], ok)
    assert (c["state"], c["lamp"], c["crit"], c["warn"], c["detail"]) == (
        "critical", "red", 1, 1, "1 warning open")
    c = agents.overall_condition([{"severity": "warn"}, {"severity": "warning"}], ok)
    assert (c["state"], c["lamp"], c["detail"]) == ("degraded", "amber", "2 warnings open")
    c = agents.overall_condition([], ok + [status("backup", "failed")])
    assert (c["state"], c["lamp"]) == ("degraded", "amber")
    c = agents.overall_condition([], ok)
    assert (c["state"], c["word"], c["lamp"], c["detail"]) == (
        "normal", "Normal", "blue", "nothing else open")


# ------------------------------------------------------------ specs + daemon


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
    cfg.settings.deadman_url = ""
    return Runtime(config=cfg, store=IncidentStore(tmp_path / "rt.sqlite3"),
                   dry_run=True, out_dir=tmp_path / "out")


def test_specs_paused_flags_and_daily_cadence_from_schedule(rt):
    st = rt.config.settings
    st.schedules.daily = ["07:00", "22:00"]
    st.threshold_detection = False
    st.uptime_kuma.url = ""
    st.schedules.security_audit = ""
    specs = {s.key: s for s in agents.agent_specs(rt.config, {})}
    assert list(specs) == list(agents.AGENT_KEYS)
    assert specs["daily"].cadence_s == 15 * 3600
    assert specs["daily"].stale_after_s == 15 * 3600 + 3600
    assert (specs["thresholds"].paused, specs["uptime"].paused, specs["security"].paused) == (True, True, True)
    assert specs["uptime"].scope == "Off"
    assert specs["alert_poller"].paused is False and specs["backup"].cadence_s == 86400
    assert specs["investigator"].cadence_s is None and specs["investigator"].stale_after_s is None
    assert specs["backup"].scope == "Expected daily at 03:30"
    assert specs["investigator"].scope.startswith("investigates ")
    running = {"investigator": {"running_host": "homelab", "running_id": 7}}
    inv = next(s for s in agents.agent_specs(rt.config, running) if s.key == "investigator")
    assert inv.scope == "homelab · investigation 7"


async def test_poll_job_records_three_agents(rt, monkeypatch):
    rt.config.settings.threshold_detection = True
    rt.config.settings.uptime_kuma.url = "http://kuma.invalid"

    async def fake_poll(_rt, **_kw):
        return {"aborted": "prometheus down", "threshold_samples": 0, "uptime_unreachable": True,
                "uptime_monitors": 5, "uptime_report_only": 2}

    monkeypatch.setattr(daemon, "run_poll", fake_poll)
    await daemon._poll_job(rt)
    by = rt.store.agent_runs_by_agent()
    assert set(by) == {"alert_poller", "thresholds", "uptime"}
    msgs = {k: v[0] for k, v in by.items()}
    assert all(r["ok"] is False for r in msgs.values())
    assert msgs["alert_poller"]["error"] == "Prometheus unreachable"
    assert msgs["thresholds"]["error"] == "no usable samples"
    assert msgs["uptime"]["error"] == "Uptime Kuma unreachable"
    assert msgs["uptime"]["detail"] == {"monitors": 5, "report_only": 2}


async def test_poll_job_skips_paused_halves(rt, monkeypatch):
    rt.config.settings.threshold_detection = False
    rt.config.settings.uptime_kuma.url = ""

    async def fake_poll(_rt, **_kw):
        return {"upserts": 0}

    monkeypatch.setattr(daemon, "run_poll", fake_poll)
    await daemon._poll_job(rt)
    by = rt.store.agent_runs_by_agent()
    assert set(by) == {"alert_poller"} and by["alert_poller"][0]["ok"] is True


async def test_daily_job_failure_records_error(rt, monkeypatch):
    async def boom(_rt, **_kw):
        raise RuntimeError("x" * 300)

    monkeypatch.setattr(daemon, "run_daily", boom)
    await daemon._daily_job(rt)
    (row,) = rt.store.agent_runs("daily")
    assert row["ok"] is False
    assert row["error"].startswith("RuntimeError: xxx") and len(row["error"]) == 200


def test_report_only_count_is_unmapped_or_non_investigable(rt):
    from types import SimpleNamespace
    from heim.pipelines.uptime import _report_only_count
    routing = rt.config.routing()
    ssh = sorted(routing.ssh_hosts)[0]
    ctx = SimpleNamespace(instance_host_map={"10.9.9.1:1": ssh}, host_names=frozenset(rt.config.hosts),
                          routing=routing)
    mons = [SimpleNamespace(address="10.9.9.1"), SimpleNamespace(address="10.9.9.2")]
    assert _report_only_count(mons, ctx) == 1
    assert _report_only_count(None, ctx) == 0
