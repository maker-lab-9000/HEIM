"""The agent model behind the dashboard's "are my agents functioning?" view.

Pure: no I/O, no store access. The daemon writes heartbeat rows
(``agent_runs``); the dashboard reads them and hands them here, together with
the loaded config, to get a spec (what the agent is and how often it should
run) and a status (what its recent runs say).

An agent with no runs is *unknown*, never *healthy*: silence is not good news.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

AGENT_KEYS = ("alert_poller", "thresholds", "uptime", "investigator", "daily", "security", "backup")

#: The nightly backup slot (hour, minute); the daemon schedules from this too.
BACKUP_TIME = (3, 30)

_NAMES = {
    "alert_poller": "Alert poller",
    "thresholds": "Threshold watch",
    "uptime": "Uptime monitor",
    "investigator": "Investigator",
    "daily": "Daily analysis",
    "security": "Security audit",
    "backup": "Backup verifier",
}

#: The poll halves: if one of these goes quiet HEIM is blind, not "normal".
_WATCHERS = ("alert_poller", "thresholds", "uptime")

#: state -> (word, lamp)
_STATES = {
    "healthy": ("Healthy", "blue"),
    "degraded": ("Degraded", "amber"),
    "failed": ("Failed", "red"),
    "paused": ("Paused", ""),
    "unknown": ("No data yet", ""),
    "stale": ("Overdue", "amber"),
    "running": ("Running", "ring"),
    "idle": ("Idle", "blue"),
}


@dataclass(frozen=True)
class AgentSpec:
    key: str
    name: str
    cadence_s: int | None
    stale_after_s: int | None
    paused: bool
    scope: str


@dataclass(frozen=True)
class AgentStatus:
    key: str
    state: str
    word: str
    lamp: str
    last_run_at: str
    last_ok_at: str
    last_error: str
    last_error_at: str
    current: str


@dataclass(frozen=True)
class Tick:
    state: str   # ok | fail | miss | open
    at: str


def _parse(iso: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _age_s(iso: str, now_iso: str) -> float | None:
    a, b = _parse(iso), _parse(now_iso)
    if a is None or b is None:
        return None
    return (b - a).total_seconds()


def _daily_cadence_s(times: list[str]) -> int:
    """Largest gap between consecutive daily times, wrapping midnight."""
    minutes = sorted({int(t.split(":")[0]) * 60 + int(t.split(":")[1]) for t in times})
    if len(minutes) < 2:
        return 24 * 3600
    gaps = [b - a for a, b in zip(minutes, minutes[1:])]
    gaps.append(minutes[0] + 24 * 60 - minutes[-1])
    return max(gaps) * 60


def investigable_hosts(cfg) -> list[str]:
    """The hosts an investigation can reach (SSH guests, the hypervisor, the
    HA host), sorted. The investigator's scope line names them, and the
    dashboard's Needs attention workflow reads the same list."""
    r = cfg.routing()
    names = set(r.ssh_hosts)
    for h in (r.hypervisor_host, r.ha_host):
        if h:
            names.add(h)
    return sorted(names)


def agent_specs(cfg, latest_detail: dict[str, dict]) -> list[AgentSpec]:
    """One spec per agent, in ``AGENT_KEYS`` order.

    ``latest_detail`` maps an agent key to its newest run's ``detail`` (the
    counters the scope strings need). The investigator's scope while running
    comes from ``latest_detail["investigator"] = {"running_host", "running_id"}``.
    """
    st = cfg.settings
    d = {k: (latest_detail.get(k) or {}) for k in AGENT_KEYS}

    def n(key: str, field: str) -> str:
        v = d[key].get(field)
        return str(v) if v is not None else "?"

    daily_cadence = _daily_cadence_s(list(st.schedules.daily))
    monitors = d["uptime"].get("monitors")
    if not st.uptime_kuma.url:
        uptime_scope = "Off"
    elif monitors is None:
        uptime_scope = "? monitors"
    elif d["uptime"].get("report_only") is not None:
        uptime_scope = f"{monitors} monitors · {d['uptime']['report_only']} report-only"
    else:
        uptime_scope = f"{monitors} monitors"

    inv = d["investigator"]
    if inv.get("running_host") and inv.get("running_id") is not None:
        inv_scope = f"{inv['running_host']} · investigation {inv['running_id']}"
    else:
        inv_scope = "investigates " + ", ".join(investigable_hosts(cfg))

    hosts = d["alert_poller"].get("hosts", len(cfg.hosts))
    daily_hosts = d["daily"].get("hosts", len(cfg.hosts))
    bh, bm = BACKUP_TIME
    scopes = {
        "alert_poller": f"Prometheus alerts · {hosts} hosts",
        "thresholds": f"{n('thresholds', 'queries')} catalog queries",
        "uptime": uptime_scope,
        "investigator": inv_scope,
        "daily": f"{n('daily', 'queries')} queries · {daily_hosts} hosts",
        "security": f"{n('security', 'checks')} checks",
        "backup": f"Expected daily at {bh:02d}:{bm:02d}",
    }
    timing = {
        "alert_poller": (300, 900), "thresholds": (300, 900), "uptime": (300, 900),
        "investigator": (None, None),
        "daily": (daily_cadence, daily_cadence + 3600),
        "security": (604800, 691200),
        "backup": (86400, 93600),
    }
    paused = {
        "thresholds": not st.threshold_detection,
        "uptime": st.uptime_kuma.url == "",
        "security": st.schedules.security_audit == "",
    }
    return [AgentSpec(key=k, name=_NAMES[k], cadence_s=timing[k][0], stale_after_s=timing[k][1],
                      paused=bool(paused.get(k, False)), scope=scopes[k]) for k in AGENT_KEYS]


def _status(key: str, state: str, *, last_run_at="", last_ok_at="", last_error="",
            last_error_at="", current="") -> AgentStatus:
    word, lamp = _STATES[state]
    return AgentStatus(key=key, state=state, word=word, lamp=lamp, last_run_at=last_run_at,
                       last_ok_at=last_ok_at, last_error=last_error,
                       last_error_at=last_error_at, current=current)


def status_of(spec: AgentSpec, runs: list[dict], now_iso: str) -> AgentStatus:
    """Status from heartbeat runs, newest first."""
    if spec.paused:
        return _status(spec.key, "paused")
    if not runs:
        return _status(spec.key, "unknown")
    last = runs[0]
    last_ok = next((r for r in runs if r.get("ok")), None)
    last_bad = next((r for r in runs if not r.get("ok")), None)
    info = dict(
        last_run_at=str(last.get("started_at") or ""),
        last_ok_at=str(last_ok.get("started_at") or "") if last_ok else "",
        last_error=str(last_bad.get("error") or "") if last_bad else "",
        last_error_at=str(last_bad.get("started_at") or "") if last_bad else "",
    )
    age = _age_s(str(last.get("finished_at") or last.get("started_at") or ""), now_iso)
    if spec.stale_after_s is not None and age is not None and age > spec.stale_after_s:
        return _status(spec.key, "stale", **info)
    if not last.get("ok"):
        return _status(spec.key, "failed", **info)
    if len(runs) > 1 and not runs[1].get("ok"):
        return _status(spec.key, "degraded", **info)
    return _status(spec.key, "healthy", **info)


def investigator_status(investigations: list[dict], now_iso: str) -> AgentStatus:
    """The investigator is event-driven: running / idle / failed, not overdue."""
    key = "investigator"
    if not investigations:
        return _status(key, "unknown")
    running = next((i for i in investigations if i.get("status") == "running"), None)
    last_bad = next((i for i in investigations if i.get("status") == "failed"), None)
    last_ok = next((i for i in investigations
                    if i.get("status") in ("complete", "resolved", "needs_human")), None)
    info = dict(
        last_run_at=str(investigations[0].get("started_at") or ""),
        last_ok_at=str(last_ok.get("started_at") or "") if last_ok else "",
        last_error=str(last_bad.get("incomplete_reason") or "investigation failed") if last_bad else "",
        last_error_at=str(last_bad.get("started_at") or "") if last_bad else "",
    )
    if running is not None:
        return _status(key, "running",
                       current=f"{running.get('host', '')} · investigation {running.get('id')}", **info)
    finished = [i for i in investigations if i.get("status") not in ("pending_approval", "declined")]
    latest = finished[0] if finished else investigations[0]
    if latest.get("status") == "failed":
        return _status(key, "failed", **info)
    if latest.get("status") == "incomplete":
        return _status(key, "degraded", **info)
    return _status(key, "idle", **info)


def run_strip(runs: list[dict], cadence_s: int | None, now_iso: str, n: int = 24) -> list[Tick]:
    """Oldest to newest, at most ``n``: ok / fail per run, a ``miss`` where a
    stretch over twice the cadence separates two runs, a trailing ``open`` slot
    when the newest run is older than one cadence."""
    ticks: list[Tick] = []
    prev: dict | None = None
    for r in reversed(runs):
        if prev is not None and cadence_s:
            gap = _age_s(str(prev.get("started_at")), str(r.get("started_at")))
            if gap is not None and gap > 2 * cadence_s:
                ticks.append(Tick("miss", str(prev.get("started_at"))))
        ticks.append(Tick("ok" if r.get("ok") else "fail", str(r.get("started_at") or "")))
        prev = r
    if cadence_s and prev is not None:
        age = _age_s(str(prev.get("started_at")), now_iso)
        if age is not None and age > cadence_s:
            ticks.append(Tick("open", now_iso))
    return ticks[-n:]


def overall_condition(open_incidents: list[dict], statuses: list[AgentStatus]) -> dict:
    crit = sum(1 for i in open_incidents if str(i.get("severity", "")).lower() in ("critical", "crit"))
    warn = sum(1 for i in open_incidents if str(i.get("severity", "")).lower() in ("warning", "warn"))
    detail = ("nothing else open" if warn == 0
              else f"{warn} warning{'s' if warn != 1 else ''} open")

    def out(state: str, word: str, lamp: str) -> dict:
        return {"state": state, "word": word, "lamp": lamp, "crit": crit, "warn": warn,
                "detail": detail}

    if any(s.key in _WATCHERS and s.state in ("stale", "unknown") for s in statuses):
        return out("unknown", "Unknown", "")
    if crit:
        return out("critical", "Critical", "red")
    if warn or any(s.state in ("failed", "degraded") for s in statuses):
        return out("degraded", "Degraded", "amber")
    return out("normal", "Normal", "blue")
