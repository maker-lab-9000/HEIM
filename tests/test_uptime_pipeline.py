"""The uptime half of the poll: I/O around ``uptime_logic.decide``."""
from __future__ import annotations

import base64
import logging
import shutil
from pathlib import Path

import httpx
import pytest

from heim.config import load_config
from heim.incidents.store import IncidentStore
from heim.pipelines import poller, uptime
from heim.runtime import Runtime

ROOT = Path(__file__).resolve().parent.parent

ENV = {
    "HEIM_SERVER_IP": "10.0.0.10",
    "HEIM_PROXMOX_IP": "10.0.0.2",
    "HEIM_HA_IP": "10.0.0.3",
    "HEIM_TELEGRAM_CHAT_ID": "111111111",
    "HEIM_EMAIL_TO": "test@example.com",
    "HEIM_EMAIL_FROM": "test@example.com",
}


def _metrics(*mons: tuple[str, str, int]) -> str:
    """(name, address, status) -> Prometheus text for http monitors."""
    return "\n".join(
        f'monitor_status{{monitor_id="{i}",monitor_name="{n}",monitor_type="http",'
        f'monitor_url="http://{a}:80",monitor_hostname="null",monitor_port="null"}} {s}'
        for i, (n, a, s) in enumerate(mons, 1)) + "\n"


def _build(tmp_path, monkeypatch, *, url: bool = True) -> Runtime:
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    if url:
        monkeypatch.setenv("HEIM_UPTIME_KUMA_URL", "http://10.0.0.3:3001")
    else:
        monkeypatch.delenv("HEIM_UPTIME_KUMA_URL", raising=False)
    monkeypatch.setenv("UPTIME_KUMA", "test-key")
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot,
                    ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    cfg.settings.loki = None
    cfg.settings.email = None
    cfg.settings.home_assistant = None
    return Runtime(config=cfg, store=IncidentStore(tmp_path / "rt.sqlite3"),
                   dry_run=False, out_dir=tmp_path / "out")


@pytest.fixture()
def rt(tmp_path, monkeypatch) -> Runtime:
    return _build(tmp_path, monkeypatch)


class Rig:
    def __init__(self, rt, monkeypatch):
        self.rt = rt
        self.notes: list[str] = []
        self.dispatched: list[tuple[str, list[dict]]] = []
        self.body: str | None = ""
        self.fetches = 0

        async def notify(text):
            self.notes.append(text)

        async def fetch(url, key, **kw):
            self.fetches += 1
            if isinstance(self.body, Exception):
                raise self.body
            return self.body

        async def dispatch(rt_, items, *, concurrent, trigger="manual"):
            self.dispatched.append((trigger, list(items)))

        monkeypatch.setattr(rt, "notify", notify)
        monkeypatch.setattr(uptime, "fetch_metrics", fetch)
        monkeypatch.setattr(uptime, "dispatch_all", dispatch)

    async def poll(self, body, at="2026-11-01T10:00:00.000+01:00"):
        self.body = body
        return await uptime.run_uptime(
            self.rt, at, dispatch_concurrently=False)


@pytest.fixture()
def rig(rt, monkeypatch):
    # run_uptime reads the clock through rt.now_iso
    r = Rig(rt, monkeypatch)
    return r


def _at(rt, monkeypatch, iso):
    monkeypatch.setattr(rt, "now_iso", lambda: iso)


async def test_settings_ship_uptime_kuma_off(tmp_path, monkeypatch):
    rt = _build(tmp_path, monkeypatch, url=False)
    assert rt.config.settings.uptime_kuma.url == ""
    rig = Rig(rt, monkeypatch)

    async def no_alerts(_u):
        return {"status": "success", "data": {"alerts": []}}

    monkeypatch.setattr(poller, "_fetch_alerts", no_alerts)
    rt.config.settings.threshold_detection = False
    await poller.run_poll(rt, dispatch_concurrently=False)
    assert rig.fetches == 0


async def test_two_down_monitors_dispatch_one_grouped_investigation(rt, rig):
    await rig.poll(_metrics(("n8n", "10.0.0.10", 0), ("grafana", "10.0.0.10", 0)))
    assert len(rig.dispatched) == 1
    trigger, items = rig.dispatched[0]
    assert trigger == "uptime" and len(items) == 1
    item = items[0]
    assert len(item["findings"]) == 2
    assert item["headline"].startswith("🔴 Down on ubuntu-server: ")
    assert item["hostRole"] and "sshHost" in item
    rows = rt.store.open_rows()
    assert len(rows) == 2 and all(r["description"].startswith("[uptime] ") for r in rows)


async def test_report_only_hosts_notify_instead(rt, rig):
    out = await rig.poll(_metrics(("kube", "10.0.0.24", 0)))
    assert rig.dispatched == []
    assert len(rig.notes) == 1
    assert rig.notes[0].endswith("(report only: not a HEIM host)")
    assert out["uptime_dispatches"] == 0 and out["uptime_messages"] == 0


async def test_dry_run_writes_nothing(rt, rig, caplog):
    rt.dry_run = True
    with caplog.at_level(logging.INFO):
        out = await rig.poll(_metrics(("n8n", "10.0.0.10", 0)))
    assert rt.store.open_rows() == []
    assert rt.store.uptime_states() == {}
    assert rt.store.uptime_fail_polls() == 0
    assert rig.notes == [] and rig.dispatched == []
    assert any("DRY-RUN uptime: " in r.message for r in caplog.records)
    assert out["uptime_groups"] == 1


async def test_dry_run_unreachable_writes_no_fail_counter(rt, rig):
    rt.dry_run = True
    await rig.poll(None)
    await rig.poll(None)
    assert rt.store.uptime_fail_polls() == 0


async def test_unreachable_alerts_after_two_polls_and_never_resolves(rt, rig):
    await rig.poll(_metrics(("n8n", "10.0.0.10", 0)))
    rig.notes.clear()
    rig.dispatched.clear()
    for _ in range(3):
        await rig.poll(None)
    assert rig.notes.count(
        "⚠️ Can't reach Uptime Kuma: service outages are not being watched.") == 1
    assert len([r for r in rt.store.open_rows()
                if r["fingerprint"].startswith("ubuntu-server|uptime_down|")]) == 1


async def test_empty_body_is_a_failed_poll_not_an_empty_one(rt, rig):
    await rig.poll(_metrics(("n8n", "10.0.0.10", 0)))
    for _ in range(3):
        await rig.poll("# no monitors here\n")
    assert len(rt.store.open_rows()) >= 1
    assert not any("no longer monitored" in n for n in rig.notes)
    assert rt.store.uptime_fail_polls() == 3


async def test_new_downs_join_a_pending_uptime_investigation(rt, rig):
    iid = rt.store.create_investigation(
        host="ubuntu-server", trigger="uptime", status="pending_approval",
        findings_json="[]", brief_md="x")
    await rig.poll(_metrics(("n8n", "10.0.0.10", 0)))
    assert rig.dispatched == []
    row = rt.store.investigation(iid)
    assert "n8n" in row["findings_json"]
    assert rig.notes[0].startswith("🔴 Also down on ubuntu-server: ")


async def test_a_pending_investigation_that_left_pending_gets_a_new_dispatch(
        rt, rig, monkeypatch):
    iid = rt.store.create_investigation(
        host="ubuntu-server", trigger="uptime", status="pending_approval",
        findings_json="[]", brief_md="x")

    def left(_rt, _id, _f):
        return False

    monkeypatch.setattr(uptime, "extend_pending_investigation", left)
    await rig.poll(_metrics(("n8n", "10.0.0.10", 0)))
    assert len(rig.dispatched) == 1
    head = rig.dispatched[0][1][0]["headline"]
    assert head.startswith("🔴 Down on ubuntu-server: n8n (")
    assert "Also down" not in head and f"#{iid}" not in head
    assert rig.notes == []


def test_pending_uptime_investigations_only_pending_uptime(rt):
    s = rt.store
    s.create_investigation(host="a", trigger="uptime", status="pending_approval")
    new = s.create_investigation(host="a", trigger="uptime", status="pending_approval")
    s.create_investigation(host="b", trigger="poller", status="pending_approval")
    s.create_investigation(host="c", trigger="uptime", status="running")
    assert uptime.pending_uptime_investigations(s) == {"a": new}


async def test_a_flap_reopens_quietly_with_one_flapping_line(rt, rig, monkeypatch):
    down = _metrics(("n8n", "10.0.0.10", 0))
    up = _metrics(("n8n", "10.0.0.10", 1))
    t = lambda m: f"2026-11-01T10:{m:02d}:00.000+01:00"  # noqa: E731
    for m in (0,):
        _at(rt, monkeypatch, t(m))
        await rig.poll(down, t(m))
    assert len(rig.dispatched) == 1
    rig.dispatched.clear(); rig.notes.clear()
    for m in (5, 10):
        _at(rt, monkeypatch, t(m))
        await rig.poll(up, t(m))
    assert rt.store.open_rows() == []
    assert any(n.startswith("✅ Back up on ubuntu-server: n8n") for n in rig.notes)
    rig.notes.clear()
    _at(rt, monkeypatch, t(15))
    out = await rig.poll(down, t(15))
    assert rig.dispatched == [] and out["uptime_groups"] == 0
    assert len(rt.store.open_rows()) == 1
    assert len(rig.notes) == 1
    assert rig.notes[0].startswith("🔁 n8n on ubuntu-server keeps flapping (2 outages since ")


async def test_the_uptime_half_failing_never_stops_the_others(rt, rig, monkeypatch, caplog):
    rig.body = RuntimeError("boom")

    async def no_alerts(_u):
        return {"status": "success", "data": {"alerts": []}}

    monkeypatch.setattr(poller, "_fetch_alerts", no_alerts)
    rt.config.settings.threshold_detection = False
    with caplog.at_level(logging.ERROR):
        out = await poller.run_poll(rt, dispatch_concurrently=False)
    assert "upserts" in out and "dispatches" in out
    assert any("the uptime half of the poll failed" in r.message for r in caplog.records)


def test_build_context_kuma_host(rt):
    ctx = uptime.build_context(rt.config, set(), {})
    assert ctx.kuma_host == "home-assistant"
    rt.config.settings.uptime_kuma.url = "http://kuma.lan:3001"
    assert uptime.build_context(rt.config, set(), {}).kuma_host == "kuma.lan"


async def test_fetch_metrics_uses_basic_auth():
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200 if req.headers["Authorization"] == _AUTH else 401,
                              text="body")

    _AUTH = "Basic " + base64.b64encode(b":test-key").decode()
    tr = httpx.MockTransport(handler)
    assert await uptime.fetch_metrics("http://10.0.0.3:3001/", "test-key", transport=tr) == "body"
    assert seen[0].url.path == "/metrics"
    assert await uptime.fetch_metrics("http://10.0.0.3:3001", "wrong", transport=tr) is None
    assert await uptime.fetch_metrics("http://10.0.0.3:3001", None, transport=tr) is None
    assert "Authorization" not in seen[-1].headers


def test_homelab_investigates_availability(rt):
    assert "availability" in rt.config.hosts["homelab"].investigable


async def test_daily_run_leaves_uptime_incidents_alone(rt, monkeypatch):
    """reconcile() bumps missedRuns on every open row the LLM didn't mention and
    resolves after 2; an uptime outage Kuma couldn't report on for a day must
    not be closed by that."""
    import json

    from heim.pipelines import daily

    fp = "homelab|uptime|Plex"
    rt.store.upsert([{
        "fingerprint": fp, "host": "homelab", "metric": "Plex", "severity": "critical",
        "status": "open", "firstSeen": "2026-11-01T08:00:00.000+01:00",
        "lastSeen": "2026-11-01T08:00:00.000+01:00", "resolvedAt": "",
        "timesSeen": 3, "missedRuns": 1, "description": "[uptime] Plex is down",
        "investigated": 0,
    }])
    payload = {"generatedAt": "2026-11-01T07:00:00.000+01:00", "windowDays": 3,
               "hosts": [], "counts": {"crit": 0, "warn": 0, "naQueries": 0},
               "overall": "healthy", "categories": {}, "topAlerts": []}
    analysis = {"overallHealth": "healthy", "headline": "ok", "executiveSummary": "ok",
                "categories": {}, "findings": [], "watchlist": []}

    async def fake_fetch(base, qdefs, window):
        return []

    async def fake_analyst(cfg, system, user):
        return json.dumps(analysis), "model-x", {"input": 1, "output": 1}

    async def fake_dispatch(rt_, items, *, concurrent, trigger="manual"):
        pass

    monkeypatch.setattr(daily, "_fetch_query_ranges", fake_fetch)
    monkeypatch.setattr(daily, "aggregate", lambda *a, **k: {"payload": payload})
    monkeypatch.setattr(daily, "analyst_complete", fake_analyst)
    monkeypatch.setattr(daily, "dispatch_all", fake_dispatch)

    await daily.run_daily(rt, dispatch_concurrently=False)
    await daily.run_daily(rt, dispatch_concurrently=False)

    row = next(r for r in rt.store.all_rows() if r["fingerprint"] == fp)
    assert row["status"] == "open"
    assert row["missedRuns"] == 1


def test_check_lines_reports_monitors_and_report_only_targets(rt):
    text = _metrics(("web", "10.0.0.10", 1), ("k8s-w1", "10.0.0.24", 1))
    assert uptime.check_lines(text, rt.config) == [
        (True, "uptime kuma", "2 active monitors"),
        (None, "uptime kuma",
         "1 monitor(s) map to no HEIM host (report only): k8s-w1"),
    ]
    assert uptime.check_lines(None, rt.config) == [
        (False, "uptime kuma",
         "unreachable, or no monitors in /metrics (check UPTIME_KUMA)")]
    assert uptime.check_lines("", rt.config)[0][0] is False
