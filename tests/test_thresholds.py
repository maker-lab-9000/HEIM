"""Threshold detection (Part A): hysteresis, ownership, fingerprint parity.

The pure decision (``thresholds.decide``) is driven directly — no Prometheus,
no store — the way ``test_poller_logic`` drives ``diff_and_decide``. The live
incident that motivated the feature is pinned with its real numbers: ``qemu/100``
read 102.5% ``pve_vm_cpu`` against ``crit: 95`` while 23 of the surrounding 24
samples were under it, so that sequence must NOT dispatch.
"""
from __future__ import annotations

import shutil
from dataclasses import asdict
from pathlib import Path

import pytest

from heim.config import load_config
from heim.incidents.reconcile import fingerprint_for
from heim.incidents.store import IncidentStore
from heim.incidents.types import HostRouting
from heim.metrics.aggregate import aggregate
from heim.metrics.queries import QueryDef
from heim.pipelines import thresholds
from heim.pipelines.thresholds import PREFIX, ThresholdConfig, build_samples, decide
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

ROUTING = HostRouting(
    ssh_hosts=frozenset({"ubuntu-server"}),
    hypervisor_host="homelab",
    hypervisor_categories=frozenset({"cpu", "memory", "disk", "temperature"}),
    ha_host="home-assistant",
)

NOW = "2026-09-19T10:15:00.000+02:00"
LATER = "2026-09-19T10:20:00.000+02:00"

#: the real catalog entry behind the observed incident
PVE_VM_CPU = QueryDef(qid="pve_vm_cpu", category="Proxmox", label="VM CPU",
                      unit="%", dir="high", warn=85, crit=95,
                      promql='pve_cpu_usage_ratio{id=~"qemu/.*"} * 100')
PVE_GUEST_INFO = QueryDef(qid="pve_guest_info", category="Proxmox",
                          label="guest info", unit="", dir="info", warn=0,
                          crit=0, promql="pve_guest_info")

#: the 24 five-minute samples around the observation: one over 95, the rest not
SPIKE_SERIES = [20.9] * 12 + [102.5] + [21.4] * 11


def _instant(qdef: QueryDef, series: list[tuple[dict, float]]) -> dict:
    """A successful ``/api/v1/query`` instant-vector response."""
    return {
        "query": asdict(qdef),
        "error": None,
        "data": {"status": "success", "data": {
            "resultType": "vector",
            "result": [{"metric": m, "value": [1_760_000_000, str(v)]}
                       for m, v in series],
        }},
    }


def _vm_cpu(value: float, *, named: bool = True) -> list[dict]:
    """One poll's worth of results: pve_vm_cpu on qemu/100 (+ the guest map)."""
    out = [_instant(PVE_VM_CPU,
                    [({"id": "qemu/100", "instance": "10.0.0.2:9221"}, value)])]
    if named:
        out.append(_instant(PVE_GUEST_INFO,
                            [({"id": "qemu/100", "name": "ubuntu-server",
                               "instance": "10.0.0.2:9221"}, 1.0)]))
    return out


def _samples(value: float, *, named: bool = True) -> list[dict]:
    return build_samples(_vm_cpu(value, named=named), {"10.0.0.2": "homelab"})


CFG = ThresholdConfig(severity="crit", consecutive=2)


# ----------------------------------------------------------- sample building


def test_samples_carry_the_flag_and_the_guest_identity():
    [s] = _samples(102.5)
    assert s["flag"] == "crit"
    assert s["host"] == "ubuntu-server"      # qemu/100 IS the guest, not the hv
    assert s["fingerprint"] == "ubuntu-server|pve_vm_cpu|"
    assert s["current"] == 102.5 and s["unit"] == "%"


def test_an_unnamed_guest_keeps_its_id_as_the_host():
    [s] = _samples(102.5, named=False)
    assert s["host"] == "qemu/100"
    assert s["fingerprint"] == "qemu/100|pve_vm_cpu|"


def test_a_failed_query_contributes_no_samples():
    results = [{"query": asdict(PVE_VM_CPU), "data": None,
                "error": "ReadTimeout: timed out"}]
    assert build_samples(results, {}) == []


# ------------------------------------------------------------- the decision


def test_below_threshold_decides_nothing():
    dec = decide(_samples(20.9), [], {}, NOW, ROUTING, CFG)
    assert dec.rows_to_upsert == [] and dec.dispatches == []
    assert dec.streak_writes == [] and dec.streak_clears == []
    assert dec.loki_events == [] and dec.state_changed is False


def test_first_crit_poll_only_starts_a_streak():
    dec = decide(_samples(102.5), [], {}, NOW, ROUTING, CFG)
    assert dec.streak_writes == [{"fingerprint": "ubuntu-server|pve_vm_cpu|",
                                  "count": 1, "severity": "crit",
                                  "last_seen": NOW}]
    assert dec.rows_to_upsert == [] and dec.dispatches == []
    assert dec.notifications == [] and dec.state_changed is False


def test_second_consecutive_crit_poll_opens_and_dispatches():
    streaks = {"ubuntu-server|pve_vm_cpu|": {"count": 1, "severity": "crit",
                                             "last_seen": NOW}}
    dec = decide(_samples(102.5), [], streaks, LATER, ROUTING, CFG)

    [row] = dec.rows_to_upsert
    assert row["fingerprint"] == "ubuntu-server|pve_vm_cpu|"
    assert row["severity"] == "critical" and row["status"] == "open"
    assert row["description"].startswith(PREFIX)          # ownership marker
    assert "102.5%" in row["description"] and "95%" in row["description"]
    assert row["firstSeen"] == LATER and row["timesSeen"] == 1
    assert row["investigated"] is True

    [d] = dec.dispatches
    assert d["fingerprint"] == "ubuntu-server|pve_vm_cpu|"
    assert d["hostRole"] == "guest" and d["sshHost"] == "ubuntu-server"
    assert dec.notifications == []                        # dispatched, not paged
    assert dec.state_changed is True
    assert [e["labels"]["status"] for e in dec.loki_events] == ["new"]
    assert dec.streak_writes[0]["count"] == 2


def test_the_observed_spike_never_dispatches():
    """1 of 24 samples over 95 — the case that must stay silent.

    Replays the real sequence through the real decision, carrying the streak
    forward exactly as the store would.
    """
    streaks: dict[str, dict] = {}
    opened: list[dict] = []
    for value in SPIKE_SERIES:
        dec = decide(_samples(value), [], streaks, NOW, ROUTING, CFG)
        opened += dec.rows_to_upsert
        for fp in dec.streak_clears:
            streaks.pop(fp, None)
        for w in dec.streak_writes:
            streaks[w["fingerprint"]] = w
    assert opened == []                     # no incident, ever
    assert streaks == {}                    # the spike's streak was cleared

    # ...and the next crit after a clear poll starts from 1 again, not from 2
    dec = decide(_samples(102.5), [], streaks, NOW, ROUTING, CFG)
    assert dec.streak_writes[0]["count"] == 1 and dec.rows_to_upsert == []


def test_a_clear_poll_clears_the_streak():
    streaks = {"ubuntu-server|pve_vm_cpu|": {"count": 1, "severity": "crit",
                                             "last_seen": NOW}}
    dec = decide(_samples(20.9), [], streaks, LATER, ROUTING, CFG)
    assert dec.streak_clears == ["ubuntu-server|pve_vm_cpu|"]
    assert dec.streak_writes == []


def _open_metric_row(**over) -> dict:
    row = {"fingerprint": "ubuntu-server|pve_vm_cpu|", "host": "ubuntu-server",
           "metric": "VM CPU", "severity": "critical", "status": "open",
           "firstSeen": NOW, "lastSeen": NOW, "resolvedAt": "", "timesSeen": 3,
           "missedRuns": 0, "description": f"{PREFIX}VM CPU is high",
           "investigated": True}
    row.update(over)
    return row


def test_two_clear_polls_resolve_a_metric_incident():
    first = decide(_samples(20.9), [_open_metric_row()], {}, NOW, ROUTING, CFG)
    [row] = first.rows_to_upsert
    assert row["status"] == "open" and row["missedRuns"] == 1
    assert first.state_changed is False

    second = decide(_samples(20.9), [_open_metric_row(missedRuns=1)], {},
                    LATER, ROUTING, CFG)
    [row] = second.rows_to_upsert
    assert row["status"] == "resolved" and row["resolvedAt"] == LATER
    assert second.state_changed is True
    assert [e["labels"]["status"] for e in second.loki_events] == ["resolved"]


@pytest.mark.parametrize("description", ["[alert] VM CPU > 95", "CPU is climbing"])
def test_foreign_incidents_are_neither_resolved_nor_duplicated(description):
    """``[alert] `` and LLM-born rows belong to the other two paths."""
    foreign = _open_metric_row(description=description)

    # under threshold: not ours to resolve, so not touched at all
    clear = decide(_samples(20.9), [foreign], {}, NOW, ROUTING, CFG)
    assert clear.rows_to_upsert == []

    # over threshold with the streak met: refreshed, never a second incident
    streaks = {"ubuntu-server|pve_vm_cpu|": {"count": 1, "severity": "crit",
                                             "last_seen": NOW}}
    hot = decide(_samples(102.5), [foreign], streaks, LATER, ROUTING, CFG)
    [row] = hot.rows_to_upsert
    assert row["description"] == description          # ownership preserved
    assert row["lastSeen"] == LATER and row["timesSeen"] == 4
    assert hot.dispatches == [] and hot.state_changed is False


def test_warn_to_crit_escalates_and_dispatches_once():
    warned = _open_metric_row(severity="warning",
                              description=f"{PREFIX}VM CPU is elevated")
    streaks = {"ubuntu-server|pve_vm_cpu|": {"count": 1, "severity": "crit",
                                             "last_seen": NOW}}
    dec = decide(_samples(102.5), [warned], streaks, LATER, ROUTING, CFG)
    [row] = dec.rows_to_upsert
    assert row["severity"] == "critical" and row["firstSeen"] == NOW
    assert len(dec.dispatches) == 1 and dec.state_changed is True
    assert [e["labels"]["status"] for e in dec.loki_events] == ["escalated"]


def test_suppressed_fingerprints_are_skipped_entirely():
    cfg = ThresholdConfig(severity="crit", consecutive=2,
                          suppressed=frozenset({"ubuntu-server|pve_vm_cpu|"}))
    streaks = {"ubuntu-server|pve_vm_cpu|": {"count": 1, "severity": "crit",
                                             "last_seen": NOW}}
    dec = decide(_samples(102.5), [_open_metric_row()], streaks, LATER,
                 ROUTING, cfg)
    assert dec.rows_to_upsert == [] and dec.dispatches == []
    assert dec.streak_writes == [] and dec.streak_clears == []
    # ...and it is not resolved out from under the mute either
    assert dec.loki_events == []


def test_threshold_severity_warn_includes_crit():
    warn_cfg = ThresholdConfig(severity="warn", consecutive=2)
    assert warn_cfg.over_flags == ("crit", "warn")

    # 88% is warn-only: invisible at severity=crit, counted at severity=warn
    assert decide(_samples(88.0), [], {}, NOW, ROUTING, CFG).streak_writes == []
    dec = decide(_samples(88.0), [], {}, NOW, ROUTING, warn_cfg)
    assert dec.streak_writes[0]["severity"] == "warn"

    streaks = {"ubuntu-server|pve_vm_cpu|": {"count": 1, "severity": "warn",
                                             "last_seen": NOW}}
    opened = decide(_samples(88.0), [], streaks, LATER, ROUTING, warn_cfg)
    assert opened.rows_to_upsert[0]["severity"] == "warning"
    # crit still counts under severity=warn
    assert decide(_samples(102.5), [], {}, NOW, ROUTING,
                  warn_cfg).streak_writes[0]["severity"] == "crit"


def test_a_non_investigable_crit_notifies_instead_of_dispatching():
    """A guest with no SSH and no hypervisor role can only be paged about."""
    streaks = {"qemu/100|pve_vm_cpu|": {"count": 1, "severity": "crit",
                                        "last_seen": NOW}}
    dec = decide(_samples(102.5, named=False), [], streaks, LATER, ROUTING, CFG)
    assert dec.dispatches == []
    [n] = dec.notifications
    assert n["host"] == "qemu/100" and n["severity"] == "critical"


# ---------------------------------------------------------- fingerprint parity


def _range(qdef: QueryDef, metric: dict, values: list[float]) -> dict:
    return {
        "query": asdict(qdef), "error": None,
        "data": {"status": "success", "data": {"resultType": "matrix", "result": [
            {"metric": metric,
             "values": [[1_760_000_000 + i * 10800, str(v)]
                        for i, v in enumerate(values)]},
        ]}},
    }


@pytest.mark.parametrize("named,host", [(True, "ubuntu-server"), (False, "qemu/100")])
def test_threshold_and_daily_agree_on_the_fingerprint(named, host):
    """The test that stops the two paths double-investigating one problem.

    Builds the SAME series through both pipelines — the daily 3-day aggregate
    plus ``reconcile.fingerprint_for``, and the threshold detector's instant
    sample — and compares the fingerprints byte for byte.
    """
    metric = {"id": "qemu/100", "instance": "10.0.0.2:9221"}
    results = [_range(PVE_VM_CPU, metric, [8.6, 12.5, 102.5])]
    if named:
        results.append(_range(PVE_GUEST_INFO,
                              {"id": "qemu/100", "name": "ubuntu-server",
                               "instance": "10.0.0.2:9221"}, [1.0, 1.0, 1.0]))
    payload = aggregate(results, instance_host_map={"10.0.0.2": "homelab"})["payload"]
    payload_rows = [r for rows in payload["categories"].values() for r in rows]
    assert [r["flag"] for r in payload_rows] == ["crit"]

    daily_fp = fingerprint_for({"host": host, "metric": "VM CPU"}, payload_rows)
    [sample] = _samples(102.5, named=named)

    assert sample["fingerprint"] == daily_fp == f"{host}|pve_vm_cpu|"


# ------------------------------------------------------------------- store


def test_streaks_upsert_clear_and_persist(tmp_path):
    path = tmp_path / "streaks.sqlite3"
    store = IncidentStore(path)
    assert store.threshold_streaks() == {}

    store.save_threshold_streaks([{"fingerprint": "a|q|", "count": 1,
                                   "severity": "crit", "last_seen": NOW}])
    store.save_threshold_streaks([{"fingerprint": "a|q|", "count": 2,
                                   "severity": "crit", "last_seen": LATER},
                                  {"fingerprint": "b|q|", "count": 1,
                                   "severity": "warn", "last_seen": LATER}])
    assert store.threshold_streaks()["a|q|"] == {
        "fingerprint": "a|q|", "count": 2, "severity": "crit", "last_seen": LATER}
    store.close()

    # a daemon restart must not reset a streak — that is the whole point of
    # keeping it in the store instead of in the poller's memory
    reopened = IncidentStore(path)
    assert set(reopened.threshold_streaks()) == {"a|q|", "b|q|"}
    assert reopened.clear_threshold_streaks(["a|q|", "missing|q|"]) == 1
    assert set(reopened.threshold_streaks()) == {"b|q|"}
    reopened.close()


# ---------------------------------------------------------------- the poll


@pytest.fixture()
def rt(tmp_path, monkeypatch) -> Runtime:
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot,
                    ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    cfg.settings.loki = None
    cfg.settings.email = None
    cfg.settings.home_assistant = None
    return Runtime(config=cfg, store=IncidentStore(tmp_path / "rt.sqlite3"),
                   dry_run=True, out_dir=tmp_path / "out")


def test_settings_ship_threshold_detection_on(rt):
    assert rt.config.settings.threshold_detection is True
    assert rt.config.settings.threshold_severity == "crit"
    assert rt.config.settings.threshold_consecutive == 2


async def test_the_poll_runs_both_halves_and_persists_the_streak(rt, monkeypatch):
    from heim.pipelines import poller

    async def no_alerts(_url):
        return {"status": "success", "data": {"alerts": []}}

    async def fake_instants(_url, _qdefs):
        return _vm_cpu(102.5)

    dispatched: list = []

    async def fake_dispatch(rt_, items, *, concurrent, trigger="manual"):
        dispatched.append((trigger, [i["fingerprint"] for i in items]))

    monkeypatch.setattr(poller, "_fetch_alerts", no_alerts)
    monkeypatch.setattr(poller.thresholds, "fetch_instants", fake_instants)
    monkeypatch.setattr(poller, "dispatch_all", fake_dispatch)

    first = await poller.run_poll(rt, dispatch_concurrently=False)
    assert first["threshold_streaks"] == 1 and first["threshold_upserts"] == 0
    assert dispatched == []
    assert rt.store.threshold_streaks()["ubuntu-server|pve_vm_cpu|"]["count"] == 1

    second = await poller.run_poll(rt, dispatch_concurrently=False)
    assert second["threshold_upserts"] == 1 and second["threshold_dispatches"] == 1
    assert dispatched == [("threshold", ["ubuntu-server|pve_vm_cpu|"])]
    [row] = rt.store.open_rows()
    assert row["description"].startswith(PREFIX) and row["severity"] == "critical"
    assert [r["kind"] for r in rt.store.runs()] == ["poll"]   # only the 2nd counted


async def test_threshold_detection_off_skips_the_half(rt, monkeypatch):
    from heim.pipelines import poller

    async def no_alerts(_url):
        return {"status": "success", "data": {"alerts": []}}

    async def boom(_url, _qdefs):
        raise AssertionError("must not be called")

    rt.config.settings.threshold_detection = False
    monkeypatch.setattr(poller, "_fetch_alerts", no_alerts)
    monkeypatch.setattr(poller.thresholds, "fetch_instants", boom)
    summary = await poller.run_poll(rt, dispatch_concurrently=False)
    assert "threshold_upserts" not in summary and summary["upserts"] == 0


async def test_each_half_survives_the_other_failing(rt, monkeypatch, caplog):
    import logging

    from heim.pipelines import poller

    async def dead_prometheus(_url):
        return {"status": "error", "error": "boom"}

    async def fake_instants(_url, _qdefs):
        return _vm_cpu(102.5)

    monkeypatch.setattr(poller, "_fetch_alerts", dead_prometheus)
    monkeypatch.setattr(poller.thresholds, "fetch_instants", fake_instants)

    # the alert half aborts; the threshold half still runs
    summary = await poller.run_poll(rt, dispatch_concurrently=False)
    assert summary["aborted"] == "prometheus unreachable"
    assert summary["threshold_streaks"] == 1

    # and the other way round: a threshold half that explodes is logged, not
    # propagated, and the alert half's result survives
    async def exploding(_url, _qdefs):
        raise RuntimeError("catalog on fire")

    async def no_alerts(_url):
        return {"status": "success", "data": {"alerts": []}}

    monkeypatch.setattr(poller, "_fetch_alerts", no_alerts)
    monkeypatch.setattr(poller.thresholds, "fetch_instants", exploding)
    with caplog.at_level(logging.ERROR, logger="heim.pipelines.poller"):
        summary = await poller.run_poll(rt, dispatch_concurrently=False)
    assert summary == {"upserts": 0, "dispatches": 0, "notifications": 0,
                       "loki_events": 0, "state_changed": False}
    assert "threshold half of the poll failed" in caplog.text


async def test_an_unreachable_prometheus_never_resolves_a_metric_incident(rt, monkeypatch):
    """No samples means "we cannot see", not "everything is fine"."""
    from heim.pipelines import poller

    rt.store.upsert([_open_metric_row()])

    async def no_alerts(_url):
        return {"status": "success", "data": {"alerts": []}}

    async def nothing(_url, _qdefs):
        return [{"query": asdict(PVE_VM_CPU), "data": None, "error": "ConnectError"}]

    monkeypatch.setattr(poller, "_fetch_alerts", no_alerts)
    monkeypatch.setattr(poller.thresholds, "fetch_instants", nothing)
    summary = await poller.run_poll(rt, dispatch_concurrently=False)
    assert summary["threshold_samples"] == 0 and summary["threshold_upserts"] == 0
    assert rt.store.open_rows()[0]["missedRuns"] == 0     # untouched
