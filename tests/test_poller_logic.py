"""Tests for heim.incidents.poller_logic (port of PAM 11 Diff & Decide)."""
from __future__ import annotations

from heim.incidents.poller_logic import diff_and_decide
from heim.incidents.types import HostRouting

NOW = "2026-01-02T03:04:05.000Z"

ROUTING = HostRouting(
    ssh_hosts=frozenset({"ubuntu-server"}),
    hypervisor_host="homelab",
    hypervisor_categories=frozenset(
        {"cpu", "memory", "temperature", "disk", "diskHealth"}
    ),
)

HOST_MAP = {"192.168.178.241": "ubuntu-server", "192.168.178.2": "homelab"}


def alert(
    qid: str,
    severity: str = "warning",
    state: str = "firing",
    instance: str = "192.168.178.241:9100",
    labels: dict | None = None,
    annotations: dict | None = None,
) -> dict:
    base_labels = {
        "qid": qid,
        "severity": severity,
        "instance": instance,
        "alertname": f"Alert_{qid}",
    }
    base_labels.update(labels or {})
    return {
        "state": state,
        "labels": base_labels,
        "annotations": annotations if annotations is not None else {"description": f"{qid} misbehaving"},
    }


def resp(*alerts: dict) -> dict:
    return {"status": "success", "data": {"alerts": list(alerts)}}


def open_row(fingerprint: str, **overrides: object) -> dict:
    row = {
        "fingerprint": fingerprint,
        "host": fingerprint.split("|")[0],
        "metric": "Alert_x",
        "severity": "warning",
        "status": "open",
        "firstSeen": "2026-01-01T00:00:00.000Z",
        "lastSeen": "2026-01-01T00:00:00.000Z",
        "resolvedAt": "",
        "timesSeen": 1,
        "missedRuns": 0,
        "description": "[alert] something",
        "investigated": True,
    }
    row.update(overrides)
    return row


def decide(alerts_resp: dict, open_rows: list[dict]):
    return diff_and_decide(alerts_resp, open_rows, NOW, ROUTING, HOST_MAP)


# ------------------------------------------------------------------ abort path

def test_non_success_response_aborts_everything() -> None:
    d = decide({"status": "error"}, [open_row("ubuntu-server|cpu_busy|", missedRuns=1)])
    assert d.aborted == "prometheus unreachable"
    assert d.rows_to_upsert == []
    assert d.dispatches == []
    assert d.notifications == []
    assert d.loki_events == []
    assert d.state_changed is False


# ------------------------------------------------------------------ new alerts

def test_new_firing_on_investigable_host_dispatches() -> None:
    d = decide(resp(alert("cpu_busy", severity="critical")), [])
    assert d.aborted is None
    assert len(d.rows_to_upsert) == 1
    row = d.rows_to_upsert[0]
    assert row["fingerprint"] == "ubuntu-server|cpu_busy|"
    assert row["status"] == "open"
    assert row["severity"] == "critical"
    assert row["description"] == "[alert] cpu_busy misbehaving"
    assert row["description"].startswith("[alert] ")
    assert row["firstSeen"] == NOW and row["lastSeen"] == NOW
    assert row["timesSeen"] == 1 and row["missedRuns"] == 0
    assert row["investigated"] is True
    assert len(d.dispatches) == 1 and d.dispatches[0]["qid"] == "cpu_busy"
    assert d.notifications == []
    assert len(d.loki_events) == 1
    ev = d.loki_events[0]
    assert ev["labels"]["status"] == "new"
    assert ev["fields"]["sevScore"] == 3
    assert d.state_changed is True


def test_new_critical_on_non_investigable_host_notifies() -> None:
    d = decide(resp(alert("cpu_busy", severity="critical", instance="10.0.0.5:9100")), [])
    row = d.rows_to_upsert[0]
    assert row["fingerprint"] == "unknown|cpu_busy|"
    assert row["investigated"] is False
    assert d.dispatches == []
    assert len(d.notifications) == 1
    assert d.notifications[0]["host"] == "unknown"


def test_new_warning_on_non_investigable_host_neither_dispatches_nor_notifies() -> None:
    d = decide(resp(alert("cpu_busy", severity="warning", instance="10.0.0.5:9100")), [])
    assert d.dispatches == []
    assert d.notifications == []
    assert len(d.rows_to_upsert) == 1  # row still written


def test_hypervisor_non_investigable_category_notifies_on_critical() -> None:
    # net_err is category "network" — not in the hypervisor's investigable set
    d = decide(
        resp(
            alert(
                "net_err",
                severity="critical",
                instance="192.168.178.2:9100",
                labels={"device": "eno1"},
            )
        ),
        [],
    )
    row = d.rows_to_upsert[0]
    assert row["fingerprint"] == "homelab|net_err|eno1"
    assert row["investigated"] is False
    assert d.dispatches == [] and len(d.notifications) == 1


def test_hypervisor_investigable_category_dispatches() -> None:
    d = decide(
        resp(alert("mem_used", severity="warning", instance="192.168.178.2:9100")), []
    )
    assert d.rows_to_upsert[0]["fingerprint"] == "homelab|mem_used|"
    assert len(d.dispatches) == 1


def test_pending_alerts_ignored() -> None:
    d = decide(resp(alert("cpu_busy", state="pending")), [])
    assert d.rows_to_upsert == []
    assert d.state_changed is False


# -------------------------------------------------------- host / fingerprint

def test_container_qid_maps_to_first_ssh_host() -> None:
    d = decide(
        resp(
            alert(
                "container_mem_dev",
                instance="whatever:8080",
                labels={"name": "n8n"},
            )
        ),
        [],
    )
    row = d.rows_to_upsert[0]
    assert row["fingerprint"] == "ubuntu-server|container_mem_dev|n8n"
    assert row["host"] == "ubuntu-server"
    assert len(d.dispatches) == 1  # ssh host is always investigable


def test_n8n_net_spike_maps_to_ssh_host_with_fixed_name() -> None:
    d = decide(resp(alert("n8n_net_spike", instance="10.9.9.9:9100")), [])
    assert d.rows_to_upsert[0]["fingerprint"] == "ubuntu-server|n8n_net_spike|n8n"


def test_pve_id_label_falls_back_to_hypervisor_host() -> None:
    """A PVE object with no usable ``instance`` still belongs to the hypervisor.

    That fallback is the ONE call-site adaptation in ``_identity_for``: an
    alert need not carry an instance label the way a series does. Everything
    else about a ``pve_`` fingerprint now comes from the shared
    ``series_identity`` helper, so the poller names it exactly as the daily
    and threshold paths do.
    """
    d = decide(
        resp(alert("pve_pool_used", instance="",
                   labels={"id": "storage/local-lvm"})),
        [],
    )
    row = d.rows_to_upsert[0]
    assert row["host"] == "homelab"
    # the storage/ prefix is stripped — aggregate()'s convention, not the raw id
    assert row["fingerprint"] == "homelab|pve_pool_used|local-lvm"
    # disk category on the hypervisor -> investigable
    assert len(d.dispatches) == 1


def test_pve_object_resolves_its_host_from_the_instance_label() -> None:
    """With an instance label the shared helper decides — same answer here."""
    d = decide(
        resp(alert("pve_pool_used", instance="192.168.178.2:9221",
                   labels={"id": "storage/local-lvm"})),
        [],
    )
    row = d.rows_to_upsert[0]
    assert row["host"] == "homelab"
    assert row["fingerprint"] == "homelab|pve_pool_used|local-lvm"


def test_a_pve_guest_alert_is_attributed_to_the_guest() -> None:
    """``qemu/``/``lxc/`` series belong to the guest, not to the hypervisor.

    This is ``series_identity``'s guest override, and it is why the poller
    now takes a ``guest_names`` map: without it the id stands in for the name,
    which is still identical across all three paths, just less readable.
    """
    firing = resp(alert("pve_vm_up", instance="192.168.178.2:9221",
                        labels={"id": "qemu/101"}))

    d = decide(firing, [])
    assert d.rows_to_upsert[0]["fingerprint"] == "qemu/101|pve_vm_up|"

    named = diff_and_decide(firing, [], NOW, ROUTING, HOST_MAP,
                            guest_names={"qemu/101": "home-assistant"})
    assert named.rows_to_upsert[0]["fingerprint"] == "home-assistant|pve_vm_up|"
    assert named.rows_to_upsert[0]["host"] == "home-assistant"


def test_fs_used_fingerprint_uses_device_and_mountpoint() -> None:
    d = decide(
        resp(alert("fs_used", labels={"device": "/dev/sda1", "mountpoint": "/"})), []
    )
    assert d.rows_to_upsert[0]["fingerprint"] == "ubuntu-server|fs_used|/dev/sda1 /"


def test_exporter_up_fingerprint_uses_job() -> None:
    d = decide(resp(alert("exporter_up", labels={"job": "cadvisor"})), [])
    assert d.rows_to_upsert[0]["fingerprint"] == "ubuntu-server|exporter_up|cadvisor"


def test_metric_field_includes_alertname_and_name() -> None:
    d = decide(resp(alert("net_err", labels={"device": "eth0"})), [])
    assert d.rows_to_upsert[0]["metric"] == "Alert_net_err eth0"


def test_duplicate_fingerprint_critical_wins() -> None:
    d = decide(
        resp(alert("cpu_busy", severity="warning"), alert("cpu_busy", severity="critical")),
        [],
    )
    assert len(d.rows_to_upsert) == 1
    assert d.rows_to_upsert[0]["severity"] == "critical"


# ----------------------------------------------------------- still firing / no-op

def test_still_firing_unchanged_is_noop() -> None:
    fp = "ubuntu-server|cpu_busy|"
    d = decide(resp(alert("cpu_busy")), [open_row(fp)])
    assert d.rows_to_upsert == []
    assert d.dispatches == []
    assert d.notifications == []
    assert d.loki_events == []
    assert d.state_changed is False


def test_declined_row_not_redispatched() -> None:
    fp = "ubuntu-server|cpu_busy|"
    d = decide(resp(alert("cpu_busy")), [open_row(fp, investigated=False)])
    assert d.dispatches == []
    assert d.rows_to_upsert == []


def test_still_firing_after_missed_run_resets_missed_runs() -> None:
    fp = "ubuntu-server|cpu_busy|"
    d = decide(resp(alert("cpu_busy")), [open_row(fp, missedRuns=1, timesSeen=4)])
    assert len(d.rows_to_upsert) == 1
    row = d.rows_to_upsert[0]
    assert row["missedRuns"] == 0
    assert row["status"] == "open"
    assert row["lastSeen"] == NOW
    assert row["timesSeen"] == 4  # not incremented on reset
    assert d.dispatches == []


# ------------------------------------------------------------------ escalation

def test_warning_to_critical_escalation_redispatches() -> None:
    fp = "ubuntu-server|cpu_busy|"
    prev = open_row(fp, severity="warning", timesSeen=3, investigated=False)
    d = decide(resp(alert("cpu_busy", severity="critical")), [prev])
    assert len(d.rows_to_upsert) == 1
    row = d.rows_to_upsert[0]
    assert row["severity"] == "critical"
    assert row["status"] == "open"
    assert row["timesSeen"] == 4
    assert row["missedRuns"] == 0
    assert row["firstSeen"] == prev["firstSeen"]
    assert row["investigated"] is True  # investigable host -> forced true
    assert len(d.dispatches) == 1
    assert d.notifications == []  # escalation never notifies
    ev = d.loki_events[0]
    assert ev["labels"]["status"] == "escalated"
    assert ev["fields"]["sevScore"] == 3


def test_critical_stays_critical_is_noop() -> None:
    fp = "ubuntu-server|cpu_busy|"
    d = decide(
        resp(alert("cpu_busy", severity="critical")),
        [open_row(fp, severity="critical")],
    )
    assert d.rows_to_upsert == []
    assert d.dispatches == []


def test_escalation_on_non_investigable_host_keeps_prev_investigated() -> None:
    fp = "unknown|cpu_busy|"
    prev = open_row(fp, host="unknown", severity="warning", investigated="false")
    d = decide(
        resp(alert("cpu_busy", severity="critical", instance="10.0.0.5:9100")), [prev]
    )
    row = d.rows_to_upsert[0]
    assert row["investigated"] is False
    assert d.dispatches == []
    assert d.notifications == []  # escalation branch never notifies


# ------------------------------------------------------------------- resolves

def test_one_clear_poll_keeps_open_with_missed_runs_1() -> None:
    fp = "ubuntu-server|cpu_busy|"
    d = decide(resp(), [open_row(fp, missedRuns=0)])
    assert len(d.rows_to_upsert) == 1
    row = d.rows_to_upsert[0]
    assert row["status"] == "open"
    assert row["missedRuns"] == 1
    assert row["resolvedAt"] == ""
    assert d.loki_events == []
    assert d.state_changed is True


def test_two_clear_polls_resolves() -> None:
    fp = "ubuntu-server|cpu_busy|"
    prev = open_row(fp, missedRuns=1, timesSeen=7)
    d = decide(resp(), [prev])
    row = d.rows_to_upsert[0]
    assert row["status"] == "resolved"
    assert row["missedRuns"] == 2
    assert row["resolvedAt"] == NOW
    assert row["timesSeen"] == 7
    ev = d.loki_events[0]
    assert ev["labels"]["status"] == "resolved"
    assert ev["labels"]["category"] == "cpu"  # derived from the fingerprint qid
    assert ev["fields"]["sevScore"] == 1
    assert ev["fields"]["resolvedAt"] == NOW


def test_only_alert_prefixed_rows_are_resolved_by_poller() -> None:
    d = decide(
        resp(),
        [
            open_row("ubuntu-server|cpu_busy|", missedRuns=1, description="anomaly: cpu weird"),
        ],
    )
    assert d.rows_to_upsert == []
    assert d.loki_events == []
    assert d.state_changed is False


def test_rows_without_fingerprint_ignored() -> None:
    d = decide(resp(), [{"description": "[alert] orphan"}, {}])
    assert d.rows_to_upsert == []
    assert d.state_changed is False


def test_mixed_poll_new_plus_resolve() -> None:
    stale = open_row("ubuntu-server|mem_used|", missedRuns=1)
    d = decide(resp(alert("cpu_busy")), [stale])
    statuses = sorted(r["status"] for r in d.rows_to_upsert)
    assert statuses == ["open", "resolved"]
    assert d.state_changed is True
