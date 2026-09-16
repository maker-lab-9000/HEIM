"""Golden-scenario tests for heim.incidents.state (port of PAM 51
"Compute State"). Expectations derived from
reference/pam-51-state-snapshot-loki/compute-state.js."""
from __future__ import annotations

from heim.incidents.state import category_of, compute_state, investigable
from heim.incidents.types import HostRouting

ROUTING = HostRouting(
    ssh_hosts=frozenset({"ubuntu-server"}),
    hypervisor_host="homelab",
    hypervisor_categories=frozenset({"cpu", "memory", "temperature", "disk", "diskHealth"}),
    ha_host="home-assistant",
)

ZERO_RISK = {"filesystem": 0, "diskHealth": 0, "temperature": 0,
             "memory": 0, "cpu": 0, "network": 0}


def row(fingerprint: str, host: str, metric: str, severity: str,
        investigated: object = "true") -> dict:
    return {"fingerprint": fingerprint, "host": host, "metric": metric,
            "severity": severity, "investigated": investigated}


def test_empty_rows_is_healthy():
    out = compute_state([], last_run_ms=1_700_000_000_000)
    assert out["event"] == "state"
    assert out["labels"] == {}
    f = out["fields"]
    assert f["overallHealth"] == "Healthy"
    assert f["healthScore"] == 0
    assert f["activeIncidents"] == 0
    assert f["pendingApproval"] == 0
    assert f["criticalCount"] == 0
    assert f["warnCount"] == 0
    assert f["riskByCategory"] == ZERO_RISK
    assert f["agentOk"] == 1
    assert f["agentStatus"] == "Healthy"
    assert f["lastRunStatus"] == "success"
    assert f["trigger"] == "run"


def test_mixed_rows_health_and_risk_categories():
    rows = [
        # filesystem, warn, investigated -> not pending
        row("a", "ubuntu-server", "fs_used root", "warning", "true"),
        # temperature, crit, not investigated, hypervisor cat -> pending
        row("b", "homelab", "host_temp_max", "critical", "false"),
        # network, warn, not investigated, unknown host -> not pending
        row("c", "pi-hole", "tcp retransmits", "warning", False),
        # cpu, crit (JS also accepts 'crit'), ssh host, not investigated -> pending
        row("d", "ubuntu-server", "cpu load", "crit", "false"),
    ]
    f = compute_state(rows, last_run_ms=1_700_000_000_000, routing=ROUTING)["fields"]
    assert f["activeIncidents"] == 4
    assert f["criticalCount"] == 2
    assert f["warnCount"] == 2
    assert f["overallHealth"] == "Critical"
    assert f["healthScore"] == 2
    assert f["pendingApproval"] == 2
    assert f["riskByCategory"] == {"filesystem": 1, "diskHealth": 0, "temperature": 1,
                                   "memory": 0, "cpu": 1, "network": 1}


def test_warn_only_scores_one():
    rows = [row("a", "ubuntu-server", "swap usage", "warning")]
    f = compute_state(rows, last_run_ms=0, routing=ROUTING)["fields"]
    assert f["overallHealth"] == "Warning"
    assert f["healthScore"] == 1
    assert f["criticalCount"] == 0
    assert f["warnCount"] == 1
    assert f["riskByCategory"]["memory"] == 1


def test_rows_without_fingerprint_are_ignored():
    rows = [
        {"host": "ubuntu-server", "metric": "cpu load", "severity": "critical"},
        None,
        row("a", "ubuntu-server", "cpu load", "warning"),
    ]
    f = compute_state(rows, last_run_ms=0)["fields"]
    assert f["activeIncidents"] == 1
    assert f["criticalCount"] == 0
    assert f["warnCount"] == 1


def test_other_category_not_counted_in_risk():
    # 'battery low' matches none of the category regexes -> 'other'
    f = compute_state([row("a", "x", "battery low", "warning")], last_run_ms=0)["fields"]
    assert f["riskByCategory"] == ZERO_RISK
    assert f["warnCount"] == 1


def test_last_run_ms_injection_and_timestamp():
    f = compute_state([], last_run_ms=1_700_000_000_000)["fields"]
    assert f["lastRunMs"] == 1_700_000_000_000
    assert f["lastRunTs"] == "2023-11-14T22:13:20.000Z"


def test_agent_ok_flag():
    f = compute_state([], last_run_ms=0, agent_ok=False)["fields"]
    assert f["agentOk"] == 0
    assert f["agentStatus"] == "Unhealthy"


def test_hypervisor_filesystem_maps_to_disk_for_pending():
    # cat 'filesystem' maps to 'disk' before the hypervisor-category check
    rows = [row("a", "homelab", "root fs usage", "warning", "false")]
    f = compute_state(rows, last_run_ms=0, routing=ROUTING)["fields"]
    assert f["pendingApproval"] == 1


def test_ha_host_never_pending_in_state_node():
    # Unlike the reconciler, compute-state.js has no HA branch in investigable.
    rows = [row("a", "home-assistant", "mem used", "warning", "false")]
    f = compute_state(rows, last_run_ms=0, routing=ROUTING)["fields"]
    assert f["pendingApproval"] == 0


def test_category_of_regexes():
    assert category_of("cpu_busy") == "cpu"
    assert category_of("swap used") == "memory"
    assert category_of("drive thermal") == "temperature"
    assert category_of("nvme wear") == "diskHealth"
    assert category_of("/var/log usage") == "filesystem"
    assert category_of("nic errors") == "network"
    assert category_of("battery low") == "other"
    assert category_of(None) == "other"


def test_investigable_gating():
    assert investigable("ubuntu-server", "other", ROUTING) is True
    assert investigable("homelab", "temperature", ROUTING) is True
    assert investigable("homelab", "filesystem", ROUTING) is True  # -> disk
    assert investigable("homelab", "network", ROUTING) is False
    assert investigable("pi-hole", "cpu", ROUTING) is False
