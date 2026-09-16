"""Golden-scenario tests for heim.incidents.reconcile (port of PAM 30
"Reconcile Incidents"). Expectations derived from
reference/pam-30-reconcile-incidents/reconcile.js."""
from __future__ import annotations

from heim.incidents.reconcile import (
    category_of,
    fingerprint_for,
    guest_ssh_host,
    host_role_for,
    is_investigable,
    reconcile,
    slug,
    ssh_host_for,
)
from heim.incidents.types import HostRouting

ROUTING = HostRouting(
    ssh_hosts=frozenset({"ubuntu-server"}),
    hypervisor_host="homelab",
    hypervisor_categories=frozenset({"cpu", "memory", "temperature", "disk", "diskHealth"}),
    ha_host="home-assistant",
)

RUN1 = "2026-09-16T10:00:00.000Z"
RUN2 = "2026-09-16T10:30:00.000Z"

PAYLOAD_ROWS = [
    {"host": "ubuntu-server", "qid": "fs_used", "name": "Root FS Usage", "label": "/"},
    {"host": "ubuntu-server", "qid": "swap_used", "name": "Swap", "label": "zram device"},
    {"host": "homelab", "qid": "host_temp_max", "name": "Host Temp Max", "label": "cpu"},
    {"host": "home-assistant", "qid": "mem_used", "name": "Memory Used", "label": "ha"},
]

FS_FP = "ubuntu-server|fs_used|Root FS Usage"


def finding(host: str, metric: str, severity: str = "warning", detail: str = "") -> dict:
    return {"host": host, "metric": metric, "severity": severity, "detail": detail}


def analysis_of(*findings: dict) -> dict:
    return {"findings": list(findings)}


def open_fs_row(**overrides: object) -> dict:
    row = {
        "fingerprint": FS_FP,
        "host": "ubuntu-server",
        "metric": "Root FS Usage",
        "severity": "warning",
        "status": "open",
        "firstSeen": RUN1,
        "lastSeen": RUN1,
        "resolvedAt": "",
        "timesSeen": "1",
        "missedRuns": "0",
        "description": "root fs at 91%",
        "investigated": "true",
    }
    row.update(overrides)
    return row


# ---------------------------------------------------------------- new finding

def test_new_finding_on_ssh_host_opens_and_queues():
    res = reconcile(
        analysis_of(finding("ubuntu-server", "Root FS Usage", "warning", "root fs at 91%")),
        PAYLOAD_ROWS, [], RUN1, ROUTING,
    )
    assert len(res.rows_to_write) == 1
    row = res.rows_to_write[0]
    assert row == {
        "fingerprint": FS_FP,
        "host": "ubuntu-server",
        "metric": "Root FS Usage",
        "severity": "warning",
        "status": "open",
        "firstSeen": RUN1,
        "lastSeen": RUN1,
        "resolvedAt": "",
        "timesSeen": 1,
        "missedRuns": 0,
        "description": "root fs at 91%",
        "investigated": True,
    }
    assert res.summary["counts"] == {"open": 1, "new": 1, "ongoing": 0, "clearing": 0, "resolved": 0}
    assert res.summary["new"] == [row]
    assert len(res.to_investigate) == 1
    inv = res.to_investigate[0]
    assert inv["hostRole"] == "guest"
    assert inv["sshHost"] == "ubuntu-server"
    assert inv["fingerprint"] == FS_FP


def test_info_findings_are_dropped():
    res = reconcile(
        analysis_of(finding("ubuntu-server", "Root FS Usage", "info", "fyi")),
        PAYLOAD_ROWS, [], RUN1, ROUTING,
    )
    assert res.rows_to_write == []
    assert res.to_investigate == []


def test_duplicate_fingerprint_keeps_highest_severity():
    res = reconcile(
        analysis_of(
            finding("ubuntu-server", "Root FS Usage", "warning", "warn detail"),
            finding("ubuntu-server", "Root FS Usage", "critical", "crit detail"),
        ),
        PAYLOAD_ROWS, [], RUN1, ROUTING,
    )
    assert len(res.rows_to_write) == 1
    assert res.rows_to_write[0]["severity"] == "critical"
    assert res.rows_to_write[0]["description"] == "crit detail"


# ------------------------------------------------------------------- ongoing

def test_same_finding_next_run_is_ongoing_not_requeued():
    res = reconcile(
        analysis_of(finding("ubuntu-server", "Root FS Usage", "warning", "root fs at 92%")),
        PAYLOAD_ROWS, [open_fs_row()], RUN2, ROUTING,
    )
    assert len(res.rows_to_write) == 1
    row = res.rows_to_write[0]
    assert row["status"] == "open"
    assert row["timesSeen"] == 2
    assert row["missedRuns"] == 0
    assert row["firstSeen"] == RUN1
    assert row["lastSeen"] == RUN2
    assert row["investigated"] is True  # dispatch lock kept
    assert res.to_investigate == []  # NOT re-queued
    assert res.summary["counts"] == {"open": 1, "new": 0, "ongoing": 1, "clearing": 0, "resolved": 0}
    assert res.summary["ongoing"][0]["escalated"] is False


# --------------------------------------------------------- clearing/resolved

def test_unseen_one_run_is_clearing_still_open():
    res = reconcile(analysis_of(), PAYLOAD_ROWS, [open_fs_row()], RUN2, ROUTING)
    assert len(res.rows_to_write) == 1
    row = res.rows_to_write[0]
    assert row["status"] == "open"
    assert row["missedRuns"] == 1
    assert row["resolvedAt"] == ""
    assert row["timesSeen"] == 1
    assert row["investigated"] is True
    assert res.summary["counts"] == {"open": 1, "new": 0, "ongoing": 0, "clearing": 1, "resolved": 0}


def test_unseen_two_consecutive_runs_resolves():
    res = reconcile(
        analysis_of(), PAYLOAD_ROWS, [open_fs_row(missedRuns="1")], RUN2, ROUTING,
    )
    assert len(res.rows_to_write) == 1
    row = res.rows_to_write[0]
    assert row["status"] == "resolved"
    assert row["missedRuns"] == 2
    assert row["resolvedAt"] == RUN2
    assert res.summary["counts"] == {"open": 0, "new": 0, "ongoing": 0, "clearing": 0, "resolved": 1}


def test_reappearing_finding_resets_missed_runs():
    res = reconcile(
        analysis_of(finding("ubuntu-server", "Root FS Usage", "warning", "back again")),
        PAYLOAD_ROWS, [open_fs_row(missedRuns="1")], RUN2, ROUTING,
    )
    row = res.rows_to_write[0]
    assert row["status"] == "open"
    assert row["missedRuns"] == 0
    assert row["timesSeen"] == 2


# ------------------------------------------------------------- re-dispatches

def test_warn_to_crit_escalation_requeues():
    res = reconcile(
        analysis_of(finding("ubuntu-server", "Root FS Usage", "critical", "root fs at 97%")),
        PAYLOAD_ROWS, [open_fs_row(investigated="true")], RUN2, ROUTING,
    )
    row = res.rows_to_write[0]
    assert row["severity"] == "critical"
    assert row["investigated"] is True
    assert res.summary["ongoing"][0]["escalated"] is True
    assert len(res.to_investigate) == 1
    assert res.to_investigate[0]["fingerprint"] == FS_FP


def test_declined_investigation_is_requeued_without_escalation():
    res = reconcile(
        analysis_of(finding("ubuntu-server", "Root FS Usage", "warning", "root fs at 91%")),
        PAYLOAD_ROWS, [open_fs_row(investigated="false")], RUN2, ROUTING,
    )
    row = res.rows_to_write[0]
    assert row["investigated"] is True  # locked once dispatched
    assert res.summary["ongoing"][0]["escalated"] is False
    assert len(res.to_investigate) == 1


# ------------------------------------------------------------- fingerprints

def test_fingerprint_anchors_to_matching_payload_row():
    fp = fingerprint_for({"host": "ubuntu-server", "metric": "Root FS Usage"}, PAYLOAD_ROWS)
    assert fp == "ubuntu-server|fs_used|Root FS Usage"


def test_fingerprint_falls_back_to_slug_when_no_match():
    fp = fingerprint_for({"host": "ubuntu-server", "metric": "Mystery Metric"}, PAYLOAD_ROWS)
    assert fp == "ubuntu-server|metric-mystery"  # slug words are sorted


def test_fingerprint_score_below_two_falls_back():
    # 'zram' overlaps only the label of the swap row -> score 1 < 2 -> fallback.
    fp = fingerprint_for({"host": "ubuntu-server", "metric": "zram growth"}, PAYLOAD_ROWS)
    assert fp == "ubuntu-server|growth-zram"


def test_fingerprint_skips_rows_from_other_hosts():
    # ubuntu-server's fs row would match, but the finding is on homelab.
    fp = fingerprint_for({"host": "homelab", "metric": "Root FS Usage"}, PAYLOAD_ROWS)
    assert fp == "homelab|fs-root-usage"


def test_fingerprint_anchoring_is_deterministic_in_reconcile():
    res = reconcile(
        analysis_of(
            finding("ubuntu-server", "Root FS Usage", "warning", "matched"),
            finding("ubuntu-server", "Mystery Metric", "warning", "unmatched"),
        ),
        PAYLOAD_ROWS, [], RUN1, ROUTING,
    )
    fps = [r["fingerprint"] for r in res.rows_to_write]
    assert fps == ["ubuntu-server|fs_used|Root FS Usage", "ubuntu-server|metric-mystery"]


# ------------------------------------------------------------- host routing

def test_hypervisor_investigable_category_is_queued():
    res = reconcile(
        analysis_of(finding("homelab", "Host Temp Max", "warning", "cpu temp 92C")),
        PAYLOAD_ROWS, [], RUN1, ROUTING,
    )
    row = res.rows_to_write[0]
    assert row["fingerprint"] == "homelab|host_temp_max|Host Temp Max"
    assert row["investigated"] is True
    assert len(res.to_investigate) == 1
    inv = res.to_investigate[0]
    assert inv["hostRole"] == "hypervisor"
    assert inv["sshHost"] == "ubuntu-server"  # investigated via the guest SSH host


def test_hypervisor_non_investigable_category_is_not_queued():
    res = reconcile(
        analysis_of(finding("homelab", "NIC RX Errors", "warning", "eth0 rx errors climbing")),
        PAYLOAD_ROWS, [], RUN1, ROUTING,
    )
    row = res.rows_to_write[0]
    assert row["fingerprint"] == "homelab|errors-nic-rx"
    assert row["investigated"] is False
    assert res.to_investigate == []
    assert res.summary["counts"]["new"] == 1  # still tracked as an incident


def test_ha_host_finding_queued_with_ha_guest_role_and_empty_ssh_host():
    res = reconcile(
        analysis_of(finding("home-assistant", "HA Memory Used", "critical", "ha mem 95%")),
        PAYLOAD_ROWS, [], RUN1, ROUTING,
    )
    row = res.rows_to_write[0]
    assert row["fingerprint"] == "home-assistant|mem_used|Memory Used"
    assert row["investigated"] is True
    assert len(res.to_investigate) == 1
    inv = res.to_investigate[0]
    assert inv["hostRole"] == "ha-guest"
    assert inv["sshHost"] == ""


def test_unknown_host_is_never_investigable():
    res = reconcile(
        analysis_of(finding("pi-hole", "CPU Busy", "critical", "cpu pegged")),
        PAYLOAD_ROWS, [], RUN1, ROUTING,
    )
    assert res.rows_to_write[0]["investigated"] is False
    assert res.to_investigate == []


# ------------------------------------------------------------------- helpers

def test_slug_sorts_words():
    assert slug("Root FS Usage") == "fs-root-usage"
    assert slug(None) == ""


def test_category_of_prefers_fingerprint_qid():
    assert category_of("home-assistant|mem_used|Memory Used", "anything", "at all") == "memory"
    assert category_of("homelab|host_temp_max|Host Temp Max", "", "") == "temperature"


def test_category_of_falls_back_to_text_keywords():
    assert category_of("h|two-parts-only", "cpu load high", "") == "cpu"  # no qid segment
    assert category_of("h|x", "eth0 rx errors", "packet loss") == "other"


def test_is_investigable_gating():
    assert is_investigable("x|y", "ubuntu-server", "anything", "", ROUTING) is True
    assert is_investigable("x|y", "home-assistant", "anything", "", ROUTING) is True
    assert is_investigable("h|host_temp_max|n", "homelab", "", "", ROUTING) is True
    assert is_investigable("x|y", "homelab", "eth0 rx errors", "", ROUTING) is False
    assert is_investigable("x|y", "pi-hole", "cpu load", "", ROUTING) is False


def test_host_role_and_ssh_host_helpers():
    assert host_role_for("homelab", ROUTING) == "hypervisor"
    assert host_role_for("home-assistant", ROUTING) == "ha-guest"
    assert host_role_for("ubuntu-server", ROUTING) == "guest"
    assert ssh_host_for("ubuntu-server", ROUTING) == "ubuntu-server"
    assert ssh_host_for("home-assistant", ROUTING) == ""
    assert ssh_host_for("homelab", ROUTING) == "ubuntu-server"
    assert guest_ssh_host(ROUTING) == "ubuntu-server"
    assert guest_ssh_host(HostRouting()) == ""
