"""Tests for the Proxmox response formatter port.

Expectations derived from the ``Format Output`` n8n Code node
(``reference/pam-44-proxmox-api/format-output.js``).
"""

from __future__ import annotations

import json

from heim.metrics.proxmox_format import format_proxmox_output

TASKS_PATH = "/api2/json/nodes/homelab/tasks?typefilter=vzdump&limit=20"
BARE_TASKS_PATH = "/api2/json/nodes/homelab/tasks"
LOG_PATH = (
    "/api2/json/nodes/homelab/tasks/"
    "UPID:homelab:0004F1A2:000A3B7C:65F01234:vzdump:100:root@pam:/log"
)

# 1700000000 -> 2023-11-14T22:13:20Z
TASKS_BODY = json.dumps(
    {
        "data": [
            {
                # OK backup task: upid kept (vzdump type), user dropped (root@pam),
                # node/pid/pstart dropped, epochs converted, durationSec added.
                "upid": "UPID:homelab:1:1:1:vzdump:100:root@pam:",
                "type": "vzdump",
                "id": "100",
                "status": "OK",
                "starttime": 1700000000,
                "endtime": 1700000300,
                "user": "root@pam",
                "node": "homelab",
                "pid": 1234,
                "pstart": 99,
            },
            {
                # failed non-backup task: upid kept (status != OK), user kept
                # (!= root@pam), no id key -> omitted, no endtime -> no end/duration.
                "upid": "UPID:homelab:2:2:2:qmstart:101:admin@pve:",
                "type": "qmstart",
                "status": "stopped: unexpected exit",
                "starttime": 1700000100,
                "user": "admin@pve",
                "node": "homelab",
                "pid": 5678,
            },
            {
                # OK non-backup task: upid dropped, user (root@pam) dropped.
                "upid": "UPID:homelab:3:3:3:qmstart:102:root@pam:",
                "type": "qmstart",
                "id": "102",
                "status": "OK",
                "starttime": 1700000100,
                "endtime": 1700000160,
                "user": "root@pam",
            },
        ],
        "total": 57,
    }
)


def test_tasks_list_is_compacted() -> None:
    out = format_proxmox_output(TASKS_PATH, TASKS_BODY)
    parsed = json.loads(out)
    assert parsed["total"] == 57
    assert (
        parsed["note"]
        == "epoch times converted to UTC ISO; upid included only for backup-type or failed tasks (needed for /tasks/<upid>/log)"
    )
    t1, t2, t3 = parsed["tasks"]

    assert t1 == {
        "type": "vzdump",
        "id": "100",
        "status": "OK",
        "start": "2023-11-14T22:13:20Z",
        "end": "2023-11-14T22:18:20Z",
        "durationSec": 300,
        "upid": "UPID:homelab:1:1:1:vzdump:100:root@pam:",
    }
    assert t2 == {
        "type": "qmstart",
        "status": "stopped: unexpected exit",
        "start": "2023-11-14T22:15:00Z",
        "user": "admin@pve",
        "upid": "UPID:homelab:2:2:2:qmstart:101:admin@pve:",
    }
    assert t3 == {
        "type": "qmstart",
        "id": "102",
        "status": "OK",
        "start": "2023-11-14T22:15:00Z",
        "end": "2023-11-14T22:16:00Z",
        "durationSec": 60,
    }
    # dropped noise fields never reappear anywhere
    assert '"node"' not in out
    assert '"pid"' not in out
    assert '"pstart"' not in out


def test_tasks_list_matches_bare_tasks_path_too() -> None:
    out = format_proxmox_output(BARE_TASKS_PATH, TASKS_BODY)
    assert json.loads(out)["total"] == 57


def test_tasks_total_falls_back_to_task_count() -> None:
    body = json.dumps({"data": [{"type": "vzdump", "status": "OK", "starttime": 1700000000}]})
    parsed = json.loads(format_proxmox_output(TASKS_PATH, body))
    assert parsed["total"] == 1
    # no endtime -> no end/durationSec; no upid key -> omitted
    assert parsed["tasks"][0] == {
        "type": "vzdump",
        "status": "OK",
        "start": "2023-11-14T22:13:20Z",
    }


def test_missing_starttime_yields_null_start() -> None:
    body = json.dumps({"data": [{"type": "vzdump", "status": "OK"}]})
    parsed = json.loads(format_proxmox_output(TASKS_PATH, body))
    assert parsed["tasks"][0]["start"] is None


def test_task_log_response_passes_through() -> None:
    body = json.dumps({"data": [{"n": 1, "t": "INFO: starting backup"}]})
    assert format_proxmox_output(LOG_PATH, body) == body


def test_non_tasks_path_passes_through() -> None:
    body = json.dumps({"data": {"uptime": 12345, "cpu": 0.02}})
    assert format_proxmox_output("/api2/json/nodes/homelab/status", body) == body


def test_malformed_json_passes_through() -> None:
    body = "pveproxy: 501 no such resource {oops"
    assert format_proxmox_output(TASKS_PATH, body) == body


def test_tasks_data_not_a_list_passes_through() -> None:
    body = json.dumps({"data": {"not": "a list"}})
    assert format_proxmox_output(TASKS_PATH, body) == body


def test_oversize_body_clipped_to_default() -> None:
    body = "x" * 9000
    out = format_proxmox_output("/api2/json/nodes/homelab/syslog", body)
    assert out == "x" * 8192 + " ...[truncated]"


def test_body_at_clip_limit_not_truncated() -> None:
    body = "x" * 8192
    assert format_proxmox_output("/api2/json/nodes/homelab/syslog", body) == body


def test_custom_clip() -> None:
    out = format_proxmox_output("/api2/json/version", "abcdefghijk", clip=10)
    assert out == "abcdefghij ...[truncated]"


def test_clip_applies_after_compaction() -> None:
    out = format_proxmox_output(TASKS_PATH, TASKS_BODY, clip=50)
    assert out.endswith(" ...[truncated]")
    assert len(out) == 50 + len(" ...[truncated]")
    assert out.startswith('{"total":57,"tasks":')
