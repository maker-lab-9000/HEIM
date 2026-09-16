"""Tests for heim.metrics.aggregate (port of the n8n "Aggregate & Summarize" node).

Expectations are derived from reference/pam-10-daily-analysis/aggregate-summarize.js.
"""

from datetime import datetime, timezone

from heim.metrics.aggregate import aggregate as _aggregate

# The JS hardcoded this map; the port takes it as a parameter. Bind it here so
# the golden tests keep matching the JS behavior verbatim.
_JS_HOST_MAP = {
    "192.168.178.241": "ubuntu-server",
    "192.168.178.2": "homelab",
    "192.168.178.137": "home-assistant",
}


def aggregate(results, now=None):
    return _aggregate(results, now=now, instance_host_map=_JS_HOST_MAP)

DAY = 86400
NOW = datetime(2026, 1, 10, 6, 0, 0, tzinfo=timezone.utc)


def make_query(**over):
    base = {
        "qid": "q1",
        "category": "CPU",
        "label": "Test metric",
        "unit": "%",
        "dir": "high",
        "warn": 80,
        "crit": 95,
        "promql": "up",
    }
    base.update(over)
    return base


def series(metric, points):
    return {"metric": metric, "values": [[t, str(v)] for t, v in points]}


def matrix(*result):
    return {"status": "success", "data": {"resultType": "matrix", "result": list(result)}}


def item(query, data=None, error=None):
    return {"query": query, "data": data, "error": error}


UBUNTU = {"instance": "192.168.178.241:9100"}
HOMELAB = {"instance": "192.168.178.2:9100"}
HA = {"instance": "192.168.178.137:8123"}


def flat(metric, value):
    """A two-sample flat series (changePct 0)."""
    return series(metric, [(0, value), (DAY, value)])


# ---------------------------------------------------------------- flagging


def test_flags_dir_high():
    out = aggregate(
        [
            item(make_query(qid="ok_q"), matrix(flat(UBUNTU, 50))),
            item(make_query(qid="warn_q"), matrix(flat(UBUNTU, 85))),
            item(make_query(qid="crit_q"), matrix(flat(UBUNTU, 96))),
        ],
        now=NOW,
    )
    rows = {r["qid"]: r for r in out["payload"]["categories"]["CPU"]}
    assert rows["ok_q"]["flag"] == "ok"
    assert rows["warn_q"]["flag"] == "warn"
    assert rows["crit_q"]["flag"] == "crit"
    assert out["payload"]["counts"] == {"crit": 1, "warn": 1, "naQueries": 0}
    assert out["payload"]["overall"] == "critical"
    # crit alert sorts before warn alert.
    assert [a["sev"] for a in out["alerts"]] == ["crit", "warn"]
    assert out["payload"]["topAlerts"] == out["alerts"]


def test_flags_dir_high_boundaries_inclusive():
    # JS: cur >= crit -> crit; cur >= warn -> warn.
    out = aggregate(
        [
            item(make_query(qid="at_warn"), matrix(flat(UBUNTU, 80))),
            item(make_query(qid="at_crit"), matrix(flat(UBUNTU, 95))),
        ],
        now=NOW,
    )
    rows = {r["qid"]: r for r in out["payload"]["categories"]["CPU"]}
    assert rows["at_warn"]["flag"] == "warn"
    assert rows["at_crit"]["flag"] == "crit"


def test_flags_dir_low():
    q = make_query(dir="low", warn=30, crit=10, category="Disk Health")
    out = aggregate(
        [
            item(dict(q, qid="crit_q"), matrix(flat(UBUNTU, 5))),
            item(dict(q, qid="crit_at"), matrix(flat(UBUNTU, 10))),  # <= crit
            item(dict(q, qid="warn_q"), matrix(flat(UBUNTU, 25))),
            item(dict(q, qid="ok_q"), matrix(flat(UBUNTU, 50))),
        ],
        now=NOW,
    )
    rows = {r["qid"]: r for r in out["payload"]["categories"]["Disk Health"]}
    assert rows["crit_q"]["flag"] == "crit"
    assert rows["crit_at"]["flag"] == "crit"
    assert rows["warn_q"]["flag"] == "warn"
    assert rows["ok_q"]["flag"] == "ok"
    assert out["payload"]["counts"] == {"crit": 2, "warn": 1, "naQueries": 0}


def test_flags_one_zero_info():
    out = aggregate(
        [
            item(make_query(qid="one_ok", dir="one"), matrix(flat(UBUNTU, 1))),
            item(make_query(qid="one_bad", dir="one"), matrix(flat(UBUNTU, 0))),
            item(make_query(qid="zero_ok", dir="zero"), matrix(flat(UBUNTU, 0))),
            item(make_query(qid="zero_bad", dir="zero"), matrix(flat(UBUNTU, 1))),
            item(make_query(qid="info_q", dir="info"), matrix(flat(UBUNTU, 12345))),
        ],
        now=NOW,
    )
    rows = {r["qid"]: r for r in out["payload"]["categories"]["CPU"]}
    assert rows["one_ok"]["flag"] == "ok"
    assert rows["one_bad"]["flag"] == "crit"
    assert rows["zero_ok"]["flag"] == "ok"
    assert rows["zero_bad"]["flag"] == "crit"
    assert rows["info_q"]["flag"] == "ok"


# ------------------------------------------------------- stats and change %


def test_per_day_averages_and_stats():
    pts = [
        (0, 10),            # age 3.0d  -> bucket 0
        (DAY // 2, 20),     # age 2.5d  -> bucket 0
        (DAY, 30),          # age 2.0d  -> bucket 0
        (DAY + DAY // 2, 40),   # age 1.5d -> bucket 1
        (2 * DAY, 50),      # age 1.0d  -> bucket 1
        (2 * DAY + DAY // 2, 60),  # age 0.5d -> bucket 2
        (3 * DAY, 70),      # age 0.0d  -> bucket 2
    ]
    out = aggregate(
        [item(make_query(dir="info"), matrix(series(UBUNTU, pts)))], now=NOW
    )
    (row,) = out["payload"]["categories"]["CPU"]
    assert row["day3d"] == [20.0, 45.0, 65.0]
    assert row["current"] == 70.0
    assert row["avg"] == 40.0
    assert row["min"] == 10.0
    assert row["max"] == 70.0
    # change % first -> current: (70 - 10) / 10 * 100
    assert row["changePct"] == 600.0


def test_change_pct_rounding_and_zero_first():
    out = aggregate(
        [
            item(
                make_query(qid="down", dir="info"),
                matrix(series(UBUNTU, [(0, 3), (DAY, 1)])),
            ),
            item(
                make_query(qid="from_zero", dir="info"),
                matrix(series(UBUNTU, [(0, 0), (DAY, 5)])),
            ),
            item(
                make_query(qid="all_zero", dir="info"),
                matrix(series(UBUNTU, [(0, 0), (DAY, 0)])),
            ),
        ],
        now=NOW,
    )
    rows = {r["qid"]: r for r in out["payload"]["categories"]["CPU"]}
    # (1 - 3) / |3| * 100 = -66.666... -> toFixed(1) -> -66.7
    assert rows["down"]["changePct"] == -66.7
    # JS: first === 0 -> 100 if cur != 0 else 0.
    assert rows["from_zero"]["changePct"] == 100
    assert rows["all_zero"]["changePct"] == 0


def test_change_pct_null_for_state_and_online_units():
    out = aggregate(
        [
            item(
                make_query(qid="pool", dir="one", unit="online", category="Proxmox"),
                matrix(series(HOMELAB, [(0, 0), (DAY, 1)])),
            )
        ],
        now=NOW,
    )
    (row,) = out["payload"]["categories"]["Proxmox"]
    assert row["changePct"] is None
    assert row["flag"] == "ok"


# ------------------------------------------------------------- degradation


def test_errored_query_degrades_gracefully():
    out = aggregate(
        [
            item(make_query(qid="dead"), data=None, error="connection timeout"),
            item(make_query(qid="bad_status"), data={"status": "error", "data": None}),
            item(make_query(qid="alive"), matrix(flat(UBUNTU, 10))),
        ],
        now=NOW,
    )
    assert out["payload"]["counts"] == {"crit": 0, "warn": 0, "naQueries": 2}
    assert out["payload"]["overall"] == "healthy"
    rows = out["payload"]["categories"]["CPU"]
    assert [r["qid"] for r in rows] == ["alive"]
    assert out["alerts"] == []


# ----------------------------------------------------- hosts, names, guests


def test_multi_instance_series_become_per_host_rows():
    out = aggregate(
        [
            item(
                make_query(dir="info"),
                matrix(flat(UBUNTU, 1), flat(HOMELAB, 2), flat(HA, 3)),
            )
        ],
        now=NOW,
    )
    rows = out["payload"]["categories"]["CPU"]
    assert {r["host"] for r in rows} == {"ubuntu-server", "homelab", "home-assistant"}
    assert out["payload"]["hosts"] == ["home-assistant", "homelab", "ubuntu-server"]


def test_series_name_from_device_and_veth_skipped_on_ubuntu_server():
    out = aggregate(
        [
            item(
                make_query(dir="info", category="Network"),
                matrix(
                    flat({**UBUNTU, "device": "veth0abc"}, 1),  # skipped
                    flat({**UBUNTU, "device": "eth0"}, 2),
                    flat({**HOMELAB, "device": "veth9"}, 3),  # veth kept off ubuntu
                ),
            )
        ],
        now=NOW,
    )
    rows = out["payload"]["categories"]["Network"]
    assert [(r["host"], r["name"]) for r in rows] == [
        ("ubuntu-server", "eth0"),
        ("homelab", "veth9"),
    ]


def test_guest_names_vmup_and_storage_names():
    guest_info = item(
        make_query(qid="pve_guest_info", dir="info", category="Proxmox"),
        matrix(series({"id": "qemu/101", "name": "vm-docker"}, [(0, 1)])),
    )
    vm_up = item(
        make_query(
            qid="pve_vm_up", dir="vmup", unit="state", category="Proxmox", warn=0, crit=0
        ),
        matrix(
            series({"id": "qemu/101", "instance": "192.168.178.2:9221"}, [(0, 1), (DAY, 1)]),
            series({"id": "qemu/102", "instance": "192.168.178.2:9221"}, [(0, 1), (DAY, 0)]),
        ),
    )
    pool_up = item(
        make_query(qid="pve_pool_up", dir="one", unit="online", category="Proxmox"),
        matrix(series({"id": "storage/homelab/local-zfs", "instance": "192.168.178.2:9221"}, [(0, 1)])),
    )
    out = aggregate([guest_info, vm_up, pool_up], now=NOW)
    rows = {(r["qid"], r["host"]): r for r in out["payload"]["categories"]["Proxmox"]}

    # pve_guest_info itself produces no rows.
    assert all(qid != "pve_guest_info" for qid, _ in rows)
    # qemu/* host becomes the guest name (or raw id if unknown); name blanked.
    named = rows[("pve_vm_up", "vm-docker")]
    assert named["name"] == ""
    assert named["flag"] == "ok"
    assert named["changePct"] is None  # unit 'state'
    unknown = rows[("pve_vm_up", "qemu/102")]
    assert unknown["flag"] == "na"  # vmup with cur < 1 -> na, not crit
    # 'na' rows count in no alert bucket.
    assert out["payload"]["counts"] == {"crit": 0, "warn": 0, "naQueries": 0}
    # storage/* id -> last path segment as name, host from instance.
    pool = rows[("pve_pool_up", "homelab")]
    assert pool["name"] == "local-zfs"


# ------------------------------------------------------------- alert order


def test_top_alerts_sorted_by_severity_then_abs_change():
    q = make_query(dir="high", warn=10, crit=1000)
    out = aggregate(
        [
            item(
                dict(q, qid="warn_small"),
                matrix(series(UBUNTU, [(0, 10), (DAY, 15)])),  # +50%
            ),
            item(
                dict(q, qid="warn_big"),
                matrix(series(HOMELAB, [(0, 50), (DAY, 15)])),  # -70%
            ),
            item(
                dict(q, qid="crit_flat"),
                matrix(flat(HA, 2000)),  # crit, changePct 0
            ),
        ],
        now=NOW,
    )
    assert [(a["sev"], a["qid"]) for a in out["alerts"]] == [
        ("crit", "crit_flat"),
        ("warn", "warn_big"),
        ("warn", "warn_small"),
    ]
    assert out["alerts"][1]["changePct"] == -70.0
    assert out["alerts"][2]["changePct"] == 50.0


def test_top_alerts_capped_at_15():
    q = make_query(dir="high", warn=1, crit=1000)
    items = [
        item(dict(q, qid=f"w{i}"), matrix(flat(UBUNTU, 5))) for i in range(20)
    ]
    out = aggregate(items, now=NOW)
    assert len(out["alerts"]) == 20
    assert len(out["payload"]["topAlerts"]) == 15


# ------------------------------------------------------------ output shape


def test_payload_and_row_shape():
    out = aggregate([item(make_query(), matrix(flat(UBUNTU, 50)))], now=NOW)
    assert set(out) == {"payload", "alerts"}
    payload = out["payload"]
    assert set(payload) == {
        "generatedAt",
        "windowDays",
        "hosts",
        "counts",
        "overall",
        "categories",
        "topAlerts",
    }
    assert payload["windowDays"] == 3
    assert payload["generatedAt"] == "2026-01-10T06:00:00.000+00:00"
    (row,) = payload["categories"]["CPU"]
    assert set(row) == {
        "host",
        "label",
        "name",
        "unit",
        "qid",
        "category",
        "current",
        "avg",
        "min",
        "max",
        "day3d",
        "changePct",
        "flag",
    }
