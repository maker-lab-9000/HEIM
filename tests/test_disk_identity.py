"""Physical disks are identified by role, never by kernel name.

Live, 2026-10-05: the hypervisor's USB disks re-enumerated at boot, so the
Transcend SSD behind /JellyMedia became ``sdd`` while every rule still said
``sdb``. The CRC rule then watched a RAID1 Toshiba that is asleep most of the
time — it had no data to fire on, so cable-fault detection on /JellyMedia was
silently off — and its documented baseline of 115 seemed to "reset" to 0.

``sdX`` is assigned in enumeration order, which USB does not keep stable. The
fix keys identity on the disk's SERIAL: one Prometheus recording rule
(``homelab:disk_role:info``) attaches a stable ``disk`` role label, every
disk-scoped query and alert joins on it, and HEIM names a disk series after
that role so a reshuffle cannot mint a new fingerprint for the same drive.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from heim.incidents.poller_logic import _category_of_qid, _name_for
from heim.metrics.aggregate import series_name

ROOT = Path(__file__).resolve().parent.parent
ALERTS = ROOT / "prometheus" / "alerts.yml"
CATALOGUE = ROOT / "config" / "queries" / "daily.yaml"

#: a selector that pins a kernel disk name — the bug, in one regex
_KERNEL_DISK = re.compile(r'device\s*=~?\s*"(sd[a-z]|nvme\d)')


def _rules():
    doc = yaml.safe_load(ALERTS.read_text())
    return [r for g in doc["groups"] for r in g["rules"]]


def _role_rule():
    rules = [r for r in _rules() if r.get("record") == "homelab:disk_role:info"]
    assert len(rules) == 1, "exactly one recording rule owns disk identity"
    return rules[0]


# ------------------------------------------------------------ naming (HEIM)


def test_daily_path_names_a_disk_by_its_role():
    metric = {"device": "sdd", "disk": "jellymedia", "instance": "10.0.0.2:9633"}
    assert series_name(metric, {}) == "jellymedia"


def test_daily_path_is_unchanged_without_a_role():
    """Guests' disks and filesystems carry no role label — keep the old name."""
    assert series_name({"device": "sda", "mountpoint": "/"}, {}) == "sda /"
    assert series_name({"device": "vda"}, {}) == "vda"


@pytest.mark.parametrize("qid", ["drive_temp", "smart_status", "media_err", "disk_crc"])
def test_poller_names_a_disk_alert_by_its_role(qid):
    labels = {"device": "sdd", "disk": "jellymedia"}
    assert _name_for(qid, labels) == "jellymedia"


def test_poller_falls_back_to_the_device_without_a_role():
    assert _name_for("drive_temp", {"device": "sdx"}) == "sdx"


def test_disk_identity_alert_names_the_role_or_the_unmapped_device():
    assert _name_for("disk_identity", {"disk": "jellymedia"}) == "jellymedia"   # role gone
    assert _name_for("disk_identity", {"device": "sdf"}) == "sdf"               # disk unmapped


@pytest.mark.parametrize("qid", ["disk_crc", "ssd_wear", "disk_identity"])
def test_disk_qids_are_disk_health(qid):
    assert _category_of_qid(qid) == "diskHealth"


def test_a_reshuffle_does_not_change_the_fingerprint_name():
    """Same drive, new kernel name — the same name on both paths."""
    before = {"device": "sdb", "disk": "jellymedia"}
    after = {"device": "sdd", "disk": "jellymedia"}
    assert series_name(before, {}) == series_name(after, {})
    assert _name_for("disk_crc", before) == _name_for("disk_crc", after)


# -------------------------------------------- the mapping (Prometheus rule)


def test_every_role_maps_to_exactly_one_serial():
    expr = _role_rule()["expr"]
    pairs = re.findall(r'serial="([^"]+)"\}\s*,\s*"disk",\s*"([^"]+)"', expr)
    assert {role for _serial, role in pairs} == {
        "photos", "jellymedia", "raid1-a", "raid1-b", "backup", "system"}
    # The two directions of "exactly one". The nvme serial appears twice in the
    # rule on purpose (node_exporter's nvme0n1 + smartctl's nvme0), but always
    # under the same role — so compare as sets, not as list lengths.
    roles_of = {}
    serials_of = {}
    for serial, role in pairs:
        roles_of.setdefault(serial, set()).add(role)
        serials_of.setdefault(role, set()).add(serial)
    assert all(len(r) == 1 for r in roles_of.values()), f"a serial claimed by two roles: {roles_of}"
    assert all(len(s) == 1 for s in serials_of.values()), f"a role with two serials: {serials_of}"


def test_the_mapping_reads_the_kernel_view_not_smart():
    """node_disk_info exists for a sleeping disk; SMART does not. Keying the
    mapping on SMART would make every spun-down Toshiba look 'missing'."""
    expr = _role_rule()["expr"]
    assert "node_disk_info" in expr
    assert "smartctl" not in expr


def test_the_nvme_role_matches_both_exporters_device_names():
    expr = _role_rule()["expr"]
    assert '"(nvme[0-9]+)n[0-9]+"' in expr      # rewrites nvme0n1 -> nvme0 for smartctl


# --------------------------------------------------- nothing pins sdX again


def test_no_alert_rule_selects_a_disk_by_kernel_name():
    offenders = [r.get("alert") or r.get("record") for r in _rules()
                 if _KERNEL_DISK.search(r.get("expr", ""))]
    assert offenders == []


def test_no_catalogue_query_selects_a_disk_by_kernel_name():
    queries = yaml.safe_load(CATALOGUE.read_text())["queries"]
    offenders = [q["qid"] for q in queries if _KERNEL_DISK.search(q["promql"])]
    assert offenders == []


def test_disk_alerts_carry_the_role_label():
    """Every per-disk SMART alert joins on the role, so its fingerprint is
    the role and its summary names the drive a person recognises."""
    for r in _rules():
        expr = r.get("expr", "")
        if r.get("alert") and "smartctl_device" in expr:
            assert "homelab:disk_role:info" in expr, r["alert"]


def test_stale_mapping_is_alerted_both_ways():
    names = {r.get("alert") for r in _rules()}
    assert {"DiskRoleUnresolved", "DiskUnmapped"} <= names
    unresolved = next(r for r in _rules() if r.get("alert") == "DiskRoleUnresolved")
    # a dead exporter must not page as six missing disks
    assert 'up{job="proxmox-host-node-exporter"}' in unresolved["expr"]
