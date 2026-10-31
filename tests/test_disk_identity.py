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

The rule and the alerts live in the ansible-homelab repo
(``stacks/ubuntu-server/prometheus/alerts.yml``), and that repo tests them:
``make guards`` holds the mapping's shape and the "no sdX in a rule" ban,
``make alerts`` runs promtool over the mapping and every disk alert. This
file covers HEIM's half: the catalogue's queries and how HEIM names a disk.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from heim.incidents.poller_logic import _category_of_qid, _name_for
from heim.metrics.aggregate import series_name

ROOT = Path(__file__).resolve().parent.parent
CATALOGUE = ROOT / "config" / "queries" / "daily.yaml"

#: a selector that pins a kernel disk name — the bug, in one regex
_KERNEL_DISK = re.compile(r'device\s*=~?\s*"(sd[a-z]|nvme\d)')

#: The qid of every per-disk alert in ansible-homelab's alerts.yml — the
#: contract with that repo. Each carries the `disk` role label.
DISK_ALERT_QIDS = (
    "smart_status", "smart_selftest", "smart_at_thresh", "smart_near_thresh",
    "smart_bad_sectors", "smart_bad_sectors_growing", "smart_realloc",
    "smart_err_counters", "smart_err_log", "disk_crc", "media_err", "nvme_crit",
    "nvme_wear", "nvme_spare", "ssd_life", "ssd_spare", "drive_temp",
)


# ------------------------------------------------------------ naming (HEIM)


def test_daily_path_names_a_disk_by_its_role():
    metric = {"device": "sdd", "disk": "jellymedia", "instance": "10.0.0.2:9633"}
    assert series_name(metric, {}) == "jellymedia"


def test_daily_path_is_unchanged_without_a_role():
    """Guests' disks and filesystems carry no role label — keep the old name."""
    assert series_name({"device": "sda", "mountpoint": "/"}, {}) == "sda /"
    assert series_name({"device": "vda"}, {}) == "vda"


@pytest.mark.parametrize("qid", DISK_ALERT_QIDS)
def test_poller_names_a_disk_alert_by_its_role(qid):
    labels = {"device": "sdd", "disk": "jellymedia"}
    assert _name_for(qid, labels) == "jellymedia"


@pytest.mark.parametrize("qid", DISK_ALERT_QIDS)
def test_two_disks_firing_one_alert_stay_two_incidents(qid):
    """An empty name would give both disks the fingerprint homelab|qid| —
    one incident for two failing drives, resolved when either recovers."""
    assert _name_for(qid, {"device": "sda", "disk": "photos"}) != \
        _name_for(qid, {"device": "sdd", "disk": "jellymedia"})


def test_poller_falls_back_to_the_device_without_a_role():
    assert _name_for("drive_temp", {"device": "sdx"}) == "sdx"
    assert _name_for("ssd_spare", {"device": "sdx"}) == "sdx"


def test_disk_identity_alert_names_the_role_or_the_unmapped_device():
    assert _name_for("disk_identity", {"disk": "jellymedia"}) == "jellymedia"   # role gone
    assert _name_for("disk_identity", {"device": "sdf"}) == "sdf"               # disk unmapped


@pytest.mark.parametrize("qid", [q for q in DISK_ALERT_QIDS if q != "drive_temp"] + ["ssd_wear", "disk_identity"])
def test_disk_qids_are_disk_health(qid):
    """diskHealth is an investigable hypervisor category; 'other' never is."""
    assert _category_of_qid(qid) == "diskHealth"


def test_drive_temperature_stays_a_temperature():
    assert _category_of_qid("drive_temp") == "temperature"


def test_a_reshuffle_does_not_change_the_fingerprint_name():
    """Same drive, new kernel name — the same name on both paths."""
    before = {"device": "sdb", "disk": "jellymedia"}
    after = {"device": "sdd", "disk": "jellymedia"}
    assert series_name(before, {}) == series_name(after, {})
    assert _name_for("disk_crc", before) == _name_for("disk_crc", after)


# --------------------------------------------------- nothing pins sdX again


def test_no_catalogue_query_selects_a_disk_by_kernel_name():
    queries = yaml.safe_load(CATALOGUE.read_text())["queries"]
    offenders = [q["qid"] for q in queries if _KERNEL_DISK.search(q["promql"])]
    assert offenders == []


def test_disk_scoped_catalogue_queries_join_the_role():
    """The hypervisor's SMART rows reach HEIM only through the role join, so
    a missing homelab:disk_role:info rule shows up as no disk-health rows."""
    queries = {q["qid"]: q for q in yaml.safe_load(CATALOGUE.read_text())["queries"]}
    for qid in ("smart_status", "ssd_wear", "disk_crc"):
        assert "homelab:disk_role:info" in queries[qid]["promql"], qid
