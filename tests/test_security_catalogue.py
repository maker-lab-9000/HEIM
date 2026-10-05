"""Catalogue loader: every SSH line is guard-checked, every PVE path is on the
audit allowlist, HA paths pass the HA guard, ids/severities are valid."""
from pathlib import Path

import pytest
import yaml

from heim.security.catalogue import (
    PVE_AUDIT_ALLOW, CatalogueError, load_catalogue, validate_pve_path, validate_ssh_line,
)
from heim.security.types import CheckResult, Evidence, EvidenceBundle, clean_subject

ROOT = Path(__file__).resolve().parent.parent
CATALOGUE = ROOT / "config" / "security" / "checks.yaml"


def test_shipped_catalogue_loads_and_is_complete():
    cat = load_catalogue(CATALOGUE)
    assert cat.pve_node == "homelab" and cat.ssh_host == "ubuntu-server" and cat.ha_host == "home-assistant"
    ids = [c.id for c in cat.checks]
    assert len(ids) == len(set(ids)) == 47
    for c in cat.checks:
        assert c.severity in ("critical", "warning", "info")
        for s in c.sources:
            assert s in cat.sources, f"{c.id} references unknown source {s}"
    kinds = {s.kind for s in cat.sources.values()}
    assert kinds == {"pve", "ha", "prom", "ssh"}


@pytest.mark.parametrize("path", [
    "/api2/json/access/tfa", "/api2/json/cluster/firewall/rules",
    "/api2/json/nodes/homelab/qemu/103/firewall/options", "/api2/json/nodes/homelab/apt/versions",
    "/api2/json/nodes/homelab/tasks?typefilter=vzdump&limit=20", "/api2/json/nodes/homelab/journal?lastentries=1000",
])
def test_pve_audit_allowlist_accepts_read_paths(path):
    assert validate_pve_path(path) == path


@pytest.mark.parametrize("path", [
    "/api2/json/nodes/homelab/apt/update",            # needs Sys.Modify; not audit
    "/api2/json/access/users/root@pam/token",          # 403 and not wanted
    "/api2/json/nodes/homelab/qemu/100/status/stop",   # a POST target
    "/api2/json/nodes/homelab/journal?lastentries=99999",
    "/api2/json/nodes/other/status", "nodes/homelab/status", "/api2/json/nodes/homelab/../access",
])
def test_pve_audit_allowlist_rejects_everything_else(path):
    with pytest.raises(CatalogueError):
        validate_pve_path(path)


@pytest.mark.parametrize("line", [
    "sudo ss -tunlpH", "cat /etc/ssh/sshd_config", "sudo -n -l", "sudo agent-docker inspect {container}",
    "journalctl --no-pager -u ssh -u sshd --since=-7d -o cat | grep -c -E 'Failed password|Invalid user'",
    "find /etc /usr/local /opt -xdev -type f -perm -0002 2>/dev/null",
])
def test_ssh_lines_that_pass(line):
    assert validate_ssh_line(line) == line


@pytest.mark.parametrize("line", [
    "sudo cat /etc/shadow",                 # sudoers excludes sudo cat; loader refuses it too
    "sudo grep root /etc/sudoers",
    "dpkg -l", "apt list --upgradable",     # package managers are hard-denied by the guard
    "cat /etc/passwd > /tmp/x", "ls $(pwd)", "systemctl restart ssh", "sudo -n -l; rm -rf /",
])
def test_ssh_lines_that_fail(line):
    with pytest.raises(CatalogueError):
        validate_ssh_line(line)


def test_loader_rejects_a_catalogue_with_a_bad_ssh_line(tmp_path):
    data = yaml.safe_load(CATALOGUE.read_text())
    data["sources"].append({"key": "ssh.evil", "kind": "ssh", "target": "sudo cat /etc/shadow"})
    p = tmp_path / "checks.yaml"
    p.write_text(yaml.safe_dump(data))
    with pytest.raises(CatalogueError, match="ssh.evil"):
        load_catalogue(p)


def test_loader_rejects_unknown_source_reference(tmp_path):
    data = yaml.safe_load(CATALOGUE.read_text())
    data["checks"][0]["sources"] = ["pve.does_not_exist"]
    p = tmp_path / "checks.yaml"
    p.write_text(yaml.safe_dump(data))
    with pytest.raises(CatalogueError, match="does_not_exist"):
        load_catalogue(p)


def test_types_fingerprint_and_finding_shape():
    r = CheckResult("ssh.listeners_unexpected", "ubuntu-server", clean_subject("8081/docker-proxy"),
                    "fail", "warning", "docker-proxy listens on :8081", detail="0.0.0.0:8081",
                    recommendation="bind to 127.0.0.1")
    assert r.fingerprint == "ubuntu-server|ssh.listeners_unexpected|8081/docker-proxy"
    assert r.is_finding
    f = r.as_finding("new")
    assert f["metric"] == "ssh.listeners_unexpected" and f["trend"] == "new"
    assert set(f) >= {"host", "metric", "severity", "trend", "summary", "detail", "recommendation", "fingerprint"}
    assert not CheckResult("x", "h", "-", "note", "info", "fact").is_finding
    assert not CheckResult("x", "h", "-", "unavailable", "warning", "n/a").is_finding


def test_clean_subject_is_stable_and_bounded():
    assert clean_subject(" root@pam ") == "root@pam"
    assert clean_subject("a b|c") == "a_b_c"
    assert clean_subject("") == "-"
    assert len(clean_subject("x" * 200)) == 64


def test_bundle_expanded_and_missing():
    b = EvidenceBundle(items={"pve.vm_config[100]": Evidence("pve.vm_config[100]", "ok", body={}),
                              "pve.vm_config[103]": Evidence("pve.vm_config[103]", "ok", body={})})
    assert set(b.expanded("pve.vm_config")) == {"100", "103"}
    assert b.get("nope").status == "error" and not b.get("nope").usable
