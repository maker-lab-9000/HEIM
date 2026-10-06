"""Proxmox evaluators + the evaluation core (control rule, per-check isolation)."""
from datetime import datetime, timezone
from pathlib import Path

from heim.security.catalogue import load_catalogue
from heim.security.evaluate import EvalContext, evaluate, gate_sources
from heim.security.types import Evidence, EvidenceBundle

CAT = load_catalogue(Path(__file__).resolve().parent.parent / "config" / "security" / "checks.yaml")
NOW = datetime(2026, 9, 28, 6, 0, tzinfo=timezone.utc)


def ctx(**kw) -> EvalContext:
    base = dict(now=NOW, instance_host_map={"10.0.0.2": "homelab", "10.0.0.10": "ubuntu-server", "10.0.0.4": "heim"},
                hosts=("heim", "home-assistant", "homelab", "ubuntu-server"), pve_node="homelab",
                ssh_host="ubuntu-server", ha_host="home-assistant", expected_offline_vms=("monitor-box",))
    base.update(kw)
    return EvalContext(**base)


def ev(key, body, status="ok", **kw) -> Evidence:
    return Evidence(key, status, body=body, **kw)


def bundle(*items: Evidence) -> EvidenceBundle:
    return EvidenceBundle(items={e.key: e for e in items})


def results_for(check_id, b: EvidenceBundle, c: EvalContext | None = None):
    return [r for r in evaluate(CAT, b, c or ctx()) if r.check_id == check_id]


USERS = [{"userid": "root@pam", "enable": 1}, {"userid": "auditor@pve", "enable": 1}, {"userid": "exporter@pve", "enable": 1}]


def test_tfa_missing_flags_root_only_when_control_proves_empty_is_genuine():
    b = bundle(ev("pve.access_tfa", [], status="empty"), ev("pve.access_users", USERS))
    rows = results_for("pve.tfa_missing", b)
    fails = [r for r in rows if r.status == "fail"]
    assert [r.subject for r in fails] == ["root@pam"] and fails[0].fingerprint == "homelab|pve.tfa_missing|root@pam"
    assert {r.subject for r in rows if r.status == "note"} == {"auditor@pve", "exporter@pve"}


def test_empty_list_without_a_working_control_is_unavailable_not_ok():
    b = bundle(ev("pve.access_tfa", [], status="empty"), ev("pve.access_users", None, status="denied", detail="HTTP 403"))
    rows = results_for("pve.tfa_missing", b)
    assert len(rows) == 1 and rows[0].status == "unavailable" and "not permitted" in rows[0].detail


def test_gate_sources_reports_missing_and_denied():
    spec = CAT.check("pve.acl_privileged")
    assert "not collected" in gate_sources(spec, CAT, bundle())
    b = bundle(ev("pve.access_acl", [], "empty"), ev("pve.access_roles", []), ev("pve.access_users", USERS))
    assert gate_sources(spec, CAT, b) == ""


def test_firewall_disabled_cluster_fail_and_vm_notes():
    b = bundle(ev("pve.fw_cluster_options", {"digest": "x"}), ev("pve.fw_cluster_rules", [], "empty"),
               ev("pve.fw_node_options", {"digest": "y"}), ev("pve.fw_node_rules", [], "empty"),
               ev("pve.fw_vm_options[100]", {"digest": "z"}), ev("pve.vm_config[100]", {"net0": "virtio=AA,bridge=vmbr0,firewall=1"}),
               ev("pve.resources_vm", [{"vmid": 100, "name": "ubuntu-server", "status": "running", "type": "qemu"}]))
    rows = results_for("pve.firewall_disabled", b)
    assert any(r.status == "fail" and r.subject == "cluster" and r.host == "homelab" for r in rows)
    assert any(r.status == "note" and r.host == "ubuntu-server" and "firewall=1" in r.summary for r in rows)
    enabled = bundle(ev("pve.fw_cluster_options", {"enable": 1}), ev("pve.fw_cluster_rules", [{"a": 1}]),
                     ev("pve.fw_node_options", {}), ev("pve.fw_node_rules", [], "empty"))
    assert results_for("pve.firewall_disabled", enabled)[0].status == "ok"


APT = [{"Package": "proxmox-kernel-6.17", "OldVersion": "6.17.2-1", "Version": "6.17.13-21"},
       {"Package": "amd64-microcode", "OldVersion": "3.20240", "Version": "3.20250"},
       {"Package": "zsh", "OldVersion": "5.9", "Version": "5.9"}]


def test_pending_updates_and_sensitive_classes():
    b = bundle(ev("pve.apt_versions", APT))
    total = results_for("pve.pending_updates", b)
    assert total[0].status == "fail" and "2 of 3" in total[0].summary
    sens = {r.subject: r.status for r in results_for("pve.pending_updates_sensitive", b)}
    assert sens["kernel"] == "fail" and sens["microcode"] == "fail" and sens["ssh"] == "ok"
    assert results_for("pve.pending_updates", bundle(ev("pve.apt_versions", [APT[2]])))[0].status == "ok"


REPOS = {"files": [{"path": "/etc/apt/sources.list.d/debian.sources",
                    "repositories": [{"Enabled": 1, "Suites": ["trixie", "trixie-security"], "URIs": ["http://deb.debian.org/debian"]}]}],
         "standard-repos": [{"handle": "enterprise", "status": 0}, {"handle": "no-subscription", "status": 1}, {"handle": "test", "status": 0}]}


def test_repos():
    b = bundle(ev("pve.apt_repositories", REPOS))
    assert results_for("pve.repo_security", b)[0].status == "ok"
    assert all(r.status == "ok" for r in results_for("pve.repo_risky", b))
    bad = {"files": [{"repositories": [{"Enabled": 1, "Suites": ["trixie"], "URIs": ["x"]}]}],
           "standard-repos": [{"handle": "test", "status": 1}]}
    b2 = bundle(ev("pve.apt_repositories", bad))
    assert results_for("pve.repo_security", b2)[0].severity == "critical"
    assert results_for("pve.repo_risky", b2)[0].subject == "pve-test" and results_for("pve.repo_risky", b2)[0].status == "fail"


def test_cert_expiry_thresholds_and_internal_ca_note():
    day = 86400
    certs = [{"filename": "pve-ssl.pem", "notafter": int(NOW.timestamp()) + 423 * day, "issuer": "CN=Proxmox Virtual Environment,OU=abc"},
             {"filename": "pveproxy-ssl.pem", "notafter": int(NOW.timestamp()) + 20 * day, "issuer": "CN=R3"}]
    rows = results_for("pve.cert_expiry", bundle(ev("pve.certificates", certs)))
    by = {(r.subject, r.status): r for r in rows}
    assert ("pve-ssl.pem", "ok") in by and by[("pveproxy-ssl.pem", "fail")].severity == "critical"
    assert any(r.status == "note" and "internal PVE CA" in r.summary for r in rows)


def test_acl_privileged():
    roles = [{"roleid": "PAMAuditor", "privs": "Datastore.Audit,Sys.Audit,Sys.Syslog,VM.Audit"},
             {"roleid": "PVEVMAdmin", "privs": "VM.Allocate,VM.Config.CPU,VM.PowerMgmt"}]
    acl = [{"ugid": "auditor@pve", "roleid": "PAMAuditor", "path": "/", "type": "user"},
           {"ugid": "ops@pve", "roleid": "PVEVMAdmin", "path": "/vms", "type": "user"},
           {"ugid": "root@pam", "roleid": "Administrator", "path": "/", "type": "user"}]
    rows = results_for("pve.acl_privileged", bundle(ev("pve.access_acl", acl), ev("pve.access_roles", roles), ev("pve.access_users", USERS)))
    assert {r.subject: r.status for r in rows} == {"auditor@pve": "ok", "ops@pve": "fail"}


RES = [{"vmid": 100, "name": "ubuntu-server", "status": "running", "type": "qemu"},
       {"vmid": 102, "name": "monitor-box", "status": "stopped", "type": "qemu"},
       {"vmid": 103, "name": "heim", "status": "running", "type": "qemu"}]


def test_backup_coverage_and_last_status():
    jobs = [{"id": "j1", "enabled": 1, "vmid": "100,101"}, {"id": "j2", "enabled": 1, "vmid": "103"}]
    rows = results_for("pve.backup_coverage", bundle(ev("pve.backup_jobs", jobs), ev("pve.resources_vm", RES)))
    st = {r.host: r.status for r in rows}
    assert st == {"ubuntu-server": "ok", "heim": "ok", "monitor-box": "note"}
    uncovered = results_for("pve.backup_coverage", bundle(ev("pve.backup_jobs", [jobs[0]]), ev("pve.resources_vm", RES)))
    assert {r.host: r.status for r in uncovered}["heim"] == "fail"
    tasks = [{"upid": "u1", "type": "vzdump", "id": "103", "status": "OK", "starttime": NOW.timestamp() - 3600},
             {"upid": "u2", "type": "vzdump", "id": "100", "status": "unexpected status", "starttime": NOW.timestamp() - 7200}]
    b = bundle(ev("pve.tasks_vzdump", tasks), ev("pve.backup_jobs", jobs), ev("pve.resources_vm", RES))
    last = results_for("pve.backup_last_status", b)
    assert [r for r in last if r.status == "fail"][0].host == "ubuntu-server"
    none = results_for("pve.backup_last_status", bundle(ev("pve.tasks_vzdump", [], "empty"), ev("pve.backup_jobs", jobs), ev("pve.resources_vm", RES)))
    assert none[0].status == "fail" and "no vzdump task" in none[0].summary


def test_services_dead_and_time_sync():
    svcs = [{"name": "sshd", "state": "running"}, {"name": "pveproxy", "state": "running"}, {"name": "pvedaemon", "state": "running"},
            {"name": "pve-firewall", "state": "dead"}, {"name": "pvefw-logger", "state": "running"},
            {"name": "chrony", "state": "running"}, {"name": "systemd-timesyncd", "state": "dead"}, {"name": "corosync", "state": "dead"}]
    rows = results_for("pve.services_dead", bundle(ev("pve.services", svcs)))
    by = {r.subject: r.status for r in rows}
    assert by["pve-firewall"] == "fail" and by["time-sync"] == "ok" and "corosync" not in by


def test_auth_failures_from_journal():
    lines = ["Sep 27 01:00:00 homelab sshd[100]: Failed password for invalid user admin from 203.0.113.9 port 4 ssh2"] * 60 \
            + ["Sep 27 01:00:00 homelab pvedaemon[200]: authentication failure; rhost=203.0.113.9 user=root@pam msg=x"] \
            + ["Sep 27 01:00:00 homelab systemd[1]: Started thing."]
    rows = {r.subject: r for r in results_for("pve.auth_failures", bundle(ev("pve.journal", lines)))}
    assert rows["sshd"].status == "fail" and rows["sshd"].severity == "critical"
    assert rows["pveproxy"].status == "fail" and rows["pveproxy"].severity == "warning"
    assert results_for("pve.auth_failures", bundle(ev("pve.journal", [], "empty")))[0].status == "unavailable"


def test_vm_notes_and_secureboot():
    b = bundle(ev("pve.resources_vm", RES),
               ev("pve.vm_config[100]", {"net0": "virtio=AA,bridge=vmbr0,firewall=1", "hostpci0": "0000:03:00"}),
               ev("pve.vm_config[102]", {"onboot": 1}), ev("pve.vm_status[102]", {"status": "stopped"}),
               ev("pve.node_status", {"boot-info": {"secureboot": 0}}))
    hard = results_for("pve.vm_hardening", b)
    assert any(r.host == "ubuntu-server" and "passthrough" in r.summary for r in hard)
    assert any(r.host == "ubuntu-server" and "protection" in r.summary for r in hard)
    stopped_notes = [r for r in results_for("pve.stopped_vm_onboot", b) if r.status == "note"]
    assert stopped_notes and stopped_notes[0].host == "monitor-box"
    assert results_for("pve.secureboot", b)[0].status == "note"


def test_evaluator_exception_becomes_unavailable_not_ok():
    b = bundle(ev("pve.certificates", "this is not a list"))
    rows = results_for("pve.cert_expiry", b)
    assert rows and all(r.status == "unavailable" for r in rows)


def test_one_evaluator_crash_does_not_sink_sibling_checks():
    b = bundle(ev("pve.certificates", "this is not a list"), ev("pve.apt_versions", APT))
    cert_rows = results_for("pve.cert_expiry", b)
    assert cert_rows and all(r.status == "unavailable" for r in cert_rows)
    pending_rows = results_for("pve.pending_updates", b)
    assert pending_rows and pending_rows[0].status == "fail" and "2 of 3" in pending_rows[0].summary


# ---------------------------------------------------------------------------
# Fix round 1 (task-4-findings-r1.md): no silent `ok` on unverifiable evidence,
# and one row per fingerprint.

def test_vm_hardening_unavailable_when_no_vm_config_collected():
    b = bundle(ev("pve.resources_vm", RES))
    rows = results_for("pve.vm_hardening", b)
    assert len(rows) == 1 and rows[0].status == "unavailable"


def test_vm_hardening_unavailable_when_every_vm_config_denied():
    b = bundle(ev("pve.resources_vm", RES),
               ev("pve.vm_config[100]", None, status="denied", detail="HTTP 403"),
               ev("pve.vm_config[102]", None, status="denied", detail="HTTP 403"))
    rows = results_for("pve.vm_hardening", b)
    assert len(rows) == 1 and rows[0].status == "unavailable"


def test_vm_hardening_mix_of_usable_and_unusable_items_yields_rows_for_both():
    b = bundle(ev("pve.resources_vm", RES),
               ev("pve.vm_config[100]", {"hostpci0": "0000:03:00"}),
               ev("pve.vm_config[102]", None, status="denied", detail="HTTP 403"))
    rows = results_for("pve.vm_hardening", b)
    assert any(r.status == "unavailable" and r.host == "monitor-box" for r in rows)
    assert any(r.status == "note" and r.host == "ubuntu-server" and "passthrough" in r.summary for r in rows)


def test_stopped_vm_onboot_unavailable_when_no_vm_config_collected():
    b = bundle(ev("pve.resources_vm", RES))
    rows = results_for("pve.stopped_vm_onboot", b)
    assert len(rows) == 1 and rows[0].status == "unavailable"


def test_firewall_disabled_unavailable_item_for_denied_vm_config():
    b = bundle(ev("pve.fw_cluster_options", {"enable": 1}), ev("pve.fw_cluster_rules", [{"a": 1}]),
               ev("pve.fw_node_options", {}), ev("pve.fw_node_rules", [], "empty"),
               ev("pve.resources_vm", RES),
               ev("pve.vm_config[100]", None, status="denied", detail="HTTP 403"))
    rows = results_for("pve.firewall_disabled", b)
    assert any(r.status == "unavailable" and r.host == "ubuntu-server" for r in rows)


def test_backup_coverage_unavailable_when_resources_vm_empty():
    jobs = [{"id": "j1", "enabled": 1, "vmid": "100"}]
    rows = results_for("pve.backup_coverage", bundle(ev("pve.backup_jobs", jobs), ev("pve.resources_vm", [], "empty")))
    assert len(rows) == 1 and rows[0].status == "unavailable" and "not permitted" in rows[0].detail


def test_acl_privileged_unknown_role_is_unavailable_for_that_principal():
    roles = [{"roleid": "PAMAuditor", "privs": "Sys.Audit"}]
    acl = [{"ugid": "auditor@pve", "roleid": "PAMAuditor", "path": "/", "type": "user"},
           {"ugid": "ops@pve", "roleid": "Administrator", "path": "/", "type": "user"}]
    rows = results_for("pve.acl_privileged", bundle(ev("pve.access_acl", acl), ev("pve.access_roles", roles), ev("pve.access_users", USERS)))
    by = {r.subject: r for r in rows}
    assert by["ops@pve"].status == "unavailable" and "Administrator" in by["ops@pve"].detail
    assert by["auditor@pve"].status == "ok"


def test_acl_privileged_whole_check_unavailable_when_roles_empty():
    acl = [{"ugid": "ops@pve", "roleid": "Administrator", "path": "/", "type": "user"}]
    rows = results_for("pve.acl_privileged", bundle(ev("pve.access_acl", acl), ev("pve.access_roles", [], "empty"), ev("pve.access_users", USERS)))
    assert len(rows) == 1 and rows[0].status == "unavailable"


def test_duplicate_fingerprint_collapses_to_worst_status_either_order():
    roles = [{"roleid": "PAMAuditor", "privs": "Sys.Audit"}, {"roleid": "PVEVMAdmin", "privs": "VM.Allocate"}]
    acl = [{"ugid": "svc@pve", "roleid": "PAMAuditor", "path": "/", "type": "user"},
           {"ugid": "svc@pve", "roleid": "PVEVMAdmin", "path": "/vms", "type": "user"}]
    rows = results_for("pve.acl_privileged", bundle(ev("pve.access_acl", acl), ev("pve.access_roles", roles), ev("pve.access_users", USERS)))
    assert len(rows) == 1 and rows[0].status == "fail"

    acl_rev = list(reversed(acl))
    rows_rev = results_for("pve.acl_privileged", bundle(ev("pve.access_acl", acl_rev), ev("pve.access_roles", roles), ev("pve.access_users", USERS)))
    assert len(rows_rev) == 1 and rows_rev[0].status == "fail"
