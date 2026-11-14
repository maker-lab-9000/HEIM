"""AdGuard Home in LXC container 112 (2026-11-14).

It left the Home Assistant add-on for CT 112 "adguard" and is the house's only
DNS server. ansible-homelab added no qids: KeyVMDown (pve_vm_up, critical)
covers lxc/112. These tests pin how HEIM names, routes and describes it.
"""
from __future__ import annotations

from pathlib import Path

from test_lxc_gpu_migration import HOST_MAP, ROUTING
from test_poller_logic import NOW, alert, resp

from heim.config import Host, Settings, _load_yaml
from heim.incidents.poller_logic import diff_and_decide
from heim.incidents.uptime_logic import map_host

ROOT = Path(__file__).resolve().parents[1]
ENV = {"HEIM_SERVER_IP": "10.0.0.241", "HEIM_PROXMOX_IP": "10.0.0.2",
       "HEIM_HA_IP": "10.0.0.137", "HEIM_OBSERVABILITY_IP": "10.0.0.243",
       "HEIM_JELLYFIN_IP": "10.0.0.210", "HEIM_LLM_IP": "10.0.0.211",
       "HEIM_ADGUARD_IP": "10.0.0.212"}


def _settings(monkeypatch, **env):
    for k, v in {**ENV, **env}.items():
        monkeypatch.setenv(k, v)
    return Settings(**_load_yaml(ROOT / "config" / "settings.example.yaml"))


def test_adguard_is_a_report_only_guest_named_after_the_pve_guest():
    h = Host(**_load_yaml(ROOT / "config" / "hosts" / "adguard.yaml"))
    assert (h.name, h.role, h.vmid, h.ssh, h.privileges) == ("adguard", "guest", 112, None, "")
    for fact in ("lxc/112", "ONLY DNS", "adguardhome.service", 'host="adguard"'):
        assert fact in h.facts, fact


def test_the_address_maps_to_adguard_ahead_of_the_hypervisor(monkeypatch):
    s = _settings(monkeypatch)
    keys = list(s.instance_host_map)
    assert s.instance_host_map["10.0.0.212"] == "adguard"
    assert keys.index("10.0.0.212") < keys.index("10.0.0.2")
    assert s.host_color_order[-1] == "adguard"


def test_an_unset_adguard_address_is_dropped(monkeypatch):
    s = _settings(monkeypatch, HEIM_ADGUARD_IP="")
    assert "" not in s.instance_host_map and "adguard" not in s.instance_host_map.values()


def test_its_uptime_kuma_monitors_land_on_adguard(monkeypatch):
    s = _settings(monkeypatch)
    names = ["adguard", "homelab", "ubuntu-server"]
    # "AdGuard web (CT 112)" (http) and "CT 112 adguard (ping)"
    assert map_host("10.0.0.212", s.instance_host_map, names) == "adguard"
    # "AdGuard DNS (CT 112)": Kuma reports the name it resolves, not the resolver,
    # so the monitor resolves adguard.com and the first label names the host
    assert map_host("adguard.com", s.instance_host_map, names) == "adguard"


def test_ct_112_down_is_a_critical_incident_on_adguard():
    a = alert("pve_vm_up", severity="critical", instance="10.0.0.2:9221",
              labels={"id": "lxc/112"})
    d = diff_and_decide(resp(a), [], NOW, ROUTING, HOST_MAP, guest_names={"lxc/112": "adguard"})
    row = d.rows_to_upsert[0]
    assert (row["fingerprint"], row["host"], row["severity"]) == (
        "adguard|pve_vm_up|", "adguard", "critical")


def test_the_loki_tool_reads_adguard_and_calls_the_add_on_legacy():
    text = (ROOT / "config" / "tools" / "loki_query.yaml").read_text()
    assert '"adguard"' in text and 'unit="adguardhome.service"' in text
    i = text.index("app_a0d7b954_adguard")
    assert "LEGACY" in text[i - 40:i + 60]


def test_the_prompts_know_ct_112_is_the_only_dns():
    analyst = (ROOT / "config" / "prompts" / "analyst.md").read_text()
    assert "3 LXC containers ('jellyfin', 'llm', 'adguard')" in analyst
    assert "(4 + 6 + 2)" in analyst and "ONLY DNS server" in analyst
    ha = (ROOT / "config" / "hosts" / "home-assistant.yaml").read_text()
    assert "no longer serves DNS" in ha
    for p in ("investigator.md.j2", "security_auditor.md.j2", "briefs/hypervisor.md.j2"):
        assert "adguard" in (ROOT / "config" / "prompts" / p).read_text(), p


def test_the_audit_still_counts_adguard_as_sensitive_until_the_add_on_is_gone():
    from heim.security.evaluate_ha import _SENSITIVE_DEFAULT
    assert "adguard" in _SENSITIVE_DEFAULT
