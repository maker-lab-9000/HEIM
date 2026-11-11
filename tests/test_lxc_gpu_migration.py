"""The 2026-11-11 move of Jellyfin and llama-server into LXC containers.

ansible-homelab added three qids (``gpu_missing``, ``gpu_gtt_high``,
``lxc_disk_growth``) and two Proxmox containers (CT 110 jellyfin at .210,
CT 111 llm at .211). These tests pin how HEIM files them.
"""
from __future__ import annotations

from pathlib import Path

from test_poller_logic import NOW, alert, resp

from heim.config import Host, Settings, _load_yaml
from heim.incidents.poller_logic import diff_and_decide
from heim.incidents.types import HostRouting

ROOT = Path(__file__).resolve().parents[1]

# as config/hosts/homelab.yaml declares it
ROUTING = HostRouting(
    ssh_hosts=frozenset({"ubuntu-server"}),
    hypervisor_host="homelab",
    hypervisor_categories=frozenset(
        {"cpu", "memory", "temperature", "disk", "diskHealth", "availability"}),
)
HOST_MAP = {"192.168.178.241": "ubuntu-server", "192.168.178.210": "jellyfin",
            "192.168.178.211": "llm", "192.168.178.2": "homelab"}


def decide(*alerts, guest_names=None):
    return diff_and_decide(resp(*alerts), [], NOW, ROUTING, HOST_MAP,
                           guest_names=guest_names or {})


# ------------------------------------------------------------- the iGPU alerts


def test_gpu_missing_has_no_instance_and_still_lands_on_the_hypervisor():
    # GpuMissing is a count(...) with no instance label at all
    a = alert("gpu_missing", severity="critical", instance="")
    a["labels"].pop("instance")
    d = decide(a)
    row = d.rows_to_upsert[0]
    assert row["fingerprint"] == "homelab|gpu_missing|igpu"
    assert row["host"] == "homelab"
    assert len(d.dispatches) == 1
    assert d.dispatches[0]["category"] == "availability"


def test_gpu_gtt_high_is_a_hypervisor_memory_finding_whatever_the_card_number():
    for card in ("card0", "card1"):   # DRM card numbers move at boot
        d = decide(alert("gpu_gtt_high", instance="192.168.178.2:9100",
                         labels={"card": card}))
        assert d.rows_to_upsert[0]["fingerprint"] == "homelab|gpu_gtt_high|igpu"
        assert d.dispatches[0]["category"] == "memory"


# ------------------------------------------------------- the LXC disk growth


def test_lxc_disk_growth_belongs_to_the_container_not_the_exporter():
    d = decide(alert("lxc_disk_growth", instance="192.168.178.241:9221",
                     labels={"id": "lxc/110"}),
               guest_names={"lxc/110": "jellyfin"})
    row = d.rows_to_upsert[0]
    assert row["fingerprint"] == "jellyfin|lxc_disk_growth|"
    assert row["host"] == "jellyfin"


def test_lxc_disk_growth_is_categorised_disk():
    from heim.incidents.poller_logic import _category_of_qid
    assert _category_of_qid("lxc_disk_growth") == "disk"
    assert _category_of_qid("gpu_missing") == "availability"
    assert _category_of_qid("gpu_gtt_high") == "memory"


# ------------------------------------------- the containers' own addresses


def test_llama_server_exporter_down_is_filed_under_llm_not_homelab():
    # '192.168.178.2' is a string prefix of '.211'; the poller matches by prefix
    d = decide(alert("exporter_up", severity="critical",
                     instance="192.168.178.211:8180", labels={"job": "llama-server"}))
    assert d.rows_to_upsert[0]["fingerprint"] == "llm|exporter_up|llama-server"


def test_settings_example_lists_the_containers_before_the_hypervisor(monkeypatch):
    env = {"HEIM_SERVER_IP": "192.168.178.241", "HEIM_PROXMOX_IP": "192.168.178.2",
           "HEIM_HA_IP": "192.168.178.137", "HEIM_OBSERVABILITY_IP": "192.168.178.243",
           "HEIM_JELLYFIN_IP": "192.168.178.210", "HEIM_LLM_IP": "192.168.178.211"}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    settings = Settings(**_load_yaml(ROOT / "config" / "settings.example.yaml"))
    keys = list(settings.instance_host_map)
    assert settings.instance_host_map["192.168.178.210"] == "jellyfin"
    assert settings.instance_host_map["192.168.178.211"] == "llm"
    # every address that has the hypervisor's as a prefix must come before it
    hyper = keys.index("192.168.178.2")
    for i, k in enumerate(keys):
        if k != "192.168.178.2" and k.startswith("192.168.178.2"):
            assert i < hyper, k
    assert settings.host_color_order[-2:] == ["jellyfin", "llm"]


def test_an_unset_container_address_leaves_no_empty_key():
    raw = _load_yaml(ROOT / "config" / "settings.example.yaml")
    raw["instance_host_map"] = {"": "jellyfin", "  ": "llm", "10.0.0.2": "homelab"}
    s = Settings(**raw)
    assert s.instance_host_map == {"10.0.0.2": "homelab"}


def test_the_containers_are_hosts_without_a_shell():
    # not load_config: it reads the real .env into os.environ
    for name, vmid in (("jellyfin", 110), ("llm", 111)):
        h = Host(**_load_yaml(ROOT / "config" / "hosts" / f"{name}.yaml"))
        assert (h.name, h.role, h.vmid, h.ssh, h.privileges) == (name, "guest", vmid, None, "")
        assert f"lxc/{vmid}" in h.facts


def test_the_unset_new_addresses_do_not_stop_startup(monkeypatch):
    monkeypatch.delenv("HEIM_JELLYFIN_IP", raising=False)
    monkeypatch.delenv("HEIM_LLM_IP", raising=False)
    settings = Settings(**_load_yaml(ROOT / "config" / "settings.example.yaml"))
    assert "" not in settings.instance_host_map


# ---------------------------------------- the Proxmox guard sees the containers


def test_the_proxmox_guard_reads_container_status_and_config_only():
    from heim.guards import guard_proxmox_path
    for path in ("/nodes/homelab/lxc", "/nodes/homelab/lxc/110/status/current",
                 "/nodes/homelab/lxc/111/config"):
        assert guard_proxmox_path(path).allowed, path
    for path in ("/nodes/homelab/lxc/110/snapshot", "/nodes/homelab/lxc/110/status/stop",
                 "/nodes/homelab/lxc/110/interfaces", "/nodes/homelab/lxc/abc/config"):
        assert not guard_proxmox_path(path).allowed, path
