from heim.incidents.types import HostRouting
from heim.incidents.uptime_logic import (
    Monitor,
    is_investigable_host,
    map_host,
    parse_metrics,
    unmapped_monitors,
)

METRICS = r'''# HELP monitor_status Monitor Status (1 = UP, 0= DOWN, 2= PENDING, 3= MAINTENANCE)
# TYPE monitor_status gauge
monitor_response_time{monitor_id="1",monitor_name="n8n",monitor_type="http",monitor_url="http://10.0.0.10:5678",monitor_hostname="null",monitor_port="null"} 12
monitor_status{monitor_id="1",monitor_name="n8n",monitor_type="http",monitor_url="http://10.0.0.10:5678",monitor_hostname="null",monitor_port="null"} 0
monitor_status{monitor_id="2",monitor_name="ssh",monitor_type="port",monitor_url="https://",monitor_hostname="10.0.0.10",monitor_port="22"} 1
monitor_status{monitor_id="3",monitor_name="ping",monitor_type="ping",monitor_url="https://",monitor_hostname="10.0.0.10",monitor_port="null"} 1
'''


def test_parse_reads_status_and_labels():
    ms = parse_metrics(METRICS)
    assert ms[0] == Monitor("1", "n8n", "http", "http://10.0.0.10:5678", "10.0.0.10", 0)
    assert (ms[1].target, ms[1].address) == ("10.0.0.10:22", "10.0.0.10")
    assert (ms[2].target, ms[2].address) == ("10.0.0.10", "10.0.0.10")
    assert len(ms) == 3


def test_parse_unescapes_label_values():
    text = (
        'monitor_status{monitor_id="9",monitor_name="My \\"prod\\" app, v2",'
        'monitor_type="http",monitor_url="http://10.0.0.10",monitor_hostname="null",'
        'monitor_port="null"} 1\n'
    )
    assert parse_metrics(text)[0].name == 'My "prod" app, v2'


def test_parse_returns_nothing_without_monitor_status():
    text = 'app_version{version="2.0"} 1\nmonitor_response_time{monitor_id="1"} 5\n'
    assert parse_metrics(text) == []


def test_map_host_matches_the_whole_address_not_a_prefix():
    m = {"10.0.0.10": "ubuntu-server", "10.0.0.2": "homelab"}
    names = set(m.values())
    assert map_host("10.0.0.24", m, names) is None
    assert map_host("10.0.0.2", m, names) == "homelab"
    assert map_host("10.0.0.10", m, names) == "ubuntu-server"


def test_map_host_ignores_port_in_map_key():
    assert map_host("10.0.0.10", {"10.0.0.10:9100": "ubuntu-server"}, []) == "ubuntu-server"


def test_map_host_by_first_dns_label():
    names = {"ubuntu-server", "homelab"}
    assert map_host("ubuntu-server.tail1234.ts.net", {}, names) == "ubuntu-server"
    assert map_host("Ubuntu-Server.example", {}, names) == "ubuntu-server"
    assert map_host("grafana.example", {}, names) is None


def test_investigability():
    r = HostRouting(
        ssh_hosts=frozenset({"ubuntu-server"}),
        hypervisor_host="homelab",
        hypervisor_categories=frozenset({"cpu", "availability"}),
        ha_host="home-assistant",
    )
    assert is_investigable_host("ubuntu-server", r)
    assert is_investigable_host("home-assistant", r)
    assert is_investigable_host("homelab", r)
    r2 = HostRouting(
        ssh_hosts=r.ssh_hosts,
        hypervisor_host="homelab",
        hypervisor_categories=frozenset({"cpu"}),
        ha_host="home-assistant",
    )
    assert not is_investigable_host("homelab", r2)
    assert not is_investigable_host("heim", r)
    assert not is_investigable_host("10.0.0.24", r)


def test_unmapped_monitors_lists_report_only_targets():
    m = {"10.0.0.10": "ubuntu-server"}
    a = Monitor("1", "a", "http", "http://10.0.0.10", "10.0.0.10", 1)
    b = Monitor("2", "b", "http", "http://10.0.0.24", "10.0.0.24", 1)
    assert unmapped_monitors([a, b], m, {"ubuntu-server"}) == [b]
