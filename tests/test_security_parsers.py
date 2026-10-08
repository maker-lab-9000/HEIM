"""Parsers for the audit's raw evidence — pure, fixture-driven."""
from heim.security.parsers import (
    apt_pending, docker_names, ip_in_cidrs, is_public_host, parse_docker_images, parse_last_hosts,
    parse_ss_listeners, parse_sshd_config, parse_updates_available, unit_states, unreadable_dropins,
    vmids_from_resources,
)

SS = """tcp   LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      4096       127.0.0.53%lo:53      0.0.0.0:*    users:(("systemd-resolve",pid=600,fd=14))
tcp   LISTEN 0      4096               *:8081            *:*    users:(("docker-proxy",pid=2001,fd=4))
tcp   LISTEN 0      4096            [::]:9100         [::]:*    users:(("node_exporter",pid=900,fd=3))
udp   UNCONN 0      0            0.0.0.0:5353      0.0.0.0:*    users:(("avahi-daemon",pid=700,fd=12))
"""


def test_ss_listeners_wildcard_and_process():
    rows = parse_ss_listeners(SS)
    by_port = {r["port"]: r for r in rows}
    assert by_port["22"]["process"] == "sshd" and by_port["22"]["wildcard"]
    assert by_port["53"]["wildcard"] is False           # loopback-scoped
    assert by_port["8081"]["wildcard"] and by_port["8081"]["process"] == "docker-proxy"
    assert by_port["9100"]["wildcard"] and by_port["9100"]["proto"] == "tcp"
    assert by_port["5353"]["proto"] == "udp"


def test_sshd_config_first_wins_and_match_stops():
    text = "PasswordAuthentication no\n# PasswordAuthentication yes\nPasswordAuthentication yes\n" \
           "PermitRootLogin=prohibit-password\nMatch User git\n  PasswordAuthentication yes\n"
    conf = parse_sshd_config(text)
    assert conf["passwordauthentication"] == "no"
    assert conf["permitrootlogin"] == "prohibit-password"
    assert "match" not in conf


def test_unreadable_dropins_from_ls():
    ls = ("total 12\ndrwxr-xr-x 2 root root 4096 Jan  1 00:00 .\n"
          "-rw-r--r-- 1 root root  100 Jan  1 00:00 50-cloud-init.conf\n"
          "-rw------- 1 root root   40 Jan  1 00:00 99-secret.conf\n")
    assert unreadable_dropins(ls) == ["99-secret.conf"]


def test_updates_available_counts():
    text = "\n12 updates can be applied immediately.\n5 of these updates are standard security updates.\n"
    assert parse_updates_available(text) == (12, 5)
    assert parse_updates_available("0 updates can be applied immediately.\n") == (0, 0)
    assert parse_updates_available("1 update can be applied immediately.\n1 of these updates is a standard security update.\n") == (1, 1)
    assert parse_updates_available("") == (0, 0)


def test_last_hosts_skips_reboot_and_trailer():
    text = ("alice  pts/0  192.168.1.20   Mon Sep 21 08:00:00 2026   still logged in\n"
            "reboot system boot 6.8.0-139-gen  Sun Sep 20 03:10:00 2026 - Sun Sep 20 03:12:00 2026 (00:02)\n"
            "alice  pts/1  100.101.102.103 Sat Sep 19 09:00:00 2026 - Sat Sep 19 09:30:00 2026 (00:30)\n"
            "bob    tty1                   Fri Sep 18 09:00:00 2026 - down (01:00)\n"
            "\nwtmp begins Tue Sep  1 00:00:00 2026\n")
    assert parse_last_hosts(text) == ["192.168.1.20", "100.101.102.103"]


def test_docker_names_and_images():
    ps = ("CONTAINER ID   IMAGE             COMMAND   CREATED       STATUS       PORTS   NAMES\n"
          "0123456789ab   grafana/grafana   \"/run.sh\" 3 weeks ago   Up 3 weeks           grafana\n"
          "abcdef012345   prom/prometheus   \"/bin/pr\" 3 weeks ago   Up 3 weeks           prometheus\n")
    assert docker_names(ps) == ["grafana", "prometheus"]
    images = ("REPOSITORY        TAG      IMAGE ID       CREATED        SIZE\n"
              "grafana/grafana   latest   aaa            3 weeks ago    400MB\n"
              "old/thing         v1       bbb            14 months ago  90MB\n"
              "ancient/thing     v0       ccc            2 years ago    90MB\n")
    assert parse_docker_images(images) == [("grafana/grafana:latest", 0), ("old/thing:v1", 14), ("ancient/thing:v0", 24)]


def test_apt_pending_and_vmids():
    body = [{"Package": "pve-firewall", "OldVersion": "6.0.4", "Version": "6.0.6"},
            {"Package": "zsh", "OldVersion": "5.9", "Version": "5.9"},
            {"Package": "qemu-server", "OldVersion": "9.0.1", "Version": "9.0.3"}]
    assert [r["Package"] for r in apt_pending(body)] == ["pve-firewall", "qemu-server"]
    res = [{"vmid": 100, "name": "ubuntu-server", "status": "running", "type": "qemu"},
           {"vmid": 102, "name": "monitor-box", "status": "stopped", "type": "qemu"}]
    assert vmids_from_resources(res) == {"100": "ubuntu-server", "102": "monitor-box"}


def test_public_host_and_cidrs():
    assert is_public_host("https://myhome.example-dyndns.net:8123")
    assert not is_public_host("http://192.168.1.5:8123")
    assert not is_public_host("http://homeassistant.local:8123")
    assert not is_public_host("https://ha.tailnet.ts.net")
    assert not is_public_host("")
    cidrs = ["192.168.0.0/16", "100.64.0.0/10", "::1/128"]
    assert ip_in_cidrs("192.168.1.20", cidrs) and ip_in_cidrs("100.101.102.103", cidrs)
    assert not ip_in_cidrs("203.0.113.9", cidrs)
    assert not ip_in_cidrs("not-an-ip", cidrs)


def test_unit_states_zips_command_and_output():
    st = unit_states("systemctl is-active ufw nftables fail2ban", "inactive\nactive\ninactive\n")
    assert st == {"ufw": "inactive", "nftables": "active", "fail2ban": "inactive"}
