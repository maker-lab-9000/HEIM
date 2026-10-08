"""Fetchers: GET-only, statuses classified, expansions, timeouts. Network is
faked by monkeypatching the module's httpx.AsyncClient / asyncssh.connect."""
import asyncio
import json
import shutil
from pathlib import Path

import pytest

from heim.config import load_config
from heim.pipelines import security_sources as src
from heim.security.catalogue import load_catalogue
from heim.security.types import SourceSpec

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def cfg(tmp_path, monkeypatch):
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    monkeypatch.setenv("PROXMOX_TOKEN", "user@pve!tok=secret")
    monkeypatch.setenv("HA_TOKEN", "hatoken")
    return load_config(croot)


class _Resp:
    def __init__(self, status_code, text):
        self.status_code, self.text = status_code, text


def fake_httpx(monkeypatch, router):
    """router(url, params) -> (status, text) ; records every call (GET only exists)."""
    calls = []

    class FakeClient:
        def __init__(self, **kw):
            self.kw = kw

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url, params=None, headers=None):
            calls.append({"url": url, "params": params, "headers": headers, "timeout": self.kw.get("timeout")})
            status, text = router(url, params)
            return _Resp(status, text)

    monkeypatch.setattr(src.httpx, "AsyncClient", FakeClient)
    return calls


def test_classify_http_statuses():
    assert src.classify_http("k", 200, json.dumps({"data": []})).status == "empty"
    assert src.classify_http("k", 200, json.dumps({"data": [1]})).status == "ok"
    assert src.classify_http("k", 403, "").status == "denied"
    assert src.classify_http("k", 404, "").status == "error"
    assert src.classify_http("k", 596, "").status == "error"
    assert src.classify_http("k", 200, "<html>").status == "error"
    raw = src.classify_http("k", 200, json.dumps({"version": "2026.9.1"}), unwrap="")
    assert raw.status == "ok" and raw.body["version"] == "2026.9.1"
    prom = src.prom_evidence("p", 200, json.dumps({"status": "success", "data": {"resultType": "vector", "result": [{"metric": {}, "value": [1, "1"]}]}}), "up")
    assert prom.status == "ok" and len(prom.body) == 1 and prom.target == "up"
    assert src.prom_evidence("p", 200, json.dumps({"status": "error", "error": "bad"}), "x").status == "error"
    assert src.prom_evidence("p", 200, json.dumps({"status": "success", "data": {"result": []}}), "x").status == "empty"


async def test_fetch_pve_expands_vmids_and_marks_denied(cfg, monkeypatch):
    def router(url, params):
        if url.endswith("/cluster/resources?type=vm"):
            return 200, json.dumps({"data": [{"vmid": 100, "name": "ubuntu-server", "type": "qemu"}, {"vmid": 103, "name": "heim", "type": "qemu"}]})
        if url.endswith("/access/tfa"):
            return 200, json.dumps({"data": []})
        if "/qemu/" in url and url.endswith("/config"):
            return 200, json.dumps({"data": {"net0": "virtio=x,firewall=1"}})
        if url.endswith("/apt/update"):
            return 403, "Permission check failed"
        return 200, json.dumps({"data": {"ok": 1}})
    calls = fake_httpx(monkeypatch, router)
    sources = [SourceSpec("pve.resources_vm", "pve", "/api2/json/cluster/resources?type=vm"),
               SourceSpec("pve.access_tfa", "pve", "/api2/json/access/tfa", control="pve.access_users"),
               SourceSpec("pve.vm_config", "pve", "/api2/json/nodes/homelab/qemu/{vmid}/config", expand="vmid")]
    out = {e.key: e for e in await src.fetch_pve(cfg, sources, node="homelab")}
    assert out["pve.resources_vm"].status == "ok"
    assert out["pve.access_tfa"].status == "empty"
    assert out["pve.vm_config[100]"].status == "ok" and out["pve.vm_config[103]"].body["net0"].endswith("firewall=1")
    assert all(c["headers"]["Authorization"].startswith("PVEAPIToken=") for c in calls)
    assert all(c["timeout"] == src.HTTP_TIMEOUT_S for c in calls)
    assert all("/api2/json/" in c["url"] for c in calls)


async def test_fetch_pve_without_token_is_denied_not_a_crash(cfg, monkeypatch):
    monkeypatch.delenv("PROXMOX_TOKEN")
    out = await src.fetch_pve(cfg, [SourceSpec("pve.version", "pve", "/api2/json/version")], node="homelab")
    assert out[0].status == "denied" and "PROXMOX_TOKEN" in out[0].detail


async def test_fetch_ha_and_prom(cfg, monkeypatch):
    def router(url, params):
        if url.endswith("/api/config"):
            return 200, json.dumps({"version": "2026.9.1"})
        if url.endswith("/api/states"):
            return 200, json.dumps([])
        if url.endswith("/api/v1/query"):
            return 200, json.dumps({"status": "success", "data": {"result": [{"metric": {"instance": "a"}, "value": [1, "0"]}]}})
        return 500, "boom"
    calls = fake_httpx(monkeypatch, router)
    ha = {e.key: e for e in await src.fetch_ha(cfg, [SourceSpec("ha.config", "ha", "/api/config"), SourceSpec("ha.states", "ha", "/api/states")], host="home-assistant")}
    assert ha["ha.config"].status == "ok" and ha["ha.states"].status == "empty"
    pr = await src.fetch_prom(cfg, [SourceSpec("prom.up", "prom", "up")])
    assert pr[0].status == "ok" and pr[0].target == "up"
    assert [c["params"] for c in calls if c["params"]] == [{"query": "up"}]


class _SshResult:
    def __init__(self, stdout, stderr="", exit_status=0):
        self.stdout, self.stderr, self.exit_status = stdout, stderr, exit_status


class _Conn:
    def __init__(self, script):
        self.script, self.ran, self.closed = script, [], False

    async def run(self, command, check=False):
        self.ran.append(command)
        r = self.script(command)
        if isinstance(r, Exception):
            raise r
        return r

    def close(self):
        self.closed = True


async def test_fetch_ssh_runs_guarded_lines_and_expands_containers(cfg, monkeypatch):
    def script(cmd):
        if cmd == "sudo agent-docker ps":
            return _SshResult("CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES\nabc img cmd 1d Up  grafana\ndef img cmd 1d Up  bad;name\n")
        if cmd.startswith("sudo agent-docker inspect "):
            return _SshResult(json.dumps([{"HostConfig": {}}]))
        if cmd.startswith("journalctl"):
            return _SshResult("0\n", stderr="Hint: You are currently not seeing messages from other users and the system.\n", exit_status=1)
        return _SshResult("x\n")
    conn = _Conn(script)

    async def fake_connect(*a, **k):
        return conn
    monkeypatch.setattr(src.asyncssh, "connect", fake_connect)
    monkeypatch.setattr(src, "SSH_CONNECT_TIMEOUT_S", 5)
    sources = [SourceSpec("ssh.docker_ps", "ssh", "sudo agent-docker ps"),
               SourceSpec("ssh.docker_inspect", "ssh", "sudo agent-docker inspect {container}", expand="container"),
               SourceSpec("ssh.auth_fail_count", "ssh", "journalctl --no-pager -u ssh -o cat | grep -c -E 'Failed password'")]
    out = {e.key: e for e in await src.fetch_ssh(cfg, sources, ssh_host="ubuntu-server")}
    assert out["ssh.docker_ps"].status == "ok"
    assert "ssh.docker_inspect[grafana]" in out and not any("bad" in k for k in out)   # invalid name never runs
    assert out["ssh.auth_fail_count"].exit_code == 1 and "not seeing messages" in out["ssh.auth_fail_count"].stderr
    assert out["ssh.auth_fail_count"].target.startswith("journalctl")
    assert conn.closed and all(not c.startswith("rm") for c in conn.ran)


def _ps_text(names):
    header = "CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES"
    rows = "\n".join(f"c{i:02d} img cmd 1d Up  {n}" for i, n in enumerate(names))
    return header + "\n" + rows + "\n"


def _ssh_docker_script(ps_text):
    def script(cmd):
        if cmd == "sudo agent-docker ps":
            return _SshResult(ps_text)
        if cmd.startswith("sudo agent-docker inspect "):
            return _SshResult(json.dumps([{"HostConfig": {}}]))
        return _SshResult("x\n")
    return script


_DOCKER_SOURCES = [SourceSpec("ssh.docker_ps", "ssh", "sudo agent-docker ps"),
                   SourceSpec("ssh.docker_inspect", "ssh", "sudo agent-docker inspect {container}", expand="container")]


async def test_fetch_ssh_sentinel_when_containers_exceed_cap(cfg, monkeypatch):
    names = [f"c{i}" for i in range(41)]
    conn = _Conn(_ssh_docker_script(_ps_text(names)))

    async def fake_connect(*a, **k):
        return conn
    monkeypatch.setattr(src.asyncssh, "connect", fake_connect)
    out = {e.key: e for e in await src.fetch_ssh(cfg, _DOCKER_SOURCES, ssh_host="ubuntu-server")}
    inspected = [k for k in out if k.startswith("ssh.docker_inspect[") and k != "ssh.docker_inspect[_not_inspected]"]
    assert len(inspected) == src.MAX_CONTAINERS
    sentinel = out["ssh.docker_inspect[_not_inspected]"]
    assert sentinel.status == "error" and "1 container" in sentinel.detail
    assert sentinel.target == "sudo agent-docker inspect {container}"


async def test_fetch_ssh_sentinel_when_a_name_fails_validation(cfg, monkeypatch):
    conn = _Conn(_ssh_docker_script(_ps_text(["grafana", "bad;name"])))

    async def fake_connect(*a, **k):
        return conn
    monkeypatch.setattr(src.asyncssh, "connect", fake_connect)
    out = {e.key: e for e in await src.fetch_ssh(cfg, _DOCKER_SOURCES, ssh_host="ubuntu-server")}
    assert "ssh.docker_inspect[grafana]" in out
    sentinel = out["ssh.docker_inspect[_not_inspected]"]
    assert sentinel.status == "error" and "1 container" in sentinel.detail


async def test_fetch_ssh_no_sentinel_when_every_container_inspected(cfg, monkeypatch):
    conn = _Conn(_ssh_docker_script(_ps_text(["grafana", "cadvisor"])))

    async def fake_connect(*a, **k):
        return conn
    monkeypatch.setattr(src.asyncssh, "connect", fake_connect)
    out = {e.key: e for e in await src.fetch_ssh(cfg, _DOCKER_SOURCES, ssh_host="ubuntu-server")}
    assert "ssh.docker_inspect[_not_inspected]" not in out
    assert "ssh.docker_inspect[grafana]" in out and "ssh.docker_inspect[cadvisor]" in out


async def test_fetch_ssh_connect_failure_marks_every_source(cfg, monkeypatch):
    async def fake_connect(*a, **k):
        raise OSError("no route to host")
    monkeypatch.setattr(src.asyncssh, "connect", fake_connect)
    out = await src.fetch_ssh(cfg, [SourceSpec("ssh.listeners", "ssh", "sudo ss -tunlpH")], ssh_host="ubuntu-server")
    assert out[0].status == "error" and "no route" in out[0].detail


async def test_fetch_ssh_host_without_shell(cfg):
    out = await src.fetch_ssh(cfg, [SourceSpec("ssh.listeners", "ssh", "sudo ss -tunlpH")], ssh_host="heim")
    assert out[0].status == "error" and "no ssh" in out[0].detail.lower()


async def test_collect_evidence_bounds_each_kind(cfg, monkeypatch):
    cat = load_catalogue(ROOT / "config" / "security" / "checks.yaml")

    async def slow(*a, **k):
        await asyncio.sleep(10)
        return []

    async def quick_pve(cfg_, sources, *, node):
        return [src.Evidence(s.key, "ok", body={"x": 1}) for s in sources if not s.expand]
    monkeypatch.setattr(src, "fetch_pve", quick_pve)
    monkeypatch.setattr(src, "fetch_ha", slow)
    monkeypatch.setattr(src, "fetch_prom", slow)
    monkeypatch.setattr(src, "fetch_ssh", slow)
    monkeypatch.setattr(src, "KIND_TIMEOUT_S", 0.05)
    bundle = await src.collect_evidence(cfg, cat, now_iso="2026-09-28T06:00:00")
    assert bundle.get("pve.version").status == "ok"
    assert bundle.get("ha.config").status == "timeout" and bundle.get("ssh.listeners").status == "timeout"
    assert bundle.collected_at == "2026-09-28T06:00:00"


async def test_fr5d_header_only_docker_ps_yields_a_no_containers_marker(cfg, monkeypatch):
    conn = _Conn(_ssh_docker_script(_ps_text([])))

    async def fake_connect(*a, **k):
        return conn
    monkeypatch.setattr(src.asyncssh, "connect", fake_connect)
    out = {e.key: e for e in await src.fetch_ssh(cfg, _DOCKER_SOURCES, ssh_host="ubuntu-server")}
    marker = out["ssh.docker_inspect[_none]"]
    assert marker.status == "empty" and marker.usable and "no containers" in marker.detail
    assert "ssh.docker_inspect[_not_inspected]" not in out


async def test_fr5d_denied_docker_ps_yields_no_marker(cfg, monkeypatch):
    def script(cmd):
        if cmd == "sudo agent-docker ps":
            return _SshResult("", stderr="sudo: a password is required\n", exit_status=1)
        return _SshResult("x\n")
    conn = _Conn(script)

    async def fake_connect(*a, **k):
        return conn
    monkeypatch.setattr(src.asyncssh, "connect", fake_connect)
    out = {e.key: e for e in await src.fetch_ssh(cfg, _DOCKER_SOURCES, ssh_host="ubuntu-server")}
    assert "ssh.docker_inspect[_none]" not in out and out["ssh.docker_inspect"].status == "error"


async def test_fr5h_fetch_ha_requests_the_guard_normalised_path(cfg, monkeypatch):
    calls = fake_httpx(monkeypatch, lambda url, params: (200, json.dumps({"version": "x"})))
    out = await src.fetch_ha(cfg, [SourceSpec("ha.config", "ha", " api/config ")], host="home-assistant")
    assert out[0].status == "ok" and out[0].target == "/api/config"
    assert [c["url"] for c in calls] and all(c["url"].endswith("/api/config") and " " not in c["url"] for c in calls)


async def test_fr5h_fetch_ha_blocks_a_path_the_guard_rejects(cfg, monkeypatch):
    calls = fake_httpx(monkeypatch, lambda url, params: (200, "{}"))
    out = await src.fetch_ha(cfg, [SourceSpec("ha.x", "ha", "/api/services/homeassistant/restart")], host="home-assistant")
    assert out[0].status == "blocked" and not calls
