"""Cross-module integration tests: config loading, routing derivation,
Loki payload building, incident store round-trips, and pipeline glue."""
import json
from pathlib import Path

import pytest

from heim.channels.loki import build_payload
from heim.config import load_config
from heim.incidents.loki_events import finding_and_category_events, incident_events
from heim.incidents.store import IncidentStore
from heim.pipelines.investigate import InvestigationRequest, findings_text

ROOT = Path(__file__).resolve().parent.parent


DUMMY_ENV = {
    "HEIM_SERVER_IP": "10.0.0.10",
    "HEIM_PROXMOX_IP": "10.0.0.2",
    "HEIM_HA_IP": "10.0.0.3",
    "HEIM_TELEGRAM_CHAT_ID": "111111111",
    "HEIM_EMAIL_TO": "test@example.com",
    "HEIM_EMAIL_FROM": "test@example.com",
}


@pytest.fixture()
def cfg(tmp_path, monkeypatch):
    # use the example settings so tests don't depend on the gitignored real file;
    # committed config references ${HEIM_*} identity vars -> set dummies
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    import shutil
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    return load_config(croot)


def test_expand_env(monkeypatch):
    from heim.config import expand_env
    monkeypatch.setenv("HEIM_X", "1.2.3.4")
    assert expand_env("url: http://${HEIM_X}:9090") == "url: http://1.2.3.4:9090"
    assert expand_env("user: ${HEIM_MISSING:-fallback}") == "user: fallback"
    monkeypatch.setenv("HEIM_EMPTY", "")
    assert expand_env("${HEIM_EMPTY:-dflt}") == "dflt"  # empty counts as unset
    with pytest.raises(RuntimeError, match="HEIM_MISSING"):
        expand_env("${HEIM_MISSING}", source="settings.yaml")


def test_config_values_interpolated(cfg):
    assert cfg.settings.prometheus.url == "http://10.0.0.10:9090"
    assert cfg.settings.telegram.chat_id == 111111111  # yaml parses the int post-expansion
    assert cfg.hosts["ubuntu-server"].ssh.host == "10.0.0.10"
    assert cfg.hosts["ubuntu-server"].ssh.user == "monitoring-agent"  # ${...:-default}
    assert cfg.settings.instance_host_map == {
        "10.0.0.10": "ubuntu-server", "10.0.0.2": "homelab", "10.0.0.3": "home-assistant"}
    assert "10.0.0.2:9100" in cfg.hosts["homelab"].facts


def test_config_loads_and_routes(cfg):
    assert set(cfg.hosts) == {"ubuntu-server", "homelab", "home-assistant"}
    assert set(cfg.tools) == {"ssh_diagnostic", "prometheus_query", "discover_metrics", "ha_api", "proxmox_api"}
    assert "investigator" in cfg.agents
    assert cfg.analyst is not None and cfg.analyst.fallback is not None
    r = cfg.routing()
    assert r.ssh_hosts == frozenset({"ubuntu-server"})
    assert r.hypervisor_host == "homelab"
    assert "temperature" in r.hypervisor_categories
    assert r.ha_host == "home-assistant"


def test_investigator_prompt_renders(cfg):
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader(cfg.prompts_dir))
    agent = cfg.agents["investigator"]
    facts = "\n".join(h.facts for h in cfg.hosts.values() if h.facts)
    text = env.get_template(agent.prompt).render(
        now="2026-09-16T07:00:00", facts=facts,
        privileges=cfg.hosts["ubuntu-server"].privileges, soft_step_budget=agent.soft_step_budget)
    assert "## Summary" in text and "agent-docker" in text and "[BUDGET" in text
    assert "{{" not in text  # no unrendered slots


def test_brief_templates_render(cfg):
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader(cfg.prompts_dir))
    for role in ("guest", "hypervisor", "ha-guest"):
        out = env.get_template(f"briefs/{role}.md.j2").render(
            host="somehost", findings_text="1. [warning] drive temp rising — 44°C", is_temperature=True)
        assert "somehost" in out
        assert "TEMPERATURE PLAYBOOK" in out          # is_temperature=True includes it
        assert "'## Summary'" in out                   # report spec included
        out2 = env.get_template(f"briefs/{role}.md.j2").render(
            host="somehost", findings_text="1. [warning] memory", is_temperature=False)
        assert "TEMPERATURE PLAYBOOK" not in out2


def test_findings_text_format():
    t = findings_text([{"severity": "warning", "metric": "Memory used", "trend": "rising",
                        "detail": "climbing", "recommendation": "check"}])
    assert t == "1. [warning] Memory used (rising) — climbing (suggested: check)"
    assert "no structured findings" in findings_text([])


def test_request_tag():
    assert InvestigationRequest(host="h", fingerprint="h|mem_used|").tag == "h|mem_used"
    assert InvestigationRequest(host="h").tag == "h"


def test_loki_payload_unique_timestamps_and_clean_labels():
    events = [
        {"event": "incident", "labels": {"host": "u", "bad key": "x", "empty": ""}, "fields": {"a": 1}},
        {"event": "incident", "labels": {"host": "u"}, "fields": {"a": 2}},
    ]
    p = build_payload(events, base_ms=1000)
    assert len(p["streams"]) == 2
    ts = [s["values"][0][0] for s in p["streams"]]
    assert ts == ["1000000000", "1001000000"]  # (base_ms + i) followed by 6 ns zeros
    s0 = p["streams"][0]["stream"]
    assert s0 == {"job": "homelab-ai-monitor", "event": "incident", "host": "u"}
    assert json.loads(p["streams"][0]["values"][0][1]) == {"a": 1}


def test_finding_category_and_incident_events():
    analysis = {
        "findings": [{"severity": "warning", "host": "U-S", "metric": "Memory used + Swap",
                      "summary": "Mem climbing fast. Extra.", "detail": "d", "recommendation": "cap it"}],
        "categories": {"Memory": {"status": "warn", "insight": "climbing"}},
    }
    payload = {"categories": {"Memory": [{"flag": "ok"}, {"flag": "warn"}]}}
    evs = finding_and_category_events(analysis, payload)
    finds = [e for e in evs if e["event"] == "finding"]
    cats = [e for e in evs if e["event"] == "category"]
    assert len(finds) == 1 and finds[0]["labels"]["severity"] == "warn"
    assert finds[0]["labels"]["category"] == "memory"
    assert finds[0]["fields"]["summary"] == "Mem climbing fast."  # first-sentence short()
    assert len(cats) == 8  # full category order emitted
    mem = next(c for c in cats if c["labels"]["category"] == "Memory")
    assert mem["labels"]["status"] == "warn"

    summary = {"new": [{"fingerprint": "u|mem_used|", "host": "u", "severity": "warning",
                        "metric": "Memory used", "description": "[x]", "firstSeen": "t1", "lastSeen": "t2",
                        "timesSeen": 1}],
               "resolved": [{"fingerprint": "u|fs_used|/", "host": "u", "severity": "critical",
                             "metric": "Filesystem used", "firstSeen": "t0", "lastSeen": "t3", "timesSeen": 9}]}
    incs = incident_events(summary)
    assert [e["labels"]["status"] for e in incs] == ["new", "resolved"]
    assert incs[0]["fields"]["sevScore"] == 2
    assert incs[1]["fields"]["sevScore"] == 1  # resolved always 1
    assert incs[0]["labels"]["category"] == "memory"


def test_incident_store_roundtrip(tmp_path):
    store = IncidentStore(tmp_path / "t.sqlite3")
    rows = [{"fingerprint": "u|mem_used|", "host": "u", "metric": "Mem", "severity": "warning",
             "status": "open", "firstSeen": "a", "lastSeen": "b", "resolvedAt": "",
             "timesSeen": 1, "missedRuns": 0, "description": "d", "investigated": True}]
    store.upsert(rows)
    got = store.open_rows()
    assert len(got) == 1 and got[0]["investigated"] is True and got[0]["timesSeen"] == 1
    store.set_investigated("u|mem_used|", False)
    assert store.open_rows()[0]["investigated"] is False
    rows[0]["status"] = "resolved"
    store.upsert(rows)
    assert store.open_rows() == []
    assert len(store.all_rows()) == 1


def test_fresh_clone_falls_back_to_the_example_settings(tmp_path, monkeypatch, caplog):
    """A fresh clone has no settings.yaml (it is gitignored) — HEIM must start
    on the example rather than crash-loop the container."""
    import logging
    import shutil
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    assert not (croot / "settings.yaml").exists()          # the fresh-clone state
    with caplog.at_level(logging.INFO, logger="heim.config"):
        cfg = load_config(croot)
    assert cfg.settings.prometheus.url == "http://10.0.0.10:9090"   # example + .env identity
    assert "settings.example.yaml" in caplog.text   # the fallback says so out loud


def test_config_dir_without_any_settings_file_still_fails_loudly(tmp_path, monkeypatch):
    """The fallback must not paper over a genuinely wrong config directory."""
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    croot = tmp_path / "config"
    croot.mkdir()
    with pytest.raises(FileNotFoundError, match="no settings.example.yaml to fall back to"):
        load_config(croot)
