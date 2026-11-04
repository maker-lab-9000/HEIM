"""The Tools pages (spec 2026-11-04-activity-jobs-tools): each tool's
definition as the model sees it, its guard, who uses it, recent calls."""
import json
import shutil
from pathlib import Path

from test_agent_tool_calls import _inv
from test_overview_console import _client, _healthy_agents

from heim.config import load_config
from heim.dashboard import app as dash

ROOT = Path(__file__).resolve().parent.parent


def _cfg(tmp_path):
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    return load_config(croot)


TOOLS = ("ssh_diagnostic", "prometheus_query", "discover_metrics", "loki_query", "ha_api",
         "proxmox_api")


def _seed(s):
    _healthy_agents(s)
    _inv(s, "investigator", 30, [("ssh_diagnostic", {"command": "df -h"}, False, 12),
                                 ("ssh_diagnostic", {"command": "rm -rf /"}, True, 1)])
    _inv(s, "security_auditor", 20, [("proxmox_api", {"path": "/nodes"}, False, 40)])


def test_tools_list_names_every_configured_tool(tmp_path, monkeypatch):
    html = _client(tmp_path, monkeypatch, _seed).get("/tools").text
    assert "<title>Tools" in html
    for t in TOOLS:
        assert f'href="/tools/{t}"' in html, t
    row = html[html.index('href="/tools/ssh_diagnostic"'):]
    row = row[:row.index("</tr>")]
    assert "Investigator" in row and ">2<" in row and ">1<" in row      # 2 calls, 1 blocked


def test_tool_detail_shows_schema_used_by_and_calls(tmp_path, monkeypatch):
    html = _client(tmp_path, monkeypatch, _seed).get("/tools/ssh_diagnostic").text
    assert 'id="h-def"' in html and ("&#34;command&#34;" in html or '"command"' in html)
    assert 'href="/agents/investigator"' in html and 'href="/agents/auditor"' not in html
    assert dash.TOOL_GUARDS["ssh_diagnostic"] in html
    assert "df -h" in html and "blocked" in html
    prox = _client(tmp_path / "b", monkeypatch, _seed).get("/tools/proxmox_api").text
    assert 'href="/agents/investigator"' in prox and 'href="/agents/auditor"' in prox


def test_tool_definition_is_what_the_model_sees(tmp_path):
    cfg = _cfg(tmp_path)
    schema = dash._tool_definition(cfg.tools["loki_query"])
    assert schema["name"] == "loki_query"
    assert schema["parameters"] == cfg.tools["loki_query"].input_schema()
    json.dumps(schema)


def test_unknown_tool_404(tmp_path, monkeypatch):
    r = _client(tmp_path, monkeypatch, _seed).get("/tools/rm_rf")
    assert r.status_code == 404 and "No tool" in r.text


def test_every_tool_has_a_guard_sentence(tmp_path):
    cfg = _cfg(tmp_path)
    assert set(dash.TOOL_GUARDS) == set(cfg.tools)


def test_overview_tool_card_links_to_tools(tmp_path, monkeypatch):
    html = _client(tmp_path, monkeypatch, _seed).get("/").text
    assert 'href="/tools"' in html[html.index("tool"):]
