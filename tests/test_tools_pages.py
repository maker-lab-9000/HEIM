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


# ------------------------------------------ feedback issues (spec 2026-11-08)

ISSUE_URL = "https://github.invalid/o/r/issues/42"


def _with_issue(s):
    _seed(s)
    s.set_feedback_issue("loki_query", 42, "open", ISSUE_URL, 7, "2026-11-08T09:00:00+00:00")


def test_tool_page_links_its_issue(tmp_path, monkeypatch):
    html = _client(tmp_path, monkeypatch, _with_issue).get("/tools/loki_query").text
    assert f'href="{ISSUE_URL}"' in html and 'rel="noopener"' in html
    assert "Issue #42" in html and "open" in html and "7 comments" in html


def test_tool_page_shows_waiting_and_failed_rows(tmp_path, monkeypatch):
    def seed(s):
        _seed(s)
        s.queue_feedback("loki_query", 1, "add X")
        r = s.queue_feedback("loki_query", 1, "add Y")
        s.mark_feedback_failed(r, "HTTPStatusError: 401 Bad credentials")
        g = s.queue_feedback("loki_query", 1, "add Z")
        for _ in range(10):
            s.mark_feedback_failed(g, "HTTPStatusError: 404")
    html = _client(tmp_path, monkeypatch, seed).get("/tools/loki_query").text
    assert "Waiting" in html and "Retrying" in html and "Failed" in html
    assert "401 Bad credentials" in html


def test_tools_list_shows_issue_number(tmp_path, monkeypatch):
    html = _client(tmp_path, monkeypatch, _with_issue).get("/tools").text
    row = html[html.index('href="/tools/loki_query"'):]
    row = row[:row.index("</tr>")]
    assert f'href="{ISSUE_URL}"' in row and "#42" in row


def test_security_page_links_audit_issue(tmp_path, monkeypatch):
    def seed(s):
        _seed(s)
        s.insert_run(kind="security_audit", run_at="2026-11-02T06:00:00+01:00", overall="ok")
        s.set_feedback_issue("security_audit", 51, "open", "https://github.invalid/51", 2, "")
    html = _client(tmp_path, monkeypatch, seed).get("/security").text
    assert 'href="https://github.invalid/51"' in html and "Issue #51" in html


def test_no_issue_line_when_none(tmp_path, monkeypatch):
    html = _client(tmp_path, monkeypatch, _seed).get("/tools/loki_query").text
    assert "Issue #" not in html and "github" not in html.lower().split("<main", 1)[-1].replace(
        "github_issues", "")
