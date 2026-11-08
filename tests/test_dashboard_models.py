"""The daily analyst's Models panel on /agents/daily (spec 2026-11-04 §4/§5).

The dashboard may override the chain's order from ``settings.analyst_models``
and nothing else; the daemon reads the override at the next run.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.config import ModelRef, load_config
from heim.dashboard import app as dash
from heim.dashboard.app import create_app
from heim.incidents.store import IncidentStore

ROOT = Path(__file__).resolve().parent.parent

OPUS = ModelRef(provider="anthropic", model="claude-opus-5-5")
DEEPSEEK = ModelRef(provider="openrouter", model="deepseek/deepseek-v4.1-flash-1017")
UNPRICED = ModelRef(provider="openai_compat", model="local", base_url="http://llama:8080/v1")


def _client(tmp_path, allowed):
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    cfg.settings.db_path = str(tmp_path / "heim.sqlite3")
    cfg.settings.analyst_models = list(allowed)
    IncidentStore(cfg.settings.db_path).close()
    return cfg, TestClient(create_app(cfg))


@pytest.fixture()
def client(tmp_path):
    return _client(tmp_path, [OPUS, DEEPSEEK, UNPRICED])


@pytest.fixture()
def readonly(tmp_path):
    return _client(tmp_path, [])


def _store(cfg):
    return IncidentStore(cfg.settings.db_path)


def _panel(html: str) -> str:
    start = html.index('id="h-models"')
    return html[start:html.index("</section>", start)]


def test_panel_shows_yaml_chain_as_default(client):
    _cfg, c = client
    panel = _panel(c.get("/agents/daily").text)
    assert panel.index("claude-opus-5-5") < panel.index("deepseek/deepseek-v4.1-flash-1017")
    assert "default" in panel


def test_panel_only_on_the_daily_agent(client):
    _cfg, c = client
    assert 'id="h-models"' not in c.get("/agents/backup").text


def test_panel_read_only_when_no_allow_list(readonly):
    _cfg, c = readonly
    panel = _panel(c.get("/agents/daily").text)
    assert "claude-opus-5-5" in panel
    assert 'action="/actions/models"' not in panel


def test_set_override_stores_chain_in_slot_order(client):
    cfg, c = client
    r = c.post("/actions/models", data={"action": "set", "slot_1": DEEPSEEK.key,
                                        "slot_2": OPUS.key, "slot_3": "",
                                        "back": "/agents/daily"}, follow_redirects=False)
    assert r.status_code == 303
    got = _store(cfg).model_override("daily_analyst")
    assert [e["model"] for e in got["chain"]] == ["deepseek/deepseek-v4.1-flash-1017",
                                                  "claude-opus-5-5"]
    panel = _panel(c.get("/agents/daily").text)
    assert "override" in panel
    assert panel.index("deepseek/deepseek-v4.1-flash-1017") < panel.index("claude-opus-5-5")


def test_htmx_set_returns_the_panel_with_feedback(client):
    _cfg, c = client
    r = c.post("/actions/models", data={"action": "set", "slot_1": OPUS.key},
               headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert 'id="h-models"' in r.text and 'class="flash' in r.text


def test_reset_clears_override(client):
    cfg, c = client
    _store(cfg).set_model_override("daily_analyst", [DEEPSEEK.model_dump()])
    r = c.post("/actions/models", data={"action": "reset"}, follow_redirects=False)
    assert r.status_code == 303
    assert _store(cfg).model_override("daily_analyst") is None


@pytest.mark.parametrize("fields", [
    {"slot_1": "", "slot_2": OPUS.key},                      # a gap
    {"slot_1": OPUS.key, "slot_2": OPUS.key},                # a duplicate
    {"slot_1": "", "slot_2": "", "slot_3": ""},              # nothing chosen
    {"slot_1": "openrouter|evil/model"},                     # not allowed
    {"slot_4": OPUS.key},                                    # beyond the allow-list
])
def test_rejects_bad_chains(client, fields):
    cfg, c = client
    r = c.post("/actions/models", data={"action": "set", **fields})
    assert r.status_code == 400
    assert _store(cfg).model_override("daily_analyst") is None


def test_rejects_set_when_nothing_is_allowed(readonly):
    cfg, c = readonly
    r = c.post("/actions/models", data={"action": "set", "slot_1": OPUS.key})
    assert r.status_code == 400
    assert _store(cfg).model_override("daily_analyst") is None


def test_rejects_unknown_action(client):
    _cfg, c = client
    assert c.post("/actions/models", data={"action": "explode"}).status_code == 400


def test_stale_override_is_labelled(client):
    cfg, c = client
    _store(cfg).set_model_override("daily_analyst",
                                   [{"provider": "openrouter", "model": "gone/model"}])
    panel = _panel(c.get("/agents/daily").text)
    assert "ignored" in panel
    assert panel.index("claude-opus-5-5") < panel.index("deepseek/deepseek-v4.1-flash-1017")


def test_unpriced_entry_is_marked(client):
    _cfg, c = client
    panel = _panel(c.get("/agents/daily").text)
    assert "unpriced" in panel


def test_overview_and_findings_mark_a_fallback_run(client):
    cfg, c = client
    attempts = [{"provider": "anthropic", "model": "claude-opus-5-5", "ok": False,
                 "error": "usage limits", "input_tokens": 0, "output_tokens": 0},
                {"provider": "openrouter", "model": "deepseek/deepseek-v4.1-flash-1017",
                 "ok": True, "error": "", "input_tokens": 9, "output_tokens": 9}]
    store = _store(cfg)
    rid = store.insert_run(kind="daily", run_at="2026-11-04T07:00:00+01:00", overall="healthy",
                           model_used="deepseek/deepseek-v4.1-flash-1017",
                           attempts_json=json.dumps(attempts))
    # the findings page lists runs through their findings
    store.insert_findings(rid, "2026-11-04T07:00:00+01:00", "daily",
                          [{"host": "homelab", "metric": "cpu", "severity": "warning",
                            "trend": "rising", "summary": "CPU climbing", "detail": "",
                            "recommendation": ""}], [""])
    for path in ("/", "/findings"):
        html = c.get(path).text
        assert "fallback" in html, path
        assert "usage limits" in html, path


def test_a_first_try_run_is_not_marked(client):
    cfg, c = client
    attempts = [{"provider": "anthropic", "model": "claude-opus-5-5", "ok": True,
                 "error": "", "input_tokens": 9, "output_tokens": 9}]
    _store(cfg).insert_run(kind="daily", run_at="2026-11-04T07:00:00+01:00", overall="healthy",
                           model_used="claude-opus-5-5", attempts_json=json.dumps(attempts))
    html = c.get("/").text
    assert "fallback" not in html[html.index("latest runs"):]


def test_action_helpers_allow_list():
    assert "set_model_override" in dash._ACTION_HELPERS
    assert "clear_model_override" in dash._ACTION_HELPERS


# ------------------------------------------------ final review fixes


def test_run_table_text_for_normal_and_fallback_runs():
    normal = {"ok": True, "detail": {"queries": 50, "hosts": 4, "fallback": False,
                                     "model_used": "claude-opus-5-5", "failed_models": []}}
    assert dash._what_happened(normal) == "50 queries · 4 hosts"
    fb = {"ok": True, "detail": {"queries": 50, "hosts": 4, "fallback": True,
                                 "model_used": "deepseek/deepseek-v4.1-flash-1017",
                                 "failed_models": ["claude-opus-5-5"]}}
    assert dash._what_happened(fb) == ("50 queries · 4 hosts · answered by "
                                       "deepseek/deepseek-v4.1-flash-1017 (fallback)")


def test_htmx_invalid_chain_returns_the_panel_with_the_error(client):
    cfg, c = client
    r = c.post("/actions/models", data={"action": "set", "slot_1": OPUS.key, "slot_2": OPUS.key},
               headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert 'id="h-models"' in r.text
    assert 'class="flash mono err"' in r.text and "Each model can appear once." in r.text
    assert _store(cfg).model_override("daily_analyst") is None


def test_slots_are_compacted_when_a_yaml_entry_is_not_offered(tmp_path):
    cfg, c = _client(tmp_path, [DEEPSEEK])      # Opus (YAML's first) is not offered
    html = _panel(c.get("/agents/daily").text)
    first = html[html.index('name="slot_1"'):html.index("</select>", html.index('name="slot_1"'))]
    assert f'value="{DEEPSEEK.key}" selected' in first


# ------------------------------------------- the investigator's model (spec
# 2026-11-04-investigator-openrouter): one model, same panel, same route


@pytest.fixture()
def inv_client(tmp_path):
    cfg, c = _client(tmp_path, [OPUS, DEEPSEEK])
    cfg.settings.investigator_models = [OPUS, DEEPSEEK]
    return cfg, TestClient(create_app(cfg))


def test_investigator_panel_shows_yaml_default(inv_client):
    _cfg, c = inv_client
    panel = _panel(c.get("/agents/investigator").text)
    assert "claude-sonnet-5-5" in panel and "default" in panel
    assert "config/agents/investigator.yaml" in panel
    assert panel.count("<select") == 1
    assert 'name="agent" value="investigator"' in panel


def test_set_investigator_override(inv_client):
    cfg, c = inv_client
    r = c.post("/actions/models", data={"agent": "investigator", "action": "set",
                                        "slot_1": DEEPSEEK.key,
                                        "back": "/agents/investigator"},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/agents/investigator"
    got = _store(cfg).model_override("investigator")
    assert [e["model"] for e in got["chain"]] == [DEEPSEEK.model]
    assert _store(cfg).model_override("daily_analyst") is None
    panel = _panel(c.get("/agents/investigator").text)
    assert "override" in panel and DEEPSEEK.model in panel


def test_investigator_rejects_two_models(inv_client):
    cfg, c = inv_client
    r = c.post("/actions/models", data={"agent": "investigator", "action": "set",
                                        "slot_1": OPUS.key, "slot_2": DEEPSEEK.key})
    assert r.status_code == 400 and "Pick one model." in r.text
    assert _store(cfg).model_override("investigator") is None


def test_rejects_unknown_agent(inv_client):
    _cfg, c = inv_client
    r = c.post("/actions/models", data={"agent": "security", "action": "set",
                                        "slot_1": OPUS.key})
    assert r.status_code == 400


def test_reset_investigator_override(inv_client):
    cfg, c = inv_client
    _store(cfg).set_model_override("investigator", [DEEPSEEK.model_dump()])
    _store(cfg).set_model_override("daily_analyst", [OPUS.model_dump()])
    r = c.post("/actions/models", data={"agent": "investigator", "action": "reset"},
               follow_redirects=False)
    assert r.status_code == 303
    assert _store(cfg).model_override("investigator") is None
    assert _store(cfg).model_override("daily_analyst") is not None


def test_dropdown_lists_keys_and_effective_default(inv_client):
    cfg, c = inv_client
    _store(cfg).set_model_override("investigator", [DEEPSEEK.model_dump()])
    html = c.get("/hosts").text
    sel = html[html.index('name="model"'):]
    sel = sel[:sel.index("</select>")]
    assert f"default ({DEEPSEEK.model})" in sel
    assert f'value="{OPUS.key}"' in sel and f'value="{DEEPSEEK.key}"' in sel
    assert "· openrouter" in sel


def test_investigate_action_accepts_key_and_bare_id(inv_client):
    cfg, c = inv_client
    for value in (DEEPSEEK.key, DEEPSEEK.model):
        r = c.post("/actions/investigate", data={"host": "ubuntu-server", "model": value},
                   follow_redirects=False)
        assert r.status_code == 303
        assert _store(cfg).jobs(limit=1)[0]["payload"]["model"] == DEEPSEEK.key


def test_detail_shows_provider_for_openrouter_run(inv_client):
    cfg, c = inv_client
    s = _store(cfg)
    inv = s.create_investigation(host="ubuntu-server", agent_name="investigator",
                                 model=DEEPSEEK.model, provider="openrouter",
                                 status="complete", started_at="2026-11-04T10:00:00+01:00",
                                 finished_at="2026-11-04T10:05:00+01:00")
    html = c.get(f"/investigations/{inv}").text
    assert f"{DEEPSEEK.model} (openrouter)" in html


def test_pending_unpinned_row_shows_current_model(inv_client):
    cfg, c = inv_client
    s = _store(cfg)
    unpinned = s.create_investigation(host="ubuntu-server", agent_name="investigator",
                                      model="claude-sonnet-5-5", status="pending_approval",
                                      started_at="2026-11-04T10:00:00+01:00")
    pinned = s.create_investigation(host="ubuntu-server", agent_name="investigator",
                                    model="claude-opus-5-5", model_pinned=1,
                                    status="pending_approval",
                                    started_at="2026-11-04T10:00:00+01:00")
    s.set_model_override("investigator", [DEEPSEEK.model_dump()])
    assert f"will run on {DEEPSEEK.model}" in c.get(f"/investigations/{unpinned}").text
    html = c.get(f"/investigations/{pinned}").text
    assert "will run on claude-opus-5-5" in html and DEEPSEEK.model not in html
