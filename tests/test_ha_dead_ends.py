"""A 404 from Home Assistant must explain itself.

HA answers a missing log file with the 14-byte body ``404: Not Found``. A live
investigation (#3, 2026-09-20) hit that on ``/api/error_log`` and had nothing to
go on; the agent's own tooling feedback asked for this. The tool now attaches a
``hint`` naming the cause and the endpoints that still work.

The companion to tests/test_ssh_errors.py: same rule, different tool — a tool
that cannot answer says what to do instead of returning a bare failure.
"""
from __future__ import annotations

import json

import httpx
import pytest

from heim.config import ApiCfg, Host, ToolCfg
from heim.tools.base import ToolContext
from heim.tools.ha_api import HaApiTool, _hint


class _Cfg:
    """Minimal config: one HA host with an api block, no settings needed."""

    def __init__(self):
        self.hosts = {"home-assistant": Host(
            name="home-assistant", role="ha-guest",
            api=ApiCfg(url="http://ha.invalid:8123", verify_ssl=False),
        )}


@pytest.fixture(autouse=True)
def _ha_token(monkeypatch):
    monkeypatch.setenv("HA_TOKEN", "test-token")


def _tool() -> HaApiTool:
    cfg = ToolCfg(name="ha_api", module="heim.tools.ha_api:HaApiTool",
                  description="d", options={"host": "home-assistant", "clip_bytes": 8192})
    return HaApiTool(cfg, ToolContext(config=_Cfg()))


# ------------------------------------------------------------- the hint itself


def test_error_log_404_names_the_cause_and_the_alternatives():
    hint = _hint("/api/error_log", 404)
    # the cause, and where to confirm it
    assert "no log file" in hint
    assert "logging.log_file_disabled_reason" in hint
    assert "null" in hint                       # the field is null on a healthy instance
    # the dead end is closed explicitly, so the agent stops hunting
    assert "websocket-only" in hint
    # the vantages that DO work
    assert "/api/states" in hint and "/api/logbook/" in hint
    assert "unavailable" in hint
    # and the honest reporting instruction
    assert "report" in hint


def test_unknown_entity_404_points_at_the_entity_list():
    hint = _hint("/api/states/sensor.nope", 404)
    assert "No such entity" in hint
    assert "/api/states" in hint


def test_no_hint_when_there_is_nothing_useful_to_say():
    assert _hint("/api/error_log", 200) == ""       # a working call
    assert _hint("/api/error_log", 500) == ""       # a server fault, not a dead end
    assert _hint("/api/states", 404) == ""          # the collection, not an entity
    assert _hint("/api/config", 404) == ""          # no guidance to offer


# --------------------------------------------------------- through the tool


async def test_tool_attaches_the_hint_to_a_404(monkeypatch):
    async def fake_get(self, url, **kw):
        return httpx.Response(404, text="404: Not Found",
                              request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    out = json.loads(await _tool()({"path": "/api/error_log"}))

    assert out["ok"] is False and out["status"] == 404
    assert out["body"] == "404: Not Found"          # still reported verbatim
    assert "/api/states" in out["hint"]


async def test_a_successful_call_carries_no_hint(monkeypatch):
    async def fake_get(self, url, **kw):
        return httpx.Response(200, text='{"state": "on"}',
                              request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    out = json.loads(await _tool()({"path": "/api/states/light.kitchen"}))

    assert out["ok"] is True and "hint" not in out


async def test_a_blocked_path_is_unchanged(monkeypatch):
    """The guard's own message is the hint on that path — do not double up."""
    out = json.loads(await _tool()({"path": "/api/services"}))
    assert out["blocked"] is True and "hint" not in out
