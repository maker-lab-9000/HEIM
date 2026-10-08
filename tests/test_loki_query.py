"""loki_query: the agents' read-only window onto journal + docker logs."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
import yaml

from heim.config import ToolCfg
from heim.tools import loki_query as lq
from heim.tools.base import ToolContext

NS = 1_000_000_000
T0 = int(datetime(2026, 10, 8, 11, 0, tzinfo=timezone.utc).timestamp()) * NS


def _stream(labels: dict, *lines: tuple[int, str]) -> dict:
    return {"stream": labels, "values": [[str(T0 + s * NS), text] for s, text in lines]}


# ------------------------------------------------------------------ pure parts

def test_lookback_and_end_parsing():
    assert lq.parse_lookback("") == timedelta(hours=1)
    assert lq.parse_lookback("15m") == timedelta(minutes=15)
    assert lq.parse_lookback("7d") == timedelta(days=7)
    for bad in ("8d", "0m", "1w", "soon"):
        with pytest.raises(ValueError):
            lq.parse_lookback(bad)
    now = datetime(2026, 10, 8, tzinfo=timezone.utc)
    assert lq.parse_end("", now) == now
    assert lq.parse_end("2026-10-08T09:40:00Z", now) == datetime(2026, 10, 8, 9, 40, tzinfo=timezone.utc)


def test_metric_vs_log_query():
    assert not lq.is_metric_query('{host="homelab"} |= "x"')
    assert lq.is_metric_query('sum by (unit) (count_over_time({host="homelab"}[1h]))')


def test_repeats_collapse_but_distinct_events_never_merge():
    sshd = {"host": "ubuntu-server", "unit": "ssh.service", "level": "info"}
    smart = {"host": "homelab", "unit": "smartctl-exporter.service", "level": "error"}
    result = [
        _stream(smart, *[(i, f"ts=2026-10-08T11:00:{i:02d}.1Z msg=\"Device open failed\" device=/dev/sdb") for i in range(30)]),
        _stream(sshd,
                (40, "Accepted password for alice from 192.0.2.10 port 53919 ssh2"),
                (41, "Accepted password for alice from 10.9.9.9 port 50001 ssh2"),      # other IP: separate
                (42, "Accepted password for alice from 192.0.2.10 port 53001 ssh2")), # same IP: merges
        _stream({"host": "ubuntu-server", "container_name": "nextcloud-app-1", "source": "stdout"},
                (50, '"GET /x HTTP/1.1" 200 18616'), (51, '"GET /x HTTP/1.1" 500 18616')),  # 200 vs 500
    ]
    lines, raw = lq.compact_streams(result, limit=50)
    assert raw == 35 and len(lines) == 5
    assert lines[0].startswith("2026-10-08T11:00:51Z  ubuntu-server/nextcloud-app-1  ")  # newest first
    smart_line = next(l for l in lines if "smartctl" in l)
    assert smart_line.startswith("×30 2026-10-08T11:00:00Z→2026-10-08T11:00:29Z  homelab/smartctl-exporter.service [error]")
    assert sum("10.9.9.9" in l for l in lines) == 1
    assert any(l.startswith("×2 ") and "192.0.2.10" in l for l in lines)
    assert any(" 500 " in l for l in lines) and any(" 200 " in l for l in lines)


def test_limit_counts_distinct_lines_and_long_lines_are_clipped():
    s = {"host": "homelab", "unit": "x.service", "level": "info"}
    result = [_stream(s, *[(i, f"event-{chr(97 + i)} " + "y" * 400) for i in range(10)])]
    lines, raw = lq.compact_streams(result, limit=3)
    assert raw == 10 and len(lines) == 3
    assert all(l.endswith("…") for l in lines)


def test_description_documents_labels_gaps_and_noise():
    text = " ".join(yaml.safe_load(open(_yaml()))["description"].split())
    for must in ('job="systemd-journal"', 'container_name="<name>"', "NO level label",
                 "bitwarden-*", "portainer", "smartctl-exporter", "home-assistant", "2026-10-08"):
        assert must in text, must


def _yaml():
    from pathlib import Path
    return Path(__file__).resolve().parent.parent / "config/tools/loki_query.yaml"


# ------------------------------------------------------------- the HTTP path

def _tool(handler, loki=True):
    cfg = ToolCfg(**yaml.safe_load(open(_yaml())))
    settings = SimpleNamespace(loki=SimpleNamespace(url="http://loki.test:3100") if loki else None)
    tool = lq.LokiQueryTool(cfg, ToolContext(config=SimpleNamespace(settings=settings)))
    real = httpx.AsyncClient
    tool_client = lambda **kw: real(transport=httpx.MockTransport(handler), **kw)  # noqa: E731
    return tool, tool_client


async def test_log_query_goes_backward_over_the_window(monkeypatch):
    seen = {}

    def handler(request: httpx.Request):
        seen["path"], seen["params"] = request.url.path, dict(request.url.params)
        return httpx.Response(200, json={"status": "success", "data": {"resultType": "streams", "result": [
            _stream({"host": "homelab", "unit": "pveproxy.service", "level": "info"}, (1, "worker 123456 started"))]}})
    tool, client = _tool(handler)
    monkeypatch.setattr(lq.httpx, "AsyncClient", client)
    out = json.loads(await tool.run({"logql": '{host="homelab"}', "lookback": "30m",
                                     "end": "2026-10-08T11:00:00Z", "limit": 10}))
    assert seen["path"] == "/loki/api/v1/query_range"
    assert seen["params"]["direction"] == "backward" and seen["params"]["limit"] == "50"
    assert int(seen["params"]["end"]) - int(seen["params"]["start"]) == 30 * 60 * NS
    assert out["ok"] and out["mode"] == "lines" and out["shown"] == 1
    assert out["window"] == {"start": "2026-10-08T10:30:00Z", "end": "2026-10-08T11:00:00Z"}


async def test_metric_query_is_instant_and_compact(monkeypatch):
    def handler(request):
        assert request.url.path == "/loki/api/v1/query"
        return httpx.Response(200, json={"status": "success", "data": {"resultType": "vector", "result": [
            {"metric": {"host": "homelab", "unit": "postfix.service"}, "value": [1791457991, "264"]}]}})
    tool, client = _tool(handler)
    monkeypatch.setattr(lq.httpx, "AsyncClient", client)
    out = json.loads(await tool.run({"logql": 'sum by (host, unit) (count_over_time({job="systemd-journal"}[24h]))'}))
    assert out["ok"] and out["mode"] == "metric-instant" and out["count"] == 1


async def test_empty_result_says_how_not_to_misread_it(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={"status": "success", "data": {"resultType": "streams", "result": []}})
    tool, client = _tool(handler)
    monkeypatch.setattr(lq.httpx, "AsyncClient", client)
    out = json.loads(await tool.run({"logql": '{container_name="n8n"} |= "boom"'}))
    assert out["shown"] == 0 and "NO level label" in out["hint"] and "2026-10-08" in out["hint"]


async def test_bad_logql_returns_lokis_parse_error(monkeypatch):
    def handler(request):
        return httpx.Response(400, text="parse error at line 1, col 17: syntax error: unexpected |=")
    tool, client = _tool(handler)
    monkeypatch.setattr(lq.httpx, "AsyncClient", client)
    out = json.loads(await tool.run({"logql": '{host="homelab" |= "x"'}))
    assert out["ok"] is False and "parse error" in out["error"] and "retry once" in out["hint"]


async def test_bad_arguments_and_missing_loki_never_call_out(monkeypatch):
    def handler(request):
        raise AssertionError("must not be called")
    tool, client = _tool(handler)
    monkeypatch.setattr(lq.httpx, "AsyncClient", client)
    assert "between 1m and 7d" in json.loads(await tool.run({"logql": "{a=\"b\"}", "lookback": "30d"}))["error"]
    assert json.loads(await tool.run({"logql": ""}))["ok"] is False
    tool2, _ = _tool(handler, loki=False)
    assert "not configured" in json.loads(await tool2.run({"logql": "{a=\"b\"}"}))["error"]


async def test_output_is_clipped_dropping_the_oldest_lines(monkeypatch):
    s = {"host": "homelab", "unit": "x.service", "level": "info"}

    def handler(request):
        return httpx.Response(200, json={"status": "success", "data": {"resultType": "streams", "result": [
            _stream(s, *[(i, f"distinct-{chr(65 + i % 26)}{chr(65 + i // 26)} " + "z" * 280) for i in range(150)])]}})
    tool, client = _tool(handler)
    monkeypatch.setattr(lq.httpx, "AsyncClient", client)
    text = await tool.run({"logql": '{host="homelab"}', "limit": 150})
    out = json.loads(text)
    assert len(text) <= 12000 and 0 < out["shown"] < 150
    assert out["lines"][0].startswith("2026-10-08T11:02:29Z")   # newest kept
