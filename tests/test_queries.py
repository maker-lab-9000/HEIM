"""Tests for the daily query catalog (port of the n8n "Build Queries" node)."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from heim.metrics.queries import QueryDef, build_window, load_queries

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG = REPO_ROOT / "config" / "queries" / "daily.yaml"


def test_yaml_loads_and_count_matches_js():
    queries = load_queries(CATALOG)
    # build-queries.js defines exactly 49 query objects.
    assert len(queries) == 49
    assert all(isinstance(q, QueryDef) for q in queries)
    # qids are unique.
    assert len({q.qid for q in queries}) == 49


def test_query_fields_are_well_formed():
    queries = load_queries(CATALOG)
    allowed_dirs = {"high", "low", "one", "zero", "info", "vmup"}
    for q in queries:
        assert q.dir in allowed_dirs, q.qid
        assert isinstance(q.warn, float), q.qid
        assert isinstance(q.crit, float), q.qid
        assert q.promql.strip(), q.qid
        # promBase must never leak into the catalog: the runtime supplies it.
        assert "http://" not in q.promql and "9090" not in q.promql, q.qid


def test_spot_check_promql_verbatim():
    by_qid = {q.qid: q for q in load_queries(CATALOG)}

    cpu = by_qid["cpu_busy"]
    assert cpu.promql == (
        '100 * (1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])))'
    )
    assert (cpu.category, cpu.label, cpu.unit, cpu.dir) == ("CPU", "CPU busy", "%", "high")
    assert (cpu.warn, cpu.crit) == (80, 95)

    net_err = by_qid["net_err"]
    assert net_err.promql == (
        'rate(node_network_receive_errs_total{device=~"nic0|enp.*|eno.*|eth.*"}[5m])'
        ' + rate(node_network_transmit_errs_total{device=~"nic0|enp.*|eno.*|eth.*"}[5m])'
        ' + rate(node_network_receive_drop_total{device=~"nic0|enp.*|eno.*|eth.*"}[5m])'
        ' + rate(node_network_transmit_drop_total{device=~"nic0|enp.*|eno.*|eth.*"}[5m])'
    )
    assert (net_err.dir, net_err.warn, net_err.crit) == ("high", 0.1, 1)

    svc = by_qid["ha_svc_uptime"]
    assert svc.promql == (
        'min by (instance) (hass_sensor_unit_percent{entity=~".+_uptime_1_day"})'
    )
    assert (svc.dir, svc.warn, svc.crit) == ("low", 99, 95)

    # The guest-name lookup query used by the aggregate must be present.
    assert by_qid["pve_guest_info"].promql == "pve_guest_info"


def test_window_shape_matches_js():
    now = datetime(2026, 1, 10, 12, 0, 0, tzinfo=timezone.utc)
    window = build_window(now)
    # Exactly the fields the JS node emitted alongside each query.
    assert set(window) == {"start", "end", "step"}
    assert window["step"] == "3h"
    assert window["end"] == "2026-01-10T12:00:00.000+00:00"
    assert window["start"] == "2026-01-07T12:00:00.000+00:00"
    # start = end - 3 days, like $now.minus({days: 3}).
    start = datetime.fromisoformat(window["start"])
    end = datetime.fromisoformat(window["end"])
    assert end - start == timedelta(days=3)


def test_yaml_window_block_matches_js_constants():
    with open(CATALOG, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    assert doc["window"] == {"days": 3, "step": "3h"}
