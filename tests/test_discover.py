"""Tests for heim.metrics.discover (ports of PAM 43 Filter Names / Format Discovery)."""
from __future__ import annotations

from heim.metrics.discover import filter_names, format_discovery

NAMES = [
    "node_cpu_seconds_total",
    "node_memory_MemFree_bytes",
    "node_filesystem_avail_bytes",
    "pve_up",
    "container_memory_usage_bytes",
    "weird(metric",
]


# ---------------------------------------------------------------- filter_names

def test_filter_names_regex_pattern() -> None:
    assert filter_names(NAMES, "^node_.*bytes$") == [
        "node_memory_MemFree_bytes",
        "node_filesystem_avail_bytes",
    ]


def test_filter_names_regex_alternation() -> None:
    assert filter_names(NAMES, "cpu|pve") == ["node_cpu_seconds_total", "pve_up"]


def test_filter_names_regex_case_insensitive() -> None:
    assert filter_names(NAMES, "MEMFREE") == ["node_memory_MemFree_bytes"]


def test_filter_names_invalid_regex_falls_back_to_substring() -> None:
    # '(' is an invalid regex -> case-insensitive substring match
    assert filter_names(NAMES, "WEIRD(") == ["weird(metric"]


def test_filter_names_empty_pattern_matches_all() -> None:
    assert filter_names(NAMES, "") == NAMES
    assert filter_names(NAMES, "   ") == NAMES


def test_filter_names_no_match() -> None:
    assert filter_names(NAMES, "zzz_nothing") == []


def test_filter_names_capped_at_100() -> None:
    many = [f"metric_{i}" for i in range(150)]
    out = filter_names(many, "metric_")
    assert len(out) == 100
    assert out == many[:100]


def test_filter_names_empty_pattern_capped_at_100() -> None:
    many = [f"metric_{i}" for i in range(150)]
    assert len(filter_names(many, "")) == 100


# ------------------------------------------------------------ format_discovery

def test_format_discovery_names_only() -> None:
    out = format_discovery("node_", ["node_a", "node_b"], None, [])
    assert out == {
        "ok": True,
        "pattern": "node_",
        "matchCount": 2,
        "metricNames": ["node_a", "node_b"],
    }
    assert "sampleSeries" not in out


def test_format_discovery_empty_metric_means_no_series() -> None:
    out = format_discovery("x", [], "", [{"job": "n"}])
    assert "sampleSeries" not in out
    assert out["matchCount"] == 0


def test_format_discovery_with_metric_includes_sample_series() -> None:
    labelsets = [{"job": "node", "cpu": str(i)} for i in range(45)]
    out = format_discovery("cpu", ["node_cpu_seconds_total"], "node_cpu_seconds_total", labelsets)
    assert out["metric"] == "node_cpu_seconds_total"
    assert out["sampleSeries"] == labelsets[:30]
    assert out["seriesShown"] == 30
    assert out["seriesTotal"] == 45


def test_format_discovery_series_under_cap() -> None:
    labelsets = [{"job": "node"}]
    out = format_discovery("up", ["up"], "up", labelsets)
    assert out["sampleSeries"] == labelsets
    assert out["seriesShown"] == 1
    assert out["seriesTotal"] == 1
