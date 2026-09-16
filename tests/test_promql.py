"""Tests for heim.metrics.promql (ports of PAM 41 Build Request / Format Result)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from heim.metrics.promql import RangeParams, build_range, compact_result

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
NOW_S = int(NOW.timestamp())


# ---------------------------------------------------------------- build_range

@pytest.mark.parametrize(
    "lookback,expected_seconds",
    [
        ("30m", 1800),
        ("6h", 21600),
        ("24h", 86400),
        ("3d", 259200),
        ("90s", 90),
    ],
)
def test_build_range_lookback_units(lookback: str, expected_seconds: int) -> None:
    p = build_range(lookback, None, NOW)
    assert p.end == float(NOW_S)
    assert p.start == float(NOW_S - expected_seconds)


def test_build_range_clamps_at_3d() -> None:
    for lookback in ("1w", "4d", "100h"):
        p = build_range(lookback, None, NOW)
        assert p.end - p.start == 3 * 86400
        assert p.step_seconds == 2592  # ceil(259200/100)


@pytest.mark.parametrize(
    "lookback,expected_step",
    [
        ("30m", 18),  # ceil(1800/100)
        ("6h", 216),
        ("24h", 864),
        ("3d", 2592),
        ("90s", 15),  # floor of 15s wins over ceil(90/100)=1
    ],
)
def test_build_range_auto_step_about_100_points(
    lookback: str, expected_step: int
) -> None:
    p = build_range(lookback, None, NOW)
    assert p.step_seconds == expected_step
    span = p.end - p.start
    assert span / p.step_seconds <= 100


def test_build_range_explicit_step_honored() -> None:
    assert build_range("6h", "5m", NOW).step_seconds == 300


def test_build_range_explicit_step_floored_at_auto_step() -> None:
    # 1m < auto step of 216s for 6h -> auto step wins
    assert build_range("6h", "1m", NOW).step_seconds == 216


def test_build_range_unparseable_step_falls_back_to_auto() -> None:
    # the JS treated a bad step like an absent one
    assert build_range("6h", "banana", NOW).step_seconds == 216


@pytest.mark.parametrize("garbage", ["yesterday", "", "10", "h", "3 d", "10x"])
def test_build_range_garbage_lookback_raises(garbage: str) -> None:
    with pytest.raises(ValueError):
        build_range(garbage, None, NOW)


def test_build_range_returns_frozen_dataclass() -> None:
    p = build_range("30m", None, NOW)
    assert isinstance(p, RangeParams)
    with pytest.raises(Exception):
        p.start = 0  # type: ignore[misc]


# ------------------------------------------------------------- compact_result

def _matrix_resp(result: list[dict]) -> dict:
    return {"status": "success", "data": {"resultType": "matrix", "result": result}}


def _vector_resp(result: list[dict]) -> dict:
    return {"status": "success", "data": {"resultType": "vector", "result": result}}


def test_compact_result_failure_response() -> None:
    out = compact_result({"status": "error", "error": "boom"}, "up")
    assert out["ok"] is False
    assert out["error"] == "Query failed or returned no data"
    assert "boom" in out["raw"]
    assert out["promql"] == "up"


def test_compact_result_evenly_spaced_matrix_uses_step_sec() -> None:
    resp = _matrix_resp(
        [
            {
                "metric": {"job": "node"},
                "values": [[1000, "1"], [1060, "2"], [1120, "3"], [1180, "4"]],
            }
        ]
    )
    out = compact_result(resp, "q")
    assert out["ok"] is True
    assert out["resultType"] == "matrix"
    assert out["count"] == 1
    s = out["series"][0]
    assert s["start"] == "1970-01-01T00:16:40Z"
    assert s["stepSec"] == 60
    assert s["values"] == [1, 2, 3, 4]
    assert "offsetsSec" not in s
    assert "format" in out and "stepSec" in out["format"]


def test_compact_result_gappy_matrix_uses_offsets() -> None:
    resp = _matrix_resp(
        [
            {
                "metric": {"job": "node"},
                "values": [[1000, "1"], [1060, "2"], [1130, "3"]],
            }
        ]
    )
    s = compact_result(resp, "q")["series"][0]
    assert s["offsetsSec"] == [0, 60, 130]
    assert s["values"] == [1, 2, 3]
    assert "stepSec" not in s


def test_compact_result_two_point_series_never_uniform() -> None:
    # JS requires > 2 points to try the stepSec encoding
    resp = _matrix_resp([{"metric": {}, "values": [[1000, "1"], [1060, "2"]]}])
    s = compact_result(resp, "q")["series"][0]
    assert s["offsetsSec"] == [0, 60]


def test_compact_result_empty_values_series() -> None:
    resp = _matrix_resp([{"metric": {"a": "b"}, "values": []}])
    s = compact_result(resp, "q")["series"][0]
    assert s == {"metric": {"a": "b"}, "values": []}


def test_compact_result_downsamples_over_100_points() -> None:
    values = [[1000 + i * 60, str(i)] for i in range(250)]
    resp = _matrix_resp([{"metric": {}, "values": values}])
    s = compact_result(resp, "q")["series"][0]
    # stride = ceil(250/100) = 3 -> indices 0,3,...,249 -> 84 points
    assert len(s["values"]) == 84
    assert len(s["values"]) <= 100
    # still evenly spaced after striding
    assert s["stepSec"] == 180
    assert s["values"][0] == 0 and s["values"][1] == 3


def test_compact_result_series_capped_at_20_with_note() -> None:
    result = [
        {"metric": {"i": str(n)}, "values": [[1000, "1"], [1060, "2"], [1120, "3"]]}
        for n in range(25)
    ]
    out = compact_result(_matrix_resp(result), "q")
    assert out["count"] == 25
    assert len(out["series"]) == 20
    assert "series capped at 20 of 25" in out["note"]


def test_compact_result_shared_labels_hoisted() -> None:
    result = [
        {"metric": {"job": "node", "instance": "a"}, "values": [[0, "1"]]},
        {"metric": {"job": "node", "instance": "b"}, "values": [[0, "2"]]},
    ]
    out = compact_result(_matrix_resp(result), "q")
    assert out["sharedLabels"] == {"job": "node"}
    assert out["series"][0]["metric"] == {"instance": "a"}
    assert out["series"][1]["metric"] == {"instance": "b"}


def test_compact_result_no_shared_labels_for_single_series() -> None:
    out = compact_result(
        _matrix_resp([{"metric": {"job": "node"}, "values": [[0, "1"]]}]), "q"
    )
    assert "sharedLabels" not in out
    assert out["series"][0]["metric"] == {"job": "node"}


def test_compact_result_cadvisor_labels_pruned() -> None:
    result = [
        {
            "metric": {
                "container_label_com_docker_compose_project": "pam",
                "id": "/system.slice/docker-abc.scope",
                "image": "n8nio/n8n:latest",
                "name": "n8n",
                "job": "cadvisor",
            },
            "values": [[0, "1"]],
        }
    ]
    out = compact_result(_matrix_resp(result), "q")
    assert out["series"][0]["metric"] == {"name": "n8n", "job": "cadvisor"}


def test_compact_result_pve_qemu_id_kept() -> None:
    result = [{"metric": {"id": "qemu/101"}, "values": [[0, "1"]]}]
    out = compact_result(_matrix_resp(result), "q")
    assert out["series"][0]["metric"] == {"id": "qemu/101"}


def test_compact_result_image_kept_when_no_name() -> None:
    result = [{"metric": {"image": "busybox"}, "values": [[0, "1"]]}]
    out = compact_result(_matrix_resp(result), "q")
    assert out["series"][0]["metric"] == {"image": "busybox"}


def test_compact_result_values_six_significant_digits() -> None:
    result = [
        {"metric": {}, "values": [[0, "3.14159265"], [60, "123456789"], [120, "NaN"]]}
    ]
    s = compact_result(_matrix_resp(result), "q")["series"][0]
    assert s["values"] == [3.14159, 123457000, None]


def test_compact_result_vector_rounds_and_caps_at_50() -> None:
    result = [
        {"metric": {"i": str(n)}, "value": [1000, "0.123456789"]} for n in range(60)
    ]
    out = compact_result(_vector_resp(result), "q")
    assert out["count"] == 60
    assert len(out["series"]) == 50
    assert out["series"][0]["value"] == 0.123457
    assert "format" not in out  # format note is matrix-only in the JS


def test_compact_result_vector_missing_value_is_none() -> None:
    out = compact_result(_vector_resp([{"metric": {"a": "b"}}]), "q")
    assert out["series"][0] == {"metric": {"a": "b"}, "value": None}
