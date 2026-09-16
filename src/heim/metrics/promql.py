"""Pure PromQL query-range helpers.

Ports of the n8n "PAM 41 - Query Prometheus" workflow Code nodes:

- :func:`build_range` — port of the **Build Request** node
  (``reference/pam-41-query-prometheus/build-request.js``).
- :func:`compact_result` — port of the **Format Result** node
  (``reference/pam-41-query-prometheus/format-result.js``).

Pure functions only; the actual HTTP calls to Prometheus live elsewhere.

Deviations from the JS (documented, deliberate):

- ``build_range`` raises :class:`ValueError` on an unparseable lookback
  instead of silently falling back to an instant query (the caller decides
  what to do); everything else (clamping, min-step) matches the JS.
- ``compact_result`` does not emit the ``mode``/request-``note`` fields the
  JS copied from the upstream "Build Request" node output, because that
  request context is not part of this pure function's inputs. The
  series-cap ``note`` is still produced exactly like the JS.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone

_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)([smhdw])$")
_MULT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_MAX_LOOKBACK_SECONDS = 3 * 86400  # Prometheus retention window: clamp at 3d

_CLIP_LIMIT = 6000
_MISSING = object()
_MAX_MATRIX_SERIES = 20
_MAX_MATRIX_POINTS = 100
_MAX_VECTOR_SERIES = 50


@dataclass(frozen=True)
class RangeParams:
    """Resolved query_range parameters (epoch seconds)."""

    start: float
    end: float
    step_seconds: int


def _js_round(x: float) -> int:
    """JS ``Math.round``: halves round toward +infinity."""
    return math.floor(x + 0.5)


def _secs(s: str) -> int | None:
    """Parse a ``<number><s|m|h|d|w>`` duration into seconds (JS ``secs()``)."""
    m = _DURATION_RE.match(s)
    if not m:
        return None
    return _js_round(float(m.group(1)) * _MULT[m.group(2)])


def build_range(lookback: str, step: str | None, now: datetime) -> RangeParams:
    """Turn the agent's lookback/step into query_range params.

    Port of the n8n "Build Request" Code node (PAM 41 - Query Prometheus).

    - ``lookback`` like ``30m``/``6h``/``24h``/``3d``; clamped to 3d.
    - ``step`` optional; the effective step is never below the auto step
      ``max(15, ceil(lookback/100))`` (~100 points max).

    Raises:
        ValueError: if ``lookback`` cannot be parsed.
    """
    lb = _secs(str(lookback or "").strip().lower())
    if lb is None:
        raise ValueError(f'invalid lookback "{lookback}"')
    clamped = min(lb, _MAX_LOOKBACK_SECONDS)
    now_s = math.floor(now.timestamp())
    st = _secs(str(step).strip().lower()) if step is not None else None
    min_step = max(15, math.ceil(clamped / 100))  # <= ~100 points
    step_seconds = min_step if st is None else max(st, min_step)
    return RangeParams(
        start=float(now_s - clamped), end=float(now_s), step_seconds=step_seconds
    )


def _clip(s: object) -> str:
    s = "" if s is None else str(s)
    if len(s) > _CLIP_LIMIT:
        return s[:_CLIP_LIMIT] + " ...[truncated]"
    return s


def _num(v: object) -> int | float | None:
    """JS ``Number(Number(v).toPrecision(6))``; None for non-finite."""
    try:
        n = float(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if not math.isfinite(n):
        return None
    return _normint(float(f"{n:.6g}"))


def _normint(x: float | int) -> int | float:
    """Collapse integral floats to int so output serializes like JS numbers."""
    if isinstance(x, float) and x.is_integer():
        return int(x)
    return x


def _iso(ts: float) -> str:
    """JS ``new Date(ts*1000).toISOString().slice(0,19)+'Z'``."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _prune(metric: dict | None) -> dict:
    """Drop cAdvisor noise labels; keep PVE ``id=qemu/...`` (cgroup ids start with '/')."""
    m = dict(metric or {})
    for k in list(m.keys()):
        if k.startswith("container_label_"):
            del m[k]
        elif k == "id" and str(m[k])[:1] == "/":
            del m[k]
        elif k == "image" and m.get("name"):
            del m[k]
    return m


def compact_result(resp: dict, promql: str) -> dict:
    """Token-compact encoding of a Prometheus query response.

    Port of the n8n "Format Result" Code node (PAM 41 - Query Prometheus).

    Handles both ``matrix`` (range) and ``vector`` (instant) result types:

    - matrix: at most 20 series x 100 points; evenly-spaced series encoded as
      ``{metric, start, stepSec, values}``, gappy ones as
      ``{metric, start, offsetsSec, values}``; values at 6 significant digits.
    - vector: at most 50 series of ``{metric, value}`` with rounded values.

    Labels identical across all series are hoisted to ``sharedLabels``;
    cAdvisor noise labels are pruned per :func:`_prune`.
    """
    out: dict = {"ok": True, "promql": promql}
    try:
        if (
            not resp
            or resp.get("status") != "success"
            or not resp.get("data")
        ):
            out["ok"] = False
            out["error"] = "Query failed or returned no data"
            out["raw"] = _clip(json.dumps(resp, separators=(",", ":")))
            return out
        data = resp["data"]
        res = [dict(s, metric=_prune(s.get("metric"))) for s in (data.get("result") or [])]
        out["resultType"] = data.get("resultType")
        out["count"] = len(res)

        # hoist labels identical across ALL series into sharedLabels
        shared: dict | None = None
        if len(res) > 1:
            shared = dict(res[0]["metric"])
            for s in res:
                m = s["metric"]
                for k in list(shared.keys()):
                    if m.get(k, _MISSING) != shared[k]:
                        del shared[k]
            if not shared:
                shared = None

        def own_labels(m: dict) -> dict:
            if not shared:
                return m
            return {k: v for k, v in m.items() if k not in shared}

        if shared:
            out["sharedLabels"] = shared

        if data.get("resultType") == "matrix":
            series = []
            for s in res[:_MAX_MATRIX_SERIES]:
                vals = s.get("values") or []
                if len(vals) > _MAX_MATRIX_POINTS:
                    stride = math.ceil(len(vals) / _MAX_MATRIX_POINTS)
                    vals = [v for i, v in enumerate(vals) if i % stride == 0]
                if not vals:
                    series.append({"metric": own_labels(s["metric"]), "values": []})
                    continue
                uniform = len(vals) > 2
                step0 = (vals[1][0] - vals[0][0]) if uniform else 0
                if uniform:
                    for i in range(2, len(vals)):
                        if vals[i][0] - vals[i - 1][0] != step0:
                            uniform = False
                            break
                t0 = vals[0][0]
                if uniform:
                    series.append(
                        {
                            "metric": own_labels(s["metric"]),
                            "start": _iso(t0),
                            "stepSec": _normint(step0),
                            "values": [_num(v[1]) for v in vals],
                        }
                    )
                else:
                    series.append(
                        {
                            "metric": own_labels(s["metric"]),
                            "start": _iso(t0),
                            "offsetsSec": [_js_round(v[0] - t0) for v in vals],
                            "values": [_num(v[1]) for v in vals],
                        }
                    )
            out["series"] = series
            out["format"] = (
                "compact series: {start, stepSec, values} = values evenly spaced "
                "from start every stepSec seconds; {start, offsetsSec, values} = "
                "value[i] is at start + offsetsSec[i] seconds; sharedLabels (if "
                "present) apply to every series"
            )
            if len(res) > _MAX_MATRIX_SERIES:
                out["note"] = (
                    (out.get("note", ""))
                    + f" | series capped at {_MAX_MATRIX_SERIES} of {len(res)}"
                ).strip()
        else:
            out["series"] = [
                {
                    "metric": own_labels(s["metric"]),
                    "value": _num(s["value"][1]) if s.get("value") else None,
                }
                for s in res[:_MAX_VECTOR_SERIES]
            ]
        return out
    except Exception as e:  # mirror the JS catch-all
        out["ok"] = False
        out["error"] = str(e)
        return out
