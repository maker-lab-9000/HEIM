"""Pure metric-discovery helpers.

Ports of the n8n "PAM 43 - Discover Metrics" workflow Code nodes:

- :func:`filter_names` — port of the **Filter Names** node
  (``reference/pam-43-discover-metrics/filter-names.js``).
- :func:`format_discovery` — port of the **Format Discovery** node
  (``reference/pam-43-discover-metrics/format-discovery.js``).

Pure functions only; the actual HTTP calls to Prometheus live elsewhere.

Note on ``matchCount``: the JS computed it before the 100-item slice inside a
single node. Here the cap lives in :func:`filter_names` (per its contract), so
``format_discovery`` reports ``matchCount`` as the length of the (possibly
already capped) list it is given.
"""
from __future__ import annotations

import re


def filter_names(all_names: list[str], pattern: str) -> list[str]:
    """Filter metric names by a pattern; return at most 100 matches.

    Port of the n8n "Filter Names" Code node (PAM 43 - Discover Metrics):
    the pattern is tried as a case-insensitive regex (searched, not anchored);
    if it is not a valid regex it falls back to a case-insensitive substring
    match. An empty pattern matches everything.
    """
    pattern = str(pattern or "").strip()
    if not pattern:
        return list(all_names)[:100]
    rx: re.Pattern[str] | None
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error:
        rx = None
    if rx is not None:
        matches = [n for n in all_names if rx.search(n)]
    else:
        needle = pattern.lower()
        matches = [n for n in all_names if needle in n.lower()]
    return matches[:100]


def format_discovery(
    pattern: str,
    names: list[str],
    metric: str | None,
    series_labelsets: list[dict],
) -> dict:
    """Format the discovery tool response for the agent.

    Port of the n8n "Format Discovery" Code node (PAM 43 - Discover Metrics).
    When ``metric`` is set (the JS ``needSeries`` flag) the sample label-sets
    for that metric are included, capped at 30.
    """
    out: dict = {
        "ok": True,
        "pattern": pattern or "",
        "matchCount": len(names),
        "metricNames": list(names),
    }
    if metric:
        out["metric"] = metric
        out["sampleSeries"] = list(series_labelsets)[:30]
        out["seriesShown"] = min(len(series_labelsets), 30)
        out["seriesTotal"] = len(series_labelsets)
    return out
