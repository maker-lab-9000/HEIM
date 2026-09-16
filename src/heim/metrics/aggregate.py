"""Fold Prometheus query_range results into the compact daily payload.

Port of the n8n "Aggregate & Summarize" Code node from workflow PAM-10 Daily
Analysis (``reference/pam-10-daily-analysis/aggregate-summarize.js``).

Input contract mapping
----------------------
The n8n node read two parallel item lists: ``$('Build Queries').all()`` (the
query metadata, one item per query) and ``$input.all()`` (the HTTP node's raw
query_range response for the same index). Here each element of ``results``
bundles the pair into one dict::

    {
        "query": <QueryDef fields as a dict: qid, category, label, unit,
                  dir, warn, crit, promql>,
        "data":  <raw Prometheus query_range response JSON, or None>,
        "error": <str, or None>,
    }

A non-``None`` ``error`` (or missing/failed ``data``) is equivalent to the
n8n HTTP node handing the JS a non-success response: the query is counted in
``counts.naQueries`` and skipped — the run degrades gracefully.

Output shape (identical to the JS node's single returned item)::

    {
        "payload": {
            "generatedAt": <ISO timestamp>,
            "windowDays": 3,
            "hosts": [<sorted host names>],
            "counts": {"crit": int, "warn": int, "naQueries": int},
            "overall": "critical" | "warning" | "healthy",
            "categories": {<category>: [<row>, ...], ...},
            "topAlerts": [<up to 15 alert rows with "sev">],
        },
        "alerts": [<all crit/warn alert rows, sorted>],
    }

Each row: ``{host, label, name, unit, qid, category, current, avg, min, max,
day3d, changePct, flag}``.

Fidelity note: the JS filtered NaN sample *values* but bucketed by the
unfiltered timestamp list, which misaligns indices when a series contains
non-numeric samples. This port filters (timestamp, value) pairs jointly —
identical results for all-finite series (the normal case), and well-defined
per-day buckets when stray non-numeric samples appear.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal

_DAY_SECONDS = 86400
_TOP_ALERTS = 15

#: instance-IP -> friendly host name. The JS ``hostFromMetric`` hardcoded the
#: deployment's map; here it is passed in (``settings.instance_host_map``).

_VETH_RE = re.compile(r"^veth", re.IGNORECASE)


def _to_fixed(value: float, digits: int) -> float:
    """JS ``+x.toFixed(n)``: round half away from zero at ``n`` decimals."""
    quantum = Decimal(1).scaleb(-digits)
    return float(Decimal(value).quantize(quantum, rounding=ROUND_HALF_UP))


def _host_from_metric(metric: dict | None, host_by_ip: dict[str, str]) -> str:
    """Port of ``hostFromMetric``."""
    if not metric:
        return "unknown"
    instance = metric.get("instance") or ""
    ip = instance.split(":")[0]
    mapped = host_by_ip.get(ip)
    if mapped is not None:
        return mapped
    return instance or "unknown"


def _series_name(metric: dict | None, guest_names: dict[str, str]) -> str:
    """Port of ``seriesName``."""
    if not metric:
        return ""
    mid = metric.get("id")
    if mid:
        if mid.startswith("qemu/") or mid.startswith("lxc/"):
            return guest_names.get(mid, mid)
        if mid.startswith("storage/"):
            return mid.split("/")[-1]
        if mid.startswith("node/") or mid.startswith("cluster/"):
            return ""
        return mid
    parts: list[str] = []
    if metric.get("device"):
        parts.append(metric["device"])
    if metric.get("mountpoint"):
        parts.append(metric["mountpoint"])
    if metric.get("chip"):
        parts.append(metric["chip"])
    if metric.get("sensor") and not metric.get("chip"):
        parts.append(metric["sensor"])
    return " ".join(parts)


def _flag_for(cur: float | None, mq: dict) -> str:
    """Port of ``flagFor`` — ok/warn/crit/na by threshold direction."""
    if cur is None or (isinstance(cur, float) and math.isnan(cur)):
        return "na"
    direction = mq["dir"]
    if direction == "one":
        return "ok" if cur >= 1 else "crit"
    if direction == "zero":
        return "crit" if cur > 0 else "ok"
    if direction == "info":
        return "ok"
    if direction == "vmup":
        return "ok" if cur >= 1 else "na"
    if direction == "low":
        if cur <= mq["crit"]:
            return "crit"
        if cur <= mq["warn"]:
            return "warn"
        return "ok"
    if cur >= mq["crit"]:
        return "crit"
    if cur >= mq["warn"]:
        return "warn"
    return "ok"


def _valid_matrix(data: dict | None) -> bool:
    """True if ``data`` looks like a query_range response with a result list."""
    return (
        isinstance(data, dict)
        and bool(data.get("data"))
        and isinstance(data["data"].get("result"), list)
    )


def _parse_pairs(series: dict) -> tuple[list[float], list[float]]:
    """Extract finite (timestamps, values) from a matrix series, jointly."""
    ts: list[float] = []
    vals: list[float] = []
    for pair in series.get("values") or []:
        try:
            v = float(pair[1])
        except (TypeError, ValueError):
            continue
        if math.isnan(v) or math.isinf(v):
            continue
        ts.append(pair[0])
        vals.append(v)
    return ts, vals


def aggregate(results: list[dict], now: datetime | None = None,
              instance_host_map: dict[str, str] | None = None) -> dict:
    """Fold query_range results into the daily payload (pure, no I/O).

    ``now`` stamps ``payload.generatedAt`` (the JS used ``$now.toISO()``);
    defaults to the current UTC time.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    # First pass: Proxmox guest id -> name map from the pve_guest_info query.
    guest_names: dict[str, str] = {}
    for item in results:
        if item["query"]["qid"] != "pve_guest_info":
            continue
        data = item.get("data")
        if not _valid_matrix(data):
            continue
        for series in data["data"]["result"]:
            metric = series.get("metric")
            if metric and metric.get("id") and metric.get("name"):
                guest_names[metric["id"]] = metric["name"]

    categories: dict[str, list[dict]] = {}
    alerts: list[dict] = []
    hosts: set[str] = set()
    crit_count = 0
    warn_count = 0
    na_queries = 0

    for item in results:
        mq = item["query"]
        data = item.get("data")
        if mq["qid"] == "pve_guest_info":
            continue
        if (
            item.get("error") is not None
            or not isinstance(data, dict)
            or data.get("status") != "success"
            or not _valid_matrix(data)
        ):
            na_queries += 1
            continue

        for series in data["data"]["result"]:
            ts, vals = _parse_pairs(series)
            if not vals:
                continue
            cur = vals[-1]
            first = vals[0]
            mn = min(vals)
            mx = max(vals)
            avg = sum(vals) / len(vals)

            # Per-day buckets: index 0 = oldest day, 2 = most recent day,
            # by sample age relative to the last timestamp.
            t_end = ts[-1] if ts else 0
            buckets: list[list[float]] = [[], [], []]
            for j, t in enumerate(ts):
                age_days = (t_end - t) / _DAY_SECONDS
                bi = 2 - min(2, math.floor(age_days))
                if bi < 0:
                    bi = 0
                buckets[bi].append(vals[j])
            day_avg = [
                _to_fixed(sum(b) / len(b), 3) if b else None for b in buckets
            ]

            # Change % first -> current sample.
            if first != 0:
                change_pct: float | None = _to_fixed(
                    (cur - first) / abs(first) * 100, 1
                )
            else:
                change_pct = 100 if cur != 0 else 0
            if mq["unit"] in ("state", "online"):
                change_pct = None

            flag = _flag_for(cur, mq)

            metric = series.get("metric")
            host = _host_from_metric(metric, instance_host_map or {})
            name = _series_name(metric, guest_names)
            mid = (metric or {}).get("id")
            if mid and (mid.startswith("qemu/") or mid.startswith("lxc/")):
                host = guest_names.get(mid, mid)
                name = ""
            device = str((metric or {}).get("device") or "")
            if host == "ubuntu-server" and _VETH_RE.match(device):
                continue
            hosts.add(host)

            row = {
                "host": host,
                "label": mq["label"],
                "name": name,
                "unit": mq["unit"],
                "qid": mq["qid"],
                "category": mq["category"],
                "current": _to_fixed(cur, 3),
                "avg": _to_fixed(avg, 3),
                "min": _to_fixed(mn, 3),
                "max": _to_fixed(mx, 3),
                "day3d": day_avg,
                "changePct": change_pct,
                "flag": flag,
            }
            categories.setdefault(mq["category"], []).append(row)
            if flag == "crit":
                crit_count += 1
                alerts.append({"sev": "crit", **row})
            elif flag == "warn":
                warn_count += 1
                alerts.append({"sev": "warn", **row})

    # crit first, then warn; within a severity, largest |changePct| first
    # (null changePct sorts as 0, like Math.abs(null) in JS).
    rank = {"crit": 0, "warn": 1}
    alerts.sort(key=lambda a: (rank[a["sev"]], -abs(a["changePct"] or 0)))

    overall = (
        "critical" if crit_count > 0 else "warning" if warn_count > 0 else "healthy"
    )

    payload = {
        "generatedAt": now.isoformat(timespec="milliseconds"),
        "windowDays": 3,
        "hosts": sorted(hosts),
        "counts": {"crit": crit_count, "warn": warn_count, "naQueries": na_queries},
        "overall": overall,
        "categories": categories,
        "topAlerts": alerts[:_TOP_ALERTS],
    }

    return {"payload": payload, "alerts": alerts}
