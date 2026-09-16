"""Query catalog and query_range window for the daily analysis pipeline.

Port of the n8n "Build Queries" Code node from workflow PAM-10 Daily Analysis
(``reference/pam-10-daily-analysis/build-queries.js``).

The JS node returned one item per query carrying ``qid/category/label/unit/
dir/warn/crit/promql`` plus a shared window (``start`` = now - 3 days,
``end`` = now, ``step`` = ``"3h"``) and a hardcoded ``promBase`` URL. In this
port the catalog lives in declarative YAML (``config/queries/daily.yaml``),
the window is computed by :func:`build_window`, and the Prometheus base URL is
supplied by the runtime — it is intentionally absent from the YAML.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

#: Defaults matching the JS node (``$now.minus({days: 3})`` .. ``$now``, step '3h').
DEFAULT_WINDOW_DAYS = 3
DEFAULT_STEP = "3h"


@dataclass(frozen=True)
class QueryDef:
    """One PromQL query definition from the daily catalog.

    ``dir`` semantics (from the JS source): ``high`` high-is-bad | ``low``
    low-is-bad | ``one`` must equal 1 | ``zero`` must stay 0 | ``info``
    informational only | ``vmup`` >=1 is ok, otherwise n/a.
    """

    qid: str
    category: str
    label: str
    unit: str
    dir: str
    warn: float | None
    crit: float | None
    promql: str


def _threshold(value: Any) -> float | None:
    """Normalize a YAML warn/crit threshold to ``float | None``."""
    if value is None:
        return None
    return float(value)


def load_queries(path: str | Path) -> list[QueryDef]:
    """Load the query catalog from a YAML file (``queries:`` list).

    Mirrors the query list emitted by the n8n "Build Queries" Code node.
    """
    from heim.config import expand_env

    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(expand_env(fh.read(), source=str(path)))
    queries = doc["queries"]
    return [
        QueryDef(
            qid=q["qid"],
            category=q["category"],
            label=q["label"],
            unit=q["unit"],
            dir=q["dir"],
            warn=_threshold(q["warn"]),
            crit=_threshold(q["crit"]),
            promql=q["promql"],
        )
        for q in queries
    ]


def _iso(dt: datetime) -> str:
    """ISO-8601 with millisecond precision, like Luxon's ``DateTime.toISO()``.

    (Luxon renders UTC as ``...Z`` where Python renders ``...+00:00``; both
    are valid RFC 3339 and accepted by the Prometheus query_range API.)
    """
    return dt.isoformat(timespec="milliseconds")


def build_window(
    now: datetime,
    *,
    days: int = DEFAULT_WINDOW_DAYS,
    step: str = DEFAULT_STEP,
) -> dict:
    """Compute the query_range window, as the n8n "Build Queries" node did.

    JS source::

        const step = '3h';
        const start = $now.minus({ days: 3 }).toISO();
        const end = $now.toISO();

    Returns ``{"start": <iso>, "end": <iso>, "step": "3h"}`` so the
    Prometheus query_range call (and downstream aggregate) see the same
    shapes the n8n HTTP node received.
    """
    return {
        "start": _iso(now - timedelta(days=days)),
        "end": _iso(now),
        "step": step,
    }
