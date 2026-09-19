"""Threshold detection: open incidents from the metric catalog's own bounds.

Why this exists
---------------
``config/queries/daily.yaml`` carries a ``warn``/``crit`` bound for every
query, and ``/metrics`` paints ``ok|warn|crit|na`` pills from them — but until
now those flags were *presentational only*. The two paths that could open an
incident were the alert poller (only rules written in ``prometheus/alerts.yml``)
and the twice-daily LLM analysis (only findings the model chose to raise). So a
metric could sit at crit on the dashboard indefinitely with nothing happening.
Observed live: ``pve_vm_cpu`` on ``qemu/100`` read 102.5% against ``crit: 95``
and no incident, no investigation.

Hysteresis is not optional
--------------------------
Over the two hours around that reading, ``qemu/100`` had **1 of 24 points**
above 95 — the current one. Opening on the first crit sample would have burned
an agent run and a human Telegram approval on a single-scrape blip. A
fingerprint therefore has to be over threshold on ``threshold_consecutive``
*consecutive* polls before an incident opens, and the streak lives in the
store (``threshold_streaks``) so a daemon restart cannot silently rearm it.

Identity
--------
Flagging and identity come from the daily path's own helpers
(:func:`heim.metrics.aggregate.flag_for`, :func:`~heim.metrics.aggregate.
series_identity`) and the fingerprint is built the way
:func:`heim.incidents.reconcile.fingerprint_for` builds it —
``norm_host(host)|qid|name``. A threshold-detected series and the same series
seen by the daily reconcile or the alert poller must produce the *same*
fingerprint, or the two paths would double-investigate one problem.

Ownership
---------
Descriptions carry a ``[metric] `` prefix, a third ownership marker alongside
the poller's ``[alert] `` and the LLM's plain text. This path resolves **only**
``[metric] `` incidents, after 2 consecutive under-threshold polls — exactly
mirroring the alert poller's rule for its own rows. If an incident for the
fingerprint already exists from another path it is refreshed, never duplicated
and never re-dispatched.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass, field

import httpx

from heim.incidents.reconcile import (
    SEV_RANK,
    category_of,
    host_role_for,
    is_investigable,
    norm_host,
    norm_sev,
    ssh_host_for,
)
from heim.incidents.types import HostRouting, ThresholdDecision
from heim.metrics.aggregate import flag_for, guest_name_map, series_identity

log = logging.getLogger(__name__)

#: Description prefix that marks an incident as owned by this path.
PREFIX = "[metric] "

#: Consecutive under-threshold polls before a ``[metric] `` incident resolves —
#: the alert poller's rule, unchanged.
RESOLVE_AFTER = 2

#: Concurrent instant queries. ~49 of them per poll is nothing for Prometheus;
#: the cap exists so a poll cannot open 49 sockets at once.
FETCH_CONCURRENCY = 8

#: flag -> incident severity word (reconcile's vocabulary).
_SEVERITY = {"crit": "critical", "warn": "warning"}


@dataclass(frozen=True)
class ThresholdConfig:
    """Everything :func:`decide` needs from configuration and the store.

    ``suppressed`` rides here rather than in a separate argument so the whole
    decision stays a pure function of its inputs; it is the same
    ``active_suppressions`` set the other two paths are filtered with.
    """

    severity: str = "crit"
    consecutive: int = 2
    suppressed: frozenset[str] = field(default_factory=frozenset)

    @property
    def over_flags(self) -> tuple[str, ...]:
        """Flags that count as over threshold (``warn`` includes ``crit``)."""
        return ("crit", "warn") if self.severity == "warn" else ("crit",)

    @classmethod
    def from_settings(cls, settings, suppressed=()) -> "ThresholdConfig":
        return cls(
            severity=str(getattr(settings, "threshold_severity", "crit")),
            consecutive=max(int(getattr(settings, "threshold_consecutive", 2) or 1), 1),
            suppressed=frozenset(suppressed or ()),
        )


# --------------------------------------------------------------- fetching


async def fetch_instants(base_url: str, qdefs) -> list[dict]:
    """One **instant** query per catalog entry; failures degrade per query.

    Deliberately not the daily path's 3-day ``query_range``: this runs every
    five minutes and only ever looks at the newest sample, so a range fetch
    would be ~50x the data for the same answer.
    """
    sem = asyncio.Semaphore(FETCH_CONCURRENCY)
    results: list[dict] = [None] * len(qdefs)  # type: ignore[list-item]

    async with httpx.AsyncClient(timeout=20) as client:
        async def one(i: int, q) -> None:
            item = {"query": asdict(q), "data": None, "error": None}
            try:
                async with sem:
                    r = await client.get(f"{base_url.rstrip('/')}/api/v1/query",
                                         params={"query": q.promql})
                item["data"] = r.json()
            except Exception as exc:
                item["error"] = f"{type(exc).__name__}: {exc}"
            results[i] = item

        await asyncio.gather(*(one(i, q) for i, q in enumerate(qdefs)))
    return results


def _vector(data: dict | None) -> list[dict]:
    """The ``result`` list of a successful instant query, else ``[]``."""
    if not isinstance(data, dict) or data.get("status") != "success":
        return []
    inner = data.get("data")
    if not isinstance(inner, dict) or not isinstance(inner.get("result"), list):
        return []
    return inner["result"]


def _value(series: dict) -> float | None:
    """The sample value of an instant-vector series, or None if unusable."""
    pair = series.get("value")
    if not isinstance(pair, (list, tuple)) or len(pair) < 2:
        return None
    try:
        v = float(pair[1])
    except (TypeError, ValueError):
        return None
    return None if v != v or v in (float("inf"), float("-inf")) else v


def build_samples(results: list[dict],
                  instance_host_map: dict[str, str] | None = None) -> list[dict]:
    """Fold instant-query results into one flagged sample per series (pure).

    Same shape the daily payload rows carry for the fields that matter
    (``host``/``qid``/``name``/``label``/``unit``/``flag``), plus the
    fingerprint the incident tables key on.
    """
    guest_metrics: list[dict] = []
    for item in results:
        if (item.get("query") or {}).get("qid") != "pve_guest_info":
            continue
        guest_metrics += [s.get("metric") for s in _vector(item.get("data"))]
    guest_names = guest_name_map(guest_metrics)

    # dict order is insertion order, and replacing a value keeps its position,
    # so the worst-flag-wins dedupe below preserves catalog order
    seen: dict[str, dict] = {}
    for item in results:
        mq = item.get("query") or {}
        if mq.get("qid") == "pve_guest_info" or item.get("error") is not None:
            continue
        for series in _vector(item.get("data")):
            cur = _value(series)
            identity = series_identity(series.get("metric"), guest_names,
                                       instance_host_map or {})
            if identity is None:
                continue
            host, name = identity
            flag = flag_for(cur, mq)
            fp = f"{norm_host(host)}|{mq.get('qid')}|{name}"
            sample = {
                "fingerprint": fp,
                "host": host,
                "qid": str(mq.get("qid") or ""),
                "name": name,
                "label": str(mq.get("label") or ""),
                "unit": str(mq.get("unit") or ""),
                "metric": (str(mq.get("label") or mq.get("qid") or "")
                           + (f" {name}" if name else "")),
                "current": cur,
                "flag": flag,
                "warn": mq.get("warn"),
                "crit": mq.get("crit"),
                "dir": str(mq.get("dir") or ""),
            }
            prev = seen.get(fp)
            # one fingerprint, one verdict: keep the worst flag seen for it
            if prev is None or _worse(flag, str(prev["flag"])):
                seen[fp] = sample
    return list(seen.values())


_FLAG_RANK = {"crit": 0, "warn": 1, "ok": 2, "na": 3}


def _worse(a: str, b: str) -> bool:
    return _FLAG_RANK.get(a, 3) < _FLAG_RANK.get(b, 3)


def describe(sample: dict, cfg: ThresholdConfig) -> str:
    """The incident description, ``[metric] ``-prefixed (ownership marker)."""
    flag = str(sample.get("flag") or "")
    bound = sample.get("crit") if flag == "crit" else sample.get("warn")
    cur = sample.get("current")
    unit = str(sample.get("unit") or "")
    value = "n/a" if cur is None else f"{cur:g}{unit}"
    limit = "" if bound is None else f" ({flag} threshold {bound:g}{unit})"
    return (f"{PREFIX}{sample.get('metric') or sample.get('qid')} on "
            f"{sample.get('host')} is {value}{limit} — over threshold on "
            f"{cfg.consecutive} consecutive polls")


# ------------------------------------------------------------ pure decision


def decide(samples: list[dict], open_rows: list[dict], streaks: dict[str, dict],
           now_iso: str, routing: HostRouting,
           cfg: ThresholdConfig) -> ThresholdDecision:
    """Diff flagged samples against open incidents and streaks. No I/O.

    Args:
        samples: :func:`build_samples` output for this poll.
        open_rows: currently-open incident rows (every path's, not just ours).
        streaks: ``fingerprint -> {count, severity, last_seen}`` from the store.
        now_iso: this poll's timestamp (injected, for purity).
        routing: host investigability routing, as the daily path uses it.
        cfg: severity/consecutive/suppressed.
    """
    rows: list[dict] = []
    dispatches: list[dict] = []
    notifications: list[dict] = []
    loki: list[dict] = []
    streak_writes: list[dict] = []
    streak_clears: list[str] = []
    state_changed = False

    over_flags = cfg.over_flags
    open_by_fp = {str(r["fingerprint"]): r for r in open_rows
                  if r and r.get("fingerprint")}
    over: set[str] = set()

    for s in samples:
        fp = str(s.get("fingerprint") or "")
        if not fp or fp in cfg.suppressed:
            continue
        flag = str(s.get("flag") or "")
        prev_streak = streaks.get(fp) or {}
        if flag not in over_flags:
            # back under threshold: the streak dies here, so a later crit
            # starts counting from 1 again (the 1-of-24 spike case)
            if prev_streak:
                streak_clears.append(fp)
            continue

        over.add(fp)
        count = int(prev_streak.get("count") or 0) + 1
        streak_writes.append({"fingerprint": fp, "count": count,
                              "severity": flag, "last_seen": now_iso})
        if count < cfg.consecutive:
            continue  # still warming up — no incident, no dispatch

        severity = _SEVERITY.get(flag, "warning")
        description = describe(s, cfg)
        host = str(s.get("host") or "")
        metric = str(s.get("metric") or "")
        category = category_of(fp, metric, description)
        will_inv = is_investigable(fp, host, metric, description, routing)
        prev = open_by_fp.get(fp)

        if prev is None:
            rows.append({
                "fingerprint": fp, "host": host, "metric": metric,
                "severity": severity, "status": "open",
                "firstSeen": now_iso, "lastSeen": now_iso, "resolvedAt": "",
                "timesSeen": 1, "missedRuns": 0, "description": description,
                "investigated": will_inv,
            })
            state_changed = True
            if will_inv:
                dispatches.append(_dispatch(rows[-1], routing))
            elif severity == "critical":
                notifications.append({**rows[-1], "category": category})
            loki.append(_incident_event(fp, host, severity, "new", category,
                                        description, metric, now_iso,
                                        first_seen=now_iso, times_seen=1))
            continue

        # An incident already exists — ours or another path's. Never duplicate
        # it, never re-dispatch it; escalation is the one exception, exactly as
        # in the alert poller.
        prev_sev = norm_sev(prev.get("severity"))
        times = _int(prev.get("timesSeen")) + 1
        escalated = SEV_RANK[severity] > SEV_RANK[prev_sev]
        rows.append({
            "fingerprint": fp,
            "host": str(prev.get("host") or host),
            "metric": str(prev.get("metric") or metric),
            "severity": severity if escalated else str(prev.get("severity") or severity),
            "status": "open",
            "firstSeen": str(prev.get("firstSeen") or now_iso),
            "lastSeen": now_iso,
            "resolvedAt": "",
            "timesSeen": times,
            "missedRuns": 0,
            "description": description if escalated else str(prev.get("description") or description),
            "investigated": True if (escalated and will_inv) else _truthy(prev.get("investigated")),
        })
        if escalated:
            state_changed = True
            if will_inv:
                dispatches.append(_dispatch(rows[-1], routing))
            loki.append(_incident_event(fp, host, severity, "escalated", category,
                                        description, metric, now_iso,
                                        first_seen=str(prev.get("firstSeen") or ""),
                                        times_seen=times))

    # --- our own incidents no longer over threshold: resolve after 2 polls ---
    for r in open_rows:
        if not r:
            continue
        fp = str(r.get("fingerprint") or "")
        if not fp or fp in over or fp in cfg.suppressed:
            continue
        if not str(r.get("description") or "").startswith(PREFIX):
            continue  # ownership: [alert] and LLM-born rows are not ours
        missed = _int(r.get("missedRuns")) + 1
        base = {
            "fingerprint": fp,
            "host": str(r.get("host") or ""),
            "metric": str(r.get("metric") or ""),
            "severity": str(r.get("severity") or ""),
            "firstSeen": str(r.get("firstSeen") or ""),
            "lastSeen": str(r.get("lastSeen") or ""),
            "timesSeen": _int(r.get("timesSeen")),
            "description": str(r.get("description") or ""),
            "investigated": _truthy(r.get("investigated")),
        }
        if missed >= RESOLVE_AFTER:
            rows.append(dict(base, status="resolved", resolvedAt=now_iso,
                             missedRuns=missed))
            state_changed = True
            loki.append(_incident_event(
                fp, base["host"], base["severity"], "resolved",
                category_of(fp, base["metric"], base["description"]),
                base["description"], base["metric"], now_iso, resolved=True))
        else:
            rows.append(dict(base, status="open",
                             resolvedAt=str(r.get("resolvedAt") or ""),
                             missedRuns=missed))

    return ThresholdDecision(
        rows_to_upsert=rows, dispatches=dispatches, notifications=notifications,
        loki_events=loki, streak_writes=streak_writes,
        streak_clears=streak_clears, state_changed=state_changed,
    )


def _dispatch(row: dict, routing: HostRouting) -> dict:
    """A dispatch item in the shape ``dispatch_all`` already consumes."""
    host = str(row.get("host") or "")
    return {**row, "hostRole": host_role_for(host, routing),
            "sshHost": ssh_host_for(host, routing)}


def _incident_event(fp: str, host: str, severity: str, status: str, category: str,
                    description: str, metric: str, now_iso: str,
                    first_seen: str = "", times_seen: int = 0,
                    resolved: bool = False) -> dict:
    """One Loki ``incident`` event, same shape the alert poller emits."""
    fields = {"fingerprint": fp, "finding": description, "metric": metric}
    if resolved:
        fields.update({"sevScore": 1, "resolvedAt": now_iso})
    else:
        fields.update({
            "sevScore": 3 if severity == "critical" else 2,
            "detectedAt": first_seen or now_iso,
            "firstSeen": first_seen,
            "lastSeen": now_iso,
            "timesSeen": times_seen,
        })
    return {"event": "incident",
            "labels": {"host": host, "severity": severity, "status": status,
                       "category": category},
            "fields": fields}


def _int(v: object) -> int:
    if v is None or v == "":
        return 0
    try:
        return int(float(v))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _truthy(v: object) -> bool:
    return v is True or str(v) == "true"
