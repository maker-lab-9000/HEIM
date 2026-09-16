"""Loki event builders for the daily run
(ports of n8n 'Findings & Categories To Loki' and 'Incidents To Loki Items').
"""
from __future__ import annotations

import re

_FLAG_SEV = {"crit": 3, "critical": 3, "warn": 2, "warning": 2, "ok": 1, "healthy": 1, "info": 0, "na": 0, "unknown": 0}
_SEV_SCORE = {"crit": 3, "warn": 2, "info": 1, "ok": 1, "na": 0}
_CAT_ORDER = ["CPU", "Memory", "Disk", "Disk Health", "Temperature", "Network", "Proxmox", "Host"]


def _norm(s) -> str:
    return str(s if s is not None else "unknown").lower()


def _canon_flag(s) -> str:
    n = _norm(s)
    if n in ("crit", "critical"):
        return "crit"
    if n in ("warn", "warning"):
        return "warn"
    if n in ("ok", "healthy"):
        return "ok"
    if n == "info":
        return "info"
    return "na"


def _short(s, cap: int) -> str:
    t = str(s if s is not None else "").strip()
    if not t:
        return ""
    i = t.find(". ")
    if 0 < i <= cap:
        return t[: i + 1]
    if len(t) <= cap:
        return t
    c = t[:cap]
    sp = c.rfind(" ")
    if sp > 40:
        c = c[:sp]
    return c.strip() + "…"


def _category_of(metric) -> str:
    q = str(metric or "").lower()
    if re.search(r"cpu|load|processor", q):
        return "cpu"
    if re.search(r"mem|swap|oom", q):
        return "memory"
    if re.search(r"temp|thermal|celsius", q):
        return "temperature"
    if re.search(r"smart|nvme|wear|spare|media err|crc", q):
        return "diskHealth"
    if re.search(r"fs|filesystem|disk|inode|pool|mount|/", q):
        return "filesystem"
    if re.search(r"net|tcp|nic|rx|tx", q):
        return "network"
    return "other"


def finding_and_category_events(analysis: dict, payload: dict) -> list[dict]:
    out: list[dict] = []
    for f in analysis.get("findings") or []:
        sev = _canon_flag(f.get("severity"))
        out.append({
            "event": "finding",
            "labels": {"severity": sev, "host": _norm(f.get("host")) or "all", "category": _category_of(f.get("metric"))},
            "fields": {
                "metric": str(f.get("metric") or ""), "trend": str(f.get("trend") or ""),
                "summary": _short(f.get("summary") or f.get("detail"), 150),
                "action": _short(f.get("recommendation"), 120),
                "detail": str(f.get("detail") or ""), "recommendation": str(f.get("recommendation") or ""),
                "sevScore": _SEV_SCORE.get(sev, 0),
            },
        })

    categories = payload.get("categories") or {}
    an_cats = analysis.get("categories") or {}
    for cat in _CAT_ORDER:
        # data-driven worst flag, upgraded by the LLM's own status if worse
        worst = None
        for r in categories.get(cat) or []:
            s = _canon_flag(r.get("flag"))
            if worst is None or _FLAG_SEV.get(s, 0) > _FLAG_SEV.get(worst, 0):
                worst = s
        info = an_cats.get(cat)
        llm = _canon_flag(info.get("status")) if info and info.get("status") else None
        st = worst
        if llm and (st is None or _FLAG_SEV.get(llm, 0) > _FLAG_SEV.get(st, 0)):
            st = llm
        st = st or "na"
        insight = (info or {}).get("insight") or "No analysis provided."
        out.append({
            "event": "category",
            "labels": {"category": cat, "status": st},
            "fields": {"insight": _short(insight, 180), "insightFull": str(insight), "statusScore": _SEV_SCORE.get(st, 0)},
        })
    return out


def incident_events(summary: dict) -> list[dict]:
    out: list[dict] = []
    for name in ("new", "ongoing", "clearing", "resolved"):
        for r in summary.get(name) or []:
            if not r or not r.get("fingerprint"):
                continue
            status = ("resolved" if name == "resolved" else "new" if name == "new"
                      else "escalated" if r.get("escalated") else "open")
            sev_score = 1 if status == "resolved" else 3 if "crit" in str(r.get("severity") or "").lower() else 2
            out.append({
                "event": "incident",
                "labels": {"host": r.get("host"), "severity": r.get("severity"), "status": status,
                           "category": _category_of(r.get("metric"))},
                "fields": {
                    "fingerprint": r["fingerprint"], "finding": r.get("description"), "metric": r.get("metric"),
                    "sevScore": sev_score, "confidence": r.get("confidence", ""),
                    "detectedAt": r.get("firstSeen") or r.get("lastSeen") or "",
                    "firstSeen": r.get("firstSeen") or "", "lastSeen": r.get("lastSeen") or "",
                    "timesSeen": r.get("timesSeen", ""),
                },
            })
    return out
