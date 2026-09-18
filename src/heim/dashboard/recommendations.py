"""Collect actionable recommendations from open incidents and investigations (spec §9).

Two sources feed one list: the analyst's ``recommendation`` on findings whose
incident is still open, and the ``Recommended remediation`` section of every
finished investigation report. A recommendation for an incident nobody has to
act on any more is noise, so findings are filtered by the open set and only the
newest finding per incident contributes — an older run's advice has already
been superseded by the newer one.

Keys are content-addressed (``rec_key``) rather than row ids so that a
recommendation the user ticked off stays ticked off when the same advice comes
back on the next run, and so the page can store state without owning rows.
"""
from __future__ import annotations

import hashlib
import re

from heim.reports.render import extract_sections

#: Investigation statuses whose report is final enough to act on. A run that is
#: still going, or that failed, has no trustworthy remediation list.
_FINISHED = ("complete", "resolved")


def rec_key(kind: str, source_id, text: str) -> str:
    """Stable 40-char sha1 over ``kind:id:normalized-text``.

    Normalisation (lowercase, whitespace collapsed) means a model that
    re-words its own spacing or capitalisation does not resurrect an item the
    user already dismissed.
    """
    norm = re.sub(r"\s+", " ", str(text).strip().lower())
    return hashlib.sha1(f"{kind}:{source_id}:{norm}".encode()).hexdigest()


def collect(open_incidents: list[dict], findings: list[dict],
            investigations: list[dict]) -> list[dict]:
    """→ ``[{key, host, text, source, source_href, at}, …]``, newest first."""
    open_fps = {i["fingerprint"] for i in open_incidents}
    rows: list[dict] = []

    latest: dict[str, dict] = {}
    for f in findings:
        if f.get("fingerprint") in open_fps and str(f.get("recommendation") or "").strip():
            k = f["fingerprint"]
            if k not in latest or str(f.get("run_at", "")) > str(latest[k].get("run_at", "")):
                latest[k] = f
    for f in latest.values():
        rows.append({
            "key": rec_key("finding", f["fingerprint"], f["recommendation"]),
            "host": f.get("host", ""),
            "text": str(f["recommendation"]).strip(),
            "source": f"finding · {f.get('metric', '')}",
            "source_href": "/findings",
            "at": str(f.get("run_at", "")),
        })

    for inv in investigations:
        if inv.get("status") not in _FINISHED:
            continue
        for item in extract_sections(inv.get("report_md") or "").get("remediation", []):
            rows.append({
                "key": rec_key("investigation", inv["id"], item),
                "host": inv.get("host", ""),
                "text": item,
                "source": f"investigation #{inv['id']}",
                "source_href": f"/investigations/{inv['id']}",
                "at": str(inv.get("finished_at") or ""),
            })

    rows.sort(key=lambda r: r["at"], reverse=True)
    return rows
