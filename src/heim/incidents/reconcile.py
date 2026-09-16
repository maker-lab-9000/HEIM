"""Pure incident reconciliation logic.

Port of the n8n Code node **"Reconcile Incidents" (PAM 30)** —
``reference/pam-30-reconcile-incidents/reconcile.js``.

Differences from the JS (all deliberate, behavior-preserving):

* Inputs arrive already parsed (the n8n node received JSON strings and the
  raw LLM chain output; the string-extraction / ``JSON.parse`` plumbing is
  therefore out of scope here). ``analysis`` is the parsed LLM analysis
  object (``{"findings": [...]}``) and ``payload_rows`` is the already
  flattened list of flagged metric rows (the JS built ``allRows`` from
  ``payload.categories``).
* The hardcoded host-routing constants (``SSH_HOSTS``, ``HYPERVISOR_HOST``,
  ``HOMELAB_INVESTIGATE_CATS``, ``HA_HOST``) come from a
  :class:`~heim.incidents.types.HostRouting` parameter instead. The JS also
  hardcoded ``GUEST_SSH_HOST = 'ubuntu-server'`` (the SSH host used to
  investigate non-SSH hosts such as the hypervisor); ``HostRouting`` has no
  such field, so :func:`guest_ssh_host` derives it deterministically as the
  lexicographically first entry of ``routing.ssh_hosts`` — identical to the
  JS whenever there is a single SSH host, as in production.
* The JS returned ``runAt`` alongside the result; :class:`ReconcileResult`
  has no such field, so the caller keeps its own ``run_at``.

Everything else — fingerprint anchoring (name-weighted scoring against ALL
payload rows, minimum score 2, slug fallback), severity hysteresis,
missed-run resolution after 2 consecutive unseen runs, and the
``investigated`` dispatch-lock semantics — is a faithful port, quirks
included (e.g. slug word *sorting*, highest-severity dedupe per
fingerprint).
"""
from __future__ import annotations

import re

from heim.incidents.types import HostRouting, ReconcileResult

__all__ = [
    "SEV_RANK",
    "norm_host",
    "slug",
    "norm_sev",
    "to_bool",
    "category_of",
    "host_role_for",
    "is_investigable",
    "guest_ssh_host",
    "ssh_host_for",
    "fingerprint_for",
    "reconcile",
]

#: Severity ranking, as in the JS ``sevRank`` map.
SEV_RANK: dict[str, int] = {"info": 0, "warning": 1, "critical": 2}

_NON_ALNUM = re.compile(r"[^a-z0-9]+")

# Metric-taxonomy constants (NOT host routing — kept hardcoded like the JS).
_CPU_QIDS = ("cpu_busy", "load_per_core", "cpu_psi", "procs_blocked", "pve_vm_cpu")
_MEM_QIDS = ("mem_used", "swap_used", "mem_psi", "oom", "pve_vm_mem")
_TEMP_QIDS = ("drive_temp", "host_temp_max", "chip_temp")
_DISK_HEALTH_QIDS = (
    "smart_status", "nvme_wear", "spare", "media_err", "errlog", "sda_wear", "sdb_crc",
)
_DISK_QIDS = ("fs_used", "fs_used_bytes", "inodes_used", "pve_pool_used", "pve_pool_used_bytes")

_CPU_WORDS = ("cpu", "load", "processor")
_MEM_WORDS = ("memory", "swap", "oom")
_TEMP_WORDS = ("temp", "thermal", "celsius")
_DISK_HEALTH_WORDS = ("smart", "nvme", "wear", "spare", "crc")
_DISK_WORDS = ("filesystem", "disk space", "disk usage", "root fs", "pool", "inode")


def norm_host(h: object) -> str:
    """Port of JS ``normHost``: lowercase + trim, ``None`` -> ``''``."""
    return str("" if h is None else h).lower().strip()


def slug(s: object) -> str:
    """Port of JS ``slug``: lowercase, non-alphanumerics to spaces, split,
    **sort** the words, join with ``-``. The sorting is a load-bearing quirk
    (fingerprints are word-order independent)."""
    text = "" if s is None else str(s)
    words = _NON_ALNUM.sub(" ", text.lower()).strip().split()
    return "-".join(sorted(words))


def norm_sev(s: object) -> str:
    """Port of JS ``normSev``: crit/critical -> critical, warn/warning ->
    warning, everything else (including empty) -> info."""
    n = str(s or "").lower()
    if n in ("crit", "critical"):
        return "critical"
    if n in ("warn", "warning"):
        return "warning"
    return "info"


def to_bool(v: object) -> bool:
    """Port of JS ``toBool``: ``v === true || String(v) === 'true'``."""
    return v is True or v == "true"


def _js_num(v: object) -> float:
    """Approximate JS ``Number(v) || 0`` for the value shapes seen in rows
    (numbers, numeric strings, None/empty/garbage -> 0)."""
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        f = float(v)
    else:
        s = str(v).strip()
        if not s:
            return 0.0
        try:
            f = float(s)
        except ValueError:
            return 0.0
    if f != f:  # NaN
        return 0.0
    return f


def category_of(fp: object, metric: object, description: object) -> str:
    """Port of JS ``categoryOf``: prefer the qid segment of an anchored
    fingerprint (``host|qid|name``), then fall back to keyword matching over
    ``metric + ' ' + description``."""
    parts = str(fp).split("|")
    q = (parts[1] if len(parts) >= 3 else "").lower()
    text = (str(metric) + " " + str(description)).lower()

    def has(words: tuple[str, ...]) -> bool:
        return any(w in text for w in words)

    if q in _CPU_QIDS:
        return "cpu"
    if q in _MEM_QIDS:
        return "memory"
    if q in _TEMP_QIDS:
        return "temperature"
    if q in _DISK_HEALTH_QIDS:
        return "diskHealth"
    if q in _DISK_QIDS:
        return "disk"
    if has(_CPU_WORDS):
        return "cpu"
    if has(_MEM_WORDS):
        return "memory"
    if has(_TEMP_WORDS):
        return "temperature"
    if has(_DISK_HEALTH_WORDS):
        return "diskHealth"
    if has(_DISK_WORDS):
        return "disk"
    return "other"


def host_role_for(host: str, routing: HostRouting) -> str:
    """Port of JS ``hostRoleFor``: hypervisor / ha-guest / guest."""
    if routing.hypervisor_host is not None and host == routing.hypervisor_host:
        return "hypervisor"
    if routing.ha_host is not None and host == routing.ha_host:
        return "ha-guest"
    return "guest"


def is_investigable(fp: object, host: str, metric: object, description: object,
                    routing: HostRouting) -> bool:
    """Port of JS ``isInvestigable``: SSH hosts always; the HA host always
    (investigated via HA REST API + Prometheus, no SSH); the hypervisor only
    for the configured category set; everything else never."""
    if host in routing.ssh_hosts:
        return True
    if routing.ha_host is not None and host == routing.ha_host:
        return True
    if routing.hypervisor_host is not None and host == routing.hypervisor_host:
        return category_of(fp, metric, description) in routing.hypervisor_categories
    return False


def guest_ssh_host(routing: HostRouting) -> str:
    """Replacement for the JS ``GUEST_SSH_HOST`` constant: the SSH host used
    to investigate findings on hosts that have no SSH of their own.

    Derived as the lexicographically first SSH host so the result is
    deterministic; with a single configured SSH host (the production case,
    ``'ubuntu-server'``) this is exactly the JS constant."""
    return min(routing.ssh_hosts) if routing.ssh_hosts else ""


def ssh_host_for(host: str, routing: HostRouting) -> str:
    """Port of the JS ``sshHost`` expression:
    ``SSH_HOSTS[host] ? host : (host === HA_HOST ? '' : GUEST_SSH_HOST)``."""
    if host in routing.ssh_hosts:
        return host
    if routing.ha_host is not None and host == routing.ha_host:
        return ""
    return guest_ssh_host(routing)


def fingerprint_for(finding: dict, payload_rows: list[dict]) -> str:
    """Port of JS ``fingerprintFor``: anchor the finding to a flagged payload
    row via name-weighted word overlap (name words count double, label words
    single). Requires a best score of at least 2 AND a truthy ``qid``;
    otherwise falls back to ``host|slug(metric)``."""
    fh = norm_host(finding.get("host"))
    fw = [w for w in slug(finding.get("metric")).split("-") if w]
    best_row: dict | None = None
    best_score = 0
    best_name_overlap = 0
    for r in payload_rows:
        if not r:
            continue
        rh = norm_host(r.get("host"))
        if fh and fh != "all" and rh and rh != fh:
            continue
        name_words = [w for w in slug(r.get("name")).split("-") if w]
        label_words = [w for w in slug(r.get("label")).split("-") if w]
        name_overlap = sum(1 for w in fw if w in name_words)
        label_overlap = sum(1 for w in fw if w in label_words)
        score = name_overlap * 2 + label_overlap
        if score > 0 and (
            best_row is None
            or score > best_score
            or (score == best_score and name_overlap > best_name_overlap)
        ):
            best_row, best_score, best_name_overlap = r, score, name_overlap
    if best_row is not None and best_score >= 2 and best_row.get("qid"):
        return (
            (norm_host(best_row.get("host")) or fh or "unknown")
            + "|" + str(best_row.get("qid"))
            + "|" + str(best_row.get("name") or "")
        )
    return (fh or "unknown") + "|" + (slug(finding.get("metric")) or "unknown")


def reconcile(analysis: dict, payload_rows: list[dict], open_rows: list[dict],
              run_at: str, routing: HostRouting) -> ReconcileResult:
    """Reconcile LLM findings against open incident rows (PAM 30 port).

    ``analysis`` is the parsed LLM analysis (``{"findings": [...]}``);
    ``payload_rows`` the flattened flagged-metric rows used for fingerprint
    anchoring; ``open_rows`` the currently-open incident table rows;
    ``run_at`` the ISO timestamp of this run.
    """
    findings_raw = analysis.get("findings") if isinstance(analysis, dict) else None
    findings = findings_raw if isinstance(findings_raw, list) else []

    # Dedupe by fingerprint keeping the highest severity; info is dropped.
    current: dict[str, dict] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = norm_sev(f.get("severity"))
        if sev == "info":
            continue
        fp = fingerprint_for(f, payload_rows)
        rec = {
            "fingerprint": fp,
            "host": norm_host(f.get("host")) or "unknown",
            "metric": str(f.get("metric") or ""),
            "severity": sev,
            "description": str(f.get("detail") or f.get("metric") or ""),
        }
        if fp not in current or SEV_RANK[sev] > SEV_RANK[current[fp]["severity"]]:
            current[fp] = rec

    open_by_fp: dict[str, dict] = {}
    for r in open_rows:
        if r and r.get("fingerprint"):
            open_by_fp[r["fingerprint"]] = r

    rows_to_write: list[dict] = []
    new_incidents: list[dict] = []
    ongoing: list[dict] = []
    clearing: list[dict] = []
    resolved_rows: list[dict] = []
    to_investigate: list[dict] = []
    seen: set[str] = set()

    for fp, c in current.items():
        seen.add(fp)
        prev = open_by_fp.get(fp)
        if prev is None:
            will_inv = is_investigable(fp, c["host"], c["metric"], c["description"], routing)
            row = {
                "fingerprint": fp,
                "host": c["host"],
                "metric": c["metric"],
                "severity": c["severity"],
                "status": "open",
                "firstSeen": run_at,
                "lastSeen": run_at,
                "resolvedAt": "",
                "timesSeen": 1,
                "missedRuns": 0,
                "description": c["description"],
                "investigated": will_inv,
            }
            rows_to_write.append(row)
            new_incidents.append(row)
            if will_inv:
                to_investigate.append({
                    **row,
                    "hostRole": host_role_for(c["host"], routing),
                    "sshHost": ssh_host_for(c["host"], routing),
                })
        else:
            prev_sev = norm_sev(prev.get("severity"))
            escalated = SEV_RANK[c["severity"]] > SEV_RANK[prev_sev]
            already_investigated = to_bool(prev.get("investigated"))
            will_inv = (
                is_investigable(fp, c["host"], c["metric"], c["description"], routing)
                and (escalated or not already_investigated)
            )
            row = {
                "fingerprint": fp,
                "host": c["host"],
                "metric": c["metric"],
                "severity": c["severity"],
                "status": "open",
                "firstSeen": str(prev.get("firstSeen") or run_at),
                "lastSeen": run_at,
                "resolvedAt": "",
                "timesSeen": int(_js_num(prev.get("timesSeen"))) + 1,
                "missedRuns": 0,
                "description": c["description"],
                "investigated": True if will_inv else already_investigated,
            }
            rows_to_write.append(row)
            ongoing.append({"escalated": escalated, **row})
            if will_inv:
                to_investigate.append({
                    **row,
                    "hostRole": host_role_for(c["host"], routing),
                    "sshHost": ssh_host_for(c["host"], routing),
                })

    # Open rows not seen this run: clearing after 1 missed run, resolved at 2.
    for r in open_rows:
        if not r:
            continue
        fp = r.get("fingerprint")
        if not fp or fp in seen:
            continue
        missed = int(_js_num(r.get("missedRuns"))) + 1
        base = {
            "fingerprint": str(fp),
            "host": str(r.get("host") or ""),
            "metric": str(r.get("metric") or ""),
            "severity": norm_sev(r.get("severity")),
            "firstSeen": str(r.get("firstSeen") or ""),
            "lastSeen": str(r.get("lastSeen") or ""),
            "timesSeen": int(_js_num(r.get("timesSeen"))),
            "description": str(r.get("description") or ""),
            "investigated": to_bool(r.get("investigated")),
        }
        if missed >= 2:
            row = {**base, "status": "resolved", "resolvedAt": run_at, "missedRuns": missed}
            rows_to_write.append(row)
            resolved_rows.append(row)
        else:
            row = {**base, "status": "open", "resolvedAt": str(r.get("resolvedAt") or ""),
                   "missedRuns": missed}
            rows_to_write.append(row)
            clearing.append(row)

    summary = {
        "counts": {
            "open": len(new_incidents) + len(ongoing) + len(clearing),
            "new": len(new_incidents),
            "ongoing": len(ongoing),
            "clearing": len(clearing),
            "resolved": len(resolved_rows),
        },
        "new": new_incidents,
        "ongoing": ongoing,
        "clearing": clearing,
        "resolved": resolved_rows,
    }
    return ReconcileResult(rows_to_write=rows_to_write, summary=summary,
                           to_investigate=to_investigate)
