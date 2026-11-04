"""Activity: how the parts are wired, and what each run started.

Pure (spec 2026-11-04-activity-jobs-tools). Two things for the dashboard's
/activity page:

- :func:`map_model` — the boxes (jobs → agents → tools) and the edges between
  them. Edges are configuration, not data: a fixed job → agent table plus
  each agent YAML's ``tools:``. The data only lights the boxes.
- :func:`timeline` — every job run newest first, with what it started nested
  under it. A child is nested ONLY by an id recorded when it was created
  (``investigations.parent_run_id``, ``runs.agent_run_id``,
  ``incident_events.run_id``); nothing is matched up by time. A row with no
  recorded parent is shown at the top level, labelled — never guessed into
  someone's tree.
"""
from __future__ import annotations

import json
from datetime import datetime

from heim.agents import AGENT_LABELS
from heim.jobs import JOB_KEYS

#: the agents, as the dashboard's pages name them
AGENTS = {"analyst": "Daily analyst", "investigator": "Investigator",
          "auditor": "Security auditor"}
#: which agent an investigation row's agent_name is
_AGENT_OF_NAME = {"investigator": "investigator", "security_auditor": "auditor"}
#: the agent YAML behind each agent box (the analyst calls no tools)
_AGENT_CFG = {"investigator": "investigator", "auditor": "security_auditor"}

#: job → agent: which schedule runs or dispatches which model
MAP_EDGES: list[tuple[str, str]] = [
    ("daily", "analyst"), ("daily", "investigator"), ("alert_poller", "investigator"),
    ("thresholds", "investigator"), ("uptime", "investigator"), ("security", "auditor"),
]

#: triggers whose investigations a job run dispatches (so a 0 parent is legacy)
_JOB_TRIGGERS = {"daily", "poller", "threshold", "uptime", "security_audit"}
_TRIGGER_WORDS = {"manual": "started manually", "dashboard": "from the dashboard",
                  "replay": "an offline replay", "retry": "a retry"}

KINDS = ("all", "jobs", "agents", "triggered")


# ------------------------------------------------------------------ the map


def map_model(cfg, statuses: dict[str, dict]) -> dict:
    """Boxes and edges. ``statuses``: box key -> {state, word, last, fact}
    (anything missing reads as no data)."""
    edges = list(MAP_EDGES)
    for box, agent_name in _AGENT_CFG.items():
        agent = cfg.agents.get(agent_name)
        edges += [(box, t) for t in (agent.tools if agent else [])]

    def box(key: str, name: str, href: str) -> dict:
        st = statuses.get(key) or {}
        return {"key": key, "name": name, "href": href,
                "state": st.get("state", "unknown"), "word": st.get("word", "No data yet"),
                "last": st.get("last", ""), "fact": st.get("fact", ""),
                "feeds": [b for a, b in edges if a == key]}

    return {"jobs": [box(k, AGENT_LABELS.get(k, k), f"/jobs/{k}") for k in JOB_KEYS],
            "agents": [box(k, n, f"/agents/{k}") for k, n in AGENTS.items()],
            "tools": [box(t, t, f"/tools/{t}") for t in cfg.tools],
            "edges": edges}


# ------------------------------------------------------------- the timeline


def _node(kind: str, key: str, at: str, lamp: str, word: str, text: str, href: str,
          children: list | None = None) -> dict:
    return {"kind": kind, "key": key, "at": at, "lamp": lamp, "word": word, "text": text,
            "href": href, "children": children or []}


def _summary(beat: dict) -> str:
    if beat.get("error"):
        return str(beat["error"])
    detail = beat.get("detail") or {}
    parts = [f"{v} {k.replace('_', ' ')}" for k, v in detail.items()
             if isinstance(v, (int, float)) and not isinstance(v, bool)]
    return " · ".join(parts)


def _fallback(run: dict) -> bool:
    try:
        attempts = json.loads(run.get("attempts_json") or "[]")
    except (TypeError, ValueError):
        return False
    return bool(attempts) and not (attempts[0] or {}).get("ok", True)


def _event_node(e: dict, at: str) -> dict:
    event = str(e.get("event") or "")
    lamp = "resolved" if event == "resolved" else str(e.get("severity") or "warning")
    word = {"new": "Opened", "escalated": "Escalated", "resolved": "Resolved"}.get(event, event)
    return _node("event", str(e.get("fingerprint") or ""), str(e.get("at") or at), lamp, word,
                 f"{word.lower()} · {e.get('fingerprint')}", "/incidents")


def _inv_node(inv: dict, tools: dict[str, int], note: str = "") -> dict:
    key = _AGENT_OF_NAME.get(str(inv.get("agent_name") or "investigator"), "investigator")
    n = int(inv.get("n_steps") or sum(tools.values()))
    status = str(inv.get("status") or "")
    text = (f"{AGENTS[key]} #{inv['id']} {inv.get('host') or ''} · {status.replace('_', ' ')}"
            f" · {n} tool call{'' if n == 1 else 's'}" + (f" · {note}" if note else ""))
    kids = [_node("tool", t, str(inv.get("started_at") or ""), "", "", f"{t} × {c}",
                  f"/tools/{t}") for t, c in sorted(tools.items(), key=lambda kv: -kv[1])]
    return _node("agent", key, str(inv.get("started_at") or ""), status,
                 status.replace("_", " "), text, f"/investigations/{inv['id']}", kids)


def _beat_node(beat: dict, run: dict | None, invs: list[dict], events: list[dict],
               tools_by_inv: dict[int, dict[str, int]]) -> dict:
    key = str(beat.get("agent") or "")
    detail = beat.get("detail") or {}
    if detail.get("paused"):
        lamp, word = "paused", "Paused"
        until = str(detail.get("until") or "")
        summary = f"paused until {until[11:16]}" if len(until) >= 16 else "paused"
    elif beat.get("ok"):
        lamp, word, summary = "healthy", "OK", _summary(beat)
    else:
        lamp, word, summary = "failed", "Failed", _summary(beat)
    at = str(beat.get("started_at") or "")
    inv_nodes = [_inv_node(i, tools_by_inv.get(int(i["id"]), {})) for i in invs]
    ev_nodes = [_event_node(e, at) for e in events]
    if key == "daily" and run is not None:
        model = str(run.get("model_used") or "")
        analyst = _node("agent", "analyst", at, "degraded" if _fallback(run) else "healthy",
                        "Fallback" if _fallback(run) else "OK",
                        f"Daily analyst · {model or 'model unknown'}"
                        + (" (fallback)" if _fallback(run) else ""),
                        "/agents/analyst", ev_nodes + inv_nodes)
        children = [analyst]
    else:
        children = ev_nodes + inv_nodes
    name = AGENT_LABELS.get(key, key)
    return _node("job", key, at, lamp, word, f"{name}" + (f" · {summary}" if summary else ""),
                 f"/jobs/{key}", children)


def _contains(node: dict, part: str) -> bool:
    return node["key"] == part or any(_contains(c, part) for c in node["children"])


def _agents_in(node: dict) -> list[dict]:
    """Every agent node in a tree, each listed once: an agent nested under
    another (an investigation under the analyst) is not repeated inside it."""
    out = ([{**node, "children": [c for c in node["children"] if c["kind"] != "agent"]}]
           if node["kind"] == "agent" else [])
    for c in node["children"]:
        out += _agents_in(c)
    return out


def _quiet(node: dict) -> bool:
    return node["kind"] == "job" and not node["children"] and node["lamp"] == "healthy"


def _collapse(nodes: list[dict]) -> list[dict]:
    """Merge each job's consecutive quiet runs into one row: a poller runs every
    5 minutes, and 288 identical rows a day would bury what happened."""
    out: list[dict] = []
    open_groups: dict[str, dict] = {}
    for n in nodes:
        if not _quiet(n):
            if n["kind"] == "job":
                open_groups.pop(n["key"], None)
            out.append(n)
            continue
        group = open_groups.get(n["key"])
        if group is None:
            group = {**n, "count": 1, "from": n["at"]}
            open_groups[n["key"]] = group
            out.append(group)
        else:
            group["count"] += 1
            group["from"] = n["at"]
    for g in out:
        if g.get("count", 1) > 1:
            name = AGENT_LABELS.get(g["key"], g["key"])
            g["text"] = f"{name} · {g['count']} quiet runs {g['from'][11:16]}–{g['at'][11:16]}"
    return out


def _sort_key(node: dict):
    try:
        return datetime.fromisoformat(node["at"]).timestamp()
    except (TypeError, ValueError):
        return 0.0


def timeline(agent_runs: list[dict], runs_by_agent_run: dict[int, dict], invs: list[dict],
             events_by_run: dict[int, list[dict]],
             tools_by_inv: dict[int, dict[str, int]], part: str = "",
             kind: str = "all") -> list[dict]:
    """The runs in ``agent_runs`` (heartbeats) and the ``invs`` with no
    parent among them, newest first, each with what it started nested under it.

    ``part`` keeps the trees that contain that key anywhere (a job, an agent
    or a tool); ``kind`` is one of :data:`KINDS`.
    """
    beat_ids = {int(b["id"]) for b in agent_runs if b.get("id")}
    children: dict[int, list[dict]] = {}
    loose: list[dict] = []
    for i in invs:
        parent = int(i.get("parent_run_id") or 0)
        if parent and parent in beat_ids:
            children.setdefault(parent, []).append(i)
        else:
            loose.append(i)

    nodes = [_beat_node(b, runs_by_agent_run.get(int(b["id"])),
                        sorted(children.get(int(b["id"]), []), key=lambda r: r["started_at"]),
                        events_by_run.get(int(b["id"]), []), tools_by_inv)
             for b in agent_runs]
    for i in loose:
        parent = int(i.get("parent_run_id") or 0)
        trigger = str(i.get("trigger") or "")
        if parent:
            note = "its run is outside the window"
        elif trigger in _JOB_TRIGGERS:
            note = f"{trigger} · started before run links were recorded"
        else:
            note = _TRIGGER_WORDS.get(trigger, trigger or "no trigger recorded")
        nodes.append(_inv_node(i, tools_by_inv.get(int(i["id"]), {}), note))
    nodes.sort(key=_sort_key, reverse=True)

    if part:
        nodes = [n for n in nodes if _contains(n, part)]
    if kind == "jobs":
        nodes = [n for n in nodes if n["kind"] == "job"]
    elif kind == "agents":
        nodes = sorted((a for n in nodes for a in _agents_in(n)), key=_sort_key, reverse=True)
    elif kind == "triggered":
        nodes = [n for n in nodes if n["kind"] == "job" and n["children"]]
    return _collapse(nodes)
