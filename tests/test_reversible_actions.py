"""Operator follow-up (2026-11-02): decisions are reversible, and an investigate
key shows what you triggered.

- Verdicts on /findings and /security: both keys always; the chosen one is
  pressed and live. The other key switches, the pressed one clears, and leaving
  false positive lifts the mute it set.
- Recommendations: both keys always; the other switches, the pressed one reopens.
- Investigate / Investigate now / Re-run: pressed green, linking to the run,
  while one is in flight for that subject; the plain key otherwise.
- The queue line reads "Requested HH:MM, D Mon → investigation #N | queue".
- Hosts: the last-investigation id has one fixed tabular width.
"""
import re
from datetime import timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from heim.dashboard import app as app_mod
from test_dashboard import _iso
from test_dashboard_actions import FP_MEM, FP_TEMP, HX, app_store  # noqa: F401
from test_overview_console import _client, _healthy_agents
from test_recommendations import seeded, seeded_client  # noqa: F401

CSS = (Path(__file__).resolve().parent.parent
       / "src/heim/dashboard/static/heim.css").read_text()


def _verdict(client, fid, verdict):
    return client.post("/actions/verdict", data={"finding_id": fid, "verdict": verdict},
                       headers=HX)


# ---------------------------------------------------------------- verdicts

def test_confirmed_switches_to_false_positive_and_back_lifting_the_mute(app_store):  # noqa: F811
    client, ids, store, _cfg = app_store
    fid = ids["finding_temp"]
    r = _verdict(client, fid, "confirmed")
    assert 'class="btn pressed go" type="submit" aria-pressed="true"' in r.text
    assert '<button class="btn" type="submit">False positive</button>' in r.text

    r = _verdict(client, fid, "false_positive")                # switch
    assert store.finding(fid)["verdict"] == "false_positive"
    assert FP_TEMP in {s["fingerprint"] for s in store.suppressed()}
    assert store.incident(FP_TEMP)["status"] == "suppressed"
    assert 'class="btn pressed other" type="submit" aria-pressed="true"' in r.text
    assert '<button class="btn" type="submit">Confirm</button>' in r.text

    r = _verdict(client, fid, "confirmed")                     # and back
    assert store.finding(fid)["verdict"] == "confirmed"
    assert FP_TEMP not in {s["fingerprint"] for s in store.suppressed()}
    assert store.incident(FP_TEMP)["status"] == "open"
    assert "Confirmed — kept in the findings history. Unmuted." in r.text


def test_pressing_the_pressed_verdict_clears_it(app_store):  # noqa: F811
    client, ids, store, _cfg = app_store
    fid = ids["finding_mem"]
    r = _verdict(client, fid, "false_positive")
    # the pressed key posts "clear"; the confirm prompt is only for setting it
    pressed = r.text.split('class="btn pressed other"')[0].rsplit("<form", 1)[1]
    assert 'name="verdict" value="clear"' in pressed and "hx-confirm" not in pressed

    r = _verdict(client, fid, "clear")
    assert store.finding(fid)["verdict"] is None
    assert FP_MEM not in {s["fingerprint"] for s in store.suppressed()}
    assert store.incident(FP_MEM)["status"] == "open"
    assert "Verdict cleared. Unmuted." in r.text
    assert 'class="btn pressed' not in r.text
    assert ">Confirm</button>" in r.text and ">False positive</button>" in r.text


def test_clearing_a_confirmed_verdict_touches_no_mute(app_store):  # noqa: F811
    client, ids, store, _cfg = app_store
    before = store.suppressed()
    _verdict(client, ids["finding_temp"], "confirmed")
    r = _verdict(client, ids["finding_temp"], "clear")
    assert store.finding(ids["finding_temp"])["verdict"] is None
    assert store.suppressed() == before
    assert "Verdict cleared." in r.text and "Unmuted" not in r.text


def test_verdict_flash_wraps_inside_its_cell():
    rule = re.search(r"\.flash \{[^}]*\}", CSS).group(0)
    assert "white-space: normal" in rule and "overflow-wrap: anywhere" in rule
    assert "min-width: 0" in rule
    assert "flex-wrap: nowrap" not in CSS.split(".ftbl td .acts", 1)[1].split("\n")[0]


# --------------------------------------------------------- recommendations

def _rec_key(client):
    return re.search(r'name="key" value="([0-9a-f]{40})"',
                     client.get("/recommendations").text).group(1)


def test_recommendation_switches_and_reopens(seeded):  # noqa: F811
    client, _ids, db = seeded
    key = _rec_key(client)
    post = lambda state: client.post("/actions/recommendation",  # noqa: E731
                                     data={"key": key, "state": state}, headers=HX)
    r = post("done")
    assert 'class="btn pressed go" type="submit"' in r.text
    # the pressed key reopens; the other switches
    assert re.search(r'value="open">\s*<input type="hidden" name="back"[^>]*>\s*'
                     r'<button class="btn pressed go"', r.text)
    assert '<button class="btn" type="submit">Dismiss</button>' in r.text

    r = post("dismissed")
    assert 'class="btn pressed crit" type="submit"' in r.text
    assert '<button class="btn" type="submit">Done</button>' in r.text

    # the handled list carries the same live keys: the pressed one reopens
    handled = client.get("/recommendations").text.split("handled (1)", 1)[1]
    assert 'class="btn pressed crit" type="submit"' in handled
    assert 'name="state" value="open"' in handled and "disabled" not in handled

    r = post("open")
    assert "Reopened." in r.text and 'class="btn pressed' not in r.text
    from heim.incidents.store import IncidentStore
    probe = IncidentStore(db)
    try:
        assert key not in probe.recommendation_states()
    finally:
        probe.close()
    assert "handled (" not in client.get("/recommendations").text


def test_reopening_is_a_listed_action_helper():
    assert "clear_recommendation_state" in app_mod._ACTION_HELPERS


# --------------------------------------------------- investigate in flight

def _idle_hosts(cfg):
    return [h for h in cfg.hosts if h not in ("ubuntu-server", "homelab")]


def test_host_key_is_pressed_while_a_run_is_in_flight(app_store):  # noqa: F811
    client, ids, _store, cfg = app_store
    html = client.get("/hosts").text
    rows = {re.search(r'<h3 class="hname mono">([^<]+)</h3>', r).group(1): r
            for r in re.findall(r'<li class="hrow.*?</li>', html, re.S)}
    # ubuntu-server: pending approval; homelab: running (it outranks the queued job)
    assert (f'<a class="btn pressed go" href="/investigations/{ids["pending"]}"'
            in rows["ubuntu-server"]) and ">Awaiting approval</a>" in rows["ubuntu-server"]
    assert (f'<a class="btn pressed go" href="/investigations/{ids["retry"]}"'
            in rows["homelab"]) and ">Investigating</a>" in rows["homelab"]
    for host in _idle_hosts(cfg):
        assert ">Investigate</button>" in rows[host]
        assert 'class="btn pressed' not in rows[host]


def test_a_queued_job_presses_the_key_and_links_the_queue(app_store):  # noqa: F811
    client, _ids, _store, cfg = app_store
    host = _idle_hosts(cfg)[0]
    r = client.post("/actions/investigate", data={"host": host}, headers=HX)
    assert '<a class="btn pressed go" href="/investigations"' in r.text
    assert ">Investigating</a>" in r.text and ">Investigate</button>" not in r.text
    row = next(r for r in re.findall(r'<li class="hrow.*?</li>',
                                     client.get("/hosts").text, re.S)
               if f">{host}</h3>" in r)
    assert '<a class="btn pressed go" href="/investigations"' in row


def test_incident_key_is_plain_when_idle_and_pressed_after_the_post(app_store):  # noqa: F811
    client, _ids, store, cfg = app_store
    host = _idle_hosts(cfg)[0]
    fp = f"{host}|cpu_used|CPU busy"
    store.upsert([{"fingerprint": fp, "host": host, "metric": "cpu_used",
                   "severity": "warning", "status": "open", "firstSeen": _iso(60),
                   "lastSeen": _iso(5), "timesSeen": 1, "missedRuns": 0,
                   "description": "CPU busy."}])
    html = client.get("/incidents").text
    cell = next(c for c in html.split('<div class="acts">')[1:] if f'value="{fp}"' in c)
    assert ">Investigate now</button>" in cell

    r = client.post("/actions/investigate", data={"host": host, "fingerprint": fp},
                    headers=HX)
    assert '<a class="btn pressed go" href="/investigations"' in r.text
    assert ">Investigate now<" not in r.text and "Mark false positive" in r.text


def _troubled(store, fp="homelab|drive_temp|jellymedia"):
    _healthy_agents(store)
    return store.create_investigation(
        fingerprint=fp, host="homelab", agent_name="investigator",
        status="needs_human", outcome="needs_human",
        started_at=_iso(600), finished_at=_iso(590), report_md="## Summary\n\nx\n")


def _attention(html):
    return html.split('aria-labelledby="h-att"', 1)[1].split("</section>", 1)[0]


def test_overview_rerun_is_plain_when_nothing_is_in_flight(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, _troubled) as c:
        att = _attention(c.get("/").text)
    assert ">Re-run</button>" in att and 'class="btn pressed' not in att


def test_overview_rerun_is_pressed_while_its_subject_is_in_flight(tmp_path, monkeypatch):
    def seed(s):
        _troubled(s)
        s.create_investigation(fingerprint="homelab|drive_temp|jellymedia", host="homelab",
                               agent_name="investigator", status="pending_approval",
                               started_at=_iso(1))

    with _client(tmp_path, monkeypatch, seed) as c:
        att = _attention(c.get("/").text)
    assert re.search(r'<a class="btn pressed go" href="/investigations/\d+"[^>]*>'
                     r'Awaiting approval</a>', att)
    assert ">Re-run</button>" not in att


def test_overview_rerun_post_answers_with_the_pressed_cell(tmp_path, monkeypatch):
    ids = {}
    with _client(tmp_path, monkeypatch,
                 lambda s: ids.setdefault("inv", _troubled(s))) as c:
        r = c.post("/actions/retrigger",
                   data={"investigation_id": ids["inv"], "cell": "attention", "back": "/"},
                   headers=HX)
    assert '<a class="btn pressed go" href="/investigations"' in r.text
    assert ">Investigating</a>" in r.text
    assert re.search(r'Requested \d\d:\d\d, \d{1,2} [A-Z][a-z]{2} → '
                     r'<a href="/investigations">queue</a>', r.text)


# ------------------------------------------------------------ requested line

def test_requested_line_names_the_queue_until_the_job_has_a_run():
    tz = ZoneInfo("Europe/Berlin")
    job = {"created_at": "2026-11-02T14:05:09+00:00", "investigation_id": 0}
    assert app_mod._requested(job, tz) == {
        "text": "Requested 15:05, 2 Nov → ",
        "link": {"href": "/investigations", "label": "queue"}}
    job["investigation_id"] = 42
    assert app_mod._requested(job, timezone.utc) == {
        "text": "Requested 14:05, 2 Nov → ",
        "link": {"href": "/investigations/42", "label": "investigation #42"}}


# ---------------------------------------------------------------- hosts

def test_last_investigation_ids_share_one_tabular_width(app_store):  # noqa: F811
    client, ids, _store, _cfg = app_store
    html = client.get("/hosts").text
    assert f'<a class="mono invid" href="/investigations/{ids["retry"]}">' in html
    assert ".hrow .invid { min-width: 5ch; font-variant-numeric: tabular-nums; }" in CSS
