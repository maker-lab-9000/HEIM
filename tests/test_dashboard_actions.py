"""Dashboard action tests (design spec §5 — the jobs queue slice).

Every write the dashboard can make, proved in the store: a job enqueued with
``requested_by='dashboard'``, a retry linked through ``retry_of``, an approval
decision the daemon's wait can read, a finding verdict, a suppression and its
lift. Plus the two response shapes (plain 303 redirect / htmx fragment with the
feedback line), the auth gate on POST, and the queue-visibility rendering.

The seeded store deliberately contains a pending_approval investigation, a
queued job, a suppressed incident and an unjudged finding — the four states the
action UI exists for.
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.dashboard.app import create_app
from heim.incidents.store import IncidentStore
from test_dashboard import _config, _iso

FP_MEM = "ubuntu-server|mem_used|Memory climbing"
FP_TEMP = "homelab|drive_temp|Drive temperature high"
FP_HA = "home-assistant|api_slow|API latency"

HX = {"HX-Request": "true"}


def _seed(db_path: Path) -> dict:
    store = IncidentStore(db_path)
    ids = {}

    ids["pending"] = store.create_investigation(
        fingerprint=FP_MEM, host="ubuntu-server", host_role="guest",
        agent_name="investigator", model="claude-sonnet-4-6", trigger="poller",
        status="pending_approval", started_at=_iso(3))
    ids["done"] = store.create_investigation(
        fingerprint=FP_TEMP, host="homelab", host_role="hypervisor",
        agent_name="investigator", model="claude-sonnet-4-6", trigger="daily",
        status="complete", started_at=_iso(200), finished_at=_iso(196),
        input_tokens=9_000, output_tokens=800, n_steps=2, outcome="resolved",
        report_md="## Summary\n\nFan curve.\n")
    ids["retry"] = store.create_investigation(
        fingerprint=FP_TEMP, host="homelab", host_role="hypervisor",
        trigger="manual", status="running", started_at=_iso(2),
        retry_of=ids["done"])

    # a job already waiting for the daemon (queued by the CLI)
    ids["job"] = store.enqueue_job(
        kind="investigate",
        payload={"host": "homelab", "host_role": "hypervisor",
                 "fingerprint": FP_TEMP, "findings": []},
        requested_by="cli")

    run_at = _iso(6)
    ids["run"] = store.insert_run(run_at=run_at, kind="daily", overall="warning",
                                  model_used="claude-opus-4-6", duration_s=30.0)
    store.insert_findings(ids["run"], run_at, "daily", [
        {"host": "ubuntu-server", "metric": "mem_used", "severity": "critical",
         "trend": "up", "summary": "Memory climbing on ubuntu-server",
         "detail": "Working set grew 18%.", "recommendation": "Cap the container."},
        {"host": "homelab", "metric": "drive_temp", "severity": "warning",
         "trend": "up", "summary": "Drive temperature high",
         "detail": "sdb peaked at 48C.", "recommendation": "Raise the fan curve."},
    ], fingerprints=[FP_MEM, FP_TEMP])
    findings = store.recent_findings(limit=10)
    ids["finding_mem"] = next(f["id"] for f in findings if f["fingerprint"] == FP_MEM)
    ids["finding_temp"] = next(f["id"] for f in findings if f["fingerprint"] == FP_TEMP)

    store.upsert([
        {"fingerprint": FP_MEM, "host": "ubuntu-server", "metric": "mem_used",
         "severity": "critical", "status": "open", "firstSeen": _iso(4000),
         "lastSeen": _iso(5), "timesSeen": 7, "missedRuns": 0,
         "description": "Working set grew 18% over three days.", "investigated": True},
        {"fingerprint": FP_TEMP, "host": "homelab", "metric": "drive_temp",
         "severity": "warning", "status": "open", "firstSeen": _iso(2000),
         "lastSeen": _iso(5), "timesSeen": 3, "missedRuns": 1,
         "description": "sdb peaked at 48C."},
        # already muted: the row the UNMUTE button exists for
        {"fingerprint": FP_HA, "host": "home-assistant", "metric": "api_slow",
         "severity": "warning", "status": "suppressed", "firstSeen": _iso(9000),
         "lastSeen": _iso(7000), "timesSeen": 2, "missedRuns": 0,
         "description": "Latency spikes during backups."},
    ])
    store.suppress(FP_HA, until=(datetime.now().astimezone() + timedelta(days=5))
                   .isoformat(timespec="milliseconds"), reason="known backup window")
    store.close()
    return ids


@pytest.fixture()
def app_store(tmp_path, monkeypatch):
    """(client, ids, store, cfg) — the store is a *second* connection, so every
    assertion reads what the dashboard actually committed."""
    cfg = _config(tmp_path, monkeypatch)
    db = tmp_path / "heim.sqlite3"
    cfg.settings.db_path = str(db)
    ids = _seed(db)
    probe = IncidentStore(db)
    with TestClient(create_app(cfg)) as client:
        yield client, ids, probe, cfg
    probe.close()


@pytest.fixture()
def client(app_store):
    return app_store[0]


@pytest.fixture()
def ids(app_store):
    return app_store[1]


@pytest.fixture()
def store(app_store):
    return app_store[2]


def _post(client, path, data, **kw):
    return client.post(path, data=data, follow_redirects=False, **kw)


def _jobs_by_dashboard(store):
    return [j for j in store.jobs(limit=50) if j["requested_by"] == "dashboard"]


def _until_day(suppression: dict):
    """The calendar day a suppression lifts.

    Compared per-day on purpose: ``suppress_fingerprint`` adds the window to a
    zone-aware "now" (same as the CLI), so the stored instant can shift by the
    DST delta of the far end. The day is what the muted pill shows anyway.
    """
    return datetime.fromisoformat(suppression["until"]).date()


def _day_from_now(days: int):
    return (datetime.now().astimezone() + timedelta(days=days)).date()


# ------------------------------------------------------------- investigate

def test_investigate_from_a_host_card_queues_a_manual_job(client, store):
    r = _post(client, "/actions/investigate", {"host": "ubuntu-server", "back": "/hosts"})
    assert r.status_code == 303 and r.headers["location"] == "/hosts"

    jobs = _jobs_by_dashboard(store)
    assert len(jobs) == 1
    job = jobs[0]
    assert job["status"] == "queued" and job["kind"] == "investigate"
    assert job["retry_of"] == 0
    assert job["payload"]["host"] == "ubuntu-server"
    assert job["payload"]["host_role"] == "guest"      # from config/hosts
    assert job["payload"]["fingerprint"] == ""
    assert job["payload"]["findings"] == []            # a bare manual run


def test_investigate_from_an_incident_carries_the_incident_subject(client, store):
    r = _post(client, "/actions/investigate",
              {"host": "ubuntu-server", "fingerprint": FP_MEM, "back": "/incidents"})
    assert r.status_code == 303

    job = _jobs_by_dashboard(store)[0]
    assert job["payload"]["fingerprint"] == FP_MEM
    finding = job["payload"]["findings"][0]
    assert finding["severity"] == "critical"
    assert finding["metric"] == "mem_used"
    assert finding["detail"] == "Working set grew 18% over three days."
    assert finding["host"] == "ubuntu-server"


def test_investigate_with_a_fingerprint_that_has_no_incident_is_a_manual_run(client, store):
    r = _post(client, "/actions/investigate",
              {"host": "homelab", "fingerprint": "homelab|gone|Vanished"})
    assert r.status_code == 303
    job = _jobs_by_dashboard(store)[0]
    assert job["payload"]["findings"] == []
    assert job["payload"]["host"] == "homelab"


def test_investigate_needs_a_configured_host(client, store):
    missing = _post(client, "/actions/investigate", {"host": ""})
    assert missing.status_code == 400
    assert "An investigation needs a host." in missing.text

    unknown = _post(client, "/actions/investigate", {"host": "nas-42"})
    assert unknown.status_code == 400
    assert "No host named nas-42 is configured." in unknown.text
    assert _jobs_by_dashboard(store) == []


def test_htmx_investigate_returns_the_panel_with_the_feedback_line(client, store):
    r = client.post("/actions/investigate", data={"host": "ubuntu-server"}, headers=HX)
    assert r.status_code == 200
    body = r.text
    assert "<html" not in body and "<!doctype" not in body.lower()
    job_id = _jobs_by_dashboard(store)[0]["id"]
    assert (f"Queued as job #{job_id} — the daemon picks it up within a few seconds."
            in body)
    assert "INVESTIGATE" in body                      # the host card, re-rendered


def test_htmx_investigate_from_an_incident_returns_the_incident_panel(client):
    r = client.post("/actions/investigate",
                    data={"host": "ubuntu-server", "fingerprint": FP_MEM}, headers=HX)
    assert r.status_code == 200
    assert "Queued as job #" in r.text
    assert "INVESTIGATE NOW" in r.text and "MARK FALSE POSITIVE" in r.text


# -------------------------------------------------------------- retrigger

def test_retrigger_enqueues_a_linked_retry(client, ids, store):
    r = _post(client, "/actions/retrigger", {"investigation_id": ids["done"]},
              headers={"referer": f"/investigations/{ids['done']}"})
    assert r.status_code == 303
    assert r.headers["location"] == f"/investigations/{ids['done']}"

    job = _jobs_by_dashboard(store)[0]
    assert job["retry_of"] == ids["done"]
    assert job["payload"]["host"] == "homelab"
    assert job["payload"]["fingerprint"] == FP_TEMP
    # the brief is rebuilt from the incident the original was about
    assert job["payload"]["findings"][0]["detail"] == "sdb peaked at 48C."


def test_retrigger_of_an_unknown_investigation_is_404(client, store):
    r = _post(client, "/actions/retrigger", {"investigation_id": 9999})
    assert r.status_code == 404
    assert "No investigation #9999." in r.text
    assert _jobs_by_dashboard(store) == []


def test_retrigger_needs_a_numeric_id(client):
    r = _post(client, "/actions/retrigger", {"investigation_id": "abc"})
    assert r.status_code == 400
    assert "numeric investigation id" in r.text


def test_htmx_retrigger_returns_the_header_actions(client, ids, store):
    r = client.post("/actions/retrigger", data={"investigation_id": ids["done"]},
                    headers=HX)
    assert r.status_code == 200 and "<html" not in r.text
    job_id = _jobs_by_dashboard(store)[0]["id"]
    assert f"Queued as job #{job_id}" in r.text
    assert "RE-RUN" in r.text


# --------------------------------------------------------------- approval

def test_approve_writes_the_decision_the_daemon_polls(client, ids, store):
    r = _post(client, "/actions/approval",
              {"investigation_id": ids["pending"], "decision": "approve"})
    assert r.status_code == 303
    assert store.approval_decision(ids["pending"]) == "approve"


def test_decline_writes_the_decision(client, ids, store):
    _post(client, "/actions/approval",
          {"investigation_id": ids["pending"], "decision": "decline"})
    assert store.approval_decision(ids["pending"]) == "decline"


def test_approval_rejects_an_unknown_decision(client, ids, store):
    r = _post(client, "/actions/approval",
              {"investigation_id": ids["pending"], "decision": "maybe"})
    assert r.status_code == 400
    assert "maybe is not a valid decision." in r.text
    assert store.approval_decision(ids["pending"]) == ""


def test_approval_of_an_unknown_investigation_is_404(client):
    r = _post(client, "/actions/approval", {"investigation_id": 4242,
                                            "decision": "approve"})
    assert r.status_code == 404
    assert "No investigation #4242." in r.text


def test_htmx_approval_returns_the_panel_and_the_feedback_line(client, ids):
    r = client.post("/actions/approval",
                    data={"investigation_id": ids["pending"], "decision": "approve"},
                    headers=HX)
    assert r.status_code == 200 and "<html" not in r.text
    assert "Approved — the daemon starts the investigation within a few seconds." in r.text


# ---------------------------------------------------------------- verdicts

def test_confirm_sets_the_verdict_and_mutes_nothing(client, ids, store):
    r = _post(client, "/actions/verdict",
              {"finding_id": ids["finding_temp"], "verdict": "confirmed"})
    assert r.status_code == 303
    assert store.finding(ids["finding_temp"])["verdict"] == "confirmed"
    assert [s["fingerprint"] for s in store.suppressed()] == [FP_HA]   # unchanged
    assert store.incident(FP_TEMP)["status"] == "open"


def test_false_positive_sets_the_verdict_and_suppresses(client, ids, store, app_store):
    cfg = app_store[3]
    r = client.post("/actions/verdict",
                    data={"finding_id": ids["finding_mem"], "verdict": "false_positive"},
                    headers=HX)
    assert r.status_code == 200
    assert store.finding(ids["finding_mem"])["verdict"] == "false_positive"

    sup = next(s for s in store.suppressed() if s["fingerprint"] == FP_MEM)
    assert _until_day(sup) == _day_from_now(cfg.settings.suppression_days)
    # the incident follows the verdict, through the backend helper
    assert store.incident(FP_MEM)["status"] == "suppressed"
    # fragment: the verdict pill replaced the buttons, plus the feedback line
    assert "Marked false positive — muted until" in r.text
    assert "CONFIRM" not in r.text
    assert "false positive" in r.text


def test_verdict_rejects_an_unknown_value(client, ids, store):
    r = _post(client, "/actions/verdict",
              {"finding_id": ids["finding_temp"], "verdict": "dunno"})
    assert r.status_code == 400
    assert "dunno is not a valid verdict." in r.text
    assert store.finding(ids["finding_temp"])["verdict"] in (None, "")


def test_verdict_on_an_unknown_finding_is_404(client):
    r = _post(client, "/actions/verdict", {"finding_id": 7777, "verdict": "confirmed"})
    assert r.status_code == 404
    assert "No finding #7777." in r.text


# ------------------------------------------------------------ mute / unmute

def test_mute_suppresses_and_flips_the_incident(client, store):
    r = _post(client, "/actions/mute", {"fingerprint": FP_TEMP, "days": "3"})
    assert r.status_code == 303

    sup = next(s for s in store.suppressed() if s["fingerprint"] == FP_TEMP)
    assert _until_day(sup) == _day_from_now(3)
    assert store.incident(FP_TEMP)["status"] == "suppressed"


def test_mute_defaults_to_the_configured_window(client, store, app_store):
    days = app_store[3].settings.suppression_days
    _post(client, "/actions/mute", {"fingerprint": FP_TEMP})
    sup = next(s for s in store.suppressed() if s["fingerprint"] == FP_TEMP)
    assert _until_day(sup) == _day_from_now(days)


def test_mute_needs_a_fingerprint(client, store):
    r = _post(client, "/actions/mute", {"fingerprint": "  "})
    assert r.status_code == 400
    assert "Muting needs a fingerprint." in r.text
    assert [s["fingerprint"] for s in store.suppressed()] == [FP_HA]


def test_unmute_lifts_the_suppression_and_reopens_the_incident(client, store):
    r = client.post("/actions/unmute", data={"fingerprint": FP_HA}, headers=HX)
    assert r.status_code == 200
    assert [s["fingerprint"] for s in store.suppressed()] == []
    assert store.incident(FP_HA)["status"] == "open"
    assert "Unmuted — the pipelines report this fingerprint again." in r.text
    # the panel now offers the pre-mute actions again
    assert "INVESTIGATE NOW" in r.text and "UNMUTE" not in r.text


def test_unmute_of_something_that_is_not_muted_is_404(client):
    r = _post(client, "/actions/unmute", {"fingerprint": FP_TEMP})
    assert r.status_code == 404
    assert f"{FP_TEMP} is not muted." in r.text


def test_mute_round_trip_from_the_dashboard(client, store):
    _post(client, "/actions/mute", {"fingerprint": FP_MEM})
    assert store.incident(FP_MEM)["status"] == "suppressed"
    _post(client, "/actions/unmute", {"fingerprint": FP_MEM})
    assert store.incident(FP_MEM)["status"] == "open"
    assert FP_MEM not in {s["fingerprint"] for s in store.suppressed()}


# ------------------------------------------------- redirects & open redirect

def test_plain_post_falls_back_to_the_referer_then_to_the_root(client):
    with_ref = _post(client, "/actions/mute", {"fingerprint": FP_MEM},
                     headers={"referer": "/incidents"})
    assert with_ref.headers["location"] == "/incidents"

    bare = _post(client, "/actions/unmute", {"fingerprint": FP_MEM})
    assert bare.headers["location"] == "/"


def test_back_field_cannot_point_off_the_box(client):
    r = _post(client, "/actions/mute",
              {"fingerprint": FP_MEM, "back": "https://evil.example/pwn"})
    assert r.status_code == 303
    assert r.headers["location"] == "/"


def test_absolute_same_site_referer_keeps_the_path(client):
    r = _post(client, "/actions/mute", {"fingerprint": FP_MEM},
              headers={"referer": "http://testserver/investigations?status=running"})
    assert r.headers["location"] == "/investigations?status=running"


# -------------------------------------------------------------------- auth

@pytest.mark.parametrize("path,data", [
    ("/actions/investigate", {"host": "ubuntu-server"}),
    ("/actions/retrigger", {"investigation_id": 1}),
    ("/actions/approval", {"investigation_id": 1, "decision": "approve"}),
    ("/actions/verdict", {"finding_id": 1, "verdict": "confirmed"}),
    ("/actions/mute", {"fingerprint": FP_TEMP}),
    ("/actions/unmute", {"fingerprint": FP_HA}),
])
def test_actions_require_auth_when_the_token_is_set(client, store, monkeypatch,
                                                    path, data):
    monkeypatch.setenv("HEIM_DASHBOARD_TOKEN", "s3cret")
    denied = _post(client, path, data)
    assert denied.status_code == 401
    assert "Basic" in denied.headers.get("www-authenticate", "")
    # nothing was written behind the 401
    assert _jobs_by_dashboard(store) == []
    assert [s["fingerprint"] for s in store.suppressed()] == [FP_HA]

    ok = _post(client, path, data, auth=("anyone", "s3cret"))
    assert ok.status_code in (200, 303)


# ------------------------------------------------------- queue visibility

def test_overview_shows_the_queued_tile(client, store):
    html = client.get("/").text
    assert "queued" in html
    queued = store.queued_count()
    assert queued == 1
    tile = html.split("queued")[1]
    assert ">1</a>" in tile and "waiting for the daemon" in tile


def test_queued_tile_counts_a_job_the_dashboard_just_queued(client, store):
    _post(client, "/actions/investigate", {"host": "ubuntu-server"})
    assert store.queued_count() == 2
    assert ">2</a>" in client.get("/").text.split("queued")[1]


def test_investigations_page_renders_ghost_rows_for_queued_jobs(client, ids):
    html = client.get("/investigations").text
    assert 'class="ghost"' in html
    assert f"job #{ids['job']}" in html
    assert "queued · waiting for daemon" in html
    # a queued job means the table keeps polling, even with nothing running
    assert 'hx-trigger="every 5s"' in html
    # and the ghost sits above the real rows
    assert html.index("queued · waiting for daemon") < html.index(f'#{ids["done"]}</a>')


def test_ghost_rows_in_the_partial_and_under_filters(client, ids):
    frag = client.get("/investigations/rows").text
    assert "<html" not in frag and f"job #{ids['job']}" in frag
    # the ghost is a homelab job: it survives that host filter and drops out of
    # another host's view
    assert f"job #{ids['job']}" in client.get("/investigations?host=homelab").text
    assert f"job #{ids['job']}" not in client.get("/investigations?host=ubuntu-server").text
    # a status filter that contradicts "queued" hides ghosts; queued shows only them
    assert f"job #{ids['job']}" not in client.get("/investigations?status=running").text
    queued_only = client.get("/investigations?status=queued").text
    assert f"job #{ids['job']}" in queued_only
    assert f'#{ids["done"]}</a>' not in queued_only


# ----------------------------------------------------------- rendered UI

def test_incidents_page_shows_the_muted_row_with_unmute(client):
    html = client.get("/incidents").text
    assert FP_HA in html                       # suppressed rows are listed
    assert "muted · until" in html
    assert "UNMUTE" in html
    assert 'action="/actions/unmute"' in html
    # an open incident keeps the other two actions instead
    assert "INVESTIGATE NOW" in html and "MARK FALSE POSITIVE" in html
    # a muted row does not offer to investigate what it just silenced
    muted_cell = html.split(FP_HA)[-1]
    assert "UNMUTE" in muted_cell.split("</details>")[0]


def test_incident_actions_post_the_fingerprint_as_a_form_field(client):
    html = client.get("/incidents").text
    # never in a URL: fingerprints carry | and /
    assert 'name="fingerprint" value="ubuntu-server|mem_used|Memory climbing"' in html
    assert "/actions/mute?" not in html and f"/actions/mute/{FP_MEM}" not in html


def test_pending_approval_detail_offers_approve_and_decline(client, ids):
    html = client.get(f"/investigations/{ids['pending']}").text
    assert "APPROVE" in html and "DECLINE" in html
    assert 'class="btn ember"' in html          # approve is the ember exception
    assert "RE-RUN" in html


def test_finished_detail_has_re_run_but_no_approval_pair(client, ids):
    html = client.get(f"/investigations/{ids['done']}").text
    assert "RE-RUN" in html
    assert "APPROVE" not in html and "DECLINE" not in html


def test_retry_detail_links_back_to_the_original(client, ids):
    html = client.get(f"/investigations/{ids['retry']}").text
    assert f'href="/investigations/{ids["done"]}"' in html
    assert f"re-run of #{ids['done']}" in html


def test_findings_page_offers_the_verdict_pair_then_shows_the_pill(client, ids):
    html = client.get("/findings").text
    assert "✓ CONFIRM" in html and "✗ FALSE POSITIVE" in html
    assert f'name="finding_id" value="{ids["finding_mem"]}"' in html

    _post(client, "/actions/verdict",
          {"finding_id": ids["finding_mem"], "verdict": "confirmed"})
    after = client.get("/findings").text
    # that finding now renders a pill; the other one keeps its buttons
    assert "confirmed</span>" in after
    assert after.count("✓ CONFIRM") == 1


def test_host_cards_offer_investigate(client):
    html = client.get("/hosts").text
    assert html.count('action="/actions/investigate"') == 3
    assert "INVESTIGATE" in html


def test_action_forms_work_without_js(client):
    """Every action is a real form posting to a real route (spec §5)."""
    for path in ("/hosts", "/incidents", "/findings"):
        html = client.get(path).text
        assert 'method="post"' in html
        assert 'hx-post="/actions/' in html      # htmx is the enhancement
        assert 'name="back"' in html


def test_confirm_prompts_on_the_destructive_actions(client, ids):
    incidents = client.get("/incidents").text
    assert incidents.count("hx-confirm=") >= 4   # investigate now + false positive
    detail = client.get(f"/investigations/{ids['pending']}").text
    assert f"Re-run investigation #{ids['pending']}" in detail


def test_json_payload_is_not_a_write_path(client, store):
    """The routes read form fields only — a JSON body queues nothing."""
    r = client.post("/actions/investigate", json={"host": "ubuntu-server"},
                    follow_redirects=False)
    assert r.status_code == 400
    assert _jobs_by_dashboard(store) == []


def test_store_unchanged_by_page_reads(client, store):
    """The read surface stays read-only: rendering every page writes nothing."""
    before = (json.dumps(store.jobs(limit=50), sort_keys=True, default=str),
              json.dumps(store.all_rows(), sort_keys=True, default=str),
              json.dumps(store.suppressed(), sort_keys=True, default=str))
    for path in ("/", "/investigations", "/incidents", "/findings", "/hosts"):
        assert client.get(path).status_code == 200
    after = (json.dumps(store.jobs(limit=50), sort_keys=True, default=str),
             json.dumps(store.all_rows(), sort_keys=True, default=str),
             json.dumps(store.suppressed(), sort_keys=True, default=str))
    assert before == after


def test_iso_helper_is_shared_with_the_read_tests():
    """Guard the import this module leans on (tests/test_dashboard.py)."""
    assert _iso(0).startswith(str(datetime.now(timezone.utc).year))
