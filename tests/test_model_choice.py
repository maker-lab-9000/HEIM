"""Model choice at trigger time (design spec §5.1).

One model id travels a long way: a `<select>` in the dashboard's INVESTIGATE
form → the job payload → ``InvestigationRequest.model_override`` → the agent
config copy the replay slice already established → the Anthropic call → the
``investigations.model`` column the cost and usage breakdowns segment by.

So the end-to-end test asserts the *API kwarg*, not a mock of our own code:
anything that forgets to thread the override would still pass a test that
only checks the request object.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heim.config import load_config
from heim.dashboard.app import create_app
from heim.incidents.store import IncidentStore
from heim.pipelines.investigate import InvestigationRequest, run_investigation
from heim.pipelines.queue import enqueue_investigation, request_from_payload
from heim.runtime import Runtime

ROOT = Path(__file__).resolve().parent.parent

DUMMY_ENV = {
    "HEIM_SERVER_IP": "10.0.0.10",
    "HEIM_PROXMOX_IP": "10.0.0.2",
    "HEIM_HA_IP": "10.0.0.3",
    "HEIM_TELEGRAM_CHAT_ID": "111111111",
    "HEIM_EMAIL_TO": "test@example.com",
    "HEIM_EMAIL_FROM": "test@example.com",
}

#: the ids the test deployment offers; both are priced in the example config
MODELS = ["claude-opus-4-6", "claude-haiku-4-5"]

REPORT = ("## Summary\n\nDisk filled up.\n\n## Root cause\n\nlogs\n\n"
          "## Confidence\n\nhigh\n")


# ---------------------------------------------------------------- fixtures


def _config(tmp_path, monkeypatch):
    for k, v in DUMMY_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("HEIM_DASHBOARD_TOKEN", raising=False)
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    return load_config(croot)


@pytest.fixture()
def rt(tmp_path, monkeypatch) -> Runtime:
    """A Runtime on the example config, every outbound channel disabled."""
    cfg = _config(tmp_path, monkeypatch)
    cfg.settings.loki = None
    cfg.settings.email = None
    cfg.settings.home_assistant = None
    cfg.settings.telegram = None
    cfg.settings.investigator_models = list(MODELS)
    return Runtime(config=cfg, store=IncidentStore(tmp_path / "rt.sqlite3"),
                   dry_run=True, out_dir=tmp_path / "out")


def _client(tmp_path, monkeypatch, models: list[str]):
    cfg = _config(tmp_path, monkeypatch)
    cfg.settings.db_path = str(tmp_path / f"heim-{len(models)}.sqlite3")
    cfg.settings.investigator_models = list(models)
    seed = IncidentStore(cfg.settings.db_path)
    seed.upsert([{
        "fingerprint": "ubuntu-server|mem_used|Memory climbing", "host": "ubuntu-server",
        "metric": "mem_used", "severity": "critical", "status": "open",
        "firstSeen": "2026-09-14T08:00:00+00:00", "lastSeen": "2026-09-18T08:00:00+00:00",
        "timesSeen": 7, "missedRuns": 0, "description": "Working set grew 18%.",
    }])
    seed.close()
    return cfg, TestClient(create_app(cfg))


@pytest.fixture()
def actions_client(tmp_path, monkeypatch):
    """The dashboard with two models configured (the select renders)."""
    cfg, client = _client(tmp_path, monkeypatch, MODELS)
    with client as c:
        c.heim_store = IncidentStore(cfg.settings.db_path)   # a second connection
        yield c
        c.heim_store.close()


@pytest.fixture()
def plain_client(tmp_path, monkeypatch):
    """The default deployment: no models listed, so no select at all."""
    _cfg, client = _client(tmp_path, monkeypatch, [])
    with client as c:
        yield c


def store_of(client) -> IncidentStore:
    return client.heim_store


# ---------------------------------------------------------- fake anthropic


class _Usage:
    def __init__(self, i: int, o: int):
        self.input_tokens, self.output_tokens = i, o


class _Text:
    type = "text"

    def __init__(self, text: str):
        self.text = text


class _Resp:
    def __init__(self, content: list, stop_reason: str, usage=(100, 20)):
        self.content = content
        self.stop_reason = stop_reason
        self.usage = _Usage(*usage)


class _FakeMessages:
    def __init__(self, script: list):
        self._script = list(script)
        self.kwargs: list[dict] = []

    async def create(self, **kwargs):
        self.kwargs.append(kwargs)
        return self._script.pop(0)


class _FakeClient:
    def __init__(self, script: list):
        self.messages = _FakeMessages(script)


def _patch_client(monkeypatch, script: list | None = None) -> _FakeClient:
    client = _FakeClient(script if script is not None else [_Resp([_Text(REPORT)], "end_turn")])
    monkeypatch.setattr("heim.agent.runner.AsyncAnthropic", lambda *a, **k: client)
    return client


# ------------------------------------------------------- request → the API


async def test_request_model_override_reaches_client(rt, monkeypatch):
    configured = rt.config.agents["investigator"].model   # captured BEFORE the run
    client = _patch_client(monkeypatch)
    req = InvestigationRequest(host="ubuntu-server", model_override="claude-opus-4-6")

    result = await run_investigation(rt, req, require_approval=False)

    assert {k["model"] for k in client.messages.kwargs} == {"claude-opus-4-6"}
    row = rt.store.investigation(result["id"])
    assert row["model"] == "claude-opus-4-6"
    # priced against the model that actually ran, not the configured default
    assert row["cost"] == pytest.approx((100 * 5.0 + 20 * 25.0) / 1e6)
    # …and the configured agent is untouched for the next caller
    assert rt.config.agents["investigator"].model == configured


async def test_no_override_runs_the_configured_model(rt, monkeypatch):
    # read rather than hardcoded, so a model bump in investigator.yaml does
    # not fail a test about overrides
    configured = rt.config.agents["investigator"].model
    client = _patch_client(monkeypatch)
    result = await run_investigation(rt, InvestigationRequest(host="ubuntu-server"),
                                     require_approval=False)
    assert {k["model"] for k in client.messages.kwargs} == {configured}
    assert rt.store.investigation(result["id"])["model"] == configured


def test_approval_text_names_an_overridden_model(rt):
    from heim.pipelines.investigate import _approval_text

    plain = _approval_text(InvestigationRequest(host="ubuntu-server"), "f")
    assert "model:" not in plain
    chosen = _approval_text(
        InvestigationRequest(host="ubuntu-server", model_override="claude-opus-4-6"), "f")
    assert "· model: claude-opus-4-6" in chosen


# -------------------------------------------------------------- the queue


def test_job_payload_round_trips_the_model(rt):
    job_id = enqueue_investigation(rt.store, host="ubuntu-server",
                                   model="claude-haiku-4-5", requested_by="cli")
    job = next(j for j in rt.store.jobs(limit=10) if j["id"] == job_id)
    assert job["payload"]["model"] == "claude-haiku-4-5"

    req = request_from_payload(job["payload"], rt)
    assert req.model_override == "claude-haiku-4-5"


def test_payload_without_a_model_is_still_understood(rt):
    """Jobs queued before this feature (and the default path) carry no key."""
    req = request_from_payload({"host": "ubuntu-server", "findings": []}, rt)
    assert req.model_override == ""


# ---------------------------------------------------------- the dashboard


def test_dashboard_investigate_accepts_allowed_model(actions_client):
    r = actions_client.post("/actions/investigate",
                            data={"host": "ubuntu-server", "model": "claude-opus-4-6",
                                  "back": "/hosts"},
                            follow_redirects=False)
    assert r.status_code == 303
    job = store_of(actions_client).jobs(limit=10)[0]
    assert '"model": "claude-opus-4-6"' in job["payload_json"]


def test_dashboard_investigate_without_a_model_queues_the_default(actions_client):
    r = actions_client.post("/actions/investigate",
                            data={"host": "ubuntu-server", "model": "", "back": "/hosts"},
                            follow_redirects=False)
    assert r.status_code == 303
    job = store_of(actions_client).jobs(limit=10)[0]
    assert job["payload"]["model"] == ""


def test_dashboard_rejects_unlisted_model(actions_client):
    r = actions_client.post("/actions/investigate",
                            data={"host": "ubuntu-server", "model": "gpt-99"})
    assert r.status_code == 400
    assert "gpt-99" in r.text
    assert store_of(actions_client).jobs(limit=10) == []


def test_dashboard_rejects_any_model_when_none_are_configured(plain_client):
    r = plain_client.post("/actions/investigate",
                          data={"host": "ubuntu-server", "model": "claude-opus-4-6"})
    assert r.status_code == 400


def test_select_rendered_only_when_configured(actions_client, plain_client):
    from heim.config import load_config
    configured = load_config(ROOT / "config").agents["investigator"].model
    with_models = actions_client.get("/hosts").text
    assert '<select class="mselect mono" name="model"' in with_models
    assert f"default ({configured})" in with_models
    for mid in MODELS:
        assert f'<option value="{mid}">' in with_models
    assert '<select name="model"' not in plain_client.get("/hosts").text
    assert 'name="model"' not in plain_client.get("/hosts").text


def test_the_select_rides_the_incident_form_too(actions_client):
    html = actions_client.get("/incidents").text
    assert html.count('name="model"') >= 1
