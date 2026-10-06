import shutil
from argparse import Namespace
from pathlib import Path

import pytest

from heim import cli, daemon
from heim.config import load_config
from heim.incidents.store import IncidentStore
from heim.runtime import Runtime

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def rt(tmp_path):
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    cfg.settings.loki = cfg.settings.email = cfg.settings.home_assistant = None
    return Runtime(config=cfg, store=IncidentStore(tmp_path / "rt.sqlite3"), dry_run=True, out_dir=tmp_path / "out")


def test_weekly_trigger_fields():
    trig = daemon.weekly_trigger("mon 06:00", "Europe/Berlin")
    fields = {f.name: str(f) for f in trig.fields}
    assert fields["day_of_week"] == "mon" and fields["hour"] == "6" and fields["minute"] == "0"
    assert str(trig.timezone) == "Europe/Berlin"


async def test_security_audit_job_notifies_on_failure_and_never_raises(rt, monkeypatch):
    async def boom(rt_, **kw):
        raise RuntimeError("every source was unreachable")
    monkeypatch.setattr(daemon, "run_security_audit", boom)
    sent = []

    async def capture(text):
        sent.append(text)
    monkeypatch.setattr(rt, "notify", capture)
    await daemon._security_audit_job(rt)                      # must not raise
    assert sent and sent[0].startswith("🔴 HEIM weekly security audit FAILED") and "unreachable" in sent[0]


async def test_security_audit_job_success_is_quiet(rt, monkeypatch):
    async def fine(rt_, **kw):
        return {"findings": 0}
    monkeypatch.setattr(daemon, "run_security_audit", fine)
    sent = []

    async def capture(text):
        sent.append(text)
    monkeypatch.setattr(rt, "notify", capture)
    await daemon._security_audit_job(rt)
    assert sent == []                                          # the pipeline delivers its own digest


def test_cli_parser_has_the_verb():
    p = cli._build_parser()
    a = p.parse_args(["security-audit", "--dry-run", "--no-llm"])
    assert a.cmd == "security-audit" and a.dry_run and a.no_llm
    assert not p.parse_args(["security-audit"]).no_llm


async def test_cli_handler_runs_pipeline_with_flags(rt, monkeypatch, capsys):
    calls = {}

    async def fake_run(rt_, *, llm=True):
        calls["llm"] = llm
        calls["dry_run"] = rt_.dry_run
        return {"run_id": 1, "findings": 2, "assessment": "skipped"}
    monkeypatch.setattr("heim.pipelines.security_audit.run_security_audit", fake_run)
    monkeypatch.setattr("heim.runtime.build_runtime", lambda dry_run=False: rt)
    rc = await cli._cmd_security_audit(Namespace(dry_run=True, no_llm=True))
    assert rc == 0 and calls == {"llm": False, "dry_run": True}
    assert '"findings": 2' in capsys.readouterr().out


# FR-5(c): a bad checks.yaml surfaces at daemon startup, without taking the daemon down.

async def test_startup_catalogue_check_notifies_on_a_bad_checks_yaml(rt, monkeypatch):
    rt.config.security_checks_path.write_text("sources:\n  - {key: ssh.x, kind: ssh, target: 'rm -rf /'}\nchecks: []\n")
    sent = []

    async def capture(text):
        sent.append(text)
    monkeypatch.setattr(rt, "notify", capture)
    assert await daemon._check_audit_catalogue(rt) is False             # never raises
    assert sent and sent[0].startswith("🔴") and "checks.yaml" in sent[0]


async def test_startup_catalogue_check_is_silent_when_valid(rt, monkeypatch):
    sent = []

    async def capture(text):
        sent.append(text)
    monkeypatch.setattr(rt, "notify", capture)
    assert await daemon._check_audit_catalogue(rt) is True and sent == []


async def test_run_daemon_checks_the_catalogue_before_registering_the_audit_job(rt, monkeypatch):
    order = []

    class _Stop(Exception):
        pass

    class FakeScheduler:
        def __init__(self, **kw):
            pass

        def add_job(self, fn, trigger, **kw):
            order.append(kw.get("name"))

        def start(self):
            raise _Stop

        def shutdown(self, wait=False):
            pass

    async def fake_check(rt_):
        order.append("catalogue-check")
        return True
    monkeypatch.setattr(daemon, "build_runtime", lambda: rt)
    monkeypatch.setattr(daemon, "AsyncIOScheduler", FakeScheduler)
    monkeypatch.setattr(daemon, "_check_audit_catalogue", fake_check)
    with pytest.raises(_Stop):
        await daemon.run_daemon()
    assert "catalogue-check" in order and order.index("catalogue-check") < order.index("security-audit")
