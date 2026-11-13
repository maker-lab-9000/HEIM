"""The daily Loki error digest (2026-11-13).

One email at 08:00: every error line of the last 24 h from the journal, the
docker containers and Home Assistant, repeats collapsed, the expected noise
listed in ``config/log_digest.yaml`` dropped and counted.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from heim.reports.log_digest import (
    DigestCfg, IgnoreRule, Source, load_digest_cfg, render_email, summarise,
)

ROOT = Path(__file__).resolve().parents[1]
NS = 1_000_000_000
T0 = int(datetime(2026, 11, 13, 6, 0, tzinfo=timezone.utc).timestamp()) * NS
START = datetime(2026, 11, 12, 7, 0, tzinfo=timezone.utc)
END = datetime(2026, 11, 13, 7, 0, tzinfo=timezone.utc)


def stream(labels, *lines, step=60):
    return {"stream": labels, "values": [[str(T0 + i * step * NS), t] for i, t in enumerate(lines)]}


JOURNAL = {"job": "systemd-journal", "host": "llm", "unit": "apt-daily.service", "level": "error"}
SMART = {"job": "systemd-journal", "host": "homelab", "unit": "smartd.service", "level": "error"}
BROWSERLESS = {"host": "ubuntu-server", "container_name": "browserless"}


def cfg(*ignore):
    return DigestCfg(lookback_hours=24, sources=(Source("journal", '{job="systemd-journal"}'),),
                     ignore=tuple(IgnoreRule(p, "why") for p in ignore))


# ------------------------------------------------------------------ grouping


def test_repeats_collapse_into_one_group_with_count_and_span():
    res = {"journal": [stream(JOURNAL, "Timeout occurred after 120 seconds (pid 4411)",
                              "Timeout occurred after 120 seconds (pid 5120)")]}
    d = summarise(res, cfg())
    assert len(d.groups) == 1
    g = d.groups[0]
    assert (g.host, g.who, g.count) == ("llm", "apt-daily.service", 2)
    assert g.first_ns == T0 and g.last_ns == T0 + 60 * NS
    assert "pid 5120" in g.text   # the newest example is shown


def test_the_same_message_on_two_hosts_is_two_groups():
    other = {**JOURNAL, "host": "jellyfin"}
    d = summarise({"journal": [stream(JOURNAL, "boom"), stream(other, "boom")]}, cfg())
    assert sorted(g.host for g in d.groups) == ["jellyfin", "llm"]


def test_groups_are_ordered_by_count():
    d = summarise({"journal": [stream(JOURNAL, "a"), stream(SMART, "b", "b", "b")]}, cfg())
    assert [g.count for g in d.groups] == [3, 1]


def test_a_line_shipped_twice_is_counted_once():
    s = stream(JOURNAL, "boom")
    d = summarise({"journal": [s], "again": [s]}, cfg())
    assert d.groups[0].count == 1 and d.lines == 1


def test_terminal_colours_are_stripped():
    d = summarise({"journal": [stream(JOURNAL, "\x1b[31mERROR boom\x1b[0m")]}, cfg())
    assert d.groups[0].text == "ERROR boom"


# ------------------------------------------------------------------ ignoring


def test_ignored_lines_are_dropped_and_counted_per_rule():
    res = {"journal": [stream(SMART, "Device: /dev/sdb, is in STANDBY mode, low-power mode",
                              "Device: /dev/sdc, is in STANDBY mode, low-power mode"),
                       stream(JOURNAL, "real error")],
           "containers": [stream(BROWSERLESS, '{"msg":"Current period usage","error":0}')]}
    d = summarise(res, cfg("low-power mode", r'"error":\s*0\b'))
    assert [g.text for g in d.groups] == ["real error"]
    assert d.ignored == {"low-power mode": 2, r'"error":\s*0\b': 1}


def test_a_real_browserless_error_is_not_ignored():
    res = {"containers": [stream(BROWSERLESS, '{"msg":"session crashed","error":1}')]}
    d = summarise(res, cfg(r'"error":\s*0\b'))
    assert d.groups and not d.ignored


def test_a_bad_ignore_pattern_is_refused():
    with pytest.raises(ValueError, match="pattern"):
        IgnoreRule("(unclosed", "why")


# ------------------------------------------------------------------ the email


def test_a_clean_day_still_sends_and_says_so():
    subject, html = render_email(summarise({"journal": []}, cfg()), START, END, "Europe/Berlin")
    assert "no errors" in subject.lower()
    assert "No error lines" in html


def test_the_subject_counts_kinds_and_lines():
    d = summarise({"journal": [stream(JOURNAL, "a", "a"), stream(SMART, "b")]}, cfg())
    subject, _ = render_email(d, START, END, "Europe/Berlin")
    assert "2 kinds" in subject and "3 lines" in subject


def test_the_body_shows_host_source_count_and_local_time():
    d = summarise({"journal": [stream(JOURNAL, "a <b> & c", "a <b> & c")]}, cfg())
    _, html = render_email(d, START, END, "Europe/Berlin")
    assert "llm" in html and "apt-daily.service" in html and "×2" in html
    assert "a &lt;b&gt; &amp; c" in html          # escaped, not injected
    assert "11-13 07:00" in html                  # 06:00Z in Berlin


def test_the_body_lists_what_was_ignored_and_why():
    rules = (IgnoreRule("low-power mode", "smartctl skips a sleeping disk"),)
    c = DigestCfg(24, (Source("journal", "{x=\"y\"}"),), rules)
    d = summarise({"journal": [stream(SMART, "x low-power mode")]}, c)
    _, html = render_email(d, START, END, "Europe/Berlin")
    assert "smartctl skips a sleeping disk" in html and ">1<" in html


def test_a_failed_or_truncated_source_marks_the_digest_incomplete():
    d = summarise({"journal": []}, cfg(), truncated=["containers"],
                  failed={"homeassistant": "ConnectError: refused"})
    subject, html = render_email(d, START, END, "Europe/Berlin")
    assert "incomplete" in subject.lower()
    assert "homeassistant" in html and "ConnectError" in html and "containers" in html
    assert "No error lines" not in html


def test_too_many_groups_are_capped_with_a_note():
    lines = [f"distinct error kind {chr(97 + i % 26)}{chr(97 + i // 26)}" for i in range(80)]
    c = DigestCfg(24, (Source("journal", "{x=\"y\"}"),), (), max_groups=50)
    d = summarise({"journal": [stream(JOURNAL, *lines)]}, c)
    _, html = render_email(d, START, END, "Europe/Berlin")
    assert html.count('class="grp"') == 50
    assert "30 more" in html


# ------------------------------------------------------------------ the shipped config


def test_the_shipped_config_loads_and_ignores_the_known_noise():
    c = load_digest_cfg(ROOT / "config" / "log_digest.yaml")
    assert c.lookback_hours == 24
    assert {s.name for s in c.sources} == {"journal", "containers", "homeassistant"}
    assert all(s.logql.lstrip().startswith("{") for s in c.sources)
    noise = ['Device: /dev/sdb [SAT], is in STANDBY mode, low-power mode, skipping',
             '{"type":"stats","msg":"Current period usage","error":0,"queued":0}']
    d = summarise({"journal": [stream(SMART, noise[0])],
                   "containers": [stream(BROWSERLESS, noise[1])]}, c)
    assert not d.groups and sum(d.ignored.values()) == 2


def test_a_source_that_is_not_a_log_query_is_refused(tmp_path):
    p = tmp_path / "d.yaml"
    p.write_text("sources:\n  - name: x\n    logql: 'sum(count_over_time({a=\"b\"}[1h]))'\n")
    with pytest.raises(ValueError, match="log query"):
        load_digest_cfg(p)


# ------------------------------------------------------------------ the pipeline, daemon and CLI

import shutil  # noqa: E402

from heim import cli, daemon  # noqa: E402
from heim.config import LokiCfg, SchedulesCfg, load_config  # noqa: E402
from heim.incidents.store import IncidentStore  # noqa: E402
from heim.pipelines import log_digest as pipe  # noqa: E402
from heim.runtime import Runtime  # noqa: E402


@pytest.fixture()
def rt(tmp_path):
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    c = load_config(croot)
    c.settings.email = c.settings.home_assistant = None
    c.settings.loki = LokiCfg(url="http://loki:3100")
    return Runtime(config=c, store=IncidentStore(tmp_path / "rt.sqlite3"), dry_run=True,
                   out_dir=tmp_path / "out")


class _Loki:
    """Answers query_range per source; a source named in ``fail`` raises."""
    def __init__(self, by_query, fail=()):
        self.by_query, self.fail, self.calls = by_query, fail, []

    def __call__(self, *a, **k):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, params=None):
        import httpx
        self.calls.append(params)
        q = params["query"]
        if any(f in q for f in self.fail):
            raise httpx.ConnectError("refused")
        return httpx.Response(200, json={"status": "success", "data": {
            "resultType": "streams", "result": self.by_query(q)}},
            request=httpx.Request("GET", url))


def _answer(q):
    if "systemd-journal" in q:
        return [stream(SMART, "x low-power mode"), stream(JOURNAL, "Timeout waiting for network")]
    return []


async def test_the_digest_reads_every_source_over_the_window_and_emails(rt, monkeypatch):
    loki = _Loki(_answer)
    monkeypatch.setattr(pipe.httpx, "AsyncClient", loki)
    out = await pipe.run_log_digest(rt, now=END)
    assert len(loki.calls) == 3
    p = loki.calls[0]
    assert int(p["end"]) - int(p["start"]) == 24 * 3600 * NS and p["direction"] == "backward"
    assert out["groups"] == 1 and out["ignored"] == 1 and not out["failed"]
    html = next((rt.out_dir).glob("*.html")).read_text()
    assert "Timeout waiting for network" in html and "low-power mode" in html


async def test_one_unreachable_source_still_sends_an_incomplete_digest(rt, monkeypatch):
    monkeypatch.setattr(pipe.httpx, "AsyncClient", _Loki(_answer, fail=('host="homeassistant"',)))
    out = await pipe.run_log_digest(rt, now=END)
    assert list(out["failed"]) == ["homeassistant"]
    assert "incomplete" in next(rt.out_dir.glob("*.html")).name.lower()


async def test_every_source_unreachable_raises(rt, monkeypatch):
    monkeypatch.setattr(pipe.httpx, "AsyncClient", _Loki(_answer, fail=("{",)))
    with pytest.raises(RuntimeError, match="every source"):
        await pipe.run_log_digest(rt, now=END)


async def test_a_full_page_is_reported_as_truncated(rt, monkeypatch):
    monkeypatch.setattr(pipe, "FETCH_LIMIT", 2)
    monkeypatch.setattr(pipe.httpx, "AsyncClient", _Loki(_answer))
    out = await pipe.run_log_digest(rt, now=END)
    assert out["truncated"] == ["journal"]


def test_the_schedule_defaults_to_eight_and_can_be_turned_off():
    assert SchedulesCfg().log_digest == "08:00"
    assert SchedulesCfg(log_digest="").log_digest == ""
    with pytest.raises(ValueError):
        SchedulesCfg(log_digest="8am")


async def test_the_daemon_job_notifies_on_failure_and_never_raises(rt, monkeypatch):
    async def boom(rt_, **kw):
        raise RuntimeError("every source failed")
    monkeypatch.setattr(daemon, "run_log_digest", boom)
    sent = []

    async def capture(text):
        sent.append(text)
    monkeypatch.setattr(rt, "notify", capture)
    await daemon._log_digest_job(rt)
    assert sent and "log digest FAILED" in sent[0] and "every source failed" in sent[0]


def test_the_cli_has_the_verb():
    a = cli._build_parser().parse_args(["log-digest", "--dry-run"])
    assert a.cmd == "log-digest" and a.dry_run


def test_stack_frames_are_ignored_but_the_error_line_is_kept():
    c = load_digest_cfg(ROOT / "config" / "log_digest.yaml")
    n8n = {"host": "ubuntu-server", "container_name": "n8n"}
    d = summarise({"containers": [stream(n8n, "Error: Unexpected close tag",
                                         "at error (/usr/lib/n8n/sax/lib/sax.js:651:10)")]}, c)
    assert [g.text for g in d.groups] == ["Error: Unexpected close tag"]
