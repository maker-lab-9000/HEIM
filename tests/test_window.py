"""The window switch: Live / 24 h / 7 d run buckets."""
import re

from heim.agents import bucket_runs
from test_overview_console import _agents, _client, _healthy_agents, _rows, _section

NOW = "2026-11-01T12:00:00+00:00"
HOUR = 3600


def _run(hours_ago, ok=True):
    from datetime import datetime, timedelta
    at = datetime.fromisoformat(NOW) - timedelta(hours=hours_ago)
    return {"started_at": at.isoformat(), "ok": ok}


def test_bucket_runs_marks_fail_miss_and_open():
    # 24 h in 24 one-hour slots; slot i covers [i h, i+1 h) after 2026-10-31T12:00.
    # 0.5 h ago -> slot 23, 5.5 h ago -> slot 18 (ok then a failure in it),
    # 10.5 h ago -> slot 13.
    runs = [_run(0.5), _run(5.5), _run(5.2, ok=False), _run(10.5)]
    ticks = bucket_runs(runs, HOUR, 24 * HOUR, NOW)
    assert len(ticks) == 24
    assert ticks[0].at == "2026-10-31T12:00:00+00:00"
    assert ticks[23].state == "ok"
    assert ticks[18].state == "fail"
    assert ticks[13].state == "ok"
    assert [i for i, t in enumerate(ticks) if t.state == "ok"] == [13, 23]
    assert all(t.state == "miss" for i, t in enumerate(ticks) if i not in (13, 18, 23))
    # the newest slot is only "open" while it is still short of a cadence
    open_ticks = bucket_runs([_run(5.5)], 2 * HOUR, 24 * HOUR, NOW)
    assert open_ticks[23].state == "open"
    assert open_ticks[22].state == "none"


def test_bucket_runs_without_cadence_never_misses():
    ticks = bucket_runs([_run(0.5), _run(30.0)], None, 24 * HOUR, NOW)
    states = [t.state for t in ticks]
    assert states[23] == "ok"
    assert "miss" not in states and "fail" not in states
    assert states.count("ok") == 1 and states.count("none") == 23
    assert bucket_runs([], None, 24 * HOUR, NOW)[23].state == "open"


def _switch(html):
    return _section(html, 'aria-label="Window"', "</div>")


def test_window_param_switches_strips_and_marks_segment(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, _healthy_agents) as c:
        html = c.get("/?window=7d&agents=all").text
        agents = c.get("/agents?window=24h").text
        live = c.get("/").text
    switch = _switch(html)
    seven = re.search(r"<a[^>]*>.*?7 d</a>", switch, re.S).group(0)
    assert 'aria-current="true"' in seven and switch.count('aria-current="true"') == 1
    assert "agents=all" in switch                    # other params survive
    row = _rows(_agents(html))[0]
    assert 'class="none"' in row or 'class="miss"' in row
    assert re.search(r'role="img" aria-label="\d+ polls?, ', html)
    day = _switch(agents)
    assert 'aria-current="true"' in re.search(r"<a[^>]*>.*?24 h</a>", day, re.S).group(0)
    assert _rows(_agents(agents))
    assert _rows(_agents(live))[0] != row


def test_bad_window_falls_back_to_live(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, _healthy_agents) as c:
        html = c.get("/?window=bogus").text
        plain = c.get("/").text
    switch = _switch(html)
    live = re.search(r"<a[^>]*>.*?Live</a>", switch, re.S).group(0)
    assert 'aria-current="true"' in live and switch.count('aria-current="true"') == 1
    assert _rows(_agents(html)) == _rows(_agents(plain))
