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
    # boundaries: a run at exactly now - window_s is slot 0, one at now is slot 23
    edge = bucket_runs([_run(24.0), _run(0.0, ok=False)], HOUR, 24 * HOUR, NOW)
    assert edge[0].state == "ok" and edge[23].state == "fail"
    assert [i for i, t in enumerate(edge) if t.state != "miss"] == [0, 23]
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
    rows = _rows(_agents(html))
    row = rows[0]
    # alert poller beat only inside the newest 7 h slot, and that was its
    # first-ever beat: 1 ok, and the 23 slots before it are blank, not missed
    # (ruling 23 -- nothing was due before the agent first ran)
    assert "Alert poller" in row
    assert row.count('class="none"') == 23 and row.count("<i") == 24
    assert 'class="miss"' not in row
    # the investigator has no cadence: its empty slots are dots, never misses
    inv = next(r for r in rows if "Investigator" in r)
    assert 'class="miss"' not in inv and inv.count('class="none"') >= 22
    assert "Last 7 d" in _agents(html) and "Last 24 runs" not in _agents(html)
    assert "Last 24 h" in _agents(agents) and "Last 24 runs" not in _agents(agents)
    assert "Last 24 runs" in _agents(live)
    assert re.search(r'role="img" aria-label="\d+ polls?, ', html)
    day = _switch(agents)
    assert 'aria-current="true"' in re.search(r"<a[^>]*>.*?24 h</a>", day, re.S).group(0)
    assert _rows(_agents(agents))
    live_row = _rows(_agents(live))[0]
    assert live_row.count("<i") == 5 and 'class="miss"' not in live_row   # five real beats


def test_bad_window_falls_back_to_live(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, _healthy_agents) as c:
        html = c.get("/?window=bogus").text
        plain = c.get("/").text
    switch = _switch(html)
    live = re.search(r"<a[^>]*>.*?Live</a>", switch, re.S).group(0)
    assert 'aria-current="true"' in live and switch.count('aria-current="true"') == 1
    assert _rows(_agents(html)) == _rows(_agents(plain))


# ------------------------------------------- first heartbeat (ruling 23)

def _five_minute_runs(hours):
    return [_run(m / 60) for m in range(0, int(hours * 60), 5)]


def test_bucket_runs_never_misses_before_the_first_heartbeat():
    """A fresh deploy: 2 h of 5-minute polls in a 24 h window. The 22 slots
    before the first-ever run are not misses; nothing was due yet."""
    runs = _five_minute_runs(2)
    first = min(r["started_at"] for r in runs)
    ticks = bucket_runs(runs, 300, 24 * HOUR, NOW, first_seen_iso=first)
    states = [t.state for t in ticks]
    assert "miss" not in states
    assert states[:22] == ["none"] * 22 and states[22:] == ["ok", "ok"]


def test_bucket_runs_still_misses_a_gap_after_the_first_heartbeat():
    # first run 10.5 h ago, then silence until 0.5 h ago
    runs = [_run(0.5), _run(10.5)]
    ticks = bucket_runs(runs, 300, 24 * HOUR, NOW, first_seen_iso=_run(10.5)["started_at"])
    states = [t.state for t in ticks]
    assert states[:13] == ["none"] * 13          # slots ending before the first run
    assert states[13] == "ok" and states[23] == "ok"
    assert states[14:23] == ["miss"] * 9         # the real gap after it


def test_window_misses_a_gap_after_the_first_heartbeat(tmp_path, monkeypatch):
    """A poller first seen 3 days ago, then silent until the last 22 min: the
    7 d strip is blank before day -3 and missed between then and now."""
    from test_overview_console import _beat

    def seed(store):
        _healthy_agents(store)
        _beat(store, "alert_poller", 3 * 24 * 60, detail={"hosts": 4})

    with _client(tmp_path, monkeypatch, seed) as c:
        html = c.get("/?window=7d").text
    row = _rows(_agents(html))[0]
    assert "Alert poller" in row
    assert row.count('class="miss"') > 0 and row.count('class="none"') > 0
    label = re.search(r'class="ruler" role="img" aria-label="\d+ polls?, \d+ failed, (\d+) missed"',
                      html)
    # first beat 72 h ago lands in slot 13 of 24 seven-hour slots; 14..22 missed
    assert label and int(label.group(1)) == 9
