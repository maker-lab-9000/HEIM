from heim.incidents.store import IncidentStore
from heim.incidents.types import HostRouting
from heim.incidents.uptime_logic import (
    Monitor,
    is_investigable_host,
    map_host,
    parse_metrics,
    unmapped_monitors,
)

METRICS = r'''# HELP monitor_status Monitor Status (1 = UP, 0= DOWN, 2= PENDING, 3= MAINTENANCE)
# TYPE monitor_status gauge
monitor_response_time{monitor_id="1",monitor_name="n8n",monitor_type="http",monitor_url="http://10.0.0.10:5678",monitor_hostname="null",monitor_port="null"} 12
monitor_status{monitor_id="1",monitor_name="n8n",monitor_type="http",monitor_url="http://10.0.0.10:5678",monitor_hostname="null",monitor_port="null"} 0
monitor_status{monitor_id="2",monitor_name="ssh",monitor_type="port",monitor_url="https://",monitor_hostname="10.0.0.10",monitor_port="22"} 1
monitor_status{monitor_id="3",monitor_name="ping",monitor_type="ping",monitor_url="https://",monitor_hostname="10.0.0.10",monitor_port="null"} 1
'''


def test_parse_reads_status_and_labels():
    ms = parse_metrics(METRICS)
    assert ms[0] == Monitor("1", "n8n", "http", "http://10.0.0.10:5678", "10.0.0.10", 0)
    assert (ms[1].target, ms[1].address) == ("10.0.0.10:22", "10.0.0.10")
    assert (ms[2].target, ms[2].address) == ("10.0.0.10", "10.0.0.10")
    assert len(ms) == 3


def test_parse_unescapes_label_values():
    text = (
        'monitor_status{monitor_id="9",monitor_name="My \\"prod\\" app, v2",'
        'monitor_type="http",monitor_url="http://10.0.0.10",monitor_hostname="null",'
        'monitor_port="null"} 1\n'
    )
    assert parse_metrics(text)[0].name == 'My "prod" app, v2'


def test_parse_returns_nothing_without_monitor_status():
    text = 'app_version{version="2.0"} 1\nmonitor_response_time{monitor_id="1"} 5\n'
    assert parse_metrics(text) == []


def test_map_host_matches_the_whole_address_not_a_prefix():
    m = {"10.0.0.10": "ubuntu-server", "10.0.0.2": "homelab"}
    names = set(m.values())
    assert map_host("10.0.0.24", m, names) is None
    assert map_host("10.0.0.2", m, names) == "homelab"
    assert map_host("10.0.0.10", m, names) == "ubuntu-server"


def test_map_host_ignores_port_in_map_key():
    assert map_host("10.0.0.10", {"10.0.0.10:9100": "ubuntu-server"}, []) == "ubuntu-server"


def test_map_host_by_first_dns_label():
    names = {"ubuntu-server", "homelab"}
    assert map_host("ubuntu-server.tail1234.ts.net", {}, names) == "ubuntu-server"
    assert map_host("Ubuntu-Server.example", {}, names) == "ubuntu-server"
    assert map_host("grafana.example", {}, names) is None


def test_investigability():
    r = HostRouting(
        ssh_hosts=frozenset({"ubuntu-server"}),
        hypervisor_host="homelab",
        hypervisor_categories=frozenset({"cpu", "availability"}),
        ha_host="home-assistant",
    )
    assert is_investigable_host("ubuntu-server", r)
    assert is_investigable_host("home-assistant", r)
    assert is_investigable_host("homelab", r)
    r2 = HostRouting(
        ssh_hosts=r.ssh_hosts,
        hypervisor_host="homelab",
        hypervisor_categories=frozenset({"cpu"}),
        ha_host="home-assistant",
    )
    assert not is_investigable_host("homelab", r2)
    assert not is_investigable_host("heim", r)
    assert not is_investigable_host("10.0.0.24", r)


def test_unmapped_monitors_lists_report_only_targets():
    m = {"10.0.0.10": "ubuntu-server"}
    a = Monitor("1", "a", "http", "http://10.0.0.10", "10.0.0.10", 1)
    b = Monitor("2", "b", "http", "http://10.0.0.24", "10.0.0.24", 1)
    assert unmapped_monitors([a, b], m, {"ubuntu-server"}) == [b]


# ------------------------------------------------------------------ store


def _row(fp, **kw):
    base = {"fingerprint": fp, "up_polls": 0, "absent_polls": 0,
            "last_recovered_at": "", "flap_outages": 0, "flap_msg_at": ""}
    base.update(kw)
    return base


def test_uptime_states_round_trip_and_survive_reopen(tmp_path):
    path = tmp_path / "u.sqlite3"
    store = IncidentStore(path)
    a, b = "h|uptime_down|a", "h|uptime_down|b"
    store.save_uptime_states([_row(a, up_polls=1), _row(b, flap_outages=2)])
    store.save_uptime_states([_row(a, up_polls=2, absent_polls=1,
                                   last_recovered_at="2026-01-01T00:00:00Z",
                                   flap_msg_at="2026-01-01T01:00:00Z")])
    got = IncidentStore(path).uptime_states()
    assert set(got) == {a, b}
    assert got[a] == _row(a, up_polls=2, absent_polls=1,
                          last_recovered_at="2026-01-01T00:00:00Z",
                          flap_msg_at="2026-01-01T01:00:00Z")
    assert got[b]["flap_outages"] == 2
    assert store.clear_uptime_states([a]) == 1
    assert set(IncidentStore(path).uptime_states()) == {b}


def test_fail_polls_default_and_persist(tmp_path):
    path = tmp_path / "f.sqlite3"
    store = IncidentStore(path)
    assert store.uptime_fail_polls() == 0
    store.set_uptime_fail_polls(2)
    assert IncidentStore(path).uptime_fail_polls() == 2


# ---------------------------------------------------------------- decide()
from heim.incidents.uptime_logic import (  # noqa: E402
    PREFIX,
    UptimeContext,
    decide,
    fingerprint,
)

NOW = "2026-11-01T02:02:00+00:00"
TEN_AGO = "2026-11-01T01:52:00+00:00"
_MAP = {"10.0.0.10": "ubuntu-server", "10.0.0.2": "homelab",
        "10.0.0.4": "heim", "10.0.0.3": "home-assistant"}


def _ctx(**kw):
    base = dict(
        instance_host_map=_MAP, host_names=frozenset(_MAP.values()),
        routing=HostRouting(ssh_hosts=frozenset({"ubuntu-server"}),
                            hypervisor_host="homelab",
                            hypervisor_categories=frozenset({"availability"}),
                            ha_host="home-assistant"),
        kuma_host="home-assistant", timezone="UTC")
    base.update(kw)
    return UptimeContext(**base)


def _mon(name, status, addr="10.0.0.10", type_="http"):
    target = f"http://{addr}:5678" if type_ == "http" else addr
    return Monitor("1", name, type_, target, addr, status)


def _orow(name="n8n", host="ubuntu-server", first=TEN_AGO, times=1, desc=None):
    return {"fingerprint": fingerprint(host, name), "host": host, "metric": name,
            "severity": "critical", "status": "open", "firstSeen": first,
            "lastSeen": first, "resolvedAt": "", "timesSeen": times,
            "missedRuns": 0, "investigated": True,
            "description": desc or f"{PREFIX}{name} (http http://10.0.0.10:5678) is down in Uptime Kuma"}


def _ostate(fp, **kw):
    return {"fingerprint": fp, "up_polls": 0, "absent_polls": 0,
            "last_recovered_at": "", "flap_outages": 0, "flap_msg_at": "", **kw}


def test_first_down_poll_opens_a_critical_incident_and_one_group():
    d = decide([_mon("n8n", 0)], [], {}, 0, NOW, _ctx())
    assert len(d.groups) == 1
    g = d.groups[0]
    assert g.host == "ubuntu-server" and g.investigable
    assert g.headline == "🔴 Down on ubuntu-server: n8n (http://10.0.0.10:5678) · first seen 02:02"
    assert d.rows_to_upsert == [{
        "fingerprint": "ubuntu-server|uptime_down|n8n", "host": "ubuntu-server",
        "metric": "n8n", "severity": "critical", "status": "open",
        "firstSeen": NOW, "lastSeen": NOW, "resolvedAt": "", "timesSeen": 1,
        "missedRuns": 0, "investigated": True,
        "description": "[uptime] n8n (http http://10.0.0.10:5678) is down in Uptime Kuma"}]
    assert g.findings[0]["detail"].startswith("Uptime Kuma check 'n8n' (http http://10.0.0.10:5678) has been failing since 02:02.")
    assert d.loki_events[0]["labels"]["category"] == "availability"


def test_three_down_monitors_on_one_host_are_one_group():
    d = decide([_mon("a", 0), _mon("b", 0), _mon("c", 0)], [], {}, 0, NOW, _ctx())
    assert len(d.groups) == 1 and len(d.groups[0].rows) == 3
    assert len(d.groups[0].findings) == 3
    assert all(n in d.groups[0].headline for n in "abc")


def test_already_open_outage_is_refreshed_not_regrouped():
    d = decide([_mon("n8n", 0)], [_orow(times=4)], {}, 0, NOW, _ctx())
    assert d.groups == []
    assert d.rows_to_upsert[0]["lastSeen"] == NOW
    assert d.rows_to_upsert[0]["timesSeen"] == 5


def test_two_up_polls_resolve_with_one_grouped_recovery():
    fp = fingerprint("ubuntu-server", "n8n")
    d1 = decide([_mon("n8n", 1)], [_orow()], {}, 0, NOW, _ctx())
    assert d1.rows_to_upsert == [] and d1.messages == []
    assert d1.state_writes[0]["up_polls"] == 1
    d2 = decide([_mon("n8n", 1)], [_orow()], {fp: _ostate(fp, up_polls=1)}, 0, NOW, _ctx())
    assert d2.rows_to_upsert[0]["status"] == "resolved"
    assert d2.rows_to_upsert[0]["resolvedAt"] == NOW
    assert d2.messages == ["✅ Back up on ubuntu-server: n8n (down 10 min)"]
    assert d2.state_writes[0]["last_recovered_at"] == NOW


def test_pending_and_maintenance_change_nothing():
    fp = fingerprint("ubuntu-server", "n8n")
    for status in (2, 3):
        d = decide([_mon("n8n", status)], [_orow()], {fp: _ostate(fp, up_polls=1)}, 0, NOW, _ctx())
        assert d.rows_to_upsert == [] and d.messages == [] and d.state_writes == []


def test_missing_for_one_poll_stays_open():
    fp = fingerprint("ubuntu-server", "n8n")
    d = decide([_mon("other", 1)], [_orow()], {}, 0, NOW, _ctx())
    assert d.rows_to_upsert == [] and d.messages == []
    assert [w for w in d.state_writes if w["fingerprint"] == fp][0]["absent_polls"] == 1


def test_missing_for_two_polls_closes_with_the_paused_note():
    fp = fingerprint("ubuntu-server", "n8n")
    d = decide([_mon("other", 1)], [_orow()], {fp: _ostate(fp, absent_polls=1)}, 0, NOW, _ctx())
    assert d.rows_to_upsert[0]["status"] == "resolved"
    assert d.messages == ["⏸ n8n on ubuntu-server is no longer monitored (paused or removed): closing its outage"]
    assert fp in d.state_clears


def test_unmapped_address_is_report_only():
    d = decide([_mon("k8s", 0, addr="10.0.0.24")], [], {}, 0, NOW, _ctx())
    g = d.groups[0]
    assert g.host == "10.0.0.24" and not g.investigable
    assert g.headline.endswith("\n(report only: not a HEIM host)")


def test_heim_is_report_only():
    d = decide([_mon("x", 0, addr="10.0.0.4")], [], {}, 0, NOW, _ctx())
    assert d.groups[0].headline.endswith("\n(report only: no investigation for this host)")


def test_new_downs_join_a_pending_investigation():
    d = decide([_mon("n8n", 0)], [], {}, 0, NOW, _ctx(pending_by_host={"ubuntu-server": 41}))
    g = d.groups[0]
    assert g.pending_investigation_id == 41
    assert g.headline == ("🔴 Also down on ubuntu-server: n8n (http://10.0.0.10:5678)"
                          " · added to pending investigation #41")


def test_unreachable_never_resolves_or_touches_monitor_state():
    d = decide(None, [_orow()], {}, 0, NOW, _ctx())
    assert d.rows_to_upsert == [] and d.state_writes == [] and d.state_clears == []
    assert d.fail_polls == 1 and d.messages == []


def test_second_failed_poll_opens_the_kuma_incident_once():
    d = decide(None, [], {}, 1, NOW, _ctx())
    assert d.fail_polls == 2
    r = d.rows_to_upsert[0]
    assert r["fingerprint"] == "home-assistant|uptime_kuma_up|"
    assert r["severity"] == "warning" and r["investigated"] is False
    assert d.messages == ["⚠️ Can't reach Uptime Kuma: service outages are not being watched."]
    d3 = decide(None, [r], {}, 2, NOW, _ctx())
    assert d3.fail_polls == 3 and d3.messages == [] and d3.rows_to_upsert == []


def test_kuma_back_resolves_its_incident_and_keeps_open_outages_quiet():
    kuma = {"fingerprint": "home-assistant|uptime_kuma_up|", "host": "home-assistant",
            "metric": "Uptime Kuma", "severity": "warning", "status": "open",
            "firstSeen": TEN_AGO, "lastSeen": TEN_AGO, "resolvedAt": "",
            "timesSeen": 1, "missedRuns": 0, "investigated": False,
            "description": f"{PREFIX}Uptime Kuma is unreachable"}
    d = decide([_mon("n8n", 0)], [kuma, _orow()], {}, 3, NOW, _ctx())
    assert d.fail_polls == 0 and d.groups == []
    assert d.messages == ["✅ Uptime Kuma is reachable again: watching service outages."]
    assert [r["status"] for r in d.rows_to_upsert if r["fingerprint"] == kuma["fingerprint"]] == ["resolved"]


def test_suppressed_fingerprints_are_skipped():
    ctx = _ctx(suppressed=frozenset({"ubuntu-server|uptime_down|n8n"}))
    d = decide([_mon("n8n", 0)], [], {}, 0, NOW, ctx)
    assert d.rows_to_upsert == [] and d.groups == [] and d.messages == []


def test_foreign_rows_are_never_touched():
    row = _orow(desc="[alert] n8n is down")
    d = decide([_mon("n8n", 0)], [row], {}, 0, NOW, _ctx())
    assert [r for r in d.rows_to_upsert if r["fingerprint"] == row["fingerprint"]] == []
    assert d.groups == [] and d.messages == []
    d = decide([_mon("n8n", 1)], [row], {}, 0, NOW, _ctx())
    assert d.rows_to_upsert == [] and d.messages == []
    d = decide([_mon("other", 1)], [row], {}, 0, NOW, _ctx())
    assert d.rows_to_upsert == [] and d.messages == []


def test_recoveries_are_listed_in_first_seen_order():
    a, b = "ubuntu-server|uptime_down|a", "ubuntu-server|uptime_down|b"
    rows = [_orow("a", first="2026-11-01T01:57:00+00:00"),
            _orow("b", first="2026-11-01T01:52:00+00:00")]
    sts = {a: _ostate(a, up_polls=1), b: _ostate(b, up_polls=1)}
    d = decide([_mon("a", 1), _mon("b", 1)], rows, sts, 0, NOW, _ctx())
    assert d.messages == ["✅ Back up on ubuntu-server: b (down 10 min), a (down 5 min)"]


def test_pipe_in_a_name_keeps_three_fingerprint_parts():
    assert fingerprint("ubuntu-server", "a|b") == "ubuntu-server|uptime_down|a/b"


# --------------------------------------------------------------- flapping

FLAP_FP = "ubuntu-server|uptime_down|n8n"


def _resolved(first=TEN_AGO):
    return {**_orow(first=first), "status": "resolved",
            "resolvedAt": "2026-11-01T01:42:00+00:00"}


def _ago(minutes):
    from datetime import datetime, timedelta
    return (datetime.fromisoformat(NOW) - timedelta(minutes=minutes)).isoformat()


def test_down_within_an_hour_reopens_quietly_with_one_flap_line():
    st = {FLAP_FP: _ostate(FLAP_FP, last_recovered_at=_ago(20))}
    d = decide([_mon("n8n", 0)], [], st, 0, NOW, _ctx(), recent_rows=[_resolved()])
    assert d.groups == []
    assert len(d.rows_to_upsert) == 1
    row = d.rows_to_upsert[0]
    assert row["status"] == "open" and row["firstSeen"] == TEN_AGO
    assert row["resolvedAt"] == "" and row["investigated"] is True
    assert d.messages == ["🔁 n8n on ubuntu-server keeps flapping (2 outages since 01:52)"]
    w = d.state_writes[0]
    assert w["flap_outages"] == 2 and w["flap_msg_at"] == NOW


def test_flap_lines_are_at_most_hourly():
    st = {FLAP_FP: _ostate(FLAP_FP, last_recovered_at=_ago(5), flap_outages=2,
                           flap_msg_at=_ago(30))}
    d = decide([_mon("n8n", 0)], [], st, 0, NOW, _ctx(), recent_rows=[_resolved()])
    assert d.messages == [] and d.groups == []
    assert d.state_writes[0]["flap_outages"] == 3
    assert d.state_writes[0]["flap_msg_at"] == _ago(30)


def test_recovery_while_flapping_is_silent():
    st = {FLAP_FP: _ostate(FLAP_FP, up_polls=1, flap_outages=3,
                           last_recovered_at=_ago(10))}
    d = decide([_mon("n8n", 1)], [_orow()], st, 0, NOW, _ctx())
    assert d.rows_to_upsert[0]["status"] == "resolved"
    assert d.messages == []
    assert d.state_writes[0]["last_recovered_at"] == NOW


def test_an_hour_up_ends_the_flap_with_one_stable_line():
    st = {FLAP_FP: _ostate(FLAP_FP, flap_outages=3, last_recovered_at=_ago(61))}
    d = decide([_mon("n8n", 1)], [], st, 0, NOW, _ctx())
    assert d.messages == ["✅ n8n on ubuntu-server stable again after 3 outages"]
    assert FLAP_FP in d.state_clears
    assert all(w["fingerprint"] != FLAP_FP for w in d.state_writes)


def test_down_more_than_an_hour_after_recovery_is_a_new_outage():
    st = {FLAP_FP: _ostate(FLAP_FP, last_recovered_at=_ago(61))}
    d = decide([_mon("n8n", 0)], [], st, 0, NOW, _ctx(), recent_rows=[_resolved()])
    assert len(d.groups) == 1 and d.groups[0].host == "ubuntu-server"
    assert d.rows_to_upsert[0]["firstSeen"] == NOW


def test_flap_state_survives_a_restart(tmp_path):
    path = tmp_path / "x.sqlite3"
    st = {FLAP_FP: _ostate(FLAP_FP, last_recovered_at=_ago(20))}
    d1 = decide([_mon("n8n", 0)], [], st, 0, NOW, _ctx(), recent_rows=[_resolved()])
    store = IncidentStore(path)
    store.upsert([{**d1.rows_to_upsert[0], "status": "resolved", "resolvedAt": _ago(2)}])
    store.save_uptime_states([{**d1.state_writes[0], "last_recovered_at": _ago(2)}])
    mem_state = {FLAP_FP: {**d1.state_writes[0], "last_recovered_at": _ago(2)}}
    mem_row = {**d1.rows_to_upsert[0], "status": "resolved", "resolvedAt": _ago(2)}
    store2 = IncidentStore(path)  # restart
    disk = decide([_mon("n8n", 0)], [], store2.uptime_states(), 0, NOW, _ctx(),
                  recent_rows=[store2.incident(FLAP_FP)])
    mem = decide([_mon("n8n", 0)], [], mem_state, 0, NOW, _ctx(), recent_rows=[mem_row])
    assert disk.rows_to_upsert == mem.rows_to_upsert
    assert disk.state_writes == mem.state_writes and disk.messages == mem.messages
    assert disk.state_writes[0]["flap_outages"] == 3 and disk.messages == []
    assert disk.rows_to_upsert[0]["firstSeen"] == TEN_AGO


def test_flapping_then_down_after_an_hour_is_a_clean_new_outage():
    st = {FLAP_FP: _ostate(FLAP_FP, flap_outages=3, last_recovered_at=_ago(70),
                           flap_msg_at=_ago(65))}
    d = decide([_mon("n8n", 0)], [], st, 0, NOW, _ctx(), recent_rows=[_resolved()])
    assert len(d.groups) == 1 and d.messages == []
    w = {x["fingerprint"]: x for x in d.state_writes}[FLAP_FP]
    assert w["flap_outages"] == 0 and w["flap_msg_at"] == ""
    # its recovery now gets the normal line
    st2 = {FLAP_FP: _ostate(FLAP_FP, up_polls=1)}
    r = decide([_mon("n8n", 1)], [_orow(first=NOW)], st2, 0, NOW, _ctx())
    assert r.messages == ["✅ Back up on ubuntu-server: n8n (down 1 min)"]


def test_stale_flap_state_of_a_vanished_monitor_expires():
    others = [_mon("other", 1)]           # a successful poll without n8n
    st = {FLAP_FP: _ostate(FLAP_FP, flap_outages=3, last_recovered_at=_ago(70))}
    d = decide(others, [], st, 0, NOW, _ctx())
    assert FLAP_FP in d.state_clears
    st = {FLAP_FP: _ostate(FLAP_FP, flap_outages=3, last_recovered_at=_ago(20))}
    assert FLAP_FP not in decide(others, [], st, 0, NOW, _ctx()).state_clears


def test_only_resolved_uptime_rows_in_recent_rows_feed_a_reopen():
    st = {FLAP_FP: _ostate(FLAP_FP, last_recovered_at=_ago(20))}
    for bad in ({**_resolved(), "status": "open"},
                {**_resolved(), "description": "[alert] n8n down"}):
        d = decide([_mon("n8n", 0)], [], st, 0, NOW, _ctx(), recent_rows=[bad])
        assert len(d.groups) == 1


# ------------------------------------------- two monitors, one fingerprint

def _web(status, type_="http", mid="1"):
    if type_ == "http":
        return Monitor(mid, "Web", "http", "http://10.0.0.10:80", "10.0.0.10", status)
    return Monitor(mid, "Web", "port", "10.0.0.10:80", "10.0.0.10", status)


def test_same_name_monitors_collapse_to_the_worst_status_with_every_target():
    """Two checks named "Web" on one host share ``host|uptime_down|Web``: the
    pair is ONE monitor, as down as its worst check, naming both targets."""
    d = decide([_web(0), _web(1, "port", "2")], [], {}, 0, NOW, _ctx())
    assert len(d.groups) == 1 and len(d.rows_to_upsert) == 1
    g = d.groups[0]
    assert g.items == "Web (http://10.0.0.10:80, 10.0.0.10:80)"
    assert len(g.findings) == 1
    assert "http://10.0.0.10:80" in g.findings[0]["detail"]
    assert "10.0.0.10:80" in g.findings[0]["detail"].split("http://10.0.0.10:80")[1]


def test_one_same_name_check_up_never_counts_toward_a_resolve():
    fp = fingerprint("ubuntu-server", "Web")
    for order in ([_web(0), _web(1, "port", "2")], [_web(1, "port", "2"), _web(0)]):
        d = decide(order, [_orow("Web")], {fp: _ostate(fp, up_polls=1)}, 0, NOW, _ctx())
        assert d.messages == []
        assert [r["status"] for r in d.rows_to_upsert] == ["open"]
        assert [w["up_polls"] for w in d.state_writes] == [0]


def test_same_name_pending_beats_up_and_both_up_resolves():
    fp = fingerprint("ubuntu-server", "Web")
    d = decide([_web(2), _web(1, "port", "2")], [_orow("Web")],
               {fp: _ostate(fp, up_polls=1)}, 0, NOW, _ctx())
    assert d.rows_to_upsert == [] and d.messages == [] and d.state_writes == []
    d = decide([_web(1), _web(1, "port", "2")], [_orow("Web")],
               {fp: _ostate(fp, up_polls=1)}, 0, NOW, _ctx())
    assert d.messages == ["✅ Back up on ubuntu-server: Web (down 10 min)"]


def test_parse_skips_infinite_and_nan_values():
    text = (
        'monitor_status{monitor_id="1",monitor_name="a",monitor_type="http",'
        'monitor_url="http://10.0.0.10",monitor_hostname="null",monitor_port="null"} +Inf\n'
        'monitor_status{monitor_id="2",monitor_name="b",monitor_type="http",'
        'monitor_url="http://10.0.0.10",monitor_hostname="null",monitor_port="null"} -Inf\n'
        'monitor_status{monitor_id="3",monitor_name="c",monitor_type="http",'
        'monitor_url="http://10.0.0.10",monitor_hostname="null",monitor_port="null"} NaN\n'
        'monitor_status{monitor_id="4",monitor_name="d",monitor_type="http",'
        'monitor_url="http://10.0.0.10",monitor_hostname="null",monitor_port="null"} 1\n'
    )
    assert [m.name for m in parse_metrics(text)] == ["d"]


def test_an_empty_monitor_list_is_a_failed_poll_not_an_empty_one():
    """Defense in depth: a caller handing decide() [] must not close outages."""
    fp = fingerprint("ubuntu-server", "n8n")
    d = decide([], [_orow()], {fp: _ostate(fp, absent_polls=1)}, 0, NOW, _ctx())
    assert d.fail_polls == 1
    assert d.rows_to_upsert == [] and d.messages == []
    assert d.state_writes == [] and d.state_clears == []
    d = decide([], [], {}, 1, NOW, _ctx())
    assert d.messages == ["⚠️ Can't reach Uptime Kuma: service outages are not being watched."]


def test_hypervisor_findings_point_at_the_journal_and_prometheus():
    """The hypervisor brief says the Proxmox API has no process list, so the
    finding must not ask for "which container or process" there."""
    d = decide([_mon("pve-ui", 0, addr="10.0.0.2")], [], {}, 0, NOW, _ctx())
    g = d.groups[0]
    assert g.host == "homelab" and g.investigable
    detail = g.findings[0]["detail"]
    assert detail.startswith("Uptime Kuma check 'pve-ui' (http http://10.0.0.2:5678) "
                             "has been failing since 02:02.")
    assert "/nodes/homelab/journal" in detail and "Prometheus" in detail
    assert "container or process" not in detail
    other = decide([_mon("n8n", 0)], [], {}, 0, NOW, _ctx()).groups[0].findings[0]["detail"]
    assert other == ("Uptime Kuma check 'n8n' (http http://10.0.0.10:5678) has been failing "
                     "since 02:02. Find which container or process on ubuntu-server serves "
                     "http://10.0.0.10:5678, whether it is running, its recent logs, and why "
                     "it stopped.")
