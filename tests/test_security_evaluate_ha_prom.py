from datetime import datetime, timezone
from pathlib import Path

from heim.security.catalogue import load_catalogue
from heim.security.evaluate import EvalContext, evaluate
from heim.security.types import Evidence, EvidenceBundle

CAT = load_catalogue(Path(__file__).resolve().parent.parent / "config" / "security" / "checks.yaml")
NOW = datetime(2026, 9, 28, 6, 0, tzinfo=timezone.utc)
CTX = dict(now=NOW, instance_host_map={"10.0.0.2": "homelab", "10.0.0.10": "ubuntu-server", "10.0.0.4": "heim"},
           hosts=("heim", "home-assistant", "homelab", "ubuntu-server"))


def rows_for(check_id, *items):
    b = EvidenceBundle(items={e.key: e for e in items})
    return [r for r in evaluate(CAT, b, EvalContext(**CTX)) if r.check_id == check_id]


def upd(eid, on=True, title="", installed="1", latest="2"):
    return {"entity_id": eid, "state": "on" if on else "off",
            "attributes": {"title": title, "installed_version": installed, "latest_version": latest}}


STATES = [
    upd("update.home_assistant_core_update", title="Home Assistant Core", installed="2026.9.1", latest="2026.9.3"),
    upd("update.vaultwarden_update", title="Vaultwarden"),
    upd("update.spotify_connect_update", title="Spotify Connect"),
    upd("update.grafana_update", on=False, title="Grafana"),
    {"entity_id": "sensor.proxmox_web_api_certificate_expiry", "state": "423", "attributes": {}},
    {"entity_id": "sensor.n8n_certificate_expiry", "state": "unknown", "attributes": {}},
    {"entity_id": "sensor.loki_certificate_expiry", "state": "unavailable", "attributes": {}},
    {"entity_id": "sensor.jellyfin_certificate_expiry", "state": "9", "attributes": {}},
    {"entity_id": "persistent_notification.http_login", "state": "notifying",
     "attributes": {"title": "Login attempt failed", "message": "Login attempt or request with invalid authentication from 203.0.113.9"}},
]
PUBLIC_CFG = {"version": "2026.9.1", "safe_mode": False, "recovery_mode": False,
              "external_url": "https://myhome.example-dyndns.net:8123", "allowlist_external_dirs": ["/media", "/config/www", "/backup"]}


def test_ha_sensitive_updates_and_other_count():
    sens = rows_for("ha.pending_updates_sensitive", Evidence("ha.states", "ok", body=STATES))
    assert {r.subject for r in sens if r.status == "fail"} == {"update.home_assistant_core_update", "update.vaultwarden_update"}
    assert all(r.host == "home-assistant" for r in sens)
    other = rows_for("ha.pending_updates_other", Evidence("ha.states", "ok", body=STATES))
    assert other[0].status == "note" and "1 " in other[0].summary


def test_ha_core_update_exposed_is_critical_only_when_public_and_pending():
    hit = rows_for("ha.core_update_exposed", Evidence("ha.states", "ok", body=STATES), Evidence("ha.config", "ok", body=PUBLIC_CFG))
    assert hit[0].status == "fail" and hit[0].severity == "critical" and "2026.9.3" in hit[0].summary
    lan = dict(PUBLIC_CFG, external_url="http://192.168.1.5:8123")
    assert rows_for("ha.core_update_exposed", Evidence("ha.states", "ok", body=STATES), Evidence("ha.config", "ok", body=lan))[0].status == "ok"
    patched = [s for s in STATES if s["entity_id"] != "update.home_assistant_core_update"]
    assert rows_for("ha.core_update_exposed", Evidence("ha.states", "ok", body=patched), Evidence("ha.config", "ok", body=PUBLIC_CFG))[0].status == "ok"


def test_ha_config_checks():
    cfg = Evidence("ha.config", "ok", body=PUBLIC_CFG)
    assert rows_for("ha.external_url", cfg)[0].status == "note"
    assert rows_for("ha.safe_mode", cfg)[0].status == "ok"
    assert rows_for("ha.safe_mode", Evidence("ha.config", "ok", body=dict(PUBLIC_CFG, safe_mode=True)))[0].status == "fail"
    dirs = rows_for("ha.external_dirs", cfg)
    assert dirs[0].status == "note" and "/backup" in dirs[0].summary


def test_ha_cert_sensors_and_login_notifications():
    rows = rows_for("ha.cert_expiry", Evidence("ha.states", "ok", body=STATES))
    by = {r.subject: r for r in rows}
    assert by["sensor.proxmox_web_api_certificate_expiry"].status == "ok"
    assert by["sensor.jellyfin_certificate_expiry"].severity == "critical"
    assert by["unpopulated"].status == "note" and "2 of 4" in by["unpopulated"].summary
    login = rows_for("ha.login_notifications", Evidence("ha.states", "ok", body=STATES))
    assert login[0].status == "fail" and login[0].subject == "persistent_notification.http_login"


def vec(*samples):
    return [{"metric": m, "value": [1.0, str(v)]} for m, v in samples]


def test_prom_reboot_failed_units_time_sync_targets():
    rr = rows_for("prom.reboot_required", Evidence("prom.reboot_required", "ok", body=vec(({"instance": "10.0.0.10:9100"}, 1), ({"instance": "10.0.0.4:9100"}, 0))))
    assert {r.host: r.status for r in rr} == {"ubuntu-server": "fail", "heim": "ok"}
    fu = rows_for("prom.failed_units", Evidence("prom.failed_units", "ok", body=vec(({"instance": "10.0.0.2:9100", "name": "openipmi.service"}, 1))))
    assert fu[0].status == "fail" and fu[0].fingerprint == "homelab|prom.failed_units|openipmi.service"
    ts = rows_for("prom.time_sync", Evidence("prom.timex", "ok", body=vec(({"instance": "10.0.0.2:9100"}, 0))))
    assert ts[0].status == "fail"
    up = rows_for("prom.targets_down", Evidence("prom.up", "ok", body=vec(({"job": "cadvisor", "instance": "10.0.0.10:8081"}, 0), ({"job": "home-assistant", "instance": "x"}, 1))))
    assert {r.subject: r.status for r in up} == {"cadvisor": "fail", "home-assistant": "ok"}


def test_prom_apt_pending_and_collector_gap():
    rows = rows_for("prom.apt_pending",
                    Evidence("prom.apt_pending", "ok", body=vec(({"instance": "10.0.0.2:9100"}, 281))),
                    Evidence("prom.apt_present", "ok", body=vec(({"instance": "10.0.0.2:9100"}, 1), ({"instance": "10.0.0.10:9100"}, 1), ({"instance": "10.0.0.4:9100"}, 1))))
    by = {(r.host, r.status) for r in rows}
    assert ("homelab", "fail") in by and ("ubuntu-server", "note") in by and ("heim", "note") in by


def test_prom_os_eol():
    body = vec(({"instance": "10.0.0.10:9100", "id": "ubuntu", "version_id": "24.04", "pretty_name": "Ubuntu 24.04.4 LTS"}, 1),
               ({"instance": "10.0.0.4:9100", "id": "debian", "version_id": "13", "pretty_name": "Debian GNU/Linux 13"}, 1),
               ({"instance": "10.0.0.2:9100", "id": "gentoo", "version_id": "", "pretty_name": "Gentoo"}, 1))
    rows = rows_for("prom.os_eol", Evidence("prom.os_info", "ok", body=body))
    by = {r.host: r for r in rows}
    assert by["ubuntu-server"].status == "ok" and by["heim"].status == "ok"
    assert by["homelab"].status == "note" and "no EOL entry" in by["homelab"].summary


# ---------------------------------------------------------------------------
# R5 deviations from the brief (see task-5-report.md): the brief's code turns
# several "could not verify" cases into a silent `ok`. These tests pin down
# the fixed behaviour.

def test_ha_empty_states_is_unavailable_not_ok():
    # /api/states on a live HA instance always returns hundreds of entities;
    # an empty (but "ok"/"empty") list must not read as "nothing pending".
    empty = Evidence("ha.states", "ok", body=[])
    for check_id in ("ha.pending_updates_sensitive", "ha.pending_updates_other", "ha.cert_expiry", "ha.login_notifications"):
        rows = rows_for(check_id, empty)
        assert rows[0].status == "unavailable", check_id
    # core_update_exposed needs both sources; states-empty must still gate it.
    rows = rows_for("ha.core_update_exposed", empty, Evidence("ha.config", "ok", body=PUBLIC_CFG))
    assert rows[0].status == "unavailable"


def test_ha_empty_config_is_unavailable_not_ok():
    empty = Evidence("ha.config", "ok", body={})
    for check_id in ("ha.external_url", "ha.safe_mode", "ha.external_dirs"):
        rows = rows_for(check_id, empty)
        assert rows[0].status == "unavailable", check_id
    rows = rows_for("ha.core_update_exposed", Evidence("ha.states", "ok", body=STATES), empty)
    assert rows[0].status == "unavailable"


def test_ha_malformed_body_type_becomes_unavailable_via_dispatcher():
    # A wrong-shaped body (string instead of list/dict) must raise inside
    # the evaluator so evaluate()'s per-check try/except records
    # `unavailable`, not silently coerce to an empty collection.
    rows = rows_for("ha.pending_updates_sensitive", Evidence("ha.states", "ok", body="not-a-list"))
    assert rows[0].status == "unavailable"
    rows = rows_for("ha.safe_mode", Evidence("ha.config", "ok", body="not-a-dict"))
    assert rows[0].status == "unavailable"


def test_prom_failed_units_empty_vector_is_unavailable_not_ok():
    # node_systemd_unit_state{state="failed"}==1 is a sparse metric: an
    # empty vector means either "nothing failed" or "nothing was scraped at
    # all" — indistinguishable here, so it must not resolve to `ok`.
    rows = rows_for("prom.failed_units", Evidence("prom.failed_units", "ok", body=[]))
    assert rows[0].status == "unavailable"


def test_prom_malformed_vector_body_becomes_unavailable_via_dispatcher():
    rows = rows_for("prom.time_sync", Evidence("prom.timex", "ok", body={"not": "a-list"}))
    assert rows[0].status == "unavailable"
