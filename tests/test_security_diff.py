from heim.incidents.store import IncidentStore
from heim.security.diff import diff_findings, finding_rows
from heim.security.types import CheckResult


def fr(check, subject, host="ubuntu-server", sev="warning"):
    return CheckResult(check, host, subject, "fail", sev, f"{check} {subject}", "d", "r")


def prev(check, subject, host="ubuntu-server", sev="warning", trend="new"):
    return {"host": host, "metric": check, "severity": sev, "trend": trend, "summary": "s", "detail": "d",
            "recommendation": "r", "fingerprint": f"{host}|{check}|{subject}"}


def test_diff_new_persisting_resolved():
    cur = [fr("ssh.world_writable", "/etc/a"), fr("ssh.world_writable", "/etc/b")]
    old = [prev("ssh.world_writable", "/etc/a"), prev("ssh.world_writable", "/etc/z")]
    d = diff_findings(cur, old, set())
    assert [r.subject for r in d.new] == ["/etc/b"]
    assert [r.subject for r in d.persisting] == ["/etc/a"]
    assert [r["fingerprint"] for r in d.resolved] == ["ubuntu-server|ssh.world_writable|/etc/z"]
    assert d.carried == []


def test_unavailable_check_carries_last_weeks_findings_instead_of_resolving_them():
    old = [prev("ssh.auth_failures", "ubuntu-server"), prev("pve.tfa_missing", "root@pam", host="homelab")]
    d = diff_findings([fr("pve.tfa_missing", "root@pam", host="homelab")], old, {"ssh.auth_failures"})
    assert d.resolved == []
    assert [c["fingerprint"] for c in d.carried] == ["ubuntu-server|ssh.auth_failures|ubuntu-server"]
    rows = finding_rows(d)
    trends = {r["fingerprint"]: r["trend"] for r in rows}
    assert trends["homelab|pve.tfa_missing|root@pam"] == "persisting"
    assert trends["ubuntu-server|ssh.auth_failures|ubuntu-server"] == "carried"
    carried = [r for r in rows if r["trend"] == "carried"][0]
    assert "not re-verified" in carried["detail"]


def test_first_run_everything_is_new():
    d = diff_findings([fr("a.b", "x")], [], set())
    assert len(d.new) == 1 and not d.persisting and not d.resolved


def test_store_reads(tmp_path):
    s = IncidentStore(tmp_path / "t.sqlite3")
    r1 = s.insert_run(kind="security_audit", run_at="2026-09-21T06:00:00")
    s.insert_findings(r1, "2026-09-21T06:00:00", "security_audit",
                      [{"host": "h", "metric": "m", "severity": "warning", "trend": "new", "summary": "s", "detail": "d", "recommendation": "r"}],
                      ["h|m|x"])
    r2 = s.insert_run(kind="security_audit", run_at="2026-09-28T06:00:00")
    s.insert_findings(r2, "2026-09-28T06:00:00", "security_audit",
                      [{"host": "h", "metric": "m", "severity": "warning", "trend": "persisting", "summary": "s", "detail": "d", "recommendation": "r"}],
                      ["h|m|x"])
    rows = s.findings_for_run(r2)
    assert len(rows) == 1 and rows[0]["fingerprint"] == "h|m|x" and rows[0]["trend"] == "persisting"
    assert s.finding_run_count("h|m|x", "security_audit") == 2
    assert s.finding_run_count("h|m|x", "daily") == 0
    assert s.runs(limit=1, kind="security_audit")[0]["id"] == r2
