from heim.reports.render import salvage, security_audit_email
from heim.security.diff import AuditDiff, finding_rows
from heim.security.report import (
    brief_sections, coverage_gaps, demote_headings, finding_events, ha_attributes, overall_of,
    render_audit_report, telegram_digest,
)
from heim.security.types import CheckResult

GEN = "2026-09-28T06:00:00.000+02:00"


def res(check, host, subject, status="fail", sev="warning", summary="x", detail="dd"):
    return CheckResult(check, host, subject, status, sev, summary, detail=detail, recommendation="rr")


CRIT = res("ha.core_update_exposed", "home-assistant", "home-assistant", sev="critical", summary="core outdated and public")
WARN = res("pve.tfa_missing", "homelab", "root@pam", summary="root without TFA")
NOTE = res("pve.secureboot", "homelab", "secureboot", status="note", sev="info", summary="Secure Boot off")
UNAV = res("ssh.auth_failures", "ubuntu-server", "-", status="unavailable", summary="not verified: journal denied", detail="journal denied")
OKR = res("prom.time_sync", "heim", "heim", status="ok", summary="")
RESULTS = [CRIT, WARN, NOTE, UNAV, OKR]
DIFF = AuditDiff(new=[CRIT], persisting=[WARN],
                 resolved=[{"fingerprint": "ubuntu-server|ssh.world_writable|/etc/x", "metric": "ssh.world_writable", "host": "ubuntu-server", "severity": "warning"}],
                 carried=[{"fingerprint": "ubuntu-server|ssh.auth_failures|ubuntu-server", "metric": "ssh.auth_failures",
                           "host": "ubuntu-server", "severity": "warning", "summary": "137 failed", "detail": "old", "recommendation": "r"}])


def test_report_contract_and_sections():
    md = render_audit_report(RESULTS, DIFF, generated_at=GEN, weeks={WARN.fingerprint: 3})
    assert md.startswith("## Summary")
    assert not salvage(md, "").incomplete
    for h in ("## Findings", "## Resolved since the previous audit", "## Details and recommendations", "## Notes", "## Coverage gaps", "## Passed checks"):
        assert h in md, h
    assert "critical" in md and "root@pam" in md and "3w" in md and "carried" in md
    assert "ssh.world_writable" in md.split("## Resolved")[1]
    assert "journal denied" in md.split("## Coverage gaps")[1]
    assert "prom.time_sync" in md.split("## Passed checks")[1]
    assert md.index("core outdated") < md.index("root without TFA")     # critical first


def test_report_with_nothing_found():
    md = render_audit_report([OKR], AuditDiff(), generated_at=GEN, weeks={})
    assert md.startswith("## Summary") and "No findings" in md


def test_coverage_and_demote_and_brief():
    assert coverage_gaps(RESULTS) == ["ssh.auth_failures — journal denied"]
    assert demote_headings("## Summary\ntext\n### Sub\n# Top") == "### Summary\ntext\n#### Sub\n## Top"
    b = brief_sections(RESULTS, DIFF)
    assert set(b) == {"table", "notes", "coverage", "resolved", "excerpts"}
    assert "| critical |" in b["table"] and "root@pam" in b["table"] and "Secure Boot" in b["notes"]
    assert "ssh.auth_failures" in b["coverage"] and "ssh.world_writable" in b["resolved"]


def test_digest_is_bounded_and_mentions_assessment_state():
    d = telegram_digest(DIFF, RESULTS, generated_at=GEN, assessment="complete", reason="")
    assert d.startswith("🛡️") and "1 new" in d and "1 resolved" in d and "1 critical" in d and len(d) <= 3500
    d2 = telegram_digest(DIFF, RESULTS, generated_at=GEN, assessment="incomplete", reason="the model declined the request")
    assert "⚠️ AI assessment unavailable" in d2 and "declined" in d2
    big = AuditDiff(new=[res("ssh.world_writable", "ubuntu-server", f"/etc/{i}", summary="w" * 200) for i in range(60)])
    assert len(telegram_digest(big, [], generated_at=GEN, assessment="skipped", reason="")) <= 3500


def test_ha_attributes_and_loki_events_and_overall():
    state, attrs = ha_attributes(DIFF, RESULTS, generated_at=GEN, report_md="## Summary\n\nx")
    assert state == "1 new · 1 persisting · 1 resolved · 1 carried"
    assert attrs["critical"] == 1 and attrs["warning"] == 1 and attrs["friendly_name"] == "PAM Weekly Security Audit"
    assert attrs["report"].startswith("## Summary")
    rows = finding_rows(DIFF)
    evs = finding_events(rows)
    assert len(evs) == 3 and {e["event"] for e in evs} == {"finding"}
    assert {e["labels"]["category"] for e in evs} == {"security"}
    assert {e["labels"]["severity"] for e in evs} == {"crit", "warn"}
    assert all(e["fields"]["source"] == "security_audit" and e["fields"]["fingerprint"] for e in evs)
    assert overall_of(rows) == "critical" and overall_of([]) == "ok"


def test_security_audit_email_subject_and_body():
    subject, html = security_audit_email(report_md="## Summary\n\nhello", incomplete=False, generated_at=GEN,
                                         n_findings=2, n_new=1, n_resolved=1, n_steps=2, input_tokens=1234, output_tokens=56)
    assert subject.startswith("🛡️ Weekly Security Audit — 2 findings, 1 new, 1 resolved — 2026-09-28")
    assert "hello" in html and "1,234" in html
    subject2, _ = security_audit_email(report_md="## Summary\n\nx", incomplete=True, generated_at=GEN,
                                       n_findings=1, n_new=0, n_resolved=0, n_steps=0, input_tokens=0, output_tokens=0)
    assert subject2.endswith("(AI assessment unavailable)") and "1 finding," in subject2
