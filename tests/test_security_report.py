from heim.reports.render import salvage, security_audit_email
from heim.security.diff import AuditDiff, finding_rows
from heim.security.report import (
    brief_sections, coverage_gaps, demote_headings, extract_audit_feedback, finding_events, ha_attributes, overall_of,
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
    assert coverage_gaps(RESULTS) == ["ssh.auth_failures (ubuntu-server/-) — journal denied"]
    assert demote_headings("## Summary\ntext\n### Sub\n# Top") == "### Summary\ntext\n#### Sub\n## Top"
    b = brief_sections(RESULTS, DIFF)
    assert set(b) == {"table", "notes", "coverage", "resolved", "excerpts"}
    assert "| critical |" in b["table"] and "root@pam" in b["table"] and "Secure Boot" in b["notes"]
    assert "ssh.auth_failures" in b["coverage"] and "ssh.world_writable" in b["resolved"]


def test_f1_passed_requires_ok_and_no_fail_or_unavailable_rows():
    # pve.vm_config: VM A ok, VM B unavailable — the check id must not be "passed",
    # and VM B's unavailable subject must be listed as a coverage gap.
    rows = [
        res("pve.vm_config", "homelab", "100", status="ok", summary=""),
        res("pve.vm_config", "homelab", "101", status="unavailable", summary="not verified: denied", detail="denied"),
    ]
    md = render_audit_report(rows, AuditDiff(), generated_at=GEN, weeks={})
    assert "pve.vm_config" not in md.split("## Passed checks")[1]
    assert "101" in md.split("## Coverage gaps")[1]


def test_f1_coverage_gaps_distinct_subjects_both_listed():
    rows = [
        res("pve.vm_config", "homelab", "101", status="unavailable", summary="not verified: denied", detail="denied"),
        res("pve.vm_config", "homelab", "102", status="unavailable", summary="not verified: timeout", detail="timeout"),
    ]
    gaps = coverage_gaps(rows)
    assert len(gaps) == 2
    assert any("101" in g for g in gaps)
    assert any("102" in g for g in gaps)


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


def test_f2_security_audit_email_escapes_raw_html_in_finding_text():
    report_md = "## Summary\n\nhello <img src=x onerror=alert(1)> world"
    _, html = security_audit_email(report_md=report_md, incomplete=False, generated_at=GEN,
                                   n_findings=1, n_new=1, n_resolved=0, n_steps=0, input_tokens=0, output_tokens=0)
    assert "&lt;img" in html
    assert "<img src=x" not in html


def _audit_email_html(rows: list[CheckResult]) -> str:
    md = render_audit_report(rows, AuditDiff(new=[r for r in rows if r.status == "fail"]), generated_at=GEN, weeks={})
    _, html = security_audit_email(report_md=md, incomplete=False, generated_at=GEN, n_findings=1, n_new=1,
                                   n_resolved=0, n_steps=0, input_tokens=0, output_tokens=0)
    return html


def test_fr2_evidence_summary_cannot_form_images_or_links_in_the_audit_email():
    evil = "![t](http://x/p.png) [x](javascript:alert(1)) <http://203.0.113.9/>"
    rows = [res("ssh.auth_failures", "ubuntu-server", "u1", summary=evil, detail="d"),
            res("pve.secureboot", "homelab", "sb", status="note", sev="info", summary=evil),
            res("ssh.listening", "ubuntu-server", "-", status="unavailable", summary="not verified", detail=evil)]
    html = _audit_email_html(rows)
    assert "<img src=" not in html and "href=" not in html
    assert "javascript:alert(1)" in html and "http://x/p.png" in html     # text kept, inert


def test_fr2_detail_cannot_close_its_code_fence():
    detail = "line one\n```\n![t](http://x/p.png) after the fence"
    html = _audit_email_html([res("ssh.auth_failures", "ubuntu-server", "u1", summary="s", detail=detail)])
    block = html.split("<pre><code>", 1)[1].split("</code></pre>", 1)[0]
    assert "after the fence" in block and "line one" in block
    assert "<img src=" not in html


def test_fr2_brief_sections_escape_evidence():
    evil = res("ssh.auth_failures", "ubuntu-server", "u1", summary="[x](javascript:alert(1))", detail="![t](http://x/p.png)")
    b = brief_sections([evil], AuditDiff(new=[evil]))
    assert "\\[x\\](javascript" in b["table"]
    assert "```\n![t](http://x/p.png)\n```" in b["excerpts"]          # verbatim, inside a fence
    long = [res("ssh.world_writable", "h", f"/etc/{i}", detail="![t](http://x/p.png) " * 40) for i in range(10)]
    clipped = brief_sections(long, AuditDiff(new=long))["excerpts"]
    assert clipped.count("```") % 2 == 0                               # the clip never leaves a fence open


FEEDBACK_MD = (
    "## Summary\n\nok\n\n## Confidence\n\nhigh\n\n"
    "## Audit feedback\n\n### Improve the audit\n\n- ssh.* — key unreadable — fix ownership\n\n"
    "### What else to check\n\n- PVE token expiry — pve.tfa_missing — /access/users\n\n"
    "## Tooling feedback\n\nproxmox_api: allow /access/tfa\n"
)


def test_audit_feedback_from_the_bare_assessment():
    fb = extract_audit_feedback(FEEDBACK_MD)
    assert fb["improve"] == "- ssh.* — key unreadable — fix ownership"
    assert fb["check"] == "- PVE token expiry — pve.tfa_missing — /access/users"
    assert "Tooling" not in fb["check"] and "proxmox_api" not in fb["check"]  # stops at the next section


def test_audit_feedback_from_the_stored_report_where_it_is_demoted():
    stored = "## Summary\n\ndeterministic\n\n## AI assessment\n\n" + demote_headings(FEEDBACK_MD)
    fb = extract_audit_feedback(stored)
    assert fb["improve"].startswith("- ssh.*") and fb["check"].startswith("- PVE token expiry")


def test_audit_feedback_missing_part_and_absent_section():
    only_improve = "## Audit feedback\n\n### Improve the audit\n\n- a — b — c\n"
    fb = extract_audit_feedback(only_improve)
    assert fb["improve"] == "- a — b — c" and fb["check"] == ""
    assert extract_audit_feedback("## Summary\n\nno feedback here\n") is None
    assert extract_audit_feedback("## Audit feedback\n\n## Tooling feedback\n\nx: y\n") is None
    loose = extract_audit_feedback("## Audit feedback\n\n- unsorted note\n")
    assert loose["other"] == "- unsorted note"
