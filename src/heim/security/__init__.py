"""Weekly security audit — the PURE half (no I/O, fully unit-tested).

catalogue.py  loads config/security/checks.yaml and refuses anything that is
              not a read: SSH lines go through guard_command, HA paths through
              guard_ha_path, PVE paths through PVE_AUDIT_ALLOW (the audit's own
              GET allowlist — wider than the model's proxmox_guard on purpose,
              and never exposed to the model).
evaluate*.py  turn an EvidenceBundle into CheckResults (ok/fail/note/unavailable).
diff.py       week-over-week: new / persisting / resolved / carried.
report.py     the deterministic '## Summary' report, digests, Loki events.

I/O lives in pipelines/security_sources.py (fetch) and pipelines/security_audit.py.
"""
