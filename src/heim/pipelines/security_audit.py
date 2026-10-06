"""The weekly read-only security audit pipeline.

Flow (run_security_audit, Task 11): catalogue → collect evidence (I/O) →
evaluate (pure) → drop suppressed → diff against the previous audit → persist
run + findings → deterministic report → ONE bounded model pass that explains
and prioritises (never detects) → deliver (email, Telegram digest, HA sensor,
Loki). A declined/failed model pass costs the report its '## AI assessment'
appendix and nothing else.

This module holds the prompt builders as well, so the prompt-hygiene test
can render exactly what the model will see.
"""
from __future__ import annotations

from jinja2 import Environment

from heim.config import expand_env
from heim.runtime import Runtime
from heim.security.diff import AuditDiff
from heim.security.report import brief_sections
from heim.security.types import CheckResult

AUDIT_KIND = "security_audit"          # runs.kind · findings.source · investigations.trigger
AGENT_NAME = "security_auditor"        # config/agents/security_auditor.yaml · investigations.agent_name
AUDIT_HOST = "all"                     # investigations.host for the run-level row

#: Words that make a defensive review read like an offensive one to a safety
#: classifier. tests/test_security_prompt.py fails if a rendered prompt
#: contains any of them; keep the templates in the vocabulary of hygiene.
ATTACK_TERMS = ("exploit", "attack", "brute", "penetration", "pentest", "payload", "intrusion", "crack", "bypass")


def build_audit_system_prompt(rt: Runtime, jenv: Environment) -> str:
    cfg = rt.config
    agent = cfg.agents[AGENT_NAME]
    facts = "\n".join(h.facts.strip() for h in sorted(cfg.hosts.values(), key=lambda h: h.name) if h.facts.strip())
    return expand_env(
        jenv.get_template(agent.prompt).render(now=rt.now_iso(), facts=facts,
                                               soft_step_budget=agent.soft_step_budget),
        source=agent.prompt,
    )


def build_audit_brief(rt: Runtime, jenv: Environment, results: list[CheckResult], diff: AuditDiff, *,
                      generated_at: str) -> str:
    sections = brief_sections(results, diff)
    return expand_env(
        jenv.get_template("briefs/security_audit.md.j2").render(
            generated_at=generated_at, n_new=len(diff.new), n_persisting=len(diff.persisting),
            n_resolved=len(diff.resolved), n_carried=len(diff.carried), **sections),
        source="briefs/security_audit.md.j2",
    )
