import shutil
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader

from heim.config import load_config
from heim.incidents.store import IncidentStore
from heim.pipelines.security_audit import (
    AGENT_NAME, ATTACK_TERMS, AUDIT_KIND, build_audit_brief, build_audit_system_prompt,
)
from heim.runtime import Runtime
from heim.security.diff import AuditDiff
from heim.security.types import CheckResult

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def rt(tmp_path):
    croot = tmp_path / "config"
    shutil.copytree(ROOT / "config", croot, ignore=shutil.ignore_patterns("settings.yaml"))
    shutil.copy(croot / "settings.example.yaml", croot / "settings.yaml")
    cfg = load_config(croot)
    return Runtime(config=cfg, store=IncidentStore(tmp_path / "s.sqlite3"), dry_run=True, out_dir=tmp_path / "out")


def test_agent_config_is_loaded_with_the_intended_budget_and_tools(rt):
    a = rt.config.agents[AGENT_NAME]
    assert a.model == "claude-opus-5-5" and a.max_tokens == 16384
    assert a.soft_step_budget == 4 and a.hard_step_cap == 6
    assert set(a.tools) == {"prometheus_query", "discover_metrics", "proxmox_api"}
    assert "ssh_diagnostic" not in a.tools
    assert a.model in rt.config.settings.model_prices          # priced, not an em dash
    assert AUDIT_KIND == "security_audit"


def test_system_prompt_renders_facts_budget_and_output_contract(rt):
    jenv = Environment(loader=FileSystemLoader(rt.config.prompts_dir))
    text = build_audit_system_prompt(rt, jenv)
    assert "## Summary" in text and "~4 tool calls" in text
    assert "ubuntu-server" in text and "heim" in text          # host facts injected
    assert "${" not in text                                    # env expanded
    assert "read-only" in text.lower() and "never change" in text.lower()


def test_brief_carries_table_diff_coverage_and_excerpts(rt):
    jenv = Environment(loader=FileSystemLoader(rt.config.prompts_dir))
    crit = CheckResult("ha.core_update_exposed", "home-assistant", "home-assistant", "fail", "critical", "core outdated and public", detail="2026.9.1 → 2026.9.3", recommendation="update")
    unav = CheckResult("ssh.auth_failures", "ubuntu-server", "-", "unavailable", "warning", "not verified: journal denied", detail="journal denied")
    diff = AuditDiff(new=[crit], resolved=[{"fingerprint": "homelab|pve.repo_risky|pve-test", "metric": "pve.repo_risky", "host": "homelab"}])
    brief = build_audit_brief(rt, jenv, [crit, unav], diff, generated_at="2026-09-28T06:00:00Z")
    assert "1 new" in brief and "1 resolved" in brief
    assert "| critical | home-assistant | ha.core_update_exposed" in brief
    assert "ssh.auth_failures (ubuntu-server/-) — journal denied" in brief
    assert "pve.repo_risky" in brief and "2026.9.3" in brief
    assert brief.rstrip().endswith("'## Summary'.")


def test_prompts_contain_no_attack_vocabulary(rt):
    jenv = Environment(loader=FileSystemLoader(rt.config.prompts_dir))
    system = build_audit_system_prompt(rt, jenv).lower()
    brief = build_audit_brief(rt, jenv, [], AuditDiff(), generated_at="2026-09-28T06:00:00Z").lower()
    for term in ATTACK_TERMS:
        assert term not in system, f"system prompt contains {term!r}"
        assert term not in brief, f"brief contains {term!r}"
    assert set(ATTACK_TERMS) >= {"exploit", "attack", "brute", "penetration", "pentest", "payload", "intrusion", "crack", "bypass"}


def test_auditor_model_has_a_price_in_the_example_settings(rt):
    # an unpriced model shows "no price" on /costs and costs 0 in the run summary
    assert rt.config.agents[AGENT_NAME].model in rt.config.settings.model_prices


def test_system_prompt_requires_the_audit_feedback_section(rt):
    jenv = Environment(loader=FileSystemLoader(rt.config.prompts_dir))
    text = build_audit_system_prompt(rt, jenv)
    assert "'## Audit feedback'" in text
    assert "'### Improve the audit'" in text and "'### What else to check'" in text
    # proposals stay read-only and come after the required sections, before the optional one
    assert "Never propose anything that writes" in text
    out = text[text.index("[OUTPUT]"):]
    assert out.index("'## Confidence'") < out.index("'## Audit feedback'") < out.index("'## Tooling feedback'")
