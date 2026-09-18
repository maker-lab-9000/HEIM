"""Configuration loading for PAM.

Everything declarative lives under ``config/``:

- ``settings.yaml``       — deployment-specific endpoints, schedules, recipients
- ``hosts/*.yaml``        — one file per monitored host (role, ssh/api access, prompt facts)
- ``tools/*.yaml``        — one file per agent tool (LLM-facing description, arg schema, options)
- ``agents/*.yaml``       — one file per agent (model, budget, tool list, prompt template)
- ``queries/daily.yaml``  — the daily PromQL catalog
- ``prompts/``            — jinja2 prompt templates

Secrets never live in YAML — they come from the environment (see ``.env.example``).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

from heim.incidents.types import HostRouting


# --------------------------------------------------------------------------- settings


class PrometheusCfg(BaseModel):
    url: str


class LokiCfg(BaseModel):
    url: str


class TelegramCfg(BaseModel):
    chat_id: int


class EmailCfg(BaseModel):
    to: str
    from_addr: str = Field(alias="from")
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 465

    model_config = {"populate_by_name": True}


class HomeAssistantCfg(BaseModel):
    url: str


class SchedulesCfg(BaseModel):
    daily: list[str] = ["07:00", "22:00"]  # HH:MM in the configured timezone
    poll_minutes: int = 5


class ApprovalsCfg(BaseModel):
    require: bool = True
    approve_timeout_hours: float = 6.0
    outcome_timeout_hours: float = 8.0


class Settings(BaseModel):
    prometheus: PrometheusCfg
    loki: LokiCfg | None = None
    telegram: TelegramCfg | None = None
    email: EmailCfg | None = None
    home_assistant: HomeAssistantCfg | None = None
    schedules: SchedulesCfg = SchedulesCfg()
    approvals: ApprovalsCfg = ApprovalsCfg()
    timezone: str = "Europe/Berlin"
    db_path: str = "heim.sqlite3"
    audit_log: str = "audit.jsonl"
    # Upper bound on investigations running their agent phase at once (the
    # approval wait does NOT occupy a slot). Guards the token budget against a
    # pathological run dispatching many agents simultaneously.
    max_concurrent_investigations: int = 2
    # Default mute window applied when a finding is marked a false positive
    # (roadmap §5.4) — 0 means forever. Overridable per call (`--days`).
    suppression_days: int = 90
    # Dead-man's switch (roadmap §5.7): a healthchecks.io-style URL the daemon
    # GETs after every completed poll cycle. Empty disables it.
    deadman_url: str = ""
    # Nightly SQLite backups: how many daily snapshots to keep in
    # <db_path dir>/backups (0 disables pruning, the backup itself always runs).
    backup_keep: int = 14
    # Retention: how long resolved/finished history is kept before the nightly
    # prune deletes it. 0 = keep forever.
    retention_days: int = 120
    # Cost accounting (roadmap §5.6): model id -> {input, output} price per
    # MILLION tokens, in `currency`. Keys must match the model ids used in
    # config/agents/*.yaml. A model with no entry here is simply not priced —
    # its cost is stored as 0 and rendered as an em dash, never guessed.
    model_prices: dict[str, dict] = {}
    # The currency `model_prices` is quoted in. Rendered as "$" for USD and as
    # the bare code otherwise ("EUR 0.42") — no conversion ever happens.
    currency: str = "USD"
    # Store the agent's full message transcript with each investigation
    # (roadmap §5.6). Off by default: it is large, and only needed when
    # post-morteming a wrong root cause. Capped at 512 KB per investigation.
    store_transcripts: bool = False
    # instance-label address prefix -> host name (used by the alert poller to
    # attribute a firing alert's `instance` label to a configured host)
    instance_host_map: dict[str, str] = {}


# --------------------------------------------------------------------------- hosts


class SshCfg(BaseModel):
    host: str
    port: int = 22
    user: str
    key_path: str  # expanded at use; override with env HEIM_SSH_KEY

    def resolved_key_path(self) -> str:
        return os.path.expanduser(os.environ.get("HEIM_SSH_KEY", self.key_path))


class ApiCfg(BaseModel):
    url: str
    verify_ssl: bool = True


class Host(BaseModel):
    name: str
    role: Literal["guest", "hypervisor", "ha-guest"]
    # 'all' or a list of investigable categories (cpu, memory, disk, diskHealth,
    # temperature, network, container, ...)
    investigable: str | list[str] = "all"
    ssh: SshCfg | None = None
    api: ApiCfg | None = None
    facts: str = ""       # injected into the investigator prompt's [FACTS] block
    privileges: str = ""  # injected into the [PRIVILEGES] block (ssh hosts only)


# --------------------------------------------------------------------------- tools & agents


class ToolCfg(BaseModel):
    name: str
    description: str          # shown to the LLM verbatim
    module: str               # "heim.tools.ssh_diagnostic:SshDiagnosticTool"
    args: dict = {}           # JSON-schema `properties` for the tool input
    required: list[str] = []
    options: dict = {}        # tool-specific knobs (host binding, clip bytes, ...)

    def input_schema(self) -> dict:
        return {"type": "object", "properties": self.args, "required": self.required}


class ModelRef(BaseModel):
    provider: Literal["anthropic", "openrouter"] = "anthropic"
    model: str


class AgentCfg(BaseModel):
    name: str
    model: str                         # anthropic model id (the agent loop is Anthropic-native)
    max_tokens: int = 4096
    soft_step_budget: int = 15         # told to the model in the prompt
    hard_step_cap: int = 25            # loop refuses tools beyond this
    prompt: str = ""                   # template filename under prompts/
    tools: list[str] = []
    temperature: float | None = None


class AnalystCfg(BaseModel):
    name: str = "daily_analyst"
    primary: ModelRef
    fallback: ModelRef | None = None
    max_tokens: int = 4096
    prompt: str = "analyst.md"


# --------------------------------------------------------------------------- loader


@dataclass
class Config:
    root: Path
    settings: Settings
    hosts: dict[str, Host]
    tools: dict[str, ToolCfg]
    agents: dict[str, AgentCfg]
    analyst: AnalystCfg | None
    prompts_dir: Path
    queries_path: Path

    def routing(self) -> HostRouting:
        """Derive incident/investigation routing from the host files."""
        ssh_hosts: set[str] = set()
        hypervisor: str | None = None
        hyper_cats: set[str] = set()
        ha_host: str | None = None
        for h in self.hosts.values():
            if h.role == "guest" and h.ssh is not None:
                ssh_hosts.add(h.name)
            elif h.role == "hypervisor":
                hypervisor = h.name
                if isinstance(h.investigable, list):
                    hyper_cats = set(h.investigable)
            elif h.role == "ha-guest":
                ha_host = h.name
        return HostRouting(
            ssh_hosts=frozenset(ssh_hosts),
            hypervisor_host=hypervisor,
            hypervisor_categories=frozenset(hyper_cats),
            ha_host=ha_host,
        )


def config_root() -> Path:
    env = os.environ.get("HEIM_CONFIG")
    if env:
        return Path(env).expanduser()
    return Path.cwd() / "config"


_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def expand_env(text: str, *, source: str = "") -> str:
    """Expand ``${VAR}`` / ``${VAR:-default}`` from the environment.

    Applied to every YAML under config/ (pre-parse, so types still work) and
    to rendered prompt templates — deployment identity (IPs, SSH user, chat
    id, recipients) lives in .env, the committed config stays generic.
    A reference without a default that is unset (or empty) raises, naming the
    variable and the file — fail fast beats a silently empty URL.
    """
    def repl(m: re.Match) -> str:
        name, default = m.group(1), m.group(2)
        val = os.environ.get(name)
        if val:
            return val
        if default is not None:
            return default
        where = f" (referenced in {source})" if source else ""
        raise RuntimeError(f"${{{name}}} is not set{where} — add it to .env (see .env.example)")

    return _ENV_REF.sub(repl, text)


def _load_yaml(path: Path) -> dict:
    with open(path) as fh:
        return yaml.safe_load(expand_env(fh.read(), source=str(path))) or {}


def load_config(root: Path | None = None) -> Config:
    root = root or config_root()
    if not root.is_dir():
        raise FileNotFoundError(f"config directory not found: {root} (set HEIM_CONFIG or run from the repo root)")

    load_dotenv(root.parent / ".env")

    settings_path = root / "settings.yaml"
    if not settings_path.exists():
        raise FileNotFoundError(
            f"{settings_path} missing — copy config/settings.example.yaml to config/settings.yaml and edit it"
        )
    settings = Settings(**_load_yaml(settings_path))

    hosts = {h.name: h for h in (Host(**_load_yaml(p)) for p in sorted((root / "hosts").glob("*.yaml")))}
    tools = {t.name: t for t in (ToolCfg(**_load_yaml(p)) for p in sorted((root / "tools").glob("*.yaml")))}

    agents: dict[str, AgentCfg] = {}
    analyst: AnalystCfg | None = None
    for p in sorted((root / "agents").glob("*.yaml")):
        data = _load_yaml(p)
        if data.get("kind") == "analyst":
            data.pop("kind", None)
            analyst = AnalystCfg(**data)
        else:
            data.pop("kind", None)
            a = AgentCfg(**data)
            agents[a.name] = a

    return Config(
        root=root,
        settings=settings,
        hosts=hosts,
        tools=tools,
        agents=agents,
        analyst=analyst,
        prompts_dir=root / "prompts",
        queries_path=root / "queries" / "daily.yaml",
    )


def env(name: str, *, required: bool = False, default: str | None = None) -> str | None:
    val = os.environ.get(name, default)
    if required and not val:
        raise RuntimeError(f"required environment variable {name} is not set (see .env.example)")
    return val
