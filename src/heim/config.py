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

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator, model_validator

from heim.incidents.types import HostRouting


log = logging.getLogger(__name__)

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


_WEEKDAYS_CRON = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def parse_weekly(spec: str) -> tuple[str, int, int]:
    """``"mon 06:00"`` → ``("mon", 6, 0)`` — the weekly cron slot format.

    APScheduler's ``day_of_week`` takes the same three-letter names, so the
    daemon passes the parts straight through. Anything else raises ValueError
    naming the value, so a typo in settings fails at load, not next Monday.
    """
    parts = str(spec or "").strip().lower().split()
    if len(parts) != 2 or parts[0] not in _WEEKDAYS_CRON:
        raise ValueError(f"weekly schedule must be '<mon..sun> HH:MM', got {spec!r}")
    hh, sep, mm = parts[1].partition(":")
    if not sep or not hh.isdigit() or not mm.isdigit() or ":" in mm:
        raise ValueError(f"weekly schedule must be '<mon..sun> HH:MM', got {spec!r}")
    hour, minute = int(hh), int(mm)
    if not (0 <= hour < 24 and 0 <= minute < 60):
        raise ValueError(f"weekly schedule time out of range in {spec!r}")
    return parts[0], hour, minute


class SchedulesCfg(BaseModel):
    daily: list[str] = ["07:00", "22:00"]  # HH:MM in the configured timezone
    poll_minutes: int = 5
    #: Weekly read-only security audit slot, "<mon..sun> HH:MM" in the
    #: configured timezone. "" disables the job. Monday morning by default:
    #: Sunday is maintenance night (PVE stop-mode backups, HEIM's own backup).
    security_audit: str = "mon 06:00"

    @field_validator("security_audit")
    @classmethod
    def _valid_weekly(cls, v: str) -> str:
        if v:
            parse_weekly(v)
        return v


def _timeout_s(hours: float) -> float | None:
    """Hours -> seconds, with ``<= 0`` meaning *wait indefinitely* (None).

    One definition of "no timeout", shared by the Telegram wait and the store
    poll, so the two halves of an approval cannot disagree about when it dies.
    """
    return None if not hours or float(hours) <= 0 else float(hours) * 3600


class ApprovalsCfg(BaseModel):
    require: bool = True
    #: 0 = wait until the operator reacts. The default, deliberately: an
    #: approval that expires silently discards the investigation and
    #: re-proposes the incident later, which is worse than a prompt that waits.
    approve_timeout_hours: float = 0.0
    #: An unanswered *outcome* prompt is benign — the investigation is already
    #: delivered — so this one keeps a real default. 0 waits indefinitely too.
    outcome_timeout_hours: float = 8.0

    @property
    def approve_timeout_s(self) -> float | None:
        return _timeout_s(self.approve_timeout_hours)

    @property
    def outcome_timeout_s(self) -> float | None:
        return _timeout_s(self.outcome_timeout_hours)


class UptimeKumaCfg(BaseModel):
    """Uptime Kuma as an alert source. Empty ``url`` = off. The API key is the
    ``UPTIME_KUMA`` env var, never config.

    ``url`` defaults to ``HEIM_UPTIME_KUMA_URL``, read when the settings are
    built (``load_config`` loads ``.env`` first), so a deployment whose own
    gitignored ``settings.yaml`` predates the feature still picks it up from
    ``.env``. An explicit ``uptime_kuma.url`` in the YAML wins."""
    url: str = Field(default_factory=lambda: os.environ.get("HEIM_UPTIME_KUMA_URL", ""))


class GitHubCfg(BaseModel):
    """Tooling feedback → GitHub issues (spec 2026-11-08). Empty ``repo`` = off.

    Two tokens, never in config: ``HEIM_GITHUB_READ_TOKEN`` (Issues: read) is
    the agents' ``github_issues`` tool, so the agent stays read-only by
    privilege; ``HEIM_GITHUB_TOKEN`` (Issues: read & write) is only the
    daemon's outbox poster. ``repo`` ("owner/name") defaults to
    ``HEIM_GITHUB_REPO``, read when the settings are built."""
    repo: str = Field(default_factory=lambda: os.environ.get("HEIM_GITHUB_REPO", ""))

    @staticmethod
    def read_token() -> str:
        return os.environ.get("HEIM_GITHUB_READ_TOKEN", "")

    @staticmethod
    def write_token() -> str:
        return os.environ.get("HEIM_GITHUB_TOKEN", "")

    @property
    def can_read(self) -> bool:
        return bool(self.repo and self.read_token())

    @property
    def can_write(self) -> bool:
        return bool(self.repo and self.write_token())


class ModelRef(BaseModel):
    """One model in a provider chain.

    ``openrouter`` and ``openai_compat`` speak the same OpenAI-compatible chat
    API; ``openrouter`` is the named shortcut (its URL + ``OPENROUTER_API_KEY``),
    ``openai_compat`` is any other such server — e.g. a LAN llama.cpp — at
    ``base_url``, authenticated only when ``api_key_env`` names a variable.
    """
    provider: Literal["anthropic", "openrouter", "openai_compat"] = "anthropic"
    model: str
    base_url: str = ""
    api_key_env: str = ""
    #: HTTP timeout for one completion. A LAN model on an iGPU (llama-server in
    #: CT 111 reads ~70 tokens/s, writes ~7) needs far more than a cloud API.
    timeout_s: float = 180.0
    #: Extra top-level fields for an OpenAI-compatible request, e.g.
    #: ``{"chat_template_kwargs": {"enable_thinking": false}}`` for Qwen3.
    extra_body: dict = {}

    @model_validator(mode="after")
    def _compat_needs_url(self) -> "ModelRef":
        if self.provider == "openai_compat" and not self.base_url.strip():
            raise ValueError("an openai_compat model needs a base_url")
        return self

    @property
    def key(self) -> str:
        """Stable identity: what the dashboard posts and the allow-list matches."""
        k = f"{self.provider}|{self.model}"
        return f"{k}|{self.base_url}" if self.base_url else k

    @property
    def label(self) -> str:
        return self.model

    @classmethod
    def from_key(cls, key: str) -> "ModelRef":
        """Inverse of ``key``; a bare model id (no ``|``) means Anthropic.
        ``api_key_env`` is not part of a key — look the full entry up in an
        allow-list when it matters."""
        if "|" not in key:
            return cls(model=key)
        provider, _, rest = key.partition("|")
        model, _, base_url = rest.partition("|")
        return cls(provider=provider, model=model, base_url=base_url)


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
    # Exact model ids offered in the dashboard's investigate dropdown and to
    # `heim investigate --model` (design spec §5.1). Empty = default only: no
    # select is rendered and every run uses the investigator agent's own model.
    # Anything listed here should also have a `model_prices` entry, or its runs
    # render an em dash instead of a cost.
    # Since 2026-11-04 entries are ModelRefs, so OpenRouter / llama.cpp models
    # can be offered; a plain string still means an Anthropic model id.
    investigator_models: list[ModelRef] = []
    # The models the dashboard may put in the daily analyst's chain (spec
    # 2026-11-04). Empty = the chain is shown read-only and only YAML sets it.
    # Each entry should also have a `model_prices` row, or its runs render "—".
    analyst_models: list[ModelRef] = []

    @field_validator("investigator_models", mode="before")
    @classmethod
    def _plain_ids_are_anthropic(cls, v):
        if isinstance(v, list):
            return [{"provider": "anthropic", "model": e} if isinstance(e, str) else e
                    for e in v]
        return v
    # instance-label address prefix -> host name (used by the alert poller to
    # attribute a firing alert's `instance` label to a configured host)
    instance_host_map: dict[str, str] = {}

    @field_validator("instance_host_map")
    @classmethod
    def _drop_unset_addresses(cls, v: dict[str, str]) -> dict[str, str]:
        # An unset optional address (`${HEIM_LLM_IP:-}`) yields an empty key,
        # and the poller matches by prefix: '' would claim every alert.
        return {k.strip(): h for k, h in v.items() if k and k.strip()}

    #: Display order for host badge colors, which are handed out by position.
    #: APPEND new hosts; inserting one repaints every host after it. Hosts left
    #: out follow in config order (alphabetical by filename).
    host_color_order: list[str] = []
    # Open incidents from metric thresholds (config/queries/daily.yaml
    # warn/crit), not just from the Prometheus alert rules. Evaluated on the
    # poller's cadence, inside the same cycle.
    threshold_detection: bool = True
    # Which flag counts as "over threshold": `crit` only, or `warn` (which
    # includes crit — warn is the weaker of the two bounds).
    threshold_severity: Literal["crit", "warn"] = "crit"
    # Consecutive polls a series must stay over threshold before an incident
    # opens. Hysteresis is not optional: a single scrape at 102% is a blip,
    # and dispatching on it burns an agent run and a human approval.
    threshold_consecutive: int = 2
    # a factory, not a shared instance: the url's env default must be read
    # when Settings is built (after .env is loaded), not at import time
    uptime_kuma: UptimeKumaCfg = Field(default_factory=UptimeKumaCfg)
    # Tooling feedback → GitHub issues (spec 2026-11-08); off without a repo
    github: GitHubCfg = Field(default_factory=GitHubCfg)


# --------------------------------------------------------------------------- hosts


class SshCfg(BaseModel):
    host: str
    port: int = 22
    user: str
    key_path: str  # expanded at use; override with env HEIM_SSH_KEY

    def resolved_key_path(self) -> str:
        return os.path.expanduser(os.environ.get("HEIM_SSH_KEY", self.key_path))

    def connect_kwargs(self) -> dict:
        """``asyncssh.connect`` arguments — every SSH connection HEIM opens.

        Everything comes from this config; nothing is read from ``$HOME``.
        asyncssh otherwise probes ``~/.ssh/config``, ``~/.ssh/ca-bundle.crt``
        and ``~/.ssh/crt`` on every connect, and the ``crt`` probe is a
        ``Path.is_dir()`` that RAISES on EACCES: in the container the process
        drops from root to uid 1000 with ``HOME`` still ``/root``, so every
        connection failed with "Permission denied: '/root/.ssh/crt'" before
        the key was ever read.
        """
        return {
            "host": self.host, "port": self.port, "username": self.user,
            "client_keys": [self.resolved_key_path()], "known_hosts": None,
            "config": None, "x509_trusted_certs": None, "x509_trusted_cert_paths": None,
        }


class ApiCfg(BaseModel):
    url: str
    verify_ssl: bool = True


class Host(BaseModel):
    name: str
    role: Literal["guest", "hypervisor", "ha-guest"]
    vmid: int | None = None  # Proxmox VM id, display only (hosts page)
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


class AgentCfg(BaseModel):
    name: str
    model: str                         # the model id at ``provider``
    # Which API runs the tool loop (spec 2026-11-04-investigator-openrouter):
    # the Anthropic-native loop, or the OpenAI-compatible one for openrouter /
    # openai_compat (same fields and meaning as ``ModelRef``).
    provider: Literal["anthropic", "openrouter", "openai_compat"] = "anthropic"
    base_url: str = ""
    api_key_env: str = ""
    max_tokens: int = 4096
    soft_step_budget: int = 15         # told to the model in the prompt
    hard_step_cap: int = 25            # loop refuses tools beyond this
    prompt: str = ""                   # template filename under prompts/
    tools: list[str] = []
    temperature: float | None = None

    @property
    def ref(self) -> ModelRef:
        return ModelRef(provider=self.provider, model=self.model,
                        base_url=self.base_url, api_key_env=self.api_key_env)

    def with_ref(self, ref: ModelRef) -> "AgentCfg":
        """A copy that runs on ``ref`` (provider, model, url and key)."""
        return self.model_copy(update={"provider": ref.provider, "model": ref.model,
                                       "base_url": ref.base_url,
                                       "api_key_env": ref.api_key_env})


class AnalystCfg(BaseModel):
    """The daily analyst: one completion, no tools, an ordered model chain.

    ``chain`` is tried in order until one entry answers usably (spec
    2026-11-04). The n8n-era ``primary`` / ``fallback`` pair still loads, as
    the chain ``[primary, fallback]``; giving both forms is an error.
    """
    name: str = "daily_analyst"
    chain: list[ModelRef] = []
    primary: ModelRef | None = None
    fallback: ModelRef | None = None
    max_tokens: int = 4096
    prompt: str = "analyst.md"

    @field_validator("chain", mode="before")
    @classmethod
    def _drop_unset_local_models(cls, v):
        # `base_url: ${HEIM_LLAMACPP_URL:-}` left unset means "no local model
        # here", not a config error that stops the daemon.
        if isinstance(v, list):
            return [e for e in v if not (isinstance(e, dict)
                                         and e.get("provider") == "openai_compat"
                                         and not str(e.get("base_url") or "").strip())]
        return v

    @model_validator(mode="after")
    def _build_chain(self) -> "AnalystCfg":
        if self.chain and (self.primary or self.fallback):
            raise ValueError("give the analyst either `chain` or `primary`/`fallback`, not both")
        if not self.chain:
            if self.primary is None:
                raise ValueError("the analyst needs a non-empty `chain`")
            self.chain = [self.primary] + ([self.fallback] if self.fallback else [])
        return self


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
    #: config/security/checks.yaml — the weekly audit's sources, checks and allowlists
    security_checks_path: Path | None = None

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

    # settings.yaml is gitignored (it is a deployment's own file), so a fresh
    # clone has only the example. The example is fully ${VAR}-interpolated and
    # is meant to be usable UNCHANGED — so fall back to it rather than
    # crash-looping a container on first run. Deployment identity still comes
    # from .env, and a missing required var still fails loudly and by name.
    settings_path = root / "settings.yaml"
    if not settings_path.exists():
        example_path = root / "settings.example.yaml"
        if not example_path.exists():
            raise FileNotFoundError(
                f"{settings_path} missing, and no {example_path.name} to fall back to — "
                f"is {root} really the config directory?"
            )
        log.info("%s not found; using %s (copy it to settings.yaml to customise)",
                 settings_path.name, example_path.name)
        settings_path = example_path
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
        security_checks_path=root / "security" / "checks.yaml",
    )


def env(name: str, *, required: bool = False, default: str | None = None) -> str | None:
    val = os.environ.get(name, default)
    if required and not val:
        raise RuntimeError(f"required environment variable {name} is not set (see .env.example)")
    return val
