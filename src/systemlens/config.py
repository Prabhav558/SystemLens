"""Config loading. One YAML file at ~/.systemlens/config.yaml plus a per-project
registry at ~/.systemlens/projects.json (owned by projects/registry.py).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

def default_home() -> Path:
    return Path(os.environ.get("SYSTEMLENS_HOME", "~/.systemlens")).expanduser()


DEFAULT_HOME = default_home()   # kept for importers; prefer default_home()

ProviderName = Literal["ollama", "groq"]


class ProviderConfig(BaseModel):
    provider: ProviderName = "ollama"       # fully local by default, no API key required
    model: str = "llama3.1"
    api_key_env: str = "GROQ_API_KEY"       # unused when provider is ollama
    base_url: Optional[str] = None          # required for ollama; optional override for groq
    max_output_tokens: int = 4096
    # Ceiling on the evidence text sent per analysis (~4 chars per token).
    # Raise it for models with room to spare; it is halved automatically
    # when the provider rejects a request as too large.
    max_evidence_chars: int = 6000
    max_retries: int = 2                    # on rate limits / transient provider errors
    fallback: Optional["ProviderConfig"] = None   # tried when the primary provider keeps failing


class RateLimitConfig(BaseModel):
    cooldown_seconds: int = 1800
    # Floor between two analyses of one fingerprint, even when a container
    # state change bypasses the cooldown — a crash-looping container flips
    # state constantly and would otherwise trigger an analysis per crash.
    min_reanalyze_seconds: int = 120
    max_analyses_per_hour: int = 20
    daily_token_budget: int = 500_000
    reanalyze_on_state_change: bool = True


class CorrelationConfig(BaseModel):
    window_seconds: int = 120
    container_log_lines: int = 50
    log_window_lines: int = 30


class MemoryConfig(BaseModel):
    use_faiss: bool = True
    similar_top_k: int = 3
    # A fingerprint with a stored resolution is answered from memory, with
    # no LLM call. Turn off to re-diagnose recurrences from scratch.
    reuse_resolutions: bool = True


class RetentionConfig(BaseModel):
    days: int = 30                       # incidents/attempts older than this are pruned at startup


class InvestigatorConfig(BaseModel):
    """Follow-up investigation with read-only tools when the first analysis
    is inconclusive. Each investigation costs several extra LLM calls, so
    automatic escalation is opt-in; `agent investigate` always works.
    """
    auto: bool = False
    max_steps: int = 5
    min_confidence: float = 0.5          # escalate below this, or on insufficient_evidence


class RemediationConfig(BaseModel):
    # `agent fix --run` only ever executes allowlisted docker restart/start
    # commands, and only when this is turned on. Proposing is always allowed.
    allow_execute: bool = False
    verify_minutes: int = 15             # no recurrence for this long => fix verified


class NotifyConfig(BaseModel):
    """A target is active when its environment variable is set."""
    slack_webhook_env: str = "SYSTEMLENS_SLACK_WEBHOOK"
    discord_webhook_env: str = "SYSTEMLENS_DISCORD_WEBHOOK"
    webhook_url_env: str = "SYSTEMLENS_WEBHOOK_URL"
    desktop: bool = False
    verdicts: list[str] = Field(default_factory=lambda: ["root_cause_identified", "probable_cause"])
    min_confidence: float = 0.5
    daily_digest_at: Optional[str] = None   # "HH:MM" local time; None = no scheduled digest


class EvalConfig(BaseModel):
    record_bundles: bool = True          # keep the latest evidence bundle per fingerprint


class SinkConfig(BaseModel):
    console: bool = True
    sqlite: bool = True
    http_enabled: bool = False
    http_url: Optional[str] = None
    http_token_env: str = "SYSTEMLENS_HTTP_TOKEN"


class ApiConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8420


class CentralConfig(BaseModel):
    """Config for `agent central serve` — a separate, optional server that
    receives findings pushed by one or more local agents (via sinks.HttpSink)
    and serves the browser dashboard. Distinct from ApiConfig, which is the
    single-machine `agent serve` reading straight from local project SQLite.
    """
    host: str = "127.0.0.1"
    port: int = 8500
    db_path: Optional[Path] = None       # defaults to <home>/central/central.db
    admin_key_env: str = "SYSTEMLENS_CENTRAL_ADMIN_KEY"


class AgentConfig(BaseModel):
    home: Path = Field(default_factory=default_home)
    llm: ProviderConfig = Field(default_factory=ProviderConfig)
    ratelimit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    correlation: CorrelationConfig = Field(default_factory=CorrelationConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    retention: RetentionConfig = Field(default_factory=RetentionConfig)
    investigator: InvestigatorConfig = Field(default_factory=InvestigatorConfig)
    remediation: RemediationConfig = Field(default_factory=RemediationConfig)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)
    eval: EvalConfig = Field(default_factory=EvalConfig)
    sinks: SinkConfig = Field(default_factory=SinkConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    central: CentralConfig = Field(default_factory=CentralConfig)
    docker_socket: Optional[str] = None     # None = let docker-py autodetect
    # Subscribe to Docker events so a crash, OOM kill or failing health check
    # produces a finding even when the container logged nothing.
    docker_events: bool = True

    @field_validator("home", mode="before")
    @classmethod
    def _expand(cls, v):
        return Path(v).expanduser() if v else default_home()

    # ---- paths -----------------------------------------------------
    @property
    def config_path(self) -> Path:
        return self.home / "config.yaml"

    @property
    def projects_path(self) -> Path:
        return self.home / "projects.json"

    def project_dir(self, project_name: str) -> Path:
        d = self.home / "projects" / project_name
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def central_db_path(self) -> Path:
        return self.central.db_path or (self.home / "central" / "central.db")

    # ---- IO ----------------------------------------------------------
    @classmethod
    def load(cls, path: Optional[Path] = None) -> "AgentConfig":
        path = path or default_home() / "config.yaml"
        if not path.exists():
            return cls()
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        return cls.model_validate(data)

    @classmethod
    def unknown_keys(cls, path: Optional[Path] = None) -> list[str]:
        """Keys in config.yaml that no setting matches — almost always a
        typo, and silently ignored otherwise.
        """
        path = path or default_home() / "config.yaml"
        if not path.exists():
            return []
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        return _unknown_keys(data, cls)

    def save(self, path: Optional[Path] = None) -> None:
        path = path or self.config_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.safe_dump(
                self.model_dump(mode="json", exclude_none=True), f, sort_keys=False
            )


def _unknown_keys(data: dict, model: type[BaseModel], prefix: str = "") -> list[str]:
    unknown: list[str] = []
    if not isinstance(data, dict):
        return unknown
    for key, value in data.items():
        field = model.model_fields.get(key)
        if field is None:
            unknown.append(prefix + str(key))
            continue
        nested = field.annotation
        for candidate in getattr(nested, "__args__", ()) or ():
            if isinstance(candidate, type) and issubclass(candidate, BaseModel):
                nested = candidate
        if isinstance(nested, type) and issubclass(nested, BaseModel) and isinstance(value, dict):
            unknown += _unknown_keys(value, nested, f"{prefix}{key}.")
    return unknown
