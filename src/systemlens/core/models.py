"""Shared vocabulary for the whole pipeline.

Everything that crosses a module boundary is defined here so no layer has to
import another layer's internals.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class Severity(IntEnum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

    @classmethod
    def parse(cls, token: str) -> "Severity":
        t = token.strip().upper()
        return {
            "TRACE": cls.DEBUG, "DEBUG": cls.DEBUG, "DBG": cls.DEBUG,
            "INFO": cls.INFO, "INFORMATION": cls.INFO, "NOTICE": cls.INFO,
            "WARN": cls.WARNING, "WARNING": cls.WARNING,
            "ERR": cls.ERROR, "ERROR": cls.ERROR, "SEVERE": cls.ERROR,
            "CRIT": cls.CRITICAL, "CRITICAL": cls.CRITICAL,
            "FATAL": cls.CRITICAL, "PANIC": cls.CRITICAL, "EMERG": cls.CRITICAL,
        }.get(t, cls.INFO)


@dataclass(slots=True)
class LogRecord:
    """One logical log event. May span many physical lines (stack traces)."""
    project: str
    source: str                 # file path or "container:<name>"
    raw: str
    ts: float                   # wall clock we observed it
    event_ts: Optional[float] = None   # timestamp parsed out of the line, if any
    severity: Severity = Severity.INFO
    lines: int = 1
    container: Optional[str] = None      # container that emitted it, when known
    category_hint: Optional[str] = None  # set by non-log sources (Docker events)

    @property
    def when(self) -> float:
        return self.event_ts if self.event_ts is not None else self.ts

    @property
    def first_line(self) -> str:
        return self.raw.split("\n", 1)[0]


@dataclass(slots=True)
class Signal:
    """A LogRecord that survived filtering, with a stable identity."""
    record: LogRecord
    template: str               # variable-masked form of the message
    fingerprint: str            # sha1 of (project, template)
    category: str               # connection_refused | timeout | oom | traceback | generic ...
    hints: dict[str, Any] = field(default_factory=dict)  # host, port, service, exc type

    @property
    def project(self) -> str:
        return self.record.project

    @property
    def severity(self) -> Severity:
        return self.record.severity


def make_fingerprint(project: str, template: str) -> str:
    return hashlib.sha1(f"{project}\x00{template}".encode("utf-8", "replace")).hexdigest()[:16]


# ---------------------------------------------------------------- containers

@dataclass(slots=True)
class ContainerState:
    id: str
    name: str
    image: str
    status: str                 # running | exited | restarting | created | paused | dead
    running: bool
    exit_code: Optional[int]
    started_at: Optional[float]
    finished_at: Optional[float]
    oom_killed: bool
    restart_count: int
    health: Optional[str]                  # healthy | unhealthy | starting | None
    health_log: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    ports: dict[str, list[str]] = field(default_factory=dict)
    networks: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    compose_project: Optional[str] = None
    compose_service: Optional[str] = None
    depends_on: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    memory_limit: Optional[int] = None

    def age_of_death(self, now: Optional[float] = None) -> Optional[float]:
        if self.finished_at is None or self.running:
            return None
        return (now or time.time()) - self.finished_at


# ---------------------------------------------------------------- correlation

@dataclass(slots=True)
class CandidateCause:
    rule_id: str
    component: str
    summary: str
    confidence: float           # 0..1, deterministic — set by the rule, not the LLM
    evidence: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    # False = a true container fact with no established link to the signal
    # (not its origin, its connection target, or a dependency of either).
    scoped: bool = True


@dataclass(slots=True)
class PriorIncident:
    fingerprint: str
    first_seen: float
    last_seen: float
    occurrences: int
    resolution: Optional[str] = None
    resolved_at: Optional[float] = None


@dataclass(slots=True)
class EvidenceBundle:
    """Everything the LLM is allowed to see. Assembled deterministically."""
    project: str
    signal: Signal
    occurrences: int
    log_window: list[LogRecord] = field(default_factory=list)
    containers: list[ContainerState] = field(default_factory=list)
    container_logs: dict[str, list[str]] = field(default_factory=dict)
    candidates: list[CandidateCause] = field(default_factory=list)
    prior: Optional[PriorIncident] = None
    similar: list[PriorIncident] = field(default_factory=list)
    docker_available: bool = True
    mapping_confidence: str = "high"     # high | low | none
    created_at: float = field(default_factory=time.time)
    max_evidence_chars: Optional[int] = None   # prompt budget; None = renderer default

    def evidence_corpus(self) -> str:
        """Every string the LLM may legitimately quote. Used to reject fabrication."""
        parts = [self.signal.record.raw]
        parts += [r.raw for r in self.log_window]
        for lines in self.container_logs.values():
            parts += lines
        for c in self.containers:
            parts.append(
                f"{c.name} {c.image} status={c.status} exit_code={c.exit_code} "
                f"health={c.health} oom_killed={c.oom_killed} restarts={c.restart_count}"
            )
            parts += c.health_log
        for cand in self.candidates:
            parts.append(cand.summary)
            parts += cand.evidence
        if self.prior and self.prior.resolution:
            parts.append(self.prior.resolution)
        return "\n".join(parts)


# ---------------------------------------------------------------- LLM output

Verdict = Literal["root_cause_identified", "probable_cause", "insufficient_evidence"]


class Analysis(BaseModel):
    """Constrained LLM output. `insufficient_evidence` is a correct answer."""
    verdict: Verdict
    root_cause: str = Field(description="One or two sentences. What actually broke and why.")
    affected_component: str = Field(description="Container, service or module name.")
    evidence: list[str] = Field(
        default_factory=list,
        description="Verbatim excerpts from the provided evidence. Never invent these.",
    )
    fix_suggestion: str = Field(description="Concrete action, ideally a command.")
    confidence: float = Field(ge=0.0, le=1.0)
    unverified_assumptions: list[str] = Field(default_factory=list)


@dataclass(slots=True)
class Finding:
    """An Analysis bound to the incident that produced it."""
    project: str
    fingerprint: str
    analysis: Analysis
    bundle: EvidenceBundle
    provider: str
    model: str
    created_at: float = field(default_factory=time.time)
    dropped_evidence: list[str] = field(default_factory=list)  # fabrications we stripped

    @property
    def severity(self) -> Severity:
        return self.bundle.signal.severity
