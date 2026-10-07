"""Remediation: propose a fix, optionally run it, then verify it held.

Proposing is always allowed. Running is not: `execute` only accepts a small
allowlist of docker restart/start commands, checks that every service or
container named belongs to the project, never uses a shell, and is refused
unless `remediation.allow_execute` is on.

Verification needs no LLM. After a fix is applied (by the tool or by hand)
the fingerprint is watched: if it recurs, the fix failed; if it stays quiet
for `verify_minutes`, the fix is recorded as the fingerprint's resolution —
so resolution memory fills itself in instead of relying on `agent resolve`.
"""
from __future__ import annotations

import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from systemlens.memory.store import ProjectStore

RECURRENCE_GRACE_SECONDS = 30   # lines already in flight when the fix was applied

_NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
_COMPOSE_RE = re.compile(rf"^docker(?: |-)compose (up -d|restart|start)((?: {_NAME})*)$")
_DOCKER_RE = re.compile(rf"^docker (restart|start) ({_NAME})$")


@dataclass(slots=True)
class Proposal:
    text: str                       # the suggestion as the analysis gave it
    command: Optional[str]          # normalised command line, if one was found
    risk: str                       # "safe" | "review" | "manual"
    reason: str
    argv: Optional[list[str]] = None
    targets: tuple[str, ...] = ()   # services / containers the command names
    kind: str = ""                  # "compose" | "docker"


_COMMAND_START = re.compile(
    r"^(docker|systemctl|kubectl|sudo|rm|chmod|chown|kill|pip|npm|apt|export|echo|cp|mv|mkdir)\b")


def extract_command(text: str) -> Optional[str]:
    """The first thing in the suggestion that looks like a shell command:
    a `backticked` span if there is one, otherwise a line that starts with a
    command. Trailing comments are dropped.
    """
    candidates = re.findall(r"`([^`]+)`", text) + text.replace("`", "").splitlines()
    for candidate in candidates:
        line = candidate.split(" #", 1)[0].strip().lstrip("$ ").strip()
        if _COMMAND_START.match(line):
            return " ".join(line.split())
    return None


def propose(fix_text: str) -> Proposal:
    command = extract_command(fix_text)
    if command is None:
        return Proposal(fix_text, None, "manual", "no runnable command in the suggestion; apply it by hand")
    m = _COMPOSE_RE.match(command)
    if m:
        targets = tuple(m.group(2).split())
        argv = ["docker", "compose", *m.group(1).split(), *targets]
        return Proposal(fix_text, command, "safe", "restarts/starts services of this compose project",
                        argv, targets, "compose")
    m = _DOCKER_RE.match(command)
    if m:
        return Proposal(fix_text, command, "safe", "restarts/starts one container of this project",
                        ["docker", m.group(1), m.group(2)], (m.group(2),), "docker")
    return Proposal(fix_text, command, "review",
                    "not on the allowlist (only docker compose up -d/restart/start and "
                    "docker restart/start can be run for you); review and run it yourself")


def compose_services(compose_file: Optional[Path]) -> set[str]:
    if compose_file is None or not Path(compose_file).is_file():
        return set()
    try:
        data = yaml.safe_load(Path(compose_file).read_text()) or {}
    except yaml.YAMLError:
        return set()
    return set((data.get("services") or {}).keys())


class ExecutionRefused(RuntimeError):
    pass


def execute(proposal: Proposal, *, allow_execute: bool, project_root: Path,
            compose_file: Optional[Path], project_containers: set[str],
            runner=subprocess.run) -> subprocess.CompletedProcess:
    """Run an allowlisted proposal. Raises ExecutionRefused for anything else."""
    if not allow_execute:
        raise ExecutionRefused("execution is off; set remediation.allow_execute: true to enable it")
    if proposal.risk != "safe" or not proposal.argv:
        raise ExecutionRefused(proposal.reason)
    if proposal.kind == "compose":
        services = compose_services(compose_file)
        if not services:
            raise ExecutionRefused("this project has no readable compose file")
        unknown = [t for t in proposal.targets if t not in services]
        if unknown:
            raise ExecutionRefused(f"not services of this project: {', '.join(unknown)}")
    else:
        unknown = [t for t in proposal.targets if t not in project_containers]
        if unknown:
            raise ExecutionRefused(f"not containers of this project: {', '.join(unknown)}")
    return runner(proposal.argv, cwd=str(project_root), capture_output=True, text=True, timeout=180)


@dataclass(slots=True)
class Verification:
    fix_id: int
    fingerprint: str
    status: str        # "verified" | "failed"
    detail: str


def verify_pending(store: ProjectStore, verify_seconds: float, now: Optional[float] = None) -> list[Verification]:
    """Settle every pending fix whose outcome is known. Pure SQLite, no LLM."""
    now = now or time.time()
    out: list[Verification] = []
    for fix in store.fixes("pending"):
        prior = store.get_prior(fix["fingerprint"])
        applied = fix["applied_at"]
        if prior is not None and prior.last_seen > applied + RECURRENCE_GRACE_SECONDS:
            detail = f"recurred {int(prior.last_seen - applied)}s after the fix was applied"
            store.set_fix_status(fix["id"], "failed", detail)
            out.append(Verification(fix["id"], fix["fingerprint"], "failed", detail))
        elif now - applied >= verify_seconds:
            detail = f"no recurrence for {int((now - applied) // 60)} min"
            store.set_fix_status(fix["id"], "verified", detail)
            store.resolve_fingerprint(fix["fingerprint"], fix["command"] or fix["fix_text"])
            out.append(Verification(fix["id"], fix["fingerprint"], "verified", detail))
    return out


def quote(argv: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)
