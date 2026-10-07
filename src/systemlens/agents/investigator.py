"""Follow-up investigation for inconclusive findings.

The first analysis sees a fixed evidence bundle. When that is not enough,
the investigator lets the model ask for more — a container's state, its
recent logs, the compose file, whether a local port is open — over a few
steps, then produces a new analysis that goes through the same evidence and
grounding checks as any other.

Bounds: every tool is read-only; containers outside the project cannot be
named; port checks are limited to localhost; the number of steps is capped;
each tool result is redacted and clipped.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, Field

from systemlens.core.analysis import Checked, check
from systemlens.core.models import Analysis, EvidenceBundle
from systemlens.llm.prompt import SYSTEM_PROMPT, render_evidence
from systemlens.logs.redact import redact

logger = logging.getLogger("systemlens.investigator")

MAX_RESULT_CHARS = 1500
MAX_COMPOSE_CHARS = 3000

INVESTIGATOR_SYSTEM = """You are investigating a failure in a local Docker Compose \
project. A first analysis was inconclusive. You may gather more evidence with \
read-only tools, one per step:

- container_state: full state of one container (set `container`)
- container_logs: recent log lines of one container (set `container`; optional `grep` \
substring filter)
- compose_file: the project's compose file
- check_port: whether a TCP port on localhost accepts connections (set `port`)
- finish: you have enough, or nothing more would help

Choose the single most informative next action. Do not repeat an action you \
already took. Prefer `finish` over a low-value step. Set unused fields to "" or 0."""

FINAL_ADDENDUM = """

You are now given the original evidence plus the results of an investigation. \
Apply the same rules. Evidence may be quoted from the investigation results too. \
If the investigation did not settle the question, the verdict is still \
"insufficient_evidence"."""


class Step(BaseModel):
    thought: str = Field(description="One sentence: what you want to learn and why.")
    action: Literal["container_state", "container_logs", "compose_file", "check_port", "finish"]
    container: str = ""
    grep: str = ""
    port: int = 0


@dataclass(slots=True)
class Investigation:
    checked: Checked
    steps: list[str] = field(default_factory=list)   # human-readable trail


class InvestigationTools:
    def __init__(self, containers, project: str, compose_file: Optional[Path]):
        self._containers = containers          # a pipeline ContainerSource
        self._project = project
        self._compose_file = compose_file

    async def run(self, step: Step) -> str:
        if step.action == "compose_file":
            return self._compose()
        if step.action == "check_port":
            return await self._check_port(step.port)
        states, _ = await self._containers.containers_for(self._project)
        target = next((c for c in states if step.container in (c.name, c.compose_service)), None)
        if target is None:
            names = ", ".join(sorted(c.name for c in states)) or "(none)"
            return f"no container named '{step.container}' in this project. Available: {names}"
        if step.action == "container_state":
            lines = [f"{target.name} image={target.image} status={target.status} running={target.running}",
                     f"exit_code={target.exit_code} oom_killed={target.oom_killed} "
                     f"restarts={target.restart_count} health={target.health}",
                     f"depends_on={target.depends_on} ports={target.ports} memory_limit={target.memory_limit}"]
            return "\n".join(lines + target.health_log[-3:])
        logs = await self._containers.logs_for(target.id, 200)
        if step.grep:
            needle = step.grep.lower()
            logs = [line for line in logs if needle in line.lower()]
        return "\n".join(redact(line) for line in logs[-40:]) or "(no matching log lines)"

    def _compose(self) -> str:
        if self._compose_file is None or not Path(self._compose_file).is_file():
            return "this project has no compose file on record"
        return redact(Path(self._compose_file).read_text(errors="replace"))[:MAX_COMPOSE_CHARS]

    @staticmethod
    async def _check_port(port: int) -> str:
        if not 1 <= port <= 65535:
            return f"{port} is not a valid port"
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout=2)
            writer.close()
            return f"localhost:{port} accepts connections"
        except (OSError, asyncio.TimeoutError):
            return f"localhost:{port} does not accept connections"


class Investigator:
    def __init__(self, llm, tools: InvestigationTools, max_steps: int = 5):
        self._llm, self._tools, self._max_steps = llm, tools, max_steps

    @staticmethod
    def supported(llm) -> bool:
        return hasattr(llm, "complete_json")

    async def investigate(self, bundle: EvidenceBundle, first: Analysis) -> Investigation:
        evidence = render_evidence(bundle)
        transcript = [
            evidence,
            f"=== FIRST ANALYSIS (inconclusive) ===\nverdict: {first.verdict}\n"
            f"root cause: {first.root_cause}\nopen questions: {first.unverified_assumptions}",
        ]
        trail: list[str] = []
        results: list[str] = []
        seen: set[tuple] = set()
        for i in range(self._max_steps):
            step = await self._llm.complete_json(
                INVESTIGATOR_SYSTEM,
                "\n\n".join(transcript) + f"\n\nStep {i + 1} of {self._max_steps}. Choose the next action.",
                Step)
            key = (step.action, step.container, step.grep, step.port)
            if step.action == "finish" or key in seen:
                break
            seen.add(key)
            result = (await self._tools.run(step))[:MAX_RESULT_CHARS]
            call = f"{step.action}({step.container or step.port or ''}{', grep=' + step.grep if step.grep else ''})"
            trail.append(f"{call} — {step.thought}")
            results.append(result)
            transcript.append(f"=== INVESTIGATION STEP {i + 1}: {call} ===\n{result}")

        if not trail:
            return Investigation(check(first, bundle), trail)
        final = await self._llm.complete_json(SYSTEM_PROMPT + FINAL_ADDENDUM, "\n\n".join(transcript), Analysis)
        checked = check(final, bundle, extra_corpus="\n".join(results))
        checked.analysis = checked.analysis.model_copy(update={
            "unverified_assumptions": checked.analysis.unverified_assumptions
            + [f"investigated with {len(trail)} read-only tool call(s)"]})
        return Investigation(checked, trail)


def needs_investigation(analysis: Analysis, min_confidence: float) -> bool:
    return analysis.verdict == "insufficient_evidence" or analysis.confidence < min_confidence
