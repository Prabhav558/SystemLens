"""Ask: answer a question from stored findings, with citations.

The model only sees findings already produced by the pipeline, each with an
id. Its answer must cite ids; ids that don't exist are dropped, and an
answer with no valid citation is labelled as unsupported rather than shown
as fact.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from pydantic import BaseModel, Field

from systemlens.memory.store import ProjectStore

ASK_SYSTEM = """You answer questions about incidents in a developer's local projects. \
You are given a list of findings, each starting with an id like [error#12]. \
Answer only from those findings. Cite the ids you relied on in `cited`. \
If the findings do not answer the question, say so plainly and cite nothing. \
Do not speculate beyond what the findings state."""

MAX_FINDINGS = 40


class Answer(BaseModel):
    answer: str
    cited: list[str] = Field(default_factory=list, description="Finding ids, e.g. error#12")


@dataclass(slots=True)
class AskResult:
    answer: str
    cited: list[dict] = field(default_factory=list)
    unsupported: bool = False


def collect_findings(stores: dict[str, ProjectStore], since: float) -> dict[str, dict]:
    found: dict[str, dict] = {}
    for project, store in stores.items():
        for row in store.recent_incidents(since=since, limit=MAX_FINDINGS):
            found[f"{project}#{row['id']}"] = {"project": project, **dict(row)}
    newest = sorted(found.items(), key=lambda kv: kv[1]["created_at"], reverse=True)[:MAX_FINDINGS]
    return dict(newest)


def render_findings(findings: dict[str, dict]) -> str:
    lines = []
    for fid, f in findings.items():
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(f["created_at"]))
        lines.append(
            f"[{fid}] {when} project={f['project']} component={f['affected_component']} "
            f"verdict={f['verdict']} confidence={f['confidence']}\n"
            f"    cause: {f['root_cause']}\n    fix: {f['fix_suggestion']}")
    return "\n".join(lines)


async def ask(llm, question: str, findings: dict[str, dict]) -> AskResult:
    if not findings:
        return AskResult("There are no findings in that time range to answer from.", unsupported=True)
    reply = await llm.complete_json(
        ASK_SYSTEM, f"FINDINGS:\n{render_findings(findings)}\n\nQUESTION: {question}", Answer)
    refs = [c.strip("[] ") for c in reply.cited]
    cited = [{**findings[ref], "id": ref} for ref in dict.fromkeys(refs) if ref in findings]
    return AskResult(reply.answer.strip(), cited, unsupported=not cited)
