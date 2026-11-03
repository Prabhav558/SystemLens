"""The one way an evidence bundle becomes a trusted Analysis: ask the
model, then apply the two deterministic checks. The live pipeline, the eval
harness and on-demand commands all go through here, so what is measured is
what runs.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from systemlens.agents import remediation
from systemlens.core.grounding import enforce_grounding
from systemlens.core.models import Analysis, EvidenceBundle
from systemlens.llm.base import LLMProvider, sanitize_evidence


@dataclass(slots=True)
class Checked:
    analysis: Analysis
    dropped_evidence: list[str] = field(default_factory=list)
    grounding_notes: list[str] = field(default_factory=list)


def check_fix(analysis: Analysis, bundle: EvidenceBundle) -> Analysis:
    """Make a suggested `docker compose ...` command usable: translate a
    container name to its compose service, and flag a service that does not
    exist in this project, so a wrong command is not shown as plain advice.
    """
    if not bundle.containers:
        return analysis                      # no container list: nothing to check against
    proposal = remediation.propose(analysis.fix_suggestion)
    if proposal.kind != "compose" or not proposal.targets:
        return analysis
    services = {c.compose_service for c in bundle.containers if c.compose_service}
    local = remediation.localize(proposal, {c.name: c.compose_service or c.name for c in bundle.containers})
    fix = analysis.fix_suggestion
    original = remediation.extract_command(fix)
    if local.command != proposal.command and original and original in fix:
        fix = fix.replace(original, local.command, 1)
    unknown = [t for t in local.targets if t not in services]
    notes = list(analysis.unverified_assumptions)
    for name in unknown:
        fix += f"  [warning: '{name}' is not a service of this project]"
        notes.append(f"the suggested command names '{name}', which matches no service in this project")
    if fix == analysis.fix_suggestion and not unknown:
        return analysis
    return analysis.model_copy(update={"fix_suggestion": fix, "unverified_assumptions": notes})


def check(analysis: Analysis, bundle: EvidenceBundle, extra_corpus: str = "") -> Checked:
    cleaned, dropped = sanitize_evidence(analysis, bundle.evidence_corpus() + "\n" + extra_corpus)
    cleaned, notes = enforce_grounding(cleaned, bundle)
    return Checked(check_fix(cleaned, bundle), dropped, notes)


async def analyze(llm: LLMProvider, bundle: EvidenceBundle) -> Checked:
    return check(await llm.analyze(bundle), bundle)
