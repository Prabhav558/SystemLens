"""The one way an evidence bundle becomes a trusted Analysis: ask the
model, then apply the two deterministic checks. The live pipeline, the eval
harness and on-demand commands all go through here, so what is measured is
what runs.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from systemlens.core.grounding import enforce_grounding
from systemlens.core.models import Analysis, EvidenceBundle
from systemlens.llm.base import LLMProvider, sanitize_evidence


@dataclass(slots=True)
class Checked:
    analysis: Analysis
    dropped_evidence: list[str] = field(default_factory=list)
    grounding_notes: list[str] = field(default_factory=list)


def check(analysis: Analysis, bundle: EvidenceBundle, extra_corpus: str = "") -> Checked:
    cleaned, dropped = sanitize_evidence(analysis, bundle.evidence_corpus() + "\n" + extra_corpus)
    cleaned, notes = enforce_grounding(cleaned, bundle)
    return Checked(cleaned, dropped, notes)


async def analyze(llm: LLMProvider, bundle: EvidenceBundle) -> Checked:
    return check(await llm.analyze(bundle), bundle)
