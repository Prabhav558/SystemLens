"""Causal grounding check, applied to every LLM analysis after
`sanitize_evidence`.

`sanitize_evidence` verifies that quoted evidence is real. It cannot verify
that the *conclusion* follows from it: a model can quote real log lines and
still connect them with an invented story. The observed failure was a
service whose own health endpoint always fails being blamed on an unrelated
database that happened to have exited — a true fact, wrongly used as a cause.

This check is deterministic and needs no cooperation from the model. A
container is *linked* to a signal when it is the signal's origin, the
subject of a scoped candidate (see core/correlate.py), or named in the
triggering record itself. The analysis is downgraded when it:

  1. names an unlinked container as `affected_component`, or
  2. mentions, in `root_cause`, an unlinked container that has a
     co-occurring (unscoped) fact — i.e. it wove that fact into the story.

Only containers that carry an unscoped fact, or signals with a known
origin, can trigger a downgrade, so a correct diagnosis of a plain log file
with no container identity is left alone.
"""
from __future__ import annotations

from typing import Optional

from systemlens.core.correlate import mentions, resolve_origin
from systemlens.core.models import Analysis, ContainerState, EvidenceBundle


def _names(c: ContainerState) -> list[str]:
    return [n for n in (c.name, c.compose_service) if n and len(n) >= 2]


def _resolve(component: str, containers: list[ContainerState]) -> Optional[ContainerState]:
    wanted = component.strip().lower()
    for c in containers:
        if wanted in (n.lower() for n in _names(c)):
            return c
    return None


def enforce_grounding(analysis: Analysis, bundle: EvidenceBundle) -> tuple[Analysis, list[str]]:
    """Returns (possibly downgraded analysis, notes describing each downgrade)."""
    if analysis.verdict == "insufficient_evidence" or not bundle.containers:
        return analysis, []

    origin = resolve_origin(bundle.signal, bundle.containers)
    signal_text = bundle.signal.record.raw.lower()

    linked_ids = {c.meta["container_id"] for c in bundle.candidates
                  if c.scoped and c.meta.get("container_id")}
    if origin is not None:
        linked_ids.add(origin.id)
    unscoped_ids = {c.meta["container_id"] for c in bundle.candidates
                    if not c.scoped and c.meta.get("container_id")}

    def linked(c: ContainerState) -> bool:
        return c.id in linked_ids or mentions(c, signal_text)

    notes: list[str] = []
    verdict, confidence = analysis.verdict, analysis.confidence

    component = _resolve(analysis.affected_component, bundle.containers)
    if (component is not None and not linked(component)
            and (origin is not None or component.id in unscoped_ids)):
        verdict, confidence = "insufficient_evidence", min(confidence, 0.2)
        notes.append(
            f"grounding: '{component.name}' was named as the affected component but has no "
            f"established link to the triggering signal (it is not the signal's origin, not a "
            f"scoped candidate, and not named in the signal)"
        )
    else:
        cause_text = analysis.root_cause.lower()
        woven = [c.name for c in bundle.containers
                 if c.id in unscoped_ids and not linked(c) and mentions(c, cause_text)]
        if woven:
            if verdict == "root_cause_identified":
                verdict = "probable_cause"
            confidence = min(confidence, 0.5)
            notes.append(
                "grounding: the stated root cause relies on " + ", ".join(sorted(woven))
                + ", which only co-occurred with this signal; no link between them was established"
            )

    if not notes:
        return analysis, []
    return analysis.model_copy(update={
        "verdict": verdict,
        "confidence": confidence,
        "unverified_assumptions": analysis.unverified_assumptions + notes,
    }), notes
