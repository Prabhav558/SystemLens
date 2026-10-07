"""Accuracy evaluation: replay recorded evidence bundles against an answer
key and score the result.

Two layers are scored separately, because they fail differently:

- the **correlator** (deterministic, no LLM): are the right containers
  linked to the signal, and the wrong ones left out?
- the **analysis** (LLM + the evidence and grounding checks): is the right
  component named, with an acceptable verdict, without blaming something it
  must not?

A suite is a YAML file:

    name: my-project
    cases:
      - id: db-down
        bundle: bundles/3ce83d45168f0c6b.json
        expect:
          component: [db, myproject-db-1]        # any of these is correct
          verdict: [root_cause_identified, probable_cause]
          must_not_blame: [cache]                # neither named nor woven into the cause
          cause_mentions_any: [exited, down]
          linked: [db]                           # correlator: must be scoped
          not_linked: [redis]                    # correlator: must not be scoped
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from systemlens.core import analysis as analysis_step
from systemlens.core.bundle_io import load_recording
from systemlens.core.correlate import correlate
from systemlens.core.models import Analysis, EvidenceBundle


@dataclass(slots=True)
class CaseResult:
    case_id: str
    correlator_failures: list[str] = field(default_factory=list)
    analysis_failures: list[str] = field(default_factory=list)
    analysis: Optional[Analysis] = None
    error: Optional[str] = None

    @property
    def correlator_ok(self) -> bool:
        return not self.correlator_failures

    @property
    def analysis_ok(self) -> bool:
        return self.analysis is not None and not self.analysis_failures and self.error is None


@dataclass(slots=True)
class Report:
    name: str
    results: list[CaseResult]
    with_llm: bool

    def rate(self, attr: str) -> float:
        return sum(getattr(r, attr) for r in self.results) / len(self.results) if self.results else 0.0

    def to_dict(self) -> dict:
        return {
            "suite": self.name, "cases": len(self.results),
            "correlator_pass_rate": round(self.rate("correlator_ok"), 3),
            "analysis_pass_rate": round(self.rate("analysis_ok"), 3) if self.with_llm else None,
            "results": [{
                "id": r.case_id, "correlator_ok": r.correlator_ok,
                "correlator_failures": r.correlator_failures,
                "analysis_ok": r.analysis_ok if self.with_llm else None,
                "analysis_failures": r.analysis_failures, "error": r.error,
                "answer": {"verdict": r.analysis.verdict, "component": r.analysis.affected_component,
                           "root_cause": r.analysis.root_cause} if r.analysis else None,
            } for r in self.results],
        }


def _same(a: str, b: str) -> bool:
    return a.strip().lower() == b.strip().lower()


def _word_in(name: str, text: str) -> bool:
    return re.search(rf"(?<![\w-]){re.escape(name.lower())}(?![\w-])", text.lower()) is not None


def _container_names(bundle: EvidenceBundle, container_id: str) -> set[str]:
    for c in bundle.containers:
        if c.id == container_id:
            return {n.lower() for n in (c.name, c.compose_service) if n}
    return set()


def score_correlator(bundle: EvidenceBundle, expect: dict, window_seconds: int = 120) -> list[str]:
    candidates = correlate(bundle, window_seconds)
    scoped: set[str] = set()
    for cand in candidates:
        if cand.scoped and cand.meta.get("container_id"):
            scoped |= _container_names(bundle, cand.meta["container_id"])
    failures = []
    for name in expect.get("linked", []):
        if name.lower() not in scoped:
            failures.append(f"'{name}' should be linked to the signal but is not")
    for name in expect.get("not_linked", []):
        if name.lower() in scoped:
            failures.append(f"'{name}' is linked to the signal but should not be")
    return failures


def score_analysis(analysis: Analysis, expect: dict) -> list[str]:
    failures = []
    components = expect.get("component")
    if components and not any(_same(analysis.affected_component, c) for c in components):
        failures.append(f"component '{analysis.affected_component}' not in {components}")
    verdicts = expect.get("verdict")
    if verdicts and analysis.verdict not in verdicts:
        failures.append(f"verdict '{analysis.verdict}' not in {verdicts}")
    for name in expect.get("must_not_blame", []):
        if _same(analysis.affected_component, name):
            failures.append(f"blamed '{name}'")
        elif analysis.verdict != "insufficient_evidence" and _word_in(name, analysis.root_cause):
            failures.append(f"root cause leans on '{name}'")
    keywords = expect.get("cause_mentions_any")
    if keywords and analysis.verdict != "insufficient_evidence" \
            and not any(k.lower() in analysis.root_cause.lower() for k in keywords):
        failures.append(f"root cause mentions none of {keywords}")
    return failures


def load_suite(path: Path) -> tuple[str, list[dict]]:
    data = yaml.safe_load(path.read_text()) or {}
    cases = data.get("cases") or []
    for case in cases:
        if "id" not in case or "bundle" not in case:
            raise ValueError(f"every case needs `id` and `bundle`: {case}")
    return data.get("name", path.parent.name), cases


async def run_suite(path: Path, llm=None, window_seconds: int = 120) -> Report:
    name, cases = load_suite(path)
    results = []
    for case in cases:
        expect = case.get("expect") or {}
        result = CaseResult(case["id"])
        try:
            bundle, _ = load_recording((path.parent / case["bundle"]).resolve())
        except (OSError, KeyError, ValueError) as e:
            result.error = f"cannot load bundle: {e}"
            result.correlator_failures.append(result.error)
            results.append(result)
            continue
        result.correlator_failures = score_correlator(bundle, expect, window_seconds)
        if llm is not None:
            # score what the current code would send, not what was recorded
            bundle.candidates = correlate(bundle, window_seconds)
            try:
                checked = await analysis_step.analyze(llm, bundle)
                result.analysis = checked.analysis
                result.analysis_failures = score_analysis(checked.analysis, expect)
            except Exception as e:  # noqa: BLE001 - one failing case must not end the run
                result.error = f"{type(e).__name__}: {str(e).splitlines()[0][:200]}"
        results.append(result)
    return Report(name, results, with_llm=llm is not None)


def init_suite(bundle_dir: Path, out_dir: Path, name: str) -> Path:
    """Copy a project's recorded bundles into a new suite with blank
    expectations to fill in. The recorded answer is included as a comment,
    as a starting point — it is what the model said, not the truth.
    """
    recordings = sorted(bundle_dir.glob("*.json"))
    if not recordings:
        raise FileNotFoundError(f"no recorded bundles in {bundle_dir}")
    (out_dir / "bundles").mkdir(parents=True, exist_ok=True)
    lines = [f"name: {name}", "cases:"]
    for rec in recordings:
        (out_dir / "bundles" / rec.name).write_text(rec.read_text())
        bundle, answer = load_recording(rec)
        lines += [
            f"  - id: {bundle.signal.category}-{rec.stem[:8]}",
            f"    bundle: bundles/{rec.name}",
            f"    # signal: {bundle.signal.record.first_line[:100]}",
            f"    # recorded answer: {(answer or {}).get('affected_component')} / {(answer or {}).get('verdict')}",
            "    expect:",
            "      component: []          # correct component name(s)",
            "      must_not_blame: []     # components that are NOT the cause",
        ]
    suite = out_dir / "suite.yaml"
    suite.write_text("\n".join(lines) + "\n")
    return suite
