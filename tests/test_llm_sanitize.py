"""Schema-validation / anti-hallucination tests: a fabricated evidence[]
entry must be dropped, and dropping all evidence must downgrade the verdict.
This is the concrete enforcement of "don't send raw logs blindly to the LLM
and don't trust its output blindly either."
"""
from systemlens.core.models import Analysis
from systemlens.llm.base import sanitize_evidence


def _analysis(verdict, evidence, assumptions=None):
    return Analysis(verdict=verdict, root_cause="db connection failed",
                     affected_component="db", evidence=evidence,
                     fix_suggestion="restart db", confidence=0.9,
                     unverified_assumptions=assumptions or [])


def test_real_evidence_is_kept():
    corpus = "line one\nERROR connection refused to db:5432\nline three"
    a = _analysis("root_cause_identified", ["ERROR connection refused to db:5432"])
    cleaned, dropped = sanitize_evidence(a, corpus)
    assert cleaned.evidence == ["ERROR connection refused to db:5432"]
    assert dropped == []
    assert cleaned.verdict == "root_cause_identified"


def test_fabricated_evidence_is_dropped():
    corpus = "line one\nline two"
    a = _analysis("root_cause_identified", ["this line was never in the logs"])
    cleaned, dropped = sanitize_evidence(a, corpus)
    assert cleaned.evidence == []
    assert dropped == ["this line was never in the logs"]


def test_all_evidence_fabricated_downgrades_verdict_to_insufficient():
    corpus = "line one\nline two"
    a = _analysis("root_cause_identified", ["fabricated line"])
    cleaned, dropped = sanitize_evidence(a, corpus)
    assert cleaned.verdict == "insufficient_evidence"


def test_mixed_real_and_fabricated_keeps_only_real():
    corpus = "real line here\nother real line"
    a = _analysis("root_cause_identified", ["real line here", "made up nonsense"])
    cleaned, dropped = sanitize_evidence(a, corpus)
    assert cleaned.evidence == ["real line here"]
    assert dropped == ["made up nonsense"]
    assert cleaned.verdict == "root_cause_identified"  # partial real evidence survives


def test_insufficient_evidence_verdict_passes_through_untouched():
    corpus = "line one"
    a = _analysis("insufficient_evidence", [])
    cleaned, dropped = sanitize_evidence(a, corpus)
    assert cleaned.verdict == "insufficient_evidence"
    assert dropped == []
