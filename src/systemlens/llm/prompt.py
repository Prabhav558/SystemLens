"""Frozen system prompt + deterministic evidence renderer.

The system prompt is stable text so it can be prompt-cached; all volatile
content (the evidence bundle) is rendered separately and goes in the user
turn, after the cache breakpoint. Structured output (Pydantic schema) does
the format enforcement — this prompt only has to state the *epistemics*.
"""
from __future__ import annotations

from systemlens.core.models import EvidenceBundle

_MAX_LINE_CHARS = 400      # per-line cap so one dense line can't dominate the budget
_MAX_EVIDENCE_CHARS = DEFAULT_MAX_EVIDENCE_CHARS = 6000  # hard ceiling on the whole rendered body, provider-agnostic
                             # safety net — MAX_FOLDED_LINES in logs/parse.py bounds the
                             # common cause (a giant traceback) at the source; this catches
                             # everything else (many containers, a noisy log window, etc.)


def _clip(text: str) -> str:
    if len(text) <= _MAX_LINE_CHARS:
        return text
    return text[:_MAX_LINE_CHARS] + f" ...[+{len(text) - _MAX_LINE_CHARS} chars truncated]"

SYSTEM_PROMPT = """You are a root-cause analysis engine for a local development \
environment. You are given: a triggering log signal, a window of surrounding \
logs, the state of Docker containers involved, deterministic correlation \
candidates already computed by rule-based analysis, and any prior incidents \
with the same fingerprint.

Your job is NOT to guess. It is to rank and explain the evidence you were \
given, and to say clearly when the evidence does not support a conclusion.

Rules:
- Every string you put in `evidence` MUST be copied verbatim from the material \
you were given. Never paraphrase into `evidence` and never invent a log line, \
timestamp, exit code, or container name that was not shown to you.
- The `candidates` list already reflects deterministic reasoning (container \
exit timing, OOM kills, dependency chains, connection targets). Prefer the \
highest-confidence candidate that the log evidence actually supports. You may \
override the ranking if the log content contradicts it, but say why.
- CO-OCCURRING CONTAINER FACTS are true, but nothing links them to the \
triggering signal: that container did not log it, was not the connection \
target, and is not a dependency. Do not name one as the cause, and do not \
build it into your explanation, unless the triggering signal itself names \
that container. Two things failing at the same time is not evidence that \
one caused the other.
- A log message describes what the program printed, not necessarily what \
happened. If the only support for a cause is the wording of a message, say so \
in `unverified_assumptions`.
- If the evidence does not clearly point to one component, or you would be \
guessing beyond what's shown, set verdict to "insufficient_evidence" and say \
what additional information would resolve it. This is a correct and expected \
answer — do not stretch weak evidence into a confident one.
- `unverified_assumptions` should list anything in your reasoning that is not \
directly backed by the evidence (e.g. "assuming no other client changed \
config between these two events").
- fix_suggestion should be the smallest concrete next action, ideally a \
runnable command, not a general recommendation.
"""


def render_evidence(bundle: EvidenceBundle) -> str:
    """Two blocks, deliberately ordered so a length budget only ever trims
    the bulky, variable-size one:

    `core` — signal, deterministic candidates, prior/similar history. Small,
    high-value, and exactly what the correlator decided matters — never cut.

    `supplementary` — the raw log window and per-container logs. This is
    where an unbounded source (a huge traceback, a noisy container, many
    relevant containers) can blow past a small model's token budget, so it
    alone absorbs the _MAX_EVIDENCE_CHARS cap.
    """
    s = bundle.signal
    core = [
        f"PROJECT: {bundle.project}",
        f"DOCKER AVAILABLE: {bundle.docker_available}",
        f"CONTAINER MAPPING CONFIDENCE: {bundle.mapping_confidence}",
        f"ORIGIN CONTAINER (emitted the triggering signal): {s.record.container or 'unknown'}",
        "",
        "=== TRIGGERING SIGNAL ===",
        f"category: {s.category}  severity: {s.severity.name}  occurrences: {bundle.occurrences}",
        _clip(s.record.raw),
        "",
        "=== DETERMINISTIC CANDIDATES (already computed, ranked) ===",
    ]
    scoped = [c for c in bundle.candidates if c.scoped]
    unscoped = [c for c in bundle.candidates if not c.scoped]
    if not scoped:
        core.append("(none)")
    for cand in scoped:
        core.append(f"- [{cand.rule_id}] {cand.component} (confidence={cand.confidence:.2f}): {cand.summary}")
        for ev in cand.evidence:
            core.append(f"    evidence: {_clip(ev)}")
    if unscoped:
        core.append("")
        core.append("=== CO-OCCURRING CONTAINER FACTS (true, but NOT linked to this signal) ===")
        for cand in unscoped:
            core.append(f"- [{cand.rule_id}] {cand.component}: {cand.summary}")

    if bundle.prior:
        core.append("")
        core.append("=== PRIOR HISTORY FOR THIS EXACT FINGERPRINT ===")
        core.append(
            f"first_seen={bundle.prior.first_seen} occurrences={bundle.prior.occurrences} "
            f"resolution={bundle.prior.resolution!r}"
        )

    if bundle.similar:
        core.append("")
        core.append("=== SIMILAR PAST INCIDENTS (different fingerprint) ===")
        for p in bundle.similar:
            core.append(f"- fingerprint={p.fingerprint} resolution={p.resolution!r}")

    supplementary: list[str] = ["", "=== SURROUNDING LOG WINDOW ==="]
    for r in bundle.log_window:
        supplementary.append(_clip(f"[{r.container or r.source}] {r.raw}"))

    supplementary.append("")
    supplementary.append("=== CONTAINER STATE ===")
    for c in bundle.containers:
        supplementary.append(
            f"- {c.name} (image={c.image}) status={c.status} running={c.running} "
            f"exit_code={c.exit_code} oom_killed={c.oom_killed} health={c.health} "
            f"restarts={c.restart_count} depends_on={c.depends_on}"
        )
        for line in bundle.container_logs.get(c.name, [])[-10:]:
            supplementary.append(_clip(f"    | {line}"))

    core_text = "\n".join(core)
    budget = (bundle.max_evidence_chars or _MAX_EVIDENCE_CHARS) - len(core_text)
    supplementary_text = "\n".join(supplementary)
    if budget <= 0:
        supplementary_text = "\n[log window and container logs omitted — no budget remaining]"
    elif len(supplementary_text) > budget:
        supplementary_text = (
            supplementary_text[:budget]
            + f"\n...[+{len(supplementary_text) - budget} chars of log window/container logs truncated to fit budget]"
        )

    return core_text + supplementary_text
