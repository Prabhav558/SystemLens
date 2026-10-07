"""Per-project wiring: takes a raw LogRecord all the way to an (optional)
Finding. This is the one place all the layers meet — logs, containers,
memory, correlation, rate limiting, and the LLM — for a single project.
Nothing here reaches across into another project's state.
"""
from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Optional

from systemlens.config import AgentConfig
from systemlens.containers.inspect import ContainerState
from systemlens.core import analysis as analysis_step
from systemlens.core.bundle_io import save_recording
from systemlens.core.correlate import correlate, resolve_origin
from systemlens.core.models import Analysis, EvidenceBundle, Finding, LogRecord, Severity, Signal
from systemlens.core.ratelimit import RateLimiter
from systemlens.core.sinks import ReportSink
from systemlens.agents.investigator import needs_investigation
from systemlens.llm.base import LLMProvider
from systemlens.logs.cluster import to_signal
from systemlens.logs.redact import redact
from systemlens.memory.store import ProjectStore
from systemlens.memory.vector import VectorIndex
from systemlens.memory.window import SlidingWindow

logger = logging.getLogger("systemlens.pipeline")


class ContainerSource:
    """What a pipeline needs from the shared container layer. Implemented by
    core.daemon.ContainerRegistry; kept as a narrow protocol so pipeline
    tests can supply a trivial stub instead of a real/fake Docker client.
    """
    async def containers_for(self, project: str) -> tuple[list[ContainerState], str]:
        raise NotImplementedError

    async def docker_available(self) -> bool:
        raise NotImplementedError

    async def logs_for(self, container_id: str, tail: int) -> list[str]:
        raise NotImplementedError


class ProjectPipeline:
    def __init__(
        self,
        project: str,
        config: AgentConfig,
        store: ProjectStore,
        window: SlidingWindow,
        vector_index: Optional[VectorIndex],
        ratelimiter: RateLimiter,
        llm: LLMProvider,
        sink: ReportSink,
        containers: ContainerSource,
        bundle_dir: Optional[Path] = None,
        investigator=None,
    ):
        self.project = project
        self._config = config
        self._store = store
        self._window = window
        self._vector = vector_index
        self._ratelimiter = ratelimiter
        self._llm = llm
        self._sink = sink
        self._containers = containers
        # container state as each fingerprint's last analysis saw it
        self._analyzed_state: dict[str, str] = {}
        # (container, category) -> when a signal of that kind was last analysed
        self._recently_analyzed: dict[tuple[str, str], float] = {}
        self._bundle_dir = bundle_dir          # None = don't record evidence bundles
        self._investigator = investigator      # None = no automatic follow-up
        # Occurrence counts live in memory and are written in batches: a
        # noisy error must not cost one SQLite write per log line.
        self._counts: dict[str, int] = {}
        self._pending: dict[str, int] = {}
        self._pending_seen: dict[str, float] = {}
        self._muted: set[str] = set()
        self._muted_checked = 0.0

    def _is_muted(self, fingerprint: str) -> bool:
        # `agent mute` runs in another process: re-read the (tiny) set now and then
        now = time.monotonic()
        if now - self._muted_checked > 5.0:
            self._muted, self._muted_checked = self._store.muted_fingerprints(), now
        return fingerprint in self._muted

    def _count(self, signal: Signal) -> int:
        fp = signal.fingerprint
        if fp not in self._counts:
            self._counts[fp] = self._store.touch_fingerprint(fp, signal.template, signal.category)
        else:
            self._counts[fp] += 1
            self._pending[fp] = self._pending.get(fp, 0) + 1
            self._pending_seen[fp] = time.time()
        return self._counts[fp]

    def flush_counts(self) -> None:
        """Write batched occurrence counts. Called periodically by the daemon,
        before an analysis reads history, and on shutdown.
        """
        for fp, n in self._pending.items():
            self._store.add_occurrences(fp, n, self._pending_seen[fp])
        self._pending.clear()
        self._pending_seen.clear()

    async def process(self, record: LogRecord) -> Optional[Finding]:
        self._window.add(record)

        signal = to_signal(record)
        if signal is None:
            return None

        occurrences = self._count(signal)

        # An unclassified warning (a startup notice, a deprecation) is counted
        # but not worth an analysis; errors and recognised patterns are.
        if signal.severity < Severity.ERROR and signal.category == "generic":
            return None
        if self._is_muted(signal.fingerprint):
            return None

        # A container's own log line and the Docker event for the same failure
        # (e.g. "health check failed" and health_status: unhealthy) are one
        # issue. If the log line was just analysed, the event adds nothing.
        kind = (record.container or "", signal.category)
        if record.source == "docker:events":
            last = self._recently_analyzed.get(kind)
            if last is not None and record.when - last <= self._config.correlation.window_seconds:
                return None

        containers, mapping_confidence = await self._containers.containers_for(self.project)
        docker_available = await self._containers.docker_available()

        # Rate-limit before paying for container log fetches — the common
        # case (a fingerprint on cooldown) rejects here, so we shouldn't do
        # a Docker round-trip per container first only to discard it.
        state = self._state_hash(containers)
        previous = self._analyzed_state.get(signal.fingerprint)
        prior = self._store.get_prior(signal.fingerprint)
        from_memory = bool(prior and prior.resolution and self._config.memory.reuse_resolutions)
        decision = self._ratelimiter.check(
            signal.fingerprint, previous is not None and previous != state, free=from_memory)
        if not decision.allow:
            logger.debug("skipping analysis for %s: %s", signal.fingerprint, decision.reason)
            return None
        self._analyzed_state[signal.fingerprint] = state
        self._recently_analyzed[kind] = record.when
        self.flush_counts()
        prior = self._store.get_prior(signal.fingerprint)

        similar = self._similar(signal, prior)

        bundle = EvidenceBundle(
            project=self.project,
            signal=signal,
            occurrences=occurrences,
            log_window=self._window.around(
                signal.record.when, self._config.correlation.window_seconds,
                self._config.correlation.log_window_lines,
            ),
            containers=containers,
            prior=prior,
            similar=similar,
            docker_available=docker_available,
            mapping_confidence=mapping_confidence,
            max_evidence_chars=self._config.llm.max_evidence_chars,
        )
        bundle.candidates = correlate(bundle, self._config.correlation.window_seconds)

        # A fingerprint the user already resolved is answered from memory:
        # no container log fetch, no LLM call.
        if from_memory:
            return await self._emit_from_memory(signal, bundle)

        # Only fetch/attach logs for containers the deterministic correlator
        # actually flagged as relevant (none of R1-R6 read container_logs —
        # it's purely extra context for the LLM). Attaching every mapped
        # container's logs regardless of relevance bloats the prompt well
        # past what small/free-tier models accept in one request — this
        # exact request was rejected live at ~11.5K tokens against Groq's
        # free-tier 8K TPM cap, from a project with 7 containers.
        if docker_available and containers:
            relevant_ids = {c.meta.get("container_id") for c in bundle.candidates
                            if c.scoped and c.meta.get("container_id")}
            relevant = [c for c in containers if c.id in relevant_ids]
            if relevant:
                fetched = await asyncio.gather(*(
                    self._containers.logs_for(c.id, self._config.correlation.container_log_lines)
                    for c in relevant
                ))
                bundle.container_logs = {
                    c.name: [redact(line) for line in lines] for c, lines in zip(relevant, fetched)
                }

        try:
            checked = await analysis_step.analyze(self._llm, bundle)
        except Exception:
            # A failed call still consumes rate-limit budget (cooldown +
            # hourly cap), or a broken provider retries unthrottled at full
            # log volume — the caller (daemon._consume_loop) logs and moves on.
            self._store.mark_analyzed(signal.fingerprint)
            self._store.record_attempt(signal.fingerprint)
            raise
        provider = self._llm.name

        if (self._investigator is not None
                and self._config.investigator.auto
                and needs_investigation(checked.analysis, self._config.investigator.min_confidence)):
            try:
                investigation = await self._investigator.investigate(bundle, checked.analysis)
                if investigation.steps:
                    checked, provider = investigation.checked, f"{self._llm.name}+investigator"
            except Exception as e:  # noqa: BLE001 - keep the first analysis
                logger.warning("investigation of %s failed: %s", signal.fingerprint, e)

        if checked.dropped_evidence:
            logger.warning("dropped %d fabricated evidence entries for %s",
                            len(checked.dropped_evidence), signal.fingerprint)
        for note in checked.grounding_notes:
            logger.warning("%s: %s", signal.fingerprint, note)

        # Cooldown tracking must not depend on which sinks are configured
        # (e.g. sqlite sink disabled) — the rate limiter itself relies on this.
        self._store.mark_analyzed(signal.fingerprint)

        approx_tokens = len(bundle.evidence_corpus()) // 4 + self._config.llm.max_output_tokens
        self._ratelimiter.record_spend(approx_tokens)

        finding = Finding(
            project=self.project, fingerprint=signal.fingerprint, analysis=checked.analysis,
            bundle=bundle, provider=provider, model=self._llm.model,
            dropped_evidence=checked.dropped_evidence,
        )
        self._record(finding)
        await self._sink.emit(finding)
        return finding

    def _record(self, finding: Finding) -> None:
        if self._bundle_dir is None:
            return
        try:
            save_recording(self._bundle_dir, finding.bundle, finding.analysis, finding.provider, finding.model)
        except OSError as e:
            logger.warning("could not record evidence bundle: %s", e)

    def _similar(self, signal, prior) -> list:
        if self._vector is not None and VectorIndex.available() and self._config.memory.use_faiss:
            return self._vector.search(signal.template, self._store, self._config.memory.similar_top_k)
        exclude = prior.fingerprint if prior else signal.fingerprint
        return self._store.similar_resolved(exclude, signal.category, self._config.memory.similar_top_k)

    async def _emit_from_memory(self, signal: Signal, bundle: EvidenceBundle) -> Finding:
        prior = bundle.prior
        last = self._store.last_diagnosis(signal.fingerprint)
        origin = resolve_origin(signal, bundle.containers)
        if last is not None:
            cause = f"Recurrence of an issue you resolved before. Last diagnosis: {last['root_cause']}"
            component = last["affected_component"] or (origin.name if origin else "unknown")
        else:
            cause = "Recurrence of an issue you resolved before (no earlier diagnosis on record)."
            component = origin.name if origin else "unknown"
        analysis = Analysis(
            verdict="probable_cause",
            root_cause=cause,
            affected_component=component,
            evidence=[signal.record.first_line],
            fix_suggestion=f"Previously resolved with: {prior.resolution}",
            confidence=0.8,
            unverified_assumptions=[
                "answered from resolution memory without a new analysis; "
                "the earlier fix may not apply if the cause has changed"
            ],
        )
        self._store.mark_analyzed(signal.fingerprint)
        finding = Finding(project=self.project, fingerprint=signal.fingerprint, analysis=analysis,
                          bundle=bundle, provider="memory", model="resolution-memory")
        self._record(finding)
        await self._sink.emit(finding)
        return finding

    @staticmethod
    def _state_hash(containers: list[ContainerState]) -> str:
        return "|".join(sorted(f"{c.name}:{c.status}:{c.exit_code}" for c in containers))
