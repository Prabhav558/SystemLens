"""End-to-end pipeline test: LogRecord -> Finding, entirely offline. Uses a
FakeContainerSource (no real/fake Docker socket needed) and a FakeProvider
(no network) so this exercises every layer — clustering, correlation, rate
limiting, sanitization, sinks — exactly as the daemon wires them, without
requiring Docker or an API key.
"""
import asyncio

import pytest

from systemlens.config import AgentConfig
from systemlens.containers.inspect import ContainerState
from systemlens.core.models import Analysis, EvidenceBundle, LogRecord, Severity
from systemlens.core.pipeline import ContainerSource, ProjectPipeline
from systemlens.core.ratelimit import RateLimiter
from systemlens.core.sinks import ReportSink
from systemlens.memory.store import ProjectStore
from systemlens.memory.window import SlidingWindow


class FakeContainerSource(ContainerSource):
    def __init__(self, containers, available=True):
        self._containers = containers
        self._available = available

    async def containers_for(self, project):
        return self._containers, "high"

    async def docker_available(self):
        return self._available

    async def logs_for(self, container_id, tail):
        return [f"fake log line for {container_id}"]


class FakeProvider:
    name = "fake"
    model = "fake-model-1"

    def __init__(self):
        self.calls = 0

    async def analyze(self, bundle: EvidenceBundle) -> Analysis:
        self.calls += 1
        top = bundle.candidates[0] if bundle.candidates else None
        return Analysis(
            verdict="root_cause_identified" if top else "insufficient_evidence",
            root_cause=f"{top.component} appears responsible" if top else "no clear cause",
            affected_component=top.component if top else "unknown",
            evidence=[bundle.signal.record.raw],
            fix_suggestion="restart the affected container",
            confidence=top.confidence if top else 0.0,
        )


class CollectingSink(ReportSink):
    def __init__(self):
        self.findings = []

    async def emit(self, finding):
        self.findings.append(finding)


def _pipeline(tmp_path, containers, docker_available=True):
    config = AgentConfig(home=tmp_path)
    store = ProjectStore(tmp_path / "state.db")
    window = SlidingWindow()
    ratelimiter = RateLimiter(config.ratelimit, store)
    provider = FakeProvider()
    sink = CollectingSink()
    containers_src = FakeContainerSource(containers, available=docker_available)
    pipeline = ProjectPipeline("demo", config, store, window, None, ratelimiter,
                                provider, sink, containers_src)
    return pipeline, store, provider, sink


def _db_down_container():
    return ContainerState(
        id="db1", name="db", image="postgres:16", status="exited", running=False,
        exit_code=0, started_at=0.0, finished_at=1_000_000.0 - 4, oom_killed=False,
        restart_count=0, health=None, compose_service="db", depends_on=[], aliases=["db"],
    )


@pytest.mark.asyncio
async def test_connection_refused_produces_root_cause_finding(tmp_path):
    pipeline, store, provider, sink = _pipeline(tmp_path, [_db_down_container()])
    record = LogRecord(
        project="demo", source="backend.log",
        raw='connection to server at "db" (172.18.0.2), port 5432 failed: Connection refused',
        ts=1_000_000.0, event_ts=1_000_000.0, severity=Severity.ERROR,
    )

    finding = await pipeline.process(record)

    assert finding is not None
    assert finding.analysis.verdict == "root_cause_identified"
    assert finding.analysis.affected_component == "db"
    assert provider.calls == 1
    assert len(sink.findings) == 1


@pytest.mark.asyncio
async def test_info_level_records_never_trigger_analysis(tmp_path):
    pipeline, store, provider, sink = _pipeline(tmp_path, [])
    record = LogRecord(project="demo", source="app.log", raw="INFO server started",
                        ts=0.0, severity=Severity.INFO)

    finding = await pipeline.process(record)

    assert finding is None
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_repeated_identical_error_only_analyzed_once(tmp_path):
    pipeline, store, provider, sink = _pipeline(tmp_path, [_db_down_container()])
    record = LogRecord(
        project="demo", source="backend.log",
        raw='connection to server at "db", port 5432 failed', ts=1_000_000.0,
        event_ts=1_000_000.0, severity=Severity.ERROR,
    )

    for _ in range(20):
        await pipeline.process(record)

    assert provider.calls == 1
    assert len(sink.findings) == 1


@pytest.mark.asyncio
async def test_docker_unavailable_still_produces_a_finding(tmp_path):
    pipeline, store, provider, sink = _pipeline(tmp_path, [], docker_available=False)
    record = LogRecord(project="demo", source="backend.log", raw="ERROR something broke",
                        ts=1_000_000.0, event_ts=1_000_000.0, severity=Severity.ERROR)

    finding = await pipeline.process(record)

    assert finding is not None
    assert finding.bundle.docker_available is False
    # deterministic correlator falls back to the R0 "log-only" candidate —
    # FakeProvider's verdict tracks whatever candidate it was given, so the
    # real assertion here is on the correlator output, not the fake LLM text
    assert finding.bundle.candidates[0].rule_id == "R0"
    assert finding.bundle.candidates[0].confidence < 0.5
