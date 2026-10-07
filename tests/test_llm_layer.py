"""Phase 2: structured output with repair, retry/shrink/fallback, bundle
recording and replay, batched occurrence counts, and the eval harness.
"""
from __future__ import annotations

import json
import time

import pytest

from systemlens.config import AgentConfig
from systemlens.core.bundle_io import bundle_from_dict, bundle_to_dict, load_recording
from systemlens.core.correlate import correlate
from systemlens.core.models import Analysis, ContainerState, EvidenceBundle, LogRecord, Severity
from systemlens.core.pipeline import ContainerSource, ProjectPipeline
from systemlens.core.ratelimit import RateLimiter
from systemlens.core.sinks import ReportSink
from systemlens.evaluation import init_suite, run_suite, score_analysis, score_correlator
from systemlens.llm.base import JsonChatProvider, ProviderUnavailable
from systemlens.llm.prompt import render_evidence
from systemlens.llm.resilient import ResilientProvider
from systemlens.logs.cluster import to_signal
from systemlens.memory.store import ProjectStore
from systemlens.memory.window import SlidingWindow

NOW = 1_000_000.0
GOOD = {"verdict": "probable_cause", "root_cause": "db is down", "affected_component": "db",
        "evidence": [], "fix_suggestion": "docker compose up -d db", "confidence": 0.7,
        "unverified_assumptions": []}


def _container(name, running=True, exit_code=None, finished_at=None, health=None, depends_on=None):
    return ContainerState(id=f"id-{name}", name=name, image="x", status="running" if running else "exited",
                          running=running, exit_code=exit_code, started_at=0.0, finished_at=finished_at,
                          oom_killed=False, restart_count=0, health=health, compose_service=name,
                          depends_on=depends_on or [])


def _bundle(raw='ERROR web: connection refused to db:5432', container="web", containers=None):
    record = LogRecord(project="demo", source=f"container:{container}", raw=raw, ts=NOW, event_ts=NOW,
                       severity=Severity.ERROR, container=container)
    containers = containers if containers is not None else [
        _container("web", depends_on=["db"]), _container("db", running=False, exit_code=1, finished_at=NOW - 5)]
    bundle = EvidenceBundle(project="demo", signal=to_signal(record), occurrences=3,
                            log_window=[record], containers=containers, docker_available=True)
    bundle.candidates = correlate(bundle, 120)
    return bundle


# -- structured output -----------------------------------------------------------

class _Scripted(JsonChatProvider):
    name, model = "scripted", "m"

    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    async def _complete(self, system, messages, schema):
        self.calls.append((system, messages, schema))
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


@pytest.mark.asyncio
async def test_invalid_json_gets_one_repair_attempt():
    provider = _Scripted(["not json at all", json.dumps(GOOD)])
    result = await provider.complete_json("sys", "user", Analysis)

    assert result.affected_component == "db"
    assert len(provider.calls) == 2
    assert "failed validation" in provider.calls[1][1][-1]["content"]
    assert "schema" in provider.calls[0][0], "non-strict providers get the schema in the prompt"


@pytest.mark.asyncio
async def test_two_bad_answers_become_insufficient_evidence_not_a_crash():
    provider = _Scripted(["{}", "still wrong"])
    analysis = await provider.analyze(_bundle())

    assert analysis.verdict == "insufficient_evidence" and analysis.confidence == 0.0


# -- retry / shrink / fallback -----------------------------------------------------

class _HttpError(Exception):
    def __init__(self, status, retry_after=None):
        super().__init__(f"HTTP {status}")
        self.status_code = status
        self.response = type("R", (), {"headers": {"retry-after": retry_after} if retry_after else {}})()


class _Flaky:
    name, model = "primary", "p1"

    def __init__(self, failures):
        self.failures, self.calls, self.budgets = list(failures), 0, []

    async def analyze(self, bundle):
        self.calls += 1
        self.budgets.append(bundle.max_evidence_chars)
        if self.failures:
            raise self.failures.pop(0)
        return Analysis(**GOOD)


async def _no_sleep(_seconds):
    return None


@pytest.mark.asyncio
async def test_rate_limit_is_retried_after_the_advertised_wait():
    waits = []

    async def sleep(seconds):
        waits.append(seconds)

    inner = _Flaky([_HttpError(429, retry_after="3")])
    result = await ResilientProvider(inner, sleep=sleep).analyze(_bundle())

    assert result.affected_component == "db" and inner.calls == 2
    assert waits == [3.0]


@pytest.mark.asyncio
async def test_request_too_large_halves_the_evidence_budget():
    inner = _Flaky([_HttpError(413)])
    bundle = _bundle()
    bundle.max_evidence_chars = 6000

    await ResilientProvider(inner, sleep=_no_sleep).analyze(bundle)

    assert inner.budgets == [6000, 3000]


@pytest.mark.asyncio
async def test_persistent_failure_is_not_retried_forever():
    inner = _Flaky([_HttpError(503)] * 10)
    with pytest.raises(_HttpError):
        await ResilientProvider(inner, max_retries=2, sleep=_no_sleep).analyze(_bundle())
    assert inner.calls == 3


@pytest.mark.asyncio
async def test_client_errors_are_not_retried():
    inner = _Flaky([_HttpError(401)])
    with pytest.raises(_HttpError):
        await ResilientProvider(inner, sleep=_no_sleep).analyze(_bundle())
    assert inner.calls == 1


@pytest.mark.asyncio
async def test_fallback_answers_when_the_primary_is_unreachable():
    primary = _Flaky([ProviderUnavailable("down")])
    fallback = _Flaky([])
    fallback.name, fallback.model = "backup", "b1"
    provider = ResilientProvider(primary, fallback=fallback, sleep=_no_sleep)

    result = await provider.analyze(_bundle())

    assert result.affected_component == "db"
    assert (provider.name, provider.model) == ("backup", "b1"), "the finding is attributed to who answered"


def test_evidence_budget_is_respected_by_the_renderer():
    bundle = _bundle()
    bundle.log_window = [bundle.signal.record] * 400
    bundle.max_evidence_chars = 2000
    assert len(render_evidence(bundle)) <= 2000 + 200


# -- recording and replay ------------------------------------------------------------

def test_bundle_survives_a_json_round_trip():
    bundle = _bundle()
    restored = bundle_from_dict(json.loads(json.dumps(bundle_to_dict(bundle))))

    assert restored.signal.fingerprint == bundle.signal.fingerprint
    assert restored.signal.record.severity is Severity.ERROR
    assert [c.name for c in restored.containers] == ["web", "db"]
    assert [(c.rule_id, c.scoped) for c in restored.candidates] == [(c.rule_id, c.scoped) for c in bundle.candidates]
    assert render_evidence(restored) == render_evidence(bundle)


class _Containers(ContainerSource):
    def __init__(self, containers=()):
        self._c = list(containers)

    async def containers_for(self, project):
        return self._c, "high"

    async def docker_available(self):
        return True

    async def logs_for(self, container_id, tail):
        return []


class _Provider:
    name, model = "fake", "fake-1"

    def __init__(self):
        self.calls = 0

    async def analyze(self, bundle):
        self.calls += 1
        return Analysis(**{**GOOD, "affected_component": bundle.signal.record.container or "unknown"})


class _Sink(ReportSink):
    def __init__(self):
        self.findings = []

    async def emit(self, finding):
        self.findings.append(finding)


def _pipeline(tmp_path, **kwargs):
    config = AgentConfig(home=tmp_path)
    store = ProjectStore(tmp_path / "state.db")
    provider = _Provider()
    pipeline = ProjectPipeline("demo", config, store, SlidingWindow(), None,
                               RateLimiter(config.ratelimit, store), provider, _Sink(), _Containers(), **kwargs)
    return pipeline, store, provider


@pytest.mark.asyncio
async def test_pipeline_records_the_bundle_it_analysed(tmp_path):
    pipeline, store, _ = _pipeline(tmp_path, bundle_dir=tmp_path / "bundles")
    record = LogRecord(project="demo", source="container:web", raw="ERROR web: request timed out",
                       ts=time.time(), severity=Severity.ERROR, container="web")
    finding = await pipeline.process(record)

    bundle, answer = load_recording(tmp_path / "bundles" / f"{finding.fingerprint}.json")
    assert bundle.signal.record.raw == record.raw
    assert answer["affected_component"] == "web"
    store.close()


@pytest.mark.asyncio
async def test_occurrences_are_counted_in_memory_and_written_in_batches(tmp_path):
    pipeline, store, provider = _pipeline(tmp_path)
    record = LogRecord(project="demo", source="app.log", raw="ERROR cache write failed",
                       ts=time.time(), severity=Severity.ERROR)
    for _ in range(50):
        await pipeline.process(record)
    fingerprint = to_signal(record).fingerprint

    assert provider.calls == 1
    assert store.get_prior(fingerprint).occurrences == 1, "49 repeats cost no further writes yet"
    pipeline.flush_counts()
    assert store.get_prior(fingerprint).occurrences == 50
    pipeline.flush_counts()
    assert store.get_prior(fingerprint).occurrences == 50, "flushing twice must not double count"
    store.close()


# -- evaluation ------------------------------------------------------------------------

def test_score_analysis_checks_component_verdict_and_blame():
    expect = {"component": ["db"], "verdict": ["probable_cause"], "must_not_blame": ["cache"],
              "cause_mentions_any": ["down", "exited"]}
    assert score_analysis(Analysis(**GOOD), expect) == []

    wrong = Analysis(**{**GOOD, "affected_component": "cache", "root_cause": "the cache is slow"})
    problems = score_analysis(wrong, expect)
    assert any("component" in p for p in problems) and any("blamed 'cache'" in p for p in problems)

    woven = Analysis(**{**GOOD, "root_cause": "db is down because cache evicted its keys"})
    assert any("leans on 'cache'" in p for p in score_analysis(woven, expect))


def test_score_correlator_checks_which_containers_are_linked():
    bundle = _bundle(raw="ERROR web: Exception on /crash [GET]\nTraceback (most recent call last):\nKeyError: 'k'")
    assert score_correlator(bundle, {"not_linked": ["db"]}) == []
    assert score_correlator(bundle, {"linked": ["db"]}) != []


@pytest.mark.asyncio
async def test_suite_runs_end_to_end_and_reports_pass_rates(tmp_path):
    pipeline, store, _ = _pipeline(tmp_path, bundle_dir=tmp_path / "recorded")
    for raw in ("ERROR web: request timed out", "ERROR web: disk quota exceeded"):
        await pipeline.process(LogRecord(project="demo", source="container:web", raw=raw,
                                         ts=time.time(), severity=Severity.ERROR, container="web"))
    store.close()

    suite = init_suite(tmp_path / "recorded", tmp_path / "suite", "demo")
    text = suite.read_text()
    assert text.count("- id:") == 2 and "recorded answer: web" in text
    # fill in the answer key: one case expects web, the other (wrongly) db
    filled = text.replace("      component: []", "      component: [web]", 1) \
                 .replace("      component: []", "      component: [db]", 1)
    suite.write_text(filled)

    report = await run_suite(suite, _Provider())
    assert report.rate("correlator_ok") == 1.0
    assert report.rate("analysis_ok") == 0.5
    assert [r.analysis_ok for r in report.results].count(False) == 1

    offline = await run_suite(suite, None)
    assert offline.with_llm is False and offline.to_dict()["analysis_pass_rate"] is None


@pytest.mark.asyncio
async def test_shipped_example_suite_passes_the_correlator_check():
    """Evidence recorded from a real broken stack: the deterministic layer
    must keep linking the right containers and leaving the others out.
    """
    from pathlib import Path
    suite = Path(__file__).parent.parent / "examples" / "eval" / "error-project" / "suite.yaml"
    report = await run_suite(suite, None)
    assert len(report.results) == 11
    assert [r.case_id for r in report.results if not r.correlator_ok] == []
