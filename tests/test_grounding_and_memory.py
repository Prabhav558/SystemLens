"""Phase 0: the grounding check, the resolution-memory shortcut, redaction
and retention. The grounding fixtures reproduce the two live findings that
blamed an unrelated database for a hard-coded health check failure.
"""
from __future__ import annotations

import time

import pytest

from systemlens.config import AgentConfig
from systemlens.core.correlate import correlate
from systemlens.core.grounding import enforce_grounding
from systemlens.core.models import Analysis, ContainerState, EvidenceBundle, LogRecord, Severity
from systemlens.core.pipeline import ContainerSource, ProjectPipeline
from systemlens.core.ratelimit import RateLimiter
from systemlens.core.sinks import ReportSink
from systemlens.logs.cluster import to_signal
from systemlens.logs.parse import assemble_records
from systemlens.logs.redact import redact
from systemlens.memory.store import ProjectStore
from systemlens.memory.window import SlidingWindow

NOW = 1_000_000.0


def _container(name, running=True, exit_code=None, finished_at=None, health=None, depends_on=None):
    return ContainerState(
        id=f"id-{name}", name=name, image="x", status="running" if running else "exited",
        running=running, exit_code=exit_code, started_at=0.0, finished_at=finished_at,
        oom_killed=False, restart_count=0, health=health, compose_service=name,
        depends_on=depends_on or [],
    )


def _flaky_health_bundle():
    record = LogRecord(project="demo", source="container:flaky_health", ts=NOW, event_ts=NOW,
                        raw="ERROR flaky-health: health check failed: dependency check did not pass",
                        severity=Severity.ERROR, container="flaky_health")
    containers = [_container("flaky_health", health="unhealthy"),
                  _container("db", running=False, exit_code=1, finished_at=NOW - 10)]
    bundle = EvidenceBundle(project="demo", signal=to_signal(record), occurrences=1,
                             containers=containers, docker_available=True)
    bundle.candidates = correlate(bundle, 120)
    return bundle


def _analysis(component, cause, verdict="root_cause_identified", confidence=0.85):
    return Analysis(verdict=verdict, root_cause=cause, affected_component=component,
                     fix_suggestion="x", confidence=confidence)


# -- grounding ---------------------------------------------------------------

def test_blaming_an_unlinked_container_is_downgraded_to_insufficient_evidence():
    bundle = _flaky_health_bundle()
    wrong = _analysis("db", "The 'db' container is exited, causing health-check failures.")

    checked, notes = enforce_grounding(wrong, bundle)

    assert checked.verdict == "insufficient_evidence"
    assert checked.confidence <= 0.2
    assert notes and "db" in notes[0]
    assert any("grounding" in a for a in checked.unverified_assumptions)


def test_weaving_a_co_occurring_fact_into_the_cause_is_downgraded():
    bundle = _flaky_health_bundle()
    woven = _analysis("flaky_health", "flaky_health cannot reach its dependencies (cache and db).")

    checked, notes = enforce_grounding(woven, bundle)

    assert checked.verdict == "probable_cause"
    assert checked.confidence <= 0.5
    assert notes


def test_a_diagnosis_about_the_origin_itself_is_untouched():
    bundle = _flaky_health_bundle()
    right = _analysis("flaky_health", "The service's own /health endpoint returns 500.")

    checked, notes = enforce_grounding(right, bundle)

    assert checked is right and notes == []


def test_a_container_named_in_the_signal_counts_as_linked():
    record = LogRecord(project="demo", source="container:web", ts=NOW, event_ts=NOW,
                        raw='ERROR web: could not translate host name "db" to address',
                        severity=Severity.ERROR, container="web")
    containers = [_container("web"), _container("db", running=False, exit_code=1, finished_at=NOW - 10)]
    bundle = EvidenceBundle(project="demo", signal=to_signal(record), occurrences=1,
                             containers=containers, docker_available=True)
    bundle.candidates = correlate(bundle, 120)

    checked, notes = enforce_grounding(_analysis("db", "db exited, so its name no longer resolves."), bundle)

    assert checked.verdict == "root_cause_identified" and notes == []


def test_plain_log_file_without_container_identity_is_not_second_guessed():
    record = LogRecord(project="demo", source="backend.log", ts=NOW, event_ts=NOW,
                        raw="ERROR unhandled KeyError in request handler", severity=Severity.ERROR)
    bundle = EvidenceBundle(project="demo", signal=to_signal(record), occurrences=1,
                             containers=[_container("backend")], docker_available=True)
    bundle.candidates = correlate(bundle, 120)

    checked, notes = enforce_grounding(_analysis("backend", "A KeyError is raised in the handler."), bundle)

    assert checked.verdict == "root_cause_identified" and notes == []


# -- parsing with container identity ------------------------------------------

def test_compose_log_prefix_gives_each_record_its_container_and_folds_tracebacks():
    lines = [
        "error_project_web  | 2026-08-19T19:30:44.223786122Z 2026-08-19 19:30:44,223 ERROR web: Exception on /crash [GET]",
        "error_project_web  | 2026-08-19T19:30:44.223786200Z Traceback (most recent call last):",
        'error_project_web  | 2026-08-19T19:30:44.223786300Z   File "/app/app.py", line 80, in crash',
        "error_project_web  | 2026-08-19T19:30:44.223786400Z KeyError: 'missing_key'",
        "error_project_db   | 2026-08-19T19:30:45.100000000Z ERROR db: shutting down",
    ]
    records = assemble_records(iter(lines), "demo", "compose.log")

    assert [r.container for r in records] == ["error_project_web", "error_project_db"]
    assert records[0].lines == 4
    assert to_signal(records[0]).category == "traceback"
    assert records[0].event_ts == pytest.approx(1787167844.223786)
    assert not records[0].raw.startswith("error_project_web")


def test_an_ordinary_line_with_a_pipe_is_not_mistaken_for_a_container_prefix():
    records = assemble_records(iter(["ERROR | cache miss storm"]), "demo", "app.log")
    assert records[0].container is None
    assert records[0].raw == "ERROR | cache miss storm"


# -- redaction ------------------------------------------------------------------

@pytest.mark.parametrize("line, secret", [
    ("connecting to postgres://app:s3cretpw@db:5432/app", "s3cretpw"),
    ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456", "abcdefghijklmnopqrstuvwxyz123456"),
    ('config loaded: {"api_key": "live-key-value-123"}', "live-key-value-123"),
    ("DB_PASSWORD=hunter2 retrying", "hunter2"),
    ("using key gsk_abcdefghijklmnopqrstuvwxyz0123456789", "gsk_abcdefghijklmnopqrstuvwxyz0123456789"),
])
def test_secrets_are_redacted(line, secret):
    out = redact(line)
    assert secret not in out
    assert "REDACTED" in out


def test_redaction_leaves_ordinary_diagnostics_alone():
    line = 'connection to server at "db" (172.18.0.2), port 5432 failed: Connection refused'
    assert redact(line) == line


def test_secrets_never_reach_a_record():
    records = assemble_records(iter(["ERROR login failed password=hunter2"]), "demo", "app.log")
    assert "hunter2" not in records[0].raw


# -- resolution memory short-circuit ---------------------------------------------

class _Containers(ContainerSource):
    async def containers_for(self, project):
        return [], "high"

    async def docker_available(self):
        return True

    async def logs_for(self, container_id, tail):
        return []


class _CountingProvider:
    name, model = "fake", "fake-1"

    def __init__(self):
        self.calls = 0

    async def analyze(self, bundle):
        self.calls += 1
        return _analysis("backend", "worker ran out of memory", confidence=0.9)


class _Sink(ReportSink):
    def __init__(self, store):
        self.findings, self._store = [], store

    async def emit(self, finding):
        self.findings.append(finding)
        self._store.record_incident(finding.fingerprint, finding.analysis, finding.provider, finding.model)


@pytest.mark.asyncio
async def test_resolved_fingerprint_is_answered_from_memory_without_an_llm_call(tmp_path):
    config = AgentConfig(home=tmp_path)
    config.ratelimit.cooldown_seconds = 0
    store = ProjectStore(tmp_path / "state.db")
    provider, sink = _CountingProvider(), _Sink(store)
    pipeline = ProjectPipeline("demo", config, store, SlidingWindow(), None,
                                RateLimiter(config.ratelimit, store), provider, sink, _Containers())
    record = LogRecord(project="demo", source="app.log", raw="ERROR worker died unexpectedly",
                        ts=time.time(), severity=Severity.ERROR)

    first = await pipeline.process(record)
    assert provider.calls == 1 and first.provider == "fake"

    store.resolve_fingerprint(first.fingerprint, "raised the worker memory limit to 512m")
    second = await pipeline.process(record)

    assert provider.calls == 1, "a resolved fingerprint must not reach the LLM again"
    assert second.provider == "memory"
    assert "raised the worker memory limit to 512m" in second.analysis.fix_suggestion
    assert "worker ran out of memory" in second.analysis.root_cause
    assert store.analyses_last_hour() == 1, "memory answers don't consume the LLM hourly cap"
    store.close()


@pytest.mark.asyncio
async def test_memory_shortcut_can_be_turned_off(tmp_path):
    config = AgentConfig(home=tmp_path)
    config.ratelimit.cooldown_seconds = 0
    config.memory.reuse_resolutions = False
    store = ProjectStore(tmp_path / "state.db")
    provider = _CountingProvider()
    pipeline = ProjectPipeline("demo", config, store, SlidingWindow(), None,
                                RateLimiter(config.ratelimit, store), provider, _Sink(store), _Containers())
    record = LogRecord(project="demo", source="app.log", raw="ERROR worker died unexpectedly",
                        ts=time.time(), severity=Severity.ERROR)

    first = await pipeline.process(record)
    store.resolve_fingerprint(first.fingerprint, "a note")
    await pipeline.process(record)

    assert provider.calls == 2
    store.close()


# -- retention -------------------------------------------------------------------

def test_prune_drops_old_history_but_keeps_resolutions(tmp_path):
    store = ProjectStore(tmp_path / "state.db")
    old = time.time() - 40 * 86400
    for fp in ("old-unresolved", "old-resolved", "recent"):
        store.touch_fingerprint(fp, "t", "generic")
        store.record_incident(fp, _analysis("x", "y"), "fake", "m")
    store.resolve_fingerprint("old-resolved", "fixed it")
    with store._conn:
        store._conn.execute("UPDATE incidents SET created_at = ? WHERE fingerprint LIKE 'old-%'", (old,))
        store._conn.execute("UPDATE fingerprints SET last_seen = ? WHERE fingerprint LIKE 'old-%'", (old,))

    pruned = store.prune(retention_days=30)

    assert pruned["incidents"] == 2 and pruned["fingerprints"] == 1
    assert store.get_prior("old-unresolved") is None
    assert store.get_prior("old-resolved").resolution == "fixed it"
    assert len(store.recent_incidents()) == 1
    store.close()


# -- what gets analysed at all ---------------------------------------------------

async def _run(tmp_path, records):
    config = AgentConfig(home=tmp_path)
    store = ProjectStore(tmp_path / "state.db")
    provider = _CountingProvider()
    pipeline = ProjectPipeline("demo", config, store, SlidingWindow(), None,
                                RateLimiter(config.ratelimit, store), provider, _Sink(store), _Containers())
    findings = [await pipeline.process(r) for r in records]
    store.close()
    return provider, findings


@pytest.mark.asyncio
async def test_unclassified_warning_is_tracked_but_not_analysed(tmp_path):
    notice = LogRecord(project="demo", source="container:redis", ts=NOW, severity=Severity.WARNING,
                        raw="# Warning: no config file specified, using the default config",
                        container="redis")
    provider, findings = await _run(tmp_path, [notice])
    assert provider.calls == 0 and findings == [None]


@pytest.mark.asyncio
async def test_classified_warning_is_still_analysed(tmp_path):
    warning = LogRecord(project="demo", source="container:web", ts=NOW, severity=Severity.WARNING,
                         raw="WARNING upstream request timed out after 30s", container="web")
    provider, _ = await _run(tmp_path, [warning])
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_docker_event_repeating_a_just_analysed_log_signal_is_dropped(tmp_path):
    from systemlens.containers.events import ContainerEvent, event_to_record
    log_line = LogRecord(project="demo", source="container:api", ts=NOW, event_ts=NOW,
                          raw="ERROR api: health check failed: upstream unavailable",
                          severity=Severity.ERROR, container="api")
    same_issue = event_to_record("demo", ContainerEvent("unhealthy", "id1", "api", None, NOW + 12))
    other_container = event_to_record("demo", ContainerEvent("unhealthy", "id2", "worker", None, NOW + 12))

    provider, findings = await _run(tmp_path, [log_line, same_issue, other_container])

    assert provider.calls == 2
    assert findings[1] is None and findings[2] is not None


@pytest.mark.asyncio
async def test_muted_issue_is_counted_but_never_analysed(tmp_path):
    config = AgentConfig(home=tmp_path)
    store = ProjectStore(tmp_path / "state.db")
    provider = _CountingProvider()
    pipeline = ProjectPipeline("demo", config, store, SlidingWindow(), None,
                                RateLimiter(config.ratelimit, store), provider, _Sink(store), _Containers())
    record = LogRecord(project="demo", source="app.log", raw="ERROR nightly job exited non-zero",
                        ts=time.time(), severity=Severity.ERROR)
    fingerprint = to_signal(record).fingerprint
    store.touch_fingerprint(fingerprint, "t", "generic")
    store.set_muted(fingerprint, True)

    assert await pipeline.process(record) is None
    assert provider.calls == 0
    pipeline.flush_counts()
    assert store.get_prior(fingerprint).occurrences == 2, "still counted"
    store.close()


@pytest.mark.asyncio
async def test_inconclusive_answer_is_escalated_to_the_investigator_when_enabled(tmp_path):
    from systemlens.agents.investigator import Investigation
    from systemlens.core.analysis import Checked

    class _Unsure:
        name, model = "fake", "fake-1"

        async def analyze(self, bundle):
            return _analysis("unknown", "cannot tell", verdict="insufficient_evidence", confidence=0.0)

    class _Investigator:
        calls = 0

        async def investigate(self, bundle, first):
            self.calls += 1
            return Investigation(Checked(_analysis("web", "REDIS_HOST points at a host that does not exist",
                                                   verdict="probable_cause", confidence=0.7)), ["compose_file()"])

    for auto, expected_provider, expected_calls in ((False, "fake", 0), (True, "fake+investigator", 1)):
        config = AgentConfig(home=tmp_path / str(auto))
        config.investigator.auto = auto
        store = ProjectStore(tmp_path / f"{auto}.db")
        investigator, sink = _Investigator(), _Sink(store)
        pipeline = ProjectPipeline("demo", config, store, SlidingWindow(), None,
                                    RateLimiter(config.ratelimit, store), _Unsure(), sink, _Containers(),
                                    investigator=investigator)
        finding = await pipeline.process(LogRecord(project="demo", source="app.log", ts=time.time(),
                                                    raw="ERROR could not resolve upstream", severity=Severity.ERROR))
        assert (finding.provider, investigator.calls) == (expected_provider, expected_calls)
        store.close()
