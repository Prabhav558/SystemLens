"""Regression tests for the 10 bugs found in code review, one test (or
tight group) per fix. Each test fails against the pre-fix code and passes
against the fix — see the review findings for the failure scenario each one
locks in.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

import pytest

from systemlens.containers.client import DockerClient, DockerUnavailable
from systemlens.core.models import Analysis, EvidenceBundle, LogRecord, Severity, Signal
from systemlens.containers.inspect import ContainerState
from systemlens.core.correlate import rule_r4_health
from systemlens.core.daemon import AgentDaemon, ContainerRegistry
from systemlens.core.ratelimit import _today_start
from systemlens.logs.parse import _parse_ts
from systemlens.logs.watcher import ProjectWatcher, matches_log_glob
from systemlens.memory.store import ProjectStore
from systemlens.memory.vector import VectorIndex
from systemlens.projects.registry import ProjectEntry


# -- fix 1: offsets saved under the real file path, not one shared key -----

@pytest.mark.asyncio
async def test_agent_daemon_stop_saves_offsets_under_real_path(tmp_path):
    """Exercises the real AgentDaemon.stop() method directly (not a
    reimplementation of it), with the heavy parts (Docker, LLM, watchdog
    Observer) never started so this stays a fast, deterministic unit test.
    """
    from systemlens.config import AgentConfig
    from systemlens.projects.registry import ProjectEntry, ProjectRegistry

    proj_root = tmp_path / "proj"
    proj_root.mkdir()
    log_file = proj_root / "app.log"
    log_file.write_text("line1\n")

    config = AgentConfig(home=tmp_path / "home")
    registry = ProjectRegistry(config)
    entry = ProjectEntry(name="demo", root=proj_root, log_globs=["*.log"])
    registry.add(entry)

    daemon = AgentDaemon(config, registry)
    store = ProjectStore(config.project_dir("demo") / "state.db")
    daemon._stores["demo"] = store

    watcher = ProjectWatcher("demo", entry.root, entry.log_globs, daemon._queue)
    watcher._register(log_file)
    watcher._tailers[str(log_file)].poll()  # prime past pre-existing content
    daemon._watchers["demo"] = watcher

    db_path = config.project_dir("demo") / "state.db"
    await daemon.stop()  # the real fixed method — closes the store, like a real shutdown

    # reopen fresh, like the daemon does on its next start() — proves the
    # offsets actually landed on disk under the real path, not just in memory
    reopened = ProjectStore(db_path)
    loaded = reopened.load_all_offsets()
    assert str(log_file) in loaded
    assert "__snapshot__" not in loaded

    with open(log_file, "a") as f:
        f.write("line2 written while stopped\n")

    resumed = ProjectWatcher("demo", entry.root, entry.log_globs, asyncio.Queue(), offsets=loaded)
    resumed._register(log_file)
    assert resumed._tailers[str(log_file)].poll() == ["line2 written while stopped"]
    reopened.close()


# -- fix 2: is_available() re-verifies instead of caching forever ----------

def test_docker_availability_recovers_after_coming_back_up(monkeypatch):
    client = DockerClient()
    calls = {"n": 0}

    def flaky_connect(self):
        calls["n"] += 1
        if calls["n"] == 1:
            self._available = False
            raise DockerUnavailable("down")
        self._available = True
        self._client = object()
        return self._client

    monkeypatch.setattr(DockerClient, "_connect", flaky_connect)
    assert client.is_available() is False
    assert client.is_available() is True  # must re-check, not return the stale False


# -- fix 3: absolute glob patterns containing "**" actually match ----------

def test_absolute_glob_with_double_star_matches_files(tmp_path):
    log_dir = tmp_path / "nested" / "logs"
    log_dir.mkdir(parents=True)
    log_file = log_dir / "app.log"
    log_file.write_text("hello\n")

    pattern = str(tmp_path / "**" / "*.log")
    watcher = ProjectWatcher("demo", tmp_path, [pattern], asyncio.Queue())
    found = watcher._resolve_globs()
    assert log_file in found


# -- fix 4: syslog timestamps are actually parsed, not silently dropped ----

def test_syslog_timestamp_is_parsed():
    line = "Jan  2 15:04:05 myapp: connection refused"
    ts = _parse_ts(line)
    assert ts is not None
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    assert (dt.month, dt.day, dt.hour, dt.minute, dt.second) == (1, 2, 15, 4, 5)


# -- fix 5: daily budget rollover uses true UTC midnight, not local mktime -

def test_today_start_is_exact_utc_midnight_regardless_of_local_tz():
    """This sandbox's local TZ is UTC, where the old time.mktime(gmtime())
    bug coincidentally produced the right answer — so the only way to
    actually catch it is to force a non-UTC local TZ for the duration of
    the check, which is exactly the condition the bug report describes.
    """
    import os as _os
    import time as _time

    original_tz = _os.environ.get("TZ")
    try:
        _os.environ["TZ"] = "America/New_York"  # UTC-4/UTC-5, unambiguous non-UTC offset
        _time.tzset()

        start = _today_start()
        dt = datetime.fromtimestamp(start, tz=timezone.utc)
        assert (dt.hour, dt.minute, dt.second, dt.microsecond) == (0, 0, 0, 0)
        now = datetime.now(timezone.utc)
        assert (dt.year, dt.month, dt.day) == (now.year, now.month, now.day)
    finally:
        if original_tz is None:
            _os.environ.pop("TZ", None)
        else:
            _os.environ["TZ"] = original_tz
        _time.tzset()


# -- fix 6: R4 distinguishes unhealthy vs starting instead of dead logic ---

def _container(health):
    return ContainerState(
        id="c1", name="flaky", image="x", status="running", running=True,
        exit_code=None, started_at=0.0, finished_at=None, oom_killed=False,
        restart_count=0, health=health,
    )


def test_r4_unhealthy_and_starting_both_fire_with_different_confidence():
    unhealthy = rule_r4_health([_container("unhealthy")])
    starting = rule_r4_health([_container("starting")])
    healthy = rule_r4_health([_container("healthy")])

    assert len(unhealthy) == 1 and len(starting) == 1
    assert healthy == []
    assert unhealthy[0].confidence > starting[0].confidence


# -- fix 7: the broken duplicate add_project_live is gone ------------------

def test_container_registry_has_no_broken_duplicate_method():
    assert not hasattr(ContainerRegistry, "add_project_live")


# -- fix 8: rate-limited signals never pay for container log fetches -------

@pytest.mark.asyncio
async def test_ratelimited_signal_skips_container_log_fetch(tmp_path):
    from systemlens.config import AgentConfig
    from systemlens.core.models import Analysis, EvidenceBundle, LogRecord, Severity
    from systemlens.core.pipeline import ContainerSource, ProjectPipeline
    from systemlens.core.ratelimit import RateLimiter
    from systemlens.core.sinks import ReportSink

    now = time.time()
    recently_exited = ContainerState(
        id="c1", name="db", image="x", status="exited", running=False,
        exit_code=1, started_at=now - 30, finished_at=now - 5, oom_killed=False,
        restart_count=0, health=None,
    )

    class CountingContainerSource(ContainerSource):
        def __init__(self):
            self.logs_for_calls = 0

        async def containers_for(self, project):
            # Recently exited -> R2 matches it, so the log-fetch relevance
            # filter (pipeline.py) actually includes it, keeping this test
            # a faithful check of rate-limiting behavior rather than a
            # no-op where nothing was ever relevant to begin with.
            return [recently_exited], "high"

        async def docker_available(self):
            return True

        async def logs_for(self, container_id, tail):
            self.logs_for_calls += 1
            return ["log line"]

    class FakeProvider:
        name, model = "fake", "fake-model-1"

        async def analyze(self, bundle: EvidenceBundle) -> Analysis:
            return Analysis(verdict="probable_cause", root_cause="x",
                             affected_component="x", fix_suggestion="x", confidence=0.5)

    class NullSink(ReportSink):
        async def emit(self, finding):
            pass

    config = AgentConfig(home=tmp_path)
    store = ProjectStore(tmp_path / "state.db")
    from systemlens.memory.window import SlidingWindow
    containers_src = CountingContainerSource()
    pipeline = ProjectPipeline("demo", config, store, SlidingWindow(), None,
                                RateLimiter(config.ratelimit, store), FakeProvider(),
                                NullSink(), containers_src)

    record = LogRecord(project="demo", source="app.log", raw="ERROR connection refused to db:5432",
                        ts=time.time(), event_ts=time.time(), severity=Severity.ERROR)

    await pipeline.process(record)
    assert containers_src.logs_for_calls == 1

    for _ in range(10):
        await pipeline.process(record)  # same fingerprint -> on cooldown every time
    assert containers_src.logs_for_calls == 1  # never fetched again for suppressed analyses
    store.close()


# -- fix 9: matches_log delegates to the same function the watcher uses ----

def test_project_entry_matches_log_uses_shared_watcher_logic(tmp_path):
    entry = ProjectEntry(name="demo", root=tmp_path, log_globs=["*.log"])
    path = tmp_path / "app.log"
    assert entry.matches_log(path) == matches_log_glob(path, ["*.log"])
    assert entry.matches_log(path) is True


# -- fix 10: VectorIndex no longer accepts/writes a disk index path --------

def test_vector_index_has_no_disk_path_param(tmp_path):
    with pytest.raises(TypeError):
        VectorIndex(embedder=None, index_path=tmp_path / "vectors.faiss")  # type: ignore[call-arg]


# -- fix 11: the Groq provider doesn't crash the daemon when the configured
# -- API key env var is unset (found via live testing, not the original
# -- static review) -------------------------------------------------------

def test_groq_provider_construction_survives_missing_api_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    from systemlens.llm.groq_provider import GroqProvider
    provider = GroqProvider(model="openai/gpt-oss-120b", api_key_env="GROQ_API_KEY")
    assert provider.name == "groq"


# -- fix 12: a failing LLM call still consumes rate-limit budget (found live
# -- against a real, persistently-invalid Groq key: 63 unthrottled retries) -

@pytest.mark.asyncio
async def test_failing_llm_call_engages_cooldown_and_hourly_cap(tmp_path):
    from systemlens.config import AgentConfig
    from systemlens.core.models import EvidenceBundle, LogRecord, Severity
    from systemlens.core.pipeline import ContainerSource, ProjectPipeline
    from systemlens.core.ratelimit import RateLimiter
    from systemlens.core.sinks import ReportSink
    from systemlens.memory.window import SlidingWindow

    class EmptyContainerSource(ContainerSource):
        async def containers_for(self, project):
            return [], "high"

        async def docker_available(self):
            return False

        async def logs_for(self, container_id, tail):
            return []

    class AlwaysFailingProvider:
        name, model = "fake", "fake-model-1"

        def __init__(self):
            self.calls = 0

        async def analyze(self, bundle: EvidenceBundle):
            self.calls += 1
            raise RuntimeError("simulated auth failure")

    class NullSink(ReportSink):
        async def emit(self, finding):
            pass

    config = AgentConfig(home=tmp_path)
    store = ProjectStore(tmp_path / "state.db")
    provider = AlwaysFailingProvider()
    pipeline = ProjectPipeline("demo", config, store, SlidingWindow(), None,
                                RateLimiter(config.ratelimit, store), provider,
                                NullSink(), EmptyContainerSource())

    record = LogRecord(project="demo", source="app.log", raw="ERROR timeout talking to db",
                        ts=time.time(), event_ts=time.time(), severity=Severity.ERROR)

    for _ in range(20):
        try:
            await pipeline.process(record)
        except RuntimeError:
            pass

    # cooldown engaged after the first failure -> every later occurrence of
    # the same fingerprint was suppressed before ever reaching the provider
    assert provider.calls == 1
    assert store.attempts_last_hour() == 1
    store.close()


# -- fix 13: strict JSON schema mode requires every property in `required`,
# -- not just the ones without a Pydantic default (found live against a real
# -- Groq API call: openai.BadRequestError on evidence/unverified_assumptions) -

def test_strict_json_schema_requires_every_property_including_defaulted_ones():
    from systemlens.llm.base import strict_json_schema

    schema = strict_json_schema(Analysis)
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"].keys())
    # the two fields that actually triggered the live failure
    assert "evidence" in schema["required"]
    assert "unverified_assumptions" in schema["required"]


# -- fix 14: container logs are only fetched for containers the correlator
# -- actually flagged as relevant, not every mapped container (found live:
# -- a 7-container project sent ~11.5K tokens against Groq's 8K TPM cap) ---

@pytest.mark.asyncio
async def test_container_logs_only_fetched_for_relevant_containers(tmp_path):
    from systemlens.config import AgentConfig
    from systemlens.core.models import Analysis, EvidenceBundle, LogRecord, Severity
    from systemlens.core.pipeline import ContainerSource, ProjectPipeline
    from systemlens.core.ratelimit import RateLimiter
    from systemlens.core.sinks import ReportSink
    from systemlens.memory.window import SlidingWindow

    now = time.time()
    relevant = ContainerState(id="c-db", name="db", image="x", status="exited", running=False,
                               exit_code=1, started_at=now - 30, finished_at=now - 5,
                               oom_killed=False, restart_count=0, health=None)
    irrelevant = ContainerState(id="c-idle", name="idle-service", image="x", status="running",
                                 running=True, exit_code=None, started_at=now - 1000,
                                 finished_at=None, oom_killed=False, restart_count=0, health="healthy")

    class RecordingContainerSource(ContainerSource):
        def __init__(self):
            self.fetched_ids: list[str] = []

        async def containers_for(self, project):
            return [relevant, irrelevant], "high"

        async def docker_available(self):
            return True

        async def logs_for(self, container_id, tail):
            self.fetched_ids.append(container_id)
            return ["log line"]

    class FakeProvider:
        name, model = "fake", "fake-model-1"

        async def analyze(self, bundle: EvidenceBundle) -> Analysis:
            return Analysis(verdict="probable_cause", root_cause="x",
                             affected_component="x", fix_suggestion="x", confidence=0.5)

    class NullSink(ReportSink):
        async def emit(self, finding):
            pass

    config = AgentConfig(home=tmp_path)
    store = ProjectStore(tmp_path / "state.db")
    containers_src = RecordingContainerSource()
    pipeline = ProjectPipeline("demo", config, store, SlidingWindow(), None,
                                RateLimiter(config.ratelimit, store), FakeProvider(),
                                NullSink(), containers_src)

    record = LogRecord(project="demo", source="app.log", raw="ERROR connection refused to db:5432",
                        ts=now, event_ts=now, severity=Severity.ERROR)
    await pipeline.process(record)

    assert containers_src.fetched_ids == ["c-db"]  # never "c-idle" — R2 didn't flag it
    store.close()


# -- fix 15: a giant multi-line record (an unbounded traceback fold) can no
# -- longer blow the whole evidence budget on its own (found live: a Flask
# -- traceback pushed a single request to ~9.8K tokens against an 8K cap) --

def test_continuation_fold_is_capped(tmp_path):
    from systemlens.logs.parse import MAX_FOLDED_LINES, assemble_records

    huge_traceback = ["Traceback (most recent call last):"] + [
        f'  File "app.py", line {i}, in handler' for i in range(500)
    ]
    records = assemble_records(iter(huge_traceback), "demo", "app.log")
    assert len(records) == 1
    assert records[0].lines <= MAX_FOLDED_LINES


def test_render_evidence_never_exceeds_hard_budget():
    from systemlens.llm.prompt import _MAX_EVIDENCE_CHARS, render_evidence

    huge_record = LogRecord(project="demo", source="app.log",
                             raw="x" * 2000, ts=time.time(), severity=Severity.ERROR)
    signal = Signal(record=huge_record, template="x", fingerprint="fp1", category="generic")
    # simulate many "relevant" containers each with noisy logs
    containers = [_container("healthy") for _ in range(20)]
    container_logs = {c.name: [f"noisy log line {i}" * 20 for i in range(10)] for c in containers}
    bundle = EvidenceBundle(project="demo", signal=signal, occurrences=1,
                             log_window=[huge_record] * 50, containers=containers,
                             container_logs=container_logs, docker_available=True)

    rendered = render_evidence(bundle)
    assert len(rendered) <= _MAX_EVIDENCE_CHARS + 500  # small headroom for the truncation marker itself
