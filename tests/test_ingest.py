"""Phase 1: container log streaming, Docker events as triggers, source
selection and the single-daemon lock. Docker itself is replaced by fakes;
the real daemon is exercised separately.
"""
from __future__ import annotations

import asyncio
import os

import pytest

from systemlens.containers.events import EventInterpreter, event_to_record
from systemlens.containers.logstream import ContainerLogStreamer, LineSplitter
from systemlens.core.lock import AlreadyRunning, DaemonLock, running_pid
from systemlens.core.models import ContainerState, Severity
from systemlens.logs.cluster import to_signal
from systemlens.projects.registry import build_project_entry


def _container(name, running=True, started_at=None):
    return ContainerState(id=f"id-{name}", name=name, image="x",
                          status="running" if running else "exited", running=running,
                          exit_code=None, started_at=started_at, finished_at=None,
                          oom_killed=False, restart_count=0, health=None)


# -- line splitting ------------------------------------------------------------

def test_line_splitter_reassembles_lines_split_across_chunks():
    splitter = LineSplitter()
    assert splitter.feed(b"2026-01-01T00:00:00Z first li") == []
    assert splitter.feed(b"ne\n2026-01-01T00:00:01Z second\npart") == [
        "2026-01-01T00:00:00Z first line", "2026-01-01T00:00:01Z second"]
    assert splitter.feed(b"ial\n") == ["partial"]


# -- streamer ------------------------------------------------------------------

class _FakeStream:
    def __init__(self, chunks):
        self._chunks, self.closed = chunks, False

    def __iter__(self):
        return iter(self._chunks)

    def close(self):
        self.closed = True


async def _drain(queue, expected, timeout=2.0):
    out = []
    while len(out) < expected:
        out.append(await asyncio.wait_for(queue.get(), timeout))
    return out


@pytest.mark.asyncio
async def test_streamer_turns_container_output_into_records_with_origin():
    queue: asyncio.Queue = asyncio.Queue()
    opened = []

    def open_stream(container_id, since):
        opened.append((container_id, since))
        return _FakeStream([
            b"2026-08-19T19:30:44.100000000Z ERROR web: Exception on /crash [GET]\n",
            b"2026-08-19T19:30:44.100000100Z Traceback (most recent call last):\n"
            b"2026-08-19T19:30:44.100000200Z KeyError: 'missing_key'\n",
            b"2026-08-19T19:30:45.000000000Z INFO web: recovered\n",
        ])

    streamer = ContainerLogStreamer("demo", open_stream, queue, asyncio.get_running_loop(), flush_delay=0.05)
    streamer.sync([_container("web"), _container("stopped", running=False)])

    records = await _drain(queue, 2)
    assert opened == [("id-web", None)], "only running containers are followed"
    assert [r.container for r in records] == ["web", "web"]
    assert records[0].lines == 3 and records[0].severity == Severity.ERROR
    assert to_signal(records[0]).category == "traceback"
    assert records[0].source == "container:web"
    assert streamer.snapshot()["web"] == pytest.approx(1787167845.0)
    streamer.stop()


@pytest.mark.asyncio
async def test_streamer_reattaches_after_a_restart_without_replaying_lines():
    queue: asyncio.Queue = asyncio.Queue()
    calls = []
    batches = [
        [b"2026-08-19T19:30:44.000000000Z ERROR web: first\n"],
        # Docker's `since` is inclusive: the last delivered line comes back
        [b"2026-08-19T19:30:44.000000000Z ERROR web: first\n",
         b"2026-08-19T19:30:50.000000000Z ERROR web: second\n"],
    ]

    def open_stream(container_id, since):
        calls.append(since)
        return _FakeStream(batches[len(calls) - 1])

    streamer = ContainerLogStreamer("demo", open_stream, queue, asyncio.get_running_loop(), flush_delay=0.05)
    web = _container("web")
    streamer.sync([web])
    first = await _drain(queue, 1)
    await asyncio.sleep(0.05)              # stream ended -> detached

    streamer.sync([web])                   # next registry refresh re-attaches
    second = await _drain(queue, 1)

    assert calls[0] is None and calls[1] == pytest.approx(1787167844.0)
    assert first[0].raw.endswith("first") and second[0].raw.endswith("second")
    assert queue.empty(), "the already-delivered line must not be delivered twice"
    streamer.stop()


@pytest.mark.asyncio
async def test_container_started_after_the_daemon_is_read_from_its_own_start():
    queue: asyncio.Queue = asyncio.Queue()
    calls = []

    def open_stream(container_id, since):
        calls.append((container_id, since))
        return _FakeStream([])

    streamer = ContainerLogStreamer("demo", open_stream, queue, asyncio.get_running_loop(), flush_delay=0.05)
    streamer.sync([_container("web", started_at=100.0)])        # present at startup: tail from now
    await asyncio.sleep(0.05)
    streamer.sync([_container("late", started_at=5000.0)])      # appeared later: from its start
    await asyncio.sleep(0.05)

    assert ("id-web", None) in calls
    assert ("id-late", 5000.0) in calls
    streamer.stop()


# -- docker events -----------------------------------------------------------------

def _event(action, cid="abc123def456", name="web", at=1000.0, **attrs):
    return {"Type": "container", "Action": action, "time": at,
            "Actor": {"ID": cid, "Attributes": {"name": name, **attrs}}}


def test_crash_is_reported():
    ev = EventInterpreter().interpret(_event("die", exitCode="1"))
    assert ev.kind == "exit" and ev.exit_code == 1 and ev.container_name == "web"


def test_clean_exit_is_not_a_failure():
    assert EventInterpreter().interpret(_event("die", exitCode="0")) is None


def test_deliberate_stop_is_not_a_failure():
    interp = EventInterpreter()
    assert interp.interpret(_event("kill", at=1000.0, signal="15")) is None
    assert interp.interpret(_event("die", at=1002.0, exitCode="143")) is None


def test_a_kill_long_ago_does_not_excuse_a_later_crash():
    interp = EventInterpreter()
    interp.interpret(_event("kill", at=1000.0))
    assert interp.interpret(_event("die", at=5000.0, exitCode="1")).kind == "exit"


def test_oom_then_die_is_reported_once_as_an_oom_kill():
    interp = EventInterpreter()
    assert interp.interpret(_event("oom", at=1000.0)) is None
    ev = interp.interpret(_event("die", at=1000.5, exitCode="137"))
    assert ev.kind == "oom" and ev.exit_code == 137


def test_only_the_unhealthy_transition_is_reported():
    interp = EventInterpreter()
    assert interp.interpret(_event("health_status: healthy")) is None
    assert interp.interpret(_event("health_status: unhealthy")).kind == "unhealthy"
    assert interp.interpret(_event("exec_start: /bin/sh -c health")) is None


def test_event_records_become_signals_with_the_right_category_and_origin():
    interp = EventInterpreter()
    interp.interpret(_event("oom", name="memory_hog"))
    oom = to_signal(event_to_record("demo", interp.interpret(_event("die", name="memory_hog", exitCode="137"))))
    crash = to_signal(event_to_record("demo", interp.interpret(_event("die", name="db", exitCode="1"))))
    sick = to_signal(event_to_record("demo", interp.interpret(_event("health_status: unhealthy", name="api"))))

    assert (oom.category, oom.record.container) == ("oom", "memory_hog")
    assert (crash.category, crash.record.container) == ("container_exit", "db")
    assert (sick.category, sick.record.container) == ("health_check", "api")
    # different exit codes of one container are the same recurring issue
    other = to_signal(event_to_record("demo", EventInterpreter().interpret(_event("die", name="db", exitCode="2"))))
    assert other.fingerprint == crash.fingerprint


# -- source selection ----------------------------------------------------------------

def test_compose_project_streams_containers_and_watches_no_files(tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services: {}\n")
    entry = build_project_entry(tmp_path)
    assert entry.stream_containers is True and entry.log_globs == []


def test_explicit_logs_keep_file_watching_and_do_not_double_ingest(tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services: {}\n")
    entry = build_project_entry(tmp_path, logs="./logs/*.log")
    assert entry.stream_containers is False and entry.log_globs == ["./logs/*.log"]


def test_project_without_compose_falls_back_to_log_files(tmp_path):
    entry = build_project_entry(tmp_path)
    assert entry.stream_containers is False and entry.log_globs


# -- daemon lock ----------------------------------------------------------------------

def test_lock_refuses_a_second_daemon_and_clears_on_exit(tmp_path):
    (tmp_path / "agent.pid").write_text(str(os.getppid()))      # a live, different process
    assert running_pid(tmp_path) == os.getppid()
    with pytest.raises(AlreadyRunning):
        DaemonLock(tmp_path).__enter__()

    (tmp_path / "agent.pid").write_text("999999999")            # stale pid
    assert running_pid(tmp_path) is None
    with DaemonLock(tmp_path):
        assert (tmp_path / "agent.pid").read_text() == str(os.getpid())
    assert not (tmp_path / "agent.pid").exists()
