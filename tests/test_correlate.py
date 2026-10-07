"""The engine. Golden fixtures: synthetic log window + container snapshot ->
asserted candidate rule IDs and ordering. No LLM anywhere in this file.
"""
from systemlens.core.correlate import correlate
from systemlens.core.models import ContainerState, EvidenceBundle, LogRecord, Severity
from systemlens.logs.cluster import to_signal


def _container(name, running, exit_code=None, finished_at=None, oom=False,
                health=None, compose_service=None, depends_on=None, aliases=None):
    return ContainerState(
        id=f"id-{name}", name=name, image=f"{name}:latest",
        status="running" if running else "exited", running=running,
        exit_code=exit_code, started_at=0.0, finished_at=finished_at,
        oom_killed=oom, restart_count=0, health=health,
        compose_service=compose_service or name, depends_on=depends_on or [],
        aliases=aliases or [name],
    )


def _bundle(signal, containers, prior=None):
    return EvidenceBundle(project="demo", signal=signal, occurrences=1,
                           containers=containers, prior=prior, docker_available=True)


def test_backend_connection_refused_correlates_to_stopped_db():
    """The spec's own success criterion:
    'Backend failed due to PostgreSQL container being down -> connection refused'
    """
    now = 1_000_000.0
    record = LogRecord(
        project="demo", source="backend.log",
        raw='connection to server at "db" (172.18.0.2), port 5432 failed: Connection refused',
        ts=now, event_ts=now, severity=Severity.ERROR,
    )
    signal = to_signal(record)
    containers = [
        _container("db", running=False, exit_code=0, finished_at=now - 4,
                    compose_service="db"),
        _container("backend", running=True, compose_service="backend", depends_on=["db"]),
    ]
    bundle = _bundle(signal, containers)
    candidates = correlate(bundle, window_seconds=120)

    rule_ids = {c.rule_id for c in candidates}
    assert "R1" in rule_ids, "should identify 'db' as the connection target"
    assert "R2" in rule_ids, "should notice db exited shortly before the error"
    assert "R5" in rule_ids, "should notice backend's compose dependency is down"

    top = candidates[0]
    assert top.component == "db"
    assert top.confidence >= 0.8


def test_running_healthy_target_gets_low_confidence():
    now = 1_000_000.0
    record = LogRecord(project="demo", source="backend.log",
                        raw='connect ECONNREFUSED to cache:6379', ts=now, event_ts=now,
                        severity=Severity.ERROR)
    signal = to_signal(record)
    containers = [_container("cache", running=True, compose_service="cache")]
    bundle = _bundle(signal, containers)
    candidates = correlate(bundle, window_seconds=120)

    r1 = next(c for c in candidates if c.rule_id == "R1")
    assert r1.confidence < 0.5, "a target that's actually running shouldn't look like the cause"


def test_oom_kill_of_the_origin_container_is_a_scoped_candidate():
    now = 1_000_000.0
    record = LogRecord(project="demo", source="container:worker", raw="ERROR worker unresponsive",
                        ts=now, event_ts=now, severity=Severity.ERROR, container="worker")
    signal = to_signal(record)
    containers = [_container("worker", running=False, exit_code=137, oom=True)]
    candidates = correlate(_bundle(signal, containers), window_seconds=120)

    oom = [c for c in candidates if c.rule_id == "R3"]
    assert len(oom) == 1
    assert oom[0].scoped and oom[0].confidence == 0.9


def test_oom_kill_of_an_unrelated_container_is_only_co_occurring():
    now = 1_000_000.0
    record = LogRecord(project="demo", source="container:web", raw="ERROR web: bad request body",
                        ts=now, event_ts=now, severity=Severity.ERROR, container="web")
    signal = to_signal(record)
    containers = [_container("web", running=True),
                  _container("worker", running=False, exit_code=137, oom=True)]
    candidates = correlate(_bundle(signal, containers), window_seconds=120)

    oom = next(c for c in candidates if c.rule_id == "R3")
    assert not oom.scoped
    assert oom.confidence <= 0.3


def test_exit_137_without_docker_oom_flag_is_not_called_an_oom_kill():
    now = 1_000_000.0
    record = LogRecord(project="demo", source="container:worker", raw="ERROR worker unresponsive",
                        ts=now, event_ts=now, severity=Severity.ERROR, container="worker")
    containers = [_container("worker", running=False, exit_code=137, oom=False)]
    candidates = correlate(_bundle(to_signal(record), containers), window_seconds=120)

    r3 = next(c for c in candidates if c.rule_id == "R3")
    assert r3.confidence == 0.5
    assert "not confirmed" in r3.summary


def test_unrelated_exit_is_not_offered_as_a_cause_of_a_health_check_failure():
    """The live failure this scoping exists for: a service whose own health
    endpoint always fails was blamed on a database that happened to exit.
    """
    now = 1_000_000.0
    record = LogRecord(project="demo", source="container:flaky_health", ts=now, event_ts=now,
                        raw="ERROR flaky-health: health check failed: dependency check did not pass",
                        severity=Severity.ERROR, container="flaky_health")
    containers = [_container("flaky_health", running=True, health="unhealthy"),
                  _container("db", running=False, exit_code=1, finished_at=now - 10)]
    candidates = correlate(_bundle(to_signal(record), containers), window_seconds=120)

    r4 = next(c for c in candidates if c.rule_id == "R4")
    r2 = next(c for c in candidates if c.rule_id == "R2")
    assert r4.scoped and r4.component == "flaky_health"
    assert not r2.scoped and r2.component == "db"
    assert candidates[0] is r4, "scoped candidates rank ahead of co-occurring facts"


def test_dependency_of_the_origin_is_linked():
    now = 1_000_000.0
    record = LogRecord(project="demo", source="container:web", raw="ERROR web: request failed",
                        ts=now, event_ts=now, severity=Severity.ERROR, container="web")
    containers = [_container("web", running=True, depends_on=["db"]),
                  _container("db", running=False, exit_code=1, finished_at=now - 10)]
    candidates = correlate(_bundle(to_signal(record), containers), window_seconds=120)

    assert next(c for c in candidates if c.rule_id == "R2").scoped
    assert next(c for c in candidates if c.rule_id == "R5").scoped


def test_no_origin_and_no_target_links_nothing():
    now = 1_000_000.0
    record = LogRecord(project="demo", source="app.log", raw="ERROR generic failure",
                        ts=now, event_ts=now, severity=Severity.ERROR)
    containers = [_container("db", running=False, exit_code=1, finished_at=now - 10)]
    candidates = correlate(_bundle(to_signal(record), containers), window_seconds=120)

    assert candidates and all(not c.scoped for c in candidates)


def test_exit_outside_window_is_not_a_candidate():
    now = 1_000_000.0
    record = LogRecord(project="demo", source="backend.log", raw="ERROR generic failure",
                        ts=now, event_ts=now, severity=Severity.ERROR)
    signal = to_signal(record)
    # exited 10 minutes before the error — outside the default 120s window
    containers = [_container("db", running=False, exit_code=0, finished_at=now - 600)]
    bundle = _bundle(signal, containers)
    candidates = correlate(bundle, window_seconds=120)

    assert not any(c.rule_id == "R2" for c in candidates)


def test_docker_unavailable_short_circuits_to_log_only():
    now = 1_000_000.0
    record = LogRecord(project="demo", source="backend.log",
                        raw='connection to server at "db", port 5432 failed', ts=now,
                        event_ts=now, severity=Severity.ERROR)
    signal = to_signal(record)
    bundle = EvidenceBundle(project="demo", signal=signal, occurrences=1,
                             containers=[], docker_available=False)
    candidates = correlate(bundle, window_seconds=120)

    assert len(candidates) == 1
    assert candidates[0].rule_id == "R0"
    assert candidates[0].confidence < 0.5


def test_prior_resolution_surfaces_as_r6_top_candidate():
    from systemlens.core.models import PriorIncident

    now = 1_000_000.0
    record = LogRecord(project="demo", source="backend.log", raw="ERROR generic failure",
                        ts=now, event_ts=now, severity=Severity.ERROR)
    signal = to_signal(record)
    prior = PriorIncident(fingerprint=signal.fingerprint, first_seen=now - 86400,
                           last_seen=now - 3600, occurrences=3,
                           resolution="bumped worker memory limit to 512m")
    bundle = _bundle(signal, containers=[], prior=prior)
    candidates = correlate(bundle, window_seconds=120)

    assert candidates[0].rule_id == "R6"
    assert candidates[0].confidence == 0.95


def test_candidates_sorted_by_confidence_descending():
    now = 1_000_000.0
    record = LogRecord(project="demo", source="backend.log",
                        raw='connection to server at "db", port 5432 failed', ts=now,
                        event_ts=now, severity=Severity.ERROR)
    signal = to_signal(record)
    containers = [_container("db", running=False, exit_code=1, finished_at=now - 2)]
    bundle = _bundle(signal, containers)
    candidates = correlate(bundle, window_seconds=120)

    scoped = [c.confidence for c in candidates if c.scoped]
    assert scoped == sorted(scoped, reverse=True)
    flags = [c.scoped for c in candidates]
    assert flags == sorted(flags, reverse=True), "scoped candidates come first"


def test_a_down_dependency_is_not_linked_to_an_unrelated_traceback():
    """Seen live: web depends on db, db had crashed, and a KeyError in one of
    web's handlers was blamed on db. A dependency explains failed connections,
    not arbitrary exceptions.
    """
    now = 1_000_000.0
    record = LogRecord(project="demo", source="container:web", ts=now, event_ts=now,
                        raw="ERROR web: Exception on /crash [GET]\nTraceback (most recent call last):\nKeyError: 'missing_key'",
                        severity=Severity.ERROR, container="web", lines=3)
    containers = [_container("web", running=True, depends_on=["db"]),
                  _container("db", running=False, exit_code=1, finished_at=now - 10)]
    candidates = correlate(_bundle(to_signal(record), containers), window_seconds=120)

    assert to_signal(record).category == "traceback"
    assert all(not c.scoped for c in candidates if c.component == "db")


def test_a_container_named_in_the_signal_is_linked_even_without_a_port():
    now = 1_000_000.0
    record = LogRecord(project="demo", source="container:web", ts=now, event_ts=now,
                        raw='ERROR web: could not translate host name "db" to address: Name or service not known',
                        severity=Severity.ERROR, container="web")
    signal = to_signal(record)
    containers = [_container("web", running=True),
                  _container("db", running=False, exit_code=1, finished_at=now - 10)]
    candidates = correlate(_bundle(signal, containers), window_seconds=120)

    assert signal.hints["host"] == "db"
    assert {c.rule_id for c in candidates if c.scoped and c.component == "db"} >= {"R1", "R2"}


def test_libpq_host_in_quotes_with_port_is_parsed():
    record = LogRecord(project="demo", source="x", ts=0.0, severity=Severity.ERROR,
                        raw='ERROR could not connect to server: Connection refused\n'
                            '\tIs the server running on host "db" (172.18.0.2), port 5432 and accepting')
    assert to_signal(record).hints == {"host": "db", "port": 5432}


def test_exit_recorded_a_moment_after_the_event_still_counts_as_recent():
    """A Docker `die` event and the container's FinishedAt are stamped
    separately; FinishedAt can be slightly later than the event.
    """
    now = 1_000_000.0
    record = LogRecord(project="demo", source="docker:events", ts=now, event_ts=now,
                        raw="container db exited unexpectedly with exit code 1",
                        severity=Severity.ERROR, container="db", category_hint="container_exit")
    containers = [_container("db", running=False, exit_code=1, finished_at=now + 0.4)]
    candidates = correlate(_bundle(to_signal(record), containers), window_seconds=120)

    r2 = next(c for c in candidates if c.rule_id == "R2")
    assert r2.scoped and "exited 0s before" in r2.summary
