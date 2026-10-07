"""Template mining: variable-heavy lines collapse to one fingerprint; genuinely
different errors do not.
"""
from systemlens.core.models import LogRecord, Severity
from systemlens.logs.cluster import categorize, extract_hints, make_template, to_signal


def test_uuid_and_timestamp_collapse_to_same_template():
    a = "2026-08-18T10:22:31Z ERROR request abc12345-1111-2222-3333-444455556666 failed"
    b = "2026-08-18T10:23:02Z ERROR request ffffffff-0000-1111-2222-333344445555 failed"
    assert make_template(a) == make_template(b)


def test_different_error_types_do_not_collapse():
    a = "ERROR connection refused to db:5432"
    b = "ERROR permission denied writing /var/log/app.log"
    assert make_template(a) != make_template(b)


def test_numbers_and_ips_are_masked():
    t = make_template("ERROR failed after 3 retries to 10.0.0.5:5432")
    assert "3" not in t
    assert "10.0.0.5" not in t
    assert "<num>" in t
    assert "<ip>" in t


def test_categorize_connection_refused():
    assert categorize("connect ECONNREFUSED 127.0.0.1:5432") == "connection_refused"


def test_categorize_oom():
    assert categorize("Out of memory: Killed process 123 (worker)") == "oom"


def test_categorize_generic_fallback():
    assert categorize("something mildly unusual happened") == "generic"


def test_extract_hints_host_port():
    hints = extract_hints('connection to server at "db", port 5432 failed')
    assert hints.get("port") == 5432


def test_to_signal_filters_info_severity():
    record = LogRecord(project="p", source="s", raw="INFO all good", ts=0.0, severity=Severity.INFO)
    assert to_signal(record) is None


def test_to_signal_keeps_warning_and_above():
    record = LogRecord(project="p", source="s", raw="WARNING disk nearly full", ts=0.0,
                        severity=Severity.WARNING)
    sig = to_signal(record)
    assert sig is not None
    assert sig.fingerprint


def test_fingerprint_stable_across_variable_values():
    r1 = LogRecord(project="demo", source="s",
                    raw="ERROR connect ECONNREFUSED 10.0.0.1:5432", ts=0.0, severity=Severity.ERROR)
    r2 = LogRecord(project="demo", source="s",
                    raw="ERROR connect ECONNREFUSED 10.0.0.9:5432", ts=1.0, severity=Severity.ERROR)
    assert to_signal(r1).fingerprint == to_signal(r2).fingerprint


def test_fingerprint_differs_across_projects():
    r1 = LogRecord(project="proj-a", source="s", raw="ERROR boom", ts=0.0, severity=Severity.ERROR)
    r2 = LogRecord(project="proj-b", source="s", raw="ERROR boom", ts=0.0, severity=Severity.ERROR)
    assert to_signal(r1).fingerprint != to_signal(r2).fingerprint


def test_extract_hints_psycopg2_style_message():
    hints = extract_hints('connection to server at "db" (172.18.0.2), port 5432 failed: Connection refused')
    assert hints == {"host": "db", "port": 5432}


def test_a_timestamp_is_not_mistaken_for_host_and_port():
    """Seen live: '10:43:01' at the start of a line was parsed as host 10,
    port 43, so the real target later in the line was never looked up.
    """
    from systemlens.logs.cluster import extract_hints
    line = "2026-10-07 10:43:01,327 ERROR dependent-svc: failed to reach flaky_health:5000 - [Errno 111] Connection refused"
    assert extract_hints(line) == {"host": "flaky_health", "port": 5000}

    dns = '2026-10-07 10:43:59,317 ERROR worker: could not translate host name "db" to address'
    assert extract_hints(dns) == {"host": "db"}

    assert extract_hints("ERROR connect ECONNREFUSED 10.0.0.2:5432") == {"host": "10.0.0.2", "port": 5432}
