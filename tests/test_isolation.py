"""Two projects with identical error text must produce separate DBs, separate
fingerprint rows, and zero cross-reads — the core isolation guarantee.
"""
from systemlens.core.models import Analysis, Severity
from systemlens.logs.cluster import to_signal
from systemlens.core.models import LogRecord
from systemlens.memory.store import ProjectStore


def _signal_for(project, text="ERROR connect ECONNREFUSED to db:5432"):
    record = LogRecord(project=project, source="app.log", raw=text, ts=0.0,
                        severity=Severity.ERROR)
    return to_signal(record)


def test_same_error_text_different_fingerprints_per_project():
    sig_a = _signal_for("project-a")
    sig_b = _signal_for("project-b")
    assert sig_a.fingerprint != sig_b.fingerprint


def test_separate_sqlite_files_no_cross_contamination(tmp_path):
    store_a = ProjectStore(tmp_path / "project-a" / "state.db")
    store_b = ProjectStore(tmp_path / "project-b" / "state.db")

    sig_a = _signal_for("project-a")
    sig_b = _signal_for("project-b")

    store_a.touch_fingerprint(sig_a.fingerprint, sig_a.template, sig_a.category)
    store_a.touch_fingerprint(sig_a.fingerprint, sig_a.template, sig_a.category)

    # project-b never touched — its DB must know nothing about project-a's fingerprint
    assert store_a.get_prior(sig_a.fingerprint).occurrences == 2
    assert store_b.get_prior(sig_a.fingerprint) is None
    assert store_b.get_prior(sig_b.fingerprint) is None

    analysis = Analysis(verdict="root_cause_identified", root_cause="x",
                         affected_component="db", evidence=[], fix_suggestion="y",
                         confidence=0.9)
    store_a.record_incident(sig_a.fingerprint, analysis, "fake", "fake-model")
    assert len(store_a.recent_incidents()) == 1
    assert len(store_b.recent_incidents()) == 0

    store_a.close()
    store_b.close()

    # on-disk files are genuinely separate
    assert (tmp_path / "project-a" / "state.db").exists()
    assert (tmp_path / "project-b" / "state.db").exists()


def test_resolution_only_visible_within_owning_project(tmp_path):
    store_a = ProjectStore(tmp_path / "a" / "state.db")
    store_b = ProjectStore(tmp_path / "b" / "state.db")
    sig_a = _signal_for("a")

    store_a.touch_fingerprint(sig_a.fingerprint, sig_a.template, sig_a.category)
    store_a.resolve_fingerprint(sig_a.fingerprint, "restarted db container")

    assert store_a.get_prior(sig_a.fingerprint).resolution == "restarted db container"
    # resolving in A must not create or leak a row in B
    assert store_b.resolve_fingerprint(sig_a.fingerprint, "should not apply") is False
    assert store_b.get_prior(sig_a.fingerprint) is None

    store_a.close()
    store_b.close()
