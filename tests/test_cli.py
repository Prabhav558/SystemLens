"""The command line, driven in-process. Each test gets its own home
directory through SYSTEMLENS_HOME, exactly as a user would set it.
"""
from __future__ import annotations

import json
import time

import pytest
from typer.testing import CliRunner

from systemlens.cli.main import app
from systemlens.config import AgentConfig
from systemlens.core.models import Analysis
from systemlens.memory.store import ProjectStore

runner = CliRunner()


@pytest.fixture()
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("SYSTEMLENS_HOME", str(home))
    monkeypatch.setenv("COLUMNS", "200")
    for var in ("SYSTEMLENS_SLACK_WEBHOOK", "SYSTEMLENS_DISCORD_WEBHOOK", "SYSTEMLENS_WEBHOOK_URL"):
        monkeypatch.delenv(var, raising=False)
    return home


@pytest.fixture()
def project(home, tmp_path):
    """A registered compose project with two analysed issues."""
    root = tmp_path / "shop"
    root.mkdir()
    (root / "docker-compose.yml").write_text("services:\n  db:\n    image: postgres\n  web:\n    image: x\n")
    assert runner.invoke(app, ["add-project", str(root)]).exit_code == 0
    store = ProjectStore(AgentConfig.load().project_dir("shop") / "state.db")
    for fp, fix in (("aaaa1111", "docker compose up -d db"), ("bbbb2222", "rewrite the handler")):
        store.touch_fingerprint(fp, f"template {fp}", "connection_refused")
        store.record_incident(fp, Analysis(verdict="root_cause_identified", root_cause=f"cause {fp}",
                                           affected_component="db", fix_suggestion=fix, confidence=0.9),
                              "fake", "m")
    store.close()
    return root


def _store():
    return ProjectStore(AgentConfig.load().project_dir("shop") / "state.db")


def test_add_list_and_remove_a_project(home, tmp_path):
    root = tmp_path / "shop"
    root.mkdir()
    (root / "compose.yaml").write_text("services: {}\n")

    added = runner.invoke(app, ["add-project", str(root)])
    assert added.exit_code == 0 and "docker container logs" in added.output
    assert runner.invoke(app, ["add-project", str(root)]).exit_code == 1, "registering twice is refused"
    assert "shop" in runner.invoke(app, ["projects"]).output

    removed = runner.invoke(app, ["remove-project", "shop", "--purge"])
    assert removed.exit_code == 0 and not (home / "projects" / "shop").exists()
    assert runner.invoke(app, ["remove-project", "shop"]).exit_code == 1


def test_up_refuses_a_directory_with_nothing_to_watch(home, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    result = runner.invoke(app, ["up", str(empty)])
    assert result.exit_code == 1 and "nothing to watch" in result.output.replace("\n", " ")


def test_findings_and_status_as_json(project):
    found = json.loads(runner.invoke(app, ["findings", "--json"]).output)
    assert {f["fingerprint"] for f in found} == {"aaaa1111", "bbbb2222"}
    assert all("analysis_json" not in f for f in found)

    status = json.loads(runner.invoke(app, ["status", "--json"]).output)
    assert status["projects"][0]["findings_24h"] == 2 and status["daemon_pid"] is None


def test_explain_accepts_a_prefix_and_rejects_ambiguity(project):
    one = runner.invoke(app, ["explain", "aaaa"])
    assert one.exit_code == 0 and "cause aaaa1111" in one.output
    assert runner.invoke(app, ["explain", "zzzz"]).exit_code == 1
    assert "ambiguous" in runner.invoke(app, ["explain", ""]).output


def test_fix_proposes_by_default_and_never_runs_unless_enabled(project):
    shown = runner.invoke(app, ["fix", "aaaa"])
    assert shown.exit_code == 0 and "safe" in shown.output and "Nothing was run" in shown.output
    assert _store().fixes() == []

    refused = runner.invoke(app, ["fix", "aaaa", "--run", "--yes"])
    assert refused.exit_code == 1 and "execution is off" in refused.output

    review = runner.invoke(app, ["fix", "bbbb"])
    assert "manual" in review.output


def test_applied_fix_is_tracked_then_verified_into_a_resolution(project):
    assert runner.invoke(app, ["fix", "aaaa", "--applied"]).exit_code == 0
    assert "pending" in runner.invoke(app, ["fixes"]).output

    store = _store()
    with store._conn:      # pretend it was applied 20 minutes ago, with no recurrence since
        store._conn.execute("UPDATE fixes SET applied_at = ?", (time.time() - 1200,))
        store._conn.execute("UPDATE fingerprints SET last_seen = ?", (time.time() - 1500,))
    store.close()

    assert "verified" in runner.invoke(app, ["fixes"]).output
    assert _store().get_prior("aaaa1111").resolution == "docker compose up -d db"


def test_resolve_mute_and_unmute(project):
    assert runner.invoke(app, ["resolve", "bbbb", "--note", "handler rewritten"]).exit_code == 0
    assert _store().get_prior("bbbb2222").resolution == "handler rewritten"

    assert runner.invoke(app, ["mute", "aaaa"]).exit_code == 0
    assert _store().muted_fingerprints() == {"aaaa1111"}
    assert runner.invoke(app, ["unmute", "aaaa"]).exit_code == 0
    assert _store().muted_fingerprints() == set()


def test_digest_and_watch_snapshot(project):
    digest = runner.invoke(app, ["digest"])
    assert digest.exit_code == 0 and "new issues (2)" in digest.output
    watch = runner.invoke(app, ["watch", "--once"])
    assert watch.exit_code == 0 and "shop" in watch.output


def test_notify_test_explains_itself_when_nothing_is_configured(home):
    result = runner.invoke(app, ["notify-test"])
    assert result.exit_code == 1 and "SYSTEMLENS_SLACK_WEBHOOK" in result.output


def test_doctor_reports_a_mistyped_config_key(home):
    home.mkdir(parents=True)
    (home / "config.yaml").write_text("ratelimt:\n  cooldown_seconds: 5\nllm:\n  modle: x\n")
    assert AgentConfig.unknown_keys() == ["ratelimt", "llm.modle"]
    out = runner.invoke(app, ["doctor"]).output.replace("\n", " ")
    assert "ratelimt" in out and "llm.modle" in out


def test_eval_run_on_the_shipped_suite_without_an_llm(home):
    result = runner.invoke(app, ["eval", "run", "examples/eval/error-project/suite.yaml",
                                 "--no-llm", "--min-pass-rate", "1.0", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output)["correlator_pass_rate"] == 1.0


def test_central_agent_lifecycle(home):
    registered = runner.invoke(app, ["central", "register-agent", "laptop"])
    assert registered.exit_code == 0 and "sla_" in registered.output
    assert "active" in runner.invoke(app, ["central", "list-agents"]).output
    assert runner.invoke(app, ["central", "revoke-agent", "1"]).exit_code == 0
    assert "revoked" in runner.invoke(app, ["central", "list-agents"]).output
    assert runner.invoke(app, ["central", "revoke-agent", "1"]).exit_code == 1
