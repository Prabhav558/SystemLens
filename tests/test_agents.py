"""Phase 3 and 4: investigator, remediation and verification, digest, ask,
notifications, the push outbox, central-server hardening, live project
reload, the live view and the MCP tools.
"""
from __future__ import annotations

import json
import sqlite3
import subprocess
import time

import httpx
import pytest

from systemlens.agents import remediation
from systemlens.agents.ask import Answer, ask, collect_findings
from systemlens.agents.digest import build_digest, render_digest
from systemlens.agents.investigator import InvestigationTools, Investigator, Step, needs_investigation
from systemlens.central.auth import generate_api_key
from systemlens.central.store import CentralStore
from systemlens.config import AgentConfig, NotifyConfig
from systemlens.core.correlate import correlate
from systemlens.core.daemon import AgentDaemon, ContainerRegistry
from systemlens.core.models import Analysis, ContainerState, EvidenceBundle, Finding, LogRecord, Severity
from systemlens.core.notify import Notifier
from systemlens.core.sinks import HttpSink
from systemlens.logs.cluster import to_signal
from systemlens.memory.store import ProjectStore
from systemlens.projects.registry import ProjectRegistry, build_project_entry

NOW = 1_000_000.0


def _container(name, running=True, exit_code=None, finished_at=None, health=None, labels=None):
    return ContainerState(id=f"id-{name}", name=name, image="x", status="running" if running else "exited",
                          running=running, exit_code=exit_code, started_at=0.0, finished_at=finished_at,
                          oom_killed=False, restart_count=0, health=health, compose_service=name,
                          labels=labels or {})


def _analysis(component="web", cause="x", verdict="root_cause_identified", confidence=0.8, fix="do it", evidence=()):
    return Analysis(verdict=verdict, root_cause=cause, affected_component=component,
                    evidence=list(evidence), fix_suggestion=fix, confidence=confidence)


def _bundle(containers):
    record = LogRecord(project="demo", source="container:web", ts=NOW, event_ts=NOW, severity=Severity.ERROR,
                       raw='ERROR web: could not translate host name "cache" to address', container="web")
    bundle = EvidenceBundle(project="demo", signal=to_signal(record), occurrences=1,
                            log_window=[record], containers=containers, docker_available=True)
    bundle.candidates = correlate(bundle, 120)
    return bundle


# -- investigator -------------------------------------------------------------------

class _Source:
    def __init__(self, containers, logs=None):
        self._containers, self._logs = containers, logs or {}

    async def containers_for(self, project):
        return self._containers, "high"

    async def logs_for(self, container_id, tail):
        return self._logs.get(container_id, [])


class _ScriptedLLM:
    name, model = "scripted", "m"

    def __init__(self, replies):
        self.replies, self.prompts = list(replies), []

    async def complete_json(self, system, user, schema_model):
        self.prompts.append(user)
        reply = self.replies.pop(0)
        assert isinstance(reply, schema_model), f"expected {schema_model.__name__}, script had {type(reply).__name__}"
        return reply


def _step(action, **kw):
    return Step(thought="t", action=action, **kw)


@pytest.mark.asyncio
async def test_investigation_gathers_evidence_and_the_result_is_still_checked(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  web:\n    environment:\n      REDIS_HOST: cache\n      "
                       "API_TOKEN: supersecretvalue\n  redis:\n    image: redis\n")
    containers = [_container("web"), _container("redis")]
    tools = InvestigationTools(_Source(containers), "demo", compose)
    final = _analysis("web", "web is configured with REDIS_HOST=cache but the service is named redis",
                      evidence=["REDIS_HOST: cache"])
    llm = _ScriptedLLM([_step("compose_file"), _step("finish"), final])
    first = _analysis("unknown", "cannot tell", verdict="insufficient_evidence", confidence=0.0)

    result = await Investigator(llm, tools, max_steps=5).investigate(_bundle(containers), first)

    assert result.steps and result.steps[0].startswith("compose_file")
    assert result.checked.analysis.verdict == "root_cause_identified"
    assert result.checked.analysis.evidence == ["REDIS_HOST: cache"], "tool output may be quoted as evidence"
    assert "supersecretvalue" not in llm.prompts[-1], "tool results are redacted before the model sees them"
    assert any("investigated" in a for a in result.checked.analysis.unverified_assumptions)


@pytest.mark.asyncio
async def test_investigation_cannot_be_used_to_blame_an_unlinked_container():
    containers = [_container("web"), _container("db", running=False, exit_code=1, finished_at=NOW - 5)]
    tools = InvestigationTools(_Source(containers), "demo", None)
    llm = _ScriptedLLM([_step("container_state", container="db"), _step("finish"),
                        _analysis("db", "db exited, which broke name resolution for cache")])
    first = _analysis("unknown", "?", verdict="insufficient_evidence", confidence=0.0)

    result = await Investigator(llm, tools).investigate(_bundle(containers), first)

    assert result.checked.analysis.verdict == "insufficient_evidence"
    assert result.checked.grounding_notes


@pytest.mark.asyncio
async def test_investigation_is_bounded_and_stops_on_a_repeated_action():
    containers = [_container("web")]
    tools = InvestigationTools(_Source(containers, {"id-web": ["line a", "ERROR boom"]}), "demo", None)
    same = _step("container_logs", container="web", grep="error")
    llm = _ScriptedLLM([same, same, _analysis("web", "boom", evidence=["ERROR boom"])])

    result = await Investigator(llm, tools, max_steps=5).investigate(_bundle(containers), _analysis())

    assert len(result.steps) == 1, "a repeated action ends the investigation"

    endless = _ScriptedLLM([_step("check_port", port=p) for p in (1, 2, 3)] + [_analysis()])
    result = await Investigator(endless, tools, max_steps=3).investigate(_bundle(containers), _analysis())
    assert len(result.steps) == 3


@pytest.mark.asyncio
async def test_tools_refuse_containers_outside_the_project():
    tools = InvestigationTools(_Source([_container("web")]), "demo", None)
    out = await tools.run(_step("container_logs", container="someone-elses-db"))
    assert "no container named" in out and "web" in out
    assert "not a valid port" in await tools.run(_step("check_port", port=70000))


def test_escalation_only_for_inconclusive_or_low_confidence_answers():
    assert needs_investigation(_analysis(verdict="insufficient_evidence", confidence=0.0), 0.5)
    assert needs_investigation(_analysis(confidence=0.3), 0.5)
    assert not needs_investigation(_analysis(confidence=0.9), 0.5)


# -- remediation --------------------------------------------------------------------

@pytest.mark.parametrize("text, risk, argv", [
    ("docker compose up -d db", "safe", ["docker", "compose", "up", "-d", "db"]),
    ("Run `docker compose restart web worker`  # bring them back", "safe",
     ["docker", "compose", "restart", "web", "worker"]),
    ("docker restart error_project_db", "safe", ["docker", "restart", "error_project_db"]),
    ("docker compose down -v && docker compose up -d", "review", None),
    ("docker exec db psql -c 'DROP TABLE users'", "review", None),
    ("docker compose up -d db; rm -rf /", "review", None),
    ("rm -rf /var/lib/app/cache", "review", None),
    ("Add error handling around the config lookup in app.py", "manual", None),
])
def test_only_plain_restarts_are_classified_safe(text, risk, argv):
    proposal = remediation.propose(text)
    assert proposal.risk == risk
    assert proposal.argv == argv


def _compose(tmp_path):
    f = tmp_path / "docker-compose.yml"
    f.write_text("services:\n  db:\n    image: postgres\n  web:\n    image: x\n")
    return f


def test_execution_is_off_by_default_and_checks_targets(tmp_path):
    compose = _compose(tmp_path)
    ran = []

    def runner(argv, **kw):
        ran.append((argv, kw["cwd"]))
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    kw = dict(project_root=tmp_path, compose_file=compose, project_containers={"demo-db-1"}, runner=runner)
    safe = remediation.propose("docker compose up -d db")

    with pytest.raises(remediation.ExecutionRefused, match="execution is off"):
        remediation.execute(safe, allow_execute=False, **kw)
    with pytest.raises(remediation.ExecutionRefused, match="not services of this project"):
        remediation.execute(remediation.propose("docker compose restart billing"), allow_execute=True, **kw)
    with pytest.raises(remediation.ExecutionRefused, match="not containers of this project"):
        remediation.execute(remediation.propose("docker restart other-project-db"), allow_execute=True, **kw)
    with pytest.raises(remediation.ExecutionRefused):
        remediation.execute(remediation.propose("rm -rf /tmp/x"), allow_execute=True, **kw)
    assert ran == []

    remediation.execute(safe, allow_execute=True, **kw)
    assert ran == [(["docker", "compose", "up", "-d", "db"], str(tmp_path))]


def test_fix_that_holds_becomes_the_resolution(tmp_path):
    store = ProjectStore(tmp_path / "state.db")
    store.touch_fingerprint("fp1", "t", "connection_refused")
    store.add_fix("fp1", "docker compose up -d db", "docker compose up -d db")

    assert remediation.verify_pending(store, verify_seconds=900) == [], "too early to tell"
    results = remediation.verify_pending(store, verify_seconds=900, now=time.time() + 901)

    assert [r.status for r in results] == ["verified"]
    assert store.get_prior("fp1").resolution == "docker compose up -d db"
    assert store.fixes("pending") == []
    store.close()


def test_fix_followed_by_a_recurrence_is_marked_failed(tmp_path):
    store = ProjectStore(tmp_path / "state.db")
    store.touch_fingerprint("fp1", "t", "connection_refused")
    store.add_fix("fp1", "restart it", None)
    store.add_occurrences("fp1", 3, time.time() + 120)      # seen again two minutes later

    results = remediation.verify_pending(store, verify_seconds=900)

    assert [r.status for r in results] == ["failed"] and "recurred" in results[0].detail
    assert store.get_prior("fp1").resolution is None
    store.close()


# -- digest and ask ---------------------------------------------------------------

def _seed(store):
    for fp, cat in (("aaa111", "connection_refused"), ("bbb222", "traceback")):
        store.touch_fingerprint(fp, f"template for {fp}", cat)
        store.record_incident(fp, _analysis("db", f"cause of {fp}", fix="docker compose up -d db"), "fake", "m")
    store.resolve_fingerprint("bbb222", "added the missing config file")


def test_digest_reports_new_resolved_and_verdicts_without_an_llm(tmp_path):
    store = ProjectStore(tmp_path / "state.db")
    _seed(store)
    text = render_digest(build_digest({"demo": store}, time.time() - 3600))

    assert "new issues (2)" in text and "resolved (1)" in text and "2 root cause" in text
    assert "added the missing config file" in text
    assert render_digest(build_digest({"demo": store}, time.time() + 10)).endswith("Nothing to report.")
    store.close()


@pytest.mark.asyncio
async def test_ask_keeps_real_citations_and_flags_uncited_answers(tmp_path):
    store = ProjectStore(tmp_path / "state.db")
    _seed(store)
    findings = collect_findings({"demo": store}, time.time() - 3600)
    real_id = next(iter(findings))

    cited = await ask(_ScriptedLLM([Answer(answer="db was down", cited=[real_id, "demo#9999"])]), "why?", findings)
    assert [c["id"] for c in cited.cited] == [real_id], "an invented citation is dropped"
    assert not cited.unsupported

    bare = await ask(_ScriptedLLM([Answer(answer="probably cosmic rays", cited=[])]), "why?", findings)
    assert bare.unsupported

    empty = await ask(_ScriptedLLM([]), "why?", {})
    assert empty.unsupported and "no findings" in empty.answer.lower()
    store.close()


# -- notifications -------------------------------------------------------------------

def _finding(verdict="root_cause_identified", confidence=0.9):
    bundle = _bundle([_container("web")])
    return Finding(project="demo", fingerprint="fp1", analysis=_analysis(verdict=verdict, confidence=confidence),
                   bundle=bundle, provider="fake", model="m")


@pytest.mark.asyncio
async def test_notifier_posts_to_every_configured_target(monkeypatch):
    monkeypatch.setenv("SYSTEMLENS_SLACK_WEBHOOK", "https://hooks.example/slack")
    monkeypatch.setenv("SYSTEMLENS_WEBHOOK_URL", "https://hooks.example/generic")
    monkeypatch.delenv("SYSTEMLENS_DISCORD_WEBHOOK", raising=False)
    seen = []

    def handler(request):
        seen.append((str(request.url), json.loads(request.content)))
        return httpx.Response(500 if "generic" in str(request.url) else 200)

    notifier = Notifier(NotifyConfig(), client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert notifier.targets == ["slack", "webhook"]

    results = await notifier.notify_finding(_finding())

    assert results == {"slack": True, "webhook": False}, "a failing target is reported, not raised"
    slack = dict(seen)["https://hooks.example/slack"]
    assert "Root cause identified in demo" in slack["text"]
    assert dict(seen)["https://hooks.example/generic"]["fingerprint"] == "fp1"


def test_notification_threshold(monkeypatch):
    monkeypatch.setenv("SYSTEMLENS_SLACK_WEBHOOK", "https://hooks.example/slack")
    notifier = Notifier(NotifyConfig(min_confidence=0.5))
    assert notifier.wants(_finding())
    assert not notifier.wants(_finding(confidence=0.2))
    assert not notifier.wants(_finding(verdict="insufficient_evidence", confidence=0.9))

    monkeypatch.delenv("SYSTEMLENS_SLACK_WEBHOOK")
    assert not Notifier(NotifyConfig()).wants(_finding()), "no targets, nothing to send"


# -- push outbox ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_findings_made_while_the_server_is_down_are_delivered_later(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSTEMLENS_HTTP_TOKEN", "sla_key")
    store = ProjectStore(tmp_path / "state.db")
    state = {"up": False, "received": []}

    def handler(request):
        if not state["up"]:
            raise httpx.ConnectError("refused")
        assert request.headers["authorization"] == "Bearer sla_key"
        state["received"].append(json.loads(request.content)["fingerprint"])
        return httpx.Response(200, json={"status": "recorded"})

    sink = HttpSink("https://central.example/ingest/findings", "SYSTEMLENS_HTTP_TOKEN", store,
                    client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    await sink.emit(_finding())
    await sink.emit(_finding())
    assert store.outbox_size() == 2 and state["received"] == []

    state["up"] = True
    assert await sink.flush_outbox() == 2
    assert store.outbox_size() == 0 and state["received"] == ["fp1", "fp1"]
    store.close()


@pytest.mark.asyncio
async def test_rejected_key_is_kept_for_retry_but_a_bad_payload_is_dropped(tmp_path):
    for status, queued in ((401, 1), (503, 1), (422, 0)):
        store = ProjectStore(tmp_path / f"state-{status}.db")
        sink = HttpSink("https://c.example/x", "NOPE", store, client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request, s=status: httpx.Response(s))))
        await sink.emit(_finding())
        assert store.outbox_size() == queued, f"HTTP {status}"
        store.close()


# -- central server ---------------------------------------------------------------------

def test_revoked_key_stops_working_and_duplicates_are_stored_once(tmp_path):
    store = CentralStore(tmp_path / "central.db")
    key = generate_api_key()
    agent_id = store.register_agent("laptop", key)
    args = (agent_id, "demo", "fp1", {"verdict": "probable_cause", "root_cause": "x"}, "fake", "m", 123.0)

    assert store.record_finding(*args) is not None
    assert store.record_finding(*args) is None, "a retried push must not create a second row"
    assert len(store.findings_for_agent(agent_id)) == 1

    assert store.revoke_agent(agent_id) is True
    assert store.agent_by_key(key) is None
    assert store.revoke_agent(agent_id) is False
    assert len(store.findings_for_agent(agent_id)) == 1, "revoking keeps the history"
    store.close()


def test_database_from_an_earlier_version_is_migrated(tmp_path):
    path = tmp_path / "central.db"
    old = sqlite3.connect(path)
    old.executescript("""
        CREATE TABLE agents (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            key_hash TEXT NOT NULL UNIQUE, created_at REAL NOT NULL, last_seen_at REAL);
        CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL,
            project TEXT NOT NULL, fingerprint TEXT NOT NULL, verdict TEXT NOT NULL, root_cause TEXT NOT NULL,
            affected_component TEXT, fix_suggestion TEXT, confidence REAL, provider TEXT, model TEXT,
            created_at REAL NOT NULL, received_at REAL NOT NULL, analysis_json TEXT NOT NULL);
        INSERT INTO agents (name, key_hash, created_at) VALUES ('old', 'h', 1.0);
        INSERT INTO findings (agent_id, project, fingerprint, verdict, root_cause, created_at, received_at, analysis_json)
            VALUES (1, 'p', 'fp', 'probable_cause', 'x', 5.0, 6.0, '{}'), (1, 'p', 'fp', 'probable_cause', 'x', 5.0, 7.0, '{}');
    """)
    old.commit()
    old.close()

    store = CentralStore(path)
    assert [dict(a)["revoked_at"] for a in store.list_agents()] == [None]
    assert len(store.findings_for_agent(1)) == 1, "pre-existing duplicates are collapsed"
    store.close()


# -- daemon: live reload, ignore label ---------------------------------------------------

def _offline_config(tmp_path):
    config = AgentConfig(home=tmp_path / "home")
    config.docker_socket = "unix:///nonexistent/docker.sock"
    config.docker_events = False
    config.sinks.console = False
    return config


@pytest.mark.asyncio
async def test_project_registered_while_the_daemon_runs_is_picked_up(tmp_path):
    config = _offline_config(tmp_path)
    project_dir = tmp_path / "proj"
    (project_dir / "logs").mkdir(parents=True)
    said = []
    daemon = AgentDaemon(config, ProjectRegistry(config), announce=said.append)
    await daemon.start()
    try:
        assert daemon._pipelines == {}

        ProjectRegistry(config).add(build_project_entry(project_dir, logs=str(project_dir / "logs" / "*.log")))
        await daemon._reload_projects()
        assert set(daemon._pipelines) == {"proj"} and "proj" in daemon._watchers

        ProjectRegistry(config).remove("proj")
        await daemon._reload_projects()
        assert daemon._pipelines == {} and daemon._watchers == {}
        assert said == ["now watching project 'proj'", "stopped watching project 'proj'"]
    finally:
        await daemon.stop()


@pytest.mark.asyncio
async def test_container_labelled_ignore_is_left_out(tmp_path):
    def attrs(name, labels):
        return {"Id": name * 12, "Name": f"/{name}", "State": {"Status": "running", "Running": True},
                "Config": {"Image": "x", "Labels": {"com.docker.compose.project": "proj", **labels}}}

    class _Docker:
        async def is_available(self):
            return True

        async def list_containers(self):
            return [attrs("a", {}), attrs("b", {"systemlens.ignore": "true"})]

    entry = build_project_entry(tmp_path / "proj")
    registry = ContainerRegistry(_Docker(), [entry])
    await registry.refresh()
    states, _ = await registry.containers_for("proj")
    assert [c.name for c in states] == ["a"]
    assert registry.project_of("b") is None


# -- live view and MCP tools ---------------------------------------------------------------

def _home_with_findings(tmp_path):
    config = AgentConfig(home=tmp_path / "home")
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    ProjectRegistry(config).add(build_project_entry(project_dir, logs="*.log"))
    store = ProjectStore(config.project_dir("proj") / "state.db")
    _seed(store)
    store.close()
    return config


def test_watch_renders_projects_and_findings(tmp_path):
    from rich.console import Console
    from systemlens.watch import render
    console = Console(record=True, width=160)
    console.print(render(_home_with_findings(tmp_path)))
    text = console.export_text()
    assert "daemon not running" in text and "proj" in text and "cause of aaa111" in text


def test_mcp_tools_read_and_resolve(tmp_path):
    from systemlens import mcp_server
    config = _home_with_findings(tmp_path)

    assert mcp_server.list_projects(config)[0]["name"] == "proj"
    found = mcp_server.list_findings(config)
    assert {f["fingerprint"] for f in found} == {"aaa111", "bbb222"}
    assert mcp_server.get_finding(config, "aaa")["finding"]["affected_component"] == "db"
    assert "error" in mcp_server.get_finding(config, "zzz")
    assert mcp_server.resolve(config, "aaa111", "restarted db") == {"resolved": "aaa111", "project": "proj"}
    assert mcp_server.get_finding(config, "aaa111")["resolution"] == "restarted db"
    assert "resolved" in mcp_server.digest(config)


def test_local_dashboard_escapes_everything_and_allows_no_scripts(tmp_path):
    from fastapi.testclient import TestClient
    from systemlens.api.server import build_app
    config = _home_with_findings(tmp_path)
    store = ProjectStore(config.project_dir("proj") / "state.db")
    store.touch_fingerprint("xss", "t", "generic")
    store.record_incident("xss", _analysis("<img src=x onerror=alert(1)>", "<script>alert(1)</script>"), "fake", "m")
    store.close()

    client = TestClient(build_app(config))
    page = client.get("/")

    assert "<script>" not in page.text and "<img src=x" not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    assert "script-src" not in page.headers["content-security-policy"]
    assert "default-src 'none'" in page.headers["content-security-policy"]
    assert len(client.get("/findings").json()) == 3
    assert client.get("/projects/nope/findings").status_code == 404
