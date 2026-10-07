"""CLI. `agent` and `systemlens` both point here (see pyproject.toml).

    agent up [path]              # register (if needed) + start, in one step
    agent init
    agent add-project <path>
    agent projects
    agent remove-project <name>
    agent start
    agent service install
    agent status
    agent findings
    agent explain <fingerprint>
    agent resolve <fingerprint> --note "..."
    agent doctor
    agent serve
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import click
import typer
from rich.console import Console
from rich.table import Table

from systemlens.config import AgentConfig, ProviderConfig
from systemlens.containers.client import AsyncDockerClient
from systemlens.core.daemon import AgentDaemon
from systemlens.core.lock import AlreadyRunning, DaemonLock, running_pid
from systemlens.memory.store import ProjectStore
from systemlens.projects.registry import ProjectEntry, ProjectRegistry, build_project_entry

app = typer.Typer(add_completion=False, no_args_is_help=True,
                   help="SystemLens — local AI ops agent with container-aware root cause analysis.")
console = Console()

_PROVIDER_DEFAULTS = {
    "ollama": ("llama3.1", ""),
    "groq": ("openai/gpt-oss-120b", "GROQ_API_KEY"),
}


@app.command()
def init():
    """Interactive first-run setup: pick an LLM provider and write config.yaml."""
    console.print("[bold]SystemLens setup[/bold]")
    provider = typer.prompt("LLM provider", type=click.Choice(["ollama", "groq"]),
                             default="ollama")
    default_model, default_env = _PROVIDER_DEFAULTS[provider]
    model = typer.prompt("Model", default=default_model)

    base_url = None
    api_key_env = default_env
    if provider == "ollama":
        base_url = typer.prompt("Ollama base URL", default="http://localhost:11434")
    else:
        api_key_env = typer.prompt("Environment variable holding your API key", default=default_env)
        if not os.environ.get(api_key_env):
            console.print(f"[yellow]Warning:[/yellow] ${api_key_env} is not currently set in this shell.")
        if provider == "groq":
            console.print("[dim]Note: strict structured-output mode is only guaranteed on "
                           "openai/gpt-oss-20b and openai/gpt-oss-120b. Other Groq models fall "
                           "back to a best-effort JSON mode with a repair retry.[/dim]")

    config = AgentConfig(llm=ProviderConfig(provider=provider, model=model,
                                             api_key_env=api_key_env, base_url=base_url))
    config.save()
    console.print(f"[green]Wrote {config.config_path}[/green]")


def _sources(entry: ProjectEntry) -> str:
    parts = []
    if entry.stream_containers:
        parts.append("docker container logs")
    parts += entry.log_globs
    return ", ".join(parts) or "(none)"


def _print_entry(entry: ProjectEntry) -> None:
    console.print(f"  root:    {entry.root}")
    console.print(f"  sources: {_sources(entry)}")
    console.print(f"  compose: {entry.compose_file or '(none found)'}")
    if entry.stream_containers and entry.compose_file is None:
        console.print("  [yellow]no compose file: containers are matched to this project by name "
                      "only (low confidence)[/yellow]")


_DOCKER_LOGS_HELP = ("Read container stdout/stderr straight from Docker. Default: on when the "
                     "project has a compose file and --logs is not given.")


@app.command("add-project")
def add_project(
    path: str = typer.Argument(..., help="Project root directory"),
    logs: Optional[str] = typer.Option(None, help="Log file glob, e.g. ./logs/**/*.log"),
    name: Optional[str] = typer.Option(None, help="Project name (defaults to directory name)"),
    docker_logs: Optional[bool] = typer.Option(None, "--docker-logs/--no-docker-logs",
                                               help=_DOCKER_LOGS_HELP),
):
    """Register a project: separate logs, separate memory, separate context."""
    config = AgentConfig.load()
    registry = ProjectRegistry(config)
    root = Path(path).resolve()
    if not root.is_dir():
        console.print(f"[red]No such directory: {root}[/red]")
        raise typer.Exit(1)

    entry = build_project_entry(root, name, logs, docker_logs)
    try:
        registry.add(entry)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    console.print(f"[green]Added project '{entry.name}'[/green]")
    _print_entry(entry)


@app.command("projects")
def projects():
    """List registered projects and what each one watches."""
    registry = ProjectRegistry(AgentConfig.load())
    table = Table(title="Registered projects")
    for column in ("name", "root", "sources", "enabled"):
        table.add_column(column)
    for entry in registry.all():
        table.add_row(entry.name, str(entry.root), _sources(entry), "yes" if entry.enabled else "no")
    console.print(table)


@app.command("remove-project")
def remove_project(
    name: str = typer.Argument(..., help="Project name, as shown by `agent projects`"),
    purge: bool = typer.Option(False, "--purge", help="Also delete its history and resolution memory"),
):
    """Unregister a project. Its history is kept unless --purge is given."""
    config = AgentConfig.load()
    registry = ProjectRegistry(config)
    if registry.get(name) is None:
        console.print(f"[red]No project named '{name}'[/red]")
        raise typer.Exit(1)
    registry.remove(name)
    console.print(f"[green]Removed project '{name}'[/green]")

    state_dir = (config.home / "projects" / name).resolve()
    if purge:
        # only ever delete a directory that sits directly under <home>/projects
        if state_dir.parent == (config.home / "projects").resolve() and state_dir.is_dir():
            shutil.rmtree(state_dir)
            console.print(f"  deleted {state_dir}")
    elif state_dir.exists():
        console.print(f"  history kept in {state_dir} (use --purge to delete it)")
    if running_pid(config.home) is not None:
        console.print("  the running daemon stops watching it within a few seconds")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if verbose:
        logging.getLogger("systemlens").setLevel(logging.DEBUG)


def _run_daemon(config: AgentConfig, registry: ProjectRegistry, verbose: bool) -> None:
    _setup_logging(verbose)

    async def _run():
        daemon = AgentDaemon(config, registry, announce=lambda m: console.print(f"[cyan]{m}[/cyan]"))
        stop = asyncio.Event()
        # systemd stops a service with SIGTERM; shut down as cleanly as Ctrl+C
        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, stop.set)
        await daemon.start()
        enabled = registry.enabled()
        console.print(f"[green]watching {len(enabled)} project(s)[/green] — Ctrl+C to stop")
        for entry in enabled:
            console.print(f"  {entry.name}: {_sources(entry)}")
        try:
            await stop.wait()
        except asyncio.CancelledError:
            pass
        finally:
            await daemon.stop()

    try:
        with DaemonLock(config.home):
            asyncio.run(_run())
    except AlreadyRunning as e:
        console.print(f"[red]{e}[/red]. Stop it first, or use it as is.")
        raise typer.Exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]stopped[/yellow]")


_VERBOSE = typer.Option(False, "--verbose", "-v", help="Debug logging, including full error tracebacks")


@app.command()
def start(verbose: bool = _VERBOSE):
    """Start the daemon: watch logs, correlate with Docker, analyze, report."""
    config = AgentConfig.load()
    _run_daemon(config, ProjectRegistry(config), verbose)


@app.command()
def up(
    path: str = typer.Argument(".", help="Project root directory (default: current directory)"),
    logs: Optional[str] = typer.Option(None, help="Also watch this log file glob"),
    name: Optional[str] = typer.Option(None, help="Project name (defaults to directory name)"),
    docker_logs: Optional[bool] = typer.Option(None, "--docker-logs/--no-docker-logs",
                                               help=_DOCKER_LOGS_HELP),
    verbose: bool = _VERBOSE,
):
    """One step: register this directory if it isn't yet, then start watching.

    With a compose file present nothing else is needed — container output
    and container failures are read from Docker directly.
    """
    config = AgentConfig.load()
    if not config.config_path.exists():
        if sys.stdin.isatty():
            console.print("No configuration yet — setting one up first.")
            init()
            config = AgentConfig.load()
        else:
            console.print("[yellow]No config.yaml found; using defaults (ollama at "
                          "localhost:11434). Run `agent init` to change that.[/yellow]")

    registry = ProjectRegistry(config)
    root = Path(path).resolve()
    if not root.is_dir():
        console.print(f"[red]No such directory: {root}[/red]")
        raise typer.Exit(1)

    entry = next((e for e in registry.all() if e.root.resolve() == root), None)
    if entry is not None:
        console.print(f"Project '{entry.name}' is already registered.")
    else:
        entry = build_project_entry(root, name, logs, docker_logs)
        if not entry.stream_containers and not logs:
            console.print(f"[red]No compose file in {root} and no --logs given, so there is "
                          f"nothing to watch.[/red] Pass --logs '<glob>' for a log-file project.")
            raise typer.Exit(1)
        try:
            registry.add(entry)
        except ValueError as e:
            console.print(f"[red]{e}[/red]. Pass --name to register it under another name.")
            raise typer.Exit(1)
        console.print(f"[green]Added project '{entry.name}'[/green]")
    _print_entry(entry)

    pid = running_pid(config.home)
    if pid is not None:
        console.print(f"A daemon is already running (pid {pid}); it picks this project up "
                      f"within a few seconds. Nothing else to do.")
        return
    _run_daemon(config, registry, verbose)


# -- shared helpers for the query commands ------------------------------------

def _open_stores(config: AgentConfig, project: Optional[str] = None) -> dict[str, ProjectStore]:
    """Open the state DB of every registered project that has one."""
    stores: dict[str, ProjectStore] = {}
    for entry in ProjectRegistry(config).all():
        db_path = config.home / "projects" / entry.name / "state.db"
        if project in (None, entry.name) and db_path.exists():
            stores[entry.name] = ProjectStore(db_path)
    return stores


def _close(stores: dict[str, ProjectStore]) -> None:
    for store in stores.values():
        store.close()


def _locate(config: AgentConfig, prefix: str) -> tuple[ProjectEntry, ProjectStore, str]:
    """Find the one fingerprint starting with `prefix`. The caller closes the store."""
    registry = ProjectRegistry(config)
    stores = _open_stores(config)
    matches = [(name, fp) for name, store in stores.items() for fp in store.find_fingerprint(prefix)]
    if len(matches) != 1:
        _close(stores)
        if not matches:
            console.print(f"[red]No fingerprint starting with '{prefix}'.[/red] See `agent findings`.")
        else:
            console.print(f"[red]'{prefix}' is ambiguous:[/red] " + ", ".join(fp for _, fp in matches[:8]))
        raise typer.Exit(1)
    name, fingerprint = matches[0]
    for other, store in stores.items():
        if other != name:
            store.close()
    return registry.get(name), stores[name], fingerprint


def _llm_or_exit(config: AgentConfig):
    from systemlens.llm.registry import get_provider
    return get_provider(config.llm)


def _fail(e: Exception) -> None:
    console.print(f"[red]{type(e).__name__}:[/red] {(str(e).splitlines() or [''])[0][:300]}")
    raise typer.Exit(1)


_JSON = typer.Option(False, "--json", help="Machine-readable output")


@app.command()
def status(as_json: bool = _JSON):
    """Per-project summary: daemon state, docker health, open issues."""
    config = AgentConfig.load()
    docker_ok = asyncio.run(AsyncDockerClient(base_url=config.docker_socket).is_available())
    pid = running_pid(config.home)
    rows = []
    for entry in ProjectRegistry(config).all():
        db_path = config.home / "projects" / entry.name / "state.db"
        recent, pending, unsent, failed = [], 0, 0, 0
        if db_path.exists():
            store = ProjectStore(db_path)
            recent = store.recent_incidents(since=time.time() - 86400)
            pending, unsent, failed = len(store.fixes("pending")), store.outbox_size(), store.attempts_last_hour()
            store.close()
        rows.append({"project": entry.name, "sources": _sources(entry), "findings_24h": len(recent),
                     "fixes_pending": pending, "unsent_findings": unsent, "failed_analyses_1h": failed,
                     "last_root_cause": recent[0]["root_cause"] if recent else None})
    if as_json:
        console.print_json(json.dumps({"daemon_pid": pid, "docker_available": docker_ok, "projects": rows}))
        return
    console.print(f"daemon: {'[green]running[/green] (pid %d)' % pid if pid else '[yellow]not running[/yellow]'}"
                  f"   docker: {'[green]up[/green]' if docker_ok else '[red]down[/red]'}")
    table = Table(title="SystemLens status")
    for column in ("project", "sources", "findings (24h)", "failed analyses (1h)", "fixes pending",
                   "last root cause"):
        table.add_column(column)
    for r in rows:
        failed = r["failed_analyses_1h"]
        table.add_row(r["project"], r["sources"], str(r["findings_24h"]),
                      f"[red]{failed}[/red]" if failed else "0", str(r["fixes_pending"]),
                      (r["last_root_cause"] or "(none)")[:60])
    console.print(table)
    if any(r["failed_analyses_1h"] for r in rows):
        console.print("[yellow]Some analyses failed: the LLM provider rejected or could not be reached. "
                      "Run `agent doctor`, or `agent start --verbose` for the error.[/yellow]")


@app.command()
def findings(
    project: Optional[str] = typer.Option(None, help="Filter to one project"),
    since: str = typer.Option("24h", help="e.g. 1h, 24h, 7d"),
    as_json: bool = _JSON,
):
    """Issue list with root causes and fixes. `agent explain <fingerprint>` shows one in full."""
    config = AgentConfig.load()
    cutoff = time.time() - _parse_since(since)
    stores = _open_stores(config, project)
    try:
        if as_json:
            out = []
            for name, store in stores.items():
                for r in store.recent_incidents(since=cutoff):
                    row = dict(r)
                    row.pop("analysis_json", None)
                    out.append({"project": name, **row})
            console.print_json(json.dumps(out))
            return
        shown = False
        for name, store in stores.items():
            rows = store.recent_incidents(since=cutoff)
            if not rows:
                continue
            shown = True
            table = Table(title=f"{name} — findings since {since}")
            for column in ("fingerprint", "verdict", "component", "root cause", "fix", "conf"):
                table.add_column(column)
            for r in rows:
                table.add_row(r["fingerprint"], r["verdict"], r["affected_component"] or "",
                              (r["root_cause"] or "")[:50], (r["fix_suggestion"] or "")[:50],
                              f"{r['confidence']:.2f}" if r["confidence"] is not None else "")
            console.print(table)
        if not shown:
            console.print(f"No findings since {since}.")
    finally:
        _close(stores)


@app.command()
def explain(fingerprint: str = typer.Argument(..., help="Fingerprint or a unique prefix of one")):
    """Show one finding in full: the signal, the evidence, and why it was (or wasn't) trusted."""
    from systemlens.core.bundle_io import load_recording
    config = AgentConfig.load()
    entry, store, fp = _locate(config, fingerprint)
    try:
        prior, row = store.get_prior(fp), store.latest_incident(fp)
        console.print(f"[bold]{entry.name} :: {fp}[/bold]   seen {prior.occurrences}× "
                      f"(last {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(prior.last_seen))})")
        if prior.resolution:
            console.print(f"[green]resolved:[/green] {prior.resolution}")
        if row is None:
            console.print("Not analysed yet (below the analysis threshold, on cooldown, or the analysis failed).")
        else:
            analysis = json.loads(row["analysis_json"])
            console.print(f"\n[bold]verdict:[/bold] {row['verdict']} (confidence {row['confidence']:.2f}, "
                          f"{row['provider']}/{row['model']})")
            console.print(f"[bold]component:[/bold] {row['affected_component']}")
            console.print(f"[bold]root cause:[/bold] {row['root_cause']}")
            console.print(f"[bold]fix:[/bold] {row['fix_suggestion']}")
            for quote in analysis.get("evidence", []):
                console.print(f"  evidence: {quote[:200]}", markup=False, highlight=False, style="dim")
            for note in analysis.get("unverified_assumptions", []):
                console.print(f"  [yellow]note:[/yellow] {note}")
        recording = config.home / "projects" / entry.name / "bundles" / f"{fp}.json"
        if recording.exists():
            bundle, _ = load_recording(recording)
            console.print(f"\n[bold]signal[/bold] ({bundle.signal.category}, from "
                          f"{bundle.signal.record.container or bundle.signal.record.source}):")
            console.print(bundle.signal.record.raw[:1200], markup=False, highlight=False)
            scoped = [c for c in bundle.candidates if c.scoped]
            other = [c for c in bundle.candidates if not c.scoped]
            console.print("\n[bold]linked to this signal:[/bold]" + ("" if scoped else " (nothing)"))
            for c in scoped:
                console.print(f"  [{c.rule_id}] {c.component} ({c.confidence:.2f}): {c.summary}", markup=False)
            if other:
                console.print("[bold]also true at the time, but not linked:[/bold]")
                for c in other:
                    console.print(f"  [{c.rule_id}] {c.component}: {c.summary}", markup=False)
    finally:
        store.close()


@app.command()
def resolve(fingerprint: str = typer.Argument(..., help="Fingerprint or a unique prefix of one"),
            note: str = typer.Option(..., "--note", help="What fixed it")):
    """Record what fixed an issue. If it recurs, the answer comes from memory with no LLM call."""
    config = AgentConfig.load()
    entry, store, fp = _locate(config, fingerprint)
    store.resolve_fingerprint(fp, note)
    store.close()
    console.print(f"[green]resolved {fp} in project '{entry.name}'[/green]")


@app.command()
def mute(fingerprint: str = typer.Argument(..., help="Fingerprint or a unique prefix of one")):
    """Stop analysing and notifying about an issue you consider noise. It is still counted."""
    config = AgentConfig.load()
    entry, store, fp = _locate(config, fingerprint)
    store.set_muted(fp, True)
    store.close()
    console.print(f"[green]muted {fp} in '{entry.name}'[/green] (undo with `agent unmute {fp[:10]}`)")


@app.command()
def unmute(fingerprint: str = typer.Argument(..., help="Fingerprint or a unique prefix of one")):
    """Resume analysing a muted issue."""
    config = AgentConfig.load()
    entry, store, fp = _locate(config, fingerprint)
    store.set_muted(fp, False)
    store.close()
    console.print(f"[green]unmuted {fp} in '{entry.name}'[/green]")


@app.command()
def investigate(fingerprint: str = typer.Argument(..., help="Fingerprint or a unique prefix of one")):
    """Dig further into a finding with read-only tools (container state, logs, compose file).

    Costs several LLM calls. Nothing is changed on your system.
    """
    from systemlens.agents.investigator import InvestigationTools, Investigator
    from systemlens.core.bundle_io import load_recording
    from systemlens.core.daemon import ContainerRegistry
    from systemlens.core.models import Analysis

    config = AgentConfig.load()
    entry, store, fp = _locate(config, fingerprint)
    recording = config.home / "projects" / entry.name / "bundles" / f"{fp}.json"
    if not recording.exists():
        store.close()
        console.print("[red]No recorded evidence for that fingerprint[/red] (it has not been analysed, "
                      "or eval.record_bundles is off).")
        raise typer.Exit(1)
    bundle, recorded = load_recording(recording)
    llm = _llm_or_exit(config)

    async def _go():
        containers = ContainerRegistry(AsyncDockerClient(base_url=config.docker_socket), [entry])
        await containers.refresh()
        tools = InvestigationTools(containers, entry.name, entry.compose_file)
        first = Analysis.model_validate(recorded) if recorded else await llm.analyze(bundle)
        return await Investigator(llm, tools, config.investigator.max_steps).investigate(bundle, first)

    try:
        result = asyncio.run(_go())
    except Exception as e:  # noqa: BLE001
        store.close()
        _fail(e)
    a = result.checked.analysis
    for i, step in enumerate(result.steps, 1):
        console.print(f"  [dim]{i}.[/dim] {step}", markup=False)
    if not result.steps:
        console.print("The model chose not to gather anything further.")
    console.print(f"\n[bold]verdict:[/bold] {a.verdict} (confidence {a.confidence:.2f})")
    console.print(f"[bold]component:[/bold] {a.affected_component}")
    console.print(f"[bold]root cause:[/bold] {a.root_cause}")
    console.print(f"[bold]fix:[/bold] {a.fix_suggestion}")
    for note in a.unverified_assumptions:
        console.print(f"  [yellow]note:[/yellow] {note}")
    if result.steps:
        store.record_incident(fp, a, f"{llm.name}+investigator", llm.model)
    store.close()


@app.command()
def fix(
    fingerprint: str = typer.Argument(..., help="Fingerprint or a unique prefix of one"),
    applied: bool = typer.Option(False, "--applied", help="You applied the fix yourself: start verifying it"),
    run: bool = typer.Option(False, "--run", help="Run the suggested command (allowlisted commands only)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Don't ask for confirmation with --run"),
):
    """Show the suggested fix for a finding, with what it would do and how risky it is.

    By default nothing is run. --applied records that you applied it, so the
    tool can confirm it worked (no recurrence) and remember it.
    """
    from systemlens.agents import remediation
    from systemlens.core.daemon import ContainerRegistry

    config = AgentConfig.load()
    entry, store, fp = _locate(config, fingerprint)
    try:
        row = store.latest_incident(fp)
        if row is None or not row["fix_suggestion"]:
            console.print("[red]No fix has been suggested for that fingerprint yet.[/red]")
            raise typer.Exit(1)
        proposal = remediation.propose(row["fix_suggestion"])
        colour = {"safe": "green", "review": "yellow", "manual": "dim"}[proposal.risk]
        console.print(f"[bold]suggested fix:[/bold] {proposal.text}")
        if proposal.command:
            console.print(f"[bold]command:[/bold] {proposal.command}", markup=False)
        console.print(f"[bold]risk:[/bold] [{colour}]{proposal.risk}[/{colour}] — {proposal.reason}")
        minutes = config.remediation.verify_minutes

        if run:
            async def _containers() -> set[str]:
                reg = ContainerRegistry(AsyncDockerClient(base_url=config.docker_socket), [entry])
                await reg.refresh()
                states, _ = await reg.containers_for(entry.name)
                return {c.name for c in states}

            if proposal.risk == "safe" and config.remediation.allow_execute and not yes:
                if not typer.confirm(f"Run `{proposal.command}` in {entry.root}?"):
                    raise typer.Exit(0)
            try:
                done = remediation.execute(
                    proposal, allow_execute=config.remediation.allow_execute, project_root=entry.root,
                    compose_file=entry.compose_file, project_containers=asyncio.run(_containers()))
            except remediation.ExecutionRefused as e:
                console.print(f"[red]Not run:[/red] {e}")
                raise typer.Exit(1)
            console.print((done.stdout + done.stderr).strip()[-1500:], markup=False, highlight=False)
            if done.returncode != 0:
                console.print(f"[red]command exited with {done.returncode}[/red]")
                raise typer.Exit(1)
            store.add_fix(fp, proposal.text, proposal.command)
            console.print(f"[green]Ran.[/green] Watching for {minutes} min; if the issue does not recur "
                          f"this is saved as its resolution (see `agent fixes`).")
        elif applied:
            store.add_fix(fp, proposal.text, proposal.command)
            console.print(f"[green]Noted.[/green] Watching for {minutes} min; if the issue does not recur "
                          f"this is saved as its resolution (see `agent fixes`).")
        else:
            console.print("\nNothing was run. After applying it yourself: "
                          f"`agent fix {fp[:10]} --applied`"
                          + ("" if proposal.risk != "safe" else f", or let the tool run it: `agent fix {fp[:10]} --run`"))
    finally:
        store.close()


@app.command()
def fixes():
    """Fixes being verified, and how earlier ones turned out."""
    from systemlens.agents.remediation import verify_pending
    config = AgentConfig.load()
    stores = _open_stores(config)
    try:
        table = Table(title="Fixes")
        for column in ("project", "fingerprint", "status", "applied", "fix", "detail"):
            table.add_column(column)
        any_rows = False
        for name, store in stores.items():
            verify_pending(store, config.remediation.verify_minutes * 60)   # settle what is already known
            for f in store.fixes():
                any_rows = True
                colour = {"verified": "green", "failed": "red", "pending": "yellow"}[f["status"]]
                table.add_row(name, f["fingerprint"][:10], f"[{colour}]{f['status']}[/{colour}]",
                              time.strftime("%m-%d %H:%M", time.localtime(f["applied_at"])),
                              (f["command"] or f["fix_text"])[:50], f["detail"] or "")
        console.print(table if any_rows else "No fixes recorded. See `agent fix <fingerprint>`.")
    finally:
        _close(stores)


@app.command()
def digest(
    since: str = typer.Option("24h", help="e.g. 24h, 7d"),
    llm: bool = typer.Option(False, "--llm", help="Add a short narrative summary (one LLM call)"),
    send: bool = typer.Option(False, "--send", help="Also send it to the configured notification targets"),
):
    """What appeared, what keeps recurring, and what got resolved."""
    from systemlens.agents.digest import build_digest, narrate, render_digest
    from systemlens.core.notify import Notifier
    config = AgentConfig.load()
    stores = _open_stores(config)
    try:
        text = render_digest(build_digest(stores, time.time() - _parse_since(since)))
    finally:
        _close(stores)
    if llm:
        try:
            text += "\n\n" + asyncio.run(narrate(_llm_or_exit(config), text))
        except Exception as e:  # noqa: BLE001
            console.print(f"[yellow]narrative skipped ({type(e).__name__})[/yellow]")
    console.print(text, markup=False, highlight=False)
    if send:
        async def _send():
            notifier = Notifier(config.notify)
            try:
                return notifier.targets, await notifier.send("SystemLens digest", text)
            finally:
                await notifier.aclose()
        targets, results = asyncio.run(_send())
        console.print(f"sent: {results}" if targets else "[yellow]no notification targets configured[/yellow]")


@app.command()
def ask(
    question: str = typer.Argument(..., help='e.g. "why did the worker fail last night?"'),
    since: str = typer.Option("7d", help="How far back to look"),
    project: Optional[str] = typer.Option(None, help="Limit to one project"),
):
    """Ask a question about past findings. The answer cites the findings it used."""
    from systemlens.agents.ask import ask as ask_agent, collect_findings
    config = AgentConfig.load()
    stores = _open_stores(config, project)
    try:
        found = collect_findings(stores, time.time() - _parse_since(since))
    finally:
        _close(stores)
    try:
        result = asyncio.run(ask_agent(_llm_or_exit(config), question, found))
    except Exception as e:  # noqa: BLE001
        _fail(e)
    console.print(result.answer, markup=False, highlight=False)
    if result.unsupported:
        console.print("[yellow]No stored finding was cited for this answer; treat it as unsupported.[/yellow]")
    for c in result.cited:
        console.print(f"  [dim]\\[{c['id']}] {c['fingerprint'][:10]} {c['affected_component']}: "
                      f"{(c['root_cause'] or '')[:90]}[/dim]")


@app.command()
def watch(
    once: bool = typer.Option(False, "--once", help="Print one snapshot and exit"),
    interval: float = typer.Option(2.0, help="Seconds between refreshes"),
):
    """Live view of projects and their latest findings."""
    from rich.live import Live
    from systemlens.watch import render
    config = AgentConfig.load()
    if once:
        console.print(render(config))
        return
    try:
        with Live(render(config), console=console, refresh_per_second=4, screen=True) as live:
            while True:
                time.sleep(interval)
                live.update(render(config))
    except KeyboardInterrupt:
        pass


@app.command()
def mcp():
    """Run the MCP server on stdio, for Claude Code and other MCP clients."""
    try:
        from systemlens.mcp_server import build_server
        server = build_server(AgentConfig.load())
    except ImportError:
        console.print('[red]The MCP SDK is not installed.[/red] Run: pip install "systemlens[mcp]"')
        raise typer.Exit(1)
    server.run()


@app.command("notify-test")
def notify_test():
    """Send a test message to every configured notification target."""
    from systemlens.core.notify import Notifier
    config = AgentConfig.load()

    async def _send():
        notifier = Notifier(config.notify)
        try:
            return notifier.targets, await notifier.send(
                "SystemLens test", "Notifications are working.", {"type": "test"})
        finally:
            await notifier.aclose()

    targets, results = asyncio.run(_send())
    if not targets:
        n = config.notify
        console.print("No notification targets are configured. Set one of "
                      f"${n.slack_webhook_env}, ${n.discord_webhook_env}, ${n.webhook_url_env}, "
                      "or notify.desktop: true.")
        raise typer.Exit(1)
    for target, ok in results.items():
        console.print(f"{target}: {'[green]delivered[/green]' if ok else '[red]failed[/red]'}")
    if not all(results.values()):
        raise typer.Exit(1)


eval_app = typer.Typer(add_completion=False, no_args_is_help=True,
                       help="Measure accuracy by replaying recorded evidence against an answer key.")
app.add_typer(eval_app, name="eval")


@eval_app.command("run")
def eval_run(
    suite: Path = typer.Argument(..., help="Path to a suite.yaml"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Score only the deterministic correlator"),
    min_pass_rate: float = typer.Option(0.0, help="Exit non-zero below this pass rate (0-1)"),
    as_json: bool = _JSON,
):
    """Replay a suite and report how many cases the correlator and the analysis get right."""
    from systemlens.evaluation import run_suite
    config = AgentConfig.load()
    try:
        report = asyncio.run(run_suite(suite, None if no_llm else _llm_or_exit(config),
                                       config.correlation.window_seconds))
    except (OSError, ValueError) as e:
        _fail(e)
    if as_json:
        console.print_json(json.dumps(report.to_dict()))
    else:
        table = Table(title=f"eval: {report.name}")
        for column in ("case", "correlator", "analysis", "answer", "problems"):
            table.add_column(column, overflow="fold")
        mark = lambda ok: "[green]pass[/green]" if ok else "[red]FAIL[/red]"   # noqa: E731
        for r in report.results:
            answer = f"{r.analysis.affected_component} / {r.analysis.verdict}" if r.analysis else ""
            problems = "; ".join(r.correlator_failures + r.analysis_failures + ([r.error] if r.error else []))
            table.add_row(r.case_id, mark(r.correlator_ok),
                          mark(r.analysis_ok) if report.with_llm else "[dim]skipped[/dim]", answer, problems)
        console.print(table)
        console.print(f"correlator: {report.rate('correlator_ok'):.0%} of {len(report.results)} cases"
                      + (f"   analysis: {report.rate('analysis_ok'):.0%}" if report.with_llm else ""))
    rate = report.rate("analysis_ok") if report.with_llm else report.rate("correlator_ok")
    if rate < min_pass_rate:
        raise typer.Exit(1)


@eval_app.command("init")
def eval_init(
    project: str = typer.Argument(..., help="Project whose recorded evidence to turn into a suite"),
    out: Path = typer.Option(Path("eval"), help="Directory to create the suite in"),
):
    """Create a suite from a project's recorded evidence, with expectations left for you to fill in."""
    from systemlens.evaluation import init_suite
    config = AgentConfig.load()
    try:
        suite = init_suite(config.home / "projects" / project / "bundles", out / project, project)
    except FileNotFoundError as e:
        _fail(e)
    console.print(f"[green]Wrote {suite}[/green]. Fill in each case's `expect`, then: agent eval run {suite}")


@app.command()
def doctor():
    """Check Docker, the LLM provider, notifications and what each project can see."""
    import httpx
    from systemlens.core.daemon import ContainerRegistry
    from systemlens.core.notify import Notifier
    config = AgentConfig.load()
    registry = ProjectRegistry(config)
    ok = True

    def line(label: str, good: bool, text: str, required: bool = True) -> None:
        nonlocal ok
        colour = "green" if good else ("red" if required else "yellow")
        console.print(f"{label + ':':22s}[{colour}]{text}[/{colour}]")
        ok = ok and (good or not required)

    line("config", config.config_path.exists(), str(config.config_path) if config.config_path.exists()
         else "none yet (defaults in use; run `agent init`)", required=False)
    unknown = AgentConfig.unknown_keys()
    if unknown:
        line("config keys", False, "not recognised (typo?): " + ", ".join(unknown), required=False)

    docker = AsyncDockerClient(base_url=config.docker_socket)
    docker_ok = asyncio.run(docker.is_available())
    line("docker daemon", docker_ok, "ok" if docker_ok else "unavailable")

    llm = config.llm
    if llm.provider == "ollama":
        url = (llm.base_url or "http://localhost:11434").rstrip("/")
        try:
            tags = httpx.get(f"{url}/api/tags", timeout=3).json().get("models", [])
            names = {m.get("name", "").split(":")[0] for m in tags} | {m.get("name", "") for m in tags}
            line("ollama", llm.model in names or llm.model.split(":")[0] in names,
                 f"reachable at {url}" + ("" if llm.model in names or llm.model.split(':')[0] in names
                                          else f", but model '{llm.model}' is not pulled"))
        except Exception:  # noqa: BLE001
            line("ollama", False, f"not reachable at {url} (is `ollama serve` running?)")
    else:
        key_set = bool(os.environ.get(llm.api_key_env))
        line(f"${llm.api_key_env}", key_set, "set" if key_set else "not set")
        if "/" not in llm.model:
            line("groq model", False, f"'{llm.model}' has no vendor prefix; Groq ids look like "
                                       f"openai/gpt-oss-120b", required=False)

    try:
        config.home.mkdir(parents=True, exist_ok=True)
        writable = os.access(config.home, os.W_OK)
    except OSError:
        writable = False
    line("data directory", writable, f"{config.home}" + ("" if writable else " (not writable)"))

    pid = running_pid(config.home)
    line("daemon", pid is not None, f"running (pid {pid})" if pid else "not running", required=False)
    targets = Notifier(config.notify).targets
    line("notifications", bool(targets), ", ".join(targets) if targets else "none configured", required=False)
    if config.sinks.http_enabled:
        token = bool(os.environ.get(config.sinks.http_token_env))
        line("central server", bool(config.sinks.http_url) and token,
             f"{config.sinks.http_url}" + ("" if token else f" (${config.sinks.http_token_env} not set)"))

    entries = registry.enabled()
    if not entries:
        line("projects", False, "none registered (run `agent up` in a project directory)", required=False)
    elif docker_ok:
        async def _mapped():
            reg = ContainerRegistry(docker, entries)
            await reg.refresh()
            return {e.name: await reg.containers_for(e.name) for e in entries}
        for name, (states, confidence) in asyncio.run(_mapped()).items():
            entry = registry.get(name)
            running = sum(c.running for c in states)
            seen = bool(states) or bool(entry.log_globs)
            line(f"project {name}", seen,
                 f"{len(states)} container(s), {running} running"
                 + (" (matched by name only)" if confidence == "low" and states else "")
                 + (f"; files: {', '.join(entry.log_globs)}" if entry.log_globs else ""), required=False)

    if not ok:
        raise typer.Exit(1)
    console.print("[green]all required checks passed[/green]")


@app.command()
def serve(port: int = typer.Option(None, help="Overrides config.api.port"),
          host: str = typer.Option(None, help="Overrides config.api.host (default 127.0.0.1)")):
    """Run the local dashboard. It has no login, so keep it on localhost."""
    import uvicorn
    config = AgentConfig.load()
    from systemlens.api.server import build_app
    host = host or config.api.host
    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print("[yellow]This dashboard has no authentication; anyone who can reach "
                      f"{host} can read your findings.[/yellow]")
    uvicorn.run(build_app(config), host=host, port=port or config.api.port)


service_app = typer.Typer(add_completion=False, no_args_is_help=True,
                          help="Run the daemon in the background as a systemd user service.")
app.add_typer(service_app, name="service")

_UNIT_NAME = "systemlens.service"


def _unit_path() -> Path:
    return Path.home() / ".config" / "systemd" / "user" / _UNIT_NAME


def _systemctl(*args: str) -> bool:
    if shutil.which("systemctl") is None:
        console.print("[yellow]systemctl not found; this system does not use systemd[/yellow]")
        return False
    result = subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True)
    if result.returncode != 0:
        console.print(f"[red]systemctl --user {' '.join(args)} failed:[/red] {result.stderr.strip()}")
    return result.returncode == 0


@service_app.command("install")
def service_install(
    enable: bool = typer.Option(False, "--enable", help="Also enable and start it now"),
):
    """Write the systemd user unit. API keys go in the env file it prints —
    a service does not inherit variables exported in your shell.
    """
    config = AgentConfig.load()
    env_file = config.home / "env"
    config.home.mkdir(parents=True, exist_ok=True)
    if not env_file.exists():
        env_file.write_text("# KEY=value lines read by the SystemLens service, e.g.\n"
                            f"# {config.llm.api_key_env or 'GROQ_API_KEY'}=...\n")
    env_file.chmod(0o600)

    unit = f"""[Unit]
Description=SystemLens — local AI ops agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={sys.executable} -m systemlens.cli.main start
Restart=on-failure
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=SYSTEMLENS_HOME={config.home}
EnvironmentFile=-{env_file}

[Install]
WantedBy=default.target
"""
    path = _unit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(unit)
    console.print(f"[green]Wrote {path}[/green]")
    console.print(f"Put API keys in {env_file} (created with mode 600).")
    if enable:
        if _systemctl("daemon-reload") and _systemctl("enable", "--now", _UNIT_NAME):
            console.print("[green]Service enabled and started.[/green] "
                          "Logs: journalctl --user -u systemlens -f")
    else:
        console.print("Start it with:\n  systemctl --user daemon-reload\n"
                      f"  systemctl --user enable --now {_UNIT_NAME}")


@service_app.command("uninstall")
def service_uninstall():
    """Stop the service and remove its unit file. Your data is not touched."""
    path = _unit_path()
    if not path.exists():
        console.print("Service is not installed.")
        return
    _systemctl("disable", "--now", _UNIT_NAME)
    path.unlink()
    _systemctl("daemon-reload")
    console.print(f"[green]Removed {path}[/green]")


@service_app.command("status")
def service_status():
    """Show the service's systemd status."""
    if shutil.which("systemctl") is None:
        console.print("[yellow]systemctl not found; this system does not use systemd[/yellow]")
        raise typer.Exit(1)
    subprocess.run(["systemctl", "--user", "status", _UNIT_NAME, "--no-pager"])


central_app = typer.Typer(
    add_completion=False, no_args_is_help=True,
    help="Central server: receive findings pushed from one or more agents "
         "(via sinks.http_enabled) and serve the browser dashboard.",
)
app.add_typer(central_app, name="central")


@central_app.command("serve")
def central_serve(port: int = typer.Option(None, help="Overrides config.central.port"),
                  host: str = typer.Option(None, help="Overrides config.central.host (default 127.0.0.1)"),
                  forwarded_allow_ips: str = typer.Option(
                      "127.0.0.1", help="Proxies whose X-Forwarded-For is trusted ('*' only when the "
                                        "server is reachable solely through your reverse proxy)")):
    """Run the central server: findings ingest + browser dashboard.

    It speaks plain HTTP. For anything beyond localhost, put it behind a
    TLS-terminating reverse proxy (see docs/DEPLOYMENT.md).
    """
    import uvicorn
    config = AgentConfig.load()
    from systemlens.central.server import build_central_app
    central_app_instance = build_central_app(
        config.central_db_path, config.central.admin_key_env, config.retention.days)
    uvicorn.run(central_app_instance, host=host or config.central.host, port=port or config.central.port,
                proxy_headers=True, forwarded_allow_ips=forwarded_allow_ips)


@central_app.command("register-agent")
def central_register_agent(
    name: str = typer.Argument(..., help="Display name for this agent, e.g. a hostname"),
):
    """Mint a new agent API key, writing directly to the central DB (no
    running server needed — same local-filesystem-access model as
    `add-project`). Put the printed key in the pushing agent's
    sinks.http_token_env variable, point its sinks.http_url at this
    server's /ingest/findings, and paste the same key into the dashboard
    to view that agent's findings.
    """
    config = AgentConfig.load()
    from systemlens.central.auth import generate_api_key
    from systemlens.central.store import CentralStore

    store = CentralStore(config.central_db_path)
    api_key = generate_api_key()
    agent_id = store.register_agent(name, api_key)
    store.close()

    console.print(f"[green]Registered agent '{name}' (id={agent_id})[/green]")
    console.print(f"API key (shown once — store it now): [bold]{api_key}[/bold]")
    console.print(
        f"\nOn the machine running that agent, set:\n"
        f"  export SYSTEMLENS_HTTP_TOKEN={api_key}\n"
        f"and in its config.yaml:\n"
        f"  sinks:\n    http_enabled: true\n"
        f"    http_url: http://<this-host>:{config.central.port}/ingest/findings\n"
        f"    http_token_env: SYSTEMLENS_HTTP_TOKEN\n"
        f"\nThen open http://<this-host>:{config.central.port}/ and paste the same key in to view its findings."
    )


@central_app.command("list-agents")
def central_list_agents():
    """List agents registered against the central server."""
    config = AgentConfig.load()
    from systemlens.central.store import CentralStore

    store = CentralStore(config.central_db_path)
    rows = store.list_agents()
    store.close()

    table = Table(title="Registered agents")
    table.add_column("id")
    table.add_column("name")
    table.add_column("registered")
    table.add_column("last seen")
    table.add_column("key")
    for r in rows:
        last_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["last_seen_at"])) if r["last_seen_at"] else "never"
        registered = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["created_at"]))
        table.add_row(str(r["id"]), r["name"], registered, last_seen,
                      "[red]revoked[/red]" if r["revoked_at"] else "[green]active[/green]")
    console.print(table)


@central_app.command("revoke-agent")
def central_revoke_agent(agent_id: int = typer.Argument(..., help="Id shown by `agent central list-agents`")):
    """Make an agent's API key stop working immediately. Its findings are kept."""
    config = AgentConfig.load()
    from systemlens.central.store import CentralStore

    store = CentralStore(config.central_db_path)
    revoked = store.revoke_agent(agent_id)
    store.close()
    if not revoked:
        console.print(f"[red]No active agent with id {agent_id}.[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Revoked agent {agent_id}.[/green] Register a new one to replace its key.")


@central_app.command("backfill")
def central_backfill(
    since: str = typer.Option("30d", help="How far back to send"),
    project: Optional[str] = typer.Option(None, help="Limit to one project"),
):
    """Send findings already stored on this machine to the central server.

    Uses sinks.http_url and the key in sinks.http_token_env. Safe to repeat:
    the server stores each finding once.
    """
    import httpx
    from systemlens.core.sinks import HttpSink
    config = AgentConfig.load()
    if not config.sinks.http_url:
        console.print("[red]sinks.http_url is not set in config.yaml.[/red]")
        raise typer.Exit(1)
    token = os.environ.get(config.sinks.http_token_env)
    if not token:
        console.print(f"[red]${config.sinks.http_token_env} is not set.[/red]")
        raise typer.Exit(1)
    cutoff = time.time() - _parse_since(since)
    stores = _open_stores(config, project)
    sent = duplicate = failed = 0
    try:
        with httpx.Client(timeout=10.0, headers={"Authorization": f"Bearer {token}"}) as client:
            for name, store in stores.items():
                for r in store.recent_incidents(since=cutoff, limit=100_000):
                    payload = HttpSink.payload(name, r["fingerprint"], json.loads(r["analysis_json"]),
                                               r["provider"], r["model"], r["created_at"])
                    try:
                        resp = client.post(config.sinks.http_url, json=payload)
                    except httpx.HTTPError as e:
                        _fail(e)
                    if resp.status_code in (401, 403):
                        console.print("[red]The central server rejected the API key.[/red]")
                        raise typer.Exit(1)
                    if resp.status_code >= 400:
                        failed += 1
                    elif resp.json().get("status") == "duplicate":
                        duplicate += 1
                    else:
                        sent += 1
    finally:
        _close(stores)
    console.print(f"sent {sent}, already there {duplicate}, failed {failed}")
    if failed:
        raise typer.Exit(1)


def _parse_since(token: str) -> int:
    unit = token[-1]
    n = int(token[:-1])
    return {"h": 3600, "d": 86400, "m": 60}.get(unit, 3600) * n


if __name__ == "__main__":
    app()
