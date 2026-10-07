"""Top-level asyncio supervisor. Owns the shared Docker connection and
per-project pipelines, and is the only place a container gets resolved
against every registered project (mapping needs the whole project list).
"""
from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Callable, Optional

from systemlens.agents.digest import build_digest, render_digest
from systemlens.agents.investigator import InvestigationTools, Investigator
from systemlens.agents.remediation import verify_pending
from systemlens.config import AgentConfig
from systemlens.containers.client import AsyncDockerClient
from systemlens.containers.events import ContainerEvent, DockerEventWatcher, event_to_record
from systemlens.containers.inspect import ContainerState, to_container_state
from systemlens.containers.logstream import OFFSET_PREFIX, ContainerLogStreamer, docker_stream_factory
from systemlens.containers.mapping import resolve as resolve_mapping
from systemlens.core.bundle_io import prune_recordings
from systemlens.core.models import LogRecord
from systemlens.core.notify import Notifier
from systemlens.core.pipeline import ContainerSource, ProjectPipeline
from systemlens.core.ratelimit import RateLimiter
from systemlens.core.sinks import ConsoleSink, FanoutSink, HttpSink, NotifySink, QueueSink, SqliteSink
from systemlens.llm.registry import get_provider
from systemlens.logs.watcher import ProjectWatcher
from systemlens.memory.embed import HashingEmbedder
from systemlens.memory.store import ProjectStore
from systemlens.memory.vector import VectorIndex
from systemlens.memory.window import SlidingWindow
from systemlens.projects.registry import ProjectEntry, ProjectRegistry

logger = logging.getLogger("systemlens.daemon")


IGNORE_LABEL = "systemlens.ignore"     # label a container `systemlens.ignore=true` to leave it out


class ContainerRegistry(ContainerSource):
    """Refreshes the full container list on an interval and resolves each
    container to a project once per refresh, so per-record processing never
    pays a Docker round-trip.
    """

    def __init__(self, docker: AsyncDockerClient, projects: list[ProjectEntry], refresh_seconds: float = 5.0):
        self._docker = docker
        self._projects = projects
        self._refresh_seconds = refresh_seconds
        self._by_project: dict[str, list[ContainerState]] = {}
        self._confidence_by_project: dict[str, str] = {}
        self._project_by_container: dict[str, str] = {}
        self._listeners: list[Callable[[], None]] = []
        self._available = True
        self._task: Optional[asyncio.Task] = None

    def add_listener(self, callback: Callable[[], None]) -> None:
        """Called (on the event loop) after every refresh."""
        self._listeners.append(callback)

    def project_of(self, container_name: str) -> Optional[str]:
        return self._project_by_container.get(container_name)

    async def start(self) -> None:
        await self.refresh()
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self._refresh_seconds)
            try:
                await self.refresh()
            except Exception:  # noqa: BLE001 - a bad refresh must not kill the daemon
                logger.exception("container registry refresh failed")

    async def refresh(self) -> None:
        self._available = await self._docker.is_available()
        by_project: dict[str, list[ContainerState]] = {p.name: [] for p in self._projects}
        confidence: dict[str, str] = {p.name: "high" for p in self._projects}

        owner: dict[str, str] = {}
        if self._available:
            raw = await self._docker.list_containers()
            for attrs in raw:
                state = to_container_state(attrs)
                if state.labels.get(IGNORE_LABEL, "").lower() == "true":
                    continue
                match = resolve_mapping(state, self._projects)
                if match is None:
                    continue
                by_project.setdefault(match.project, []).append(state)
                owner[state.name] = match.project
                if match.confidence == "low":
                    confidence[match.project] = "low"

        self._by_project = by_project
        self._confidence_by_project = confidence
        self._project_by_container = owner
        for callback in self._listeners:
            callback()

    async def containers_for(self, project: str) -> tuple[list[ContainerState], str]:
        return self._by_project.get(project, []), self._confidence_by_project.get(project, "high")

    async def docker_available(self) -> bool:
        return self._available

    async def logs_for(self, container_id: str, tail: int) -> list[str]:
        return await self._docker.logs(container_id, tail=tail)


HOUSEKEEPING_SECONDS = 5.0
OUTBOX_EVERY = 30.0
SLOW_EVERY = 60.0


class AgentDaemon:
    def __init__(self, config: AgentConfig, registry: ProjectRegistry,
                 finding_queue: Optional[asyncio.Queue] = None,
                 announce: Optional[Callable[[str], None]] = None):
        self._config = config
        self._registry = registry
        self._finding_queue = finding_queue
        self._announce = announce or (lambda message: logger.info(message))
        self._queue: asyncio.Queue[LogRecord] = asyncio.Queue(maxsize=10_000)
        self._watchers: dict[str, ProjectWatcher] = {}
        self._pipelines: dict[str, ProjectPipeline] = {}
        self._stores: dict[str, ProjectStore] = {}
        self._http_sinks: dict[str, HttpSink] = {}
        self._docker = AsyncDockerClient(base_url=config.docker_socket)
        self._streamers: dict[str, ContainerLogStreamer] = {}
        self._events: Optional[DockerEventWatcher] = None
        self._event_tasks: set[asyncio.Task] = set()
        self._container_registry: Optional[ContainerRegistry] = None
        self._notifier: Optional[Notifier] = None
        self._consume_task: Optional[asyncio.Task] = None
        self._housekeeping_task: Optional[asyncio.Task] = None
        self._projects_mtime = self._registry_mtime()
        self._last_digest_day: Optional[str] = None
        self._running = False

    async def start(self) -> None:
        projects = self._registry.enabled()
        if not projects:
            logger.warning("no projects registered; run `agent up` in a project directory first")

        self._notifier = Notifier(self._config.notify)
        self._container_registry = ContainerRegistry(self._docker, list(projects))
        await self._container_registry.start()

        for project in projects:
            self._attach_project(project)
        self._container_registry.add_listener(self._sync_streams)
        self._sync_streams()

        if self._config.docker_events:
            self._events = DockerEventWatcher(
                self._docker.sync, asyncio.get_running_loop(), self._on_container_event)
            self._events.start()

        self._running = True
        self._consume_task = asyncio.create_task(self._consume_loop())
        self._housekeeping_task = asyncio.create_task(self._housekeeping_loop())

    # -- projects ---------------------------------------------------------
    def _attach_project(self, project: ProjectEntry) -> None:
        """Build the project's pipeline and start its log sources."""
        loop = asyncio.get_running_loop()
        self._pipelines[project.name] = self._build_pipeline(project)
        store = self._stores[project.name]
        pruned = store.prune(self._config.retention.days)
        prune_recordings(self._bundle_dir(project.name), self._config.retention.days)
        if any(pruned.values()):
            logger.info("pruned %s for project=%s", pruned, project.name)

        offsets = store.load_all_offsets()
        watcher = ProjectWatcher(project.name, project.root, project.log_globs, self._queue, offsets=offsets)
        watcher.start(loop)
        self._watchers[project.name] = watcher

        if project.stream_containers:
            resume = {key[len(OFFSET_PREFIX):]: data["since"] for key, data in offsets.items()
                      if key.startswith(OFFSET_PREFIX) and "since" in data}
            self._streamers[project.name] = ContainerLogStreamer(
                project.name, docker_stream_factory(self._docker.sync), self._queue, loop, resume=resume)

    def _detach_project(self, name: str) -> None:
        """Stop watching a project and persist where its sources left off."""
        pipeline = self._pipelines.pop(name, None)
        store = self._stores.pop(name, None)
        watcher = self._watchers.pop(name, None)
        streamer = self._streamers.pop(name, None)
        self._http_sinks.pop(name, None)
        if pipeline:
            pipeline.flush_counts()
        if watcher:
            watcher.stop()
        if streamer:
            streamer.stop()
        if store:
            if watcher:
                for file_path, offset_data in watcher.snapshot_offsets().items():
                    store.save_offsets(file_path, offset_data)
            if streamer:
                for container, since in streamer.snapshot().items():
                    store.save_offsets(f"{OFFSET_PREFIX}{container}", {"since": since})
            store.close()

    def _registry_mtime(self) -> float:
        try:
            return self._config.projects_path.stat().st_mtime
        except OSError:
            return 0.0

    async def _reload_projects(self) -> None:
        """Pick up `agent up` / `add-project` / `remove-project` run while the
        daemon is live, so registering a project never needs a restart.
        """
        mtime = self._registry_mtime()
        if mtime == self._projects_mtime:
            return
        self._projects_mtime = mtime
        try:
            wanted = {p.name: p for p in ProjectRegistry(self._config).enabled()}
        except Exception as e:  # noqa: BLE001 - half-written or invalid file: keep what we have
            logger.warning("could not reload projects: %s", e)
            return
        current = set(self._pipelines)
        for name in current - set(wanted):
            self._detach_project(name)
            self._announce(f"stopped watching project '{name}'")
        self._container_registry._projects[:] = list(wanted.values())
        for name in set(wanted) - current:
            self._attach_project(wanted[name])
            self._announce(f"now watching project '{name}'")
        if current != set(wanted):
            await self._container_registry.refresh()

    def _bundle_dir(self, project: str) -> Path:
        return self._config.project_dir(project) / "bundles"

    def _sync_streams(self) -> None:
        if self._container_registry is None:
            return
        for name, streamer in self._streamers.items():
            streamer.sync(self._container_registry._by_project.get(name, []))

    # -- docker events ------------------------------------------------------
    def _on_container_event(self, event: ContainerEvent) -> None:
        task = asyncio.ensure_future(self._handle_container_event(event))
        self._event_tasks.add(task)
        task.add_done_callback(self._event_tasks.discard)

    async def _handle_container_event(self, event: ContainerEvent) -> None:
        # refresh first: the analysis must see the container's state *after*
        # the event, not the cached state from up to a refresh interval ago
        await self._container_registry.refresh()
        project = self._container_registry.project_of(event.container_name)
        if project is None or project not in self._pipelines:
            return
        try:
            self._queue.put_nowait(event_to_record(project, event))
        except asyncio.QueueFull:
            logger.warning("queue full, dropping container event for %s", event.container_name)

    # -- pipeline -----------------------------------------------------------
    def _build_pipeline(self, project: ProjectEntry) -> ProjectPipeline:
        store = ProjectStore(self._config.project_dir(project.name) / "state.db")
        self._stores[project.name] = store

        window = SlidingWindow()
        vector = None
        if self._config.memory.use_faiss and VectorIndex.available():
            vector = VectorIndex(HashingEmbedder())
            vector.rebuild(store)

        ratelimiter = RateLimiter(self._config.ratelimit, store)
        llm = get_provider(self._config.llm)

        sinks = []
        if self._config.sinks.console:
            sinks.append(ConsoleSink())
        if self._config.sinks.sqlite:
            sinks.append(SqliteSink(store))
        if self._config.sinks.http_enabled and self._config.sinks.http_url:
            http = HttpSink(self._config.sinks.http_url, self._config.sinks.http_token_env, store)
            self._http_sinks[project.name] = http
            sinks.append(http)
        if self._notifier is not None and self._notifier.targets:
            sinks.append(NotifySink(self._notifier))
        if self._finding_queue is not None:
            sinks.append(QueueSink(self._finding_queue))

        investigator = None
        if self._config.investigator.auto and Investigator.supported(llm):
            tools = InvestigationTools(self._container_registry, project.name, project.compose_file)
            investigator = Investigator(llm, tools, self._config.investigator.max_steps)

        return ProjectPipeline(
            project.name, self._config, store, window, vector, ratelimiter, llm, FanoutSink(sinks),
            self._container_registry,
            bundle_dir=self._bundle_dir(project.name) if self._config.eval.record_bundles else None,
            investigator=investigator,
        )

    async def _consume_loop(self) -> None:
        while self._running:
            record = await self._queue.get()
            pipeline = self._pipelines.get(record.project)
            if pipeline is None:
                continue
            try:
                await pipeline.process(record)
            except Exception as e:  # noqa: BLE001 - one bad record must not kill the daemon
                reason = (str(e).splitlines() or [""])[0][:300]
                logger.error("analysis failed for project=%s: %s: %s",
                             record.project, type(e).__name__, reason)
                logger.debug("pipeline traceback", exc_info=True)

    # -- housekeeping -------------------------------------------------------
    async def _housekeeping_loop(self) -> None:
        last_outbox = last_slow = time.monotonic()
        while self._running:
            await asyncio.sleep(HOUSEKEEPING_SECONDS)
            now = time.monotonic()
            try:
                for pipeline in list(self._pipelines.values()):
                    pipeline.flush_counts()
                await self._reload_projects()
                if now - last_outbox >= OUTBOX_EVERY:
                    last_outbox = now
                    for sink in list(self._http_sinks.values()):
                        await sink.flush_outbox()
                if now - last_slow >= SLOW_EVERY:
                    last_slow = now
                    await self._verify_fixes()
                    await self._maybe_send_digest()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - housekeeping must never stop the daemon
                logger.exception("housekeeping failed")

    async def _verify_fixes(self) -> None:
        window = self._config.remediation.verify_minutes * 60
        for name, store in list(self._stores.items()):
            for result in verify_pending(store, window):
                if result.status == "verified":
                    message = (f"fix for {result.fingerprint} in '{name}' verified ({result.detail}); "
                               f"saved as its resolution")
                else:
                    message = f"fix for {result.fingerprint} in '{name}' did not hold: {result.detail}"
                self._announce(message)
                if self._notifier and self._notifier.targets:
                    await self._notifier.send("SystemLens fix " + result.status, message)

    async def _maybe_send_digest(self) -> None:
        at = self._config.notify.daily_digest_at
        if not at or not self._notifier or not self._notifier.targets:
            return
        today = time.strftime("%Y-%m-%d")
        if self._last_digest_day == today or time.strftime("%H:%M") < at:
            return
        self._last_digest_day = today
        digest = build_digest(self._stores, time.time() - 86400)
        await self._notifier.send("SystemLens daily digest", render_digest(digest))

    async def add_project_live(self, project: ProjectEntry) -> None:
        """Register and start watching a project after the daemon is already
        running (used by the SDK's `Agent.add_project` when called on a live
        agent, rather than before `start()`).
        """
        self._attach_project(project)
        self._projects_mtime = self._registry_mtime()
        if self._container_registry is not None:
            self._container_registry._projects.append(project)
            await self._container_registry.refresh()

    async def stop(self) -> None:
        self._running = False
        for task in (self._consume_task, self._housekeeping_task):
            if task:
                task.cancel()
        if self._events:
            self._events.stop()
        for name in {*self._pipelines, *self._watchers, *self._stores}:
            self._detach_project(name)
        if self._container_registry:
            await self._container_registry.stop()
        if self._notifier:
            await self._notifier.aclose()
        for store in self._stores.values():
            store.close()
        self._stores.clear()

    # -- status -----------------------------------------------------------
    async def status(self) -> dict:
        out: dict = {}
        for project in self._registry.all():
            store = self._stores.get(project.name)
            containers, confidence = ([], "n/a")
            if self._container_registry:
                containers, confidence = await self._container_registry.containers_for(project.name)
            recent = store.recent_incidents(since=time.time() - 86400) if store else []
            out[project.name] = {
                "watching": project.name in self._watchers,
                "docker_available": await self._docker.is_available(),
                "mapping_confidence": confidence,
                "containers": [c.name for c in containers],
                "open_issues_24h": len(recent),
                "recent": [
                    {"fingerprint": r["fingerprint"], "verdict": r["verdict"],
                     "root_cause": r["root_cause"], "confidence": r["confidence"]}
                    for r in recent[:5]
                ],
            }
        return out
