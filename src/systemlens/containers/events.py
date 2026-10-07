"""Docker events as triggers. A crash, an OOM kill or a failing health check
often leaves no log line at all (a SIGKILLed process cannot log), so
log-driven analysis alone never sees it. These events are turned into
synthetic records that go through the same pipeline as any log signal.

`interpret_event` is pure, so the decision logic is tested without Docker.
"""
from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from systemlens.core.models import LogRecord, Severity

logger = logging.getLogger("systemlens.events")

USER_STOP_WINDOW = 30.0   # a `die` this soon after a `kill` is a stop someone asked for
OOM_WINDOW = 30.0


@dataclass(slots=True)
class ContainerEvent:
    kind: str                 # "exit" | "oom" | "unhealthy"
    container_id: str
    container_name: str
    exit_code: Optional[int]
    at: float


class EventInterpreter:
    """Decides which Docker events are failures worth analysing.

    - `die` with exit code 0, or shortly after a `kill` event (docker stop /
      kill / compose down), is a deliberate stop — ignored.
    - `die` after an `oom` event is reported once, as an OOM kill.
    - `health_status: unhealthy` is reported; other health transitions are not.
    """

    def __init__(self) -> None:
        self._kills: dict[str, float] = {}
        self._ooms: dict[str, float] = {}

    def interpret(self, event: dict) -> Optional[ContainerEvent]:
        if event.get("Type") != "container":
            return None
        action = str(event.get("Action", ""))
        actor = event.get("Actor") or {}
        cid = str(actor.get("ID") or event.get("id") or "")
        attrs = actor.get("Attributes") or {}
        name = attrs.get("name", "")
        nanos = event.get("timeNano")
        at = nanos / 1e9 if nanos else float(event.get("time") or time.time())
        if not cid or not name:
            return None

        if action == "kill":
            self._kills[cid] = at
            return None
        if action == "oom":
            self._ooms[cid] = at
            return None
        if action == "die":
            try:
                exit_code = int(attrs.get("exitCode", 0))
            except (TypeError, ValueError):
                exit_code = None
            oom_at = self._ooms.pop(cid, None)
            kill_at = self._kills.pop(cid, None)
            if oom_at is not None and at - oom_at <= OOM_WINDOW:
                return ContainerEvent("oom", cid[:12], name, exit_code, at)
            if exit_code == 0:
                return None
            if kill_at is not None and at - kill_at <= USER_STOP_WINDOW:
                return None
            return ContainerEvent("exit", cid[:12], name, exit_code, at)
        if action.startswith("health_status") and action.endswith("unhealthy"):
            return ContainerEvent("unhealthy", cid[:12], name, None, at)
        return None


def event_to_record(project: str, ev: ContainerEvent) -> LogRecord:
    if ev.kind == "oom":
        raw = (f"container {ev.container_name} was killed by the kernel OOM killer "
               f"(exit code {ev.exit_code})")
        category, severity = "oom", Severity.CRITICAL
    elif ev.kind == "unhealthy":
        raw = f"container {ev.container_name} health check is failing (status: unhealthy)"
        category, severity = "health_check", Severity.ERROR
    else:
        raw = f"container {ev.container_name} exited unexpectedly with exit code {ev.exit_code}"
        category, severity = "container_exit", Severity.ERROR
    return LogRecord(project=project, source="docker:events", raw=raw, ts=time.time(),
                     event_ts=ev.at, severity=severity, container=ev.container_name,
                     category_hint=category)


class DockerEventWatcher:
    """Reads the Docker event stream in a thread and calls `on_event` on the
    event loop for each failure. Reconnects if the daemon goes away.
    """

    def __init__(self, docker_sync, loop: asyncio.AbstractEventLoop,
                 on_event: Callable[[ContainerEvent], None], retry_seconds: float = 5.0):
        self._docker = docker_sync
        self._loop = loop
        self._on_event = on_event
        self._retry_seconds = retry_seconds
        self._interpreter = EventInterpreter()
        self._stream = None
        self._stopped = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._run, name="docker-events", daemon=True).start()

    def stop(self) -> None:
        self._stopped.set()
        stream = self._stream
        if stream is not None:
            try:
                stream.close()
            except Exception:  # noqa: BLE001 - best effort on shutdown
                pass

    def _run(self) -> None:
        while not self._stopped.is_set():
            try:
                client = self._docker.new_raw_client()
                self._stream = client.events(decode=True, filters={"type": "container"})
                for event in self._stream:
                    if self._stopped.is_set():
                        return
                    ev = self._interpreter.interpret(event)
                    if ev is not None:
                        self._loop.call_soon_threadsafe(self._on_event, ev)
            except Exception as e:  # noqa: BLE001 - daemon down or stream closed
                logger.debug("docker event stream ended: %s", e)
            self._stopped.wait(self._retry_seconds)
