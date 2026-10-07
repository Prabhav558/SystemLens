"""Native container log ingestion: follow each mapped container's
stdout/stderr through the Docker API, so a project needs no log files and no
`docker compose logs > file` workaround. Every record carries the container
that emitted it, which is what lets the correlator scope its candidates.

Threading: one reader thread per container blocks on the Docker stream and
hands each line to the event loop with call_soon_threadsafe. All buffering,
assembly and bookkeeping happens on the loop, so none of it needs a lock.
"""
from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Callable, Iterable, Optional

from systemlens.core.models import ContainerState, LogRecord
from systemlens.logs.parse import assemble_records, split_docker_line

logger = logging.getLogger("systemlens.logstream")

OFFSET_PREFIX = "container:"
MAX_RESUME_SECONDS = 600     # never replay more than this after a restart
FLUSH_DELAY = 0.25           # quiet period that ends a multi-line record
MAX_BUFFERED_LINES = 200


class LineSplitter:
    """Docker delivers log data in arbitrary chunks; this yields whole lines."""

    def __init__(self) -> None:
        self._carry = b""

    def feed(self, chunk: bytes) -> list[str]:
        data = self._carry + chunk
        *complete, self._carry = data.split(b"\n")
        return [line.decode("utf-8", errors="replace").rstrip("\r") for line in complete]


# (container_id, since) -> an iterable of byte chunks that also has .close()
StreamFactory = Callable[[str, Optional[float]], Iterable[bytes]]


class _DockerLogStream:
    """A followed log stream plus the dedicated client that owns its connection."""

    def __init__(self, client, stream):
        self._client, self._stream = client, stream

    def __iter__(self):
        try:
            yield from self._stream
        finally:
            self.close()

    def close(self) -> None:
        for closer in (getattr(self._stream, "close", None), self._client.close):
            try:
                if closer:
                    closer()
            except Exception:  # noqa: BLE001 - already closed
                pass


def docker_stream_factory(docker_sync) -> StreamFactory:
    def open_stream(container_id: str, since: Optional[float]):
        client = docker_sync.new_raw_client()
        kwargs = {"stream": True, "follow": True, "timestamps": True}
        if since is None:
            kwargs["tail"] = 0          # only what is logged from now on
        else:
            kwargs["since"] = since
        try:
            return _DockerLogStream(client, client.containers.get(container_id).logs(**kwargs))
        except Exception:
            client.close()
            raise
    return open_stream


class ContainerLogStreamer:
    """Follows the logs of one project's containers. Call `sync()` with the
    current container list whenever it is refreshed; streams are attached
    for running containers and re-attached after a restart.
    """

    def __init__(self, project: str, open_stream: StreamFactory,
                 out_queue: "asyncio.Queue[LogRecord]", loop: asyncio.AbstractEventLoop,
                 resume: Optional[dict[str, float]] = None, flush_delay: float = FLUSH_DELAY):
        self.project = project
        self._open_stream = open_stream
        self._queue = out_queue
        self._loop = loop
        self._flush_delay = flush_delay
        now = time.time()
        # newest log timestamp delivered per container; doubles as resume point
        self._last_ts: dict[str, float] = {
            name: max(ts, now - MAX_RESUME_SECONDS) for name, ts in (resume or {}).items()
        }
        self._attached: dict[str, object] = {}        # name -> open stream
        self._buffers: dict[str, list[str]] = {}
        self._flush_handles: dict[str, asyncio.TimerHandle] = {}
        self._first_sync_done = False
        self._stopped = False

    # -- lifecycle (loop thread) -------------------------------------------
    def sync(self, containers: list[ContainerState]) -> None:
        if self._stopped:
            return
        for c in containers:
            if not c.running or c.name in self._attached:
                continue
            since = self._last_ts.get(c.name)
            if since is None and self._first_sync_done:
                # Appeared while we were already watching: take its logs from
                # its own start, not from whenever we happened to notice it.
                since = c.started_at
            self._attached[c.name] = None
            threading.Thread(target=self._reader, args=(c.id, c.name, since),
                             name=f"logstream-{c.name}", daemon=True).start()
        self._first_sync_done = True

    def stop(self) -> None:
        self._stopped = True
        for stream in list(self._attached.values()):
            close = getattr(stream, "close", None)
            if close:
                try:
                    close()
                except Exception:  # noqa: BLE001 - best effort on shutdown
                    pass
        for name in list(self._buffers):
            self._flush(name)

    def snapshot(self) -> dict[str, float]:
        return dict(self._last_ts)

    # -- reader thread --------------------------------------------------------
    def _reader(self, container_id: str, name: str, since: Optional[float]) -> None:
        try:
            stream = self._open_stream(container_id, since)
            self._loop.call_soon_threadsafe(self._on_opened, name, stream)
            splitter = LineSplitter()
            for chunk in stream:
                for line in splitter.feed(chunk):
                    self._loop.call_soon_threadsafe(self._on_line, name, line, since)
        except Exception as e:  # noqa: BLE001 - container gone, daemon down, stream closed
            logger.debug("log stream for %s ended: %s", name, e)
        finally:
            try:
                self._loop.call_soon_threadsafe(self._on_closed, name)
            except RuntimeError:
                pass  # loop already closed during shutdown

    # -- loop thread ------------------------------------------------------------
    def _on_opened(self, name: str, stream: object) -> None:
        if self._stopped:
            close = getattr(stream, "close", None)
            if close:
                close()
            return
        if name in self._attached:
            self._attached[name] = stream

    def _on_line(self, name: str, line: str, since: Optional[float]) -> None:
        if self._stopped:
            return
        _, ts, _ = split_docker_line(line, name)
        # `since` is inclusive on the Docker side: drop what was already delivered
        if ts is not None and since is not None and ts <= since:
            return
        if ts is not None:
            self._last_ts[name] = max(ts, self._last_ts.get(name, 0.0))
        buf = self._buffers.setdefault(name, [])
        buf.append(line)
        handle = self._flush_handles.pop(name, None)
        if handle:
            handle.cancel()
        if len(buf) >= MAX_BUFFERED_LINES:
            self._flush(name)
        else:
            # a traceback arrives as many lines; wait for a quiet moment so
            # they are assembled into one record rather than split
            self._flush_handles[name] = self._loop.call_later(self._flush_delay, self._flush, name)

    def _flush(self, name: str) -> None:
        handle = self._flush_handles.pop(name, None)
        if handle:
            handle.cancel()
        lines = self._buffers.pop(name, [])
        if not lines:
            return
        for record in assemble_records(iter(lines), self.project, f"{OFFSET_PREFIX}{name}", container=name):
            try:
                self._queue.put_nowait(record)
            except asyncio.QueueFull:
                logger.warning("queue full for project=%s, dropping record", self.project)

    def _on_closed(self, name: str) -> None:
        self._flush(name)
        self._attached.pop(name, None)   # next sync() re-attaches if it is running again
