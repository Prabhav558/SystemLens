"""Bridges watchdog's synchronous, threaded filesystem events into the
asyncio pipeline. One ProjectWatcher per project; every event lands on the
same asyncio.Queue via call_soon_threadsafe (never call queue.put_nowait
directly from a watchdog thread — it isn't thread-safe against the loop).
"""
from __future__ import annotations

import asyncio
import glob as glob_module
import logging
from pathlib import Path
from typing import Optional

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from systemlens.core.models import LogRecord
from systemlens.logs.parse import assemble_records
from systemlens.logs.tailer import FileTailer

logger = logging.getLogger("systemlens.watcher")


def matches_log_glob(path: Path, log_globs: list[str]) -> bool:
    return any(path.match(g) or str(path).endswith(Path(g).name.lstrip("*")) for g in log_globs)


class _Handler(FileSystemEventHandler):
    def __init__(self, watcher: "ProjectWatcher"):
        self._watcher = watcher

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._watcher._notify_threadsafe(Path(event.src_path))

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._watcher._notify_threadsafe(Path(event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        # rotation via rename (logrotate `copytruncate`-less mode)
        if not event.is_directory:
            self._watcher._notify_threadsafe(Path(event.dest_path))


class ProjectWatcher:
    """Watches every file matching the project's log globs and pushes
    LogRecords onto `out_queue`.
    """

    def __init__(
        self,
        project: str,
        root: Path,
        log_globs: list[str],
        out_queue: "asyncio.Queue[LogRecord]",
        offsets: Optional[dict] = None,
    ):
        self.project = project
        self.root = root
        self.log_globs = log_globs
        self._queue = out_queue
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._tailers: dict[str, FileTailer] = {}
        self._offsets = offsets or {}
        self._observer: Optional[Observer] = None
        self._watched_dirs: set[Path] = set()

    # -- lifecycle -------------------------------------------------------
    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._observer = Observer()
        for path in self._resolve_globs():
            self._register(path)
        for d in self._watched_dirs:
            self._observer.schedule(_Handler(self), str(d), recursive=False)
        self._observer.start()
        # prime: pick up anything already in each file (from saved offsets)
        for path in list(self._tailers):
            self._drain(Path(path))

    def stop(self) -> None:
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)

    def snapshot_offsets(self) -> dict:
        return {p: t.to_offsets() for p, t in self._tailers.items()}

    # -- internals ---------------------------------------------------------
    def _resolve_globs(self) -> list[Path]:
        found: list[Path] = []
        for pattern in self.log_globs:
            if Path(pattern).is_absolute():
                # stdlib glob (not pathlib) so "**" is handled recursively
                # even for absolute patterns like /project/logs/**/*.log.
                found.extend(Path(p) for p in glob_module.glob(pattern, recursive=True))
            else:
                found.extend(self.root.glob(pattern))
        return found

    def _register(self, path: Path) -> None:
        key = str(path)
        if key in self._tailers:
            return
        saved = self._offsets.get(key)
        self._tailers[key] = (
            FileTailer.from_offsets(path, saved) if saved else FileTailer(path, from_end=True)
        )
        self._watched_dirs.add(path.parent)

    def _notify_threadsafe(self, path: Path) -> None:
        if self._loop is None:
            return
        if not matches_log_glob(path, self.log_globs):
            # new file appearing in a watched dir that doesn't match our globs
            if str(path) not in self._tailers:
                return
        self._loop.call_soon_threadsafe(self._on_event, path)

    def _on_event(self, path: Path) -> None:
        self._register(path)
        self._drain(path)

    def _drain(self, path: Path) -> None:
        tailer = self._tailers.get(str(path))
        if tailer is None:
            return
        try:
            lines = tailer.poll()
        except OSError as e:
            logger.warning("tailer poll failed for %s: %s", path, e)
            return
        if not lines:
            return
        for record in assemble_records(iter(lines), self.project, str(path)):
            try:
                self._queue.put_nowait(record)
            except asyncio.QueueFull:
                logger.warning("queue full for project=%s, dropping record", self.project)
