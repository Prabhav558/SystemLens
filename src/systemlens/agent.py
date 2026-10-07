"""The pip-installable SDK entry point:

    from systemlens import Agent

    async with Agent.from_config() as a:
        await a.add_project("./myapp", logs="./logs")
        async for finding in a.watch():
            print(finding.analysis.root_cause, finding.analysis.fix_suggestion)

Thin wrapper around AgentDaemon + ProjectRegistry — the CLI (`agent start`)
is built on the same class, so the SDK and CLI never drift apart.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import AsyncIterator, Optional

from systemlens.config import AgentConfig
from systemlens.core.daemon import AgentDaemon
from systemlens.core.models import Finding
from systemlens.projects.registry import ProjectEntry, ProjectRegistry, build_project_entry


class Agent:
    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig.load()
        self.registry = ProjectRegistry(self.config)
        self._finding_queue: asyncio.Queue[Finding] = asyncio.Queue()
        self._daemon: Optional[AgentDaemon] = None

    @classmethod
    def from_config(cls, path: Optional[Path] = None) -> "Agent":
        return cls(AgentConfig.load(path))

    async def add_project(self, path: str, logs: Optional[str] = None, name: Optional[str] = None,
                          docker_logs: Optional[bool] = None) -> ProjectEntry:
        entry = build_project_entry(Path(path).resolve(), name, logs, docker_logs)
        self.registry.add(entry)
        if self._daemon is not None:
            await self._daemon.add_project_live(entry)
        return entry

    async def start(self) -> None:
        self._daemon = AgentDaemon(self.config, self.registry, finding_queue=self._finding_queue)
        await self._daemon.start()

    async def stop(self) -> None:
        if self._daemon is not None:
            await self._daemon.stop()
            self._daemon = None

    async def status(self) -> dict:
        if self._daemon is None:
            return {}
        return await self._daemon.status()

    async def watch(self) -> AsyncIterator[Finding]:
        """Yield Findings as they're produced. Must be running (`start()` /
        `async with`) first.
        """
        while True:
            yield await self._finding_queue.get()

    async def __aenter__(self) -> "Agent":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.stop()
