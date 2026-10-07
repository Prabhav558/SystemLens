"""Where a Finding goes once it's produced. ReportSink is the seam that
keeps Render-hosting a config change instead of a rewrite: HttpSink exists
today, ships disabled by default, and posts to wherever `sinks.http_url`
points — local dashboard now, a Render-hosted one later.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Protocol

from rich.console import Console
from rich.panel import Panel

from systemlens.core.models import Finding
from systemlens.memory.store import ProjectStore

logger = logging.getLogger("systemlens.sinks")


class ReportSink(Protocol):
    async def emit(self, finding: Finding) -> None: ...


class ConsoleSink:
    def __init__(self):
        self._console = Console()

    async def emit(self, finding: Finding) -> None:
        a = finding.analysis
        color = {"root_cause_identified": "red", "probable_cause": "yellow",
                 "insufficient_evidence": "dim"}[a.verdict]
        body = (
            f"[bold]component:[/bold] {a.affected_component}\n"
            f"[bold]root cause:[/bold] {a.root_cause}\n"
            f"[bold]fix:[/bold] {a.fix_suggestion}\n"
            f"[bold]confidence:[/bold] {a.confidence:.2f}  "
            f"[bold]verdict:[/bold] {a.verdict}"
        )
        self._console.print(Panel(
            body, title=f"[{color}]{finding.project} :: {finding.fingerprint}[/{color}]",
            border_style=color,
        ))


class SqliteSink:
    """Persists via the same ProjectStore the correlator/ratelimiter use —
    one row per analyzed incident, keyed by fingerprint.
    """
    def __init__(self, store: ProjectStore):
        self._store = store

    async def emit(self, finding: Finding) -> None:
        # Cooldown tracking (mark_analyzed) is owned by ProjectPipeline itself,
        # so it applies regardless of which sinks are enabled.
        self._store.record_incident(finding.fingerprint, finding.analysis,
                                     finding.provider, finding.model)


class HttpSink:
    """Off by default (config.sinks.http_enabled). Pushes each finding to a
    central server. A push that fails is kept in the project's outbox and
    retried, so findings made while the server is unreachable are not lost.
    Only the analysis is sent — never raw logs or the evidence bundle.
    """
    def __init__(self, url: str, token_env: str, store: ProjectStore, client=None):
        import httpx
        self._url = url
        self._token = os.environ.get(token_env)
        self._store = store
        self._client = client or httpx.AsyncClient(timeout=10.0)

    @staticmethod
    def payload(project: str, fingerprint: str, analysis: dict, provider, model, created_at: float) -> dict:
        return {"project": project, "fingerprint": fingerprint, "analysis": analysis,
                "provider": provider, "model": model, "created_at": created_at}

    async def emit(self, finding: Finding) -> None:
        payload = self.payload(finding.project, finding.fingerprint,
                               json.loads(finding.analysis.model_dump_json()),
                               finding.provider, finding.model, finding.created_at)
        if await self.push(payload):
            await self.flush_outbox()       # the server is reachable: drain anything queued
        else:
            self._store.outbox_add(payload)

    async def push(self, payload: dict) -> bool:
        headers = {"Authorization": f"Bearer {self._token}"} if self._token else {}
        try:
            resp = await self._client.post(self._url, json=payload, headers=headers)
        except Exception as e:  # noqa: BLE001 - network trouble: retry later
            logger.warning("push to central server failed (%s); queued for retry", type(e).__name__)
            return False
        if resp.status_code in (401, 403):
            logger.warning("central server rejected the API key (HTTP %s); queued for retry",
                           resp.status_code)
            return False
        if resp.status_code >= 500 or resp.status_code == 429:
            logger.warning("central server returned HTTP %s; queued for retry", resp.status_code)
            return False
        if resp.status_code >= 400:
            # the server understood and refused this payload: retrying cannot help
            logger.warning("central server refused a finding (HTTP %s); dropped", resp.status_code)
        return True

    async def flush_outbox(self, limit: int = 20) -> int:
        sent = 0
        for row in self._store.outbox_batch(limit):
            if not await self.push(json.loads(row["payload"])):
                self._store.outbox_failed(row["id"])
                break               # still unreachable: stop, try again later
            self._store.outbox_done(row["id"])
            sent += 1
        return sent

    async def aclose(self) -> None:
        await self._client.aclose()


class NotifySink:
    """Sends findings that pass the notification threshold to Slack /
    Discord / webhook / desktop (see core/notify.py).
    """
    def __init__(self, notifier):
        self._notifier = notifier

    async def emit(self, finding: Finding) -> None:
        if self._notifier.wants(finding):
            await self._notifier.notify_finding(finding)


class FanoutSink:
    def __init__(self, sinks: list[ReportSink]):
        self._sinks = sinks

    async def emit(self, finding: Finding) -> None:
        for sink in self._sinks:
            try:
                await sink.emit(finding)
            except Exception:  # noqa: BLE001 - one sink failing must not block others
                logger.exception("sink %s failed to emit finding", sink)


class QueueSink:
    """Feeds Findings into an asyncio.Queue — how the SDK's `Agent.watch()`
    receives results without polling SQLite.
    """
    def __init__(self, queue):
        self._queue = queue

    async def emit(self, finding: Finding) -> None:
        await self._queue.put(finding)
