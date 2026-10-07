"""Notifications: Slack, Discord, a generic webhook and desktop popups.

A target is active when its environment variable is set (webhook URLs are
credentials, so they stay out of config.yaml). Sending never raises: a
notification problem must not affect analysis.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
from typing import Optional

import httpx

from systemlens.config import NotifyConfig
from systemlens.core.models import Finding

logger = logging.getLogger("systemlens.notify")

_VERDICT_LABEL = {
    "root_cause_identified": "Root cause identified",
    "probable_cause": "Probable cause",
    "insufficient_evidence": "Inconclusive",
}


class Notifier:
    def __init__(self, config: NotifyConfig, client: Optional[httpx.AsyncClient] = None):
        self._config = config
        self._slack = os.environ.get(config.slack_webhook_env)
        self._discord = os.environ.get(config.discord_webhook_env)
        self._webhook = os.environ.get(config.webhook_url_env)
        self._desktop = config.desktop and shutil.which("notify-send") is not None
        self._client = client or httpx.AsyncClient(timeout=10.0)

    @property
    def targets(self) -> list[str]:
        return [name for name, on in (("slack", self._slack), ("discord", self._discord),
                                      ("webhook", self._webhook), ("desktop", self._desktop)) if on]

    def wants(self, finding: Finding) -> bool:
        a = finding.analysis
        return bool(self.targets) and a.verdict in self._config.verdicts \
            and a.confidence >= self._config.min_confidence

    async def send(self, title: str, body: str, payload: Optional[dict] = None) -> dict[str, bool]:
        """Deliver to every active target. Returns target -> delivered."""
        jobs = {}
        if self._slack:
            jobs["slack"] = self._post(self._slack, {"text": f"*{title}*\n{body}"})
        if self._discord:
            jobs["discord"] = self._post(self._discord, {"content": f"**{title}**\n{body}"[:1990]})
        if self._webhook:
            jobs["webhook"] = self._post(self._webhook, payload or {"title": title, "body": body})
        if self._desktop:
            jobs["desktop"] = self._desktop_notify(title, body)
        results = await asyncio.gather(*jobs.values())
        return dict(zip(jobs.keys(), results))

    async def notify_finding(self, finding: Finding) -> dict[str, bool]:
        a = finding.analysis
        title = f"{_VERDICT_LABEL.get(a.verdict, a.verdict)} in {finding.project}: {a.affected_component}"
        body = (f"{a.root_cause}\nFix: {a.fix_suggestion}\n"
                f"Confidence {a.confidence:.2f} · fingerprint {finding.fingerprint}")
        payload = {
            "type": "finding", "project": finding.project, "fingerprint": finding.fingerprint,
            "verdict": a.verdict, "affected_component": a.affected_component,
            "root_cause": a.root_cause, "fix_suggestion": a.fix_suggestion,
            "confidence": a.confidence, "created_at": finding.created_at,
        }
        return await self.send(title, body, payload)

    async def _post(self, url: str, body: dict) -> bool:
        try:
            resp = await self._client.post(url, json=body)
            resp.raise_for_status()
            return True
        except Exception as e:  # noqa: BLE001 - never let a notification break analysis
            logger.warning("notification failed: %s", type(e).__name__)
            return False

    @staticmethod
    async def _desktop_notify(title: str, body: str) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec("notify-send", "--app-name=SystemLens", title, body[:400])
            return await proc.wait() == 0
        except OSError:
            return False

    async def aclose(self) -> None:
        await self._client.aclose()
