"""Retry, shrink and fall back — in one place, for every provider.

- 429 and transient 5xx / connection errors: wait (honouring Retry-After,
  capped) and retry, up to `max_retries`.
- 413 "request too large": halve the evidence budget and retry. This is the
  per-minute token ceiling on small tiers, which a wait alone never fixes.
- When the primary provider is exhausted and a fallback is configured, the
  fallback answers instead.

The analysis pipeline handles one record at a time, so total waiting is
capped: a slow provider must not stall log processing for minutes.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Optional

from systemlens.core.models import Analysis, EvidenceBundle
from systemlens.llm.base import ProviderUnavailable
from systemlens.llm.prompt import DEFAULT_MAX_EVIDENCE_CHARS

logger = logging.getLogger("systemlens.llm")

MAX_WAIT_SECONDS = 20.0
MIN_EVIDENCE_CHARS = 1500
_TRANSIENT = {408, 429, 500, 502, 503, 504}


def status_of(exc: BaseException) -> Optional[int]:
    status = getattr(exc, "status_code", None)
    if status is None:
        status = getattr(getattr(exc, "response", None), "status_code", None)
    return status if isinstance(status, int) else None


def retry_after_of(exc: BaseException) -> Optional[float]:
    headers = getattr(getattr(exc, "response", None), "headers", None) or {}
    try:
        return float(headers.get("retry-after"))
    except (TypeError, ValueError):
        return None


def _is_connection_error(exc: BaseException) -> bool:
    return type(exc).__name__ in {"APIConnectionError", "APITimeoutError", "ConnectError",
                                  "ConnectTimeout", "ReadTimeout", "RemoteProtocolError"}


class ResilientProvider:
    def __init__(self, primary, fallback=None, max_retries: int = 2,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep):
        self._primary, self._fallback = primary, fallback
        self._max_retries = max_retries
        self._sleep = sleep
        self._last = primary

    # whoever answered last, so findings are attributed to the right model
    @property
    def name(self) -> str:
        return self._last.name

    @property
    def model(self) -> str:
        return self._last.model

    async def analyze(self, bundle: EvidenceBundle) -> Analysis:
        return await self._run("analyze", bundle)

    async def complete_json(self, system: str, user: str, schema_model):
        return await self._run("complete_json", system, user, schema_model)

    async def complete_text(self, system: str, user: str) -> str:
        return await self._run("complete_text", system, user)

    async def _run(self, method: str, *args: Any):
        try:
            return await self._attempts(self._primary, method, args)
        except Exception as primary_error:  # noqa: BLE001
            if self._fallback is None or not hasattr(self._fallback, method):
                raise
            logger.warning("%s failed (%s: %s); using fallback provider %s",
                           self._primary.name, type(primary_error).__name__,
                           str(primary_error).splitlines()[0][:160], self._fallback.name)
            return await self._attempts(self._fallback, method, args)

    async def _attempts(self, provider, method: str, args: tuple):
        bundle = args[0] if args and isinstance(args[0], EvidenceBundle) else None
        waited, attempt = 0.0, 0
        while True:
            try:
                result = await getattr(provider, method)(*args)
                self._last = provider
                return result
            except ProviderUnavailable:
                raise
            except Exception as e:  # noqa: BLE001 - classified below
                status = status_of(e)
                if status == 413 and bundle is not None:
                    current = bundle.max_evidence_chars or DEFAULT_MAX_EVIDENCE_CHARS
                    if current // 2 < MIN_EVIDENCE_CHARS:
                        raise
                    bundle.max_evidence_chars = current // 2
                    logger.warning("%s rejected the request as too large; retrying with %d chars "
                                   "of evidence", provider.name, bundle.max_evidence_chars)
                    continue
                if (status in _TRANSIENT or _is_connection_error(e)) and attempt < self._max_retries:
                    wait = retry_after_of(e)
                    if wait is None:
                        wait = 2.0 * (2 ** attempt)
                    if waited + wait > MAX_WAIT_SECONDS:
                        raise
                    attempt += 1
                    waited += wait
                    logger.info("%s returned %s; retrying in %.1fs", provider.name, status or type(e).__name__, wait)
                    await self._sleep(wait)
                    continue
                raise
