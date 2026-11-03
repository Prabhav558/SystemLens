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
import time
from typing import Any, Awaitable, Callable, Optional

from systemlens.core.models import Analysis, EvidenceBundle
from systemlens.llm.base import ProviderRateLimited, ProviderUnavailable
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
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
                 max_wait: float = MAX_WAIT_SECONDS, rate_limit_floor: float = 0.0):
        self._primary, self._fallback = primary, fallback
        self._max_retries = max_retries
        self._sleep = sleep
        self._max_wait = max_wait
        self._rate_limit_floor = rate_limit_floor
        self._last = primary
        self._blocked_until: dict[int, float] = {}     # id(provider) -> monotonic time

    def patient(self, max_wait: float = 240.0, max_retries: int = 10, rate_limit_floor: float = 15.0):
        """Wait out per-minute rate limits instead of giving up. For batch work
        (`agent eval`) where nothing is stalled by waiting; the live pipeline
        keeps the short default so one slow provider cannot hold up log processing.
        """
        self._max_wait, self._max_retries, self._rate_limit_floor = max_wait, max_retries, rate_limit_floor
        return self

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
        # A provider that just told us to wait is not asked again until then:
        # every call in the meantime would be refused and only use up quota.
        remaining = self._blocked_until.get(id(provider), 0.0) - time.monotonic()
        if remaining > 0:
            raise ProviderRateLimited(remaining)
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
                if status == 429:
                    wait = retry_after_of(e)
                    if wait is None:
                        wait = 2.0 * (2 ** attempt)
                    wait = max(wait, self._rate_limit_floor)
                    if attempt >= self._max_retries or waited + wait > self._max_wait:
                        # too long to block on: hand back "try again in N seconds"
                        wait = max(wait, 5.0)
                        self._blocked_until[id(provider)] = time.monotonic() + wait
                        raise ProviderRateLimited(wait, str(e).splitlines()[0][:120]) from e
                    attempt += 1
                    waited += wait
                    logger.info("%s returned 429; retrying in %.1fs", provider.name, wait)
                    await self._sleep(wait)
                    continue
                if (status in _TRANSIENT or _is_connection_error(e)) and attempt < self._max_retries:
                    wait = retry_after_of(e)
                    if wait is None:
                        wait = 2.0 * (2 ** attempt)
                    if waited + wait > self._max_wait:
                        raise
                    attempt += 1
                    waited += wait
                    logger.info("%s returned %s; retrying in %.1fs", provider.name, status or type(e).__name__, wait)
                    await self._sleep(wait)
                    continue
                raise
