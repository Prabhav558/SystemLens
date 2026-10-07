"""The thing that keeps this usable. Without deduplication and budgets, a
chatty dev log fires an LLM call per error and either bankrupts the user or
gets ignored within a week. This module is consulted before every LLM call
and is the single place that decision is made.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from systemlens.config import RateLimitConfig
from systemlens.memory.store import ProjectStore


@dataclass(slots=True)
class RateLimitDecision:
    allow: bool
    reason: str


class RateLimiter:
    def __init__(self, config: RateLimitConfig, store: ProjectStore):
        self._config = config
        self._store = store
        self._token_spend_today = 0
        self._day_start = _today_start()

    def _roll_day(self) -> None:
        start = _today_start()
        if start != self._day_start:
            self._day_start = start
            self._token_spend_today = 0

    def record_spend(self, tokens: int) -> None:
        self._roll_day()
        self._token_spend_today += tokens

    def check(self, fingerprint: str, state_changed: bool, free: bool = False) -> RateLimitDecision:
        """`free` marks an answer that costs no LLM call (resolution memory):
        the token and hourly budgets don't apply, only the cooldown does.
        """
        self._roll_day()

        if not free:
            if self._token_spend_today >= self._config.daily_token_budget:
                return RateLimitDecision(False, "daily_token_budget_exhausted")

            calls_last_hour = self._store.analyses_last_hour() + self._store.attempts_last_hour()
            if calls_last_hour >= self._config.max_analyses_per_hour:
                return RateLimitDecision(False, "hourly_analysis_cap_reached")

        on_cooldown = not self._store.should_analyze(fingerprint, self._config.cooldown_seconds)
        if on_cooldown:
            if (self._config.reanalyze_on_state_change and state_changed
                    and self._store.should_analyze(fingerprint, self._config.min_reanalyze_seconds)):
                return RateLimitDecision(True, "cooldown_bypassed_state_changed")
            return RateLimitDecision(False, "fingerprint_on_cooldown")

        return RateLimitDecision(True, "ok")


def _today_start() -> float:
    now = datetime.now(timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
