"""Short-term memory: a per-project sliding window of recent LogRecords, used
to build the `log_window` evidence the correlator/LLM sees around an incident.
"""
from __future__ import annotations

from collections import deque
from typing import Iterable

from systemlens.core.models import LogRecord


class SlidingWindow:
    def __init__(self, maxlen: int = 500):
        self._buf: deque[LogRecord] = deque(maxlen=maxlen)

    def add(self, record: LogRecord) -> None:
        self._buf.append(record)

    def around(self, ts: float, window_seconds: int, limit: int) -> list[LogRecord]:
        lo, hi = ts - window_seconds, ts + 5
        matched = [r for r in self._buf if lo <= r.when <= hi]
        return matched[-limit:]

    def recent(self, limit: int) -> list[LogRecord]:
        return list(self._buf)[-limit:]

    def __len__(self) -> int:
        return len(self._buf)

    def extend(self, records: Iterable[LogRecord]) -> None:
        for r in records:
            self.add(r)
