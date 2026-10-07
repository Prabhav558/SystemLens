"""Turn raw tailed lines into LogRecords: parse severity/timestamp, and glue
multi-line stack traces / tracebacks back into one logical record.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Iterator, Optional

from systemlens.core.models import LogRecord, Severity
from systemlens.logs.redact import redact

# Common timestamp shapes: ISO8601, syslog, uvicorn/gunicorn, docker json-log.
_TS_PATTERNS = [
    re.compile(r"^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]?"),
    re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),  # "Jan  2 15:04:05"
]

_LEVEL_RE = re.compile(
    r"\b(TRACE|DEBUG|DBG|INFO|NOTICE|WARN(?:ING)?|ERR(?:OR)?|SEVERE|CRIT(?:ICAL)?|FATAL|PANIC|EMERG)\b",
    re.IGNORECASE,
)

# A continuation line: indented, or a traceback frame, or a bare "Caused by:".
_CONTINUATION_RE = re.compile(
    r"^(\s+|Traceback \(most recent call last\)|Caused by:|\tat |  File \"|"
    r"[\w.]+(Error|Exception)\b)"
)


_ISO_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
)


def _parse_ts(line: str) -> Optional[float]:
    m = _TS_PATTERNS[0].match(line)
    if m:
        raw = m.group(1)
        for fmt in _ISO_FORMATS:
            try:
                dt = datetime.strptime(raw, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except ValueError:
                continue

    m = _TS_PATTERNS[1].match(line)
    if m:
        # syslog format carries no year ("Jan  2 15:04:05") — assume current
        # year, which is the conventional interpretation for this format.
        try:
            dt = datetime.strptime(m.group(1), "%b %d %H:%M:%S")
            dt = dt.replace(year=datetime.now(timezone.utc).year, tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            pass
    return None


def _parse_severity(line: str) -> Severity:
    m = _LEVEL_RE.search(line)
    return Severity.parse(m.group(1)) if m else Severity.INFO


def is_continuation(line: str) -> bool:
    return bool(_CONTINUATION_RE.match(line)) if line else False


MAX_FOLDED_LINES = 40  # a record's raw text is dumped in full into LLM prompts
                        # (render_evidence has no per-line cap) — an unbounded
                        # fold lets one large traceback consume the entire
                        # token budget regardless of anything else in play.


# `docker compose logs --timestamps` prefixes every line "service  | <ts> ".
# The Docker RFC3339 timestamp is required for a match, so an ordinary line
# such as "ERROR | something" is never mistaken for a container prefix.
_COMPOSE_PREFIX_RE = re.compile(
    r"^(?P<name>[\w][\w.-]*)\s+\| (?P<rest>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z(?: .*)?)$",
    re.S,
)
_DOCKER_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z ?(.*)$", re.S)


def split_docker_line(line: str, container: Optional[str] = None) -> tuple[Optional[str], Optional[float], str]:
    """Strip Docker framing from a line: an optional `docker compose logs`
    service prefix and the Docker-added timestamp. Returns (container,
    docker timestamp, the application's own text). Lines without that
    framing come back unchanged with (container, None, line).
    """
    if container is None:
        m = _COMPOSE_PREFIX_RE.match(line)
        if m:
            container, line = m.group("name"), m.group("rest")
        else:
            return None, None, line
    m = _DOCKER_TS_RE.match(line)
    if not m:
        return container, None, line
    head, frac, rest = m.groups()
    frac = ((frac or "") + "000000")[:6]
    ts = datetime.strptime(f"{head}.{frac}", "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp()
    return container, ts, rest


def assemble_records(lines: Iterator[str], project: str, source: str,
                     container: Optional[str] = None) -> list[LogRecord]:
    """Group raw lines into logical records, folding continuation lines
    (stack traces, wrapped JSON, etc.) into the record they belong to, up to
    MAX_FOLDED_LINES — further continuation lines are dropped, not folded,
    so one huge traceback can't grow a record without bound.

    `container` is given when the lines come straight from one container's
    log stream. Without it, a `docker compose logs --timestamps` prefix is
    recognised per line, so a tee'd compose log still yields each record's
    origin container. Secrets are redacted here, once, for everything
    downstream.
    """
    records: list[LogRecord] = []
    now = time.time()
    for line in lines:
        origin, docker_ts, text = split_docker_line(line, container)
        if not text.strip():
            continue
        text = redact(text)
        if records and is_continuation(text) and records[-1].container == origin:
            prev = records[-1]
            if prev.lines >= MAX_FOLDED_LINES:
                continue  # cap reached — drop further continuation lines
            prev.raw = f"{prev.raw}\n{text}"
            prev.lines += 1
            if prev.severity < Severity.ERROR and _LEVEL_RE.search(text):
                prev.severity = max(prev.severity, _parse_severity(text))
            continue
        records.append(LogRecord(
            project=project,
            source=source,
            raw=text,
            ts=now,
            event_ts=docker_ts if docker_ts is not None else _parse_ts(text),
            severity=_parse_severity(text),
            container=origin,
        ))
    return records
