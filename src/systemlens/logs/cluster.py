"""Log template mining: collapse variable-heavy lines (UUIDs, timestamps,
IPs, numbers, hex) into a stable template, then fingerprint per-project.

This is a lightweight Drain-style masking pass rather than the full Drain
tree algorithm — sufficient at the volume a handful of local projects
produce, and it has zero external dependencies.
"""
from __future__ import annotations

import re

from systemlens.core.models import LogRecord, Signal, Severity, make_fingerprint

_MASKS = [
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"), "<ts>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<hex>"),
    (re.compile(r"\b[0-9a-fA-F]{12,64}\b"), "<hash>"),
    (re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?![\w.])"), "<num>"),
    (re.compile(r"'[^']{1,200}'"), "'<str>'"),
    (re.compile(r'"[^"]{1,200}"'), '"<str>"'),
    (re.compile(r"\s+"), " "),
]

# category detection — cheap keyword rules feed R1/R2/R3 in the correlator
_CATEGORY_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"connection refused|econnrefused", re.I), "connection_refused"),
    (re.compile(r"\btimed? ?out\b|timeout", re.I), "timeout"),
    (re.compile(r"\boom\b|out of memory|killed process|memory limit", re.I), "oom"),
    (re.compile(r"could not translate host|name or service not known|dns", re.I), "dns_failure"),
    (re.compile(r"traceback \(most recent call last\)|exception in thread|panic:|unhandled", re.I), "traceback"),
    (re.compile(r"permission denied|EACCES", re.I), "permission_denied"),
    (re.compile(r"no such file or directory|ENOENT", re.I), "missing_file"),
    (re.compile(r"unhealthy|health ?check failed", re.I), "health_check"),
]

# Real error strings put host/port together in several different shapes:
#   "db:5432"                                   (classic host:port)
#   'at "db" (10.0.0.2), port 5432'             (psycopg2 / libpq style)
#   "host=db port=5432"                          (libpq keyword/value style)
_HOST_PORT_PATTERNS = [
    re.compile(r"\bhost=([\w.-]+)\b.*?\bport=(\d{2,5})\b", re.I | re.S),
    re.compile(r'(?:at|host) "([\w.-]+)"(?:\s*\([^)]*\))?,?\s*port\s+(\d{2,5})\b', re.I),
    # a hostname must start with a letter, or "10:43:01" in a timestamp reads as host 10, port 43
    re.compile(r"(?<![\w.-])([A-Za-z][\w.-]*)[:@](\d{2,5})\b"),
    re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b"),
]
# a failed lookup names the host but has no port: 'could not translate host name "db"'
_HOST_ONLY_PATTERN = re.compile(r'host ?name "([\w.-]+)"', re.I)


def make_template(text: str) -> str:
    first_line = text.split("\n", 1)[0]
    out = first_line
    for pattern, repl in _MASKS:
        out = pattern.sub(repl, out)
    return out.strip()[:400]


def categorize(text: str) -> str:
    for pattern, name in _CATEGORY_RULES:
        if pattern.search(text):
            return name
    return "generic"


def extract_hints(text: str) -> dict:
    hints: dict = {}
    for pattern in _HOST_PORT_PATTERNS:
        m = pattern.search(text)
        if m:
            hints["host"] = m.group(1)
            hints["port"] = int(m.group(2))
            break
    if "host" not in hints:
        m = _HOST_ONLY_PATTERN.search(text)
        if m:
            hints["host"] = m.group(1)
    return hints


def to_signal(record: LogRecord) -> Signal | None:
    """Filter: only WARNING+ becomes a signal worth tracking. Returns None
    for routine INFO/DEBUG noise.
    """
    if record.severity < Severity.WARNING:
        return None
    template = make_template(record.raw)
    fingerprint = make_fingerprint(record.project, template)
    category = record.category_hint or categorize(record.raw)
    hints = extract_hints(record.raw)
    return Signal(record=record, template=template, fingerprint=fingerprint,
                  category=category, hints=hints)
