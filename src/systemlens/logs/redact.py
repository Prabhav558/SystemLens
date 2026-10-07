"""Secret redaction, applied once at ingestion so nothing downstream (SQLite,
the LLM prompt, the central server) ever holds the original value.

Targeted patterns only: credentials in URLs, key=value secrets, bearer
tokens, JWTs and well-known key prefixes. A generic "long random string"
rule would mangle hashes and IDs that diagnoses depend on.
"""
from __future__ import annotations

import re

_REDACTED = "[REDACTED]"

_SECRET_KEYS = (
    r"password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?"
)

_PATTERNS: list[tuple[re.Pattern, str]] = [
    # scheme://user:password@host
    (re.compile(r"([a-z][a-z0-9+.-]*://[^/\s:@]+):([^@\s/]+)@", re.I), rf"\1:{_REDACTED}@"),
    # Authorization: Bearer xxx / bare "Bearer xxx"
    (re.compile(r"\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}", re.I), rf"\1 {_REDACTED}"),
    # password=..., "api_key": "...", DB_PASSWORD: ...
    (re.compile(
        rf"((?:[\w-]*(?:{_SECRET_KEYS}))[\"']?\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)", re.I),
     rf"\1{_REDACTED}"),
    # JWTs
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[REDACTED_JWT]"),
    # well-known key prefixes
    (re.compile(
        r"\b(?:sk-[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9]{20,}|sla_[A-Za-z0-9_-]{20,}"
        r"|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})"),
     _REDACTED),
]


def redact(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
