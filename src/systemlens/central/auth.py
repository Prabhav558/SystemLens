"""Agent API keys. Server-generated, high-entropy, random secrets — not
user-chosen passwords — so a fast salted hash (sha256) is the right tool
here, not bcrypt/argon2 (those defend against guessing weak human-chosen
passwords, a threat model that doesn't apply to a 256-bit random token).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

_PREFIX = "sla_"  # SystemLens Agent key — lets a leaked key be recognized at a glance


def generate_api_key() -> str:
    return _PREFIX + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def verify_key(key: str, key_hash: str) -> bool:
    return hmac.compare_digest(hash_key(key), key_hash)
