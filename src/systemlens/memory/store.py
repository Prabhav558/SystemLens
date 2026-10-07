"""SQLite is the source of truth for long-term memory: fingerprints,
occurrences, incidents and resolutions. One database file per project
(isolation boundary), at <home>/projects/<name>/state.db.

FAISS (memory/vector.py) is a derived, optional index built from the
`fingerprints` table below — never the other way around.
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Optional

from systemlens.core.models import Analysis, PriorIncident

SCHEMA = """
CREATE TABLE IF NOT EXISTS fingerprints (
    fingerprint   TEXT PRIMARY KEY,
    template      TEXT NOT NULL,
    category      TEXT NOT NULL,
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    occurrences   INTEGER NOT NULL DEFAULT 0,
    last_analyzed REAL,
    resolution    TEXT,
    resolved_at   REAL
);

CREATE TABLE IF NOT EXISTS incidents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint   TEXT NOT NULL,
    created_at    REAL NOT NULL,
    verdict       TEXT NOT NULL,
    root_cause    TEXT NOT NULL,
    affected_component TEXT,
    fix_suggestion TEXT,
    confidence    REAL,
    provider      TEXT,
    model         TEXT,
    analysis_json TEXT NOT NULL,
    FOREIGN KEY (fingerprint) REFERENCES fingerprints (fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_incidents_fp ON incidents (fingerprint);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents (created_at);

CREATE TABLE IF NOT EXISTS offsets (
    path   TEXT PRIMARY KEY,
    data   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attempts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint   TEXT NOT NULL,
    at            REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attempts_at ON attempts (at);

-- a fix someone applied, waiting to be confirmed by the issue not recurring
CREATE TABLE IF NOT EXISTS fixes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint   TEXT NOT NULL,
    fix_text      TEXT NOT NULL,
    command       TEXT,
    status        TEXT NOT NULL,          -- pending | verified | failed
    applied_at    REAL NOT NULL,
    checked_at    REAL,
    detail        TEXT
);

-- findings that could not be pushed to the central server yet
CREATE TABLE IF NOT EXISTS outbox (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    payload       TEXT NOT NULL,
    created_at    REAL NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 0
);
"""


class ProjectStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        columns = {r["name"] for r in self._conn.execute("PRAGMA table_info(fingerprints)")}
        if "muted" not in columns:      # databases created before muting existed
            self._conn.execute("ALTER TABLE fingerprints ADD COLUMN muted INTEGER NOT NULL DEFAULT 0")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- fingerprints --------------------------------------------------
    def touch_fingerprint(self, fingerprint: str, template: str, category: str) -> int:
        """Record one more occurrence. Returns occurrence count after this call."""
        now = time.time()
        with self._conn:
            cur = self._conn.execute(
                "SELECT occurrences FROM fingerprints WHERE fingerprint = ?", (fingerprint,)
            )
            row = cur.fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO fingerprints (fingerprint, template, category, first_seen, "
                    "last_seen, occurrences) VALUES (?, ?, ?, ?, ?, 1)",
                    (fingerprint, template, category, now, now),
                )
                return 1
            occurrences = row["occurrences"] + 1
            self._conn.execute(
                "UPDATE fingerprints SET occurrences = ?, last_seen = ? WHERE fingerprint = ?",
                (occurrences, now, fingerprint),
            )
            return occurrences

    def set_muted(self, fingerprint: str, muted: bool) -> bool:
        with self._conn:
            return self._conn.execute("UPDATE fingerprints SET muted = ? WHERE fingerprint = ?",
                                      (1 if muted else 0, fingerprint)).rowcount > 0

    def muted_fingerprints(self) -> set[str]:
        return {r["fingerprint"] for r in
                self._conn.execute("SELECT fingerprint FROM fingerprints WHERE muted = 1")}

    def add_occurrences(self, fingerprint: str, count: int, last_seen: float) -> None:
        """Apply a batch of sightings counted in memory (see ProjectPipeline)."""
        with self._conn:
            self._conn.execute(
                "UPDATE fingerprints SET occurrences = occurrences + ?, last_seen = MAX(last_seen, ?) "
                "WHERE fingerprint = ?", (count, last_seen, fingerprint))

    def mark_analyzed(self, fingerprint: str) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE fingerprints SET last_analyzed = ? WHERE fingerprint = ?",
                (time.time(), fingerprint),
            )

    def get_prior(self, fingerprint: str) -> Optional[PriorIncident]:
        row = self._conn.execute(
            "SELECT * FROM fingerprints WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if row is None:
            return None
        return PriorIncident(
            fingerprint=row["fingerprint"], first_seen=row["first_seen"],
            last_seen=row["last_seen"], occurrences=row["occurrences"],
            resolution=row["resolution"], resolved_at=row["resolved_at"],
        )

    def resolve_fingerprint(self, fingerprint: str, note: str) -> bool:
        with self._conn:
            cur = self._conn.execute(
                "UPDATE fingerprints SET resolution = ?, resolved_at = ? WHERE fingerprint = ?",
                (note, time.time(), fingerprint),
            )
            return cur.rowcount > 0

    def should_analyze(self, fingerprint: str, cooldown_seconds: int) -> bool:
        row = self._conn.execute(
            "SELECT last_analyzed FROM fingerprints WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if row is None or row["last_analyzed"] is None:
            return True
        return (time.time() - row["last_analyzed"]) >= cooldown_seconds

    def analyses_last_hour(self) -> int:
        """LLM analyses in the last hour. Findings answered from resolution
        memory (provider 'memory') cost nothing and don't count.
        """
        cutoff = time.time() - 3600
        return self._conn.execute(
            "SELECT COUNT(*) c FROM incidents WHERE created_at >= ? "
            "AND COALESCE(provider, '') != 'memory'", (cutoff,)
        ).fetchone()["c"]

    def last_diagnosis(self, fingerprint: str) -> Optional[sqlite3.Row]:
        """Most recent LLM-produced incident for a fingerprint, if any."""
        return self._conn.execute(
            "SELECT * FROM incidents WHERE fingerprint = ? AND COALESCE(provider, '') != 'memory' "
            "ORDER BY created_at DESC LIMIT 1", (fingerprint,)
        ).fetchone()

    def prune(self, retention_days: int) -> dict[str, int]:
        """Delete history older than the retention window. Fingerprints that
        carry a resolution are kept indefinitely — that is the long-term
        memory the tool exists to build.
        """
        cutoff = time.time() - retention_days * 86400
        with self._conn:
            incidents = self._conn.execute(
                "DELETE FROM incidents WHERE created_at < ?", (cutoff,)).rowcount
            attempts = self._conn.execute(
                "DELETE FROM attempts WHERE at < ?", (cutoff,)).rowcount
            self._conn.execute("DELETE FROM outbox WHERE created_at < ?", (cutoff,))
            self._conn.execute("DELETE FROM fixes WHERE applied_at < ? AND status != 'pending'", (cutoff,))
            fingerprints = self._conn.execute(
                "DELETE FROM fingerprints WHERE last_seen < ? AND resolution IS NULL "
                "AND fingerprint NOT IN (SELECT fingerprint FROM incidents)", (cutoff,)).rowcount
        return {"incidents": incidents, "attempts": attempts, "fingerprints": fingerprints}

    def record_attempt(self, fingerprint: str) -> None:
        """A failed LLM call still consumes rate-limit budget — otherwise a
        broken provider (bad key, outage) retries unthrottled at full log
        volume, exactly what the hourly cap and cooldown exist to prevent.
        """
        with self._conn:
            self._conn.execute(
                "INSERT INTO attempts (fingerprint, at) VALUES (?, ?)",
                (fingerprint, time.time()),
            )

    def attempts_last_hour(self) -> int:
        cutoff = time.time() - 3600
        return self._conn.execute(
            "SELECT COUNT(*) c FROM attempts WHERE at >= ?", (cutoff,)
        ).fetchone()["c"]

    # -- incidents -------------------------------------------------------
    def record_incident(self, fingerprint: str, analysis: Analysis, provider: str, model: str) -> int:
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO incidents (fingerprint, created_at, verdict, root_cause, "
                "affected_component, fix_suggestion, confidence, provider, model, analysis_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (fingerprint, time.time(), analysis.verdict, analysis.root_cause,
                 analysis.affected_component, analysis.fix_suggestion, analysis.confidence,
                 provider, model, analysis.model_dump_json()),
            )
            return cur.lastrowid

    def recent_incidents(self, since: Optional[float] = None, limit: int = 100) -> list[sqlite3.Row]:
        if since is not None:
            return self._conn.execute(
                "SELECT * FROM incidents WHERE created_at >= ? ORDER BY created_at DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        return self._conn.execute(
            "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()

    def similar_resolved(self, exclude_fingerprint: str, category: Optional[str], limit: int) -> list[PriorIncident]:
        """Cheap fallback used when FAISS is disabled: same category, has a resolution."""
        query = (
            "SELECT * FROM fingerprints WHERE resolution IS NOT NULL "
            "AND fingerprint != ? "
        )
        params: list = [exclude_fingerprint]
        if category:
            query += "AND category = ? "
            params.append(category)
        query += "ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [
            PriorIncident(fingerprint=r["fingerprint"], first_seen=r["first_seen"],
                           last_seen=r["last_seen"], occurrences=r["occurrences"],
                           resolution=r["resolution"], resolved_at=r["resolved_at"])
            for r in rows
        ]

    def all_resolved_templates(self) -> list[tuple[str, str]]:
        """(fingerprint, template) pairs with a resolution — FAISS index input."""
        rows = self._conn.execute(
            "SELECT fingerprint, template FROM fingerprints WHERE resolution IS NOT NULL"
        ).fetchall()
        return [(r["fingerprint"], r["template"]) for r in rows]

    # -- offsets (tailer state, for restart resume) -----------------------
    def save_offsets(self, path: str, data: dict) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO offsets (path, data) VALUES (?, ?) "
                "ON CONFLICT(path) DO UPDATE SET data = excluded.data",
                (path, json.dumps(data)),
            )

    def load_all_offsets(self) -> dict[str, dict]:
        rows = self._conn.execute("SELECT path, data FROM offsets").fetchall()
        return {r["path"]: json.loads(r["data"]) for r in rows}

    # -- incidents: lookups ------------------------------------------------
    def latest_incident(self, fingerprint: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM incidents WHERE fingerprint = ? ORDER BY created_at DESC LIMIT 1",
            (fingerprint,)).fetchone()

    def find_fingerprint(self, prefix: str) -> list[str]:
        """Fingerprints starting with `prefix`, so a CLI user can type a short one."""
        rows = self._conn.execute(
            "SELECT fingerprint FROM fingerprints WHERE fingerprint LIKE ? ORDER BY last_seen DESC",
            (prefix + "%",)).fetchall()
        return [r["fingerprint"] for r in rows]

    def summary(self, since: float) -> dict:
        """Counts for the digest: what appeared, what recurred, what got resolved."""
        q = self._conn.execute
        return {
            "new": [dict(r) for r in q(
                "SELECT fingerprint, category, template, occurrences FROM fingerprints "
                "WHERE first_seen >= ? ORDER BY occurrences DESC", (since,)).fetchall()],
            "recurring": [dict(r) for r in q(
                "SELECT fingerprint, category, template, occurrences FROM fingerprints "
                "WHERE first_seen < ? AND last_seen >= ? ORDER BY occurrences DESC LIMIT 10",
                (since, since)).fetchall()],
            "resolved": [dict(r) for r in q(
                "SELECT fingerprint, category, resolution FROM fingerprints WHERE resolved_at >= ?",
                (since,)).fetchall()],
            "verdicts": {r["verdict"]: r["c"] for r in q(
                "SELECT verdict, COUNT(*) c FROM incidents WHERE created_at >= ? GROUP BY verdict",
                (since,)).fetchall()},
            "failed_analyses": q("SELECT COUNT(*) c FROM attempts WHERE at >= ?", (since,)).fetchone()["c"],
            "fixes": {r["status"]: r["c"] for r in q(
                "SELECT status, COUNT(*) c FROM fixes WHERE applied_at >= ? GROUP BY status",
                (since,)).fetchall()},
        }

    # -- fixes (remediation + verification) -----------------------------------
    def add_fix(self, fingerprint: str, fix_text: str, command: Optional[str] = None) -> int:
        with self._conn:
            # one open verification per fingerprint: a newer fix supersedes it
            self._conn.execute(
                "UPDATE fixes SET status = 'failed', checked_at = ?, detail = 'superseded by a newer fix' "
                "WHERE fingerprint = ? AND status = 'pending'", (time.time(), fingerprint))
            return self._conn.execute(
                "INSERT INTO fixes (fingerprint, fix_text, command, status, applied_at) "
                "VALUES (?, ?, ?, 'pending', ?)", (fingerprint, fix_text, command, time.time())).lastrowid

    def fixes(self, status: Optional[str] = None) -> list[sqlite3.Row]:
        if status:
            return self._conn.execute(
                "SELECT * FROM fixes WHERE status = ? ORDER BY applied_at DESC", (status,)).fetchall()
        return self._conn.execute("SELECT * FROM fixes ORDER BY applied_at DESC").fetchall()

    def set_fix_status(self, fix_id: int, status: str, detail: str) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE fixes SET status = ?, checked_at = ?, detail = ? WHERE id = ?",
                (status, time.time(), detail, fix_id))

    # -- outbox (central server pushes that have not succeeded yet) -----------
    def outbox_add(self, payload: dict) -> None:
        with self._conn:
            self._conn.execute("INSERT INTO outbox (payload, created_at) VALUES (?, ?)",
                               (json.dumps(payload), time.time()))

    def outbox_batch(self, limit: int = 20) -> list[sqlite3.Row]:
        return self._conn.execute("SELECT * FROM outbox ORDER BY id LIMIT ?", (limit,)).fetchall()

    def outbox_done(self, row_id: int) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM outbox WHERE id = ?", (row_id,))

    def outbox_failed(self, row_id: int) -> None:
        with self._conn:
            self._conn.execute("UPDATE outbox SET attempts = attempts + 1 WHERE id = ?", (row_id,))

    def outbox_size(self) -> int:
        return self._conn.execute("SELECT COUNT(*) c FROM outbox").fetchone()["c"]
