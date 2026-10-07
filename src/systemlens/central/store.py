"""Central server datastore: registered agents and the findings they've
pushed. Separate from memory/store.py's per-project ProjectStore (that one
is local, per-project, keyed by fingerprint for correlation/cooldown state;
this one is server-side, keyed by agent, purely a received-findings log).
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Optional

from systemlens.central.auth import hash_key

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    key_hash      TEXT NOT NULL UNIQUE,
    created_at    REAL NOT NULL,
    last_seen_at  REAL
);

CREATE TABLE IF NOT EXISTS findings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id            INTEGER NOT NULL,
    project             TEXT NOT NULL,
    fingerprint         TEXT NOT NULL,
    verdict             TEXT NOT NULL,
    root_cause          TEXT NOT NULL,
    affected_component  TEXT,
    fix_suggestion      TEXT,
    confidence          REAL,
    provider            TEXT,
    model               TEXT,
    created_at          REAL NOT NULL,
    received_at         REAL NOT NULL,
    analysis_json       TEXT NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agents (id)
);

CREATE INDEX IF NOT EXISTS idx_findings_agent ON findings (agent_id, received_at);
"""


class CentralStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Bring a database created by an earlier version up to date."""
        columns = {r["name"] for r in self._conn.execute("PRAGMA table_info(agents)")}
        if "revoked_at" not in columns:
            self._conn.execute("ALTER TABLE agents ADD COLUMN revoked_at REAL")
        # a finding is identified by who sent it and when it was made, so a
        # retried or backfilled push is stored once
        self._conn.execute(
            "DELETE FROM findings WHERE id NOT IN (SELECT MIN(id) FROM findings "
            "GROUP BY agent_id, project, fingerprint, created_at)")
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_identity "
            "ON findings (agent_id, project, fingerprint, created_at)")

    def close(self) -> None:
        self._conn.close()

    # -- agents ----------------------------------------------------------
    def register_agent(self, name: str, api_key: str) -> int:
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO agents (name, key_hash, created_at) VALUES (?, ?, ?)",
                (name, hash_key(api_key), time.time()),
            )
            return cur.lastrowid

    def agent_by_key(self, api_key: str) -> Optional[sqlite3.Row]:
        """O(1) lookup by the hash of the presented key — every agent has a
        unique key, so this is a direct index lookup, not a scan-and-compare
        over all rows (which wouldn't scale and would also leak timing).
        """
        row = self._conn.execute(
            "SELECT * FROM agents WHERE key_hash = ? AND revoked_at IS NULL", (hash_key(api_key),)
        ).fetchone()
        if row is not None:
            with self._conn:
                self._conn.execute(
                    "UPDATE agents SET last_seen_at = ? WHERE id = ?", (time.time(), row["id"])
                )
        return row

    def list_agents(self) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT id, name, created_at, last_seen_at, revoked_at FROM agents").fetchall()

    def revoke_agent(self, agent_id: int) -> bool:
        """The key stops working at once. Its findings are kept."""
        with self._conn:
            return self._conn.execute(
                "UPDATE agents SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (time.time(), agent_id)).rowcount > 0

    # -- findings ----------------------------------------------------------
    def record_finding(self, agent_id: int, project: str, fingerprint: str, analysis: dict,
                        provider: Optional[str], model: Optional[str], created_at: float) -> Optional[int]:
        """Returns the new row id, or None if this exact finding was already stored."""
        with self._conn:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO findings (agent_id, project, fingerprint, verdict, root_cause, "
                "affected_component, fix_suggestion, confidence, provider, model, created_at, "
                "received_at, analysis_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (agent_id, project, fingerprint, analysis.get("verdict"), analysis.get("root_cause"),
                 analysis.get("affected_component"), analysis.get("fix_suggestion"),
                 analysis.get("confidence"), provider, model, created_at, time.time(),
                 json.dumps(analysis)),
            )
            return cur.lastrowid if cur.rowcount else None

    def prune(self, retention_days: int) -> int:
        cutoff = time.time() - retention_days * 86400
        with self._conn:
            return self._conn.execute(
                "DELETE FROM findings WHERE received_at < ?", (cutoff,)).rowcount

    def findings_for_agent(self, agent_id: int, project: Optional[str] = None,
                            since: Optional[float] = None, limit: int = 200) -> list[sqlite3.Row]:
        query = "SELECT * FROM findings WHERE agent_id = ?"
        params: list = [agent_id]
        if project:
            query += " AND project = ?"
            params.append(project)
        if since is not None:
            query += " AND received_at >= ?"
            params.append(since)
        query += " ORDER BY received_at DESC LIMIT ?"
        params.append(limit)
        return self._conn.execute(query, params).fetchall()
