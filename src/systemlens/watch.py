"""`agent watch`: a live terminal view of what the daemon is seeing. Reads
the same SQLite files the daemon writes, so it works from any terminal and
needs no connection to the daemon process.
"""
from __future__ import annotations

import time

from rich.console import Group
from rich.table import Table
from rich.text import Text

from systemlens.config import AgentConfig
from systemlens.core.lock import running_pid
from systemlens.memory.store import ProjectStore
from systemlens.projects.registry import ProjectRegistry

_STYLE = {"root_cause_identified": "red", "probable_cause": "yellow", "insufficient_evidence": "dim"}


def _ago(ts: float) -> str:
    seconds = max(0, int(time.time() - ts))
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return f"{seconds // size}{unit} ago"
    return f"{seconds}s ago"


def render(config: AgentConfig, limit: int = 12) -> Group:
    registry = ProjectRegistry(config)
    pid = running_pid(config.home)
    header = Text.assemble(
        ("SystemLens  ", "bold"),
        (f"daemon running (pid {pid})" if pid else "daemon not running", "green" if pid else "red"),
        (f"   {time.strftime('%H:%M:%S')}", "dim"))

    projects = Table(title="Projects", expand=True)
    for column in ("project", "issues tracked", "seen last hour", "findings 24h", "fixes pending", "unsent"):
        projects.add_column(column)
    recent: list[tuple[float, str, dict]] = []
    hour_ago, day_ago = time.time() - 3600, time.time() - 86400
    for entry in registry.all():
        db_path = config.home / "projects" / entry.name / "state.db"
        if not db_path.exists():
            projects.add_row(entry.name, "0", "0", "0", "0", "0")
            continue
        store = ProjectStore(db_path)
        try:
            q = store._conn.execute
            tracked = q("SELECT COUNT(*) c FROM fingerprints").fetchone()["c"]
            active = q("SELECT COUNT(*) c FROM fingerprints WHERE last_seen >= ?", (hour_ago,)).fetchone()["c"]
            incidents = store.recent_incidents(since=day_ago, limit=limit)
            projects.add_row(entry.name, str(tracked), str(active), str(len(incidents)),
                             str(len(store.fixes("pending"))), str(store.outbox_size()))
            recent += [(r["created_at"], entry.name, dict(r)) for r in incidents]
        finally:
            store.close()

    findings = Table(title="Latest findings", expand=True)
    for column in ("when", "project", "fingerprint", "verdict", "component", "root cause"):
        findings.add_column(column, overflow="fold" if column == "root cause" else "ellipsis")
    for created, project, row in sorted(recent, key=lambda item: item[0], reverse=True)[:limit]:
        style = _STYLE.get(row["verdict"], "")
        findings.add_row(_ago(created), project, row["fingerprint"][:10],
                         Text(row["verdict"].replace("_", " "), style=style),
                         row["affected_component"] or "", (row["root_cause"] or "")[:160])
    if not recent:
        findings.add_row("", "", "", "", "", "no findings in the last 24h")
    return Group(header, projects, findings)
