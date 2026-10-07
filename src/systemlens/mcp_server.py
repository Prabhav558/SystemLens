"""MCP server (`agent mcp`): lets an MCP client such as Claude Code or an
IDE read SystemLens findings and record resolutions. It runs over stdio and
reads the same local SQLite files as the CLI; it does not need the daemon.

Requires the optional `mcp` package: pip install "systemlens[mcp]".
"""
from __future__ import annotations

import time
from typing import Optional

from systemlens.agents.digest import build_digest, render_digest
from systemlens.config import AgentConfig
from systemlens.core.bundle_io import load_recording
from systemlens.memory.store import ProjectStore
from systemlens.projects.registry import ProjectRegistry


def _stores(config: AgentConfig, project: Optional[str] = None) -> dict[str, ProjectStore]:
    out = {}
    for entry in ProjectRegistry(config).all():
        db_path = config.home / "projects" / entry.name / "state.db"
        if project in (None, entry.name) and db_path.exists():
            out[entry.name] = ProjectStore(db_path)
    return out


def _close(stores: dict[str, ProjectStore]) -> None:
    for store in stores.values():
        store.close()


def list_projects(config: AgentConfig) -> list[dict]:
    return [{"name": e.name, "root": str(e.root), "enabled": e.enabled,
             "sources": (["docker container logs"] if e.stream_containers else []) + e.log_globs}
            for e in ProjectRegistry(config).all()]


def list_findings(config: AgentConfig, project: Optional[str] = None,
                  since_hours: float = 24, limit: int = 20) -> list[dict]:
    stores = _stores(config, project)
    try:
        rows = []
        for name, store in stores.items():
            for r in store.recent_incidents(since=time.time() - since_hours * 3600, limit=limit):
                rows.append({
                    "project": name, "fingerprint": r["fingerprint"], "verdict": r["verdict"],
                    "affected_component": r["affected_component"], "root_cause": r["root_cause"],
                    "fix_suggestion": r["fix_suggestion"], "confidence": r["confidence"],
                    "created_at": r["created_at"],
                })
        return sorted(rows, key=lambda r: r["created_at"], reverse=True)[:limit]
    finally:
        _close(stores)


def get_finding(config: AgentConfig, fingerprint: str) -> dict:
    """Latest finding for a fingerprint (a unique prefix is enough), with the
    evidence it was based on when a recorded bundle is available.
    """
    stores = _stores(config)
    try:
        for name, store in stores.items():
            matches = store.find_fingerprint(fingerprint)
            if len(matches) != 1:
                continue
            row = store.latest_incident(matches[0])
            prior = store.get_prior(matches[0])
            out: dict = {"project": name, "fingerprint": matches[0],
                         "occurrences": prior.occurrences if prior else None,
                         "resolution": prior.resolution if prior else None,
                         "finding": dict(row) if row else None}
            if out["finding"]:
                out["finding"].pop("analysis_json", None)
            recording = config.home / "projects" / name / "bundles" / f"{matches[0]}.json"
            if recording.exists():
                bundle, _ = load_recording(recording)
                out["evidence"] = {
                    "signal": bundle.signal.record.raw[:1500],
                    "origin_container": bundle.signal.record.container,
                    "category": bundle.signal.category,
                    "candidates": [{"rule": c.rule_id, "component": c.component, "summary": c.summary,
                                    "linked_to_signal": c.scoped} for c in bundle.candidates],
                }
            return out
        return {"error": f"no unique fingerprint matching '{fingerprint}'"}
    finally:
        _close(stores)


def resolve(config: AgentConfig, fingerprint: str, note: str) -> dict:
    stores = _stores(config)
    try:
        for name, store in stores.items():
            matches = store.find_fingerprint(fingerprint)
            if len(matches) == 1 and store.resolve_fingerprint(matches[0], note):
                return {"resolved": matches[0], "project": name}
        return {"error": f"no unique fingerprint matching '{fingerprint}'"}
    finally:
        _close(stores)


def digest(config: AgentConfig, since_hours: float = 24) -> str:
    stores = _stores(config)
    try:
        return render_digest(build_digest(stores, time.time() - since_hours * 3600))
    finally:
        _close(stores)


def build_server(config: AgentConfig):
    try:                                   # mcp >= 2
        from mcp.server.mcpserver import MCPServer as Server
    except ImportError:                    # mcp 1.x
        from mcp.server.fastmcp import FastMCP as Server

    server = Server("systemlens")

    @server.tool(name="list_projects")
    def _list_projects() -> list[dict]:
        """Projects SystemLens is watching and what each one reads."""
        return list_projects(config)

    @server.tool(name="list_findings")
    def _list_findings(project: Optional[str] = None, since_hours: float = 24, limit: int = 20) -> list[dict]:
        """Recent root-cause findings, newest first. Filter by project name if given."""
        return list_findings(config, project, since_hours, limit)

    @server.tool(name="get_finding")
    def _get_finding(fingerprint: str) -> dict:
        """One finding in full, with the triggering log signal and the correlation candidates."""
        return get_finding(config, fingerprint)

    @server.tool(name="resolve")
    def _resolve(fingerprint: str, note: str) -> dict:
        """Record what fixed an issue. The same issue is then answered from memory if it recurs."""
        return resolve(config, fingerprint, note)

    @server.tool(name="digest")
    def _digest(since_hours: float = 24) -> str:
        """Summary of new, recurring and resolved issues over a time window."""
        return digest(config, since_hours)

    return server
