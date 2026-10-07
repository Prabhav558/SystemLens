"""Per-project registry: ~/.systemlens/projects.json.

This is the isolation boundary. Each entry owns its own log globs, its own
container map overrides, and its own state directory under
~/.systemlens/projects/<name>/. No module outside this file mutates the
registry file directly.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from systemlens.config import AgentConfig
from systemlens.logs.watcher import matches_log_glob
from systemlens.projects.discovery import find_compose_file, guess_log_globs, guess_project_name


class ProjectEntry(BaseModel):
    name: str
    root: Path
    log_globs: list[str] = Field(default_factory=list)
    compose_file: Optional[Path] = None
    container_map: dict[str, str] = Field(default_factory=dict)  # container name -> service alias
    # Read each mapped container's stdout/stderr straight from Docker. Off for
    # entries created before this existed, so a project that already tees
    # `docker compose logs` into a watched file doesn't see every line twice.
    stream_containers: bool = False
    enabled: bool = True

    def matches_log(self, path: Path) -> bool:
        return matches_log_glob(path, self.log_globs)


def build_project_entry(root: Path, name: Optional[str] = None, logs: Optional[str] = None,
                        docker_logs: Optional[bool] = None) -> ProjectEntry:
    """Decide a project's log sources. With a compose file and no explicit
    log glob, container output is read straight from Docker; log files are
    only watched when asked for (or when there is nothing else to watch).
    """
    compose = find_compose_file(root)
    if docker_logs is None:
        docker_logs = compose is not None and logs is None
    if logs:
        globs = [logs]
    elif docker_logs:
        globs = []
    else:
        globs = guess_log_globs(root)
    return ProjectEntry(name=name or guess_project_name(root), root=root, log_globs=globs,
                        compose_file=compose, stream_containers=docker_logs)


class ProjectRegistry:
    def __init__(self, config: AgentConfig):
        self._config = config
        self._path = config.projects_path
        self._entries: dict[str, ProjectEntry] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        raw = json.loads(self._path.read_text() or "{}")
        for name, data in raw.items():
            self._entries[name] = ProjectEntry.model_validate(data)

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {n: json.loads(e.model_dump_json()) for n, e in self._entries.items()}
        self._path.write_text(json.dumps(payload, indent=2, default=str))

    def add(self, entry: ProjectEntry) -> None:
        if entry.name in self._entries:
            raise ValueError(f"project '{entry.name}' already registered")
        self._entries[entry.name] = entry
        self._config.project_dir(entry.name)  # ensure isolated state dir exists
        self._save()

    def remove(self, name: str) -> None:
        self._entries.pop(name, None)
        self._save()

    def get(self, name: str) -> Optional[ProjectEntry]:
        return self._entries.get(name)

    def all(self) -> list[ProjectEntry]:
        return list(self._entries.values())

    def enabled(self) -> list[ProjectEntry]:
        return [e for e in self._entries.values() if e.enabled]
