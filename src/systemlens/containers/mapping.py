"""Container -> project resolution. Deliberately the most careful module in
the containers package: a wrong mapping here corrupts every downstream
correlation, silently.

Resolution order, first match wins:
  1. explicit container_map override on the ProjectEntry
  2. compose project label match (com.docker.compose.project)
  3. compose working_dir label match against the project root
  4. name-prefix heuristic — last resort, tagged low confidence
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from systemlens.core.models import ContainerState
from systemlens.projects.registry import ProjectEntry


@dataclass(slots=True)
class MappingResult:
    project: str
    confidence: str  # "high" | "low"
    reason: str


def _compose_project_name(root: Path) -> str:
    # docker compose's own default project-name derivation: lowercased dir name,
    # with anything that isn't [a-z0-9_-] stripped.
    name = root.resolve().name.lower()
    return "".join(c for c in name if c.isalnum() or c in "_-")


def resolve(container: ContainerState, projects: list[ProjectEntry]) -> MappingResult | None:
    # 1. explicit override
    for project in projects:
        if container.name in project.container_map:
            return MappingResult(project.container_map[container.name], "high", "explicit_override")

    # 2. compose project label
    if container.compose_project:
        for project in projects:
            if container.compose_project == _compose_project_name(project.root):
                return MappingResult(project.name, "high", "compose_project_label")

    # 3. compose working_dir label
    working_dir = container.labels.get("com.docker.compose.project.working_dir")
    if working_dir:
        for project in projects:
            try:
                if Path(working_dir).resolve() == project.root.resolve():
                    return MappingResult(project.name, "high", "compose_working_dir_label")
            except OSError:
                continue

    # 4. name-prefix heuristic, last resort
    for project in projects:
        prefix = _compose_project_name(project.root)
        if container.name.startswith(prefix) or project.name.lower() in container.name.lower():
            return MappingResult(project.name, "low", "name_prefix_heuristic")

    return None


def build_dependency_graph(containers: list[ContainerState]) -> dict[str, list[str]]:
    """service/name -> list of services it depends_on, from compose labels."""
    graph: dict[str, list[str]] = {}
    for c in containers:
        key = c.compose_service or c.name
        graph[key] = c.depends_on
    return graph
