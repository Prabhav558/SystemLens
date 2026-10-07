"""Best-effort discovery helpers for `agent add-project`.

These only propose defaults; the user (or caller) always has final say via
explicit CLI flags. Nothing here is load-bearing for correctness.
"""
from __future__ import annotations

from pathlib import Path

COMPOSE_NAMES = (
    "docker-compose.yml", "docker-compose.yaml",
    "compose.yml", "compose.yaml",
)

COMMON_LOG_DIRS = ("logs", "log", "var/log")


def find_compose_file(root: Path) -> Path | None:
    for name in COMPOSE_NAMES:
        candidate = root / name
        if candidate.exists():
            return candidate
    return None


def guess_log_globs(root: Path) -> list[str]:
    globs: list[str] = []
    for d in COMMON_LOG_DIRS:
        p = root / d
        if p.is_dir():
            globs.append(f"{p}/**/*.log")
    if not globs:
        globs.append(f"{root}/**/*.log")
    return globs


def guess_project_name(root: Path) -> str:
    return root.resolve().name
