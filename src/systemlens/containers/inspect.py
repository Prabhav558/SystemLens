"""Translate raw `docker inspect`-shaped dicts into ContainerState.

Kept separate from client.py so the parsing logic is unit-testable against
static fixtures without a real (or fake) Docker client in the loop.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from systemlens.core.models import ContainerState


def _parse_docker_ts(raw: Optional[str]) -> Optional[float]:
    if not raw or raw.startswith("0001-01-01"):
        return None
    raw = raw.rstrip("Z")
    if "." in raw:
        head, frac = raw.split(".", 1)
        frac = (frac + "000000")[:6]
        raw = f"{head}.{frac}"
        fmt = "%Y-%m-%dT%H:%M:%S.%f"
    else:
        fmt = "%Y-%m-%dT%H:%M:%S"
    try:
        return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def to_container_state(attrs: dict) -> ContainerState:
    state = attrs.get("State", {}) or {}
    config = attrs.get("Config", {}) or {}
    host_config = attrs.get("HostConfig", {}) or {}
    labels: dict = config.get("Labels") or {}
    health = (state.get("Health") or {}).get("Status")
    health_log_raw = (state.get("Health") or {}).get("Log") or []
    health_log = [
        f"{h.get('End', '')} exit={h.get('ExitCode')} {h.get('Output', '').strip()}"
        for h in health_log_raw[-5:]
    ]

    net = attrs.get("NetworkSettings", {}) or {}
    networks = list((net.get("Networks") or {}).keys())
    ip_addresses = [n.get("IPAddress") for n in (net.get("Networks") or {}).values() if n.get("IPAddress")]
    aliases: list[str] = []
    for n in (net.get("Networks") or {}).values():
        aliases.extend(n.get("Aliases") or [])

    depends_on_raw = labels.get("com.docker.compose.depends_on", "")
    depends_on = [d.split(":")[0] for d in depends_on_raw.split(",") if d]

    name = attrs.get("Name", "").lstrip("/")

    return ContainerState(
        id=attrs.get("Id", "")[:12],
        name=name,
        image=config.get("Image", ""),
        status=state.get("Status", "unknown"),
        running=bool(state.get("Running", False)),
        exit_code=state.get("ExitCode"),
        started_at=_parse_docker_ts(state.get("StartedAt")),
        finished_at=_parse_docker_ts(state.get("FinishedAt")),
        oom_killed=bool(state.get("OOMKilled", False)),
        restart_count=int(attrs.get("RestartCount", 0) or 0),
        health=health,
        health_log=health_log,
        labels=labels,
        ports=attrs.get("NetworkSettings", {}).get("Ports") or {},
        networks=networks,
        aliases=aliases,
        compose_project=labels.get("com.docker.compose.project"),
        compose_service=labels.get("com.docker.compose.service"),
        depends_on=depends_on,
        ip_addresses=ip_addresses,
        memory_limit=host_config.get("Memory") or None,
    )
