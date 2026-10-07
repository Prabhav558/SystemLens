"""Docker access with graceful degradation.

If the Docker daemon or socket is unavailable (no `docker` binary, no
/var/run/docker.sock — the exact situation on a fresh WSL distro), the rest
of the pipeline must keep running on logs alone. Every call here is safe to
invoke when Docker is down; it just returns empty/DockerUnavailable rather
than raising into the pipeline.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional, Protocol

logger = logging.getLogger("systemlens.docker")


class DockerUnavailable(RuntimeError):
    pass


class ContainerClientProtocol(Protocol):
    """What the rest of the app needs from a docker client. `FakeDockerClient`
    in tests implements the same surface with zero real Docker involved.
    """
    def list_containers(self) -> list[dict]: ...
    def inspect(self, container_id: str) -> dict: ...
    def logs(self, container_id: str, tail: int = 50) -> list[str]: ...


class DockerClient:
    """Thin synchronous wrapper over docker-py. All methods are blocking —
    callers must invoke via asyncio.to_thread.
    """

    def __init__(self, base_url: Optional[str] = None):
        self._base_url = base_url
        self._client = None
        self._available: Optional[bool] = None

    def _connect(self):
        if self._client is not None:
            return self._client
        try:
            import docker  # local import: optional dependency, absent is fine
        except ImportError:
            self._available = False
            raise DockerUnavailable("the 'docker' package is not installed")
        try:
            self._client = (
                docker.DockerClient(base_url=self._base_url) if self._base_url
                else docker.from_env()
            )
            self._client.ping()
            self._available = True
        except Exception as e:  # noqa: BLE001 - any failure here means "unavailable"
            self._available = False
            self._client = None
            raise DockerUnavailable(f"docker daemon unreachable: {e}") from e
        return self._client

    def new_raw_client(self):
        """A fresh docker-py client for a long-lived streaming call (log
        follow, events). Each stream gets its own connection so it never
        competes with the short request/response calls above.
        """
        try:
            import docker
        except ImportError:
            raise DockerUnavailable("the 'docker' package is not installed")
        try:
            return docker.DockerClient(base_url=self._base_url) if self._base_url else docker.from_env()
        except Exception as e:  # noqa: BLE001
            raise DockerUnavailable(f"docker daemon unreachable: {e}") from e

    def is_available(self) -> bool:
        """Re-verifies on every call rather than trusting a cached bool, so
        the daemon notices both directions of a Docker state change: coming
        back up after being down, and going down after being up.
        """
        if self._client is not None:
            try:
                self._client.ping()
                self._available = True
                return True
            except Exception:  # noqa: BLE001 - stale/dead connection
                self._client = None
        try:
            self._connect()
        except DockerUnavailable:
            pass
        return bool(self._available)

    def list_containers(self) -> list[dict]:
        client = self._connect()
        return [c.attrs for c in client.containers.list(all=True)]

    def inspect(self, container_id: str) -> dict:
        client = self._connect()
        return client.containers.get(container_id).attrs

    def logs(self, container_id: str, tail: int = 50) -> list[str]:
        client = self._connect()
        raw = client.containers.get(container_id).logs(tail=tail, timestamps=True)
        text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
        return [l for l in text.splitlines() if l]


class AsyncDockerClient:
    """Async facade. Every call runs the blocking client in a thread so the
    event loop never stalls on Docker I/O.
    """

    def __init__(self, base_url: Optional[str] = None):
        self._inner = DockerClient(base_url=base_url)

    @property
    def sync(self) -> DockerClient:
        """The blocking client, for code that runs in its own thread."""
        return self._inner

    async def is_available(self) -> bool:
        return await asyncio.to_thread(self._inner.is_available)

    async def list_containers(self) -> list[dict]:
        try:
            return await asyncio.to_thread(self._inner.list_containers)
        except DockerUnavailable:
            return []

    async def inspect(self, container_id: str) -> Optional[dict]:
        try:
            return await asyncio.to_thread(self._inner.inspect, container_id)
        except DockerUnavailable:
            return None

    async def logs(self, container_id: str, tail: int = 50) -> list[str]:
        try:
            return await asyncio.to_thread(self._inner.logs, container_id, tail)
        except DockerUnavailable:
            return []
