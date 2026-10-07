"""Single-daemon lock. Two daemons on one home directory would analyse every
signal twice and fight over the same SQLite files, so `agent start` / `agent
up` refuse to run alongside a live one.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


class AlreadyRunning(RuntimeError):
    def __init__(self, pid: int):
        super().__init__(f"a SystemLens daemon is already running (pid {pid})")
        self.pid = pid


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def running_pid(home: Path) -> Optional[int]:
    """Pid of the live daemon for this home directory, or None."""
    try:
        pid = int((home / "agent.pid").read_text().strip())
    except (OSError, ValueError):
        return None
    return pid if pid != os.getpid() and _alive(pid) else None


class DaemonLock:
    def __init__(self, home: Path):
        self._path = home / "agent.pid"
        self._home = home

    def __enter__(self) -> "DaemonLock":
        pid = running_pid(self._home)
        if pid is not None:
            raise AlreadyRunning(pid)
        self._home.mkdir(parents=True, exist_ok=True)
        self._path.write_text(str(os.getpid()))
        return self

    def __exit__(self, *exc) -> None:
        try:
            if self._path.read_text().strip() == str(os.getpid()):
                self._path.unlink()
        except OSError:
            pass
