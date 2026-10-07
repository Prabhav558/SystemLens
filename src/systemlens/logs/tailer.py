"""Rotation-safe incremental file reader (tail -f semantics).

Handles: truncation (size shrinks -> reopen from 0), rotation (inode
changes -> reopen), partial trailing lines (buffer until a newline arrives),
and UTF-8 sequences split across two reads.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class TailerState:
    inode: Optional[int] = None
    offset: int = 0
    buffer: bytes = b""


class FileTailer:
    """Stateful, synchronous. One instance per watched file. Call `poll()`
    after a filesystem event to get newly-completed lines.
    """

    def __init__(self, path: Path, state: Optional[TailerState] = None, from_end: bool = True):
        self.path = path
        self.state = state or TailerState()
        self._from_end = from_end
        self._initialized = state is not None

    def _stat(self) -> Optional[os.stat_result]:
        try:
            return os.stat(self.path)
        except FileNotFoundError:
            return None

    def poll(self) -> list[str]:
        st = self._stat()
        if st is None:
            return []  # file missing (mid-rotation); caller retries next event

        if not self._initialized:
            self.state.inode = st.st_ino
            self.state.offset = st.st_size if self._from_end else 0
            self._initialized = True
            if self._from_end:
                # Priming: intentionally skip pre-existing content and start
                # tailing from here, like `tail -f`.
                return []
            # from_end=False means "read the whole file now" — fall through
            # to the normal read path below instead of discarding it.
        else:
            rotated = st.st_ino != self.state.inode
            truncated = (not rotated) and st.st_size < self.state.offset
            if rotated or truncated:
                self.state.inode = st.st_ino
                self.state.offset = 0
                self.state.buffer = b""

        if st.st_size <= self.state.offset:
            return []

        lines: list[str] = []
        with open(self.path, "rb") as f:
            f.seek(self.state.offset)
            chunk = f.read(st.st_size - self.state.offset)
            self.state.offset = f.tell()

        data = self.state.buffer + chunk
        *complete, tail = data.split(b"\n")
        self.state.buffer = tail  # may be partial line, or partial UTF-8 sequence
        for raw in complete:
            lines.append(raw.decode("utf-8", errors="replace").rstrip("\r"))
        return lines

    def to_offsets(self) -> dict:
        return {"inode": self.state.inode, "offset": self.state.offset}

    @classmethod
    def from_offsets(cls, path: Path, data: dict) -> "FileTailer":
        state = TailerState(inode=data.get("inode"), offset=data.get("offset", 0))
        return cls(path, state=state)
