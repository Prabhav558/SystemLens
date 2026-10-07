"""Rotation-safe tailer: truncation, rotation (inode change), partial trailing
lines, and UTF-8 sequences split across reads.
"""
from pathlib import Path

from systemlens.logs.tailer import FileTailer


def test_from_end_ignores_pre_existing_content(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("old line 1\nold line 2\n")
    t = FileTailer(p, from_end=True)
    assert t.poll() == []  # first poll just primes the offset

    with open(p, "a") as f:
        f.write("new line\n")
    assert t.poll() == ["new line"]


def test_partial_line_buffered_until_newline(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("")
    t = FileTailer(p, from_end=True)
    t.poll()

    with open(p, "a") as f:
        f.write("partial-no-newline-yet")
    assert t.poll() == []  # nothing complete yet

    with open(p, "a") as f:
        f.write(" more text\n")
    assert t.poll() == ["partial-no-newline-yet more text"]


def test_truncation_reopens_from_zero(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("line1\nline2\n")
    t = FileTailer(p, from_end=False)
    assert t.poll() == ["line1", "line2"]

    # simulate truncate (e.g. `> file.log`)
    p.write_text("fresh\n")
    assert t.poll() == ["fresh"]


def test_rotation_by_new_inode_reopens_from_zero(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("line1\n")
    t = FileTailer(p, from_end=False)
    assert t.poll() == ["line1"]

    rotated = tmp_path / "a.log.1"
    p.rename(rotated)
    p.write_text("post-rotation line\n")
    assert t.poll() == ["post-rotation line"]


def test_utf8_split_across_reads(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"")
    t = FileTailer(p, from_end=False)
    t.poll()

    snowman = "☃".encode("utf-8")  # 3-byte sequence
    with open(p, "ab") as f:
        f.write(b"before-" + snowman[:1])   # write a truncated multibyte char
    assert t.poll() == []  # nothing terminated by \n yet, so nothing to decode prematurely

    with open(p, "ab") as f:
        f.write(snowman[1:] + b"-after\n")
    lines = t.poll()
    assert lines == ["before-☃-after"]


def test_offsets_roundtrip(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("l1\nl2\n")
    t = FileTailer(p, from_end=False)
    t.poll()
    saved = t.to_offsets()

    with open(p, "a") as f:
        f.write("l3\n")

    t2 = FileTailer.from_offsets(p, saved)
    assert t2.poll() == ["l3"]


def test_missing_file_returns_empty(tmp_path):
    t = FileTailer(tmp_path / "does-not-exist.log", from_end=False)
    assert t.poll() == []
