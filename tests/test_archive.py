from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

import tracehush.archive as archive_module
from tracehush.archive import _validate_members, open_trace
from tracehush.model import ArchiveError


def write_zip(path: Path, members: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            archive.writestr(name, data)


def test_open_trace_validates_and_reads_members(tmp_path: Path) -> None:
    source = tmp_path / "trace.zip"
    write_zip(source, [("0-trace.trace", b'{"type":"context-options"}\n')])

    with open_trace(source) as archive:
        assert [item.filename for item in archive.infolist()] == ["0-trace.trace"]
        assert archive.read("0-trace.trace").startswith(b"{")

    assert not (tmp_path / "0-trace.trace").exists()


@pytest.mark.parametrize(
    "name",
    ["../outside", "folder/../outside", "/absolute", "\\absolute", "C:/absolute"],
)
def test_rejects_unsafe_member_names(tmp_path: Path, name: str) -> None:
    source = tmp_path / "unsafe.zip"
    write_zip(source, [(name, b"data"), ("0-trace.trace", b"{}\n")])

    with pytest.raises(ArchiveError, match="unsafe member name"), open_trace(source):
        pass


def test_rejects_duplicate_member_names(tmp_path: Path) -> None:
    source = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("0-trace.trace", b"first")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("0-trace.trace", b"second")

    with pytest.raises(ArchiveError, match="duplicate member name"), open_trace(source):
        pass


def test_rejects_encrypted_member_metadata() -> None:
    info = zipfile.ZipInfo("0-trace.trace")
    info.flag_bits |= 0x1

    with pytest.raises(ArchiveError, match="encrypted"):
        _validate_members([info])


def test_rejects_too_many_members(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "many.zip"
    write_zip(source, [("0-trace.trace", b"{}"), ("1-trace.trace", b"{}")])
    monkeypatch.setattr(archive_module, "MAX_MEMBERS", 1)

    with pytest.raises(ArchiveError, match="more than 1 members"), open_trace(source):
        pass


def test_rejects_oversized_member_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    info = zipfile.ZipInfo("0-trace.trace")
    info.file_size = 11
    monkeypatch.setattr(archive_module, "MAX_ENTRY_BYTES", 10)

    with pytest.raises(ArchiveError, match="exceeds 10 bytes"):
        _validate_members([info])


def test_rejects_oversized_total_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    first = zipfile.ZipInfo("0-trace.trace")
    second = zipfile.ZipInfo("0-trace.network")
    first.file_size = 6
    second.file_size = 6
    monkeypatch.setattr(archive_module, "MAX_TOTAL_BYTES", 10)

    with pytest.raises(ArchiveError, match="total uncompressed size"):
        _validate_members([first, second])


@pytest.mark.parametrize("content", [b"not a zip", b""])
def test_rejects_non_zip_input(tmp_path: Path, content: bytes) -> None:
    source = tmp_path / "bad.zip"
    source.write_bytes(content)

    with pytest.raises(ArchiveError, match="valid ZIP"), open_trace(source):
        pass


def test_rejects_zip_without_playwright_trace_member(tmp_path: Path) -> None:
    source = tmp_path / "generic.zip"
    write_zip(source, [("notes.txt", b"hello")])

    with pytest.raises(ArchiveError, match=r"Playwright \\.trace or \\.network"), open_trace(source):
        pass
