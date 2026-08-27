"""Bounded, non-extracting access to Playwright trace ZIP files."""

from __future__ import annotations

import zipfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path, PurePosixPath, PureWindowsPath

from tracehush.model import ArchiveError

MAX_MEMBERS = 10_000
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024


def _unsafe_member_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    return (
        PurePosixPath(normalized).is_absolute()
        or PureWindowsPath(name).is_absolute()
        or ".." in PurePosixPath(normalized).parts
    )


def _validate_members(infos: Sequence[zipfile.ZipInfo]) -> None:
    if len(infos) > MAX_MEMBERS:
        raise ArchiveError(f"archive contains more than {MAX_MEMBERS} members")

    names: set[str] = set()
    total_size = 0
    has_trace_data = False

    for info in infos:
        if info.flag_bits & 0x1:
            raise ArchiveError(f"encrypted member is not supported: {info.filename}")
        if _unsafe_member_name(info.filename):
            raise ArchiveError(f"unsafe member name: {info.filename}")
        if info.filename in names:
            raise ArchiveError(f"duplicate member name: {info.filename}")
        names.add(info.filename)

        if info.file_size > MAX_ENTRY_BYTES:
            raise ArchiveError(
                f"member {info.filename} exceeds {MAX_ENTRY_BYTES} bytes uncompressed"
            )
        total_size += info.file_size
        if total_size > MAX_TOTAL_BYTES:
            raise ArchiveError("archive total uncompressed size exceeds the supported limit")

        if not info.is_dir() and info.filename.endswith((".trace", ".network")):
            has_trace_data = True

    if not has_trace_data:
        raise ArchiveError("archive has no Playwright .trace or .network member")


@contextmanager
def open_trace(path: str | Path) -> Iterator[zipfile.ZipFile]:
    """Open a validated trace archive without extracting any member."""

    source = Path(path)
    try:
        if not source.is_file() or not zipfile.is_zipfile(source):
            raise ArchiveError(f"{source} is not a valid ZIP file")
        with zipfile.ZipFile(source, "r") as archive:
            _validate_members(archive.infolist())
            yield archive
    except ArchiveError:
        raise
    except (OSError, zipfile.BadZipFile) as exc:
        raise ArchiveError(f"{source} is not a valid ZIP file") from exc
