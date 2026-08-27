"""Whole-archive audit and atomic text-redaction workflows."""

from __future__ import annotations

import os
import tempfile
import zipfile
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from tracehush.archive import open_trace
from tracehush.model import (
    AuditReport,
    Finding,
    SanitizationError,
    SanitizationReport,
    TraceHushError,
)
from tracehush.redact import process_text


def _audit_open_archive(
    archive: zipfile.ZipFile,
    source: str,
    secrets: Sequence[str],
) -> AuditReport:
    findings: list[Finding] = []
    binary_members: list[str] = []
    text_members = 0
    total_members = 0

    for info in archive.infolist():
        if info.is_dir():
            continue
        total_members += 1
        data = archive.read(info)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            binary_members.append(info.filename)
            continue

        text_members += 1
        findings.extend(process_text(info.filename, text, secrets).findings)

    return AuditReport(
        source=source,
        total_members=total_members,
        text_members=text_members,
        binary_members=tuple(binary_members),
        findings=tuple(findings),
    )


def audit_trace(source: str | Path, secrets: Sequence[str] = ()) -> AuditReport:
    """Audit each UTF-8 member of a validated trace archive."""

    source_path = Path(source)
    with open_trace(source_path) as archive:
        return _audit_open_archive(archive, str(source_path), secrets)


def _copy_archive(
    source: Path,
    temporary_output: Path,
    secrets: Sequence[str],
) -> None:
    with open_trace(source) as input_archive, zipfile.ZipFile(
        temporary_output, "w"
    ) as output_archive:
        output_archive.comment = input_archive.comment
        for info in input_archive.infolist():
            data = input_archive.read(info)
            if not info.is_dir():
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    pass
                else:
                    data = process_text(info.filename, text, secrets).redacted.encode("utf-8")
            output_archive.writestr(info, data)


def sanitize_trace(
    source: str | Path,
    output: str | Path,
    secrets: Sequence[str] = (),
) -> SanitizationReport:
    """Create and verify a text-redacted copy, leaving the source untouched."""

    source_path = Path(source)
    output_path = Path(output)
    if source_path.resolve() == output_path.resolve():
        raise SanitizationError("input and output paths must differ")
    if not output_path.parent.is_dir():
        raise SanitizationError(f"output directory does not exist: {output_path.parent}")

    before = audit_trace(source_path, secrets)
    temporary_path: Path | None = None

    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            dir=output_path.parent,
        )
        os.close(descriptor)
        temporary_path = Path(temporary_name)

        _copy_archive(source_path, temporary_path, secrets)
        with zipfile.ZipFile(temporary_path, "r") as candidate:
            corrupt_member = candidate.testzip()
        if corrupt_member is not None:
            raise SanitizationError(f"sanitized archive failed integrity at: {corrupt_member}")

        after = audit_trace(temporary_path, secrets)
        if not after.clean:
            raise SanitizationError("sanitized archive still contains detected textual findings")

        os.replace(temporary_path, output_path)
        temporary_path = None
        return SanitizationReport(
            before=before,
            after=replace(after, source=str(output_path)),
            output=str(output_path),
        )
    except TraceHushError:
        raise
    except (OSError, zipfile.BadZipFile) as exc:
        raise SanitizationError(f"could not create sanitized archive: {output_path}") from exc
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
