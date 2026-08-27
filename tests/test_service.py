from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from tracehush.model import SanitizationError
from tracehush.service import audit_trace, sanitize_trace


def write_trace(
    path: Path,
    members: list[tuple[zipfile.ZipInfo | str, bytes]],
    *,
    comment: bytes = b"",
) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.comment = comment
        for name_or_info, data in members:
            archive.writestr(name_or_info, data)


def test_audit_scans_jsonl_and_utf8_resources_and_reports_binary(tmp_path: Path) -> None:
    source = tmp_path / "trace.zip"
    action_secret = "captured-form-private-123"
    resource_secret = "resource-password-123"
    write_trace(
        source,
        [
            (
                "0-trace.trace",
                (
                    json.dumps(
                        {
                            "type": "before",
                            "method": "fill",
                            "params": {"value": action_secret},
                        }
                    )
                    + "\n"
                ).encode(),
            ),
            ("resources/text-hash", f"password={resource_secret}\n".encode()),
            ("resources/image-hash", b"\x89PNG\r\n\x1a\n\x00\xff"),
        ],
    )

    report = audit_trace(source)

    assert report.total_members == 3
    assert report.text_members == 2
    assert report.binary_members == ("resources/image-hash",)
    assert {item.category for item in report.findings} == {"form-input", "sensitive-field"}
    assert action_secret not in repr(report)
    assert resource_secret not in repr(report)
    assert not report.clean
    assert report.has_binary_residuals


def test_sanitize_preserves_source_and_zip_metadata_then_reaudits_clean(
    tmp_path: Path,
) -> None:
    source = tmp_path / "trace.zip"
    output = tmp_path / "trace.redacted.zip"
    secret = "Bearer source-token-123456"
    info = zipfile.ZipInfo("0-trace.trace", date_time=(2024, 2, 3, 4, 5, 6))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    info.comment = b"trace entry"
    binary = b"\x89PNG\r\n\x1a\n\x00\xff"
    write_trace(
        source,
        [
            (info, (json.dumps({"authorization": secret}) + "\n").encode()),
            ("resources/image-hash", binary),
        ],
        comment=b"archive comment",
    )
    original = source.read_bytes()

    result = sanitize_trace(source, output)

    assert source.read_bytes() == original
    assert result.before.findings
    assert result.after.clean
    assert result.output == str(output)
    assert result.after.binary_members == ("resources/image-hash",)
    assert result.has_binary_residuals
    with zipfile.ZipFile(output) as archive:
        assert archive.testzip() is None
        assert archive.comment == b"archive comment"
        assert archive.namelist() == ["0-trace.trace", "resources/image-hash"]
        copied = archive.getinfo("0-trace.trace")
        assert copied.date_time == info.date_time
        assert copied.external_attr == info.external_attr
        assert copied.comment == info.comment
        assert secret.encode() not in archive.read("0-trace.trace")
        assert archive.read("resources/image-hash") == binary


def test_sanitize_uses_explicit_secrets(tmp_path: Path) -> None:
    source = tmp_path / "trace.zip"
    output = tmp_path / "redacted.zip"
    literal = "customer-reference-private"
    write_trace(source, [("0-trace.trace", json.dumps({"note": literal}).encode())])

    result = sanitize_trace(source, output, secrets=(literal,))

    assert result.after.clean
    with zipfile.ZipFile(output) as archive:
        assert literal.encode() not in archive.read("0-trace.trace")


def test_sanitize_refuses_in_place_output_without_mutating_source(tmp_path: Path) -> None:
    source = tmp_path / "trace.zip"
    write_trace(source, [("0-trace.trace", b"{}\n")])
    original = source.read_bytes()

    with pytest.raises(SanitizationError, match="must differ"):
        sanitize_trace(source, source)

    assert source.read_bytes() == original


def test_sanitize_fails_when_output_parent_does_not_exist(tmp_path: Path) -> None:
    source = tmp_path / "trace.zip"
    write_trace(source, [("0-trace.trace", b"{}\n")])

    with pytest.raises(SanitizationError, match="output directory does not exist"):
        sanitize_trace(source, tmp_path / "missing" / "redacted.zip")
