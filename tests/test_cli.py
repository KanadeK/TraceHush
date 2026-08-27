from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from tracehush import __version__
from tracehush.cli import main


def write_trace(path: Path, members: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members:
            archive.writestr(name, data)


def test_audit_json_exit_codes_and_no_secret_leak(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    safe = tmp_path / "safe.zip"
    leaky = tmp_path / "leaky.zip"
    secret = "Bearer cli-private-token-123"
    write_trace(safe, [("0-trace.trace", b'{"type":"context-options","version":9}\n')])
    write_trace(
        leaky,
        [
            ("0-trace.trace", json.dumps({"authorization": secret}).encode()),
            ("resources/image", b"\x00\xff"),
        ],
    )

    assert main(["audit", str(safe), "--format", "json"]) == 0
    safe_payload = json.loads(capsys.readouterr().out)
    assert safe_payload["schema_version"] == 1
    assert safe_payload["command"] == "audit"
    assert safe_payload["status"] == "clean"

    assert main(["audit", str(leaky), "--format", "json"]) == 1
    captured = capsys.readouterr()
    assert secret not in captured.out
    payload = json.loads(captured.out)
    assert payload["status"] == "findings"
    assert payload["summary"]["findings"] == 1
    assert payload["summary"]["binary_members"] == 1
    assert payload["residual_risks"][0]["kind"] == "uninspected-binary-members"


def test_audit_console_is_actionable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "trace.zip"
    write_trace(
        source,
        [
            (
                "0-trace.trace",
                json.dumps(
                    {"type": "before", "method": "fill", "params": {"value": "private input"}}
                ).encode(),
            )
        ],
    )

    assert main(["audit", str(source)]) == 1

    output = capsys.readouterr().out
    assert "FINDINGS" in output
    assert "form-input" in output
    assert "0-trace.trace:1" in output
    assert "private input" not in output


def test_sanitize_writes_archive_and_json_report(tmp_path: Path) -> None:
    source = tmp_path / "trace.zip"
    output = tmp_path / "trace.redacted.zip"
    report = tmp_path / "report.json"
    secret = "Bearer sanitize-cli-private"
    write_trace(source, [("0-trace.trace", json.dumps({"authorization": secret}).encode())])

    exit_code = main(
        [
            "sanitize",
            str(source),
            str(output),
            "--format",
            "json",
            "--report",
            str(report),
        ]
    )

    assert exit_code == 0
    assert output.is_file()
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["command"] == "sanitize"
    assert payload["status"] == "text-redacted"
    assert payload["summary"]["findings_removed"] == 1
    assert payload["summary"]["remaining_text_findings"] == 0
    assert secret not in report.read_text(encoding="utf-8")


def test_explicit_secret_file_is_used_without_echoing_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "trace.zip"
    secrets = tmp_path / "secrets.env"
    literal = "custom-private-literal-123"
    write_trace(source, [("0-trace.trace", json.dumps({"note": literal}).encode())])
    secrets.write_text(f"CUSTOM_VALUE={literal}\n", encoding="utf-8")

    assert main(["audit", str(source), "--secrets-from", str(secrets)]) == 1

    captured = capsys.readouterr()
    assert literal not in captured.out
    assert literal not in captured.err
    assert "explicit-secret" in captured.out


def test_expected_input_error_returns_two_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "bad.zip"
    source.write_bytes(b"not a zip")

    assert main(["audit", str(source)]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "tracehush: error:" in captured.err
    assert "valid ZIP" in captured.err
    assert "Traceback" not in captured.err


def test_short_secret_is_rejected_without_echoing_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "trace.zip"
    secrets = tmp_path / "secrets.env"
    write_trace(source, [("0-trace.trace", b"{}\n")])
    secrets.write_text("TOKEN=abc\n", encoding="utf-8")

    assert main(["audit", str(source), "--secrets-from", str(secrets)]) == 2

    captured = capsys.readouterr()
    assert "line 1" in captured.err
    assert "shorter than 4" in captured.err
    assert "abc" not in captured.err


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["--version"])

    assert raised.value.code == 0
    assert capsys.readouterr().out.strip() == f"tracehush {__version__}"
