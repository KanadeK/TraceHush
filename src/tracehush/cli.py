"""Command-line boundary for TraceHush."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from tracehush import __version__
from tracehush.model import ReportError, SecretFileError, TraceHushError
from tracehush.report import (
    audit_payload,
    render_audit_console,
    render_json,
    render_sanitization_console,
    sanitization_payload,
)
from tracehush.service import audit_trace, sanitize_trace

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tracehush",
        description="Audit and text-redact Playwright trace ZIP files offline.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser("audit", help="Audit a trace without changing it.")
    audit.add_argument("trace", type=Path)
    audit.add_argument("--format", choices=("console", "json"), default="console")
    audit.add_argument("--output", type=Path, help="Write the report instead of stdout.")
    audit.add_argument("--secrets-from", type=Path, metavar="PATH")

    sanitize = subparsers.add_parser("sanitize", help="Create a text-redacted trace copy.")
    sanitize.add_argument("trace", type=Path)
    sanitize.add_argument("output", type=Path)
    sanitize.add_argument("--format", choices=("console", "json"), default="console")
    sanitize.add_argument("--report", type=Path, help="Write the report instead of stdout.")
    sanitize.add_argument("--secrets-from", type=Path, metavar="PATH")

    return parser


def _load_secrets(path: Path | None) -> tuple[str, ...]:
    if path is None:
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SecretFileError(f"could not read UTF-8 secret file: {path}") from exc

    secrets: list[str] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        candidate = line
        if "=" in line:
            name, value = line.split("=", 1)
            if _ENV_NAME_RE.fullmatch(name.strip()):
                candidate = value.strip()
        if len(candidate) >= 2 and candidate[0] == candidate[-1] and candidate[0] in {'"', "'"}:
            candidate = candidate[1:-1]
        if len(candidate) < 4:
            raise SecretFileError(
                f"secret file line {line_number} has a value shorter than 4 characters"
            )
        if candidate not in secrets:
            secrets.append(candidate)
    return tuple(secrets)


def _emit(content: str, destination: Path | None) -> None:
    if destination is None:
        print(content)
        return
    try:
        destination.write_text(content + "\n", encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"could not write report: {destination}") from exc


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        secrets = _load_secrets(args.secrets_from)
        if args.command == "audit":
            audit_report = audit_trace(args.trace, secrets)
            rendered = (
                render_json(audit_payload(audit_report))
                if args.format == "json"
                else render_audit_console(audit_report)
            )
            _emit(rendered, args.output)
            return 0 if audit_report.clean else 1

        sanitization_report = sanitize_trace(args.trace, args.output, secrets)
        rendered = (
            render_json(sanitization_payload(sanitization_report))
            if args.format == "json"
            else render_sanitization_console(sanitization_report)
        )
        _emit(rendered, args.report)
        return 0
    except TraceHushError as exc:
        print(f"tracehush: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
