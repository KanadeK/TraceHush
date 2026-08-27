"""Build deterministic Playwright-shaped example archives."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "generated"
_TIMESTAMP = (2024, 1, 2, 3, 4, 6)


def _jsonl(*events: object) -> bytes:
    return ("\n".join(json.dumps(event, separators=(",", ":")) for event in events) + "\n").encode()


def _write_trace(path: Path, members: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.comment = b"Reproducible TraceHush demo"
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)


def main() -> None:
    OUTPUT.mkdir(exist_ok=True)

    safe_trace = _jsonl(
        {
            "type": "context-options",
            "version": 9,
            "browserName": "chromium",
            "platform": "demo",
        },
        {
            "type": "before",
            "callId": "call@1",
            "method": "goto",
            "params": {"url": "https://example.test/catalog?page=1"},
        },
    )
    safe_network = _jsonl(
        {
            "type": "resource-snapshot",
            "snapshot": {
                "request": {
                    "url": "https://example.test/catalog?page=1",
                    "headers": [{"name": "Accept", "value": "application/json"}],
                    "cookies": [{"name": "locale", "value": "en"}],
                    "queryString": [{"name": "page", "value": "1"}],
                }
            },
        }
    )
    _write_trace(
        OUTPUT / "safe-trace.zip",
        [
            ("0-trace.trace", safe_trace),
            ("0-trace.network", safe_network),
            ("resources/demo-image", b"\x89PNG\r\n\x1a\n\x00\xff"),
        ],
    )

    leaky_trace = _jsonl(
        {"type": "context-options", "version": 9, "browserName": "chromium"},
        {
            "type": "before",
            "callId": "call@1",
            "method": "fill",
            "params": {"selector": "#account", "value": "demo-form-private-123"},
        },
        {
            "type": "console",
            "text": (
                "debug eyJhbGciOiJIUzI1NiJ9."
                "eyJzdWIiOiJ0cmFjZWh1c2gtZGVtbyJ9.demo-signature-123"
            ),
        },
    )
    leaky_network = _jsonl(
        {
            "type": "resource-snapshot",
            "snapshot": {
                "request": {
                    "url": (
                        "https://demo:password@example.test/account"
                        "?access_token=demo-query-private-123&page=1"
                    ),
                    "headers": [
                        {"name": "Authorization", "value": "Bearer demo-header-private-123"},
                        {"name": "Accept", "value": "application/json"},
                    ],
                    "cookies": [
                        {"name": "session", "value": "demo-cookie-private-123"},
                        {"name": "locale", "value": "en"},
                    ],
                    "queryString": [
                        {"name": "api_key", "value": "demo-query-private-123"},
                        {"name": "page", "value": "1"},
                    ],
                }
            },
        }
    )
    _write_trace(
        OUTPUT / "leaky-trace.zip",
        [
            ("0-trace.trace", leaky_trace),
            ("0-trace.network", leaky_network),
            ("resources/demo-image", b"\x89PNG\r\n\x1a\n\x00\xff"),
        ],
    )

    print(OUTPUT / "safe-trace.zip")
    print(OUTPUT / "leaky-trace.zip")


if __name__ == "__main__":
    main()
