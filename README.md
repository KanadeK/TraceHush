# TraceHush

[![CI](https://github.com/KanadeK/TraceHush/actions/workflows/ci.yml/badge.svg)](https://github.com/KanadeK/TraceHush/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](https://www.python.org/)

**Audit a Playwright trace before it becomes somebody else's artifact.**

TraceHush is a dependency-free, offline CLI for existing Playwright trace ZIPs. It finds credential-like values and captured form input without printing them, then can produce a structurally valid, text-redacted copy.

Playwright's own CI guide warns that traces may contain test credentials, access tokens, and source code. TraceHush addresses the last-mile moment after a trace exists but before it is uploaded or shared.

## What makes it useful

- Post-hoc: no test-suite integration or Playwright runtime required.
- Trace-aware: understands JSONL action events and HAR name/value structures.
- Non-leaking reports: category, location, severity, and fingerprint; never the matched value.
- Scriptable: audit exits 0 clean, 1 findings, and 2 invalid input/error.
- Evidence-preserving: member order, timestamps, permissions, comments, and binary bytes are retained.
- Honest boundary: screenshots and other binary members are reported as residual risk, never declared safe.
- Offline: no upload, telemetry, account, or runtime dependency.

## Install

From the v0.1.0 wheel:

    uv tool install https://github.com/KanadeK/TraceHush/releases/download/v0.1.0/tracehush-0.1.0-py3-none-any.whl

Or directly from source:

    uv tool install git+https://github.com/KanadeK/TraceHush.git

Python 3.11 or newer is required. pipx can be used with the same wheel or Git URL.

## Thirty-second workflow

Audit a trace:

    tracehush audit test-results/login/trace.zip

Create a machine-readable report:

    tracehush audit test-results/login/trace.zip --format json --output tracehush-report.json

Create a text-redacted copy and re-audit it:

    tracehush sanitize trace.zip trace.redacted.zip --format json --report sanitize-report.json
    tracehush audit trace.redacted.zip

Add application-specific literals without exposing them in output:

    tracehush audit trace.zip --secrets-from .tracehush-secrets.env

The secrets file accepts blank/comment lines, NAME=VALUE lines, and literal lines. Values under four characters are rejected.

## Example result

    TraceHush audit: FINDINGS
    Source: trace.zip
    Members: 3 total, 2 text, 1 binary
    Findings: 2
    - HIGH authorization 0-trace.network:1 $.snapshot.request.headers[0].value fingerprint=9d3b...
    - MEDIUM form-input 0-trace.trace:2 $.params.value fingerprint=87f1...
    RESIDUAL RISK: 1 binary member(s) were not inspected or altered.

The fingerprint is the first 12 hexadecimal characters of SHA-256 over a matched value. It helps correlate repeated exposure without revealing the value.

## Detection coverage

| Surface | Examples | Severity |
|---|---|---|
| HAR headers | Authorization, Proxy-Authorization, Cookie, Set-Cookie, API-key names | high |
| HAR cookies/query | session-like cookie names, token/key/secret query names | high |
| Nested named fields | password, accessToken, api_key, clientSecret, sessionId | high |
| Credential URLs | user-info and credential-like query values | high |
| Token shapes | JWT, GitHub token prefixes, AWS access-key identifiers | high |
| Explicit literals | values supplied through --secrets-from | high |
| Playwright actions | fill, type, insertText value/text parameters | medium |

See [detection details](docs/detection.md) for exact behavior and false-positive policy.

## Residual risk is part of the result

A text-redacted trace is **not universally safe to share**. PNG/JPEG frames, video, fonts, and arbitrary attachments may still reveal screen content or embedded data. TraceHush preserves those bytes and reports every uninspected binary member. Regenerate a trace without sensitive visual content or review/remove those resources before sharing.

See the [security model](docs/security.md).

## CI use

A single trace can gate an upload directly:

    tracehush audit test-results/checkout/trace.zip --format json --output tracehush.json

Only archive/upload when that command exits 0. Exit 1 means findings need review or sanitization. Exit 2 means the artifact or command is invalid and should not be uploaded.

## Reproducible examples

    uv run python examples/build_examples.py
    uv run tracehush audit examples/generated/safe-trace.zip
    uv run tracehush audit examples/generated/leaky-trace.zip
    uv run tracehush sanitize examples/generated/leaky-trace.zip examples/generated/leaky-trace.redacted.zip

The leaky example intentionally exits 1. Generated archives use fixed metadata so they are reproducible.

## Development and acceptance

    uv sync --frozen --extra dev
    uv run ruff check .
    uv run ruff format --check .
    uv run mypy src tests
    uv run pytest --basetemp .pytest-tmp --cov=tracehush --cov-branch --cov-fail-under=90
    uv build
    uv run pip-audit
    pwsh -NoProfile -File scripts/release-gate.ps1

The complete gate also builds examples, exercises all three exit-code paths, sanitizes and re-audits the leaky trace, builds wheel/sdist, and runs the wheel through uvx.

If anything fails, use the copy-ready [failure and recovery guide](docs/recovery.md).

## Format sources and compatibility

The implementation follows Playwright's official trace event and HAR type definitions:

- https://github.com/microsoft/playwright/blob/main/packages/trace/src/trace.ts
- https://github.com/microsoft/playwright/blob/main/packages/trace/src/har.ts
- https://github.com/microsoft/playwright/blob/main/docs/src/ci-intro.md#properly-handling-secrets
- https://github.com/microsoft/playwright/issues/31728

TraceHush does not depend on one numeric trace-format version. It requires a ZIP containing at least one .trace or .network member and processes JSONL plus UTF-8 resources conservatively.

## Contributing

Bug reports and focused detector improvements are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) before attaching any trace: never upload a real sensitive artifact.

MIT licensed.
