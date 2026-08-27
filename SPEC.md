# TraceHush v0.1 specification

## Objective

Deliver a public, installable, offline CLI that audits Playwright trace ZIP files for share-risk and creates text-redacted copies without exposing matched values in reports.

## Stack

Python 3.11+, standard library only at runtime, uv for locking, pytest/coverage, Ruff, mypy, build, pip-audit, and GitHub Actions on Ubuntu and Windows. No browser or Playwright runtime is required.

## Public CLI

    tracehush audit TRACE.zip [--format console|json] [--output PATH] [--secrets-from PATH]
    tracehush sanitize TRACE.zip OUTPUT.zip [--format console|json] [--report PATH] [--secrets-from PATH]
    tracehush --version

Audit reads without extraction, reports built-in and user-supplied secret matches without values, and exits 0 clean, 1 findings, 2 invalid input or operational error.

Sanitize refuses in-place output, deterministically replaces textual matches, preserves ZIP metadata, copies binary members unchanged with an explicit residual-risk warning, validates the new ZIP, re-audits it, and exits 0 success or 2 failure.

The optional UTF-8 secret file accepts each nonblank, non-comment line as NAME=VALUE or a literal. Values shorter than four characters fail fast. Names and values never enter reports.

## Finding contract

Each finding contains only severity, category, member name, one-based line, JSON path/text location, and a 12-character SHA-256 fingerprint. Placeholders are deterministic:

    [TRACEHUSH_REDACTED:<category>:<fingerprint>]

High severity covers authorization/cookie values, credential-like named values, JWTs, GitHub token shapes, AWS access-key identifiers, explicit literals, and credential-bearing URLs. Medium severity covers Playwright fill, type, and insertText values.

## Archive boundary

Fail before processing if input is not a regular ZIP, an entry is encrypted, an entry name is absolute or traverses with .., names duplicate, members exceed 10,000, one uncompressed member exceeds 64 MiB, or total uncompressed size exceeds 512 MiB.

## Structure

    src/tracehush/__init__.py  version
    src/tracehush/model.py     immutable models/errors
    src/tracehush/archive.py   validated member iteration
    src/tracehush/redact.py    detection/replacement
    src/tracehush/service.py   audit/sanitize orchestration
    src/tracehush/report.py    console/JSON rendering
    src/tracehush/cli.py       argparse and exit codes
    tests/                     unit/integration/CLI tests
    examples/                  generated safe/leaky traces
    scripts/                   release gate

Use typed small functions and immutable values. Validate at CLI, secret-file, and ZIP boundaries. Catch explicit TraceHushError subclasses once at the CLI boundary; do not swallow unexpected exceptions.

## Tests and commands

Unit and integration tests cover archive limits, secret parsing, all detectors, false positives, no-value-leak, deterministic redaction, metadata, input immutability, residual risk, and exit codes. Coverage threshold is 90% lines and branches.

    uv sync --extra dev
    uv run ruff check .
    uv run ruff format --check .
    uv run mypy src tests
    uv run pytest --cov=tracehush --cov-branch --cov-fail-under=90
    uv build
    uv run pip-audit
    pwsh -NoProfile -File scripts/release-gate.ps1

## Boundaries

Always remain offline, preserve input, omit raw matches, report binary residuals, and fail closed on malformed input.

Ask before adding network access, telemetry, runtime dependencies, incompatible schemas, or binary-sanitization claims.

Never upload a trace, mutate input in place, print raw secrets, or call output universally safe.

## Success criteria

- Playwright-shaped ZIPs audit without extraction.
- All detector classes have positive/negative tests and reports never expose seeded values.
- Sanitized ZIPs pass integrity and re-audit clean for textual findings.
- Console and JSON both expose binary residual risk.
- Safe/leaky/invalid examples exit 0/1/2.
- Wheel installs and runs in a clean environment.
- Ruff, mypy, 90% branch coverage, build, audit, package smoke, and examples pass locally and on Windows/Ubuntu CI.
- Public repository, v0.1.0 tag, Release, wheel, sdist, checksums, source archive, contributors, and release install are remotely verified.
- Gmail is sent to self only after remote verification.

Deferred: OCR/image redaction, SARIF, a native action wrapper, and non-Playwright formats.
