# Contributing

Keep changes narrow and test-driven.

## Setup

    uv sync --frozen --extra dev

## Workflow

1. Add the smallest failing test for one behavior.
2. Run that focused test and record the RED reason.
3. Implement the minimum behavior.
4. Run the focused test, then the full gate.
5. Update detection/security docs when behavior or risk changes.

## Gate

    pwsh -NoProfile -File scripts/release-gate.ps1

## Detector requirements

A new detector needs:

- a positive test,
- a nearby negative/false-positive test,
- proof that console and JSON do not contain the matched value,
- deterministic replacement,
- a detection-doc update.

Do not commit real secrets or real Playwright traces. Use unmistakably fake values in generated fixtures.

## Scope

Network upload, telemetry, runtime dependencies, incompatible report-schema changes, and claims of binary sanitization require a design discussion before code.
