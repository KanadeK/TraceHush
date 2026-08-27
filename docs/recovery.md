# Failure and recovery guide

Every command has a deterministic exit class:

| Exit | Meaning | Next action |
|---:|---|---|
| 0 | Audit clean, or sanitize completed and verified | Review binary residuals before sharing |
| 1 | Audit found textual share-risk | Inspect report locations, then sanitize or regenerate |
| 2 | Invalid input, unsafe archive, bad arguments, or operational failure | Fix the stated boundary error; do not upload |

## Audit exits 1

Create a JSON report without exposing values:

    tracehush audit trace.zip --format json --output tracehush-report.json

Then create and verify a copy:

    tracehush sanitize trace.zip trace.redacted.zip --format json --report sanitize-report.json
    tracehush audit trace.redacted.zip

If a value is application-specific and was not detected, put the exact value in a local ignored file and pass --secrets-from. Never commit that file.

## Binary residual warning remains

This is expected for traces with screenshots or binary resources. TraceHush deliberately keeps them unchanged.

Repair options:

1. Regenerate the Playwright trace with sensitive visual content absent.
2. Disable screenshots for the trace using the supported option in your Playwright binding/configuration.
3. Remove or replace binary artifacts through a reviewed workflow.
4. Share only after manual review through a trusted/encrypted channel.

Do not interpret a clean textual audit as image approval.

## Exit 2: not a valid ZIP

Confirm the path points to a completed Playwright trace ZIP:

    uv run python -m zipfile -t trace.zip

A report HTML ZIP, test-results directory, truncated download, or generic ZIP is not accepted. Obtain the original trace artifact and retry.

## Exit 2: no Playwright .trace or .network member

List the archive without extracting it:

    uv run python -m zipfile -l trace.zip

Use the actual Playwright trace ZIP rather than a surrounding CI artifact bundle.

## Exit 2: unsafe, encrypted, duplicate, or oversized member

Do not bypass the check. Regenerate the trace from Playwright. For large traces, reduce captured source/screenshots/network scope or split the test scenario. v0.1 intentionally has no command-line limit override.

## Exit 2: output directory does not exist

Create the intended narrow directory, then retry:

    New-Item -ItemType Directory -Path reports
    tracehush sanitize trace.zip reports/trace.redacted.zip

TraceHush does not guess or create parent directories.

## Dependency or local gate failure

Restore the locked development environment:

    uv sync --frozen --extra dev
    pwsh -NoProfile -File scripts/release-gate.ps1

If Pytest cannot access the Windows user temp directory, use the repository-local boundary already used by the project:

    uv run pytest --basetemp .pytest-tmp

Do not add product-code fallbacks for a test-runner permission issue.

## Release rollback

Do not replace an already published tag. Revert the faulty commit, add a regression test, release a new patch version, and mark the affected GitHub Release as deprecated with a link to the replacement.
