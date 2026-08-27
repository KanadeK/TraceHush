# TraceHush idea brief

## Problem

Playwright traces are excellent debugging artifacts, but they can also contain DOM snapshots, network data, console output, filled form values, attachments, and source locations. Teams often discover this only when a failed-test trace is about to be uploaded or shared.

## One-line promise

Audit an existing Playwright trace offline, show where share-risk exists without printing the secret, and create a text-redacted copy that preserves archive structure.

## Core workflow

1. Run tracehush audit trace.zip before artifact upload.
2. Receive a non-zero exit code when credential-like data or captured form input is present.
3. Run tracehush sanitize trace.zip trace.redacted.zip.
4. Review residual risk before sharing; binary resources are never silently declared safe.

## Differentiation

- Operates on already-created trace ZIPs rather than requiring test-code changes.
- Understands Playwright JSONL/HAR shapes, including name/value pairs and action parameters.
- Reports category, member, JSON path, line, and fingerprint but never raw values.
- Stays offline and dependency-free at runtime.
- Produces a deterministic, structurally valid ZIP copy rather than only warnings.

## Research decision

PowerPoint privacy preflight, CSV formula-injection cleaning, multi-camera clock drift, and DMX patch linting were rejected because direct mature coverage exists. GitHub searches for playwright trace sanitizer, playwright trace secrets, and trace.zip redact found no direct post-hoc sanitizer. The exact TraceHush repository search had no result, and the PyPI endpoint returned 404 on 2026-08-27.

## Official source basis

- Sensitive artifact warning: https://github.com/microsoft/playwright/blob/main/docs/src/ci-intro.md#properly-handling-secrets
- User demand for trace scrubbing: https://github.com/microsoft/playwright/issues/31728
- Trace event types: https://github.com/microsoft/playwright/blob/main/packages/trace/src/trace.ts
- HAR types: https://github.com/microsoft/playwright/blob/main/packages/trace/src/har.ts

## Non-goals

- Guaranteeing that screenshots, videos, fonts, or arbitrary binary attachments are safe.
- Extracting archives to disk.
- Uploading traces or fingerprints.
- Replacing a general repository secret scanner.
- Mutating the source trace in place.
