# TraceHush v0.1 implementation plan

## Task 0 — Product contract

Files: idea brief, SPEC, ADR, plan, todo.
Acceptance: scope, non-goals, CLI, failures, limits, evidence, and release criteria are explicit.

## Task 1 — Archive boundary and model

Files: pyproject, package init, model, archive, archive tests.
TDD: prove tests fail before implementation.
Acceptance: valid members iterate; malformed, encrypted, unsafe, duplicate, excessive-member, excessive-entry, and excessive-total archives fail explicitly.
Verify: focused pytest, typing, lint.

## Task 2 — Detection and redaction

Files: redact module/tests/helpers and detection docs.
TDD: specify structured headers/queries/actions, nested names, URLs, token shapes, literals, and false positives first.
Acceptance: findings omit values, fingerprints/placeholders are deterministic, JSON remains parseable, plain text works.

## Task 3 — Services

Files: service module/tests, example builder, gitignore.
TDD: specify immutability, metadata, binary residuals, second-pass verification, and atomic output first.
Acceptance: leaky example is found; sanitized example passes integrity and textual re-audit.

## Task 4 — CLI and reports

Files: report/CLI modules and tests.
TDD: specify exit codes, streams, JSON contract, files, secret-file validation, and version first.
Acceptance: safe/leaky/error outcomes are scriptable and no seeded value appears.

## Task 5 — Documentation and packaging

Files: README, security, recovery, changelog, license.
Acceptance: install, quickstart, examples, limitations, CI use, acceptance commands, and failure repairs are copy-ready.
Verify: follow README from a clean wheel install.

## Task 6 — CI and release

Files: CI/release workflows, release gate, SECURITY.
Acceptance: Ubuntu/Windows gate all checks; tags build release assets.
Verify: local gate then remote Actions/Release.

## Task 7 — Delivery

Acceptance: exact repo pushed, CI green, v0.1.0 tag/Release/assets/checksums/source/contributors/install verified, Gmail sent to self and visible in Sent.
