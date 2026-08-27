# ADR 0001: Offline standard-library post-hoc sanitizer

Status: accepted for v0.1.0

## Context

Playwright advises treating traces as sensitive artifacts. The unmet point is immediately before upload or sharing, when a trace already exists. The format consists of ZIP members containing JSONL trace/network records plus content-addressed resources.

## Decision

Build a Python 3.11+ CLI with no runtime dependencies. Read and rewrite one bounded ZIP member at a time. Parse JSONL when possible so header pairs, action parameters, and nested names are handled structurally; use bounded pattern matching for non-JSON UTF-8 text.

Call output text-redacted, not safe, because unchanged binary resources may reveal sensitive screen content.

## Consequences

- Installation and use stay small, offline, and cross-platform.
- Post-hoc use works for every Playwright language binding.
- JSONL whitespace can change while data structure remains valid.
- Binary privacy remains a disclosed manual-review responsibility.

## Rejected alternatives

A Playwright plugin cannot cover existing cross-language artifacts. Regex-only byte replacement can corrupt escapes and misses structured pairs. A hosted service creates the exposure risk being reduced. OCR in v0.1 adds large dependencies without a trustworthy guarantee.
