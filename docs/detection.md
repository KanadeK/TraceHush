# Detection model

TraceHush combines structural JSON processing with bounded patterns for UTF-8 text. It does not scan binary members.

## Structured rules

Each .trace, .network, .stacks, JSON, log, or UTF-8 resource is processed one line at a time. A line that parses as JSON is traversed recursively.

- Sensitive dictionary names are normalized by case and punctuation before exact matching.
- HAR-style arrays retain context. A header named Authorization is treated differently from an unrelated value field; locale cookies and page query parameters remain unchanged.
- Playwright actions whose method is fill, type, or insertText redact params.value and params.text as medium-severity captured input.
- Strings are also checked for credential-bearing URLs and token shapes.

If a JSON line changes, it is emitted as compact valid JSON. Unchanged lines keep their original characters and line endings.

## Plain-text rules

Non-JSON text supports Authorization/Proxy-Authorization lines, Cookie/Set-Cookie lines, credential-name assignments, JWTs, GitHub token prefixes, AWS access-key identifiers, URLs, and explicit literals.

Rules prefer identifiable context over entropy scoring. TraceHush intentionally does not flag every long random string because that would make CI output noisy and untrustworthy.

## Fingerprints and placeholders

Reports contain a 12-character SHA-256 prefix, not the value. The replacement is deterministic:

    [TRACEHUSH_REDACTED:<category>:<fingerprint>]

A previously redacted placeholder is ignored on a second audit. Repeated instances of the same value keep a stable fingerprint.

## Explicit literal file

Each UTF-8 nonblank, non-comment line is either:

    VARIABLE_NAME=value
    literal value

Matching quote pairs around a value are removed. There is no interpolation or environment expansion. Values shorter than four characters fail fast because replacing them broadly would destroy useful trace content.

## Known limits

- Binary image/video/attachment content is not inspected.
- Obfuscated, encrypted, split, or application-specific secrets need an explicit literal.
- Generic personal data such as names and addresses is not automatically classified.
- A source archive containing already-redacted placeholders is treated as clean for those placeholders.
