# Security policy

## Supported versions

The latest 0.1.x release receives security fixes.

## Reporting a vulnerability

Do not open a public issue containing a trace, secret, token, screenshot, or exploit payload.

Use GitHub private vulnerability reporting when available. If that option is unavailable, open a minimal public issue asking the maintainer to establish a private contact channel; include no sensitive details.

A useful private report includes the affected version, detector category, smallest synthetic reproducer, impact, and whether reports or output expose a value.

## Disclosure behavior

TraceHush never claims universal share safety. A successful sanitize command proves only that this release's textual detectors find no remaining match and that the ZIP passes integrity checks. Binary resources always require separate review.
