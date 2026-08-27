# Security model

## Threat model

TraceHush treats the input ZIP and secret file as untrusted local inputs. It assumes the machine running the CLI is trusted.

The main risks are accidental disclosure in reports, archive resource exhaustion, path traversal during extraction, source mutation, incomplete redaction, and network exfiltration.

## Controls

- No network code or runtime dependency.
- ZIP members are read without extraction.
- Absolute/traversing and duplicate member names are rejected.
- Encrypted members are rejected instead of guessed.
- Limits: 10,000 members, 64 MiB per uncompressed member, 512 MiB total.
- Findings contain no matched value.
- Source and output paths must differ.
- Output is written to a same-directory temporary file, integrity-tested, text re-audited, then atomically replaced.
- A failed operation removes its temporary file.
- Binary members are copied unchanged and listed as residual risk.

## What text-redacted means

It means all textual values detected by this version's rules were replaced and the resulting textual archive re-audited clean. It does not mean anonymous, compliant, or universally safe.

Screenshots can show passwords, names, account data, and internal UI. Attachments may contain arbitrary formats. Source locations and harmless URLs may remain because removing all diagnostic context would defeat the artifact's purpose.

## Safe operational pattern

1. Use synthetic test accounts and data.
2. Audit before any upload.
3. Sanitize textual findings.
4. Re-audit the output.
5. Review binary residuals.
6. Share only through a trusted or encrypted channel.

Never attach a real sensitive trace to a public issue.
