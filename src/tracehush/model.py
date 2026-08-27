"""Shared domain errors and immutable report values."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class TraceHushError(Exception):
    """Base class for expected user-facing failures."""


class ArchiveError(TraceHushError):
    """The input archive violates the supported safety boundary."""


class DetectionError(TraceHushError):
    """A supported text member contains malformed sensitive data."""


class PathConflictError(TraceHushError):
    """CLI paths would overwrite an input or another output."""


class SanitizationError(TraceHushError):
    """A text-redacted archive could not be created and verified."""


class SecretFileError(TraceHushError):
    """A user-provided literal-secret file is invalid or unreadable."""


class ReportError(TraceHushError):
    """A requested report file could not be written."""


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"


@dataclass(frozen=True, slots=True)
class Finding:
    severity: Severity
    category: str
    member: str
    line: int
    location: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class TextResult:
    redacted: str
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class AuditReport:
    source: str
    total_members: int
    text_members: int
    binary_members: tuple[str, ...]
    findings: tuple[Finding, ...]

    @property
    def clean(self) -> bool:
        return not self.findings

    @property
    def has_binary_residuals(self) -> bool:
        return bool(self.binary_members)


@dataclass(frozen=True, slots=True)
class SanitizationReport:
    before: AuditReport
    after: AuditReport
    output: str

    @property
    def has_binary_residuals(self) -> bool:
        return self.after.has_binary_residuals
