"""Shared domain errors and immutable report values."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class TraceHushError(Exception):
    """Base class for expected user-facing failures."""


class ArchiveError(TraceHushError):
    """The input archive violates the supported safety boundary."""


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
