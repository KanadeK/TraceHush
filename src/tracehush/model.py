"""Shared domain errors and immutable report values."""

from __future__ import annotations


class TraceHushError(Exception):
    """Base class for expected user-facing failures."""


class ArchiveError(TraceHushError):
    """The input archive violates the supported safety boundary."""
