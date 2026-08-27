"""Stable console and JSON rendering for TraceHush results."""

from __future__ import annotations

import json
from typing import Any

from tracehush.model import AuditReport, Finding, SanitizationReport, Severity

SCHEMA_VERSION = 1


def _finding_payload(finding: Finding) -> dict[str, Any]:
    return {
        "severity": finding.severity.value,
        "category": finding.category,
        "member": finding.member,
        "line": finding.line,
        "location": finding.location,
        "fingerprint": finding.fingerprint,
    }


def _summary(report: AuditReport) -> dict[str, int]:
    return {
        "members": report.total_members,
        "text_members": report.text_members,
        "binary_members": len(report.binary_members),
        "findings": len(report.findings),
        "high": sum(item.severity is Severity.HIGH for item in report.findings),
        "medium": sum(item.severity is Severity.MEDIUM for item in report.findings),
    }


def _residual_risks(report: AuditReport) -> list[dict[str, Any]]:
    if not report.binary_members:
        return []
    return [
        {
            "kind": "uninspected-binary-members",
            "count": len(report.binary_members),
            "members": list(report.binary_members),
            "message": "Binary members were not inspected or altered and require manual review.",
        }
    ]


def audit_payload(report: AuditReport) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "command": "audit",
        "status": "clean" if report.clean else "findings",
        "source": report.source,
        "summary": _summary(report),
        "findings": [_finding_payload(item) for item in report.findings],
        "residual_risks": _residual_risks(report),
    }


def sanitization_payload(report: SanitizationReport) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "command": "sanitize",
        "status": "text-redacted",
        "source": report.before.source,
        "output": report.output,
        "summary": {
            "findings_removed": len(report.before.findings),
            "remaining_text_findings": len(report.after.findings),
            "members": report.after.total_members,
            "text_members": report.after.text_members,
            "binary_members": len(report.after.binary_members),
        },
        "findings": [_finding_payload(item) for item in report.before.findings],
        "residual_risks": _residual_risks(report.after),
    }


def render_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def render_audit_console(report: AuditReport) -> str:
    status = "CLEAN" if report.clean else "FINDINGS"
    lines = [
        f"TraceHush audit: {status}",
        f"Source: {report.source}",
        (
            f"Members: {report.total_members} total, {report.text_members} text, "
            f"{len(report.binary_members)} binary"
        ),
        f"Findings: {len(report.findings)}",
    ]
    for finding in report.findings:
        lines.append(
            f"- {finding.severity.value.upper()} {finding.category} "
            f"{finding.member}:{finding.line} {finding.location} "
            f"fingerprint={finding.fingerprint}"
        )
    if report.binary_members:
        lines.append(
            "RESIDUAL RISK: "
            f"{len(report.binary_members)} binary member(s) were not inspected or altered."
        )
    return "\n".join(lines)


def render_sanitization_console(report: SanitizationReport) -> str:
    lines = [
        "TraceHush sanitize: TEXT-REDACTED",
        f"Source: {report.before.source}",
        f"Output: {report.output}",
        f"Text findings removed: {len(report.before.findings)}",
        f"Remaining text findings: {len(report.after.findings)}",
    ]
    if report.has_binary_residuals:
        lines.append(
            "RESIDUAL RISK: "
            f"{len(report.after.binary_members)} binary member(s) were copied without inspection."
        )
    return "\n".join(lines)
