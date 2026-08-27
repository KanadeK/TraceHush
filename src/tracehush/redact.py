"""Structured and plain-text secret detection with deterministic replacement."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from tracehush.model import Finding, Severity, TextResult

_REDACTED_PREFIX = "[TRACEHUSH_REDACTED:"
_FORM_METHODS = {"fill", "type", "inserttext"}
_AUTH_NAMES = {"authorization", "proxyauthorization"}
_COOKIE_NAMES = {"cookie", "setcookie"}
_SENSITIVE_NAMES = {
    "password",
    "passwd",
    "pwd",
    "token",
    "authtoken",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "apikey",
    "apisecret",
    "secret",
    "clientsecret",
    "session",
    "sessionid",
}
_URL_RE = re.compile(r"\b(?:https?|wss?)://[^\s\"'<>]+")
_AUTH_LINE_RE = re.compile(
    r"(?im)(\b(?:proxy-authorization|authorization)\s*[:=]\s*(?:bearer|basic)\s+)"
    r"([^\s,;]+)"
)
_COOKIE_LINE_RE = re.compile(r"(?im)(\b(?:set-cookie|cookie)\s*[:=]\s*)([^\r\n]+)")
_NAMED_LINE_RE = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|token|auth_token|access_token|refresh_token|"
    r"api_key|api_secret|client_secret|session_id)\b\s*[:=]\s*)([^\s,;&}]{4,})"
)
_TOKEN_PATTERNS = (
    (
        "jwt",
        re.compile(
            r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{5,}\."
            r"[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})(?![A-Za-z0-9_-])"
        ),
    ),
    (
        "github-token",
        re.compile(
            r"(?<![A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{20,}|"
            r"gh[pousr]_[A-Za-z0-9]{20,})(?![A-Za-z0-9_])"
        ),
    ),
    (
        "aws-access-key",
        re.compile(r"(?<![A-Z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])"),
    ),
)


def _normalized_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _is_redacted(value: str) -> bool:
    return value.startswith(_REDACTED_PREFIX) and value.endswith("]")


def _path(parent: str, key: str) -> str:
    if key.isidentifier():
        return f"{parent}.{key}"
    return f"{parent}[{json.dumps(key, ensure_ascii=False)}]"


class _Processor:
    def __init__(self, member: str, line: int, secrets: Sequence[str]) -> None:
        self.member = member
        self.line = line
        self.secrets = tuple(sorted(set(secrets), key=len, reverse=True))
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, str, str]] = set()

    def _redact(
        self,
        value: str,
        category: str,
        location: str,
        severity: Severity = Severity.HIGH,
    ) -> str:
        if not value or _is_redacted(value):
            return value
        fingerprint = _fingerprint(value)
        key = (category, location, fingerprint)
        if key not in self._seen:
            self._seen.add(key)
            self.findings.append(
                Finding(
                    severity=severity,
                    category=category,
                    member=self.member,
                    line=self.line,
                    location=location,
                    fingerprint=fingerprint,
                )
            )
        return f"{_REDACTED_PREFIX}{category}:{fingerprint}]"

    def _replace_group(
        self, text: str, pattern: re.Pattern[str], category: str, location: str
    ) -> str:
        def replace(match: re.Match[str]) -> str:
            value = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(1)
            group = 2 if match.lastindex and match.lastindex >= 2 else 1
            replacement = self._redact(value, category, f"{location}@{match.start(group)}")
            relative_start = match.start(group) - match.start(0)
            relative_end = match.end(group) - match.start(0)
            matched = match.group(0)
            return matched[:relative_start] + replacement + matched[relative_end:]

        return pattern.sub(replace, text)

    def _sanitize_url(self, raw_url: str, location: str) -> str:
        parts = urlsplit(raw_url)
        netloc = parts.netloc
        changed = False

        if "@" in netloc:
            userinfo, host = netloc.rsplit("@", 1)
            decoded_userinfo = unquote(userinfo)
            if not _is_redacted(decoded_userinfo):
                safe_userinfo = quote(
                    self._redact(
                        decoded_userinfo,
                        "url-credentials",
                        f"{location}.userinfo",
                    ),
                    safe="",
                )
                netloc = f"{safe_userinfo}@{host}"
                changed = True

        query_items: list[tuple[str, str]] = []
        for index, (name, value) in enumerate(parse_qsl(parts.query, keep_blank_values=True)):
            if _normalized_name(name) in _SENSITIVE_NAMES:
                value = self._redact(
                    value,
                    "sensitive-query",
                    f"{location}.query[{index}]",
                )
                changed = True
            query_items.append((name, value))

        if not changed:
            return raw_url
        return urlunsplit(
            (parts.scheme, netloc, parts.path, urlencode(query_items, doseq=True), parts.fragment)
        )

    def _generic_string(self, value: str, location: str) -> str:
        result = value

        for secret in self.secrets:
            if secret in result:
                replacement = self._redact(secret, "explicit-secret", location)
                result = result.replace(secret, replacement)

        result = _URL_RE.sub(
            lambda match: self._sanitize_url(match.group(0), f"{location}@{match.start()}"),
            result,
        )
        result = self._replace_group(result, _AUTH_LINE_RE, "authorization", location)
        result = self._replace_group(result, _COOKIE_LINE_RE, "cookie", location)
        result = self._replace_group(result, _NAMED_LINE_RE, "sensitive-field", location)

        for category, pattern in _TOKEN_PATTERNS:
            result = self._replace_group(result, pattern, category, location)

        return result

    def _named_category(self, name: str, container: str | None) -> str | None:
        normalized = _normalized_name(name)
        if normalized in _AUTH_NAMES:
            return "authorization"
        if normalized in _COOKIE_NAMES:
            return "cookie"
        if normalized not in _SENSITIVE_NAMES:
            return None
        if container == "cookies":
            return "cookie"
        if container == "query":
            return "sensitive-query"
        return "sensitive-field"

    def transform(self, value: Any, location: str, container: str | None = None) -> Any:
        if isinstance(value, str):
            return self._generic_string(value, location)
        if isinstance(value, list):
            return [
                self.transform(item, f"{location}[{index}]", container)
                for index, item in enumerate(value)
            ]
        if not isinstance(value, dict):
            return value

        pair_category: str | None = None
        if isinstance(value.get("name"), str) and isinstance(value.get("value"), str):
            pair_category = self._named_category(value["name"], container)

        form_method = str(value.get("method", "")).lower() in _FORM_METHODS
        transformed: dict[str, Any] = {}
        for key, child in value.items():
            child_location = _path(location, key)
            category = self._named_category(key, None)

            if key == "value" and pair_category is not None and isinstance(child, str):
                transformed[key] = self._redact(child, pair_category, child_location)
                continue
            if (
                container == "form-params"
                and key.lower() in {"value", "text"}
                and isinstance(child, str)
            ):
                transformed[key] = self._redact(
                    child,
                    "form-input",
                    child_location,
                    Severity.MEDIUM,
                )
                continue
            if category is not None and isinstance(child, str):
                transformed[key] = self._redact(child, category, child_location)
                continue

            child_container: str | None = None
            normalized_key = _normalized_name(key)
            if normalized_key == "headers":
                child_container = "headers"
            elif normalized_key == "cookies":
                child_container = "cookies"
            elif normalized_key == "querystring":
                child_container = "query"
            elif key == "params" and form_method:
                child_container = "form-params"

            transformed[key] = self.transform(child, child_location, child_container)

        return transformed


def _line_parts(raw_line: str) -> tuple[str, str]:
    if raw_line.endswith("\r\n"):
        return raw_line[:-2], "\r\n"
    if raw_line.endswith(("\r", "\n")):
        return raw_line[:-1], raw_line[-1:]
    return raw_line, ""


def process_text(member: str, text: str, secrets: Sequence[str] = ()) -> TextResult:
    """Find and redact sensitive values without putting them in findings."""

    output: list[str] = []
    findings: list[Finding] = []

    for line_number, raw_line in enumerate(text.splitlines(keepends=True), start=1):
        body, ending = _line_parts(raw_line)
        processor = _Processor(member, line_number, secrets)
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            redacted = processor.transform(body, "$text")
        else:
            transformed = processor.transform(parsed, "$")
            redacted = (
                json.dumps(transformed, ensure_ascii=False, separators=(",", ":"))
                if processor.findings
                else body
            )
        output.append(redacted + ending)
        findings.extend(processor.findings)

    if text and not output:
        processor = _Processor(member, 1, secrets)
        output.append(processor.transform(text, "$text"))
        findings.extend(processor.findings)

    return TextResult(redacted="".join(output), findings=tuple(findings))
