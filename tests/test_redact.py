from __future__ import annotations

import json

from tracehush.redact import process_text


def test_redacts_playwright_fill_value_without_reporting_it() -> None:
    secret = "form-value-private-123"
    source = json.dumps(
        {"type": "before", "method": "fill", "params": {"selector": "#email", "value": secret}}
    )

    result = process_text("0-trace.trace", source + "\n")

    assert secret not in result.redacted
    assert secret not in repr(result.findings)
    assert json.loads(result.redacted)["params"]["value"].startswith(
        "[TRACEHUSH_REDACTED:form-input:"
    )
    assert [(item.severity.value, item.category) for item in result.findings] == [
        ("medium", "form-input")
    ]


def test_redacts_har_headers_cookies_queries_and_url_credentials() -> None:
    source = json.dumps(
        {
            "type": "resource-snapshot",
            "snapshot": {
                "request": {
                    "url": "https://user:passphrase@example.test/items?access_token=query-secret-123&page=1",
                    "headers": [
                        {"name": "Authorization", "value": "Bearer header-secret-123"},
                        {"name": "Accept", "value": "application/json"},
                    ],
                    "cookies": [
                        {"name": "session", "value": "cookie-secret-123"},
                        {"name": "locale", "value": "en"},
                    ],
                    "queryString": [
                        {"name": "api_key", "value": "query-secret-123"},
                        {"name": "page", "value": "1"},
                    ],
                }
            },
        }
    )

    result = process_text("0-trace.network", source)

    for value in [
        "user:passphrase",
        "query-secret-123",
        "header-secret-123",
        "cookie-secret-123",
    ]:
        assert value not in result.redacted
        assert value not in repr(result.findings)
    assert {item.category for item in result.findings} >= {
        "authorization",
        "cookie",
        "sensitive-query",
        "url-credentials",
    }
    request = json.loads(result.redacted)["snapshot"]["request"]
    assert request["headers"][1]["value"] == "application/json"
    assert request["cookies"][1]["value"] == "en"
    assert request["queryString"][1]["value"] == "1"


def test_redacts_nested_sensitive_field() -> None:
    source = '{"config":{"clientSecret":"nested-secret-123","retry":3}}'

    result = process_text("0-trace.trace", source)

    assert "nested-secret-123" not in result.redacted
    assert result.findings[0].category == "sensitive-field"
    assert result.findings[0].location == "$.config.clientSecret"


def test_redacts_token_shapes_in_arbitrary_string_values() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123456"
    github = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    aws = "AKIAABCDEFGHIJKLMNOP"
    source = json.dumps({"message": f"{jwt} {github} {aws}"})

    result = process_text("0-trace.trace", source)

    assert jwt not in result.redacted
    assert github not in result.redacted
    assert aws not in result.redacted
    assert {item.category for item in result.findings} == {
        "jwt",
        "github-token",
        "aws-access-key",
    }


def test_redacts_explicit_literal_everywhere_deterministically() -> None:
    secret = "literal-secret-9876"
    source = json.dumps({"first": secret, "second": f"prefix {secret} suffix"})

    first = process_text("0-trace.trace", source, secrets=(secret,))
    second = process_text("0-trace.trace", source, secrets=(secret,))

    assert secret not in first.redacted
    assert first.redacted == second.redacted
    assert {item.fingerprint for item in first.findings} == {first.findings[0].fingerprint}
    assert first.redacted.count("[TRACEHUSH_REDACTED:explicit-secret:") == 2


def test_redacts_non_json_authorization_cookie_and_named_value() -> None:
    source = (
        "Authorization: Bearer plain-token-123456\n"
        "Cookie: session=cookie-value-123\n"
        "password=plain-password-123\n"
    )

    result = process_text("resources/plain.txt", source)

    for value in ["plain-token-123456", "session=cookie-value-123", "plain-password-123"]:
        assert value not in result.redacted
    assert {item.category for item in result.findings} == {
        "authorization",
        "cookie",
        "sensitive-field",
    }


def test_safe_text_is_byte_for_character_unchanged() -> None:
    source = '{"method":"goto","params":{"url":"https://example.test/?page=1"}}\r\nplain text\n'

    result = process_text("0-trace.trace", source)

    assert result.redacted == source
    assert result.findings == ()


def test_similar_but_nonsensitive_names_are_not_flagged() -> None:
    source = json.dumps(
        {"token_count": 12, "author": "BearerCat", "headers": [{"name": "Accept", "value": "*/*"}]}
    )

    result = process_text("0-trace.network", source)

    assert result.redacted == source
    assert result.findings == ()
