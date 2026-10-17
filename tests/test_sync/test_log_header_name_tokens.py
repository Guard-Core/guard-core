import logging
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.sync._utils.request_logging import (
    _redact_sensitive_headers,
    log_activity,
)
from guard_core.sync.decorators.base import RouteConfig
from tests.test_sync.conftest import SyncMockGuardRequest

SECRET = "SEKRET-VALUE-123"


@pytest.mark.parametrize(
    "name",
    [
        "X-Auth-Token",
        "X-Access-Token",
        "X-CSRF-Token",
        "X-XSRF-Token",
        "X-Amz-Security-Token",
        "X-Goog-Iam-Authorization-Token",
        "X-Api-Key",
        "apiKey",
        "APIKey",
        "x_service_key",
        "X-Client-Secret",
        "X-Session-Id",
        "X-SID",
        "X-Password",
        "X-Pass",
        "X-Pwd",
        "X-Passwd",
        "X-Passphrase",
        "X-SessionId",
        "X-Apikey",
        "Authorization",
        "X-Otp",
        "X-Auth",
        "Sec-WebSocket-Key",
        "x.auth.header",
    ],
)
def test_a_credential_shaped_header_name_is_redacted(name: str) -> None:
    redacted = _redact_sensitive_headers({name: SECRET}, None)

    assert redacted[name] == "[REDACTED]"


@pytest.mark.parametrize(
    "name",
    [
        "User-Agent",
        "Accept",
        "Content-Type",
        "X-Request-Id",
        "X-Forwarded-For",
        "Keywords",
        "X-Author",
        "X-Monkey",
        "X-Passenger",
        "X-Keyboard",
        "X-Otpion",
        "Authority",
    ],
)
def test_a_header_name_that_only_contains_a_token_is_not_redacted(name: str) -> None:
    redacted = _redact_sensitive_headers({name: "plain-value"}, None)

    assert redacted[name] == "plain-value"


def test_the_default_names_and_the_configured_names_still_redact() -> None:
    redacted = _redact_sensitive_headers(
        {"Authorization": SECRET, "Cookie": SECRET, "X-Mine": SECRET},
        frozenset({"x-mine"}),
    )

    assert set(redacted.values()) == {"[REDACTED]"}


def _logged(route_config: RouteConfig | None, headers: dict[str, str]) -> str:
    request = SyncMockGuardRequest(path="/x", headers=headers)
    request.state.route_config = route_config
    logger = MagicMock(spec=logging.Logger)
    log_activity(request, logger, level="INFO")
    return " ".join(str(call.args) for call in logger.info.call_args_list)


def test_a_route_api_key_header_is_redacted_in_the_log_line() -> None:
    route_config = RouteConfig()
    route_config.api_key_header = "Svc-Credential"

    line = _logged(route_config, {"Svc-Credential": SECRET, "Accept": "text/html"})

    assert SECRET not in line
    assert "text/html" in line


def test_a_route_required_header_name_is_redacted_in_the_log_line() -> None:
    route_config = RouteConfig()
    route_config.required_headers = {"X-Internal-Marker": "required"}

    line = _logged(route_config, {"X-Internal-Marker": SECRET})

    assert SECRET not in line


def test_an_unrelated_route_header_is_not_redacted() -> None:
    route_config = RouteConfig()
    route_config.api_key_header = "Svc-Credential"

    line = _logged(route_config, {"X-Trace": "trace-abc"})

    assert "trace-abc" in line


def test_no_route_config_means_only_the_token_rule_applies() -> None:
    line = _logged(None, {"X-Auth-Token": SECRET, "X-Trace": "trace-abc"})

    assert SECRET not in line
    assert "trace-abc" in line


def test_a_route_config_that_is_not_a_route_config_is_ignored() -> None:
    request: Any = SyncMockGuardRequest(path="/x", headers={"X-Trace": "trace-abc"})
    request.state.route_config = object()
    logger = MagicMock(spec=logging.Logger)

    log_activity(request, logger, level="INFO")

    assert "trace-abc" in " ".join(str(c.args) for c in logger.info.call_args_list)
