from typing import Any
from unittest.mock import AsyncMock, Mock, patch

from guard_core.core.checks.helpers import is_referrer_domain_allowed
from guard_core.models import SecurityConfig
from guard_core.utils import (
    _extract_from_forwarded_header,
    _sanitize_for_log,
    detect_penetration_attempt,
    extract_client_ip,
)


def test_sanitize_empty_string() -> None:
    result = _sanitize_for_log("")
    assert result == ""


def test_sanitize_none() -> None:
    not_a_string: Any = None
    result = _sanitize_for_log(not_a_string)
    assert result is None


def test_sanitize_with_content() -> None:
    result = _sanitize_for_log("test\nvalue")
    assert result == "test\\nvalue"


def test_extract_empty_header() -> None:
    result = _extract_from_forwarded_header("", 1)
    assert result is None


def test_extract_with_valid_header() -> None:
    result = _extract_from_forwarded_header("1.2.3.4, 5.6.7.8", 2)
    assert result == "1.2.3.4"


async def test_extract_client_ip_returns_cached_ip() -> None:
    request = Mock()
    request.state.client_ip = "10.0.0.1"

    config = SecurityConfig()
    result = await extract_client_ip(request, config, None)
    assert result == "10.0.0.1"


async def test_extract_client_ip_with_invalid_forwarded_for() -> None:
    request = Mock()
    request.client_host = "192.168.1.1"
    request.state.client_ip = None
    request.headers = {"X-Forwarded-For": "invalid-ip-format"}

    config = SecurityConfig()
    config.trusted_proxies = ("192.168.1.1",)
    config.trusted_proxy_depth = 999

    with patch(
        "guard_core._utils.ip_extraction._extract_from_forwarded_header",
        side_effect=ValueError("Invalid IP"),
    ):
        result = await extract_client_ip(request, config, None)
        assert result == "192.168.1.1"


async def test_extract_client_ip_logs_warning_on_error() -> None:
    request = Mock()
    request.client_host = "192.168.1.1"
    request.state.client_ip = None
    request.headers = {"X-Forwarded-For": "1.2.3.4"}

    config = SecurityConfig()
    config.trusted_proxies = ("192.168.1.1",)
    config.trusted_proxy_depth = 1

    with (
        patch(
            "guard_core._utils.ip_extraction._extract_from_forwarded_header",
            side_effect=IndexError("Test error"),
        ),
        patch("guard_core._utils.ip_extraction.logger") as mock_logging,
    ):
        result = await extract_client_ip(request, config, None)

        assert result == "192.168.1.1"
        mock_logging.warning.assert_any_call("Error processing client IP: Test error")


async def test_detect_penetration_url_path_with_real_threat() -> None:
    request = Mock()
    request.client_host = "1.2.3.4"
    request.query_params = {}
    request.url_path = "/../../etc/passwd"
    request.headers = {}
    request.body = AsyncMock(return_value=b"")

    _dpa = await detect_penetration_attempt(request)

    detected, trigger = _dpa.is_threat, _dpa.trigger_info

    assert detected is True
    assert "URL path" in trigger


def test_is_referrer_domain_allowed_with_none() -> None:
    not_a_string: Any = None
    result = is_referrer_domain_allowed(not_a_string, ["example.com"])
    assert result is False


def test_is_referrer_domain_allowed_with_invalid_type() -> None:
    not_a_string: Any = 12345
    result = is_referrer_domain_allowed(not_a_string, ["example.com"])
    assert result is False


def test_is_referrer_domain_allowed_with_malformed_url() -> None:
    result = is_referrer_domain_allowed("://no-scheme", ["example.com"])
    assert result is False
