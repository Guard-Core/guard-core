from unittest.mock import AsyncMock, Mock, patch

import pytest

from guard_core.core.checks.implementations.authentication import AuthenticationCheck
from guard_core.core.checks.implementations.emergency_mode import EmergencyModeCheck
from guard_core.core.checks.implementations.https_enforcement import (
    HttpsEnforcementCheck,
)
from guard_core.core.checks.implementations.referrer import ReferrerCheck
from guard_core.core.checks.implementations.request_size_content import (
    RequestSizeContentCheck,
)
from guard_core.core.checks.implementations.required_headers import RequiredHeadersCheck
from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.decorators.base import RouteConfig
from guard_core.detection_result import DetectionResult
from guard_core.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    config = SecurityConfig()
    config.enforce_https = True
    config.trust_x_forwarded_proto = True
    config.trusted_proxies = ("192.168.1.0/24", "10.0.0.1")
    return config


@pytest.fixture
def mock_middleware(security_config: SecurityConfig) -> Mock:
    middleware = Mock()
    middleware.config = security_config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_https_violation_event = AsyncMock()
    middleware.response_factory = Mock()
    middleware.response_factory.create_https_redirect = AsyncMock(
        return_value=Mock(status_code=301)
    )
    return middleware


@pytest.fixture
def https_check(mock_middleware: Mock) -> HttpsEnforcementCheck:
    return HttpsEnforcementCheck(mock_middleware)


def test_is_trusted_proxy_cidr_match(
    https_check: HttpsEnforcementCheck,
) -> None:
    result = https_check._is_trusted_proxy("192.168.1.100")
    assert result is True


def test_is_trusted_proxy_cidr_no_match(
    https_check: HttpsEnforcementCheck,
) -> None:
    result = https_check._is_trusted_proxy("172.16.0.1")
    assert result is False


def test_is_trusted_proxy_single_ip_no_match(
    https_check: HttpsEnforcementCheck,
) -> None:
    result = https_check._is_trusted_proxy("10.0.0.2")
    assert result is False


async def test_check_passive_mode_no_redirect(
    https_check: HttpsEnforcementCheck, security_config: SecurityConfig
) -> None:
    security_config.passive_mode = True

    request = Mock()
    request.url_scheme = "http"
    request.client_host = "1.2.3.4"
    request.headers = {}
    request.state = Mock()
    request.state.route_config = None

    result = await https_check.check(request)
    assert result is None


async def test_check_with_cidr_trusted_proxy_https_forwarded(
    https_check: HttpsEnforcementCheck,
) -> None:
    request = Mock()
    request.url_scheme = "http"
    request.client_host = "192.168.1.50"
    request.headers = {"X-Forwarded-Proto": "https"}
    request.state = Mock()
    request.state.route_config = None

    result = await https_check.check(request)
    assert result is None


@pytest.mark.parametrize(
    "connecting_ip,expected",
    [
        ("192.168.1.1", True),
        ("192.168.1.255", True),
        ("192.168.2.1", False),
        ("10.0.0.1", True),
        ("10.0.0.2", False),
        ("8.8.8.8", False),
    ],
)
def test_is_trusted_proxy_various_ips(
    https_check: HttpsEnforcementCheck, connecting_ip: str, expected: bool
) -> None:
    result = https_check._is_trusted_proxy(connecting_ip)
    assert result == expected


async def test_handle_missing_referrer_passive_mode_unit() -> None:
    config = SecurityConfig()
    config.passive_mode = True

    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()

    check = ReferrerCheck(middleware)
    route_config = RouteConfig()
    route_config.require_referrer = ["example.com"]

    request = Mock()
    request.state = Mock()

    with patch(
        "guard_core.core.checks.implementations.referrer.log_activity",
        return_value=AsyncMock(),
    ):
        result = await check._handle_missing_referrer(request, route_config)
        assert result is None


async def test_handle_invalid_referrer_passive_mode_unit() -> None:
    config = SecurityConfig()
    config.passive_mode = True

    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()

    check = ReferrerCheck(middleware)
    route_config = RouteConfig()
    route_config.require_referrer = ["example.com"]

    request = Mock()
    request.state = Mock()

    with patch(
        "guard_core.core.checks.implementations.referrer.log_activity",
        return_value=AsyncMock(),
    ):
        result = await check._handle_invalid_referrer(
            request, "https://evil.com", route_config
        )
        assert result is None


async def test_authentication_check_passive_mode_unit() -> None:
    config = SecurityConfig()
    config.passive_mode = True

    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()

    check = AuthenticationCheck(middleware)
    route_config = RouteConfig()
    route_config.auth_required = "bearer"

    request = Mock()
    request.state = Mock()
    request.state.route_config = route_config
    request.headers = {}

    with patch(
        "guard_core.core.checks.implementations.authentication.log_activity",
        return_value=AsyncMock(),
    ):
        result = await check.check(request)
        assert result is None


async def test_emergency_mode_check_no_client_ip_extracts_unit() -> None:
    config = SecurityConfig()
    config.emergency_mode = True
    config.emergency_whitelist = ["192.168.1.1"]

    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.agent_handler = None
    middleware.create_error_response = AsyncMock(
        return_value=Mock(status_code=503, headers={})
    )

    check = EmergencyModeCheck(middleware)

    request = Mock()
    request.state = Mock()
    request.state.client_ip = None

    with patch(
        "guard_core.core.checks.implementations.emergency_mode.extract_client_ip",
        return_value="8.8.8.8",
    ):
        with patch(
            "guard_core.core.checks.implementations.emergency_mode.log_activity",
            return_value=AsyncMock(),
        ):
            result = await check.check(request)
            assert result is not None


async def test_emergency_mode_check_passive_mode_unit() -> None:
    config = SecurityConfig()
    config.passive_mode = True
    config.emergency_mode = True

    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()

    check = EmergencyModeCheck(middleware)

    request = Mock()
    request.state = Mock()
    request.state.client_ip = "8.8.8.8"

    with patch(
        "guard_core.core.checks.implementations.emergency_mode.log_activity",
        return_value=AsyncMock(),
    ):
        result = await check.check(request)
        assert result is None


async def test_check_request_size_limit_passive_mode_unit() -> None:
    config = SecurityConfig()
    config.passive_mode = True

    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()

    check = RequestSizeContentCheck(middleware)
    route_config = RouteConfig()
    route_config.max_request_size = 100

    request = Mock()
    request.state = Mock()
    request.headers = {"content-length": "1000"}

    with patch(
        "guard_core.core.checks.implementations.request_size_content.log_activity",
        return_value=AsyncMock(),
    ):
        result = await check._check_request_size_limit(request, route_config)
        assert result is None


async def test_check_content_type_allowed_passive_mode_unit() -> None:
    config = SecurityConfig()
    config.passive_mode = True

    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()

    check = RequestSizeContentCheck(middleware)
    route_config = RouteConfig()
    route_config.allowed_content_types = ["application/json"]

    request = Mock()
    request.state = Mock()
    request.headers = {"content-type": "text/html"}

    with patch(
        "guard_core.core.checks.implementations.request_size_content.log_activity",
        return_value=AsyncMock(),
    ):
        result = await check._check_content_type_allowed(request, route_config)
        assert result is None


async def test_required_headers_check_passive_mode_unit() -> None:
    config = SecurityConfig()
    config.passive_mode = True

    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()

    check = RequiredHeadersCheck(middleware)
    route_config = RouteConfig()
    route_config.required_headers = {"X-API-Key": "required"}

    request = Mock()
    request.state = Mock()
    request.state.route_config = route_config
    request.headers = {}

    with patch(
        "guard_core.core.checks.implementations.required_headers.log_activity",
        return_value=AsyncMock(),
    ):
        result = await check.check(request)
        assert result is None


async def test_suspicious_activity_check_no_client_ip_unit() -> None:
    config = SecurityConfig()
    config.passive_mode = False
    config.enable_penetration_detection = True

    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)

    check = SuspiciousActivityCheck(middleware)

    request = Mock()
    request.state = Mock()
    request.state.route_config = None
    request.state.client_ip = None
    request.state.is_whitelisted = False

    result = await check.check(request)
    assert result is None


async def test_suspicious_activity_check_passive_mode_unit() -> None:
    config = SecurityConfig()
    config.passive_mode = True
    config.enable_penetration_detection = True

    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.suspicious_request_counts = {}

    check = SuspiciousActivityCheck(middleware)

    request = Mock()
    request.state = Mock()
    request.state.route_config = None
    request.state.client_ip = "1.2.3.4"
    request.state.is_whitelisted = False

    with patch(
        "guard_core.core.checks.implementations.suspicious_activity.get_cached_detection_result",
        return_value=DetectionResult(is_threat=True, trigger_info="SQL injection"),
    ):
        with patch(
            "guard_core.core.checks.implementations.suspicious_activity.log_activity",
            return_value=AsyncMock(),
        ):
            result = await check.check(request)
            assert result is None
            assert middleware.suspicious_request_counts == {}
