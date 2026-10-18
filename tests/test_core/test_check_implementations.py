from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from guard_core.core.checks.implementations.authentication import AuthenticationCheck
from guard_core.core.checks.implementations.cloud_ip_refresh import CloudIpRefreshCheck
from guard_core.core.checks.implementations.cloud_provider import CloudProviderCheck
from guard_core.core.checks.implementations.custom_request import CustomRequestCheck
from guard_core.core.checks.implementations.custom_validators import (
    CustomValidatorsCheck,
)
from guard_core.core.checks.implementations.emergency_mode import EmergencyModeCheck
from guard_core.core.checks.implementations.https_enforcement import (
    HttpsEnforcementCheck,
)
from guard_core.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.core.checks.implementations.referrer import ReferrerCheck
from guard_core.core.checks.implementations.request_logging import RequestLoggingCheck
from guard_core.core.checks.implementations.request_size_content import (
    RequestSizeContentCheck,
)
from guard_core.core.checks.implementations.required_headers import (
    RequiredHeadersCheck,
)
from guard_core.core.checks.implementations.route_config import RouteConfigCheck
from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.core.checks.implementations.time_window import TimeWindowCheck
from guard_core.core.checks.implementations.user_agent import UserAgentCheck
from guard_core.core.events.event_types import EVENT_ROUTE_UNRESOLVED
from guard_core.decorators.base import RouteConfig
from guard_core.detection_result import DetectionResult
from guard_core.handlers.ratelimit_handler import RateLimitBlock
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import IpAccessResult
from tests.conftest import MockGuardRequest, MockGuardResponse

_IMPL = "guard_core.core.checks.implementations"


def _make_middleware(
    passive_mode: bool = False,
    **config_overrides: object,
) -> MagicMock:
    mw = MagicMock()
    config = SecurityConfig(
        enable_redis=False,
        passive_mode=passive_mode,
        **config_overrides,
    )
    mw.config = config
    mw.logger = MagicMock()
    mw.event_bus = MagicMock()
    mw.event_bus.send_middleware_event = AsyncMock()
    mw.event_bus.send_https_violation_event = AsyncMock()
    mw.event_bus.send_cloud_detection_events = AsyncMock()
    mw.create_error_response = AsyncMock(return_value=MockGuardResponse("error", 403))
    mw.response_factory = MagicMock()
    mw.response_factory.apply_modifier = AsyncMock(side_effect=lambda r: r)
    mw.response_factory.create_https_redirect = AsyncMock(
        return_value=MockGuardResponse("redirect", 301, {"Location": "https://test/"})
    )
    mw.route_resolver = MagicMock()
    mw.route_resolver.should_bypass_check = MagicMock(return_value=False)
    mw.route_resolver.get_cloud_providers_to_check = MagicMock(return_value=[])
    mw.route_resolver.get_route_config = MagicMock(return_value=None)
    mw.geo_ip_handler = None
    mw.agent_handler = None
    mw.rate_limit_handler = MagicMock()
    mw.rate_limit_handler.report_rate_limit_block = AsyncMock()
    mw.rate_limit_handler.check_rate_limit_tiers = AsyncMock(return_value=None)
    mw.suspicious_request_counts = {}
    mw.last_cloud_ip_refresh = 0
    mw.refresh_cloud_ip_ranges = AsyncMock()
    return mw


def _make_request_with_route_config(
    route_config: RouteConfig, **kwargs: Any
) -> MockGuardRequest:
    req = MockGuardRequest(**kwargs)
    req.state.route_config = route_config
    return req


async def test_route_config_check_name() -> None:
    mw = _make_middleware()
    check = RouteConfigCheck(mw)
    assert check.check_name == "route_config"


async def test_route_config_check_sets_state() -> None:
    mw = _make_middleware()
    rc = RouteConfig()
    mw.route_resolver.get_route_config = MagicMock(return_value=rc)
    check = RouteConfigCheck(mw)
    req = MockGuardRequest()
    with patch(
        f"{_IMPL}.route_config.extract_client_ip",
        new_callable=AsyncMock,
        return_value="1.2.3.4",
    ):
        result = await check.check(req)
    assert result is None
    assert req.state.route_config is rc
    assert req.state.client_ip == "1.2.3.4"


async def _run_route_config_check(
    mw: MagicMock, req: MockGuardRequest
) -> GuardResponse | None:
    check = RouteConfigCheck(mw)
    with (
        patch(
            f"{_IMPL}.route_config.extract_client_ip",
            new_callable=AsyncMock,
            return_value="1.2.3.4",
        ),
        patch(f"{_IMPL}.route_config.log_activity", new_callable=AsyncMock),
    ):
        return await check.check(req)


async def test_route_config_unresolved_route_allowed_by_default() -> None:
    mw = _make_middleware()
    req = MockGuardRequest()
    req.state.guard_route_unresolved = True

    assert await _run_route_config_check(mw, req) is None
    mw.event_bus.send_middleware_event.assert_not_awaited()


async def test_route_config_unresolved_route_blocked_when_strict() -> None:
    mw = _make_middleware(route_resolution_strict=True)
    mw.create_error_response = AsyncMock(
        return_value=MockGuardResponse("unresolved", 500)
    )
    req = MockGuardRequest()
    req.state.guard_route_unresolved = True

    result = await _run_route_config_check(mw, req)

    assert result is not None
    assert result.status_code == 500
    assert (
        mw.event_bus.send_middleware_event.await_args.kwargs["event_type"]
        == EVENT_ROUTE_UNRESOLVED
    )


async def test_route_config_undecorated_route_allowed_when_strict() -> None:
    mw = _make_middleware(route_resolution_strict=True)
    req = MockGuardRequest()

    assert await _run_route_config_check(mw, req) is None
    mw.event_bus.send_middleware_event.assert_not_awaited()


async def test_route_config_unresolved_route_logged_only_in_passive_mode() -> None:
    mw = _make_middleware(passive_mode=True, route_resolution_strict=True)
    req = MockGuardRequest()
    req.state.guard_route_unresolved = True

    assert await _run_route_config_check(mw, req) is None
    assert (
        mw.event_bus.send_middleware_event.await_args.kwargs["action_taken"]
        == "logged_only"
    )


async def test_emergency_mode_check_name() -> None:
    mw = _make_middleware()
    check = EmergencyModeCheck(mw)
    assert check.check_name == "emergency_mode"


async def test_emergency_mode_disabled() -> None:
    mw = _make_middleware()
    check = EmergencyModeCheck(mw)
    req = MockGuardRequest()
    result = await check.check(req)
    assert result is None


async def test_emergency_mode_blocks_non_whitelisted() -> None:
    mw = _make_middleware(emergency_mode=True, emergency_whitelist=["10.0.0.1"])
    mw.create_error_response = AsyncMock(
        return_value=MockGuardResponse("unavailable", 503)
    )
    check = EmergencyModeCheck(mw)
    req = MockGuardRequest(client_host="192.168.1.1")
    req.state.client_ip = "192.168.1.1"
    with patch(f"{_IMPL}.emergency_mode.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is not None
    assert result.status_code == 503


async def test_emergency_mode_allows_whitelisted() -> None:
    mw = _make_middleware(emergency_mode=True, emergency_whitelist=["10.0.0.1"])
    check = EmergencyModeCheck(mw)
    req = MockGuardRequest(client_host="10.0.0.1")
    req.state.client_ip = "10.0.0.1"
    with patch(f"{_IMPL}.emergency_mode.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is None


async def test_emergency_mode_extracts_ip_if_missing() -> None:
    mw = _make_middleware(emergency_mode=True, emergency_whitelist=[])
    mw.create_error_response = AsyncMock(return_value=MockGuardResponse("err", 503))
    check = EmergencyModeCheck(mw)
    req = MockGuardRequest()
    with patch(
        f"{_IMPL}.emergency_mode.extract_client_ip",
        new_callable=AsyncMock,
        return_value="5.5.5.5",
    ):
        with patch(f"{_IMPL}.emergency_mode.log_activity", new_callable=AsyncMock):
            result = await check.check(req)
    assert result is not None


async def test_https_enforcement_check_name() -> None:
    mw = _make_middleware()
    check = HttpsEnforcementCheck(mw)
    assert check.check_name == "https_enforcement"


async def test_https_enforcement_not_required() -> None:
    mw = _make_middleware()
    check = HttpsEnforcementCheck(mw)
    req = MockGuardRequest(scheme="http")
    result = await check.check(req)
    assert result is None


async def test_https_enforcement_already_https() -> None:
    mw = _make_middleware(enforce_https=True)
    check = HttpsEnforcementCheck(mw)
    req = MockGuardRequest(scheme="https")
    result = await check.check(req)
    assert result is None


async def test_https_enforcement_redirects_http() -> None:
    mw = _make_middleware(enforce_https=True)
    check = HttpsEnforcementCheck(mw)
    req = MockGuardRequest(scheme="http")
    result = await check.check(req)
    assert result is not None
    assert result.status_code == 301


async def test_https_enforcement_passive_mode() -> None:
    mw = _make_middleware(enforce_https=True, passive_mode=True)
    check = HttpsEnforcementCheck(mw)
    req = MockGuardRequest(scheme="http")
    result = await check.check(req)
    assert result is None


async def test_https_enforcement_route_config_override() -> None:
    mw = _make_middleware()
    check = HttpsEnforcementCheck(mw)
    rc = RouteConfig()
    rc.require_https = True
    req = _make_request_with_route_config(rc, scheme="http")
    result = await check.check(req)
    assert result is not None


async def test_https_enforcement_trusted_proxy() -> None:
    mw = _make_middleware(
        enforce_https=True,
        trust_x_forwarded_proto=True,
        trusted_proxies=["127.0.0.1"],
    )
    check = HttpsEnforcementCheck(mw)
    req = MockGuardRequest(
        scheme="http",
        client_host="127.0.0.1",
        headers={"X-Forwarded-Proto": "https"},
    )
    result = await check.check(req)
    assert result is None


async def test_https_enforcement_trusted_proxy_cidr() -> None:
    mw = _make_middleware(
        enforce_https=True,
        trust_x_forwarded_proto=True,
        trusted_proxies=["10.0.0.0/8"],
    )
    check = HttpsEnforcementCheck(mw)
    req = MockGuardRequest(
        scheme="http",
        client_host="10.1.2.3",
        headers={"X-Forwarded-Proto": "https"},
    )
    result = await check.check(req)
    assert result is None


async def test_request_logging_check_name() -> None:
    mw = _make_middleware()
    check = RequestLoggingCheck(mw)
    assert check.check_name == "request_logging"


async def test_request_logging_check() -> None:
    mw = _make_middleware()
    check = RequestLoggingCheck(mw)
    req = MockGuardRequest()
    with patch(f"{_IMPL}.request_logging.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is None


async def test_request_size_content_check_name() -> None:
    mw = _make_middleware()
    check = RequestSizeContentCheck(mw)
    assert check.check_name == "request_size_content"


async def test_request_size_content_no_route_config() -> None:
    mw = _make_middleware()
    check = RequestSizeContentCheck(mw)
    req = MockGuardRequest()
    result = await check.check(req)
    assert result is None


async def test_request_size_content_no_limit() -> None:
    mw = _make_middleware()
    check = RequestSizeContentCheck(mw)
    rc = RouteConfig()
    req = _make_request_with_route_config(rc)
    result = await check.check(req)
    assert result is None


async def test_request_size_content_exceeds_limit() -> None:
    mw = _make_middleware()
    mw.create_error_response = AsyncMock(return_value=MockGuardResponse("large", 413))
    check = RequestSizeContentCheck(mw)
    rc = RouteConfig()
    rc.max_request_size = 100
    req = _make_request_with_route_config(rc, headers={"content-length": "200"})
    with patch(f"{_IMPL}.request_size_content.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is not None
    assert result.status_code == 413


async def test_request_size_content_within_limit() -> None:
    mw = _make_middleware()
    check = RequestSizeContentCheck(mw)
    rc = RouteConfig()
    rc.max_request_size = 1000
    req = _make_request_with_route_config(rc, headers={"content-length": "50"})
    result = await check.check(req)
    assert result is None


async def test_request_size_content_no_content_length() -> None:
    mw = _make_middleware()
    check = RequestSizeContentCheck(mw)
    rc = RouteConfig()
    rc.max_request_size = 100
    req = _make_request_with_route_config(rc)
    result = await check.check(req)
    assert result is None


async def test_request_size_content_type_blocked() -> None:
    mw = _make_middleware()
    mw.create_error_response = AsyncMock(
        return_value=MockGuardResponse("bad type", 415)
    )
    check = RequestSizeContentCheck(mw)
    rc = RouteConfig()
    rc.allowed_content_types = ["application/json"]
    req = _make_request_with_route_config(rc, headers={"content-type": "text/html"})
    with patch(f"{_IMPL}.request_size_content.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is not None
    assert result.status_code == 415


async def test_request_size_content_type_allowed() -> None:
    mw = _make_middleware()
    check = RequestSizeContentCheck(mw)
    rc = RouteConfig()
    rc.allowed_content_types = ["application/json"]
    req = _make_request_with_route_config(
        rc, headers={"content-type": "application/json; charset=utf-8"}
    )
    result = await check.check(req)
    assert result is None


async def test_request_size_passive_mode() -> None:
    mw = _make_middleware(passive_mode=True)
    check = RequestSizeContentCheck(mw)
    rc = RouteConfig()
    rc.max_request_size = 100
    req = _make_request_with_route_config(rc, headers={"content-length": "200"})
    with patch(f"{_IMPL}.request_size_content.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is None


async def test_request_content_type_passive_mode() -> None:
    mw = _make_middleware(passive_mode=True)
    check = RequestSizeContentCheck(mw)
    rc = RouteConfig()
    rc.allowed_content_types = ["application/json"]
    req = _make_request_with_route_config(rc, headers={"content-type": "text/html"})
    with patch(f"{_IMPL}.request_size_content.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is None


async def test_required_headers_check_name() -> None:
    mw = _make_middleware()
    check = RequiredHeadersCheck(mw)
    assert check.check_name == "required_headers"


async def test_required_headers_no_route_config() -> None:
    mw = _make_middleware()
    check = RequiredHeadersCheck(mw)
    req = MockGuardRequest()
    result = await check.check(req)
    assert result is None


async def test_required_headers_missing() -> None:
    mw = _make_middleware()
    mw.create_error_response = AsyncMock(return_value=MockGuardResponse("missing", 400))
    check = RequiredHeadersCheck(mw)
    rc = RouteConfig()
    rc.required_headers = {"X-API-Key": "required"}
    req = _make_request_with_route_config(rc)
    with patch(f"{_IMPL}.required_headers.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is not None
    assert result.status_code == 400


async def test_required_headers_present() -> None:
    mw = _make_middleware()
    check = RequiredHeadersCheck(mw)
    rc = RouteConfig()
    rc.required_headers = {"X-API-Key": "required"}
    req = _make_request_with_route_config(rc, headers={"X-API-Key": "mykey"})
    result = await check.check(req)
    assert result is None


async def test_required_headers_authorization_classification() -> None:
    mw = _make_middleware()
    mw.create_error_response = AsyncMock(return_value=MockGuardResponse("missing", 400))
    check = RequiredHeadersCheck(mw)
    rc = RouteConfig()
    rc.required_headers = {"authorization": "required"}
    req = _make_request_with_route_config(rc)
    with patch(f"{_IMPL}.required_headers.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is not None


async def test_required_headers_generic_classification() -> None:
    mw = _make_middleware()
    mw.create_error_response = AsyncMock(return_value=MockGuardResponse("missing", 400))
    check = RequiredHeadersCheck(mw)
    rc = RouteConfig()
    rc.required_headers = {"X-Custom": "required"}
    req = _make_request_with_route_config(rc)
    with patch(f"{_IMPL}.required_headers.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is not None


async def test_required_headers_passive_mode() -> None:
    mw = _make_middleware(passive_mode=True)
    check = RequiredHeadersCheck(mw)
    rc = RouteConfig()
    rc.required_headers = {"X-API-Key": "required"}
    req = _make_request_with_route_config(rc)
    with patch(f"{_IMPL}.required_headers.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is None


async def test_required_headers_empty_configured_dict_is_noop() -> None:
    mw = _make_middleware()
    check = RequiredHeadersCheck(mw)
    rc = RouteConfig()
    rc.required_headers = {}
    req = _make_request_with_route_config(rc)
    result = await check.check(req)
    assert result is None


async def test_required_headers_matching_literal_value() -> None:
    mw = _make_middleware()
    check = RequiredHeadersCheck(mw)
    rc = RouteConfig()
    rc.required_headers = {"X-Custom": "expected-value"}
    req = _make_request_with_route_config(rc, headers={"X-Custom": "expected-value"})
    result = await check.check(req)
    assert result is None


async def test_required_headers_mismatched_literal_value_is_blocked() -> None:
    mw = _make_middleware()
    mw.create_error_response = AsyncMock(
        return_value=MockGuardResponse("mismatch", 400)
    )
    check = RequiredHeadersCheck(mw)
    rc = RouteConfig()
    rc.required_headers = {"X-Custom": "expected-value"}
    req = _make_request_with_route_config(rc, headers={"X-Custom": "wrong-value"})
    with patch(f"{_IMPL}.required_headers.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is not None
    assert result.status_code == 400


async def test_required_headers_mismatch_reason_does_not_leak_values() -> None:
    mw = _make_middleware()
    mw.create_error_response = AsyncMock(
        return_value=MockGuardResponse("mismatch", 400)
    )
    check = RequiredHeadersCheck(mw)
    rc = RouteConfig()
    rc.required_headers = {"X-Custom": "super-secret-expected"}
    req = _make_request_with_route_config(
        rc, headers={"X-Custom": "super-secret-received"}
    )
    with patch(
        f"{_IMPL}.required_headers.log_activity", new_callable=AsyncMock
    ) as log_mock:
        await check.check(req)
    body = mw.create_error_response.call_args.kwargs["default_message"]
    assert body == "Bad request"
    reason = log_mock.call_args.kwargs["reason"]
    assert reason == "Header 'X-Custom' does not match the required value"
    assert "super-secret-expected" not in reason
    assert "super-secret-received" not in reason


async def test_required_headers_mismatch_passive_mode_does_not_block() -> None:
    mw = _make_middleware(passive_mode=True)
    check = RequiredHeadersCheck(mw)
    rc = RouteConfig()
    rc.required_headers = {"X-Custom": "expected-value"}
    req = _make_request_with_route_config(rc, headers={"X-Custom": "wrong-value"})
    with patch(f"{_IMPL}.required_headers.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is None


async def test_authentication_check_name() -> None:
    mw = _make_middleware()
    check = AuthenticationCheck(mw)
    assert check.check_name == "authentication"


async def test_authentication_no_route_config() -> None:
    mw = _make_middleware()
    check = AuthenticationCheck(mw)
    req = MockGuardRequest()
    result = await check.check(req)
    assert result is None


async def test_authentication_no_auth_required() -> None:
    mw = _make_middleware()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    req = _make_request_with_route_config(rc)
    result = await check.check(req)
    assert result is None


def _approve(request: object, credential: str) -> dict[str, str]:
    return {"user": "test"}


async def test_authentication_bearer_valid() -> None:
    mw = _make_middleware()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "bearer"
    rc.auth_verifier = _approve
    req = _make_request_with_route_config(
        rc, headers={"authorization": "Bearer token123"}
    )
    result = await check.check(req)
    assert result is None


async def test_authentication_bearer_invalid() -> None:
    mw = _make_middleware()
    mw.create_error_response = AsyncMock(return_value=MockGuardResponse("unauth", 401))
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "bearer"
    req = _make_request_with_route_config(rc, headers={"authorization": "Basic creds"})
    with patch(f"{_IMPL}.authentication.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is not None
    assert result.status_code == 401


async def test_authentication_basic_valid() -> None:
    mw = _make_middleware()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "basic"
    rc.auth_verifier = _approve
    req = _make_request_with_route_config(
        rc, headers={"authorization": "Basic dXNlcjpwYXNz"}
    )
    result = await check.check(req)
    assert result is None


async def test_authentication_basic_invalid() -> None:
    mw = _make_middleware()
    mw.create_error_response = AsyncMock(return_value=MockGuardResponse("unauth", 401))
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "basic"
    req = _make_request_with_route_config(rc, headers={"authorization": "Bearer token"})
    with patch(f"{_IMPL}.authentication.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is not None


async def test_authentication_passive_mode() -> None:
    mw = _make_middleware(passive_mode=True)
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "bearer"
    req = _make_request_with_route_config(rc, headers={"authorization": "invalid"})
    with patch(f"{_IMPL}.authentication.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is None


async def test_authentication_custom_type_missing() -> None:
    mw = _make_middleware()
    mw.create_error_response = AsyncMock(return_value=MockGuardResponse("unauth", 401))
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "custom"
    req = _make_request_with_route_config(rc, headers={"authorization": ""})
    with patch(f"{_IMPL}.authentication.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is not None


async def test_referrer_check_name() -> None:
    mw = _make_middleware()
    check = ReferrerCheck(mw)
    assert check.check_name == "referrer"


async def test_referrer_no_route_config() -> None:
    mw = _make_middleware()
    check = ReferrerCheck(mw)
    req = MockGuardRequest()
    result = await check.check(req)
    assert result is None


async def test_referrer_not_required() -> None:
    mw = _make_middleware()
    check = ReferrerCheck(mw)
    rc = RouteConfig()
    req = _make_request_with_route_config(rc)
    result = await check.check(req)
    assert result is None


async def test_referrer_missing() -> None:
    mw = _make_middleware()
    mw.create_error_response = AsyncMock(return_value=MockGuardResponse("no ref", 403))
    check = ReferrerCheck(mw)
    rc = RouteConfig()
    rc.require_referrer = ["example.com"]
    req = _make_request_with_route_config(rc)
    with patch(f"{_IMPL}.referrer.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is not None
    assert result.status_code == 403


async def test_referrer_invalid_domain() -> None:
    mw = _make_middleware()
    mw.create_error_response = AsyncMock(return_value=MockGuardResponse("bad ref", 403))
    check = ReferrerCheck(mw)
    rc = RouteConfig()
    rc.require_referrer = ["example.com"]
    req = _make_request_with_route_config(
        rc, headers={"referer": "https://evil.com/page"}
    )
    with patch(f"{_IMPL}.referrer.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is not None


async def test_referrer_valid_domain() -> None:
    mw = _make_middleware()
    check = ReferrerCheck(mw)
    rc = RouteConfig()
    rc.require_referrer = ["example.com"]
    req = _make_request_with_route_config(
        rc, headers={"referer": "https://example.com/page"}
    )
    result = await check.check(req)
    assert result is None


async def test_referrer_passive_mode_missing() -> None:
    mw = _make_middleware(passive_mode=True)
    check = ReferrerCheck(mw)
    rc = RouteConfig()
    rc.require_referrer = ["example.com"]
    req = _make_request_with_route_config(rc)
    with patch(f"{_IMPL}.referrer.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is None


async def test_referrer_passive_mode_invalid() -> None:
    mw = _make_middleware(passive_mode=True)
    check = ReferrerCheck(mw)
    rc = RouteConfig()
    rc.require_referrer = ["example.com"]
    req = _make_request_with_route_config(rc, headers={"referer": "https://evil.com/"})
    with patch(f"{_IMPL}.referrer.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is None


async def test_custom_validators_check_name() -> None:
    mw = _make_middleware()
    check = CustomValidatorsCheck(mw)
    assert check.check_name == "custom_validators"


async def test_custom_validators_no_route_config() -> None:
    mw = _make_middleware()
    check = CustomValidatorsCheck(mw)
    req = MockGuardRequest()
    result = await check.check(req)
    assert result is None


async def test_custom_validators_passes() -> None:
    mw = _make_middleware()
    check = CustomValidatorsCheck(mw)
    rc = RouteConfig()
    rc.custom_validators = [AsyncMock(return_value=None)]
    req = _make_request_with_route_config(rc)
    result = await check.check(req)
    assert result is None


async def test_custom_validators_blocks() -> None:
    mw = _make_middleware()
    blocked_resp = MockGuardResponse("blocked", 403)
    check = CustomValidatorsCheck(mw)
    rc = RouteConfig()
    rc.custom_validators = [AsyncMock(return_value=blocked_resp)]
    req = _make_request_with_route_config(rc)
    with patch(f"{_IMPL}.custom_validators.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is not None
    assert result.status_code == 403


async def test_custom_validators_passive_mode() -> None:
    mw = _make_middleware(passive_mode=True)
    blocked_resp = MockGuardResponse("blocked", 403)
    check = CustomValidatorsCheck(mw)
    rc = RouteConfig()
    rc.custom_validators = [AsyncMock(return_value=blocked_resp)]
    req = _make_request_with_route_config(rc)
    with patch(f"{_IMPL}.custom_validators.log_activity", new_callable=AsyncMock):
        result = await check.check(req)
    assert result is None


async def test_time_window_check_name() -> None:
    mw = _make_middleware()
    check = TimeWindowCheck(mw)
    assert check.check_name == "time_window"


async def test_time_window_no_route_config() -> None:
    mw = _make_middleware()
    check = TimeWindowCheck(mw)
    req = MockGuardRequest()
    result = await check.check(req)
    assert result is None


async def test_time_window_allowed() -> None:
    mw = _make_middleware()
    check = TimeWindowCheck(mw)
    rc = RouteConfig()
    rc.time_restrictions = {"start": "00:00", "end": "23:59", "timezone": "UTC"}
    req = _make_request_with_route_config(rc)
    result = await check.check(req)
    assert result is None


async def test_time_window_blocked() -> None:
    mw = _make_middleware()
    mw.create_error_response = AsyncMock(return_value=MockGuardResponse("denied", 403))
    check = TimeWindowCheck(mw)
    rc = RouteConfig()
    rc.time_restrictions = {"start": "00:00", "end": "00:01", "timezone": "UTC"}
    req = _make_request_with_route_config(rc)

    with patch.object(
        check,
        "_check_time_window",
        new_callable=AsyncMock,
        return_value=False,
    ):
        with patch(
            f"{_IMPL}.time_window.log_activity",
            new_callable=AsyncMock,
        ):
            result = await check.check(req)
    assert result is not None
    assert result.status_code == 403


async def test_time_window_passive_mode() -> None:
    mw = _make_middleware(passive_mode=True)
    check = TimeWindowCheck(mw)
    rc = RouteConfig()
    rc.time_restrictions = {
        "start": "00:00",
        "end": "00:01",
        "timezone": "UTC",
    }
    req = _make_request_with_route_config(rc)

    with patch.object(
        check,
        "_check_time_window",
        new_callable=AsyncMock,
        return_value=False,
    ):
        with patch(
            f"{_IMPL}.time_window.log_activity",
            new_callable=AsyncMock,
        ):
            result = await check.check(req)
    assert result is None


async def test_time_window_overnight() -> None:
    mw = _make_middleware()
    check = TimeWindowCheck(mw)
    tw = {"start": "22:00", "end": "06:00", "timezone": "UTC"}
    result = await check._check_time_window(tw)
    assert isinstance(result, bool)


async def test_time_window_invalid_timezone() -> None:
    mw = _make_middleware()
    check = TimeWindowCheck(mw)
    tw = {
        "start": "00:00",
        "end": "23:59",
        "timezone": "Invalid/Zone",
    }
    result = await check._check_time_window(tw)
    assert isinstance(result, bool)


async def test_time_window_error_handling() -> None:
    mw = _make_middleware()
    check = TimeWindowCheck(mw)
    result = await check._check_time_window({})
    assert result is True


async def test_cloud_ip_refresh_check_name() -> None:
    mw = _make_middleware()
    check = CloudIpRefreshCheck(mw)
    assert check.check_name == "cloud_ip_refresh"


async def test_cloud_ip_refresh_no_block() -> None:
    mw = _make_middleware()
    check = CloudIpRefreshCheck(mw)
    req = MockGuardRequest()
    result = await check.check(req)
    assert result is None


async def test_cloud_ip_refresh_triggers() -> None:
    from guard_core.handlers.cloud_handler import cloud_handler

    mw = _make_middleware()
    mw.config.block_cloud_providers = {"AWS"}
    mw.config.cloud_ip_refresh_interval = 1
    mw.last_cloud_ip_refresh = 0
    mw.route_resolver.get_cloud_providers_to_check = MagicMock(return_value=["AWS"])
    check = CloudIpRefreshCheck(mw)
    req = MockGuardRequest()

    with patch.object(
        cloud_handler, "schedule_refresh", new_callable=AsyncMock
    ) as schedule:
        result = await check.check(req)

    assert result is None
    schedule.assert_called_once_with({"AWS"}, ttl=1, refresh=mw.refresh_cloud_ip_ranges)
    assert mw.last_cloud_ip_refresh > 0
    mw.refresh_cloud_ip_ranges.assert_not_called()


async def test_cloud_ip_refresh_triggers_for_route_only_cloud_config() -> None:
    from guard_core.handlers.cloud_handler import cloud_handler

    mw = _make_middleware()
    mw.config.cloud_ip_refresh_interval = 1
    mw.last_cloud_ip_refresh = 0
    mw.route_resolver.get_cloud_providers_to_check = MagicMock(return_value=["GCP"])
    check = CloudIpRefreshCheck(mw)
    req = MockGuardRequest()

    with patch.object(
        cloud_handler, "schedule_refresh", new_callable=AsyncMock
    ) as schedule:
        result = await check.check(req)

    assert result is None
    schedule.assert_called_once_with({"GCP"}, ttl=1, refresh=mw.refresh_cloud_ip_ranges)
    assert mw.last_cloud_ip_refresh > 0


async def test_cloud_provider_check_name() -> None:
    mw = _make_middleware()
    check = CloudProviderCheck(mw)
    assert check.check_name == "cloud_provider"


async def test_cloud_provider_whitelisted() -> None:
    mw = _make_middleware()
    check = CloudProviderCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = True
    result = await check.check(req)
    assert result is None


async def test_cloud_provider_no_client_ip() -> None:
    mw = _make_middleware()
    check = CloudProviderCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = False
    result = await check.check(req)
    assert result is None


async def test_cloud_provider_bypass() -> None:
    mw = _make_middleware()
    mw.route_resolver.should_bypass_check = MagicMock(return_value=True)
    check = CloudProviderCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    result = await check.check(req)
    assert result is None


async def test_cloud_provider_no_providers() -> None:
    mw = _make_middleware()
    mw.route_resolver.get_cloud_providers_to_check = MagicMock(return_value=[])
    check = CloudProviderCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    result = await check.check(req)
    assert result is None


async def test_cloud_provider_blocks() -> None:
    mw = _make_middleware()
    mw.route_resolver.get_cloud_providers_to_check = MagicMock(return_value=["AWS"])
    check = CloudProviderCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    with patch.object(check, "cloud_handler") as mock_ch:
        mock_ch.is_cloud_ip = MagicMock(return_value=True)
        mock_ch.get_cloud_provider_details = MagicMock(return_value=None)
        with patch(f"{_IMPL}.cloud_provider.log_activity", new_callable=AsyncMock):
            result = await check.check(req)
    assert result is not None


async def test_cloud_provider_not_cloud_ip() -> None:
    mw = _make_middleware()
    mw.route_resolver.get_cloud_providers_to_check = MagicMock(return_value=["AWS"])
    check = CloudProviderCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    with patch.object(check, "cloud_handler") as mock_ch:
        mock_ch.is_cloud_ip = MagicMock(return_value=False)
        result = await check.check(req)
    assert result is None


async def test_cloud_provider_passive_mode() -> None:
    mw = _make_middleware(passive_mode=True)
    mw.route_resolver.get_cloud_providers_to_check = MagicMock(return_value=["AWS"])
    check = CloudProviderCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    with patch.object(check, "cloud_handler") as mock_ch:
        mock_ch.is_cloud_ip = MagicMock(return_value=True)
        mock_ch.get_cloud_provider_details = MagicMock(return_value=None)
        with patch(f"{_IMPL}.cloud_provider.log_activity", new_callable=AsyncMock):
            result = await check.check(req)
    assert result is None


async def test_user_agent_check_name() -> None:
    mw = _make_middleware()
    check = UserAgentCheck(mw)
    assert check.check_name == "user_agent"


async def test_user_agent_whitelisted() -> None:
    mw = _make_middleware()
    check = UserAgentCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = True
    result = await check.check(req)
    assert result is None


async def test_user_agent_allowed() -> None:
    mw = _make_middleware()
    check = UserAgentCheck(mw)
    req = MockGuardRequest(headers={"User-Agent": "Mozilla/5.0"})
    req.state.is_whitelisted = False
    with patch(
        f"{_IMPL}.user_agent.check_user_agent_allowed",
        new_callable=AsyncMock,
        return_value=True,
    ):
        result = await check.check(req)
    assert result is None


async def test_user_agent_blocked_global() -> None:
    mw = _make_middleware()
    check = UserAgentCheck(mw)
    req = MockGuardRequest(headers={"User-Agent": "badbot"})
    req.state.is_whitelisted = False
    with patch(
        f"{_IMPL}.user_agent.check_user_agent_allowed",
        new_callable=AsyncMock,
        return_value=False,
    ):
        with patch(f"{_IMPL}.user_agent.log_activity", new_callable=AsyncMock):
            result = await check.check(req)
    assert result is not None


async def test_user_agent_blocked_by_route_decorator() -> None:
    mw = _make_middleware()
    check = UserAgentCheck(mw)
    rc = RouteConfig()
    rc.blocked_user_agents = ["badbot"]
    req = _make_request_with_route_config(rc, headers={"User-Agent": "badbot"})
    req.state.is_whitelisted = False
    with patch(
        f"{_IMPL}.user_agent.check_user_agent_allowed",
        new_callable=AsyncMock,
        return_value=False,
    ):
        with patch(f"{_IMPL}.user_agent.log_activity", new_callable=AsyncMock):
            result = await check.check(req)
    assert result is not None


async def test_user_agent_passive_mode() -> None:
    mw = _make_middleware(passive_mode=True)
    check = UserAgentCheck(mw)
    req = MockGuardRequest(headers={"User-Agent": "badbot"})
    req.state.is_whitelisted = False
    with patch(
        f"{_IMPL}.user_agent.check_user_agent_allowed",
        new_callable=AsyncMock,
        return_value=False,
    ):
        with patch(f"{_IMPL}.user_agent.log_activity", new_callable=AsyncMock):
            result = await check.check(req)
    assert result is None


async def test_ip_security_check_name() -> None:
    mw = _make_middleware()
    check = IpSecurityCheck(mw)
    assert check.check_name == "ip_security"


async def test_ip_security_no_client_ip() -> None:
    mw = _make_middleware()
    check = IpSecurityCheck(mw)
    req = MockGuardRequest()
    result = await check.check(req)
    assert result is None


async def test_ip_security_banned_ip() -> None:
    mw = _make_middleware()
    check = IpSecurityCheck(mw)
    req = MockGuardRequest()
    req.state.client_ip = "1.2.3.4"
    with patch.object(check, "ip_ban_manager") as mock_ban:
        mock_ban.is_ip_banned = AsyncMock(return_value=True)
        with patch(f"{_IMPL}.ip_security.log_activity", new_callable=AsyncMock):
            result = await check.check(req)
    assert result is not None


async def test_ip_security_bypass_ip_check() -> None:
    mw = _make_middleware()
    mw.route_resolver.should_bypass_check = MagicMock(
        side_effect=lambda check, rc: check == "ip"
    )
    check = IpSecurityCheck(mw)
    req = MockGuardRequest()
    req.state.client_ip = "1.2.3.4"
    with patch.object(check, "ip_ban_manager") as mock_ban:
        mock_ban.is_ip_banned = AsyncMock(return_value=False)
        result = await check.check(req)
    assert result is None


async def test_ip_security_route_ip_blocked() -> None:
    mw = _make_middleware()
    mw.route_resolver.should_bypass_check = MagicMock(return_value=False)
    check = IpSecurityCheck(mw)
    rc = RouteConfig()
    rc.ip_blacklist = ["1.2.3.4"]
    req = _make_request_with_route_config(rc)
    req.state.client_ip = "1.2.3.4"
    with patch.object(check, "ip_ban_manager") as mock_ban:
        mock_ban.is_ip_banned = AsyncMock(return_value=False)
        with patch(f"{_IMPL}.ip_security.log_activity", new_callable=AsyncMock):
            result = await check.check(req)
    assert result is not None


async def test_ip_security_route_ip_allowed() -> None:
    mw = _make_middleware()
    mw.route_resolver.should_bypass_check = MagicMock(return_value=False)
    check = IpSecurityCheck(mw)
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]
    req = _make_request_with_route_config(rc)
    req.state.client_ip = "1.2.3.4"
    with patch.object(check, "ip_ban_manager") as mock_ban:
        mock_ban.is_ip_banned = AsyncMock(return_value=False)
        result = await check.check(req)
    assert result is None


async def test_ip_security_global_check() -> None:
    mw = _make_middleware(whitelist=["1.2.3.4"])
    mw.route_resolver.should_bypass_check = MagicMock(return_value=False)
    check = IpSecurityCheck(mw)
    req = MockGuardRequest()
    req.state.client_ip = "1.2.3.4"
    with patch.object(check, "ip_ban_manager") as mock_ban:
        mock_ban.is_ip_banned = AsyncMock(return_value=False)
        with patch(
            f"{_IMPL}.ip_security.check_ip_access",
            new_callable=AsyncMock,
            return_value=IpAccessResult(True, ""),
        ):
            result = await check.check(req)
    assert result is None


async def test_ip_security_global_blocked() -> None:
    mw = _make_middleware()
    mw.route_resolver.should_bypass_check = MagicMock(return_value=False)
    check = IpSecurityCheck(mw)
    req = MockGuardRequest()
    req.state.client_ip = "9.9.9.9"
    with patch.object(check, "ip_ban_manager") as mock_ban:
        mock_ban.is_ip_banned = AsyncMock(return_value=False)
        with patch(
            f"{_IMPL}.ip_security.check_ip_access",
            new_callable=AsyncMock,
            return_value=IpAccessResult(
                False, "IP 9.9.9.9 not in global allowlist/blocklist"
            ),
        ):
            with patch(f"{_IMPL}.ip_security.log_activity", new_callable=AsyncMock):
                result = await check.check(req)
    assert result is not None


async def test_ip_security_passive_mode_banned() -> None:
    mw = _make_middleware(passive_mode=True)
    check = IpSecurityCheck(mw)
    req = MockGuardRequest()
    req.state.client_ip = "1.2.3.4"
    with patch.object(check, "ip_ban_manager") as mock_ban:
        mock_ban.is_ip_banned = AsyncMock(return_value=True)
        with patch(f"{_IMPL}.ip_security.log_activity", new_callable=AsyncMock):
            result = await check.check(req)
    assert result is None


async def test_ip_security_passive_mode_route_blocked() -> None:
    mw = _make_middleware(passive_mode=True)
    mw.route_resolver.should_bypass_check = MagicMock(return_value=False)
    check = IpSecurityCheck(mw)
    rc = RouteConfig()
    rc.ip_blacklist = ["1.2.3.4"]
    req = _make_request_with_route_config(rc)
    req.state.client_ip = "1.2.3.4"
    with patch.object(check, "ip_ban_manager") as mock_ban:
        mock_ban.is_ip_banned = AsyncMock(return_value=False)
        with patch(f"{_IMPL}.ip_security.log_activity", new_callable=AsyncMock):
            result = await check.check(req)
    assert result is None


async def test_ip_security_passive_mode_global_blocked() -> None:
    mw = _make_middleware(passive_mode=True)
    mw.route_resolver.should_bypass_check = MagicMock(return_value=False)
    check = IpSecurityCheck(mw)
    req = MockGuardRequest()
    req.state.client_ip = "9.9.9.9"
    with patch.object(check, "ip_ban_manager") as mock_ban:
        mock_ban.is_ip_banned = AsyncMock(return_value=False)
        with patch(
            f"{_IMPL}.ip_security.check_ip_access",
            new_callable=AsyncMock,
            return_value=IpAccessResult(
                False, "IP 9.9.9.9 not in global allowlist/blocklist"
            ),
        ):
            with patch(f"{_IMPL}.ip_security.log_activity", new_callable=AsyncMock):
                result = await check.check(req)
    assert result is None


async def test_rate_limit_check_name() -> None:
    mw = _make_middleware()
    check = RateLimitCheck(mw)
    assert check.check_name == "rate_limit"


async def test_rate_limit_whitelisted() -> None:
    mw = _make_middleware()
    check = RateLimitCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = True
    result = await check.check(req)
    assert result is None


async def test_rate_limit_no_client_ip() -> None:
    mw = _make_middleware()
    check = RateLimitCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = False
    result = await check.check(req)
    assert result is None


async def test_rate_limit_bypass() -> None:
    mw = _make_middleware()
    mw.route_resolver.should_bypass_check = MagicMock(return_value=True)
    check = RateLimitCheck(mw)
    rc = RouteConfig()
    req = _make_request_with_route_config(rc)
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    result = await check.check(req)
    assert result is None


async def test_rate_limit_endpoint_specific() -> None:
    mw = _make_middleware(endpoint_rate_limits={"/api": (5, 60)})
    blocked_resp = MockGuardResponse("rate limited", 429)
    mw.rate_limit_handler.report_rate_limit_block = AsyncMock()
    mw.rate_limit_handler.check_rate_limit_tiers = AsyncMock(
        return_value=RateLimitBlock(0, 6, blocked_resp)
    )
    check = RateLimitCheck(mw)
    req = MockGuardRequest(path="/api")
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    result = await check.check(req)
    assert result is not None
    assert result.status_code == 429


async def test_rate_limit_route_specific() -> None:
    mw = _make_middleware()
    blocked_resp = MockGuardResponse("rate limited", 429)
    mw.rate_limit_handler.report_rate_limit_block = AsyncMock()
    mw.rate_limit_handler.check_rate_limit_tiers = AsyncMock(
        return_value=RateLimitBlock(0, 6, blocked_resp)
    )
    check = RateLimitCheck(mw)
    rc = RouteConfig()
    rc.rate_limit = 10
    rc.rate_limit_window = 30
    req = _make_request_with_route_config(rc, path="/test")
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    result = await check.check(req)
    assert result is not None


async def test_rate_limit_global() -> None:
    mw = _make_middleware()
    check = RateLimitCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    result = await check.check(req)
    assert result is None


async def test_rate_limit_passive_mode() -> None:
    mw = _make_middleware(passive_mode=True, endpoint_rate_limits={"/api": (5, 60)})
    blocked_resp = MockGuardResponse("rate limited", 429)
    mw.rate_limit_handler.report_rate_limit_block = AsyncMock()
    mw.rate_limit_handler.check_rate_limit_tiers = AsyncMock(
        return_value=RateLimitBlock(0, 6, blocked_resp)
    )
    check = RateLimitCheck(mw)
    req = MockGuardRequest(path="/api")
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    result = await check.check(req)
    assert result is None


async def test_rate_limit_global_passive_mode() -> None:
    mw = _make_middleware(passive_mode=True)
    blocked_resp = MockGuardResponse("rate limited", 429)
    mw.rate_limit_handler.report_rate_limit_block = AsyncMock()
    mw.rate_limit_handler.check_rate_limit_tiers = AsyncMock(
        return_value=RateLimitBlock(0, 6, blocked_resp)
    )
    check = RateLimitCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    result = await check.check(req)
    assert result is None


async def test_rate_limit_geo_rate_limit() -> None:
    mw = _make_middleware()
    mw.geo_ip_handler = MagicMock()
    mw.geo_ip_handler.get_country = MagicMock(return_value="US")
    blocked_resp = MockGuardResponse("rate limited", 429)
    mw.rate_limit_handler.report_rate_limit_block = AsyncMock()
    mw.rate_limit_handler.check_rate_limit_tiers = AsyncMock(
        return_value=RateLimitBlock(0, 6, blocked_resp)
    )
    check = RateLimitCheck(mw)
    rc = RouteConfig()
    rc.geo_rate_limits = {"US": (5, 60)}
    req = _make_request_with_route_config(rc, path="/test")
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    result = await check.check(req)
    assert result is not None


async def test_rate_limit_geo_wildcard() -> None:
    mw = _make_middleware()
    mw.geo_ip_handler = MagicMock()
    mw.geo_ip_handler.get_country = MagicMock(return_value="FR")
    blocked_resp = MockGuardResponse("rate limited", 429)
    mw.rate_limit_handler.report_rate_limit_block = AsyncMock()
    mw.rate_limit_handler.check_rate_limit_tiers = AsyncMock(
        return_value=RateLimitBlock(0, 6, blocked_resp)
    )
    check = RateLimitCheck(mw)
    rc = RouteConfig()
    rc.geo_rate_limits = {"*": (5, 60)}
    req = _make_request_with_route_config(rc, path="/test")
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    result = await check.check(req)
    assert result is not None


async def test_rate_limit_geo_no_handler() -> None:
    mw = _make_middleware()
    mw.geo_ip_handler = None
    check = RateLimitCheck(mw)
    rc = RouteConfig()
    rc.geo_rate_limits = {"US": (5, 60)}
    req = _make_request_with_route_config(rc, path="/test")
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    result = await check.check(req)
    assert result is None


async def test_rate_limit_geo_no_match() -> None:
    mw = _make_middleware()
    mw.geo_ip_handler = MagicMock()
    mw.geo_ip_handler.get_country = MagicMock(return_value="FR")
    check = RateLimitCheck(mw)
    rc = RouteConfig()
    rc.geo_rate_limits = {"US": (5, 60)}
    req = _make_request_with_route_config(rc, path="/test")
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    result = await check.check(req)
    assert result is None


async def test_suspicious_activity_check_name() -> None:
    mw = _make_middleware()
    check = SuspiciousActivityCheck(mw)
    assert check.check_name == "suspicious_activity"


async def test_suspicious_activity_whitelisted() -> None:
    mw = _make_middleware()
    check = SuspiciousActivityCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = True
    result = await check.check(req)
    assert result is None


async def test_suspicious_activity_no_client_ip() -> None:
    mw = _make_middleware()
    check = SuspiciousActivityCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = False
    result = await check.check(req)
    assert result is None


async def test_suspicious_activity_not_detected() -> None:
    mw = _make_middleware()
    check = SuspiciousActivityCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    with patch(
        f"{_IMPL}.suspicious_activity.get_cached_detection_result",
        new_callable=AsyncMock,
        return_value=DetectionResult(is_threat=False, trigger_info="not_enabled"),
    ):
        result = await check.check(req)
    assert result is None


async def test_suspicious_activity_disabled_by_decorator() -> None:
    mw = _make_middleware()
    check = SuspiciousActivityCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    with patch(
        f"{_IMPL}.suspicious_activity.get_cached_detection_result",
        new_callable=AsyncMock,
        return_value=DetectionResult(
            is_threat=False, trigger_info="disabled_by_decorator"
        ),
    ):
        result = await check.check(req)
    assert result is None
    mw.event_bus.send_middleware_event.assert_called_once()


async def test_suspicious_activity_detected_active() -> None:
    mw = _make_middleware()
    mw.suspicious_request_counts = {}
    mw.create_error_response = AsyncMock(return_value=MockGuardResponse("bad", 400))
    check = SuspiciousActivityCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    with patch(
        f"{_IMPL}.suspicious_activity.get_cached_detection_result",
        new_callable=AsyncMock,
        return_value=DetectionResult(is_threat=True, trigger_info="sql_injection"),
    ):
        with patch(f"{_IMPL}.suspicious_activity.log_activity", new_callable=AsyncMock):
            result = await check.check(req)
    assert result is not None
    assert result.status_code == 400


async def test_suspicious_activity_detected_passive() -> None:
    mw = _make_middleware(passive_mode=True)
    mw.suspicious_request_counts = {}
    check = SuspiciousActivityCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    with patch(
        f"{_IMPL}.suspicious_activity.get_cached_detection_result",
        new_callable=AsyncMock,
        return_value=DetectionResult(is_threat=True, trigger_info="xss"),
    ):
        with patch(f"{_IMPL}.suspicious_activity.log_activity", new_callable=AsyncMock):
            result = await check.check(req)
    assert result is None


async def test_suspicious_activity_auto_ban() -> None:
    mw = _make_middleware(
        enable_ip_banning=True,
        auto_ban_threshold=2,
        auto_ban_duration=300,
    )
    mw.suspicious_request_counts = {"1.2.3.4": {"sqli": 2}}
    mw.create_error_response = AsyncMock(return_value=MockGuardResponse("banned", 403))
    check = SuspiciousActivityCheck(mw)
    req = MockGuardRequest()
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    with patch(
        f"{_IMPL}.suspicious_activity.get_cached_detection_result",
        new_callable=AsyncMock,
        return_value=DetectionResult(is_threat=True, trigger_info="sqli"),
    ):
        with patch.object(check, "ip_ban_manager") as mock_ban:
            mock_ban.ban_ip = AsyncMock()
            with patch(
                f"{_IMPL}.suspicious_activity.log_activity", new_callable=AsyncMock
            ):
                result = await check.check(req)
    assert result is not None
    assert result.status_code == 403


async def test_custom_request_check_name() -> None:
    mw = _make_middleware()
    check = CustomRequestCheck(mw)
    assert check.check_name == "custom_request"


async def test_custom_request_no_check() -> None:
    mw = _make_middleware()
    check = CustomRequestCheck(mw)
    req = MockGuardRequest()
    result = await check.check(req)
    assert result is None


async def test_custom_request_returns_none() -> None:
    mw = _make_middleware(custom_request_check=AsyncMock(return_value=None))
    check = CustomRequestCheck(mw)
    req = MockGuardRequest()
    result = await check.check(req)
    assert result is None


async def test_custom_request_blocks() -> None:
    blocked_resp = MockGuardResponse("blocked", 403)
    custom_fn = AsyncMock(return_value=blocked_resp)
    custom_fn.__name__ = "my_custom_check"
    mw = _make_middleware(custom_request_check=custom_fn)
    check = CustomRequestCheck(mw)
    req = MockGuardRequest()
    result = await check.check(req)
    assert result is not None
    assert result.status_code == 403


async def test_custom_request_passive_mode() -> None:
    blocked_resp = MockGuardResponse("blocked", 403)
    custom_fn = AsyncMock(return_value=blocked_resp)
    custom_fn.__name__ = "my_check"
    mw = _make_middleware(passive_mode=True, custom_request_check=custom_fn)
    check = CustomRequestCheck(mw)
    req = MockGuardRequest()
    result = await check.check(req)
    assert result is None


async def test_rate_limit_route_default_window() -> None:
    mw = _make_middleware()
    mw.rate_limit_handler.report_rate_limit_block = AsyncMock()
    mw.rate_limit_handler.check_rate_limit_tiers = AsyncMock(return_value=None)
    check = RateLimitCheck(mw)
    rc = RouteConfig()
    rc.rate_limit = 10
    rc.rate_limit_window = None
    req = _make_request_with_route_config(rc, path="/test")
    req.state.is_whitelisted = False
    req.state.client_ip = "1.2.3.4"
    result = await check.check(req)
    assert result is None
