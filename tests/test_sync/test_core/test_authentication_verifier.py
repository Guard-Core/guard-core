from typing import Any
from unittest.mock import MagicMock, patch

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.authentication import (
    AuthenticationCheck,
)
from guard_core.sync.decorators.base import RouteConfig
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

_IMPL = "guard_core.sync.core.checks.implementations"


def _make_middleware(
    passive_mode: bool = False,
    **config_overrides: object,
) -> MagicMock:
    mw = MagicMock()
    config = SyncSecurityConfig(
        enable_redis=False,
        passive_mode=passive_mode,
        **config_overrides,
    )
    mw.config = config
    mw.logger = MagicMock()
    mw.event_bus = MagicMock()
    mw.event_bus.send_middleware_event = MagicMock()
    mw.event_bus.send_https_violation_event = MagicMock()
    mw.event_bus.send_cloud_detection_events = MagicMock()
    mw.create_error_response = MagicMock(return_value=MockGuardResponse("error", 403))
    mw.response_factory = MagicMock()
    mw.response_factory.apply_modifier = MagicMock(side_effect=lambda r: r)
    mw.response_factory.create_https_redirect = MagicMock(
        return_value=MockGuardResponse("redirect", 301, {"Location": "https://test/"})
    )
    mw.route_resolver = MagicMock()
    mw.route_resolver.should_bypass_check = MagicMock(return_value=False)
    mw.route_resolver.get_cloud_providers_to_check = MagicMock(return_value=[])
    mw.route_resolver.get_route_config = MagicMock(return_value=None)
    mw.geo_ip_handler = None
    mw.agent_handler = None
    mw.rate_limit_handler = MagicMock()
    mw.rate_limit_handler.check_rate_limit = MagicMock(return_value=None)
    mw.suspicious_request_counts = {}
    mw.last_cloud_ip_refresh = 0
    mw.refresh_cloud_ip_ranges = MagicMock()
    return mw


def _make_request_with_route_config(
    route_config: RouteConfig,
    **kwargs: Any,
) -> SyncMockGuardRequest:
    req = SyncMockGuardRequest(**kwargs)
    req.state.route_config = route_config
    return req


def _verifier_returning(principal: Any) -> Any:
    def verifier(request: Any, credential: str) -> Any:
        return principal

    return verifier


def _async_verifier_returning(principal: Any) -> Any:
    def verifier(request: Any, credential: str) -> Any:
        return principal

    return verifier


def _deny_response_mw() -> MagicMock:
    mw = _make_middleware()
    mw.create_error_response = MagicMock(return_value=MockGuardResponse("unauth", 401))
    return mw


def test_arbitrary_bearer_rejected_without_verifier() -> None:
    mw = _deny_response_mw()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "bearer"
    rc.auth_verifier = None
    req = _make_request_with_route_config(
        rc, headers={"authorization": "Bearer attacker-value"}
    )
    with patch(f"{_IMPL}.authentication.log_activity"):
        result = check.check(req)
    assert result is not None
    assert result.status_code == 401


def test_verifier_denial_rejected() -> None:
    mw = _deny_response_mw()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "bearer"
    rc.auth_verifier = _verifier_returning(None)
    req = _make_request_with_route_config(rc, headers={"authorization": "Bearer creds"})
    with patch(f"{_IMPL}.authentication.log_activity"):
        result = check.check(req)
    assert result is not None
    assert result.status_code == 401


def test_verifier_raises_exception_fail_closed() -> None:
    def verifier(_request: Any, _credential: str) -> Any:
        raise RuntimeError("jwt decode failed")

    mw = _deny_response_mw()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "bearer"
    rc.auth_verifier = verifier
    req = _make_request_with_route_config(rc, headers={"authorization": "Bearer token"})
    with patch(f"{_IMPL}.authentication.log_activity"):
        result = check.check(req)
    assert result is not None
    assert result.status_code == 401


def test_verifier_success_allows_and_stashes_principal() -> None:
    mw = _make_middleware()
    check = AuthenticationCheck(mw)
    principal = {"user": "alice"}
    rc = RouteConfig()
    rc.auth_required = "bearer"
    rc.auth_verifier = _verifier_returning(principal)
    req = _make_request_with_route_config(
        rc, headers={"authorization": "Bearer good-token"}
    )
    result = check.check(req)
    assert result is None
    assert request_state_auth_principal(req) == principal


def test_wrong_scheme_rejected() -> None:
    mw = _deny_response_mw()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "bearer"
    rc.auth_verifier = _verifier_returning({"user": "x"})
    req = _make_request_with_route_config(rc, headers={"authorization": "Basic creds"})
    with patch(f"{_IMPL}.authentication.log_activity"):
        result = check.check(req)
    assert result is not None
    assert result.status_code == 401


def test_missing_authorization_rejected() -> None:
    mw = _deny_response_mw()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "bearer"
    rc.auth_verifier = _verifier_returning({"user": "x"})
    req = _make_request_with_route_config(rc, headers={})
    with patch(f"{_IMPL}.authentication.log_activity"):
        result = check.check(req)
    assert result is not None
    assert result.status_code == 401


def test_global_verifier_used_when_route_has_none() -> None:
    principal = {"user": "bob"}
    mw = _make_middleware(auth_verifier=_verifier_returning(principal))
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "bearer"
    rc.auth_verifier = None
    req = _make_request_with_route_config(rc, headers={"authorization": "Bearer token"})
    result = check.check(req)
    assert result is None
    assert request_state_auth_principal(req) == principal


def test_route_verifier_overrides_global() -> None:
    route_principal = {"user": "route"}
    global_principal = {"user": "global"}
    mw = _make_middleware(auth_verifier=_verifier_returning(global_principal))
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "bearer"
    rc.auth_verifier = _verifier_returning(route_principal)
    req = _make_request_with_route_config(rc, headers={"authorization": "Bearer token"})
    result = check.check(req)
    assert result is None
    assert request_state_auth_principal(req) == route_principal


def test_api_key_without_verifier_fail_closed() -> None:
    mw = _deny_response_mw()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.api_key_required = True
    rc.api_key_header = "X-API-Key"
    rc.required_headers = {"X-API-Key": "required"}
    rc.api_key_verifier = None
    req = _make_request_with_route_config(rc, headers={"X-API-Key": "any-value"})
    with patch(f"{_IMPL}.authentication.log_activity"):
        result = check.check(req)
    assert result is not None
    assert result.status_code == 401


def test_api_key_missing_rejected() -> None:
    mw = _deny_response_mw()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.api_key_required = True
    rc.api_key_header = "X-API-Key"
    rc.api_key_verifier = _verifier_returning({"user": "x"})
    req = _make_request_with_route_config(rc, headers={})
    with patch(f"{_IMPL}.authentication.log_activity"):
        result = check.check(req)
    assert result is not None
    assert result.status_code == 401


def test_api_key_verifier_denial() -> None:
    mw = _deny_response_mw()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.api_key_required = True
    rc.api_key_header = "X-API-Key"
    rc.api_key_verifier = _verifier_returning(None)
    req = _make_request_with_route_config(rc, headers={"X-API-Key": "bad"})
    with patch(f"{_IMPL}.authentication.log_activity"):
        result = check.check(req)
    assert result is not None
    assert result.status_code == 401


def test_api_key_verifier_success() -> None:
    principal = {"user": "dave"}
    mw = _make_middleware()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.api_key_required = True
    rc.api_key_header = "X-API-Key"
    rc.api_key_verifier = _verifier_returning(principal)
    req = _make_request_with_route_config(rc, headers={"X-API-Key": "good"})
    result = check.check(req)
    assert result is None
    assert request_state_auth_principal(req) == principal


def test_presence_only_allows_any_bearer_no_principal() -> None:
    mw = _make_middleware()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.authorization_header_required = "bearer"
    req = _make_request_with_route_config(
        rc, headers={"authorization": "Bearer anything"}
    )
    result = check.check(req)
    assert result is None
    assert not hasattr(req.state, "auth_principal") or req.state.auth_principal is None


def test_presence_only_missing_header_rejected() -> None:
    mw = _deny_response_mw()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.authorization_header_required = "bearer"
    req = _make_request_with_route_config(rc, headers={})
    with patch(f"{_IMPL}.authentication.log_activity"):
        result = check.check(req)
    assert result is not None
    assert result.status_code == 401


def test_presence_only_wrong_scheme_rejected() -> None:
    mw = _deny_response_mw()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.authorization_header_required = "bearer"
    req = _make_request_with_route_config(rc, headers={"authorization": "Basic creds"})
    with patch(f"{_IMPL}.authentication.log_activity"):
        result = check.check(req)
    assert result is not None
    assert result.status_code == 401


def test_passive_mode_fail_closed_does_not_block() -> None:
    mw = _make_middleware(passive_mode=True)
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "bearer"
    rc.auth_verifier = None
    req = _make_request_with_route_config(
        rc, headers={"authorization": "Bearer attacker-value"}
    )
    with patch(f"{_IMPL}.authentication.log_activity"):
        result = check.check(req)
    assert result is None


def test_passive_mode_denial_does_not_block() -> None:
    mw = _make_middleware(passive_mode=True)
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "bearer"
    rc.auth_verifier = _verifier_returning(None)
    req = _make_request_with_route_config(rc, headers={"authorization": "Bearer creds"})
    with patch(f"{_IMPL}.authentication.log_activity"):
        result = check.check(req)
    assert result is None


def request_state_auth_principal(req: SyncMockGuardRequest) -> Any:
    return req.state.auth_principal
