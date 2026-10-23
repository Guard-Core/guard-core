import pytest
from pydantic import ValidationError

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.helpers import _increment_suspicious_counts
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest


def _error_response(status_code: int, message: str) -> MockGuardResponse:
    return MockGuardResponse(message, status_code)


def _config(**settings: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False, rate_limit=1, rate_limit_window=60, **settings
    )


def test_both_caps_are_config_fields_defaulting_to_10000() -> None:
    config = SyncSecurityConfig(enable_redis=False)

    assert config.rate_limit_max_tracked_keys == 10_000
    assert config.ban_counters_max_tracked_ips == 10_000


@pytest.mark.parametrize(
    "field", ["rate_limit_max_tracked_keys", "ban_counters_max_tracked_ips"]
)
def test_a_cap_below_one_is_rejected(field: str) -> None:
    with pytest.raises(ValidationError):
        SyncSecurityConfig(enable_redis=False, **{field: 0})


def test_the_rate_limit_store_honors_its_cap() -> None:
    config = _config(rate_limit_max_tracked_keys=3)
    manager = RateLimitManager(config)

    for last_octet in range(10):
        ip = f"198.51.100.{last_octet}"
        request = SyncMockGuardRequest(path="/x", client_host=ip)
        manager.check_rate_limit(request, ip, _error_response)

    assert len(manager.request_timestamps) == 3


def test_one_ip_cannot_evict_a_victim_by_requesting_many_paths() -> None:
    from unittest.mock import MagicMock, Mock

    from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck

    config = _config(rate_limit_max_tracked_keys=5, enable_rate_limiting=False)
    manager = RateLimitManager(config)
    middleware = Mock()
    middleware.config = config
    middleware.resolve_route = None
    middleware.rate_limit_handler = manager
    middleware.event_bus = Mock(send_middleware_event=MagicMock())
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    middleware.route_resolver = Mock(should_bypass_check=Mock(return_value=False))
    middleware.geo_ip_handler = None
    middleware.suspicious_request_counts = {}
    check = RateLimitCheck(middleware)
    route_config = RouteConfig()
    route_config.rate_limit = 1
    route_config.rate_limit_window = 60

    def request_from(ip: str, path: str) -> SyncMockGuardRequest:
        request = SyncMockGuardRequest(path=path, client_host=ip)
        request.state.client_ip = ip
        request.state.route_config = route_config
        request.state.guard_route_id = "app.limited"
        request.state.is_whitelisted = False
        return request

    assert check.check(request_from("198.51.100.1", "/p/0")) is None
    assert check.check(request_from("198.51.100.1", "/p/0")) is not None

    for index in range(50):
        check.check(request_from("203.0.113.9", f"/p/{index}"))

    assert check.check(request_from("198.51.100.1", "/p/0")) is not None


def test_the_ban_counter_store_honors_its_cap() -> None:
    config = SyncSecurityConfig(enable_redis=False, ban_counters_max_tracked_ips=3)
    from unittest.mock import Mock

    middleware = Mock()
    middleware.config = config
    middleware.suspicious_request_counts = {}

    for last_octet in range(10):
        _increment_suspicious_counts(middleware, f"198.51.100.{last_octet}", "sqli")

    assert len(middleware.suspicious_request_counts) == 3
