import logging
from collections.abc import Iterator
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


class _FakeErrorResponse:
    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        self.headers: dict[str, str] = {}


def _make_middleware(config: SecurityConfig) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.resolve_route = None
    middleware.logger = logging.getLogger("test_rate_limit_singleton_isolation")
    middleware.rate_limit_handler = RateLimitManager(config)
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
        side_effect=lambda status_code, message: _FakeErrorResponse(
            status_code, message
        )
    )
    return middleware


@pytest.fixture(autouse=True)
def _reset_rate_limit_singleton() -> Iterator[None]:
    RateLimitManager._instance = None
    yield
    RateLimitManager._instance = None


async def test_two_middlewares_enforce_their_own_rate_limit_interleaved() -> None:
    config_tight = SecurityConfig(
        enable_rate_limiting=True, rate_limit=1, rate_limit_window=60
    )
    config_loose = SecurityConfig(
        enable_rate_limiting=True, rate_limit=100, rate_limit_window=60
    )

    middleware_tight = _make_middleware(config_tight)
    middleware_loose = _make_middleware(config_loose)

    assert middleware_tight.rate_limit_handler is middleware_loose.rate_limit_handler

    check_tight = RateLimitCheck(middleware_tight)
    check_loose = RateLimitCheck(middleware_loose)

    ip_tight = "198.51.100.10"
    ip_loose = "198.51.100.20"

    result = await check_tight._check_global_rate_limit(
        MockGuardRequest(client_host=ip_tight), ip_tight
    )
    assert result is None, "middleware with rate_limit=1 blocked its first request"

    for _ in range(5):
        result = await check_loose._check_global_rate_limit(
            MockGuardRequest(client_host=ip_loose), ip_loose
        )
        assert result is None, "middleware with rate_limit=100 blocked too early"

    result = await check_tight._check_global_rate_limit(
        MockGuardRequest(client_host=ip_tight), ip_tight
    )
    assert result is not None, (
        "middleware with rate_limit=1 was not enforced; the singleton used "
        "another middleware's rate_limit instead of its own"
    )
    assert result.status_code == 429

    for _ in range(90):
        result = await check_loose._check_global_rate_limit(
            MockGuardRequest(client_host=ip_loose), ip_loose
        )
        assert result is None, "middleware with rate_limit=100 blocked too early"


async def test_endpoint_limit_survives_a_later_middleware_with_rate_limiting_off() -> (
    None
):
    config_limited = SecurityConfig(
        enable_rate_limiting=True, endpoint_rate_limits={"/special": (1, 60)}
    )
    config_off = SecurityConfig(enable_rate_limiting=False)

    middleware_limited = _make_middleware(config_limited)
    _make_middleware(config_off)

    check_limited = RateLimitCheck(middleware_limited)
    ip = "198.51.100.30"

    first = await check_limited._check_endpoint_rate_limit(
        MockGuardRequest(path="/special", client_host=ip), ip
    )
    second = await check_limited._check_endpoint_rate_limit(
        MockGuardRequest(path="/special", client_host=ip), ip
    )
    assert first is None
    assert second is not None, (
        "the endpoint limit was skipped because the limiter read the last "
        "constructed middleware's enable_rate_limiting instead of its own"
    )
