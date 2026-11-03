from collections.abc import AsyncGenerator, Generator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.detection_result import DetectionResult
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix

IDENTITY = "2001:db8:0:1::/64"
ADDRESSES = ["2001:db8:0:1::5", "2001:db8:0:1::6"]


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture
async def redis() -> AsyncGenerator[RedisManager, None]:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=suite_redis_prefix("wp9:grouped"),
    )
    manager = RedisManager(config)
    await manager.initialize()
    try:
        yield manager
    finally:
        await manager.delete_pattern("*")
        await manager.close()


def _check(
    monkeypatch: pytest.MonkeyPatch, redis: RedisManager
) -> SuspiciousActivityCheck:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=redis.config.redis_url,
        redis_prefix=redis.config.redis_prefix,
        enable_ip_banning=True,
        enable_penetration_detection=True,
        enable_rate_limiting=False,
        auto_ban_threshold=2,
        auto_ban_duration=600,
    )
    middleware = MagicMock()
    middleware.config = config
    middleware.suspicious_request_counts = {}
    middleware.rate_limit_handler.redis_handler = redis
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
        return_value=MagicMock(status_code=403)
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    check = SuspiciousActivityCheck(middleware)
    manager = IPBanManager()
    manager.config = config
    manager.redis_handler = redis
    check.ip_ban_manager = manager

    async def detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        return DetectionResult(
            is_threat=True, trigger_info="probe", threat_categories=["xss"]
        )

    monkeypatch.setattr(
        "guard_core.core.checks.implementations.suspicious_activity"
        ".get_cached_detection_result",
        detect,
    )
    return check


async def _strike(check: SuspiciousActivityCheck, address: str) -> None:
    request = MagicMock()
    request.state.is_whitelisted = False
    request.state.client_ip = address
    request.state.route_config = None
    request.url_full = "https://test/x"
    await check.check(request)


async def test_a_detection_auto_ban_of_an_ipv6_client_bans_its_identity(
    monkeypatch: pytest.MonkeyPatch, redis: RedisManager
) -> None:
    check = _check(monkeypatch, redis)

    for address in ADDRESSES:
        await _strike(check, address)

    assert await redis.get_key("banned_identities", IDENTITY) is not None
    assert await redis.get_key("banned_ips", ADDRESSES[1]) is None
    assert await check.ip_ban_manager.is_ip_banned("2001:db8:0:1::99") is True


async def test_an_ipv4_auto_ban_stays_a_per_address_ban(
    monkeypatch: pytest.MonkeyPatch, redis: RedisManager
) -> None:
    check = _check(monkeypatch, redis)

    for _ in range(2):
        await _strike(check, "203.0.113.7")

    assert await redis.get_key("banned_ips", "203.0.113.7") is not None


async def test_an_operator_cidr_ban_is_not_an_identity_ban(
    monkeypatch: pytest.MonkeyPatch, redis: RedisManager
) -> None:
    check = _check(monkeypatch, redis)

    assert await check.ip_ban_manager.ban_ip("2001:db8:7::/48", 600, "operator")

    assert await redis.get_key("banned_identities", "2001:db8:7::/48") is None
