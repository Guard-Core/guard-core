import uuid
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.detection_result import DetectionResult
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL

SAME_PREFIX = [f"2001:db8:0:1::{index:x}" for index in range(1, 6)]
OTHER_PREFIXES = [f"2001:db8:0:{index}::1" for index in range(1, 6)]
DETECT_MODULE = "guard_core.core.checks.implementations.suspicious_activity"


def _config(**fields: Any) -> SecurityConfig:
    values: dict[str, Any] = {
        "enable_ip_banning": True,
        "enable_redis": False,
        "enable_penetration_detection": True,
        "enable_rate_limiting": False,
        "auto_ban_threshold": 5,
        "auto_ban_duration": 300,
    }
    values.update(fields)
    return SecurityConfig(**values)


class _Worker:
    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        config: SecurityConfig,
        redis: RedisManager | None = None,
    ) -> None:
        middleware = MagicMock()
        middleware.config = config
        middleware.suspicious_request_counts = {}
        middleware.rate_limit_handler.redis_handler = redis
        middleware.event_bus.send_middleware_event = AsyncMock()
        middleware.create_error_response = AsyncMock(
            return_value=MagicMock(status_code=403)
        )
        middleware.route_resolver.should_bypass_check = lambda *_: False
        self.middleware = middleware
        self.check = SuspiciousActivityCheck(middleware)
        self.bans: list[tuple[str, int, str]] = []

        async def detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
            return DetectionResult(
                is_threat=True, trigger_info="probe", threat_categories=["xss"]
            )

        async def ban(
            ip: str, duration: int, reason: str = "", *, grouped: bool = False
        ) -> bool:
            self.bans.append((ip, duration, reason))
            return True

        monkeypatch.setattr(f"{DETECT_MODULE}.get_cached_detection_result", detect)
        monkeypatch.setattr(self.check.ip_ban_manager, "ban_ip", ban)

    async def strike(self, client_ip: str) -> None:
        request = MagicMock()
        request.state.is_whitelisted = False
        request.state.client_ip = client_ip
        request.state.route_config = None
        request.url_full = "https://test/x"
        await self.check.check(request)


async def test_addresses_of_one_prefix_share_the_strike_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _Worker(monkeypatch, _config())

    for address in SAME_PREFIX:
        await worker.strike(address)

    assert [ban[1:] for ban in worker.bans] == [(300, "penetration_attempt")]
    assert worker.bans[0][0] == "2001:db8:0:1::/64"


async def test_addresses_of_different_prefixes_keep_separate_strikes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _Worker(monkeypatch, _config())

    for address in OTHER_PREFIXES:
        await worker.strike(address)

    assert worker.bans == []


async def test_a_full_length_prefix_keeps_one_strike_count_per_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _Worker(monkeypatch, _config(ipv6_prefix_length=128))

    for address in SAME_PREFIX:
        await worker.strike(address)

    assert worker.bans == []


async def test_ipv4_strikes_stay_keyed_by_the_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _Worker(monkeypatch, _config())

    await worker.strike("203.0.113.7")

    assert list(worker.middleware.suspicious_request_counts) == ["203.0.113.7"]


@pytest.fixture
async def redis() -> AsyncGenerator[RedisManager, None]:
    config = _config(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"test:wp9:strikeid:{uuid.uuid4().hex}:",
    )
    manager = RedisManager(config)
    await manager.initialize()
    try:
        yield manager
    finally:
        await manager.delete_pattern("*")
        await manager.close()


async def test_shared_strikes_are_keyed_by_the_prefix_identity(
    monkeypatch: pytest.MonkeyPatch, redis: RedisManager
) -> None:
    first = _Worker(monkeypatch, redis.config, redis)
    second = _Worker(monkeypatch, redis.config, redis)

    for index, address in enumerate(SAME_PREFIX):
        await (first if index % 2 else second).strike(address)

    banned_by = first.bans + second.bans
    assert [ban[1:] for ban in banned_by] == [(300, "penetration_attempt")]
