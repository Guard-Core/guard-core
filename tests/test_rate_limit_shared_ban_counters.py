import logging
import uuid
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, MockGuardRequest, MockGuardResponse

IP = "198.51.100.50"
THRESHOLD = 6
WORKERS = 4


def _config(redis: bool, prefix: str = "") -> SecurityConfig:
    return SecurityConfig(
        enable_redis=redis,
        redis_url=REDIS_URL,
        redis_prefix=prefix or f"test:wp3:{uuid.uuid4().hex}:",
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        auto_ban_threshold=THRESHOLD,
        auto_ban_duration=300,
    )


class _Worker:
    def __init__(self, config: SecurityConfig, redis: RedisManager | None) -> None:
        self.manager = RateLimitManager(config)
        self.redis = redis
        self.bans: list[tuple[str, int, str]] = []
        middleware = Mock()
        middleware.config = config
        middleware.logger = logging.getLogger("test_shared_ban_counters")
        middleware.resolve_route = None
        middleware.rate_limit_handler = self.manager
        middleware.event_bus = Mock(send_middleware_event=AsyncMock())
        middleware.suspicious_request_counts = {}
        middleware.geo_ip_handler = None
        middleware.create_error_response = AsyncMock(
            side_effect=lambda status_code, default_message: MockGuardResponse(
                default_message, status_code
            )
        )
        middleware.route_resolver = Mock(should_bypass_check=Mock(return_value=False))
        self.middleware = middleware
        self.check = RateLimitCheck(middleware)

        async def record_ban(
            ip: str, duration: int, reason: str = "", *, grouped: bool = False
        ) -> bool:
            self.bans.append((ip, duration, reason))
            return duration

        self.check.ip_ban_manager = Mock(_ban_ip_escalating=record_ban)

    async def violate(self) -> Any:
        request = MockGuardRequest(path="/x", client_host=IP)
        request.state.client_ip = IP
        request.state.route_config = None
        request.state.is_whitelisted = False
        return await self.check.check(request)


@pytest.fixture
async def redis_workers() -> AsyncGenerator[list[_Worker], None]:
    config = _config(True)
    redis = RedisManager(config)
    await redis.initialize()
    workers = []
    for _ in range(WORKERS):
        worker = _Worker(config, redis)
        await worker.manager.initialize_redis(redis)
        workers.append(worker)
    try:
        yield workers
    finally:
        await redis.delete_pattern("*")
        await redis.close()


def _all_bans(workers: list[_Worker]) -> list[tuple[str, int, str]]:
    return [ban for worker in workers for ban in worker.bans]


async def test_the_ban_threshold_counts_violations_across_every_worker(
    redis_workers: list[_Worker],
) -> None:
    assert await redis_workers[0].violate() is None
    violations = 0
    while not _all_bans(redis_workers) and violations < 40:
        assert await redis_workers[violations % WORKERS].violate() is not None
        violations += 1

    assert violations == THRESHOLD
    assert _all_bans(redis_workers) == [(IP, 300, "rate_limit_exceeded")]


async def test_the_shared_counter_is_cleared_when_the_ban_lands(
    redis_workers: list[_Worker],
) -> None:
    await redis_workers[0].violate()
    for index in range(THRESHOLD):
        await redis_workers[index % WORKERS].violate()
    assert len(_all_bans(redis_workers)) == 1

    for index in range(THRESHOLD - 1):
        await redis_workers[index % WORKERS].violate()

    assert len(_all_bans(redis_workers)) == 1


async def test_the_shared_counter_survives_a_restart(
    redis_workers: list[_Worker],
) -> None:
    first = redis_workers[0]
    await first.violate()
    for _ in range(THRESHOLD - 1):
        await first.violate()
    assert _all_bans(redis_workers) == []

    restarted = _Worker(first.manager.config, first.redis)
    await restarted.manager.initialize_redis(first.redis)
    await restarted.violate()

    assert len(restarted.bans) == 1


async def test_without_redis_each_process_keeps_its_own_counter() -> None:
    config = _config(False)
    workers = [_Worker(config.model_copy(), None) for _ in range(WORKERS)]
    for worker in workers:
        await worker.violate()

    for index in range(THRESHOLD * WORKERS - WORKERS):
        await workers[index % WORKERS].violate()

    assert _all_bans(workers) == []


async def test_the_by_ip_primitive_counts_in_the_same_shared_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.handlers.ipban_handler import IPBanManager
    from guard_core.handlers.ratelimit_handler import check_rate_limit_by_ip

    config = _config(True)
    config.auto_ban_threshold = 3
    redis = RedisManager(config)
    await redis.initialize()
    bans: list[tuple[str, int, str]] = []

    async def record_ban(
        ip: str, duration: int, reason: str = "", *, grouped: bool = False
    ) -> bool:
        bans.append((ip, duration, reason))
        return duration

    monkeypatch.setattr(IPBanManager(), "_ban_ip_escalating", record_ban)
    key = f"{config.redis_prefix}rate_limit:violations:{IP}"

    async def stored() -> int:
        async with redis.get_connection() as conn:
            return int(await conn.zcard(key))

    try:
        assert await check_rate_limit_by_ip(IP, config, redis) is True
        for _ in range(2):
            assert await check_rate_limit_by_ip(IP, config, redis) is False
        assert (bans, await stored()) == ([], 2)

        assert await check_rate_limit_by_ip(IP, config, redis) is False
        assert (bans, await stored()) == ([(IP, 300, "rate_limit_exceeded")], 0)
    finally:
        await redis.delete_pattern("*")
        await redis.close()
