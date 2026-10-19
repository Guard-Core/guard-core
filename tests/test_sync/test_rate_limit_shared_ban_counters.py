import logging
import uuid
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL, MockGuardResponse, SyncMockGuardRequest

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
        middleware.event_bus = Mock(send_middleware_event=MagicMock())
        middleware.suspicious_request_counts = {}
        middleware.geo_ip_handler = None
        middleware.create_error_response = MagicMock(
            side_effect=lambda status_code, default_message: MockGuardResponse(
                default_message, status_code
            )
        )
        middleware.route_resolver = Mock(should_bypass_check=Mock(return_value=False))
        self.middleware = middleware
        self.check = RateLimitCheck(middleware)

        def record_ban(
            ip: str, duration: int, reason: str = "", *, grouped: bool = False
        ) -> int | None:
            self.bans.append((ip, duration, reason))
            return duration

        self.check.ip_ban_manager = Mock(_ban_ip_escalating=record_ban)

    def violate(self) -> Any:
        request = SyncMockGuardRequest(path="/x", client_host=IP)
        request.state.client_ip = IP
        request.state.route_config = None
        request.state.is_whitelisted = False
        return self.check.check(request)


@pytest.fixture
def redis_workers() -> Generator[list[_Worker], None]:
    config = _config(True)
    redis = RedisManager(config)
    redis.initialize()
    workers = []
    for _ in range(WORKERS):
        worker = _Worker(config, redis)
        worker.manager.initialize_redis(redis)
        workers.append(worker)
    try:
        yield workers
    finally:
        redis.delete_pattern("*")
        redis.close()


def _all_bans(workers: list[_Worker]) -> list[tuple[str, int, str]]:
    return [ban for worker in workers for ban in worker.bans]


def test_the_ban_threshold_counts_violations_across_every_worker(
    redis_workers: list[_Worker],
) -> None:
    assert redis_workers[0].violate() is None
    violations = 0
    while not _all_bans(redis_workers) and violations < 40:
        assert redis_workers[violations % WORKERS].violate() is not None
        violations += 1

    assert violations == THRESHOLD
    assert _all_bans(redis_workers) == [(IP, 300, "rate_limit_exceeded")]


def test_the_shared_counter_is_cleared_when_the_ban_lands(
    redis_workers: list[_Worker],
) -> None:
    redis_workers[0].violate()
    for index in range(THRESHOLD):
        redis_workers[index % WORKERS].violate()
    assert len(_all_bans(redis_workers)) == 1

    for index in range(THRESHOLD - 1):
        redis_workers[index % WORKERS].violate()

    assert len(_all_bans(redis_workers)) == 1


def test_the_shared_counter_survives_a_restart(
    redis_workers: list[_Worker],
) -> None:
    first = redis_workers[0]
    first.violate()
    for _ in range(THRESHOLD - 1):
        first.violate()
    assert _all_bans(redis_workers) == []

    restarted = _Worker(first.manager.config, first.redis)
    restarted.manager.initialize_redis(first.redis)
    restarted.violate()

    assert len(restarted.bans) == 1


def test_without_redis_each_process_keeps_its_own_counter() -> None:
    config = _config(False)
    workers = [_Worker(config.model_copy(), None) for _ in range(WORKERS)]
    for worker in workers:
        worker.violate()

    for index in range(THRESHOLD * WORKERS - WORKERS):
        workers[index % WORKERS].violate()

    assert _all_bans(workers) == []


def test_the_by_ip_primitive_counts_in_the_same_shared_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.sync.handlers.ipban_handler import IPBanManager
    from guard_core.sync.handlers.ratelimit_handler import check_rate_limit_by_ip

    config = _config(True)
    config.auto_ban_threshold = 3
    redis = RedisManager(config)
    redis.initialize()
    bans: list[tuple[str, int, str]] = []

    def record_ban(
        ip: str, duration: int, reason: str = "", *, grouped: bool = False
    ) -> int | None:
        bans.append((ip, duration, reason))
        return duration

    monkeypatch.setattr(IPBanManager(), "_ban_ip_escalating", record_ban)
    key = f"{config.redis_prefix}rate_limit:violations:{IP}"

    def stored() -> int:
        with redis.get_connection() as conn:
            return int(conn.zcard(key))

    try:
        assert check_rate_limit_by_ip(IP, config, redis) is True
        for _ in range(2):
            assert check_rate_limit_by_ip(IP, config, redis) is False
        assert (bans, stored()) == ([], 2)

        assert check_rate_limit_by_ip(IP, config, redis) is False
        assert (bans, stored()) == ([(IP, 300, "rate_limit_exceeded")], 0)
    finally:
        redis.delete_pattern("*")
        redis.close()
